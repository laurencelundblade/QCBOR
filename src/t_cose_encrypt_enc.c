/*
 * t_cose_encrypt_enc.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_standard_constants.h"
#include "qcbor/qcbor.h"
#include <stdio.h>
#include <stdlib.h>
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_recipient_enc_hpke.h"
#include "t_cose/t_cose_recipient_enc_aes_kw.h"

/**
 * \brief  Initialize a recipient structure for use with HPKE.
 *
 * \param[in] context           The t_cose_encrypt_recipient_ctx context.
 * \param[in] option_flags       One of \c T_COSE_OPT_XXXX.
 * \param[in] cose_algorithm_id  the HPKE algorithm, for example
 *                               \ref COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM.
 *
 */
enum t_cose_err_t
t_cose_encrypt_recipient_init(struct t_cose_encrypt_recipient_ctx *context,
                              uint32_t                             option_flags,
                              int32_t                              cose_algorithm_id)
{
    memset(context, 0, sizeof(*context));
    context->cose_algorithm_id = cose_algorithm_id;
    context->option_flags = option_flags;

    /* Setting key distribution parameters. */
    switch(cose_algorithm_id) {
#ifndef T_COSE_DISABLE_HPKE
    case T_COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM:
    case T_COSE_ALGORITHM_HPKE_P521_HKDF512_AES256_GCM:
        context->recipient_func = t_cose_create_recipient_hpke;
        break;
#endif /* T_COSE_DISABLE_HPKE */

#ifndef T_COSE_DISABLE_AES_KW
    case T_COSE_ALGORITHM_A256KW:
    case T_COSE_ALGORITHM_A192KW:
    case T_COSE_ALGORITHM_A128KW:
        context->recipient_func = t_cose_create_recipient_aes_kw;
        break;
#endif /* T_COSE_DISABLE_AES_KW */
            
    default:
        context->recipient_func = NULL;
    }

    return(T_COSE_SUCCESS);
}

static inline void
t_cose_encrypt_set_recipient_key(struct t_cose_encrypt_recipient_ctx *context,
                                 struct t_cose_key                    recipient_key,
                                 struct q_useful_buf_c                kid)
{
    context->recipient_key = recipient_key;
    context->kid = kid;
}


enum t_cose_err_t
t_cose_encrypt_enc(struct t_cose_encrypt_enc_ctx *context,
                   struct q_useful_buf_c          payload,
                   struct q_useful_buf            encrypted_payload,
                   struct q_useful_buf_c         *encrypted_payload_final,
                   struct q_useful_buf            out_buf,
                   struct q_useful_buf_c         *result)
{
    QCBOREncodeContext     additional_data;
    UsefulBufC             scratch;
    QCBORError             ret;
    QCBOREncodeContext     encrypt_ctx;
    struct q_useful_buf_c  nonce_result;
    struct q_useful_buf_c  random_result={NULL,0};
    size_t data_length;

    /* Additional data buffer */
    UsefulBufC             add_data_buf;
    uint8_t                add_data[20];
    size_t                 add_data_len = sizeof(add_data);
    struct q_useful_buf    add_data_struct = {add_data, add_data_len};

    size_t                 key_bitlen;
    enum t_cose_err_t      cose_result;
    Q_USEFUL_BUF_MAKE_STACK_UB(random, 16);
    Q_USEFUL_BUF_MAKE_STACK_UB(nonce, T_COSE_ENCRYPTION_MAX_KEY_LENGTH);

    /* Determine algorithm parameters */
    switch(context->cose_algorithm_id) {
    case T_COSE_ALGORITHM_A128GCM:
        key_bitlen = 128;
        break;
    case T_COSE_ALGORITHM_A256GCM:
        key_bitlen = 256;
        break;
    default:
        /* Unsupported algorithm */
        return(T_COSE_ERR_UNSUPPORTED_CIPHER_ALG);
    }

    /* Initialize CBOR encoder context with output buffer */
    QCBOREncode_Init(&encrypt_ctx, out_buf);

    /* Should we use COSE_Encrypt or COSE_Encrypt0? */
    if ((context->option_flags & T_COSE_OPT_COSE_ENCRYPT0) > 0) {
        /* Add the CBOR tag indicating COSE_Encrypt0 */
        QCBOREncode_AddTag(&encrypt_ctx, CBOR_TAG_COSE_ENCRYPT0);
    } else {
        /* Add the CBOR tag indicating COSE_Encrypt */
        QCBOREncode_AddTag(&encrypt_ctx, CBOR_TAG_COSE_ENCRYPT);
    }

    /* Open array */
    QCBOREncode_OpenArray(&encrypt_ctx);

    /* Add protected headers with alg parameter */
    QCBOREncode_BstrWrap(&encrypt_ctx);

    QCBOREncode_OpenMap(&encrypt_ctx);

    QCBOREncode_AddInt64ToMapN(&encrypt_ctx,
                               T_COSE_HEADER_PARAM_ALG,
                               context->cose_algorithm_id);

    QCBOREncode_CloseMap(&encrypt_ctx);

    QCBOREncode_CloseBstrWrap2(&encrypt_ctx, false, &scratch);

    /* Add unprotected Header */
    QCBOREncode_OpenMap(&encrypt_ctx);

    /* Generate random nonce */
    cose_result = t_cose_crypto_get_random(nonce, key_bitlen / 8,
                                           &nonce_result );

    if (cose_result != T_COSE_SUCCESS) {
        return(cose_result);
    }

    /* Add nonce */
    QCBOREncode_AddBytesToMapN(&encrypt_ctx,
                               T_COSE_HEADER_PARAM_IV,
                               nonce_result
                              );

    /* Add kid */
    if ((context->option_flags & T_COSE_OPT_COSE_ENCRYPT0) > 0) {
        QCBOREncode_AddBytesToMapN(&encrypt_ctx,
                                   T_COSE_HEADER_PARAM_KID,
                                   context->recipient_ctx.kid);
    }

    /* Close unprotected header map */
    QCBOREncode_CloseMap(&encrypt_ctx);

    if ((context->option_flags & T_COSE_OPT_COSE_ENCRYPT_DETACHED) > 0) {
        /* Indicate detached ciphertext with NULL */
        QCBOREncode_AddSimple(&encrypt_ctx, CBOR_SIMPLEV_NULL);
    }

    /* Encrypt payload */

    /* Create Additional Data Structure
    *
    *  Enc_structure = [
    *    context : "Encrypt",
    *    protected : empty_or_serialized_map,
    *    external_aad : bstr
    *  ]
    */

    /* Initialize additional data CBOR array */
    QCBOREncode_Init(&additional_data, add_data_struct);

    QCBOREncode_BstrWrap(&additional_data);

    /* Open array */
    QCBOREncode_OpenArray(&additional_data);

    /* 1. Add context string "Encrypt" or "Encrypt0" */
    if ( (context->option_flags & T_COSE_OPT_COSE_ENCRYPT0) > 0) {
        QCBOREncode_AddText(&additional_data,
                            ((struct q_useful_buf_c) {"Encrypt0", 8}));
    } else
    {
        QCBOREncode_AddText(&additional_data,
                            ((struct q_useful_buf_c) {"Encrypt", 7}));
    }

    /* 2. Add protected headers (as bstr) */
    QCBOREncode_BstrWrap(&additional_data);

    QCBOREncode_OpenMap(&additional_data);

    QCBOREncode_AddInt64ToMapN(&additional_data,
                               T_COSE_HEADER_PARAM_ALG,
                               context->cose_algorithm_id);

    QCBOREncode_CloseMap(&additional_data);
    QCBOREncode_CloseBstrWrap2(&additional_data, false, &add_data_buf);

    /* 3. Add any externally provided additional data,
     * which is empty in our case.
     */
    QCBOREncode_BstrWrap(&additional_data);
    QCBOREncode_CloseBstrWrap2(&additional_data, false, &add_data_buf);

    /* Close array */
    QCBOREncode_CloseArray(&additional_data);

    QCBOREncode_CloseBstrWrap2(&additional_data, false, &add_data_buf);

    /* Finish and check the results */
    ret = QCBOREncode_Finish(&additional_data, &add_data_buf);

    if (ret != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_FORMATTING);
    }

    struct t_cose_key cek_handle;

    if ( (context->option_flags & T_COSE_OPT_COSE_ENCRYPT0) == 0) {
        /* For everything but direct encryption, we create a
         * random CEK and encrypt payload with CEK.
         */
        cose_result = t_cose_crypto_get_random(random, 16, &random_result);
        if (cose_result != T_COSE_SUCCESS) {
            return(cose_result);
        }

        cose_result = t_cose_crypto_make_symmetric_key_handle(context->cose_algorithm_id,
                                                random_result,
                                                &cek_handle);

    } else {
        /* Direct encryption with recipient key. This requires us
         * to export the shared secret for later use in the payload
         * encryption.
         */

        cose_result = t_cose_crypto_export_key(
                                        context->recipient_ctx.recipient_key,
                                        random,
                                        &data_length);

        if (cose_result != T_COSE_SUCCESS) {
            return(cose_result);
        }

        random_result.ptr = random.ptr;
        random_result.len = data_length;

        cek_handle = context->recipient_ctx.recipient_key;
    }

    cose_result = t_cose_crypto_aead_encrypt(
                        context->cose_algorithm_id,
                        cek_handle,
                        nonce_result,
                        add_data_buf,
                        payload,
                        encrypted_payload,
                        encrypted_payload_final);

    if (cose_result != T_COSE_SUCCESS) {
        return(cose_result);
    }

    if ((context->option_flags & T_COSE_OPT_COSE_ENCRYPT_DETACHED) == 0) {
        /* Embed ciphertext */
        QCBOREncode_AddBytes(&encrypt_ctx,
                             (struct q_useful_buf_c)
                                {
                                  .len = encrypted_payload_final->len,
                                  .ptr = encrypted_payload_final->ptr
                                }
                            );
    }

    /* COSE_Encrypt0 does contain a recipient structure. Furthermore, there
     * is no function pointer associated with context->recipient_ctx.recipient_func.
     *
     * COSE_Encrypt, however, requires a recipient structure. Here we add it.
     */
    if ( (context->option_flags & T_COSE_OPT_COSE_ENCRYPT0) == 0) {
        cose_result = context->recipient_ctx.recipient_func(
                                    &context->recipient_ctx,
                                    context->cose_algorithm_id,
                                    context->recipient_ctx.recipient_key,
                                    random_result,
                                    &encrypt_ctx);

        if (cose_result != T_COSE_SUCCESS) {
            return(cose_result);
        }
    }

     /* Close COSE_Encrypt/COSE_Encrypt0 array */
    QCBOREncode_CloseArray(&encrypt_ctx);

    /* Export COSE_Encrypt structure */
    ret = QCBOREncode_Finish(&encrypt_ctx, result);

    if (ret != QCBOR_SUCCESS) {
        return(T_COSE_ERR_FAIL);
    }

    return(T_COSE_SUCCESS);
}

enum t_cose_err_t
t_cose_encrypt_add_recipient(struct t_cose_encrypt_enc_ctx* context,
                             int32_t                        cose_algorithm_id,
                             struct t_cose_key              recipient_key,
                             struct q_useful_buf_c          kid)
{
    enum t_cose_err_t result;

    /* Init recipient */
    result = t_cose_encrypt_recipient_init(&context->recipient_ctx,
                                           0,
                                           cose_algorithm_id);
    if (result != T_COSE_SUCCESS) {
        return(result);
    }

    /* Set recipient key */
    t_cose_encrypt_set_recipient_key(&context->recipient_ctx,
                                     recipient_key,
                                     kid);

    return(T_COSE_SUCCESS);
}
