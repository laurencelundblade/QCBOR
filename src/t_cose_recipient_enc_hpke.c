/**
 * \file t_cose_recipient_enc_hpke.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#ifndef T_COSE_DISABLE_HPKE

#include <stdint.h>
#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_recipient_enc.h"
#include "t_cose/t_cose_recipient_enc_hpke.h" /* Interface implemented */
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_crypto.h"
#include "hpke.h"
#include "t_cose_util.h"


/**
 * \brief HPKE Encrypt Wrapper
 *
 * \param[in] suite               HPKE ciphersuite
 * \param[in] pkR                 pkR buffer
 * \param[in] pkE                 pkE buffer
 * \param[in] plaintext           Plaintext buffer
 * \param[in] ciphertext          Ciphertext buffer
 * \param[out] ciphertext_len     Length of the produced ciphertext
 *
 * \retval T_COSE_SUCCESS
 *         HPKE encrypt operation was successful.
 * \retval T_COSE_ERR_HPKE_ENCRYPT_FAIL
 *         Encrypt operation failed.
 */

enum t_cose_err_t
t_cose_crypto_hpke_encrypt(struct t_cose_crypto_hpke_suite_t  suite,
                           struct q_useful_buf_c              pkR,
                           struct t_cose_key                  pkE,
                           struct q_useful_buf_c              aad,
                           struct q_useful_buf_c              plaintext,
                           struct q_useful_buf                ciphertext,
                           size_t                             *ciphertext_len)
{
    int             ret;
    hpke_suite_t    hpke_suite;

    hpke_suite.aead_id = suite.aead_id;
    hpke_suite.kdf_id = suite.kdf_id;
    hpke_suite.kem_id = suite.kem_id;

    ret = mbedtls_hpke_encrypt(
            HPKE_MODE_BASE,                     // HPKE mode
            hpke_suite,                         // ciphersuite
            NULL, 0, NULL,                      // PSK
            pkR.len,                            // pkR length
            pkR.ptr,                            // pkR
            0,                                  // skI
            plaintext.len,                      // plaintext length
            plaintext.ptr,                      // plaintext
            //TODO: fix the const-ness all the way down so this cast can go away
            aad.len, (uint8_t *)(uintptr_t)aad.ptr,         // Additional data
            0, NULL,                            // Info
            (psa_key_handle_t)
            pkE.key.handle,                   // skE handle
            0, NULL,                            // pkE
            ciphertext_len,                     // ciphertext length
            (uint8_t *) ciphertext.ptr);        // ciphertext

    if (ret != 0) {
        return(T_COSE_ERR_HPKE_ENCRYPT_FAIL);
    }

    return(T_COSE_SUCCESS);
}


/*
 * See documentation in t_cose_recipient_enc_hpke.h
 */
enum t_cose_err_t
t_cose_recipient_create_hpke_cb_private(struct t_cose_recipient_enc  *me_x,
                                        struct q_useful_buf_c         cek,
                                        QCBOREncodeContext           *cbor_encoder)
{
    struct q_useful_buf_c  proteced_params;
    uint8_t                encrypted_cek[T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_MAX_SYMMETRIC_KEY_LENGTH)];
    size_t                 encrypted_cek_len = T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_MAX_SYMMETRIC_KEY_LENGTH);
    struct q_useful_buf_c  cek_encrypted_cbor;
    size_t                 pkR_len = T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE;
    uint8_t                pkR[T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE] = {0};
    size_t                 pkE_len = T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE;
    uint8_t                pkE[T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE] = {0};
    enum t_cose_err_t      return_value;
    struct t_cose_key      ephemeral_key;
    MakeUsefulBufOnStack(  enc_struct_buf, 50); // TODO: allow this to be
                                                // supplied externally
    struct q_useful_buf_c  enc_struct;
    struct t_cose_recipient_enc_hpke *context;

    context = (struct t_cose_recipient_enc_hpke *)me_x;

    /* Create ephemeral key */
    return_value = t_cose_crypto_generate_key(&ephemeral_key,
                                              context->hpke_suite.kem_id);
    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* Export pkR */
    return_value = t_cose_crypto_export_public_key(
                         context->pkR,
                         (struct q_useful_buf) {.ptr=pkR, .len=pkR_len},
                         &pkR_len);

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* Export pkE */
    return_value = t_cose_crypto_export_public_key(
                         ephemeral_key,
                         (struct q_useful_buf) {.ptr=pkE, .len=pkE_len},
                         &pkE_len);

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* There's an odd order dependency here.
     * First get started encoding and output/make the protected header.
     * Then, before outputting the unprotected header, make the Enc_structure
     * and do the HPKE encrypt. This requires the protected headers as input.
     * This will produce the HPKE "enc" value.
     * Then the unprotected headers which includes the "enc"
     * value can be output. This is going to be a problem with encode_headers().
     * The fix is to break up HPKE into two parts. */

    /* Create recipient array */
    QCBOREncode_OpenArray(cbor_encoder);

    /* Add protected headers with alg parameter */
    QCBOREncode_BstrWrap(cbor_encoder);

    QCBOREncode_OpenMap(cbor_encoder);

    QCBOREncode_AddInt64ToMapN(cbor_encoder,
                               T_COSE_HEADER_PARAM_ALG,
                               T_COSE_ALGORITHM_HPKE_v1_BASE);

    QCBOREncode_CloseMap(cbor_encoder);

    QCBOREncode_CloseBstrWrap2(cbor_encoder,
                               false,
                               &proteced_params);


    /* --- Make the Enc_structure ---- */

    return_value = create_enc_structure("Enc_Recipient",/* in: context string */
                         proteced_params,
                         NULL_Q_USEFUL_BUF_C, /* in: Externally supplied AAD */
                         enc_struct_buf,
                         &enc_struct);


    /* --- HPKE encryption of the CEK ---- */
    return_value = t_cose_crypto_hpke_encrypt(
                        context->hpke_suite,
                        (struct q_useful_buf_c) {.ptr = pkR, .len = pkR_len},
                        ephemeral_key,
                        enc_struct,
                        cek,
                        (struct q_useful_buf) {.ptr = encrypted_cek,
                                               .len = encrypted_cek_len},
                        &encrypted_cek_len);

    t_cose_crypto_free_symmetric_key(ephemeral_key); // TODO: free method for generate key

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* Add unprotected Header */
    QCBOREncode_OpenMap(cbor_encoder);

    /* Create HPKE_sender_info structure
     *
     *  HPKE_sender_info = [
     *     kem_id : uint,       ; kem identifier
     *     kdf_id : uint,       ; kdf identifier
     *     aead_id : uint,      ; aead identifier
     *     enc : bstr,          ; encapsulated key
     *  ]
     */
    /* Open HPKE_sender_info array */
    QCBOREncode_OpenArrayInMapN(cbor_encoder,
                                T_COSE_HEADER_ALG_PARAM_HPKE_SENDER_INFO);

    /* -- add kem id */
    QCBOREncode_AddUInt64(cbor_encoder,
                          context->hpke_suite.kem_id);

    /* -- add kdf id */
    QCBOREncode_AddUInt64(cbor_encoder,
                          context->hpke_suite.kdf_id);

    /* -- add aead id */
    QCBOREncode_AddUInt64(cbor_encoder,
                          context->hpke_suite.aead_id);

    /* -- add enc */
    QCBOREncode_AddBytes(cbor_encoder,
                         (struct q_useful_buf_c)
                         {
                           pkE,
                           pkE_len
                         }
                        );

    /* Close HPKE_sender_info array */
    QCBOREncode_CloseArray(cbor_encoder);


    /* Add kid to unprotected map  */
    QCBOREncode_AddBytesToMapN(cbor_encoder,
                               T_COSE_HEADER_PARAM_KID,
                               context->kid);

    /* Close unprotected map */
    QCBOREncode_CloseMap(cbor_encoder);

    /* Convert to UsefulBufC structure */
    cek_encrypted_cbor.len = encrypted_cek_len;
    cek_encrypted_cbor.ptr = encrypted_cek;

    /* Add encrypted CEK */
    QCBOREncode_AddBytes(cbor_encoder, cek_encrypted_cbor);

    /* Close recipient array */
    QCBOREncode_CloseArray(cbor_encoder);

    return(T_COSE_SUCCESS);
}


#else

/* Place holder for compiler tools that don't like files with no functions */
void t_cose_recipient_enc_hpke_placeholder(void) {}

#endif /* T_COSE_DISABLE_HPKE */
