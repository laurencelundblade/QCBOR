/**
 * \file t_cose_recipient_enc_aes_kw.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#include "t_cose/t_cose_recipient_enc.h"
#include "t_cose/t_cose_recipient_enc_aes_kw.h" /* Interface implemented */
#include "qcbor/qcbor.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_encrypt_enc.h"
#include <stdint.h>
#include <stdbool.h>
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_standard_constants.h"


#ifndef T_COSE_DISABLE_AES_KW
/*
 * See documentation in t_cose_recipient_enc_aes_kw.h
 */
enum t_cose_err_t t_cose_create_recipient_aes_kw(
                           void                   *ctx,
                           int32_t                 cose_algorithm_id,
                           struct t_cose_key       recipient_key,
                           struct q_useful_buf_c   plaintext,
                           QCBOREncodeContext     *encrypt_ctx)
{
    UsefulBufC             scratch;
    enum t_cose_err_t      return_value;
    enum t_cose_err_t      cose_result;
    size_t                 recipient_key_len;
    struct t_cose_encrypt_recipient_ctx *context;

    // TODO: check the algorithm ID
    (void)cose_algorithm_id;

    Q_USEFUL_BUF_MAKE_STACK_UB(recipient_key_buf, T_COSE_ENCRYPTION_MAX_KEY_LENGTH);
    Q_USEFUL_BUF_MAKE_STACK_UB(encrypted_cek, T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_ENCRYPTION_MAX_KEY_LENGTH));
    struct q_useful_buf_c  recipient_key_result={NULL,0};
    struct q_useful_buf_c  encrypted_cek_result={NULL,0};

    context=(struct t_cose_encrypt_recipient_ctx *) ctx;

    if (context == NULL || encrypt_ctx == NULL) {
        return(T_COSE_ERR_INVALID_ARGUMENT);
    }

    cose_result = t_cose_crypto_export_key(
                                    recipient_key,
                                    recipient_key_buf,
                                    &recipient_key_len);

    if (cose_result != T_COSE_SUCCESS) {
        return(cose_result);
    }

    recipient_key_result.ptr = recipient_key_buf.ptr;
    recipient_key_result.len = recipient_key_len;

    /* AES key wrap encryption */
    return_value = t_cose_crypto_kw_wrap(
                        0,
                        recipient_key_result,
                        plaintext,
                        encrypted_cek,
                        &encrypted_cek_result);

    if (return_value != T_COSE_SUCCESS) {
        return(return_value);
    }

    /* Create recipient array */
    QCBOREncode_OpenArray(encrypt_ctx);

    /* Add empty protected map encoded as bstr */
    QCBOREncode_BstrWrap(encrypt_ctx);
    QCBOREncode_CloseBstrWrap2(encrypt_ctx, false, &scratch);

    /* Add unprotected header alg and kid parameters */
    QCBOREncode_OpenMap(encrypt_ctx);

    QCBOREncode_AddInt64ToMapN(encrypt_ctx,
                               T_COSE_HEADER_PARAM_ALG,
                               context->cose_algorithm_id);

    QCBOREncode_AddBytesToMapN(encrypt_ctx,
                               T_COSE_HEADER_PARAM_KID,
                               context->kid);

    /* Close protected header map */
    QCBOREncode_CloseMap(encrypt_ctx);

    /* Add encrypted CEK */
    QCBOREncode_AddBytes(encrypt_ctx, encrypted_cek_result);

    /* Close recipient array */
    QCBOREncode_CloseArray(encrypt_ctx);

    return(T_COSE_SUCCESS);
}

#else /* T_COSE_DISABLE_AES_KW */

/* Place holder for compiler tools that don't like files with no functions */
void t_cose_recipient_enc_aes_placeholder(void) {}

#endif /* T_COSE_DISABLE_AES_KW */
