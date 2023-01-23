/**
 * \file t_cose_recipient_enc_aes_kw.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#include "t_cose/t_cose_recipient_enc_aes_kw.h" /* Interface implemented */
#include "qcbor/qcbor_encode.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"


#ifndef T_COSE_DISABLE_AES_KW

enum t_cose_err_t
t_cose_recipient_create_keywrap_cb_private(struct t_cose_recipient_enc  *me_x,
                                           const struct q_useful_buf_c   plaintext,
                                           QCBOREncodeContext           *cbor_encoder)
{
    struct t_cose_recipient_enc_keywrap *me;
    enum t_cose_err_t                    return_value;
    struct t_cose_parameter              params[2];
    struct q_useful_buf                  encrypted_cek_destiation;
    struct q_useful_buf_c                encrypted_cek_result;
    struct q_useful_buf_c                protected_params_not;

    me = (struct t_cose_recipient_enc_keywrap *) me_x;

    /* Create recipient array */
    QCBOREncode_OpenArray(cbor_encoder);

    /* Output the header parameters */
    params[0]  = t_cose_make_alg_id_parameter(me->keywrap_cose_algorithm_id);
    params[0].in_protected = false; /* Override t_cose_make_alg_id_parameter() because there is no protection in AES Keywrap */
    if(!q_useful_buf_c_is_null(me->kid)) {
        params[1] = t_cose_make_kid_parameter(me->kid);
        params[0].next = &params[1];
    }
    t_cose_parameter_list_append(params, me->added_params);
    // TODO: make sure no custom headers are protected because there is no protect with key wrap
    return_value = t_cose_encode_headers(cbor_encoder, params, &protected_params_not);
    if (return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    if(!q_useful_buf_c_is_null(protected_params_not)) {
        return_value = T_CODE_ERR_PROTECTED_PARAM_NOT_ALLOWED;
        goto Done;
    }

    /* Do the keywrap directly into the output buffer */
    /* t_cose_crypto_kw_wrap() will catch incorrect algorithm ID errors */
    QCBOREncode_OpenBytes(cbor_encoder, &encrypted_cek_destiation);
    return_value = t_cose_crypto_kw_wrap(me->keywrap_cose_algorithm_id,
                                         me->wrapping_key,
                                         plaintext,
                                         encrypted_cek_destiation,
                                        &encrypted_cek_result);
    QCBOREncode_CloseBytes(cbor_encoder, encrypted_cek_result.len);
    /* Error is just returned directly below and no need to skip CloseArray */

    /* Close recipient array */
    QCBOREncode_CloseArray(cbor_encoder);

Done:
    return return_value;
}

#else /* T_COSE_DISABLE_AES_KW */

/* Place holder for compiler tools that don't like files with no functions */
void t_cose_recipient_enc_aes_placeholder(void) {}

#endif /* T_COSE_DISABLE_AES_KW */
