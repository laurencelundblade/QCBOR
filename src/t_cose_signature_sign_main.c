/*
 * t_cose_signature_sign_main.c
 *
 * Copyright (c) 2022, Laurence Lundblade. All rights reserved.
 * Created by Laurence Lundblade on 5/23/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose/t_cose_signature_sign_main.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"


static void
t_cose_main_headers(struct t_cose_signature_sign   *me_x,
                     struct t_cose_parameter       **params)
{
    struct t_cose_signature_sign_main *me =
                                    (struct t_cose_signature_sign_main *)me_x;

    me->local_params[0]  = t_cose_make_alg_id_parameter(me->cose_algorithm_id);
    if(!q_useful_buf_c_is_null(me->kid)) {
        me->local_params[1] = t_cose_make_kid_parameter(me->kid);
        me->local_params[0].next = &me->local_params[1];
    }

    *params = me->local_params;
}


/* While this is a private function, it is called externally
 * as a callback via a function pointer that is set up in
 * t_cose_ecdsa_signer_init().  */
static enum t_cose_err_t
t_cose_main_sign(struct t_cose_signature_sign  *me_x,
                  uint32_t                       options,
                  const struct q_useful_buf_c    protected_body_headers,
                  const struct q_useful_buf_c    aad,
                  const struct q_useful_buf_c    signed_payload,
                  QCBOREncodeContext            *qcbor_encoder)
{
    struct t_cose_signature_sign_main *me =
                                     (struct t_cose_signature_sign_main *)me_x;
    enum t_cose_err_t           return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB( buffer_for_tbs_hash, T_COSE_CRYPTO_MAX_HASH_SIZE);
    struct q_useful_buf         buffer_for_signature;
    struct q_useful_buf_c       tbs_hash;
    struct q_useful_buf_c       signature;
    struct q_useful_buf_c       signer_protected_headers;
    struct t_cose_parameter    *parameters;


    /* -- The headers if if is a COSE_Sign -- */
    signer_protected_headers = NULL_Q_USEFUL_BUF_C;
    if(T_COSE_OPT_IS_SIGN(options)) {
        /* COSE_Sign, so making a COSE_Signature  */
        QCBOREncode_OpenArray(qcbor_encoder);

        t_cose_main_headers(me_x, &parameters);
        t_cose_parameter_list_append(parameters, me->added_signer_params);

        t_cose_encode_headers(qcbor_encoder,
                              parameters,
                              &signer_protected_headers);
    }

    /* -- The signature -- */
    QCBOREncode_OpenBytes(qcbor_encoder, &buffer_for_signature);

    if (QCBOREncode_IsBufferNULL(qcbor_encoder)) {
        /* Size calculation mode */
        signature.ptr = NULL;
        t_cose_crypto_sig_size(me->cose_algorithm_id,
                               me->signing_key,
                               &signature.len);

        return_value = T_COSE_SUCCESS;

    } else {
        /* Run the crypto to produce the signature */

        /* Create the hash of the to-be-signed bytes. Inputs to the
         * hash are the protected parameters, the payload that is
         * getting signed, the cose signature alg from which the hash
         * alg is determined. The cose_algorithm_id was checked in
         * t_cose_sign1_init() so it doesn't need to be checked here.
         */
        return_value = create_tbs_hash(me->cose_algorithm_id,
                                       protected_body_headers,
                                       signer_protected_headers,
                                       aad,
                                       signed_payload,
                                       buffer_for_tbs_hash,
                                       &tbs_hash);
        if(return_value) {
            goto Done;
        }

        /* The signature gets written directly into the output buffer.
         * The matching QCBOREncode_CloseBytes call further down still
         * needs do a memmove to make space for the CBOR header, but
         * at least we avoid the need to allocate an extra buffer.
         */

        return_value = t_cose_crypto_sign(me->cose_algorithm_id,
                                          me->signing_key,
                                          tbs_hash,
                                          buffer_for_signature,
                                          &signature);

    }
    QCBOREncode_CloseBytes(qcbor_encoder, signature.len);


    /* -- If a COSE_Sign, close of the COSE_Signature */
    if(T_COSE_OPT_IS_SIGN(options)) {
        QCBOREncode_CloseArray(qcbor_encoder);
    }
    // TODO: lots of error handling

Done:
    return return_value;
}


void
t_cose_signature_sign_main_init(struct t_cose_signature_sign_main *me,
                                int32_t                            cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
    me->s.callback        = t_cose_main_sign;
    me->s.h_callback      = t_cose_main_headers;
    me->cose_algorithm_id = cose_algorithm_id;
}
