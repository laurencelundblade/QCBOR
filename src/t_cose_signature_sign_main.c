/*
 * t_cose_signature_sign_main.c
 *
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * Created by Laurence Lundblade on 5/23/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor_encode.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_signature_main.h"
#include "t_cose/t_cose_signature_sign_main.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"
#include "t_cose_crypto.h"


/** This is an implementation of \ref t_cose_signature_sign_headers_cb */
static void
t_cose_signature_sign_headers_main_cb(struct t_cose_signature_sign   *me_x,
                                      struct t_cose_parameter       **params)
{
    struct t_cose_signature_sign_main *me =
                                    (struct t_cose_signature_sign_main *)me_x;

    me->local_params[0]  = t_cose_param_make_alg_id(me->cose_algorithm_id);
    if(!q_useful_buf_c_is_null(me->kid)) {
        me->local_params[1] = t_cose_param_make_kid(me->kid);
        me->local_params[0].next = &me->local_params[1];
    }

    *params = me->local_params;
}


/** This is an implementation of \ref t_cose_signature_sign_cb */
static enum t_cose_err_t
t_cose_signature_sign1_main_cb(struct t_cose_signature_sign     *me_x,
                               const struct t_cose_sign_inputs *sign_inputs,
                               QCBOREncodeContext              *cbor_encoder)
{
    struct t_cose_signature_sign_main *me =
                                     (struct t_cose_signature_sign_main *)me_x;
    enum t_cose_err_t           return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB( buffer_for_tbs_hash, T_COSE_MAIN_MAX_HASH_SIZE);
    struct q_useful_buf         buffer_for_signature;
    struct q_useful_buf_c       tbs_hash;
    struct q_useful_buf_c       signature;

    /* Check encoder state before QCBOREncode_OpenBytes() for sensible
     * error reporting. */
    return_value = qcbor_encode_error_to_t_cose_error(cbor_encoder);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* The signature gets written directly into the output buffer.
     * The matching QCBOREncode_CloseBytes call further down still
     * needs do a memmove to make space for the CBOR header, but
     * at least we avoid the need to allocate an extra buffer.
     */
    QCBOREncode_OpenBytes(cbor_encoder, &buffer_for_signature);

    if (QCBOREncode_IsBufferNULL(cbor_encoder)) {
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
         * t_cose_sign_init() so it doesn't need to be checked here.
         */
        return_value = create_tbs_hash(me->cose_algorithm_id,
                                       sign_inputs,
                                       buffer_for_tbs_hash,
                                      &tbs_hash);
        if(return_value) {
            goto Done;
        }

        return_value = t_cose_crypto_sign(me->cose_algorithm_id,
                                          me->signing_key,
                                          me->crypto_context,
                                          tbs_hash,
                                          buffer_for_signature,
                                         &signature);
    }
    QCBOREncode_CloseBytes(cbor_encoder, signature.len);

Done:
    return return_value;
}


/** This is an implementation of \ref t_cose_signature_sign1_cb */
static enum t_cose_err_t
t_cose_signature_sign_main_cb(struct t_cose_signature_sign  *me_x,
                              struct t_cose_sign_inputs     *sign_inputs,
                              QCBOREncodeContext            *cbor_encoder)
{
#ifndef T_COSE_DISABLE_COSE_SIGN
    struct t_cose_signature_sign_main *me =
                                     (struct t_cose_signature_sign_main *)me_x;
    enum t_cose_err_t         return_value;
    struct t_cose_parameter  *parameters;

    /* Array that holds a COSE_Signature */
    QCBOREncode_OpenArray(cbor_encoder);

    /* -- The headers for a COSE_Sign -- */
    t_cose_signature_sign_headers_main_cb(me_x, &parameters);
    t_cose_params_append(&parameters, me->added_signer_params);
    t_cose_headers_encode(cbor_encoder,
                          parameters,
                          &sign_inputs->sign_protected);

    /* The actual signature (this runs hash and public key crypto) */
    return_value = t_cose_signature_sign1_main_cb(me_x,
                                                  sign_inputs,
                                                  cbor_encoder);

    /* Close the array for the COSE_Signature */
    QCBOREncode_CloseArray(cbor_encoder);

    return return_value;

#else /* !T_COSE_DISABLE_COSE_SIGN */

    (void)me_x;
    (void)sign_inputs;
    (void)cbor_encoder;

    return T_COSE_ERR_UNSUPPORTED;
#endif /* !T_COSE_DISABLE_COSE_SIGN */
}


void
t_cose_signature_sign_main_init(struct t_cose_signature_sign_main *me,
                                const int32_t               cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
    me->s.rs.ident        = RS_IDENT(TYPE_RS_SIGNER, 'M');
    me->s.headers_cb      = t_cose_signature_sign_headers_main_cb;
    me->s.sign_cb         = t_cose_signature_sign_main_cb;
    me->s.sign1_cb        = t_cose_signature_sign1_main_cb;
    me->cose_algorithm_id = cose_algorithm_id;
}
