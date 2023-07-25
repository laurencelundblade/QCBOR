/*
 * t_cose_signature_sign_restart.c
 *
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 * Created by Laurence Lundblade on 5/23/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor_encode.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_signature_sign_restart.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"
#include "t_cose_crypto.h"


/** This is an implementation of \ref t_cose_signature_sign_headers_cb */
static void
t_cose_signature_sign_headers_restart_cb(struct t_cose_signature_sign   *me_x,
                                         struct t_cose_parameter       **params)
{
    struct t_cose_signature_sign_restart *me =
                                (struct t_cose_signature_sign_restart *)me_x;

    me->local_params[0] = t_cose_param_make_alg_id(me->cose_algorithm_id);

    *params = me->local_params;
}


/** This is an implementation of \ref t_cose_signature_sign_cb */
static enum t_cose_err_t
t_cose_signature_sign1_restart_cb(struct t_cose_signature_sign     *me_x,
                                  const struct t_cose_sign_inputs *sign_inputs,
                                  QCBOREncodeContext              *qcbor_encoder)
{
    struct t_cose_signature_sign_restart *me =
                                (struct t_cose_signature_sign_restart *)me_x;
    enum t_cose_err_t           return_value;
    struct q_useful_buf_c       signature;
    bool                        do_signing_step = true;

    if(!me->started) {
        me->buffer_for_tbs_hash.ptr = me->c_buffer_for_tbs_hash;
        me->buffer_for_tbs_hash.len = sizeof(me->c_buffer_for_tbs_hash);

        /* Check encoder state before QCBOREncode_OpenBytes() for sensible
         * error reporting. */
        return_value = qcbor_encode_error_to_t_cose_error(qcbor_encoder);
        if(return_value != T_COSE_SUCCESS) {
            goto Done;
        }

        /* The signature gets written directly into the output buffer.
         * The matching QCBOREncode_CloseBytes call further down still
         * needs do a memmove to make space for the CBOR header, but
         * at least we avoid the need to allocate an extra buffer.
         */
        QCBOREncode_OpenBytes(qcbor_encoder, &(me->buffer_for_signature));


        if(QCBOREncode_IsBufferNULL(qcbor_encoder)) {
            /* Size calculation mode */
            signature.ptr = NULL;
            t_cose_crypto_sig_size(me->cose_algorithm_id,
                                   me->signing_key,
                                   &signature.len);

            return_value = T_COSE_SUCCESS;
            do_signing_step = false;

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
                                           me->buffer_for_tbs_hash,
                                           &me->tbs_hash);
            if(return_value) {
                goto Done;
            }
        }
    }

    if(do_signing_step) {
        return_value = t_cose_crypto_sign_restart(
                    me->started,
                    me->cose_algorithm_id,
                    me->signing_key,
                    me->crypto_context,
                    me->tbs_hash,
                    me->buffer_for_signature,
                    &signature);
        if(return_value == T_COSE_ERR_SIG_IN_PROGRESS) {
            me->started = true;
            goto Done;
        } else {
            /* Reset the started value to enable reuse of the context */
            me->started = false;
        }
    }

    QCBOREncode_CloseBytes(qcbor_encoder, signature.len);

Done:
    return return_value;
}


/** This is an implementation of \ref t_cose_signature_sign1_cb */
static enum t_cose_err_t
t_cose_signature_sign_restart_cb(struct t_cose_signature_sign  *me_x,
                              struct t_cose_sign_inputs     *sign_inputs,
                              QCBOREncodeContext            *qcbor_encoder)
{
    (void)me_x;
    (void)sign_inputs;
    (void)qcbor_encoder;

    return T_COSE_ERR_FAIL;
}


void
t_cose_signature_sign_restart_init(struct t_cose_signature_sign_restart *me,
                                   const int32_t            cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
    me->s.rs.ident        = RS_IDENT(TYPE_RS_SIGNER, 'M');
    me->s.headers_cb      = t_cose_signature_sign_headers_restart_cb;
    me->s.sign_cb         = t_cose_signature_sign_restart_cb;
    me->s.sign1_cb        = t_cose_signature_sign1_restart_cb;
    me->cose_algorithm_id = cose_algorithm_id;
}
