/*
 * t_cose_signature_sign_eddsa.c
 *
 * Copyright (c) 2022, Laurence Lundblade. All rights reserved.
 * Created by Laurence Lundblade on 11/15/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose/t_cose_signature_sign_eddsa.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"


static void
t_cose_eddsa_headers(struct t_cose_signature_sign   *me_x,
                     struct t_cose_parameter       **params)
{
    // TODO: this is the same as the main signer (formerly the ecdsa signer) reuse?
    struct t_cose_signature_sign_eddsa *me =
                                    (struct t_cose_signature_sign_eddsa *)me_x;

    me->local_params[0]  = t_cose_make_alg_id_parameter(T_COSE_ALGORITHM_EDDSA);
    if(!q_useful_buf_c_is_null(me->kid)) {
        me->local_params[1] = t_cose_make_kid_parameter(me->kid);
        me->local_params[0].next = &me->local_params[1];
    }

    *params = me->local_params;
}


/* While this is a private function, it is called externally
 * as a callback via a function pointer that is set up in
 * t_cose_eddsa_signer_init().  */
static enum t_cose_err_t
t_cose_eddsa_sign(struct t_cose_signature_sign    *me_x,
                  uint32_t                         options,
                  const struct t_cose_sign_inputs *sign_inputs,
                  QCBOREncodeContext              *qcbor_encoder)
{
    struct t_cose_signature_sign_eddsa *me =
                                     (struct t_cose_signature_sign_eddsa *)me_x;
    enum t_cose_err_t           return_value;
    struct q_useful_buf_c       tbs;
    struct q_useful_buf_c       signature;
    struct q_useful_buf_c       signer_protected_headers;
    struct t_cose_parameter    *parameters;
    struct q_useful_buf         buffer_for_signature;


    /* -- The headers if if is a COSE_Sign -- */
    signer_protected_headers = NULLUsefulBufC;
    if(T_COSE_OPT_IS_SIGN(options)) {
        /* COSE_Sign, so making a COSE_Signature  */
        QCBOREncode_OpenArray(qcbor_encoder);

        t_cose_eddsa_headers(me_x, &parameters);
        t_cose_parameter_list_append(parameters, me->added_signer_params);

        t_cose_encode_headers(qcbor_encoder,
                              parameters,
                              &signer_protected_headers);
    }

    /* Serialize the TBS data into the auxiliary buffer.
     * If auxiliary_buffer.ptr is NULL this will succeed, computing
     * the necessary size.
     */
    return_value = create_tbs(sign_inputs, me->auxiliary_buffer, &tbs);
    if (return_value == T_COSE_ERR_TOO_SMALL) {
        /* Be a bit more specific about which buffer is too small */
        return_value = T_COSE_ERR_AUXILIARY_BUFFER_SIZE;
    }
    if (return_value) {
        goto Done;
    }


    /* Record how much buffer we actually used / would have used,
     * allowing the caller to allocate an appropriately sized buffer.
     * This is particularly useful when buffer_for_signature.ptr is
     * NULL and no signing is actually taking place yet.
     */
    me->auxiliary_buffer_size = tbs.len;

    QCBOREncode_OpenBytes(qcbor_encoder, &buffer_for_signature);


    if (buffer_for_signature.ptr == NULL) {
        /* Output size calculation. Only need signature size. */
        signature.ptr = NULL;
        // TODO: an eddsa-specific size calculator?
        return_value  = t_cose_crypto_sig_size(T_COSE_ALGORITHM_EDDSA,
                                               me->signing_key,
                                               &signature.len);
    } else if (me->auxiliary_buffer.ptr == NULL) {
        /* Without a real auxiliary buffer, we have nothing to sign. */
        return_value = T_COSE_ERR_NEED_AUXILIARY_BUFFER;
    } else {
        /* Perform the public key signing over the TBS bytes we just
         * serialized.
         */
        return_value = t_cose_crypto_sign_eddsa(me->signing_key,
                                                tbs,
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
t_cose_signature_sign_eddsa_init(struct t_cose_signature_sign_eddsa *me)
{
    memset(me, 0, sizeof(*me));
    me->s.callback        = t_cose_eddsa_sign;
    me->s.h_callback      = t_cose_eddsa_headers;
}
