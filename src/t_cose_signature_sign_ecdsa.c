//
//  t_cose_signature_sign_ecdsa.c
//
//  Created by Laurence Lundblade on 5/23/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose/t_cose_signature_sign_ecdsa.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"


static void
t_cose_ecdsa_headers(struct t_cose_signature_sign  *me_x,
                     const struct t_cose_header_param **params)
{
    struct t_cose_signature_sign_ecdsa *me = (struct t_cose_signature_sign_ecdsa *)me_x;

    me->local_params[0]  = T_COSE_MAKE_ALG_ID_PARAM(me->cose_algorithm_id);
    if(!q_useful_buf_c_is_null(me->kid)) {
        // TODO: optimize this if possible
        me->local_params[1]  = T_COSE_KID_PARAM(me->kid);
        me->local_params[2]  = T_COSE_END_PARAM;
    } else  {
        me->local_params[1]  = T_COSE_END_PARAM;
    }
    *params = me->local_params;
}


/* While this is a private function, it is called externally
 as a callback via a function pointer that is set up in  t_cose_ecdsa_signer_init().  */
static enum t_cose_err_t
t_cose_ecdsa_sign(struct t_cose_signature_sign  *me_x,
                  bool                         make_cose_signature,
                  const struct q_useful_buf_c  protected_body_headers,
                  const struct q_useful_buf_c  aad,
                  const struct q_useful_buf_c  signed_payload,
                  QCBOREncodeContext          *qcbor_encoder)
{
    struct t_cose_signature_sign_ecdsa *me = (struct t_cose_signature_sign_ecdsa *)me_x;

    enum t_cose_err_t                  return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(        buffer_for_tbs_hash, T_COSE_CRYPTO_MAX_HASH_SIZE);
    Q_USEFUL_BUF_MAKE_STACK_UB(        buffer_for_signature, T_COSE_MAX_SIG_SIZE);
    struct q_useful_buf_c              tbs_hash;
    struct q_useful_buf_c              signature;
    const struct t_cose_header_param  *params_vector[3];
    struct q_useful_buf_c              signer_protected_headers;


    /* -- The headers if if is a COSE_Sign -- */
    signer_protected_headers = NULLUsefulBufC;
    if(make_cose_signature) {
        /* COSE_Sign, so making a COSE_Signature  */
        QCBOREncode_OpenArray(qcbor_encoder);

        t_cose_ecdsa_headers(me_x, &params_vector[0]);
        params_vector[1] = me->added_signer_params;
        params_vector[2] = NULL;

        t_cose_encode_headers(qcbor_encoder, params_vector, &signer_protected_headers);
    }

    /* -- The signature -- */
    if (QCBOREncode_IsBufferNULL(qcbor_encoder)) {
        /* Size calculation mode */
        signature.ptr = NULL;
        t_cose_crypto_sig_size(me->cose_algorithm_id, me->signing_key, &signature.len);

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
                                       signed_payload,
                                       aad,
                                       buffer_for_tbs_hash,
                                       &tbs_hash);
        if(return_value) {
            goto Done;
        }

        return_value = t_cose_crypto_sign(me->cose_algorithm_id,
                                          me->signing_key,
                                          tbs_hash,
                                          buffer_for_signature,
                                          &signature);
    }
    QCBOREncode_AddBytes(qcbor_encoder, signature);


    /* -- If a COSE_Sign, close of the COSE_Signature */
    if(make_cose_signature) {
        QCBOREncode_CloseArray(qcbor_encoder);
    }
    // TODO: lots of error handling

Done:
    return return_value;
}


void
t_cose_signature_sign_ecdsa_init(struct t_cose_signature_sign_ecdsa *me,
                                 int32_t                             cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
    me->s.callback        = t_cose_ecdsa_sign;
    me->s.h_callback      = t_cose_ecdsa_headers;
    me->cose_algorithm_id = cose_algorithm_id;
}
