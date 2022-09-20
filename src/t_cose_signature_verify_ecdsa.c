//
//  t_cose_signature_verify_ecdsa.c
//
//  Created by Laurence Lundblade on 7/19/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose/t_cose_signature_verify_ecdsa.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose_crypto.h"

//#define T_COSE_CRYPTO_MAX_HASH_SIZE 300 // TODO: fix this

/* Warning: this is still early development. Documentation may be incorrect. */


static enum t_cose_err_t
t_cose_signature_verify1_ecdsa(struct t_cose_signature_verify *me_x,
                               const struct q_useful_buf_c       protected_body_headers,
                               const struct q_useful_buf_c       protected_signature_headers,
                               const struct q_useful_buf_c       payload,
                               const struct q_useful_buf_c       aad,
                               const struct t_cose_header_param *body_parameters,
                               const struct q_useful_buf_c       signature)
{
    int32_t                             cose_algorithm_id;
    enum t_cose_err_t                   return_value;
    struct q_useful_buf_c               kid;
    const struct t_cose_signature_verify_ecdsa *me = (const struct t_cose_signature_verify_ecdsa *)me_x;
    Q_USEFUL_BUF_MAKE_STACK_UB(         buffer_for_tbs_hash, T_COSE_CRYPTO_MAX_HASH_SIZE);
    struct q_useful_buf_c               tbs_hash;

    /* --- Get the parameters values needed here --- */
    cose_algorithm_id = t_cose_find_parameter_alg_id(body_parameters);
    if(cose_algorithm_id == T_COSE_ALGORITHM_NONE) {
        return_value = T_COSE_ERR_NO_ALG_ID;
        goto Done;
    }
    kid = t_cose_find_parameter_kid(body_parameters);

    /* --- Compute the hash of the to-be-signed bytes -- */
    return_value = create_tbs_hash(cose_algorithm_id,
                                   protected_body_headers,
                                   protected_signature_headers,
                                   aad,
                                   payload,
                                   buffer_for_tbs_hash,
                                   &tbs_hash);
    if(return_value) {
        goto Done;
    }

    /* -- Verify the signature -- */
    return_value = t_cose_crypto_verify(cose_algorithm_id,
                                        me->verification_key,
                                        kid,
                                        tbs_hash,
                                        signature);
Done:
    return return_value;

}



/*
 Returns: END_OF_HEADERS if no there are no more COSE_Signatures
          CBOR decoding error
          Error decoding the COSE_Signature (but not a COSE error)
          Signature validate
          Signature didn't validate
 */
static enum t_cose_err_t
t_cose_signature_verify_ecdsa(struct t_cose_signature_verify *me_x,
                              const bool                        run_crypto,
                              const struct header_location      loc,
                              const struct q_useful_buf_c       protected_body_headers,
                              const struct q_useful_buf_c       payload,
                              const struct q_useful_buf_c       aad,
                              const struct header_param_storage params,
                              QCBORDecodeContext               *qcbor_decoder)
{
    QCBORError             qcbor_error;
    enum t_cose_err_t      return_value;
    struct q_useful_buf_c  protected_parameters;
    struct q_useful_buf_c  signature;
    const struct t_cose_signature_verify_ecdsa *me = (const struct t_cose_signature_verify_ecdsa *)me_x;

    /* --- Decode the COSE_Signature ---*/
    QCBORDecode_EnterArray(qcbor_decoder, NULL);

    return_value = t_cose_headers_decode(qcbor_decoder,
                                         loc,
                                         me->reader,
                                         me->reader_ctx,
                                         params,
                                        &protected_parameters);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --- The signature --- */
    QCBORDecode_GetByteString(qcbor_decoder, &signature);

    QCBORDecode_ExitArray(qcbor_decoder);
    qcbor_error = QCBORDecode_GetError(qcbor_decoder);
    if(qcbor_error != QCBOR_SUCCESS) {
        return_value = qcbor_decode_error_to_t_cose_error(qcbor_error, T_COSE_ERR_SIGNATURE_FORMAT);
        goto Done;
    }
    /* --- Done decoding the COSE_Signature --- */


    if(!run_crypto) {
        goto Done;
    }

    return_value = t_cose_signature_verify1_ecdsa(me_x,
                                                  protected_body_headers,
                                                  protected_parameters,
                                                  payload,
                                                  aad,
                                                  params.storage,
                                                  signature);
Done:
    return return_value;
}


void
t_cose_signature_verify_ecdsa_init(struct t_cose_signature_verify_ecdsa *me)
{
    memset(me, 0, sizeof(*me));
    me->s.callback  = t_cose_signature_verify_ecdsa;
    me->s.callback1 = t_cose_signature_verify1_ecdsa;
}
