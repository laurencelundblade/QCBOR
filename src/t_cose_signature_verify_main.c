/*
 * t_cose_signature_verify_main.c
 *
 * Copyright (c) 2022-2023, Laurence Lundblade. All rights reserved.
 * Created by Laurence Lundblade on 7/19/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_signature_verify_main.h"
#include "t_cose/t_cose_signature_verify.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"
#include "t_cose_crypto.h"




/* The list of algorithms supported by this verifier. */
static bool
sig_algorithm_check(int32_t cose_algorithm_id)
{
    static const int32_t supported_algorithms[] = {
#ifndef T_COSE_DISABLE_PS256
        T_COSE_ALGORITHM_PS256,
#endif
#ifndef T_COSE_DISABLE_PS384
        T_COSE_ALGORITHM_PS384,
#endif
#ifndef T_COSE_DISABLE_PS512
        T_COSE_ALGORITHM_PS512,
#endif
        T_COSE_ALGORITHM_ES256,
#ifndef T_COSE_DISABLE_ES384
        T_COSE_ALGORITHM_ES384,
#endif
#ifndef T_COSE_DISABLE_ES512
        T_COSE_ALGORITHM_ES512,
#endif
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
        T_COSE_ALGORITHM_SHORT_CIRCUIT_256,
        T_COSE_ALGORITHM_SHORT_CIRCUIT_384,
        T_COSE_ALGORITHM_SHORT_CIRCUIT_512,
#endif
        T_COSE_ALGORITHM_NONE
    };

    return t_cose_check_list(cose_algorithm_id, supported_algorithms);
}


/** This is an implementation of \ref t_cose_signature_verify1_cb. */
static enum t_cose_err_t
t_cose_signature_verify1_main_cb(struct t_cose_signature_verify   *me_x,
                                 const uint32_t                   option_flags,
                                 const struct t_cose_sign_inputs *sign_inputs,
                                 const struct t_cose_parameter   *parameter_list,
                                 const struct q_useful_buf_c      signature)
{
    const struct t_cose_signature_verify_main *me =
                          (const struct t_cose_signature_verify_main *)me_x;
    int32_t                      cose_algorithm_id;
    enum t_cose_err_t            return_value;
    struct q_useful_buf_c        kid;
    Q_USEFUL_BUF_MAKE_STACK_UB(  tbs_hash_buffer, T_COSE_CRYPTO_MAX_HASH_SIZE);
    struct q_useful_buf_c        tbs_hash;

    /* --- Get the parameters values needed --- */
    cose_algorithm_id = t_cose_find_parameter_alg_id(parameter_list, true);
    if(cose_algorithm_id == T_COSE_ALGORITHM_NONE) {
        return_value = T_COSE_ERR_NO_ALG_ID;
        goto Done;
    }

    if(!sig_algorithm_check(cose_algorithm_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    if(option_flags & T_COSE_OPT_DECODE_ONLY) {
        /* It's mainly EdDSA, not this, that runs when only decoding */
        return T_COSE_SUCCESS;
    }

    kid = t_cose_find_parameter_kid(parameter_list);
    if(!q_useful_buf_c_is_null(me->verification_kid)) {
        if(q_useful_buf_c_is_null(kid)) {
            return T_COSE_ERR_NO_KID;
        }
        if(q_useful_buf_compare(kid, me->verification_kid)) {
            return T_COSE_ERR_KID_UNMATCHED;
        }
    }

    /* --- Compute the hash of the to-be-signed bytes -- */
    return_value = create_tbs_hash(cose_algorithm_id,
                                   sign_inputs,
                                   tbs_hash_buffer,
                                   &tbs_hash);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* -- Verify the signature -- */
    return_value = t_cose_crypto_verify(cose_algorithm_id,
                                        me->verification_key,
                                        kid,
                                        me->crypto_context,
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

 This is an implementation of t_cose_signature_verify_cb
 */

/** This is an implementation of \ref t_cose_signature_verify_cb. */
static enum t_cose_err_t
t_cose_signature_verify_main_cb(struct t_cose_signature_verify  *me_x,
                                const uint32_t                  option_flags,
                                const struct t_cose_header_location loc,
                                struct t_cose_sign_inputs       *sign_inputs,
                                struct t_cose_parameter_storage *param_storage,
                                QCBORDecodeContext              *qcbor_decoder,
                                struct t_cose_parameter        **decoded_params)
{
    const struct t_cose_signature_verify_main *me =
                            (const struct t_cose_signature_verify_main *)me_x;
    QCBORError             qcbor_error;
    enum t_cose_err_t      return_value;
    struct q_useful_buf_c  protected_parameters;
    struct q_useful_buf_c  signature;

    /* --- Decode the COSE_Signature ---*/
    QCBORDecode_EnterArray(qcbor_decoder, NULL);
    qcbor_error = QCBORDecode_GetError(qcbor_decoder);
    if(qcbor_error == QCBOR_ERR_NO_MORE_ITEMS) {
        return T_COSE_ERR_NO_MORE;
    }
    // TODO: make sure other errors are processed correctly by fall through here

    return_value = t_cose_headers_decode(qcbor_decoder,
                                         loc,
                                         me->param_decode_cb,
                                         me->param_decode_cb_context,
                                         param_storage,
                                         decoded_params,
                                        &protected_parameters);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    sign_inputs->sign_protected = protected_parameters;

    /* --- The signature --- */
    QCBORDecode_GetByteString(qcbor_decoder, &signature);

    QCBORDecode_ExitArray(qcbor_decoder);
    qcbor_error = QCBORDecode_GetError(qcbor_decoder);
    if(qcbor_error != QCBOR_SUCCESS) {
        return_value = qcbor_decode_error_to_t_cose_error(qcbor_error, T_COSE_ERR_SIGNATURE_FORMAT);
        goto Done;
    }
    /* --- Done decoding the COSE_Signature --- */


    return_value = t_cose_signature_verify1_main_cb(me_x,
                                                    option_flags,
                                                    sign_inputs,
                                                   *decoded_params,
                                                    signature);
Done:
    return return_value;
}


void
t_cose_signature_verify_main_init(struct t_cose_signature_verify_main *me)
{
    memset(me, 0, sizeof(*me));
    me->s.rs.ident = RS_IDENT(TYPE_RS_VERIFIER, 'm');
    me->s.verify_cb  = t_cose_signature_verify_main_cb;
    me->s.verify1_cb = t_cose_signature_verify1_main_cb;
}
