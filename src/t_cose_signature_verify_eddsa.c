/*
 * t_cose_signature_verify_eddsa.c
 *
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 * Created by Laurence Lundblade on 11/19/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_signature_verify_eddsa.h"
#include "t_cose/t_cose_signature_verify.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"
#include "t_cose_crypto.h"


/** This is an implementation of \ref t_cose_signature_verify1_cb. */
static enum t_cose_err_t
t_cose_signature_verify1_eddsa_cb(struct t_cose_signature_verify *me_x,
                                  const uint32_t                  option_flags,
                                  const struct t_cose_sign_inputs *sign_inputs,
                                  const struct t_cose_parameter  *parameter_list,
                                  const struct q_useful_buf_c     signature)
{
    struct t_cose_signature_verify_eddsa *me =
                          (struct t_cose_signature_verify_eddsa *)me_x;
    int32_t                      cose_algorithm_id;
    enum t_cose_err_t            return_value;
    struct q_useful_buf_c        kid;
    struct q_useful_buf_c        tbs;

    /* --- Get the parameters values needed --- */
    cose_algorithm_id = t_cose_param_find_alg_id(parameter_list, true);
    if(cose_algorithm_id == T_COSE_ALGORITHM_NONE) {
        return_value = T_COSE_ERR_NO_ALG_ID;
        goto Done;
    }
    if(cose_algorithm_id != T_COSE_ALGORITHM_EDDSA) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    kid = t_cose_param_find_kid(parameter_list);
    if(!q_useful_buf_c_is_null(me->verification_kid)) {
        if(q_useful_buf_c_is_null(kid)) {
            return T_COSE_ERR_NO_KID;
        }
        if(q_useful_buf_compare(kid, me->verification_kid)) {
            return T_COSE_ERR_KID_UNMATCHED;
        }
    }

    /* We need to serialize the Sig_structure (rather than hashing it
     * incrementally) before signing. We do this before checking for
     * the DECODE_ONLY option, as this allows the caller to discover
     * the necessary buffer size (create_tbs supports a NULL
     * auxiliary_buffer, and we record the size the structure would
     * have occupied).
     */
    return_value = create_tbs(sign_inputs,
                              me->auxiliary_buffer,
                             &tbs);
    if (return_value == T_COSE_ERR_TOO_SMALL) {
        /* Be a bit more specific about which buffer is too small */
        return_value = T_COSE_ERR_AUXILIARY_BUFFER_SIZE;
    }
    if (return_value) {
        goto Done;
    }

    /* -- Verify the signature -- */
    /* Record how much buffer we actually used / would have used,
     * allowing the caller to allocate an appropriately sized buffer.
     * This is particularly useful in DECODE_ONLY mode.
     */
    me->auxiliary_buffer_size = tbs.len;

    if(option_flags & T_COSE_OPT_DECODE_ONLY) {
        return_value = T_COSE_SUCCESS;
        goto Done;
    }

    if (me->auxiliary_buffer.ptr == NULL) {
        return_value = T_COSE_ERR_NEED_AUXILIARY_BUFFER;
        goto Done;
    }

    return_value = t_cose_crypto_verify_eddsa(me->verification_key,
                                              NULL,
                                              tbs,
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

 This is an implementation of t_cose_signature_verify_callback
 */
/** This is an implementation of \ref t_cose_signature_verify_cb. It will
 * decode a COSE_Signature and if the algorithm is EdDSA it will verify it.
 * It will also decode all headers and return them in a linked list.
 */
static enum t_cose_err_t
t_cose_signature_verify_eddsa_cb(struct t_cose_signature_verify  *me_x,
                                 const uint32_t                   option_flags,
                                 const struct t_cose_header_location loc,
                                 struct t_cose_sign_inputs       *sign_inputs,
                                 struct t_cose_parameter_storage *param_storage,
                                 QCBORDecodeContext             *cbor_decoder,
                                 struct t_cose_parameter       **decoded_params)
{
#ifndef T_COSE_DISABLE_COSE_SIGN
    const struct t_cose_signature_verify_eddsa *me =
                            (const struct t_cose_signature_verify_eddsa *)me_x;
    QCBORError             qcbor_error;
    enum t_cose_err_t      return_value;
    struct q_useful_buf_c  protected_parameters;
    struct q_useful_buf_c  signature;

    /* --- Decode the COSE_Signature ---*/
    QCBORDecode_EnterArray(cbor_decoder, NULL);
    qcbor_error = QCBORDecode_GetError(cbor_decoder);
    if(qcbor_error == QCBOR_ERR_NO_MORE_ITEMS) {
        return T_COSE_ERR_NO_MORE;
    }

    return_value = t_cose_headers_decode(cbor_decoder,
                                         loc,
                                         me->special_param_decode_cb,
                                         me->special_param_decode_ctx,
                                         param_storage,
                                         decoded_params,
                                        &protected_parameters);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    sign_inputs->sign_protected = protected_parameters;

    /* --- The signature --- */
    QCBORDecode_GetByteString(cbor_decoder, &signature);

    QCBORDecode_ExitArray(cbor_decoder);
    qcbor_error = QCBORDecode_GetError(cbor_decoder);
    if(qcbor_error != QCBOR_SUCCESS) {
        return_value = qcbor_decode_error_to_t_cose_error(qcbor_error, T_COSE_ERR_SIGNATURE_FORMAT);
        goto Done;
    }
    /* --- Done decoding the COSE_Signature --- */

    return_value = t_cose_signature_verify1_eddsa_cb(me_x,
                                                     option_flags,
                                                     sign_inputs,
                                                    *decoded_params,
                                                     signature);
Done:
    return return_value;

#else /* !T_COSE_DISABLE_COSE_SIGN */

    (void)me_x;
    (void)option_flags;
    (void)loc;
    (void)sign_inputs;
    (void)param_storage;
    (void)cbor_decoder;
    (void)decoded_params;

    return T_COSE_ERR_UNSUPPORTED;
#endif /* !T_COSE_DISABLE_COSE_SIGN */
}


void
t_cose_signature_verify_eddsa_init(struct t_cose_signature_verify_eddsa *me,
                                   uint32_t option_flags)
{
    memset(me, 0, sizeof(*me));
    me->s.rs.ident   = RS_IDENT(TYPE_RS_VERIFIER, 'E');
    me->s.verify_cb   = t_cose_signature_verify_eddsa_cb;
    me->s.verify1_cb  = t_cose_signature_verify1_eddsa_cb;
    me->option_flags = option_flags;

    /* Start with large (but NULL) auxiliary buffer.
     * The Sig_Structure data will be serialized here.
     */
    me->auxiliary_buffer.len = SIZE_MAX;
}
