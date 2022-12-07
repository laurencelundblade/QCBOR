/*
 * t_cose_signature_verify_eddsa.c
 *
 * Copyright (c) 2022, Laurence Lundblade. All rights reserved.
 * Created by Laurence Lundblade on 11/19/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose/t_cose_signature_verify_eddsa.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose_crypto.h"


/* Warning: this is still early development. Documentation may be incorrect. */


/*
 * This is an implementation of t_cose_signature_verify1_callback.
 */
static enum t_cose_err_t
t_cose_signature_verify1_eddsa(struct t_cose_signature_verify *me_x,
                               const uint32_t                  option_flags,
                               const struct q_useful_buf_c     protected_body_headers,
                               const struct q_useful_buf_c     protected_signature_headers,
                               const struct q_useful_buf_c     payload,
                               const struct q_useful_buf_c     aad,
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
    cose_algorithm_id = t_cose_find_parameter_alg_id(parameter_list);
    if(cose_algorithm_id == T_COSE_ALGORITHM_NONE) {
        return_value = T_COSE_ERR_NO_ALG_ID;
        goto Done;
    }
    if(cose_algorithm_id != T_COSE_ALGORITHM_EDDSA) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    kid = t_cose_find_parameter_kid(parameter_list);

    /* We need to serialize the Sig_structure (rather than hashing it
     * incrementally) before signing. We do this before checking for
     * the DECODE_ONLY option, as this allows the caller to discover
     * the necessary buffer size (create_tbs supports a NULL
     * auxiliary_buffer, and we record the size the structure would
     * have occupied).
     */
    return_value = create_tbs(protected_body_headers,
                              aad,
                              protected_signature_headers,
                              payload,
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
                                              kid,
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
static enum t_cose_err_t
t_cose_signature_verify_eddsa_cb(struct t_cose_signature_verify  *me_x,
                              const uint32_t                      option_flags,
                              const struct t_cose_header_location loc,
                              const struct q_useful_buf_c         protected_body_headers,
                              const struct q_useful_buf_c         payload,
                              const struct q_useful_buf_c         aad,
                              struct t_cose_parameter_storage    *param_storage,
                              QCBORDecodeContext                 *qcbor_decoder,
                              struct t_cose_parameter           **decoded_signature_parameters)
{
    const struct t_cose_signature_verify_eddsa *me =
                            (const struct t_cose_signature_verify_eddsa *)me_x;
    QCBORError             qcbor_error;
    enum t_cose_err_t      return_value;
    struct q_useful_buf_c  protected_parameters;
    struct q_useful_buf_c  signature;

    /* --- Decode the COSE_Signature ---*/
    QCBORDecode_EnterArray(qcbor_decoder, NULL);

    return_value = t_cose_headers_decode(qcbor_decoder,
                                         loc,
                                         me->reader,
                                         me->reader_ctx,
                                         param_storage,
                                         decoded_signature_parameters,
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

    return_value = t_cose_signature_verify1_eddsa(me_x,
                                                  option_flags,
                                                  protected_body_headers,
                                                  protected_parameters,
                                                  payload,
                                                  aad,
                                                  *decoded_signature_parameters,
                                                  signature);
Done:
    return return_value;
}


void
t_cose_signature_verify_eddsa_init(struct t_cose_signature_verify_eddsa *me,
                                   uint32_t option_flags)
{
    memset(me, 0, sizeof(*me));
    me->s.callback   = t_cose_signature_verify_eddsa_cb;
    me->s.callback1  = t_cose_signature_verify1_eddsa;
    me->option_flags = option_flags;

    /* Start with large (but NULL) auxiliary buffer.
     * The Sig_Structure data will be serialized here.
     */
    me->auxiliary_buffer.len = SIZE_MAX;
}
