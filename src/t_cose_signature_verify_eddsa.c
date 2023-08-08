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
t_cose_signature_verify_eddsa_cb(struct t_cose_signature_verify *me_x,
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

    /* --- Check the algorithm --- */
    cose_algorithm_id = t_cose_param_find_alg_id(parameter_list, true);
    if(cose_algorithm_id == T_COSE_ALGORITHM_NONE) {
        return_value = T_COSE_ERR_NO_ALG_ID;
        goto Done;
    }
    if(cose_algorithm_id != T_COSE_ALGORITHM_EDDSA) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }


    /* --- Serialize the bytes to be verified --- */
    /* We need to serialize the Sig_structure (rather than hashing it
     * incrementally) before signing because of the way EdDSA works. This serves both for size
     * calculation of the aux buffer and for creating the
     * an actual Sig_structure. create_tbs() supports a NULL
     * auxiliary_buffer for size calculation mode.
     */
    return_value = create_tbs(sign_inputs,
                              me->auxiliary_buffer,
                             &tbs);
    if (return_value == T_COSE_ERR_TOO_SMALL) {
        /* Be specific about which buffer is too small */
        return_value = T_COSE_ERR_AUXILIARY_BUFFER_SIZE;
    }
    if (return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --- Record aux buf size --- */
    /* Record how much buffer we actually used / would have used,
     * allowing the caller to allocate an appropriately sized buffer.
     * This is particularly useful in DECODE_ONLY mode. This
     * might have to verify multiple signatures of different sizes
     * so the size recorded is the max size.
     */
    if(me->auxiliary_buffer_size == SIZE_MAX || tbs.len > me->auxiliary_buffer_size) {
        me->auxiliary_buffer_size = tbs.len;
    }

    if(option_flags & T_COSE_OPT_DECODE_ONLY) {
        return_value = T_COSE_SUCCESS;
        goto Done;
    }

    if(me->auxiliary_buffer.ptr == NULL) {
        return_value = T_COSE_ERR_NEED_AUXILIARY_BUFFER;
        goto Done;
    }


    /* --- Check kid --- */
    /* Kid verification is not done in decode only mode. */
    kid = t_cose_param_find_kid(parameter_list);
    if(!q_useful_buf_c_is_null(me->verification_kid)) {
        if(q_useful_buf_c_is_null(kid)) {
            return T_COSE_ERR_NO_KID;
        }
        if(q_useful_buf_compare(kid, me->verification_kid)) {
            return T_COSE_ERR_KID_UNMATCHED;
        }
    }

    /* -- Verify the signature -- */
    return_value = t_cose_crypto_verify_eddsa(me->verification_key,
                                              NULL,
                                              tbs,
                                              signature);

Done:
    return return_value;
}




/*
 * Public function. See t_cose_signature_verify_eddsa.h
 */
void
t_cose_signature_verify_eddsa_init(struct t_cose_signature_verify_eddsa *me,
                                   uint32_t option_flags)
{
    memset(me, 0, sizeof(*me));
    me->s.rs.ident   = RS_IDENT(TYPE_RS_VERIFIER, 'E');
    me->s.verify_cb  = t_cose_signature_verify_eddsa_cb;
    me->option_flags = option_flags;

    /* Start with large (but NULL) auxiliary buffer.
     * The Sig_Structure data will be serialized in it.
     */
    me->auxiliary_buffer.len = SIZE_MAX;
}
