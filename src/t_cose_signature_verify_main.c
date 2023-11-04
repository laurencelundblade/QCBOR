/*
 * t_cose_signature_verify_main.c
 *
 * Copyright (c) 2022-2023, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 * Created by Laurence Lundblade on 7/19/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_signature_main.h"
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


/**
 * \brief "Main" verifier implementation of \ref t_cose_signature_verify1_cb.
 *
 * \param[in] me_x            The context, the  t_cose_signature_verify_main
 *                            instance.
 * \param[in] option_flags    Option flags from t_cose_sign_verify_init().
 *                            Mostly for \ref T_COSE_OPT_DECODE_ONLY.
 * \param[in] sign_inputs     Payload, aad and header parameters to verify.
 * \param[in] parameter_list  Parameter list in which algorithm and kid is
 *                            found.
 * \param[in] signature       The signature.
 *
 * This does the job of calling the crypto that does a signature
 * verification. It is used as a callback for COSE_Sign1. It is also
 * called for COSE_Signatures in COSE_Sign as the work done for those
 * is similar and reusing this saves code.
 *
 * This does no CBOR decoding.
 *
 * Specifically this
 *  - Checks the algorithm ID
 *  - Checks the kid if needed
 *  - Computes the hash over the signed input
 *  - Call the signature verification alg through the crypto adaptation layer
 */
static enum t_cose_err_t
t_cose_signature_verify_main_cb(struct t_cose_signature_verify   *me_x,
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
    Q_USEFUL_BUF_MAKE_STACK_UB(  tbs_hash_buffer, T_COSE_MAIN_MAX_HASH_SIZE);
    struct q_useful_buf_c        tbs_hash;

    /* --- Get the parameters values needed --- */
    cose_algorithm_id = t_cose_param_find_alg_id_prot(parameter_list);
    if(cose_algorithm_id == T_COSE_ALGORITHM_NONE) {
        return_value = T_COSE_ERR_NO_ALG_ID;
        goto Done;
    }

    if(!sig_algorithm_check(cose_algorithm_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    if(option_flags & T_COSE_OPT_DECODE_ONLY) {
        return T_COSE_SUCCESS;
    }

    // TODO: COSE doesn't require kids to be unique. This code probably won't
    // work if they're not unique
    kid = t_cose_param_find_kid(parameter_list);
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
                                        me->crypto_context,
                                        tbs_hash,
                                        signature);
Done:
    return return_value;
}



void
t_cose_signature_verify_main_init(struct t_cose_signature_verify_main *me)
{
    memset(me, 0, sizeof(*me));
    me->s.rs.ident = RS_IDENT(TYPE_RS_VERIFIER, 'M');
    me->s.verify_cb = t_cose_signature_verify_main_cb;
}
