/*
 * t_cose_signature_verify.h
 *
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 * Created by Laurence Lundblade on 7/17/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_signature_verify_h
#define t_cose_signature_verify_h

#include "t_cose/t_cose_parameters.h"


/*
 * This is the abstract base class that t_cose_sign_verify
 * calls to run signature verification. A concrete
 * implementation of this must be created in actual use.
 *
 * Verifiers can do just a little or quite a lot. The
 * minimum would probably be verification of only COSE_Sign1
 * and only one key. A large verifier might support
 * look up in a key database, multiple algorithms,
 * and maybe even complex add-ons that manifest
 * as additional header parameters in a COSE_Signature.
 *
 */
struct t_cose_signature_verify;


/**
 * \brief Type definition of function to verify the bare signature in COSE_Sign1.
 *
 * \param[in] me              The context, the  t_cose_signature_verify
 *                            instance. This  will actully be some thing like
 *                            t_cose_signature_verify_main that inplements
 *                            t_cose_signature_verify.
 * \param[in] option_flags    Option flags from t_cose_sign_verify_init().
 *                            Mostly for \ref T_COSE_OPT_DECODE_ONLY.
 * \param[in] sign_inputs     Payload, aad and header parameters to verify.
 * \param[in] parameter_list  Parameter list in which algorithm and kid is
 *                            found.
 * \param[in] signature       The signature.
 *
 * This runs the crypto to actually verify a signature. The decoded headers are
 * passed in \c parameter_list.
 */
typedef enum t_cose_err_t
t_cose_signature_verify1_cb(struct t_cose_signature_verify *me,
                            uint32_t                        option_flags,
                            const struct t_cose_sign_inputs *sign_inputs,
                            const struct t_cose_parameter  *parameter_list,
                            const struct q_useful_buf_c     signature);


/**
 * Data structure that must be the first part of every context of
 * every concrete implementation of t_cose_signature_verify. \c
 * verify_cb must not be \c NULL. Header parameter decoding for
 * integer and string parameters is done automatically. \c
 * special_param_decode_cb should be non-NULL if there are non-integer
 * or non-string parameters to decode.  \c special_param_decode_ctx is
 * only passed to \c special_param_decode_cb so it may or may not by
 * NULL as needed.
 */
struct t_cose_signature_verify {
    struct t_cose_rs_obj             rs;
    t_cose_signature_verify1_cb     *verify_cb;
    t_cose_param_special_decode_cb  *special_param_decode_cb;
    void                            *special_param_decode_ctx;
};


#endif /* t_cose_signature_verify_h */
