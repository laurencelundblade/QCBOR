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
 * \brief Type definition of function used to verify a COSE_Signature in a COSE_Sign.
 *
 * \param[in] me               The context, the  t_cose_signature_verify
 *                             instance. This  will actully be some thing like
 *                             t_cose_signature_verify_main that inplements
 *                             t_cose_signature_verify.
 * \param[in] option_flags     Option flags from t_cose_sign_verify_init().
 *                             Mostly for \ref T_COSE_OPT_DECODE_ONLY.
 * \param[in] loc              The location of the signature inside the
 *                             COSE_Sign.
 * \param[in] sign_inputs      Payload, aad and header parameters to verify.
 * \param[in] params           The place to put the decoded params.
 * \param[in] qcbor_decoder    The decoder instance from where the
 *                             COSE_Signature is decoded.
 * \param[out] decoded_params  Returned linked list of decoded parameters.
 *
 * This must return T_COSE_ERR_NO_MORE if there are no more COSE_Signatures.
 */
typedef enum t_cose_err_t
t_cose_signature_verify_cb(struct t_cose_signature_verify     *me,
                           uint32_t                            option_flags,
                           const struct t_cose_header_location loc,
                           struct t_cose_sign_inputs          *sign_inputs,
                           struct t_cose_parameter_storage    *params,
                           QCBORDecodeContext                 *qcbor_decoder,
                           struct t_cose_parameter           **decoded_params);


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
 * This is very different from t_cose_signature_verify_cb()
 * because there is no header decoding to be done. Instead the headers
 * are decoded outside of this and passed in.
 */
typedef enum t_cose_err_t
t_cose_signature_verify1_cb(struct t_cose_signature_verify *me,
                            uint32_t                        option_flags,
                            const struct t_cose_sign_inputs *sign_inputs,
                            const struct t_cose_parameter  *parameter_list,
                            const struct q_useful_buf_c     signature);


/**
 * Data structure that must be the first part of every context of every concrete
 * implementation of t_cose_signature_verify. Callback functions must not
 * be NULL, but can be stubs that return an error when COSE_SIgn1 or COSE_Sign
 * are not supported.
 */
struct t_cose_signature_verify {
    struct t_cose_rs_obj             rs;
    t_cose_signature_verify_cb      *verify_cb;
    t_cose_signature_verify1_cb     *verify1_cb;
};


#endif /* t_cose_signature_verify_h */
