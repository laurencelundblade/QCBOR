/*
 * t_cose_signature_verify.h
 *
 * Copyright (c) 2022, Laurence Lundblade. All rights reserved.
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
 * implementation of this is needed.
 *
 * Implementations may choose to support only COSE_Sign1,
 * only COSE_Signature/COSE_Sign or both. They are encouraged to
 * support both.
 *
 * An instance of this may be used without any verification
 * key material to decode to get the key ID or such.
 *
 * An instance of this may also be set up with key material,
 * perhaps just one key.
 *
 * An instance of this may be wired up to a key database.
 */
struct t_cose_signature_verify;


/**
 * \brief Type definition of function used to verify a COSE_Signature in a COSE_Sign.
 *
 * \param[in] me                      The context, the  t_cose_signature_verify
 *                                    instance. This  will actully be some thing like
 *                                    t_cose_signature_verify_main that inplements
 *                                    t_cose_signature_verify.
 * \param[in] option_flags          Option flags from t_cose_sign_verify_init(). Mostly for \ref T_COSE_OPT_DECODE_ONLY.
 * \param[in] loc                     The location of the signature inside the COSE_Sign.
 * \param[in] sign_inputs             Payload, aad and header parameters to verify.
 * \param[in] params                  The place to put the decoded params.
 * \param[in] qcbor_decoder           The decoder instance from where the
 *                                     COSE_Signature is decoded.
 * \param[out] decoded_signature_parameters  Linked list of decoded parameters.
 */
typedef enum t_cose_err_t
t_cose_signature_verify_callback(struct t_cose_signature_verify   *me,
                                 uint32_t                          option_flags,
                                 const struct t_cose_header_location loc,
                                 const struct t_cose_sign_inputs *sign_inputs,
                                 struct t_cose_parameter_storage  *params,
                                 QCBORDecodeContext               *qcbor_decoder,
                                 struct t_cose_parameter         **decoded_signature_parameters);


/**
 * \brief Type definition of function to verify the bare signature in COSE_Sign1.
 *
 * \param[in] me                       The context, the  t_cose_signature_verify
 *                                     instance. This  will actully be some thing like
 *                                     t_cose_signature_verify_main that inplements
 *                                     t_cose_signature_verify.
 * \param[in] option_flags          Option flags from t_cose_sign_verify_init(). Mostly for \ref T_COSE_OPT_DECODE_ONLY.
 * \param[in] sign_inputs             Payload, aad and header parameters to verify.
 * \param[in] parameter_list           Parameter list in which algorithm and kid is
 *                                     found.
 * \param[in] signature                The signature.
 *
 * This is very different from t_cose_signature_verify_callback
 * because there is no header decoding to be done. Instead the headers
 * are decoded outside of this and passed in.
 */
typedef enum t_cose_err_t
t_cose_signature_verify1_callback(struct t_cose_signature_verify *me,
                                  uint32_t                        option_flags,
                                  const struct t_cose_sign_inputs *sign_inputs,
                                  const struct t_cose_parameter  *parameter_list,
                                  const struct q_useful_buf_c     signature);


/**
 * Data structture that must be the first part of every context of every concrete
 * implementation of t_cose_signature_verify.
 */
struct t_cose_signature_verify {
    t_cose_signature_verify_callback  *callback; /* some will call this a vtable with two entries */
    t_cose_signature_verify1_callback *callback1;
    struct t_cose_signature_verify    *next_in_list; /* Linked list of signers */
};


#endif /* t_cose_signature_verify_h */
