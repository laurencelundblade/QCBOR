//
//  t_cose_signature_verify.h
//  t_cose
//
//  Created by Laurence Lundblade on 7/17/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_signature_verify_h
#define t_cose_signature_verify_h

#include "t_cose/t_cose_parameters.h"

/* Warning: this is still early development. Documentation may be incorrect. */


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


/*
This is the call back used to verify a COSE_Signature in a COSE_Sign.

 @param[in] me
 @param[in] run_crypto   If true, do the full sig verification. If not just decode parameters.
 @param[in] loc          The location of the signature inside the COSE_Sign.
 @param[in] protected_body_headers   Body headers from COSE_Signature to verify
 @param[in] payload                  The payload to verify (regular or detached)
 @param[in] aad                      The aad to verify
 @param[in] params                   The place to put the decoded params.
 @param[in]                          The decoder instance from where the COSE_Signature is decoded.
 @param[out] decoded_signature_parameters

 */
typedef enum t_cose_err_t
(t_cose_signature_verify_callback)(struct t_cose_signature_verify   *me,
                                   bool                              run_crypto,
                                   const struct t_cose_header_location loc,
                                   const struct q_useful_buf_c       protected_body_headers,
                                   const struct q_useful_buf_c       payload,
                                   const struct q_useful_buf_c       aad,
                                   struct t_cose_parameter_storage  *params,
                                   QCBORDecodeContext               *qcbor_decoder,
                                   struct t_cose_parameter         **decoded_signature_parameters);




/* Verify the bare signature in COSE_Sign1.

 @param[in] me
 @param[in] protected_body_headers   Encoded body headers from COSE_Signature to verify
 @param[in]protected_signature_headers  
 @param[in] payload                  The payload to verify (regular or detached)
 @param[in] aad                      The aad to verify
 @param[in] parameter_list           Parameter list in which algorithm and kid is found.
 @param[in] signature                The signature.

 This is very different from t_cose_signature_verify_callback because
 there is no header decoding to be done. Instead the headers are decoded outside
 of this and passed in.
 */
typedef enum t_cose_err_t
(t_cose_signature_verify1_callback)(struct t_cose_signature_verify *me,
                                    const struct q_useful_buf_c     protected_body_headers,
                                    const struct q_useful_buf_c     protected_signature_headers,
                                    const struct q_useful_buf_c     payload,
                                    const struct q_useful_buf_c     aad,
                                    const struct t_cose_parameter  *parameter_list,
                                    const struct q_useful_buf_c     signature);



/* The definition (not declaration) of the context that every
 * t_cose_signature_verify implemtation has.
 */
struct t_cose_signature_verify {
    t_cose_signature_verify_callback  *callback; /* some will call this a vtable with two entries */
    t_cose_signature_verify1_callback *callback1;
    struct t_cose_signature_verify    *next_in_list; /* Linked list of signers */
};


#endif /* t_cose_signature_verify_h */
