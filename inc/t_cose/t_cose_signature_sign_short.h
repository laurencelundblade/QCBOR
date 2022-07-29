//
//  t_cose_signature_sign_short.h
//  t_cose_test
//
//  Created by Laurence Lundblade on 7/27/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_signature_sign_short_h
#define t_cose_signature_sign_short_h

#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_parameters.h"



struct t_cose_signature_sign_short {
    /* Private data structure */

    /* t_cose_signer must be the first item for the polymorphism to work.
     * This structure, t_cose_short_signer, will sometimes be uses as a t_cose_signer.
     */
    struct t_cose_signature_sign       s;

    /* The rest of this is mostly specific to ECDSA signing */
    int32_t                            cose_algorithm_id;
    struct q_useful_buf_c              kid;
    struct t_cose_header_param         local_params[3];
    const struct t_cose_header_param  *added_signer_params;
};


/*
 *
 *
 * Short-circuit signer for test and development  */
void
t_cose_signature_sign_short_init(struct t_cose_signature_sign_short *context,
                                 int32_t                             cose_algorithm_id);



/* The header parameter for the algorithm ID is generated automatically.
   and should not be added in this list.

 This is for the header parameters that go in the COSE_Signature. See
 t_cose_sign_add_body_header_parameters() for the parameters that go in
 the COSE_Sign and COSE_Sign1 main body.

 The parameters to add are passed in as an array of t_cose_header_param.
 Note that individual parameters in this array can have a call back that does
 the encoding, so it is possible to handle complicated parameters, such
 as ones that are maps and arrays themselves.
 */
static void
t_cose_signature_sign_short_set_header_parameter(struct t_cose_signature_sign_short *context,
                                                 const struct t_cose_header_param   *header_parameters);


/* This is how you get the general interface / instance for a signer,
 * a t_cose_signer, from the specific and concrete instance of a
 * signer. Because the t_cose_signer is the first member in a
 * t_cose_short_signer, the implementation for this is in essence just a
 * cast and in the end no code is generated.
 *
 * t_cose calls signers as follows:
 *   struct t_cose_signature_sign *signer;
 *   signer = t_cose_signature_sign_from_short(me);
 *
 *   result = (signer->s.callback)(signer, ....);
 *
 * It makes use of the function pointer in signer->s. This
 * callback is when all the interesting work id done by
 * t_cose_signature_sign_short.
 *
 */
static struct t_cose_signature_sign *
t_cose_signature_sign_from_short(struct t_cose_signature_sign_short *me);



/* =========================================================================
 BEGINNING OF PRIVATE INLINE IMPLEMENTATION
 ========================================================================= */



static inline struct t_cose_signature_sign *
t_cose_signature_sign_from_short(struct t_cose_signature_sign_short *me)
{
    /* Because s is the first item in the t_cose_short_signer, this function should
     * compile to nothing. It is here to keep the type checking safe.
     */
    return &(me->s);
}


static inline void
t_cose_signature_sign_short_set_header_parameter(struct t_cose_signature_sign_short *me,
                                                 const struct t_cose_header_param   *header_parameters)
{
    me->added_signer_params = header_parameters;
}

#endif /* t_cose_signature_sign_short_h */
