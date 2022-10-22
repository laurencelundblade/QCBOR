/*
 * t_cose_signature_sign_short.h
 *
 * Copyright (c) 2022, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_signature_sign_short_h
#define t_cose_signature_sign_short_h

#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_parameters.h"


/**
 * The context to perform short-circuit signing. This is a private
 * data structure.  The user of t_cose allocates this, often on the
 * stack.
 *
 * This is kind of an object as it is a context and some methods that
 * operate on it. It has two function pointers in it that are defined
 * in t_cose_signature_sign.h.
 */
struct t_cose_signature_sign_short {
    /* Private data structure */

    /* t_cose_signer must be the first item for the polymorphism to
     * work.  This structure, t_cose_short_signer, will sometimes be
     * uses as a t_cose_signer.
     */
    struct t_cose_signature_sign       s;

    int32_t                            cose_algorithm_id;
    struct q_useful_buf_c              kid;
    struct t_cose_parameter         local_params[2];
    struct t_cose_parameter        *added_signer_params;
};


/**
 * @brief Initialize the short-circuit signer
 *
 * \param[in] context            The t_cose t_cose_signature_sign_short context.
 * \param[in] cose_algorithm_id  The signing algorithm to pretend to be.
 *
 * This is the Short-circuit signer for test and development, NOT
 * commercial use -- it is not secure.  This can pretend to be ES256,
 * ES384 or ES512 because that is what it did in t_cose 1.0. No plan
 * or need to pretend to to be any more. Short-circuit signer can
 * serve its testing purpose without any further additions.
 *
 * This init call sets up the callbacks in the contex that t_cose uses
 * to do the actual work of getting the header parameters and creating
 * signatures.
 *
 * This can put short-circuit signatures into both a COSE_Sign and COSE_Sign1.
 */
void
t_cose_signature_sign_short_init(struct t_cose_signature_sign_short *context,
                                 int32_t                             cose_algorithm_id);


/* There is no set_key() for the short-circuit signer. It fakes the signatures
 * by copying the hash. */



/**
 * @brief Return instance of t_cose_signature_sign from a t_cose_signature_sign_short.
 *
 * \param[in] context      The t_cose t_cose_signature_sign_short context.
 * \param[in] header_parameters  Array of header parameters to add.
 *
 * The header parameter for the algorithm ID is generated
 * automatically.  and should not be added in this list.
 *
 * This is for the header parameters that go in the
 * COSE_Signature. See t_cose_sign_add_body_header_parameters() for
 * the parameters that go in the COSE_Sign and COSE_Sign1 main body.
 *
 * The parameters to add are passed in as an array of
 * t_cose_header_param.  Note that individual parameters in this array
 * can have a call back that does the encoding, so it is possible to
 * handle complicated parameters, such as ones that are maps and
 * arrays themselves.
 */
static void
t_cose_signature_sign_short_set_header_parameter(struct t_cose_signature_sign_short *context,
                                                 struct t_cose_parameter            *header_parameters);


/**
 * @brief Return instance of t_cose_signature_sign from a t_cose_signature_sign_short.
 *
 * \param[in] context      The t_cose t_cose_signature_sign_short context.
 *
 * \returns Pointer to the t_cose_signature_sign context.
 *
 * This returns a t_cose_signer, from the specific and concrete
 * instance of a signer. Because the t_cose_signer is the first member
 * in a t_cose_short_signer, the implementation for this is in essence
 * just a cast and in the end no code is generated.
 *
 * t_cose calls signers as follows:
 *   struct t_cose_signature_sign *signer;
 *   signer = t_cose_signature_sign_from_short(me);
 *
 *   result = (signer->s.callback)(signer, ....);
 *
 * It makes use of the function pointer in signer->s. This callback is
 * when all the interesting work id done by
 * t_cose_signature_sign_short.
 */
static struct t_cose_signature_sign *
t_cose_signature_sign_from_short(struct t_cose_signature_sign_short *context);


/**
 * @brief Get the never-changing kid for a short-circuit signature.
 *
 * @returns  Pointer and length of the kid.
 *
 * This is for testing and development only.
 *
 * This never fails.
 *
 * The value is always
 *      0xef, 0x95, 0x4b, 0x4b, 0xd9, 0xbd, 0xf6, 0x70,
 *      0xd0, 0x33, 0x60, 0x82, 0xf5, 0xef, 0x15, 0x2a,
 *      0xf8, 0xf3, 0x5b, 0x6a, 0x6c, 0x00, 0xef, 0xa6,
 *      0xa9, 0xa7, 0x1f, 0x49, 0x51, 0x7e, 0x18, 0xc6
 */
struct q_useful_buf_c
t_cose_get_short_circuit_kid(void);




/* =========================================================================
     BEGINNING OF PRIVATE INLINE IMPLEMENTATION
   ========================================================================= */

static inline void
t_cose_signature_sign_short_set_header_parameter(struct t_cose_signature_sign_short *me,
                                                 struct t_cose_parameter            *header_parameters)
{
    me->added_signer_params = header_parameters;
}


static inline struct t_cose_signature_sign *
t_cose_signature_sign_from_short(struct t_cose_signature_sign_short *me)
{
    /* Because s is the first item in the t_cose_short_signer, this
     * function should compile to nothing. It is here to keep the type
     * checking safe.
     */
    return &(me->s);
}

#endif /* t_cose_signature_sign_short_h */
