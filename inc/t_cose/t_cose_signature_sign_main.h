/*
 * t_cose_signature_sign_main.h
 *
 * Copyright (c) 2022-2023, Laurence Lundblade. All rights reserved.
 * Created by Laurence Lundblade on 5/23/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_signature_sign_main_h
#define t_cose_signature_sign_main_h

#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_key.h"


#ifdef __cplusplus
extern "C" {
#endif


struct t_cose_signature_sign_main {
    /* Private data structure */

    /* t_cose_signer must be the first item for the polymorphism to
     * work.  This structure, t_cose_signature_sign_main, will sometimes be
     * uses as a t_cose_signature_sign.
     */
    struct t_cose_signature_sign s;

    /* The rest of this is mostly specific to ECDSA signing */
    int32_t                      cose_algorithm_id;
    struct q_useful_buf_c        kid;
    struct t_cose_key            signing_key;
    void                        *crypto_context;
    struct t_cose_parameter      local_params[2];
    struct t_cose_parameter     *added_signer_params;
};


/*
 *
 *
 * This signer supports the ECDSA algorithms PS256, PS384 and PS512. */
void
t_cose_signature_sign_main_init(struct t_cose_signature_sign_main *context,
                                int32_t                     cose_algorithm_id);


/*
 * Set the signing key and kid. The kid may be NULL_Q_USEFUL_BUF_C.
 */
static void
t_cose_signature_sign_main_set_signing_key(struct t_cose_signature_sign_main *context,
                                           struct t_cose_key        signing_key,
                                           struct q_useful_buf_c    kid);


/**
 * \brief  Set the crypto context to be passed to the crypto library..
 *
 * \param[in] context The signer context.
 * \param[in] crypto_context   Pointer to the crypto context.
 *
 * The crypto context will be passed down to the crypto adapter
 * layer. It can be used to configure special features, track special
 * state or to return information for the crypto library.  The
 * structure pointed to by the crypto context is specific to the
 * crypto adapter that is in use. Many crypto adapters don't support
 * this at all as it is not needed for most use cases.
 */
static void
t_cose_signature_sign_main_set_crypto_context(struct t_cose_signature_sign_main *context,
                                              void *crypto_context);


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
t_cose_signature_sign_main_set_header_parameter(struct t_cose_signature_sign_main *context,
                                                struct t_cose_parameter   *header_parameters);


/* This is how you get the general interface / instance for a signer,
 * a t_cose_signer, from the specific and concrete instance of a
 * signer. Because the t_cose_signer is the first member in a
 * t_cose_ecdsa_signer, the implementation for this is in essence just
 * a cast and in the end no code is generated.
 *
 * t_cose calls signers as follows:
 *   struct t_cose_signature_sign *signer;
 *   signer = t_cose_signature_sign_from_main(me);
 *
 *   result = (signer->s.callback)(signer, ....);
 *
 * It makes use of the function pointer in signer->s. This callback is
 * when all the interesting work id done by
 * t_cose_signature_sign_main.
 *
 */
static struct t_cose_signature_sign *
t_cose_signature_sign_from_main(struct t_cose_signature_sign_main *me);



/* =========================================================================
 BEGINNING OF PRIVATE INLINE IMPLEMENTATION
 ========================================================================= */

static inline void
t_cose_signature_sign_main_set_signing_key(struct t_cose_signature_sign_main *context,
                                            struct t_cose_key       signing_key,
                                            struct q_useful_buf_c   kid)
{
    context->signing_key = signing_key;
    context->kid         = kid;
}



static inline struct t_cose_signature_sign *
t_cose_signature_sign_from_main(struct t_cose_signature_sign_main *me)
{
    /* Because s is the first item in the t_cose_ecdsa_signer, this
     * function should compile to nothing. It is here to keep the type
     * checking safe.
     */
    return &(me->s);
}


static inline void
t_cose_signature_sign_main_set_header_parameter(struct t_cose_signature_sign_main *me,
                                                 struct t_cose_parameter   *header_parameters)
{
    me->added_signer_params = header_parameters;
}


static inline void
t_cose_signature_sign_main_set_crypto_context(struct t_cose_signature_sign_main *me,
                                              void *crypto_context)
{
    me->crypto_context = crypto_context;
}


#ifdef __cplusplus
}
#endif

#endif /* t_cose_signature_sign_main_h */
