/*
 * t_cose_signature_verify_main.h
 *
 * Copyright (c) 2022, Laurence Lundblade. All rights reserved.
 * Created by Laurence Lundblade on 7/22/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_signature_verify_main_h
#define t_cose_signature_verify_main_h

#include "t_cose/t_cose_signature_verify.h"
#include "t_cose_parameters.h"


/* Warning: this is still early development. Documentation may be incorrect. */


/**
 * Verification context. */
struct t_cose_signature_verify_main {
    /* Private data structure */

    /* t_cose_signature_verify must be the first item for the polymorphism to work.
     * This structure, t_cose_signature_verify_main, will sometimes be uses as
     * a t_cose_signature_verify.
     */
    struct t_cose_signature_verify     s;
    struct t_cose_key                  verification_key;
    void                              *crypto_context;
    t_cose_parameter_decode_callback  *reader;
    void                              *reader_ctx;
};


void
t_cose_signature_verify_main_init(struct t_cose_signature_verify_main *me);


static void
t_cose_signature_verify_main_set_key(struct t_cose_signature_verify_main *me,
                                      struct t_cose_key verification_key);

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
t_cose_signature_verify_main_set_crypto_context(struct t_cose_signature_verify_main *context,
                                                void *crypto_context);


static void
t_cose_signature_verify_main_set_header_reader(struct t_cose_signature_verify_main *me,
                                                t_cose_parameter_decode_callback   *reader,
                                                void                               *reader_ctx);

static struct t_cose_signature_verify *
t_cose_signature_verify_from_main(struct t_cose_signature_verify_main *context);




/* ------------------------------------------------------------------------
 * Private and inline implementations of public functions defined above.
 */

static inline void
t_cose_signature_verify_main_set_key(struct t_cose_signature_verify_main *me,
                                      struct t_cose_key verification_key)
{
    me->verification_key = verification_key;
}


static inline void
t_cose_signature_verify_main_set_header_reader(struct t_cose_signature_verify_main *me,
                                                t_cose_parameter_decode_callback *reader,
                                                void *reader_ctx)
{
    me->reader     = reader;
    me->reader_ctx = reader_ctx;
}


static inline void
t_cose_signature_verify_main_set_crypto_context(struct t_cose_signature_verify_main *me,
                                                void *crypto_context)
{
    me->crypto_context = crypto_context;
}


static inline struct t_cose_signature_verify *
t_cose_signature_verify_from_main(struct t_cose_signature_verify_main *me)
{
    /* Because s is the first item in the t_cose_ecdsa_signer, this function should
     * compile to nothing. It is here to keep the type checking safe.
     */
    return &(me->s);
}

#endif /* t_cose_signature_verify_main_h */
