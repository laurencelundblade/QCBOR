//
//  t_cose_signature_verify_ecdsa.h
//  t_cose
//
//  Created by Laurence Lundblade on 7/22/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_signature_verify_ecdsa_h
#define t_cose_signature_verify_ecdsa_h

#include "t_cose/t_cose_signature_verify.h"
#include "t_cose_parameters.h"


/* Warning: this is still early development. Documentation may be incorrect. */


struct t_cose_signature_verify_ecdsa {
    /* Private data structure */

    /* t_cose_signer must be the first item for the polymorphism to work.
     * This structure, t_cose_signature_verify_ecdsa, will sometimes be uses as
     * a t_cose_signature_verify.
     */
    struct t_cose_signature_verify s;
    struct t_cose_key              verification_key;

    t_cose_parameter_decode_callback  *reader;
    void                  *reader_ctx;
};


void
t_cose_signature_verify_ecdsa_init(struct t_cose_signature_verify_ecdsa *me);


static void
t_cose_signature_verify_ecdsa_set_key(struct t_cose_signature_verify_ecdsa *me,
                                      struct t_cose_key verification_key);

static void
t_cose_signature_verify_ecdsa_set_header_reader(struct t_cose_signature_verify_ecdsa *me,
                                                t_cose_parameter_decode_callback                 *reader,
                                                void                                 *reader_ctx);

static struct t_cose_signature_verify *
t_cose_signature_verify_from_ecdsa(struct t_cose_signature_verify_ecdsa *context);



/* ------------------------------------------------------------------------
 * Private and inline implementations of public functions defined above.
 */

static inline void
t_cose_signature_verify_ecdsa_set_key(struct t_cose_signature_verify_ecdsa *me,
                                      struct t_cose_key verification_key)
{
    me->verification_key = verification_key;
}


static inline void
t_cose_signature_verify_ecdsa_set_header_reader(struct t_cose_signature_verify_ecdsa *me,
                                                t_cose_parameter_decode_callback *reader,
                                                void *reader_ctx)
{
    me->reader = reader;
    me->reader_ctx = reader_ctx;
}


static inline struct t_cose_signature_verify *
t_cose_signature_verify_from_ecdsa(struct t_cose_signature_verify_ecdsa *me)
{
    /* Because s is the first item in the t_cose_ecdsa_signer, this function should
     * compile to nothing. It is here to keep the type checking safe.
     */
    return &(me->s);
}

#endif /* t_cose_signature_verify_ecdsa_h */
