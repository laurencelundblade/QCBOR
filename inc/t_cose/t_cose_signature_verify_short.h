//
//  t_cose_signature_verify_short.h
//  t_cose
//
//  Created by Laurence Lundblade on 7/27/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#ifndef t_cose_signature_verify_short_h
#define t_cose_signature_verify_short_h

#include "t_cose/t_cose_signature_verify.h"
#include "t_cose_parameters.h"


/* Warning: this is still early development. Documentation may be incorrect. */


struct t_cose_signature_verify_short {
    /* Private data structure */

    /* t_cose_signer must be the first item for the polymorphism to work.
     * This structure, t_cose_signature_verify_short, will sometimes be uses as
     * a t_cose_signature_verify.
     */
    struct t_cose_signature_verify s;

    t_cose_header_reader  *reader;
    void                  *reader_ctx;
};


void
t_cose_signature_verify_short_init(struct t_cose_signature_verify_short *me);

static void
t_cose_signature_verify_short_set_header_reader(struct t_cose_signature_verify_short *me,
                                                t_cose_header_reader                 *reader,
                                                void                                 *reader_ctx);

static struct t_cose_signature_verify *
t_cose_signature_verify_from_short(struct t_cose_signature_verify_short *context);



/* ------------------------------------------------------------------------
 * Private and inline implementations of public functions defined above.
 */


static inline void
t_cose_signature_verify_short_set_header_reader(struct t_cose_signature_verify_short *me,
                                                t_cose_header_reader *reader,
                                                void *reader_ctx)
{
    me->reader = reader;
    me->reader_ctx = reader_ctx;
}


static inline struct t_cose_signature_verify *
t_cose_signature_verify_from_short(struct t_cose_signature_verify_short *me)
{
    /* Because s is the first item in the t_cose_short_signer, this function should
     * compile to nothing. It is here to keep the type checking safe.
     */
    return &(me->s);
}

#endif /* t_cose_signature_verify_short_h */
