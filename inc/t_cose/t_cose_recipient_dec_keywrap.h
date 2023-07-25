/*
 * t_cose_recipient_dec_keywrap.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_RECIPIENT_DEC_KEYWRAP_H__
#define __T_COSE_RECIPIENT_DEC_KEYWRAP_H__

#include <stdlib.h>
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_key.h"
#include "t_cose_recipient_dec.h"

#ifdef __cplusplus
extern "C" {
#endif


/* This is the decoder for COSE_Recipients of type key wrap.  To use
 * this make an instance of it, initialize it and set the kek, and add
 * it as a t_cose_recipient_dec to t_cose_encrypt_dec.  When
 * t_cose_encrypt_dec() is called to process the cose message a
 * callback will be made to this code to process COSE_Recpients it
 * encounters that might be of type key wrap.
 */
struct t_cose_recipient_dec_keywrap {
     /* Private data structure */

     /* t_cose_recipient_dec must be the first item for the
       * polymorphism to work.  This structure,
       * t_cose_recipient_dec_keywrap, will sometimes be used as a
       * t_cose_recipient_dec.
       */
    struct t_cose_recipient_dec base;

    struct t_cose_key     kek;
    struct q_useful_buf_c kid;
};


static void
t_cose_recipient_dec_keywrap_init(struct t_cose_recipient_dec_keywrap *context);


/* The kek must always be set and must be of the right type for the
 * algorithm in the key wrap COSE_Recipient. The algorithm ID can be
 * found using decode only mode....* TODO: implement and describe this
 *
 * TODO: describe and implement the rules for kid matching
 */
static void
t_cose_recipient_dec_keywrap_set_kek(struct t_cose_recipient_dec_keywrap *context,
                                     struct t_cose_key                    kek,
                                     struct q_useful_buf_c                kid);



/* =========================================================================
     BEGINNING OF PRIVATE INLINE IMPLEMENTATION
   ========================================================================= */

/* The semi-private implementation of t_cose_recipient_dec. It is only
 * here so it can be referenced by t_cose_recipient_dec_keywrap_init()
 * which is an inline function. */
enum t_cose_err_t
t_cose_recipient_dec_keywrap_cb_private(struct t_cose_recipient_dec     *me_x,
                                        const struct t_cose_header_location loc,
                                        const struct t_cose_alg_and_bits ce_alg,
                                        QCBORDecodeContext        *cbor_decoder,
                                        struct q_useful_buf         cek_buffer,
                                        struct t_cose_parameter_storage *p_storage,
                                        struct t_cose_parameter   **params,
                                        struct q_useful_buf_c      *cek);


static inline void
t_cose_recipient_dec_keywrap_init(struct t_cose_recipient_dec_keywrap *me)
{
    memset(me, 0, sizeof(*me));
    me->base.decode_cb = t_cose_recipient_dec_keywrap_cb_private;
}


static inline void
t_cose_recipient_dec_keywrap_set_kek(struct t_cose_recipient_dec_keywrap *me,
                                     struct t_cose_key                    kek,
                                     struct q_useful_buf_c                kid)
{
    me->kek = kek;
    me->kid = kid;
}


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_DEC_KEYWRAP_H__ */
