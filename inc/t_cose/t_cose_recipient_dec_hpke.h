/*
 * t_cose_recipient_dec_hpke.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_RECIPIENT_DEC_HPKE_H__
#define __T_COSE_RECIPIENT_DEC_HPKE_H__

#include <stdint.h>
#include <stdlib.h>
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_recipient_dec.h"
#include "t_cose/t_cose_key.h"


#ifdef __cplusplus
extern "C" {
#endif



/* This is the decoder for COSE_Recipients of type HPKE.
* To use this make an instance of it, initialize it and set
* the sKR, and add it as a t_cose_recipient_dec to t_cose_encrypt_dec.
* When t_cose_encrypt_dec() is called to process the cose message
* a callback will be made to this code to process COSE_Recpients
* it encounters that might be of type HPKE.
*/
struct t_cose_recipient_dec_hpke {
     /* Private data structure */

     /* t_cose_recipient_dec must be the first item for the polymorphism to
       * work.  This structure, t_cose_recipient_enc_keywrap, will sometimes be
       * uses as a t_cose_recipient_enc.
       */
    struct t_cose_recipient_dec base;

    struct t_cose_key     skr;
    struct q_useful_buf_c kid;
};


static void
t_cose_recipient_dec_hpke_init(struct t_cose_recipient_dec_hpke *context);



/* Set the secret key of the receiver, the skR in RFC 9180, the one that will be used to
 * by the DH key agreement in HPKE to decrypt the CEK. The kid
 * is optional. */

// TODO: describe and implement the rules for kid matching

static void
t_cose_recipient_dec_hpke_set_skr(struct t_cose_recipient_dec_hpke *context,
                                  struct t_cose_key                 skr,
                                  struct q_useful_buf_c             kid);


/* =========================================================================
     BEGINNING OF PRIVATE INLINE IMPLEMENTATION
   ========================================================================= */


enum t_cose_err_t
t_cose_recipient_dec_hpke_cb_private(struct t_cose_recipient_dec *me_x,
                                     const struct t_cose_header_location loc,
                                     const struct t_cose_alg_and_bits ce_alg,
                                     QCBORDecodeContext *cbor_decoder,
                                     struct q_useful_buf cek_buffer,
                                     struct t_cose_parameter_storage *p_storage,
                                     struct t_cose_parameter **params,
                                     struct q_useful_buf_c *cek);


static inline void
t_cose_recipient_dec_hpke_init(struct t_cose_recipient_dec_hpke *me)
{
    memset(me, 0, sizeof(*me));

    me->base.decode_cb = t_cose_recipient_dec_hpke_cb_private;
}


static inline void
t_cose_recipient_dec_hpke_set_skr(struct t_cose_recipient_dec_hpke *me,
                                  struct t_cose_key                 skr,
                                  struct q_useful_buf_c             kid)
{
    me->skr = skr;
    me->kid           = kid;
}


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_DEC_HPKE_H__ */
