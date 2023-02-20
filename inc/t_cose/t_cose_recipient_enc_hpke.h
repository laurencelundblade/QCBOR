/*
 * t_cose_recipient_enc_hpke.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_RECIPIENT_ENC_HPKE_H__
#define __T_COSE_RECIPIENT_ENC_HPKE_H__

#include <stdint.h>
#include <stdlib.h>
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_key.h"

#ifdef __cplusplus
extern "C" {
#endif


struct t_cose_recipient_enc_hpke {
    /* Private data structure */

    /* t_cose_recipient_enc must be the first item for the polymorphism to
      * work.  This structure, t_cose_recipient_enc_hpke, will sometimes be
      * uses as a t_cose_recipient_enc.
      */
    struct t_cose_recipient_enc e;

    struct t_cose_key           pkR; /* recipient public key */
    struct q_useful_buf_c       kid;
    int32_t                     cose_algorithm_id;
};



/**
 * @brief Initialize the creator COSE_Recipient for HPKE content key distribution.

 * @param[in]  cose_algorithm_id  The key wrap algorithm ID.
 *
 * This must be called not only to set the algorithm ID, but also because
 * this sets up the callbacks in the t_cose_recipient_enc_keywrap. That is when
 * all the real work of keywrapping gets done.
 *
 * This typically only supports AES key wrap.
 *
 * If an unknown algortihm ID is passed, the error will occur when t_cose_encrypt_enc() is
 * called and the error code will be returned there.
 */
static void
t_cose_recipient_enc_hpke_init(struct t_cose_recipient_enc_hpke *context,
                               int32_t                     cose_algorithm_id);


/**
 * @brief Sets the recipient key, pkR
 *
 * The kid is optional and can be NULL
 */
static void
t_cose_recipient_enc_hpke_set_key(struct t_cose_recipient_enc_hpke *context,
                                  struct t_cose_key                 recipient,
                                  struct q_useful_buf_c             kid);



/* =========================================================================
     BEGINNING OF PRIVATE INLINE IMPLEMENTATION
   ========================================================================= */

enum t_cose_err_t
t_cose_recipient_create_hpke_cb_private(struct t_cose_recipient_enc  *me_x,
                                        struct q_useful_buf_c         cek,
                                        QCBOREncodeContext           *cbor_encoder);


static inline void
t_cose_recipient_enc_hpke_init(struct t_cose_recipient_enc_hpke *me,
                               int32_t                           cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
    me->e.creat_cb = t_cose_recipient_create_hpke_cb_private;
    me->cose_algorithm_id = cose_algorithm_id;
}


static inline void
t_cose_recipient_enc_hpke_set_key(struct t_cose_recipient_enc_hpke *me,
                                  struct t_cose_key                 pkR,
                                  struct q_useful_buf_c             kid)
{
    me->pkR = pkR;
    me->kid = kid;
}

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_ENC_HPKE_H__ */
