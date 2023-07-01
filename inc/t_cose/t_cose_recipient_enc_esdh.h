/*
 * t_cose_recipient_enc_esdh.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_RECIPIENT_ENC_ESDH_H__
#define __T_COSE_RECIPIENT_ENC_ESDH_H__

#include <stdint.h>
#include <stdlib.h>
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_key.h"

#ifdef __cplusplus
extern "C" {
#endif


struct t_cose_recipient_enc_esdh {
    /* Private data structure */

    /* t_cose_recipient_enc must be the first item for the polymorphism to
      * work.  This structure, t_cose_recipient_enc_esdh, will sometimes be
      * uses as a t_cose_recipient_enc.
      */
    struct t_cose_recipient_enc e;

    struct t_cose_key           pkR; /* recipient public key */
    struct q_useful_buf_c       kid;
    struct t_cose_crypto_esdh_suite_t esdh_suite;
    struct t_cose_parameter    *added_params;
    struct t_cose_info_t       *info;
};



/**
 * @brief Initialize the creator COSE_Recipient for ESDH content key distribution.

 * @param[in]  ckd_id    The content key distribution algorithm ID.
 * @param[in]  curve_id  The curve ID.
 *
 * This must be called not only to set the keywrap id, the content key distribution (ckd) id, and
 * the curve id, but also because this sets up the recipient callbacks. That is when all the real
 * work of content key distribution gets done.
 *
 * If unknown algorithm IDs are passed, an error will occur when t_cose_encrypt_enc() is
 * called and the error code will be returned there.
 */
static void
t_cose_recipient_enc_esdh_init(struct t_cose_recipient_enc_esdh *context,
                               int16_t                          ckd_id,
                               int16_t                          curve_id);


/**
 * @brief Sets the recipient key, pkR
 *
 * The kid is optional and can be NULL
 */
static void
t_cose_recipient_enc_esdh_set_key(struct t_cose_recipient_enc_esdh *context,
                                  struct t_cose_key                 recipient,
                                  struct q_useful_buf_c             kid);


/**
 * @brief Sets the info structure
 */
static inline void
t_cose_recipient_enc_esdh_set_info(struct t_cose_recipient_enc_esdh *me,
                                   struct t_cose_info_t             *info);

/* =========================================================================
     BEGINNING OF PRIVATE INLINE IMPLEMENTATION
   ========================================================================= */

enum t_cose_err_t
t_cose_recipient_create_esdh_cb_private(struct t_cose_recipient_enc  *me_x,
                                        struct q_useful_buf_c         cek,
                                        const struct t_cose_alg_and_bits ce_alg,
                                        QCBOREncodeContext           *cbor_encoder);


static inline void
t_cose_recipient_enc_esdh_init(struct t_cose_recipient_enc_esdh *me,
                               int16_t                          ckd_id,
                               int16_t                          curve_id
                               )
{
    memset(me, 0, sizeof(*me));
    me->e.creat_cb = t_cose_recipient_create_esdh_cb_private;
    me->esdh_suite.ckd_id = ckd_id;
    me->esdh_suite.curve_id = curve_id;
}

static inline void
t_cose_recipient_enc_esdh_set_info(struct t_cose_recipient_enc_esdh *me,
                                   struct t_cose_info_t             *info)
{
    me->info = info;
}

static inline void
t_cose_recipient_enc_esdh_set_key(struct t_cose_recipient_enc_esdh *me,
                                  struct t_cose_key                 pkR,
                                  struct q_useful_buf_c             kid)
{
    me->pkR = pkR;
    me->kid = kid;
}

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_ENC_ESDH_H__ */
