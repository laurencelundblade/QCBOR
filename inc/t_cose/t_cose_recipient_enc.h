/**
 * \file t_cose_recipient_enc_hpke.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#ifndef t_cose_recipient_enc_h
#define t_cose_recipient_enc_h


#include "t_cose_parameters.h"
#include "t_cose_crypto.h"

/**
 * \brief Function pointer for use with different key agreement / key transport
 *        schemes used within the recipient structure of COSE_Encrypt.
 *
 *
 * \return The \ref t_cose_err_t.
 */

typedef enum t_cose_err_t t_cose_create_recipient(
                           void                                *context,
                           int32_t                              cose_algorithm_id,
                           struct t_cose_key                    recipient_key,
                           struct q_useful_buf_c                plaintext,
                           QCBOREncodeContext                  *encrypt_ctx);

/**
 * This is the context for storing a recipient structure for use with
 * HPKE and AES-KW. The caller should allocate it.
 * The size of this structure is around 56 bytes.
 */
struct t_cose_encrypt_recipient_ctx {
    /* Private data structure */
    int32_t                   cose_algorithm_id;
    struct q_useful_buf_c     kid;
    struct t_cose_key         cek;
    uint32_t                  option_flags;
    struct t_cose_key         ephemeral_key;
    struct t_cose_key         recipient_key;
    t_cose_create_recipient  *recipient_func;
};



#endif /* t_cose_recipient_enc_h */
