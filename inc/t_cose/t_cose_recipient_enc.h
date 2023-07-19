/**
 * \file t_cose_recipient_enc.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#ifndef t_cose_recipient_enc_h
#define t_cose_recipient_enc_h

#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_common.h"


/* This is an "abstract base class" for all creators of COSE_Recipients
* of all types for all algorithms. This is the interface
* and data structure that t_cose_encrypt_enc knows about to be able
* to create each type of COSE_Recipient regardles of its type or algorithm.
*
* See longer discussion in t_cose_signature_sign.h about this
* approach.
*/


/* Forward declaration */
struct t_cose_recipient_enc;


/**
 * \brief Typedef of callback that creates a COSE_Recipient.
 *
 * \param[in] context                Context for create COSE_Recipient
 * \param[in] cek              Plaintext (typically the CEK)
 * \param[out] cbor_encoder           Resulting encryption structure
 *
 * \retval T_COSE_SUCCESS
 *         Operation was successful.
 * \retval Error messages otherwise.
 */
typedef enum t_cose_err_t
t_cose_create_recipient_cb(struct t_cose_recipient_enc     *context,
                           struct q_useful_buf_c            cek,
                           const struct t_cose_alg_and_bits ce_alg,
                           QCBOREncodeContext              *cbor_encoder);


/**
 * Data structure that must be the first part of every context of every concrete
 * implementation of t_cose_recipient_enc.
 */
struct t_cose_recipient_enc {
    t_cose_create_recipient_cb   *creat_cb;
    struct t_cose_recipient_enc  *next_in_list;
};


#endif /* t_cose_recipient_enc_h */
