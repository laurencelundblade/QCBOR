/*
 * t_cose_recipient_dec.h
 *
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * Created by Laurence Lundblade on 1/23/23.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */


#ifndef t_cose_recipient_dec_h
#define t_cose_recipient_dec_h


#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_common.h"


/* This is an "abstract base class" for all decoders of COSE_Recipients
* of all types for all algorithms. This is the interface
* and data structure that t_cose_encrypt_dec knows about to be able
* to create each type of COSE_Recipient regardles of its type or algorithm.
*
* See longer discussion in t_cose_signature_sign.h about this
* approach.
*/


/* Forward declaration */
struct t_cose_recipient_dec;


/**
 * \brief Typedef of callback that decodes a COSE_Recipient.
 *
 * \param[in] context                Context to decode a COSE_Recipient
 * \param[in] cbor_decoder           The CBOR decoder to read from.
 * \param[in] loc       The location of the header params in the COSE message
 * \param[in] cek_buffer  The buffer to output the cek into.
 * \param[in,out] p_storage  Pool of parameter nodes from which to allocate.
 * \param[out] params  Place to put linked list of decoded parameters.
 * \param[out] cek              Plaintext (typically the CEK)
 *
 *
 * \retval T_COSE_SUCCESS
 *         Operation was successful.
 * \retval T_COSE_ERR_DECLINE
 * \retval T_COSE_ERR_KID_UNMATCHED
 * \retval T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG
 * \retval ....
 *
 *
 * The error returned is important as it determines whether
 * other recipient decoders are called or not. TODO: describe this more...
 */
typedef enum t_cose_err_t
t_cose_recipient_dec_cb(struct t_cose_recipient_dec        *context,
                        const struct t_cose_header_location loc,
                        const struct t_cose_alg_and_bits    ce_alg,
                        QCBORDecodeContext                 *cbor_decoder,
                        struct q_useful_buf                 cek_buffer,
                        struct t_cose_parameter_storage    *p_storage,
                        struct t_cose_parameter           **params,
                        struct q_useful_buf_c              *cek);


/**
 * Data structure that must be the first part of every context of every concrete
 * implementation of t_cose_recipient_dec.
 */
struct t_cose_recipient_dec {
    struct t_cose_rs_obj       base_obj;
    t_cose_recipient_dec_cb   *decode_cb;
};


#endif /* t_cose_recipient_dec_h */
