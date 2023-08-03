/*
 * t_cose_recipient_dec_esdh.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_RECIPIENT_DEC_ESDH_H__
#define __T_COSE_RECIPIENT_DEC_ESDH_H__

#include <stdint.h>
#include <stdlib.h>
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_recipient_dec.h"
#include "t_cose/t_cose_key.h"


#ifdef __cplusplus
extern "C" {
#endif


/* The default size of the COSE_KDF_Context. See
 * t_cose_recipient_dec_esdh_kdf_buf() and
 * T_COSE_ERR_KDF_BUFFER_TOO_SMALL.  See also \ref
 * T_COSE_ENC_COSE_KDF_CONTEXT which usually has the same value. */
#define T_COSE_DEC_COSE_KDF_CONTEXT_SIZE 50


/* This is the decoder for COSE_Recipients of type ESDH.  To use this
* make an instance of it, initialize it and set the sKR, and add it as
* a t_cose_recipient_dec to t_cose_encrypt_dec.  When
* t_cose_encrypt_dec() is called to process the cose message a
* callback will be made to this code to process COSE_Recpients it
* encounters that might be of type ESDH.
*/
struct t_cose_recipient_dec_esdh {
     /* Private data structure */

     /* t_cose_recipient_dec must be the first item for the
       * polymorphism to work.  This structure,
       * t_cose_recipient_enc_keywrap, will sometimes be uses as a
       * t_cose_recipient_enc.
       */
    struct t_cose_recipient_dec base;

    struct t_cose_key     private_key;
    struct q_useful_buf_c kid;

    /* stuff for info struct KDF context */
    struct q_useful_buf_c  party_u_ident;
    struct q_useful_buf_c  party_v_ident;
    struct q_useful_buf_c  supp_pub_other;
    struct q_useful_buf_c  supp_priv_info;

    struct q_useful_buf    kdf_context_buf;
};


static void
t_cose_recipient_dec_esdh_init(struct t_cose_recipient_dec_esdh *context);



/* Set the secret key of the receiver, the skR, the one that will be
 * used to by the DH key agreement in ESDH. The kid is optional. */

// TODO: describe and implement the rules for kid matching

static void
t_cose_recipient_dec_esdh_set_key(struct t_cose_recipient_dec_esdh *context,
                                  struct t_cose_key                 private_key,
                                  struct q_useful_buf_c             kid);


/**
 * \brief Set supplimentary data items in the KDF context info struct.
 *
 * \param[in] context         ESDH Decryptor context.
 * \param[in] supp_pub_other  Supplemental public info other or
 *                            \c NULL_Q_USEFUL_BUF_C.
 * \param[in] supp_priv_info  Supplemental private info other or
 *                            \c NULL_Q_USEFUL_BUF_C.
 *
 * It is required that this be called to supply \c supp_pub_other if
 * this was set when the encypted message was created. If not, message
 * decryption will fail with the \ref T_COSE_ERR_DATA_AUTH_FAILED
 * error.  Often this is a fixed string that is the same for every
 * message for a a use case. See more detailed discussion in
 * t_cose_recipient_enc_esdh_supp_info().
 *
 * \c supp_priv_info is very rarely used. It functions the same as \c
 * supp_pub_other. If it is used in constructing the message being
 * decrypted, this must be set or \ref T_COSE_ERR_DATA_AUTH_FAILED
 * will occur
 */
static inline void
t_cose_recipient_dec_esdh_supp_info(struct t_cose_recipient_dec_esdh *context,
                                    const struct q_useful_buf_c supp_pub_other,
                                    const struct q_useful_buf_c supp_priv_info);


/**
 * \brief Set PartyU and PartyV for KDF context info struct.
 *
 * \param[in] context        ESDH Decryptor context.
 * \param[in] party_u_ident  String for PartyU or
 *                           \c NULL_Q_USEFUL_BUF_C.
 * \param[in] party_v_ident  String for PartyV or
 *                           \c NULL_Q_USEFUL_BUF_C.
 *
 * In most use of COSE, these parts of the KDF context are not used,
 * and when they are used, they arrive in header parameters so it is
 * very rare that this function is needed. If this is set, they
 * override the values set in the headers.
 *
 * Note that Party U and Party V must be what was used when the
 * message was encrypted. If not, \ref T_COSE_ERR_DATA_AUTH_FAILED
 * will occur.  Often they arrive in headers, so even if they are in
 * use, it is unusual to call this.
 *
 * Note that this setting these to \c NULL_Q_USEFUL_BUF_C will result in
 * the values from the headers being used. If the headers are absent
 * then the value used will be \c NULL.
 *
 * The values of these are in \c returned_parameters from
 * t_cose_encrypt_dec().
 *
 * Also see detailed documentation for
 * t_cose_recipient_enc_esdh_party_info().
 */
static inline void
t_cose_recipient_dec_esdh_party_info(struct t_cose_recipient_dec_esdh *context,
                                     const struct q_useful_buf_c party_u_ident,
                                     const struct q_useful_buf_c party_v_ident);


/**
 * \brief Configure a larger buffer for the COSE_KDF_Context.
 *
 * \param[in] context     ESDH Decryptor context.
 * \param[in] kdf_buffer  The buffer used to serialize the COSE_KDF_Context.
 *
 * For most use the internal buffer for the COSE_KDF_Context is
 * usually large enough. The internal buffer size is \ref
 * T_COSE_DEC_COSE_KDF_CONTEXT_SIZE.
 *
 * \ref T_COSE_ERR_KDF_BUFFER_TOO_SMALL will be returned from
 * t_cose_encrypt_enc() or t_cose_encrypt_enc_detached() if the buffer
 * is too small.
 *
 * The COSE_KDF_Context described RFC 9053 section 5.3 must fit in
 * this buffer. With no additional context items provided it is about
 * 20 bytes including the protected headers for the algorithm ID. If
 * additional protected headers are added with xxx, PartyU or PartyV
 * is added with t_cose_recipient_enc_esdh_party_info() or
 * suppplemental info is added with
 * t_cose_recipient_enc_esdh_supp_info(), it may be necessary to call
 * this with a larger buffer.
 */
static void
t_cose_recipient_dec_esdh_kdf_buf(struct t_cose_recipient_dec_esdh *context,
                                  struct q_useful_buf               kdf_buffer);


/* =========================================================================
     BEGINNING OF PRIVATE INLINE IMPLEMENTATION
   ========================================================================= */


enum t_cose_err_t
t_cose_recipient_dec_esdh_cb_private(struct t_cose_recipient_dec *me_x,
                                     const struct t_cose_header_location loc,
                                     const struct t_cose_alg_and_bits    ce_alg,
                                     QCBORDecodeContext *cbor_decoder,
                                     struct q_useful_buf cek_buffer,
                                     struct t_cose_parameter_storage *p_storage,
                                     struct t_cose_parameter **params,
                                     struct q_useful_buf_c *cek);


static inline void
t_cose_recipient_dec_esdh_init(struct t_cose_recipient_dec_esdh *me)
{
    memset(me, 0, sizeof(*me));

    me->base.decode_cb = t_cose_recipient_dec_esdh_cb_private;
}


static inline void
t_cose_recipient_dec_esdh_set_key(struct t_cose_recipient_dec_esdh *me,
                                  struct t_cose_key                 private_key,
                                  struct q_useful_buf_c             kid)
{
    me->private_key = private_key;
    me->kid = kid;
}


static inline void
t_cose_recipient_dec_esdh_supp_info(struct t_cose_recipient_dec_esdh *me,
                                    const struct q_useful_buf_c  supp_pub_other,
                                    const struct q_useful_buf_c  supp_priv_info)
{
    me->supp_priv_info = supp_priv_info;
    me->supp_pub_other = supp_pub_other;
}


static inline void
t_cose_recipient_dec_esdh_party_info(struct t_cose_recipient_dec_esdh *me,
                                     const struct q_useful_buf_c  party_u_ident,
                                     const struct q_useful_buf_c  party_v_ident)
{
    me->party_u_ident = party_u_ident;
    me->party_v_ident = party_v_ident;
}


static inline void
t_cose_recipient_dec_esdh_kdf_buf(struct t_cose_recipient_dec_esdh *me,
                                  struct q_useful_buf               kdf_buffer)
{
    me->kdf_context_buf = kdf_buffer;
}


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_DEC_ESDH_H__ */
