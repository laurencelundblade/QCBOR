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
#define T_COSE_DEC_COSE_KDF_CONTEXT 200


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
    struct q_useful_buf_c  supp_pub_other;
    struct q_useful_buf_c  supp_priv_info;
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
 *
 * Normally these fields are decoded out of parameters in the COSE
 * recipient so there is no need to set them. This method is provided
 * for use cases where they are not sent and a nil value is not
 * sufficient.  TODO: this is not implemented.
 */
static inline void
t_cose_recipient_dec_esdh_party_info(struct t_cose_recipient_dec_esdh *context,
                                     const struct q_useful_buf_c party_u_ident,
                                     const struct q_useful_buf_c party_v_ident);


/**
 *
 * Normally supp_other_info is decoded from the header
 * parameters. This method is provided for use cases where it is not
 * sent and a nil value is not sufficient.
 *
 * supp_priv_info is never decoded from a header parameter. If it is
 * used, it must be set here.  To set it and use supp_other_info from
 * the header parameter pass NULL_Q_USEFUL_BUF_C for supp_other_info.
 */
static inline void
t_cose_recipient_dec_esdh_supp_info(struct t_cose_recipient_dec_esdh *context,
                                    const struct q_useful_buf_c supp_pub_other,
                                    const struct q_useful_buf_c supp_priv_info);


/**
 * \brief Configure a larger buffer used to serialize the COSE_KDF_Context.
 *
 * \param[in] context           The t_cose signing context.
 * \param[in] kdf_buffer  The buffer used to serialize the COSE_KDF_Context.
 *
 * For normal use the internal buffer for the COSE_KDF_Context is
 * larger enough.  If the error \ref T_COSE_ERR_KDF_BUFFER_TOO_SMALL
 * occurs use this to set a larger buffer.
 *
 * \ref T_COSE_ERR_KDF_BUFFER_TOO_SMALL will occur if the protected
 * headers are large, or if fields like party U, party V or
 * SuppPubInfo are large. On the decryption side, these come in as
 * header parameters so the caller must anticiapte the largest
 * possible value. Often these are empty so there is no issue.
 */
void
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

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_DEC_ESDH_H__ */
