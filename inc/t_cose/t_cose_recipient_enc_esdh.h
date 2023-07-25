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


/* The default size of the COSE_KDF_Context. See
 * t_cose_recipient_dec_esdh_kdf_buf() and
 * T_COSE_ERR_KDF_BUFFER_TOO_SMALL. */
#define T_COSE_ENC_COSE_KDF_CONTEXT 200

struct t_cose_recipient_enc_esdh {
    /* Private data structure */

    /* t_cose_recipient_enc must be the first item for the polymorphism to
      * work.  This structure, t_cose_recipient_enc_esdh, will sometimes be
      * uses as a t_cose_recipient_enc.
      */
    struct t_cose_recipient_enc e;

    struct t_cose_key           recipient_pub_key;
    struct q_useful_buf_c       kid;
    int32_t                     cose_ec_curve_id;
    int32_t                     cose_algorithm_id;
    struct t_cose_parameter    *added_params;

    /* stuff for KDF context info struct */
    struct q_useful_buf_c       party_u_identity;
    struct q_useful_buf_c       party_v_identity;
    struct q_useful_buf_c       supp_pub_other;
    struct q_useful_buf_c       supp_priv_info;
};



/**
 * @brief Initialize the creator COSE_Recipient for ESDH content key distribution.

 * @param[in]  cose_algorithm_id    The content key distribution algorithm ID.
 * @param[in]  cose_ec_curve_id  The curve ID.
 *
 * This must be called not only to set the keywrap id, the content key
 * distribution (ckd) id, and the curve id, but also because this sets
 * up the recipient callbacks. That is when all the real work of
 * content key distribution gets done.
 *
 * If unknown algorithm IDs are passed, an error will occur when
 * t_cose_encrypt_enc() is called and the error code will be returned
 * there.
 */
static void
t_cose_recipient_enc_esdh_init(struct t_cose_recipient_enc_esdh *context,
                               int32_t                      cose_algorithm_id,
                               int32_t                      cose_ec_curve_id);


/**
 * @brief Sets the recipient key, pkR
 *
 * The kid is optional and can be NULL
 */
static void
t_cose_recipient_enc_esdh_set_key(struct t_cose_recipient_enc_esdh *context,
                                  struct t_cose_key                 recipient,
                                  struct q_useful_buf_c             kid);


/*
 * This COSE_Recipient always uses and sends a random salt as
 * described section 5.1 of RFC 9053. The length of the salt
 * is set based on the algorithm ID.
 *
 * t_cose is assumed to be integrated with a high quality
 * random number generated as such are common. The salt
 * is thusly generated.
 *
 * Because the salt is always present and of high quality,
 * all the nonce parameters in the PartyInfo are considered
 * unnecessary and there is no interface to provide them.
 *
 * Also, the algorithm and key length that go into PartyInfo
 * are derived from the algorithm IDs set elsewhere.
 */

/**
 * If this is not called, these default to nil.
 *
 * These fields will be sent in the recipient in header parameters (COSE header params -21 and -24).
 *
 * These fields provide extra binding to the sender and recipient that
 * improve security in some use cases. (To be honest, it is hard to
 * decribe exactly what these scenarios are and in the opinion of the
 * t_cose author they might not be that critical. The original
 * motivation comes from Appendix B of NIST SP800-56A.)
 *
 * No option is provided for setting party U and V nonce because they
 * are primarily to provide randomness and the salt input to the HKDF,
 * which is set by default, provides it. Similarly, party U and V
 * other seem unneeded. Theses values are all set to nil.
 */
static inline void
t_cose_recipient_enc_esdh_party_info(struct t_cose_recipient_enc_esdh *context,
                                     const struct q_useful_buf_c party_u_ident,
                                     const struct q_useful_buf_c party_v_ident);


/**
 * Set the "SuppPubInfo.other" field of PartyInfo as described in RFC
 * 9053.  This is optional and will be nil if not set. If this is set
 * it will be sent to the recipient in a header parameter.  Don't call
 * this or pass NULL_USEFUL_BUF_C to not set this.
 *
 * Also sets "SuppPrivInfo" from PartyInfo. This is optional. It is
 * never sent since it is pivate info. Somehow the recipient must also
 * know and set this during decryption. Don't call this or pass
 * NULL_USEFUL_BUF_C to not set this.
 *
 * The reasons for setting these and background on what to set it to
 * are in Section 5.2 of RFC 9053 and in NIST SP800-56A.
 */
static inline void
t_cose_recipient_enc_esdh_supp_info(struct t_cose_recipient_enc_esdh *context,
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
t_cose_recipient_enc_esdh_kdf_buf(struct t_cose_recipient_enc_esdh *context,
                                  struct q_useful_buf               kdf_buffer);

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
                               int32_t                      cose_algorithm_id,
                               int32_t                      cose_ec_curve_id)
{
    memset(me, 0, sizeof(*me));
    me->e.creat_cb        = t_cose_recipient_create_esdh_cb_private;
    me->cose_algorithm_id = cose_algorithm_id;
    me->cose_ec_curve_id  = cose_ec_curve_id;
}


static inline void
t_cose_recipient_enc_esdh_set_key(struct t_cose_recipient_enc_esdh *me,
                                  struct t_cose_key           recipient_pub_key,
                                  struct q_useful_buf_c       kid)
{
    me->recipient_pub_key = recipient_pub_key;
    me->kid               = kid;
}


static inline void
t_cose_recipient_enc_esdh_party_info(struct t_cose_recipient_enc_esdh *me,
                                     const struct q_useful_buf_c  party_u_ident,
                                     const struct q_useful_buf_c  party_v_ident)
{
    me->party_u_identity = party_u_ident;
    me->party_v_identity = party_v_ident;
}


static inline void
t_cose_recipient_enc_esdh_supp_info(struct t_cose_recipient_enc_esdh *me,
                                    const struct q_useful_buf_c  supp_pub_other,
                                    const struct q_useful_buf_c  supp_priv_info)
{
    me->supp_pub_other = supp_pub_other;
    me->supp_priv_info = supp_priv_info;
}

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_ENC_ESDH_H__ */
