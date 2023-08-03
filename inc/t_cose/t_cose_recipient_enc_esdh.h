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


/**
 * \file t_cose_recipient_enc_esdh.h
 *
 * \brief ECDH Recipient Encrypt for COSE_Encrypt Messages.
 */




/** The default size of the COSE_KDF_Context. See
 * t_cose_recipient_enc_esdh_kdf_buf() and
 * \ref T_COSE_ERR_KDF_BUFFER_TOO_SMALL. */
#define T_COSE_ENC_COSE_KDF_CONTEXT_SIZE 50

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
    struct q_useful_buf_c       party_u_ident;
    struct q_useful_buf_c       party_v_ident;
    struct q_useful_buf_c       supp_pub_other;
    struct q_useful_buf_c       supp_priv_info;
    struct q_useful_buf         kdf_context_buf;
    bool                        do_not_send_party;
    bool                        use_salt;
    struct q_useful_buf_c       salt_bytes;
};



/**
 * @brief Initialize the creator COSE_Recipient for ESDH content key 
 *        distribution.

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


/**
 * \brief Set supplimentary items in the KDF context info struct.
 *
 * \param[in] context         ESDH encryption context.
 * \param[in] supp_pub_other  Supplemental public info other or
 *                            \c NULL_Q_USEFUL_BUF_C
 * \param[in] supp_priv_info  Supplemental private info other or
 *                            \c NULL_Q_USEFUL_BUF_C
 *
 * It is not so easy to figure out how to use the required COSE KDF
 * context in RFC 9053, section 5, so this starts out with an opinion
 * and recommendation.  If you are just getting started playing with
 * COSE encryption, set everything to NULL (all of PartyU/V, all supp
 * items). Everything in the COSE WG Examples repository is like
 * this. This is easily accomplished in t_cose by not doing
 * anything. (Note that the algorithm ID and size and the protected
 * headers in the context structure can't be NULL, but they are filled
 * in automatically by t_cose).
 *
 * If you are moving beyond getting started to define a new use case for
 * COSE, set \c supp_pub_other to a fixed string naming your use
 * case. For example, "Xxxx Firmware Encryption". This is not the name
 * of the application implementing the use case, but the broad name of
 * the COSE use case. All applications for the use case must hard code
 * the same string. Everything else can by \c NULL.
 *
 * Note that the receiver of a COSE message must have the same KDF
 * context set up. If not, the intermediate derived keys will not be
 * the same and the decrypt will return \ref
 * T_COSE_ERR_DATA_AUTH_FAILED.
 *
 * See RFC 9053 section 5.2 for more background and also NIST SP 800
 * 56 and references in it for rationale for the existence of all the
 * facets of the KDF Context.
 *
 * See t_cose_recipient_enc_esdh_party_info() and
 * t_cose_recipient_enc_esdh_salt() for related discussion.
 *
 * This recommendation of minimum use of the KDF context is made based
 * on discussion with long-time experts in COSE, CMS, LAMPS and
 * other. An important justification is that the ephemeral key is
 * always generated anew from a high-quality random number generator
 * for each encrypted message.
 *
 * Now on to the mechanics of this API.
 *
 * This sets the "SuppPubInfo.other" field of PartyInfo as described
 * in RFC 9053.  This is optional and will be \c NULL if not set. If
 * this is set, it will be sent to the recipient in a header
 * parameter.  Don't call this or pass \c NULL_USEFUL_BUF_C to not set
 * this.
 *
 * This can also set the "SuppPrivInfo" field in PartyInfo. This is
 * optional. It is never sent in a header parameter since it is
 * private information. Somehow the recipient must also have and set
 * this during decryption. Don't call this or pass \c
 * NULL_USEFUL_BUF_C to not set SuppPrivInfo.
 */
static inline void
t_cose_recipient_enc_esdh_supp_info(struct t_cose_recipient_enc_esdh *context,
                                    const struct q_useful_buf_c supp_pub_other,
                                    const struct q_useful_buf_c supp_priv_info);


/**
 * \brief Set PartyU and PartyV identity for KDF context info struct.
 *
 * \param[in] context        ESDH encryption context.
 * \param[in] party_u_ident  String for PartyU or NULL_Q_USEFUL_BUF_C.
 * \param[in] party_v_ident  String for PartyV or NULL_Q_USEFUL_BUF_C.
 * \param[in] do_not_send    True indicates these should be left out of the
 *                           COSE header parameters, that they should not be
 *                           sent to the recipient.
 *
 * Like the documentation for t_cose_recipient_enc_esdh_supp_info()
 * this gives and opinion and recommendation: PartyU and PartyV
 * should be left unset and unused. Don't call this method.
 *
 * The point of PartyU and PartyV is to bind the content encryption
 * key to the sender and receiver context.  These are in COSE because
 * they are in NIST SP800-56A and JOSE. They are justified by academic
 * papers on attacks on key agreement protocols found in Appendix B of
 * NIST SP800-56A. Probably these attacks don't apply because you
 * probably are using a good RNG and because the ephemeral key is
 * generated anew for every encryption. Good RNGs are much more common
 * now (2023) than when these papers were authored.
 *
 * These data items are described in RFC 9053 section 5.2. This API
 * only allows setting Party*.identity. It doesn't allow setting
 * Party*.nonce or Party*.other. It always sets them to \c
 * NULL. Speaking with opinion, 'nonce' and 'other' seem very
 * unnecessary and complex. Hopefully, no implementation ever uses
 * them. Everything needed can be done with the 'PartyInfo*.idenity'
 * data items.
 *
 * See t_cose_recipient_enc_esdh_supp_info() where it is recommended
 * to set one of the KDF context inputs and additionally
 * t_cose_recipient_enc_esdh_salt().
 *
 * The opinions here were formed from discussions with long-time
 * workers on COSE, CMS, LAMPS, reading of NIST SP800-56A and trying
 * to formulate attacks that these data items defend against.
 *
 * Now on to non-opinion mechanics of this API.
 *
 * If these data items are not set, then PartyInfo*.identity will be
 * \c NULL when the KDF Context Information Structure is
 * created. Otherwise, they will be the values set here. If they are
 * set to \c NULL_Q_USEFUL_C here, they will also be \c NULL in the
 * input to the KDF. PartyInfo*.nonce and PartyInfo*.other are always
 * \ cNULL in this implementation. It is not possible to set them.
 *
 * If these are set to non-NULL values, they will be sent in
 * unprotected headers, unless \c do_not_send is \c true.
 *
 * If these are set to long strings, then
 * t_cose_recipient_enc_esdh_kdf_buf() may have to be called to supply
 * a buffer larger than \ref T_COSE_ENC_COSE_KDF_CONTEXT_SIZE for the
 * internal KDF Context construction.
 */
static inline void
t_cose_recipient_enc_esdh_party_info(struct t_cose_recipient_enc_esdh *context,
                                     const struct q_useful_buf_c party_u_ident,
                                     const struct q_useful_buf_c party_v_ident,
                                     const bool                  do_not_send);


/**
 * \brief Configure salt in KDF Context.
 *
 * \param[in] context     ESDH encryption context.
 * \param[in] use_salt    Set to \c true to enable, \c false to disable
 * \param[in] salt_bytes  Bytes for the salt or \ref NULL_Q_USEFUL_BUF_C
 *                        for an internally generated random salt.
 *
 * By default no salt is input to the KDF context. It is usually not
 * used or needed.
 *
 * If \c use_salt is true and \c salt_bytes is \c NULL_Q_USEFUL_BUF_C,
 * the RNG will be used to make a salt of the same size that the KDF
 * is requested to output.  If \c use_salt is true and \c salt_bytes
 * are not \c NULL_Q_USEFUL_BUF_C, those bytes will be used as the
 * salt. In either case the salt will always be sent in the
 * unprotected headers.  If the \c use_salt is false, no salt will be
 * used in the KDF context and no salt will be sent.
 *
 * Most use case do not need the salt. See discussion in RFC 5869 and
 * NIST SP 800 56 for reasons for sending or not sending a salt.  The
 * purpose of the salt is to provide extra randomness in the KDF
 * context. This is often unnecessary because the ephemeral key is
 * randomly generated anew for every encryption. Note that t_cose
 * assumes integration with a good quality random number generator as
 * sufficient security is unlikely without one.
 *
 * Note that if the salt is used, then the receiver must be able to
 * process a salt. If not, the KDF will produce an incorrect result,
 * and the decryption will fail with the \ref
 * T_COSE_ERR_DATA_AUTH_FAILED error.  The t_cose ECDH decrypt
 * implementation, t_cose_recipient_dec_esdh, will decode the salt
 * header parameter and use it automatically with no configuration on
 * the decryption side. Other COSE implementations may or may not
 * decode and/or process the salt.
 */
static void
t_cose_recipient_enc_esdh_salt(struct t_cose_recipient_enc_esdh *context,
                               const bool                        use_salt,
                               const struct q_useful_buf_c       salt_bytes);


/**
 * \brief Configure a larger buffer to serialize the COSE_KDF_Context.
 *
 * \param[in] context     ESDH encryption context.
 * \param[in] kdf_buffer  The buffer used to serialize the COSE_KDF_Context.
 *
 * For most use, the internal buffer for the COSE_KDF_Context is large
 * enough. The internal buffer size is \ref
 * T_COSE_ENC_COSE_KDF_CONTEXT_SIZE.
 *
 * The \c COSE_KDF_Context described RFC 9053 section 5.3 must fit in
 * this buffer. With no additional context items provided the
 * serialized internal KDF context is about 20 bytes including the
 * protected headers for the algorithm ID. If additional protected
 * headers are added with TODO, PartyU or PartyV are added with
 * t_cose_recipient_enc_esdh_party_info() or suppplemental info is
 * added with t_cose_recipient_enc_esdh_supp_info(), it may be
 * necessary to call this with a buffer larger than \ref
 * T_COSE_ENC_COSE_KDF_CONTEXT_SIZE.
 *
 * \ref T_COSE_ERR_KDF_BUFFER_TOO_SMALL will be returned from
 * t_cose_encrypt_enc() or t_cose_encrypt_enc_detached() if the buffer
 * is too small.
 */
static void
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
                                     const struct q_useful_buf_c  party_v_ident,
                                     const bool                   do_not_send)
{
    me->party_u_ident     = party_u_ident;
    me->party_v_ident     = party_v_ident;
    me->do_not_send_party = do_not_send;
}


static inline void
t_cose_recipient_enc_esdh_supp_info(struct t_cose_recipient_enc_esdh *me,
                                    const struct q_useful_buf_c  supp_pub_other,
                                    const struct q_useful_buf_c  supp_priv_info)
{
    me->supp_pub_other = supp_pub_other;
    me->supp_priv_info = supp_priv_info;
}


static inline void
t_cose_recipient_enc_esdh_salt(struct t_cose_recipient_enc_esdh *me,
                               const bool                        use_salt,
                               const struct q_useful_buf_c       salt_bytes)
{
    me->use_salt   = use_salt;
    me->salt_bytes = salt_bytes;
}


static inline void
t_cose_recipient_enc_esdh_kdf_buf(struct t_cose_recipient_enc_esdh *me,
                                  struct q_useful_buf               kdf_context_buf)
{
    me->kdf_context_buf = kdf_context_buf;
}


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_ENC_ESDH_H__ */
