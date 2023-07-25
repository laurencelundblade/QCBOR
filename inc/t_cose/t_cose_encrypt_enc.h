/*
 * t_cose_encrypt_enc.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_ENCRYPT_ENC_H__
#define __T_COSE_ENCRYPT_ENC_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "t_cose_parameters.h"
#include "t_cose/t_cose_key.h"
#include "t_cose/t_cose_recipient_enc.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * \file t_cose_encrypt_enc.h
 *
 * Warning: documentation may be incorrect in some places here.
 *
 * \brief Encrypt plaintext and encode it in a CBOR-based structure
 * referred to as COSE_Encrypt0 or COSE_Encrypt.
 *
 * The functions defined encrypt plaintext with a symmetric
 * cryptographic algorithm.  The result is then stored in \c
 * COSE_Encrypt0 or in a \c COSE_Encrypt message, as defined in [COSE
 * (RFC 8152)] (https://tools.ietf.org/html/rfc8152). \c COSE_Encrypt0
 * and \c COSE_Encrypt messages are CBOR encoded binary payloads that
 * contain header parameters, a payload - the ciphertext. The payload
 * may be detached in which case it is not included in the CBOR
 * encoded message and needs to be conveyed separately.
 *
 * \c COSE_Encrypt and \c COSE_Encrypt0 messages require a symmetric
 * key for encryption (referred to as Content Encryption Key or
 * CEK). Hence, it is necessary to think about key distribution and
 * COSE (RFC 8152) defines various "Content Key Distribution Methods",
 * as RFC 8152 calls it, and two of them are implemented in this
 * library:
 *
 * 1) The CEK is pre-negotiated between the involved communication
 * parties.  Hence, no CEK is transported in the COSE message. For
 * this approach the COSE_Encrypt0 message is used.
 *
 * 2) Key agreement: This approach requires utilizes an algorithm for
 * establishing a shared secret, which then serves as a
 * CEK. Therefore, a recipient structure must be included in the COSE
 * message and the COSE_Encrypt message carries such a recipient
 * structure(while \c COSE_Encrypt0 does not). The key agreement
 * algorithm used in this implementation is based on Hybrid Public Key
 * Encryption (HPKE) and is described in
 * https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/.
 *
 * This implementation is intended to be small and portable to
 * different OS's and platforms. Its dependencies are:
 * - [QCBOR](https://github.com/laurencelundblade/QCBOR)
 * - <stdint.h>, <string.h>, <stddef.h>
 * - Encryption functions like AES-GCM.
 * - Hash functions like SHA-256 (for use with HPKE)
 *
 * Additionally, it is necessary to either sign or MAC the resulting
 * COSE_Encrypt0 or COSE_Encrypt message to provide authentication and
 * integrity protection. This functionality is supported by other APIs
 * in the t_cose library.
 *
 * There is a cryptographic adaptation layer defined in
 * t_cose_crypto.h.  An implementation can be made of the functions in
 * it for different cryptographic libraries. This means that different
 * integrations with different cryptographic libraries may, for
 * example, support only encryption with a particular set of
 * algorithms.  At this moment, only the integration with Mbed TLS
 * (and more specifically the PSA Crypto API) is supported.
 *
 * See t_cose_common.h for preprocessor defines to reduce object code
 * and stack use by disabling features.
 *
 * Direct key distribution requires the following steps to be taken:
 *
 * 1. Use t_cose_encrypt_enc0_init() to initialize the
 *    \c t_cose_encrypt_enc_ctx context.
 * 2. Set the CEK with t_cose_encrypt_set_encryption_key().
 * 3. Call t_cose_encrypt_enc_detached() or t_cose_encrypt_enc().
 *    The former API call does not include the ciphertext in the
 *    COSE_Encrypt0 message while the latter API call does.
 * 4. Call t_cose_encrypt_enc_finish() to create the final output.
 *    When subsequently calling QCBOREncode_Finish() the output
 *    can be serialized into a byte string for distribution in an
 *    Internet protocol.
 *
 * HPKE-based key distribution requires more steps, namely:
 *
 * 1. A recipient context has to be created with
 *    t_cose_encrypt_recipient_init().
 * 2. A CEK has to be generated, for example via the
 *    psa_generate_random() API call, and then set via
 *    t_cose_encrypt_set_encryption_key().
 * 3. An ephemeral ECDHE key pair has to be generated,
 *    for example via psa_generate_key(), and then assigned
 *    to the recipient context using
 *    t_cose_encrypt_set_ephemeral_key().
 * 4. The public key of the recipient has to be imported
 *    and assigned to the recipient context via
 *    t_cose_encrypt_set_recipient_key().
 * 5. Now, the recipient structure can be created with
 *    t_cose_encrypt_create_recipient(). Using
 *    QCBOREncode_Finish() the recipient structure is
 *    seralized as a byte string.
 * 6. Now an encrypt context is needed, which must be
 *    initialized with t_cose_encrypt_enc_init().
 * 7. The t_cose_encrypt_set_encryption_key() is used to
 *    configure the CEK with the encryption context, which
 *    will subsequently be used to encrypt the plaintext.
 * 8. The t_cose_encrypt_enc_detached() or the
 *    t_cose_encrypt_enc() functions will be used to
 *    encrypted the plaintext.
 * 9  The t_cose_encrypt_add_recipient() finalizes the
 *    COSE_Encrypt message the recipient structure has to be
 *    attached.
 * 10.t_cose_encrypt_enc_finish() completes the process and
 *    QCBOREncode_Finish() exports the COSE structure as a
 *    binary string for use in Internet protocols.
 *
 * In a nutshell, the steps are:
 *
 * (a) create a recipient structure, which contains the HPKE
 *     parameters,
 * (b) create a encrypt structure and encrypt the plaintext,
 * (c) attach the recipient to the encrypt structure, and
 * (d) wrap the entire encrypt structure (which includes the
 *     recipient structure).
 */


/**
 * This is the context for creating \c COSE_Encrypt and \c
 * COSE_Encrypt0 structures.  The caller should allocate it and pass
 * it to the functions here. This is around 50 bytes, so it fits
 * easily on the stack.
 */
struct t_cose_encrypt_enc {
    /* Private data structure */
    int32_t                       payload_cose_algorithm_id;
    uint32_t                      option_flags;
    struct t_cose_recipient_enc  *recipients_list;
    struct t_cose_key             cek;
    struct t_cose_parameter      *added_body_parameters;
    struct q_useful_buf           extern_enc_struct_buffer;
    struct q_useful_buf           extern_hash_buffer;
    int32_t                       hash_cose_algorithm_id;
};


/**
 * \brief  Initialize to start creating a \c COSE_Encrypt structure.
 *
 * \param[in,out] context        The t_cose_encrypt_enc_ctx context.
 * \param[in] option_flags       One of \c T_COSE_OPT_XXXX.
 * \param[in] payload_cose_algorithm_id  The algorithm to use for encrypting
 *                               data, for example
 *                               \ref COSE_ALGORITHM_A128GCM.
 *
 * The lower bits of \ref option_flags may be either
 * \ref  T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0 or
 * \ref T_COSE_OPT_MESSAGE_TYPE_ENCRYPT to select the message type. If
 * the lower bits are zero it will default to
 * \re T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0.
 *
 * The algorithm ID is requires and is from [COSE
 * (RFC9053)](https://tools.ietf.org/html/rfc9053) and the [IANA COSE
 * Registry](https://www.iana.org/assignments/cose/cose.xhtml).  \ref
 * T_COSE_ALGORITHM_A128GCM and a few others are defined here for
 * convenience. The supported algorithms depend on the cryptographic
 * library that t_cose is integrated with.  The algorithm ID given
 * here is for the bulk encryption of the payload, typically an AES
 * AEAD algorithm. (Non-recpient HPKE will be an exception here.)
 *
 * The algorithm ID for the COSE_Recipient is set in the particular
 * t_cose_recipient_enc being used. You can even have serveral with
 * different algorithms (but there can only be one payload encryption
 * algorithm).
 * TODO: decode-only mode to get parameters to look up keys
 */
void
t_cose_encypt_enc_init(struct t_cose_encrypt_enc *context,
                       uint32_t                   option_flags,
                       int32_t                    payload_cose_algorithm_id);


/**
 * \brief  Add a recipient to an existing COSE encrypt context.
 *         Information about a recipient needs to be provided.
 *
 *
 * \param[in] context                  The t_cose_encrypt_enc_ctx context.
 * \param[in] recipient  Pointer to recipient object.
 *
 * The recipient object should be initialized with algorithm ID and
 * key material.  Note that for COSE encryption there are two
 * algorithm IDs, the one for the payload/content set with
 * t_cose_encypt_enc_init() and the one for COSE_Recpient set in the
 * API implementing it.
 *
 * The recipient object set here has callbacks that will when t_cose_encrypt_enc()
 * is doing its work.
 *
 * For multiple recipients this is called multiple times. For direct encryption
 * this is not called.
 */
static void
t_cose_encrypt_add_recipient(struct t_cose_encrypt_enc    *context,
                             struct t_cose_recipient_enc  *recipient);


/**
 * \brief Add header parameters to the \c COSE_Encrypt0 or \c COSE_Encrypt main body.
 *
 * \param[in] context     The t_cose encrypting context.
 * \param[in] parameters  Linkes list of parameters to add.
 *
 * For simple use cases it is not necessary to call this as the
 * algorithm ID, the only mandatory parameter, is automatically
 * added.
 *
 *
 * This adds parameters to the \c COSE_Encrypt0 \c COSE_Encrypt
 * body. Parameters in \c COSE_Recipient in \c COSE_Encrypt are handed
 * through \ref t_cose_recipient_enc.
 *
 * This adds a linked list of struct t_cose_parameter terminated by a NULL.
 *
 * Parameters with integer and string parameters are handled by putting
 * there values in the struct t_cose_parameter node in the linked list..
 *
 * All the parameters must have a label and a value.
 *
 * Alternatively, and particularly for parameters that are not
 * integers or strings the value may be a callback of type
 * t_cose_parameter_encode_callback in which case the callback will be
 * called when it is time to output the CBOR for the custom
 * header. The callback should output the CBOR for the particular
 * parameter.
 *
 * This supports only integer labels. (String labels could be added
 * but would increase object code size).
 *
 * All parameters must be added in one call. Multiple calls to this
 * don't accumlate parameters.
 */
static void
t_cose_encrypt_enc_body_header_params(struct t_cose_encrypt_enc *context,
                                      struct t_cose_parameter   *parameters);


/**
 * \brief Set the content-encryption key, the CEK
 *
 *
 * This is required for COSE_Encrypt0 when there is no recipient. This
 * may be used for COSE_Encrypt to explicitly set the CEK. If it is
 * not called the CEK will automatically be generated using the random
 * number generator. (Which random number generator depends on the
 * crypto adaptor layer, but is usually the highest-quality generator
 * on the device. Typically the port of OpenSSL or MbedTLS to the
 * particular platform will use the highest-quality generator).
 *
 * RFC 9052 section 5.2 discourages setting the kid for COSE_Encrypt0
 * so this API doesn't faciliate it, but t_cose_encrypt_enc_body_header_params()
 * can be used to set it.
 *
 * RFC 9052 uses the term "direct" encryption sometimes to refer to
 * COSE_Encrypt0, but much more prevalentaly uses it to refer to a
 * type of COSE_Recipient. See the t_cose_recipient_direct (which hasn't
 * been created yet)
 */
static void
t_cose_encrypt_set_cek(struct t_cose_encrypt_enc *context,
                       struct t_cose_key          cek);


/**
 * \brief Setup buffer for larger AAD or header parameters.
 *
 * \param[in] context    The encryption context
 * \param[in] enc_buffer    Pointer and length of buffer to add.
 *
 * By default there is a limit of T_COSE_ENCRYPT_STRUCT_DEFAULT_SIZE
 * (typically 64 bytes) for the AAD and protected header
 * parameters. Normally this is quite adequate, but it may not be in
 * all cases. If not call this with a larger buffer.
 *
 * Specifically, this is the buffer to create the Enc_structure
 * described in RFC 9052 section 5.2. It needs to be the size of the
 * CBOR-encoded protected headers, the AAD and some overhead.
 *
 * TODO: size calculation mode that will tell the caller how bit it should be
 */
static void
t_cose_encrypt_set_enc_struct_buffer(struct t_cose_encrypt_enc *context,
                                     struct q_useful_buf        enc_buffer);


/**
 * \brief  Create a \c COSE_Encrypt or \c COSE_Encrypt0 structure
 *  and encrypt the provided plaintext.
 *
 * \param[in] context                  The t_cose_encrypt_enc_ctx context.
 * \param[in] payload                  Plaintext to be encypted.
 * \param[in] aad        Additional authenticated data or \ref NULL_Q_USEFUL_BUF if none.
 * \param[in] buffer_for_message                  Buffer for COSE message.
 * \param[out] encrypted_message                  Completed COSE message.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This is where all the work gets done including calling the
 * cryptographic algorithms.  In most cases this will cause callbacks
 * to the t_cose_recipient_enc object to be made to create the
 * COSE_Recipients. Only when direct encryption is used are they not
 * called.
 *
 * The size of encoded protected parameters plus the aad is limited to
 * TODO by default. If it is exceeded the error TODO: will be
 * returned. See TODO to increase this.
 *
 * This puts the encrypted payload in the body of the message. See
 * also t_cose_encrypt_enc_detached().
 *
 * \c buffer_for_message must be large enough to hold the resulting
 * COSE_Encrypt or COSE_Encrypt0 message with the encrypted payload in
 * the message.  To use this in size calculation mode, pass a \c
 * buffer_for_message with ptr NULL and a very large size like \c
 * SIZE_MAX.
 */
static enum t_cose_err_t
t_cose_encrypt_enc(struct t_cose_encrypt_enc *context,
                   struct q_useful_buf_c      payload,
                   struct q_useful_buf_c      aad,
                   struct q_useful_buf        buffer_for_message,
                   struct q_useful_buf_c     *encrypted_message);


/**
 * \brief  Create a \c COSE_Encrypt or \c COSE_Encrypt0 structure
 *  and encrypt the provided plaintext.
 *
 * \param[in] context                  The t_cose_encrypt_enc_ctx context.
 * \param[in] payload                  Plaintext to be encypted.
 * \param[in] aad        Additional authenticated data or \ref NULL_Q_USEFUL_BUF if none.
 * \param[in] buffer_for_detached                 Buffer for detached cipher text.
 * \param[in] buffer_for_message                  Buffer for COSE message.
 * \param[out] encrypted_detached                 Detached ciphertext.
 * \param[out] encrypted_message                  Completed COSE message.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This is the same as t_cose_encrypt_enc() except it produces two
 * separate outputs, the detached ciphertext and the \c COSE_Encrypt
 * or \c COSE_Encrypt0. Typically the detached ciphertext is 16 bytes
 * larger than then payload and the COSE_Encrypt COSE_Encrypt is
 * relatively small and fixed.
 *
 * This may be used in size calculation mode in which case both the
 * size of the detached ciphertext and the encrypted message will be
 * computed and returned.
 *
 * \c buffer_for_detached may be \ref NULL_Q_USEFUL_BUF and \c
 * encrypted_detached may be \c NULL in which case this behaves
 * exactly like t_cose_encrypt_enc().
 */
enum t_cose_err_t
t_cose_encrypt_enc_detached(struct t_cose_encrypt_enc *context,
                            struct q_useful_buf_c      payload,
                            struct q_useful_buf_c      aad,
                            struct q_useful_buf        buffer_for_detached,
                            struct q_useful_buf        buffer_for_message,
                            struct q_useful_buf_c     *encrypted_detached,
                            struct q_useful_buf_c     *encrypted_message);




/* ----------------------- Private Implementations --------------------*/

static inline void
t_cose_encrypt_enc_init(struct t_cose_encrypt_enc *context,
                        uint32_t                   option_flags,
                        int32_t                    payload_cose_algorithm_id
                       )
{
    memset(context, 0, sizeof(*context));
    context->payload_cose_algorithm_id = payload_cose_algorithm_id;
    context->option_flags              = option_flags;
}


static inline void
t_cose_encrypt_set_cek(struct t_cose_encrypt_enc *context,
                       struct t_cose_key          cek)
{
    context->cek = cek;
}


static inline void
t_cose_encrypt_enc_body_header_params(struct t_cose_encrypt_enc   *context,
                                      struct t_cose_parameter *parameters)
{
    context->added_body_parameters = parameters;
}


static inline void
t_cose_encrypt_add_recipient(struct t_cose_encrypt_enc   *me,
                             struct t_cose_recipient_enc *recipient)
{

    /* Use base class function to add a signer/recipient to the linked list. */
    t_cose_link_rs((struct t_cose_rs_obj **)&me->recipients_list,
                   (struct t_cose_rs_obj *)recipient);
}


static inline void
t_cose_encrypt_set_enc_struct_buffer(struct t_cose_encrypt_enc *context,
                                     struct q_useful_buf extern_enc_buffer)
{
    context->extern_enc_struct_buffer = extern_enc_buffer;
}


static inline enum t_cose_err_t
t_cose_encrypt_enc(struct t_cose_encrypt_enc *context,
                   struct q_useful_buf_c      payload,
                   struct q_useful_buf_c      aad,
                   struct q_useful_buf        buffer_for_message,
                   struct q_useful_buf_c     *encrypted_cose_message)
{
    return t_cose_encrypt_enc_detached(context,
                                       payload,
                                       aad,
                                       NULL_Q_USEFUL_BUF,
                                       buffer_for_message,
                                       NULL,
                                       encrypted_cose_message);
}

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_ENCRYPT_ENC_H__ */
