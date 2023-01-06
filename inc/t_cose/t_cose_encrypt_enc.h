/*
 * t_cose_encrypt_enc.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
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
#include "t_cose_crypto.h"
#include "t_cose/t_cose_recipient_enc.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef QCBOR_SPIFFY_DECODE
#error This version of t_cose requires a version of QCBOR that supports spiffy decode
#endif


/**
 * \file t_cose_encrypt_enc.h
 *
 * \brief Encrypt plaintext and encode it in a CBOR-based structure referred to as
 * COSE_Encrypt0 or COSE_Encrypt.
 *
 * The functions defined encrypt plaintext with a symmetric cryptographic algorithm.
 * The result is then stored in \c COSE_Encrypt0 or in a \c COSE_Encrypt
 * message, as defined in [COSE (RFC 8152)]
 * (https://tools.ietf.org/html/rfc8152). \c COSE_Encrypt0 and \c COSE_Encrypt
 * messages are CBOR encoded binary payloads that contain header parameters,
 * a payload - the ciphertext. The payload may be detached in which case it is
 * not included in the CBOR encoded message and needs to be conveyed separately.
 *
 * \c COSE_Encrypt and \c COSE_Encrypt0 messages require a symmetric key for encryption
 * (referred to as Content Encryption Key or CEK). Hence, it is necessary to think
 * about  key distribution and COSE (RFC 8152) defines various "Content Key
 * Distribution Methods", as RFC 8152 calls it, and two of them are
 * implemented in this library:
 *
 * 1) Direct: The CEK is pre-negotiated between the involved communication parties.
 * Hence, no CEK is transported in the COSE message. For this approach the COSE_Encrypt0
 * message is used.
 *
 * 2) Key agreement: This approach requires utilizes an algorithm for establishing
 * a shared secret, which then serves as a CEK. Therefore, a recipient structure
 * must be included in the COSE message and the COSE_Encrypt message carries such
 * a recipient structure(while \c COSE_Encrypt0 does not). The key agreement
 * algorithm used in this implementation is based on Hybrid Public Key Encryption
 * (HPKE) and is described in https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/.
 *
 * This implementation is intended to be small and portable to
 * different OS's and platforms. Its dependencies are:
 * - [QCBOR](https://github.com/laurencelundblade/QCBOR)
 * - <stdint.h>, <string.h>, <stddef.h>
 * - Encryption functions like AES-GCM.
 * - HPKE when COSE_Encrypt is utilized. The HPKE library can be found
 *   at https://github.com/hannestschofenig/mbedtls/tree/hpke
 * - Hash functions like SHA-256 (for use with HPKE)
 *
 * Additionally, it is necessary to either sign or MAC the resulting
 * COSE_Encrypt0 or COSE_Encrypt message to provide authentication and
 * integrity protection. This functionality is supported by other APIs in
 * the t_cose library.
 *
 * There is a cryptographic adaptation layer defined in
 * t_cose_crypto.h.  An implementation can be made of the functions in
 * it for different cryptographic libraries. This means that different
 * integrations with different cryptographic libraries may, for example,
 * support only encryption with a particular set of algorithms.
 * At this moment, only the integration with Mbed TLS (and more
 * specifically the PSA Crypto API) is supported.
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
 * An \c option_flag for t_cose_encrypt_enc_init()
 */
#define T_COSE_OPT_COSE_ENCRYPT            0x00000000
#define T_COSE_OPT_COSE_ENCRYPT0           0x00000001
#define T_COSE_OPT_COSE_ENCRYPT_SINGLE_CEK 0x00000002
#define T_COSE_OPT_COSE_ENCRYPT_DETACHED   0x00000004


/**
 * This is the context for creating \c COSE_Encrypt and \c COSE_Encrypt0 structures.
 * The caller should allocate it and pass it to the functions here. This
 * is around 76 bytes, so it fits easily on the stack.
 */
struct t_cose_encrypt_enc_ctx {
    /* Private data structure */
    struct q_useful_buf_c               protected_parameters;
    int32_t                             cose_algorithm_id;
    uint8_t                            *key;
    size_t                              key_len;
    uint32_t                            option_flags;
    struct q_useful_buf_c               kid;
    uint8_t                             recipients;
    struct t_cose_encrypt_recipient_ctx recipient_ctx;
};


/**
 * \brief  Add a recipient to an existing COSE encrypt context.
 *         Information about a recipient needs to be provided.
 *
 *         Note: This implementation currently supports a single
 *         recipient only. It will be extended later to supports
 *         multiple recipients.
 *
 * \param[in] context                  The t_cose_encrypt_enc_ctx context.
 * \param[in] cose_algorithm_id        COSE algorithm id.
 * \param[in] recipient_key            Key used with the recipient.
 * \param[in] kid                      Key identifier.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 */
enum t_cose_err_t
t_cose_encrypt_add_recipient(struct t_cose_encrypt_enc_ctx*   context,
                             int32_t                          cose_algorithm_id,
                             struct t_cose_key                recipient_key,
                             struct q_useful_buf_c            kid);


/**
 * \brief  Create a \c COSE_Encrypt or \c COSE_Encrypt0 structure
 *  and encrypt the provided plaintext. Two variants are supported
 *  by this function:
 *  - Detached ciphertext: In this case the ciphertext is not included
 *    in the resulting COSE structure and has to be conveyed separately.
 *  - Embedded ciphertext: In this mode the ciphertext is included in
 *    the COSE structure.
 *
 *    See option_flags in t_cose_encrypt_enc_init to toggle between these
 *    two modes.
 *
 * \param[in] context                  The t_cose_encrypt_enc_ctx context.
 * \param[in] payload                  Plaintext.
 * \param[in] encrypted_payload        Buffer where the ciphertext goes.
 * \param[out] encrypted_payload_final Ciphertext with correct length.
 * \param[in] out_buf                  Buffer allocated for COSE message.
 * \param[out] result                  COSE message with correct length.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 */
enum t_cose_err_t
t_cose_encrypt_enc(struct t_cose_encrypt_enc_ctx *context,
                   struct q_useful_buf_c          payload,
                   struct q_useful_buf            encrypted_payload,
                   struct q_useful_buf_c         *encrypted_payload_final,
                   struct q_useful_buf            out_buf,
                   struct q_useful_buf_c         *result);

/**
 * \brief  Initialize to start creating a \c COSE_Encrypt structure.
 *
 * \param[in,out] context        The t_cose_encrypt_enc_ctx context.
 * \param[in] option_flags       One of \c T_COSE_OPT_XXXX.
 * \param[in] cose_algorithm_id  The algorithm to use for encrypting
 *                               data, for example
 *                               \ref COSE_ALGORITHM_A128GCM.
 *
 * Initializes the \ref t_cose_encrypt_enc_ctx context. No
 * \c option_flags are needed and 0 can be passed. A \c cose_algorithm_id
 * must always be given.
 *
 * The algorithm ID space is from
 * [COSE (RFC8152)](https://tools.ietf.org/html/rfc8152) and the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 * \ref COSE_ALGORITHM_A128GCM and a few others are defined here for
 * convenience. The supported algorithms depend on the
 * cryptographic library that t_cose is integrated with.
 */
static inline void
t_cose_encrypt_enc_init( struct t_cose_encrypt_enc_ctx *context,
                         uint32_t                       option_flags,
                         int32_t                        cose_algorithm_id
                       )
{
    memset(context, 0, sizeof(*context));
    context->cose_algorithm_id = cose_algorithm_id;
    context->option_flags = option_flags;
    context->recipients = 0;
}


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_ENCRYPT_ENC_H__ */
