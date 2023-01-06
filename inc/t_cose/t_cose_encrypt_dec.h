/*
 * t_cose_encrypt_dec.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_ENCRYPT_DEC_H__
#define __T_COSE_ENCRYPT_DEC_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "t_cose_parameters.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef QCBOR_SPIFFY_DECODE
#error This version of t_cose requires a version of QCBOR that supports spiffy decode
#endif

/**
 * \file t_cose_encrypt_dec.h
 *
 * \brief Process a COSE_Encrypt0 or COSE_Encrypt message, which decrypts the
 * integrated or detached ciphertext.
 *
 * The functions in this file decrypt ciphertext with a symmetric cryptographic
 * algorithm, as defined in [COSE (RFC 8152)]
 * (https://tools.ietf.org/html/rfc8152), for use with \c COSE_Encrypt0 and
 * \c COSE_Encrypt messages. The ciphertext may be detached, in which case it
 * is not included in the CBOR encoded message.
 *
 * \c COSE_Encrypt and \c COSE_Encrypt0 messages require a symmetric key for
 * decryption (referred to as Content Encryption Key or CEK). Two "Content
 * Key Distribution Methods" are implemented in this library:
 *
 * 1) Direct: The CEK is pre-negotiated between the involved communication
 * parties. For this approach the COSE_Encrypt0 message is used and no
 * encrypted CEK is conveyed in the message.
 *
 * 2) Key agreement: This approach requires utilizes an algorithm for
 * establishing a shared secret, which then serves as a CEK. This approach
 * requires a so-called recipient structure to be included in the COSE
 * message. COSE_Encrypt carries such a recipient structure while
 * \c COSE_Encrypt0 does not. The key agreement algorithm used in this
 * implementation is based on Hybrid Public Key Encryption (HPKE) and
 * is described in https://datatracker.ietf.org/doc/draft-ietf-cose-hpke/.
 *
 * This implementation is intended to be small and portable to
 * different OS's and platforms. Its dependencies are:
 * - [QCBOR](https://github.com/laurencelundblade/QCBOR)
 * - <stdint.h>, <string.h>, <stddef.h>
 * - Decryption functions like AES-GCM.
 * - HPKE when COSE_Encrypt is utilized. The HPKE library can be found
 *   at https://github.com/hannestschofenig/mbedtls/tree/hpke
 * - Hash functions like SHA-256 (for use with HPKE)
 *
 * Prior to using the decryption functionality, a digital signature or MAC
 * must be verified. Signing and MACing is supported by other APIs in the
 * t_cose library.
 *
 * There is a cryptographic adaptation layer defined in t_cose_crypto.h.
 * An implementation can be made of the functions in it for different
 * cryptographic libraries. This means that different integrations with
 * different cryptographic libraries may, for example, support only
 * encryption with a particular set of algorithms. At this moment, only
 * the integration with Mbed TLS (and more specifically the PSA Crypto
 * API) is supported.
 *
 * See t_cose_common.h for preprocessor defines to reduce object code
 * and stack use by disabling features.
 *
 * A recipient of a COSE_Encrypt0 or a COSE_Encrypt message knows what key
 * distribution mechanism is utilized in a specific context since the keys
 * have to be available accordingly.
 *
 * 1. Import a key, for example with psa_import_key().
 *    This key may be the pre-agreed CEK (in case of direct key distribution)
 *    or the private key corresponding to the public key used by the sender
 *    (in case of key agreement with HPKE).
 * 2. Initialize the decrypt context with t_cose_encrypt_dec_init() for use
 *    with a selected key distribution mechanism.
 * 3. Use t_cose_encrypt_dec_set_private_key() to associate the previously
 *    imported key with the decryption structure.
 * 4. Call t_cose_encrypt_dec() to decrypt the ciphertext.
 */

/**
 * Support key distribution types for use with t_cose_encrypt_dec_init().
 */
#define T_COSE_KEY_DISTRIBUTION_DIRECT 0x00000001
#define T_COSE_KEY_DISTRIBUTION_HPKE   0x00000002

/**
 * Context for use with decryption.
 */
struct t_cose_encrypt_dec_ctx {
    /* Private data structure */
    uint32_t              key_distribution;
    uint32_t              option_flags;
    struct q_useful_buf_c kid;
    struct t_cose_key     recipient_key;
};

/**
 * \brief Initialize context for \c COSE_Encrypt and \c COSE_Encrypt0
 * decryption.
 *
 * \param[in]      context           The context to initialize.
 * \param[in]      option_flags      Options controlling the encryption.
 *                                   Currently none.
 * \param[in]      key_distribution  Key distribution setting
 */
static void
t_cose_encrypt_dec_init(struct t_cose_encrypt_dec_ctx *context,
                        uint32_t                       option_flags,
                        uint32_t                       key_distribution);


/**
 * \brief Set private key for decryption of \c COSE_Encrypt and
 * \c COSE_Encrypt0.
 *
 * \param[in] context       The t_cose_encrypt_dec_ctx context.
 * \param[in] key           The private key.
 * \param[in] kid           The key identifier.
 *
 * Important: The key distribution mechanism determines what type of key
 * is provided. When direct key management is used then the key parameter
 * contains a symmetric key (and the \c COSE_Encrypt0 structure is assumed).
 * For use with HPKE an asymmetric private key has to be provided and the
 * \c COSE_Encrypt structure is assumed.
 */
static void
t_cose_encrypt_dec_set_private_key(struct t_cose_encrypt_dec_ctx *context,
                                   struct t_cose_key              key,
                                   struct q_useful_buf_c          kid);


/**
 * \brief Decryption of a \c COSE_Encrypt0 or \c COSE_Encrypt structure.
 *
 * \param[in,out] context               The t_cose_encrypt_dec_ctx context.
 * \param[in] cose                      The COSE payload (a COSE_Encrypt0
 *                                      or COSE_Encrypt).
 * \param[in] cose_len                  The COSE payload length.
 * \param[in] detached_ciphertext       The detached ciphertext.
 * \param[in] detached_ciphertext_len   The detached ciphertext length.
 * \param[out] plaintext_ptr                A buffer for plaintext.
 * \param[in] plaintext_len             The length of the plaintext buffer.
 * \param[out] plaintext     Place to return pointer and length of the plaintext.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * Note: If the ciphertext is integrated into the COSE_Encrypt0 or COSE_Encrypt
 * structure then set the detached_ciphertext parameter NULL and
 * detached_ciphertext to 0.
 */
enum t_cose_err_t
t_cose_encrypt_dec(struct t_cose_encrypt_dec_ctx *context,
                   uint8_t *cose, size_t cose_len,
                   uint8_t *detached_ciphertext, size_t detached_ciphertext_len,
                   uint8_t *plaintext_ptr, size_t plaintext_len,
                   struct q_useful_buf_c *plaintext
                  );

/* ------------------------------------------------------------------------
 * Inline implementations of public functions defined above.
 */
static inline void
t_cose_encrypt_dec_init(struct t_cose_encrypt_dec_ctx *context,
                        uint32_t                       option_flags,
                        uint32_t                       key_distribution)
{
    memset(context, 0, sizeof(*context));
    context->option_flags = option_flags;
    context->key_distribution = key_distribution;
}

static inline void
t_cose_encrypt_dec_set_private_key(struct t_cose_encrypt_dec_ctx *context,
                                   struct t_cose_key              recipient_key,
                                   struct q_useful_buf_c          kid)
{
    context->recipient_key = recipient_key;
    memcpy(&context->kid, &kid, sizeof(struct q_useful_buf_c));
}

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_ENCRYPT_DEC_H__ */
