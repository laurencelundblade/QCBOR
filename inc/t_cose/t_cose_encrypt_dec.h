/*
 * t_cose_encrypt_dec.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_ENCRYPT_DEC_H__
#define __T_COSE_ENCRYPT_DEC_H__

#include <stdint.h>
#include <stdlib.h>
#include "t_cose_parameters.h"
#include "t_cose/t_cose_recipient_dec.h"
#include "t_cose/t_cose_key.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file t_cose_encrypt_dec.h
 *
 * \brief Process a COSE_Encrypt0 or COSE_Encrypt message, which decrypts the
 * integrated or detached ciphertext.
 *
 * TODO: update this documentation
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
 * Context for use with decryption.
 */
struct t_cose_encrypt_dec_ctx {
    /* Private data structure */
    struct t_cose_recipient_dec *recipient_list;

    uint32_t              option_flags;
    struct t_cose_key     cek;

    struct t_cose_parameter_storage   params;
    struct t_cose_parameter           __params[T_COSE_NUM_VERIFY_DECODE_HEADERS];
    struct t_cose_parameter_storage  *p_storage;
};


/**
 * \brief Initialize context to decrypt a \c COSE_Encrypt or \c COSE_Encrypt0.
 *
 * \param[in]      context           The context to initialize.
 * \param[in]      option_flags      Options controlling the encryption.
 *                                   Currently none.
 *
 * TODO: not all of the following is implemented
 * If \c option_flags includes either \ref T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0 
 * or \ref T_COSE_OPT_MESSAGE_TYPE_ENCRYPT then the input message must be
 * \c COSE_Encrypt0 or \c COSE_Encrypt respectively. The error
 * T_COSE_ERR_XXXXXX will be returned if the option_flags indicated
 * \c COSE_Encrypt0 and the input is \c COSE_Encrypt and vice versa.  If
 * \c option_flags are \ref T_COSE_OPT_MESSAGE_TYPE_UNSPECIFIED (which
 * is 0) then the message type will be determined by CBOR tag. If
 * there is no tag then the error T_COSE_ERR_XXXXXX will be returned.
 * The errors mentioned here are returned when t_cose_encrypt_dec() is called.
 *
 * When the message type is COSE_Encrypt0, t_cose_encrypt_dec_set_cek()
 * must have been called to set the CEK and t_cose_encrypt_dec_add_recipient()
 * must not have been called.  When the message type is COSE_Encrypt,
 * t_cose_encrypt_dec_add_recipient() must have been called at least
 * once. t_cose_encrypt_dec_set_cek() can be called to
 * explicitly set the CEK, but it rarely needed as the CEK is
 * generated automatocally from the random number generator when
 * it is not set.
 */
static void
t_cose_encrypt_dec_init(struct t_cose_encrypt_dec_ctx *context,
                        uint32_t                       option_flags);


/**
 * \brief Set content encryption key for \c COSE_Encrypt0.
 *
 * \param[in] context       The t_cose_encrypt_dec_ctx context.
 * \param[in] cek           The content encryption key.
 *
 * This sets the content encryption key (the CEK). This must
 * be called for COSE_Encrypt0 as there is no COSE_Recipient
 * to provide the CEK. The type of the key must be appropriate
 * for the content encryption algorithm for body of the
 * COSE_Encrypt0. This may be obtained by....
 * TODO: implement decode-only mode to return header params
 *
 * If called for COSE_Encrypt, this will be ignored as the CEK
 * comes from the COSE_Recipient.
 */
static void
t_cose_encrypt_dec_set_cek(struct t_cose_encrypt_dec_ctx *context,
                           struct t_cose_key              cek);


/*
 * See the various recipient implementations such as the ones for
 * direct encryption (TBD), keywrap and HPKE.
 */
static void
t_cose_encrypt_dec_add_recipient(struct t_cose_encrypt_dec_ctx *me,
                                 struct t_cose_recipient_dec   *recipient);


/**
 * \brief Decryption of a \c COSE_Encrypt0 or \c COSE_Encrypt structure.
 *
 * \param[in,out] context               The t_cose_encrypt_dec_ctx context.
 * \param[in] message                      The COSE message (a COSE_Encrypt0
 *                                      or COSE_Encrypt).
 * \param[in] aad   Additional data that is verified or \ref NULL_Q_USEFUL_BUF if none.
 * \param[in] plaintext_buffer                A buffer for plaintext.
 * \param[out] plaintext     Place to return pointer and length of the plaintext.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This decrypts and returns the plaintext.
 *
 * It accepts either COSE_Encrypt0 or COSE_Encrypt. For COSE_Encrypt0,
 * t_cose_encrypt_dec_set_cek() must have been called to set the decryption
 * key. For COSE_Encrypt, t_cose_encrypt_dec_add_recipient() must have
 * been called to provide COSE_Recipient processers that have been
 * set up with decryption keys.
 *
 * See also t_cose_encrypt_dec_detached().
 */
// TODO: return the parameters
// TODO: support a decode-only mode
enum t_cose_err_t
t_cose_encrypt_dec(struct t_cose_encrypt_dec_ctx *context,
                   struct q_useful_buf_c          message,
                   struct q_useful_buf_c          aad,
                   struct q_useful_buf            plaintext_buffer,
                   struct q_useful_buf_c         *plaintext);


/**
 * \brief Decrypt a \c COSE_Encrypt0 or \c COSE_Encrypt with detached cipher text.
 *
 * \param[in,out] context               The t_cose_encrypt_dec_ctx context.
 * \param[in] message                      The COSE message (a COSE_Encrypt0
 *                                      or COSE_Encrypt).
 * \param[in] aad   Additional data that is verified or \ref NULL_Q_USEFUL_BUF if none.
 * \param[in] detached_ciphertext  The detached ciphertext.
 * \param[in] plaintext_buffer                A buffer for plaintext.
 * \param[out] plaintext     Place to return pointer and length of the plaintext.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * Note: If the ciphertext is integrated into the COSE_Encrypt0 or COSE_Encrypt
 * structure then set the detached_ciphertext parameter NULL and
 * detached_ciphertext to 0.
 */
enum t_cose_err_t
t_cose_encrypt_dec_detached(struct t_cose_encrypt_dec_ctx *context,
                            struct q_useful_buf_c          message,
                            struct q_useful_buf_c          aad,
                            struct q_useful_buf_c          detached_ciphertext,
                            struct q_useful_buf            plaintext_buffer,
                            struct q_useful_buf_c         *plaintext);


/* ------------------------------------------------------------------------
 * Inline implementations of public functions defined above.
 */
static inline void
t_cose_encrypt_dec_init(struct t_cose_encrypt_dec_ctx *me,
                        uint32_t                       option_flags)
{
    memset(me, 0, sizeof(*me));
    T_COSE_PARAM_STORAGE_INIT(me->params, me->__params);
    me->p_storage        = &(me->params);
    me->option_flags     = option_flags;
}


static inline void
t_cose_encrypt_dec_set_cek(struct t_cose_encrypt_dec_ctx *context,
                           struct t_cose_key              cek)
{
    context->cek = cek;
}


static inline void
t_cose_encrypt_dec_add_recipient(struct t_cose_encrypt_dec_ctx *me,
                                 struct t_cose_recipient_dec   *recipient)
{
    /* Use the base class function to add a signer/recipient to the linked list. */
    t_cose_link_rs((struct t_cose_rs_obj **)&me->recipient_list,
                   (struct t_cose_rs_obj *)recipient);
}



#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_ENCRYPT_DEC_H__ */
