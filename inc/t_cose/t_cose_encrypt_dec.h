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

/* This is alpha-release code; documentation is mostly OK, but
 * still likely to be incomplete and wrong at times.
 *
 * Here's the major TODO items:
 *   decode only mode
 *   size calculation mode include of Enc_structure size
 *   testing of error conditions and make error codes better
 *   tag message type detection
 *   header decode call back functions
 *   AE algorithms
 *   HPKE single-recipient mode
 */


/**
 * \file t_cose_encrypt_dec.h
 *
 * \brief Process a COSE_Encrypt0 or COSE_Encrypt message, which
 * decrypts the integrated or detached ciphertext.
 *
 * The functions in this file decrypt ciphertext with a symmetric
 * cryptographic algorithm, as defined in [COSE (RFC 9052)]
 * (https://tools.ietf.org/html/rfc9052), for use with \c
 * COSE_Encrypt0 and \c COSE_Encrypt messages. The ciphertext may be
 * detached, in which case it is not included in the CBOR encoded
 * message.
 *
 * \c COSE_Encrypt and \c COSE_Encrypt0 messages require a symmetric
 * key for decryption (referred to as Content Encryption Key or
 * CEK). For \c COSE_Encrypt0 the CEK is supplied directly by an API
 * below.  For \c COSE_Encrypt the CEK is provided in a \c
 * COSE_Recipient that is carried in the \c COSE_Encrypt. There
 * several types of \c COSE_Recipient such as HPKE and keywrap.  \c
 * COSE_Recipient implementations are separate objects that plug-in
 * here. This supports multiple \c COSE_Recipients and \c
 * COSE_Recipients of multiple types simultanesously.  They are
 * defined in separate headers files.
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
 * Prior to using the decryption functionality, a digital signature or
 * MAC should be verified. Signing and MACing is supported by other
 * APIs in the t_cose library.
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
 */


/**
 * Context for decryption.
 */
struct t_cose_encrypt_dec_ctx {
    /* Private data structure */
    struct t_cose_recipient_dec *recipient_list;

    uint32_t              option_flags;
    struct t_cose_key     cek;

    struct t_cose_parameter_storage   params;
    struct t_cose_parameter           __params[T_COSE_NUM_VERIFY_DECODE_HEADERS];
    struct t_cose_parameter_storage  *p_storage;

    uint64_t                         unprocessed_tag_nums[T_COSE_MAX_TAGS_TO_RETURN];

    struct q_useful_buf           extern_enc_struct_buffer;
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


/**
 * \brief Add a \c COSE_Recipient decryptor/decoder.
 *
 * \param[in] context     Encrypted message decryption context.
 * \param[in] recipient  Recipient decryptor/decoder object.

 * See the various recipient implementations such as the ones for
 * keywrap and HPKE.
 *
 * This may be called multiple times to configure many \c
 * COSE_Recipient decryptor/decoders. Many of the same type may be
 * added for different keys with different key IDs. Many of different
 * types may be added.
 *
 * See t_cose_encrypt_dec() for the details of each individual
 * t_cose_recipient_dec is invoked in a loop on each COSE_Recipient.
 */
static void
t_cose_encrypt_dec_add_recipient(struct t_cose_encrypt_dec_ctx *context,
                                 struct t_cose_recipient_dec   *recipient);


/**
 * \brief Add storage for header parameter decoding.
 *
 * \param[in] context     Encrypted message decryption context.
 * \param[in] storage     The parameter storage to add.
 *
 * This is optionally called to increase the number of storage nodes
 * for COSE_Encrypt or COSE_Encrypt0 message with
 * T_COSE_NUM_VERIFY_DECODE_HEADERS header parameters.  Decoded
 * parameters are returned in a linked list of struct
 * t_cose_parameter.  The storage for the nodes in the list is not
 * dynamically allocated as there is no dynamic storage allocation
 * used here.
 *
 * It is assumed that the number of parameters is small and/or can be
 * anticipated.  There must be room to decode all the header
 * parameters that are in the body and in all in the
 * COSE_Signatures. If not \ref T_COSE_ERR_TOO_MANY_PARAMETERS will be
 * returned by t_cose_sign_verify() and similar.
 *
 * By default, if this is not called there is internal storage for
 * \ref T_COSE_NUM_VERIFY_DECODE_HEADERS headers. If this is not
 * enough call this function to use external storage instead of the
 * internal. This replaces the internal storage. It does not add to
 * it.
 *
 * t_cose_parameter_storage allows for the storage to be partially
 * used when it is passed in and whatever is not used by this
 * decode can be used elsewhere. It internall keeps track of how
 * many nodes were used.
 */
static void
t_cose_encrypt_add_param_storage(struct t_cose_encrypt_dec_ctx   *context,
                                 struct t_cose_parameter_storage *storage);

// TODO: Add equivalent of t_cose_signature_verify_main_set_special_param_decoder()

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
t_cose_decrypt_set_enc_struct_buffer(struct t_cose_encrypt_dec_ctx *context,
                                     struct q_useful_buf            enc_buffer);

/**
 * \brief Decryption of a \c COSE_Encrypt0 or \c COSE_Encrypt structure.
 *
 * \param[in,out] context       The t_cose_encrypt_dec_ctx context.
 * \param[in] message           The COSE message (a COSE_Encrypt0
 *                              or COSE_Encrypt).
 * \param[in] aad               Additional data that is verified or
 *                              \ref NULL_Q_USEFUL_BUF if none.
 * \param[in] plaintext_buffer  A buffer for plaintext.
 * \param[out] plaintext        Place to return pointer and length of
 *                              the plaintext.
 * \param[out] returned_parameters  Linked list of all header parameters.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This returns the decrypted plain text.
 *
 * It accepts either COSE_Encrypt0 or COSE_Encrypt. For COSE_Encrypt0,
 * t_cose_encrypt_dec_set_cek() must have been called to set the
 * decryption key. For COSE_Encrypt,
 * t_cose_encrypt_dec_add_recipient() must have been called to provide
 * COSE_Recipient processers that have been set up with decryption
 * keys.
 *
 * Each \ref struct t_cose_recipient_dec is invoked on each \c
 * COSE_Recipient until one successfully decrypts the content
 * encryption key. Only one success is necessary. Each
 * t_cose_recipient_dec may decline to decrypt if it is not suitable
 * for the particular COSE_Recipient (the algorith ID doesn't match)
 * or if the key ID (the kid) doesn't match). If a
 * t_cose_recipient_dec attempts and fails, this is a hard error that
 * stops the decode of the whole COSE_Encrypt.
 *
 * See also t_cose_encrypt_dec_detached().
 */
// TODO: support a decode-only mode
static enum t_cose_err_t
t_cose_encrypt_dec(struct t_cose_encrypt_dec_ctx *context,
                   struct q_useful_buf_c          message,
                   struct q_useful_buf_c          aad,
                   struct q_useful_buf            plaintext_buffer,
                   struct q_useful_buf_c         *plaintext,
                   struct t_cose_parameter      **returned_parameters);


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
 * \param[out] returned_parameters  Place to return linked list of header parameters.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * Note: If the ciphertext is integrated into the COSE_Encrypt0 or
 * COSE_Encrypt structure then set the detached_ciphertext parameter
 * NULL and detached_ciphertext to 0.
 */
enum t_cose_err_t
t_cose_encrypt_dec_detached(struct t_cose_encrypt_dec_ctx *context,
                            struct q_useful_buf_c          message,
                            struct q_useful_buf_c          aad,
                            struct q_useful_buf_c          detached_ciphertext,
                            struct q_useful_buf            plaintext_buffer,
                            struct q_useful_buf_c         *plaintext,
                            struct t_cose_parameter      **returned_parameters);



/**
 * \brief Return unprocessed tags from most recent decryption.
 *
 * \param[in] context   The t_cose decryption context.
 * \param[in] n         Index of the tag to return.
 *
 * \return  The tag value or \ref CBOR_TAG_INVALID64 if there is no tag
 *          at the index or the index is too large.
 *
 * The 0th tag is the one for which the COSE message is the content. Loop
 * from 0 up until \ref CBOR_TAG_INVALID64 is returned. The maximum
 * is \ref T_COSE_MAX_TAGS_TO_RETURN.
 *
 * It will be necessary to call this for a general implementation
 * of a CWT since sometimes the CWT tag is required. This is also
 * useful for recursive processing of nested COSE signing, mac
 * and encryption.
 */
static inline uint64_t
t_cose_encrypt_dec_nth_tag(const struct t_cose_encrypt_dec_ctx *context,
                           size_t                               n);


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


static inline void
t_cose_encrypt_add_param_storage(struct t_cose_encrypt_dec_ctx   *me,
                                 struct t_cose_parameter_storage *storage)
{
    me->p_storage = storage;
}


static inline void
t_cose_decrypt_set_enc_struct_buffer(struct t_cose_encrypt_dec_ctx *context,
                                     struct q_useful_buf extern_enc_buffer)
{
    context->extern_enc_struct_buffer = extern_enc_buffer;
}



static inline enum t_cose_err_t
t_cose_encrypt_dec(struct t_cose_encrypt_dec_ctx *me,
                   struct q_useful_buf_c          message,
                   struct q_useful_buf_c          aad,
                   struct q_useful_buf            plaintext_buffer,
                   struct q_useful_buf_c         *plaintext,
                   struct t_cose_parameter      **returned_parameters)
{
    return t_cose_encrypt_dec_detached(me,
                                       message,
                                       aad,
                                       NULL_Q_USEFUL_BUF_C,
                                       plaintext_buffer,
                                       plaintext,
                                       returned_parameters);
}


static inline uint64_t
t_cose_encrypt_dec_nth_tag(const struct t_cose_encrypt_dec_ctx *me,
                           size_t                               n)
{
    if(n > T_COSE_MAX_TAGS_TO_RETURN) {
        return CBOR_TAG_INVALID64;
    }
    return me->unprocessed_tag_nums[n];
}

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_ENCRYPT_DEC_H__ */
