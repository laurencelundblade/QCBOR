/*
 *  t_cose_sign1_verify.h
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef __T_COSE_SIGN1_VERIFY_H__
#define __T_COSE_SIGN1_VERIFY_H__

#include <stdint.h>
#include "q_useful_buf.h"
#include "t_cose_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file t_cose_sign1_verify.h
 *
 * \brief Verify a COSE_Sign1 Message
 *
 * This verifies a \c COSE_Sign1 in compliance with [COSE (RFC 8152)]
 * (https://tools.ietf.org/html/rfc8152). A \c COSE_Sign1 message is a CBOR
 * encoded binary blob that contains headers, a payload and a
 * signature. Usually the signature is made with an EC signing
 * algorithm like ECDSA.
 *
 * This implementation is intended to be small and portable to
 * different OS's and platforms. Its dependencies are:
 * - QCBOR
 * - <stdint.h>, <string.h>, <stddef.h>
 * - Hash functions like SHA-256
 * - Signature verifications functions like ECDSA
 *
 * There is a cryptographic adaptation layer defined in
 * t_cose_crypto.h.  An implementation can be made of the functions in
 * it for different platforms or OS's. This means that different
 * platforms and OS's may support only verification with a particular set
 * of algorithms.
 */


/**
 The result of parsing a set of COSE headers.

 Size on 64-bit machine: 4 + (4 * 16) + 4pad = 72
 Size on 32-bit machine: 4 + (4 * 8) = 36
 */
struct t_cose_headers {
    /** The algorithm ID. \ref T_COSE_UNSET_ALGORITHM_ID if the algorithm ID
     * header is not present. String type algorithm IDs are not
     * supported */
    int32_t               cose_algorithm_id;
    /** The COSE key ID. \c NULL_Q_USEFUL_BUF_C if header is not
	present */
    struct q_useful_buf_c kid;
    /** The COSE initialization vector. \c NULL_Q_USEFUL_BUF_C if header
	is not present */
    struct q_useful_buf_c iv;
    /** The COSE partial initialization vector. \c NULL_Q_USEFUL_BUF_C if
	header is not present */
    struct q_useful_buf_c partial_iv;
    /** The content type as a MIME type like
	"text/plain". \c NULL_Q_USEFUL_BUF_C if header is not present */
    struct q_useful_buf_c content_type_tstr;
    /** The content type as a CoAP Content-Format
	integer. \ref T_COSE_EMPTY_UINT_CONTENT_TYPE if header is not
	present. Allowed range is 0 to UINT16_MAX per RFC 7252. */
    uint32_t              content_type_uint;
};


/**
 * Indicates no COSE algorithm ID or an unset COSE algorithm ID.
 */
#define T_COSE_UNSET_ALGORITHM_ID 0




/**
 * Pass this as \c option_flags to allow verification of
 * short-circuit signatures. This should only be used as
 * a test mode as short-circuit signatures are not secure.
 */
#define T_COSE_OPT_ALLOW_SHORT_CIRCUIT 0x00000001


/**
 * The error \ref T_COSE_ERR_NO_KID is returned if the header kid header
 * is missing. Note that the kid header is primarily passed
 * on to the crypto layer so the crypto layer can look up the
 * key. If the verification key is determined by other than
 * the kid, then it is fine if there is no kid.
 */
#define T_COSE_OPT_REQUIRE_KID 0x00000002


/**
 * Normally this will decode the CBOR presented as a
 * COSE_Sign1 whether it is tagged as such or not.
 * This this option is set, then \ref T_COSE_ERR_INCORRECTLY_TAGGED is returned if
 * it is not tagged.
 */
#define T_COSE_OPT_TAG_REQUIRED  0x00000004


/**
 * Option that disables signature verification.
 * With this option the \c verification_key is not needed.
 * This is useful to parse the COSE_Sign1 to get the kid (key ID)
 * so the key can be found and t_cose_sign1_verify() can
 * be called again, this time with the key.
 *
 * The payload will always be returned whether this is
 * option is given or not.
 *
 * (Note that key ID look up can be part of the crypto adaptation layer
 * so it is not always necessary to use this option.)
 */
#define T_COSE_OPT_PARSE_ONLY  0x00000008



/**
 * Context for signature verification
 * About 20 bytes.
 */
struct t_cose_sign1_verify_ctx {
    /* Private data structure */
    struct t_cose_key     verification_key;
    int32_t               option_flags;
};


/**
 * \brief Initialize for \c COSE_Sign1 message verification.
 *
 * \param[in] option_flags      Options controlling the verification.
 *
 * This must be called before using the context.
 */
static void
t_cose_sign1_verify_init(struct t_cose_sign1_verify_ctx *context,
                         int32_t                         option_flags);


/**
 * \brief Set key for \c COSE_Sign1 message verification.
 *
 * \param[in] verification_key  The verification key to use.
 *
 * The source of the verification key depends on the how the how the
 * underlying cryptographic layer works. Simpler layers have no key
 * store or database in which case the verification key must be passed in
 * the \c verification_key parameter.
 * The OpenSSL cryptographic layer is simple like this.
 *
 * Usually the kid (key ID) header parameter identifies the verification
 * key needed to verify the signature. With a simple cryptographic adaption
 * layer, the caller wishing to use the key ID should call t_cose_sign1_verify()
 * first with the \ref T_COSE_OPT_PARSE_ONLY option. The kid will be returned in \c headers.
 * The caller must then find the key on their own. Then call this
 * to set the key. Last call t_cose_sign1_verify(),
 * again without the \ref T_COSE_OPT_PARSE_ONLY option.
 *
 * When the cryptographic adaptation layer supports key lookup,
 * then calling this is not necessary. Also, if the key is
 * somehow know without examining the \c COSE_Sign1, calling this
 * is not necessary.
 */
static void
t_cose_sign1_set_verification_key(struct t_cose_sign1_verify_ctx *context,
                            struct t_cose_key               verification_key);


/**
 * \brief Verify a COSE_Sign1
 *
 * \param[in] sign1             Pointer and length of CBOR encoded \c COSE_Sign1
 *                              that is to be verified.
 * \param[out] payload          Pointer and length of the payload.
 * \param[out] headers          Place to return parsed headers. Maybe be NULL.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * Verification involves the following steps.
 *
 * The CBOR-format COSE_Sign1 structure is parsed. It makes sure \c sign1
 * is valid CBOR and follows the required structure for \c COSE_Sign1.
 *
 * The protected headers are parsed, particular the algorithm id.
 *
 * The unprotected headers are parsed, particularly the kid.
 *
 * The payload is identified. The internals of the payboad are not parsed.
 *
 * The expected hash, the "to-be-signed" bytes are computed. The hash
 * algorithm to use comes from the signing algorithm in the protected
 * headers. If the algorithm is not known or not supported this will
 * error out.
 *
 * Finally, the signature verification is performed.
 *
 * If it is successful, the pointer of the CBOR-encoded payload is
 * returned. The headers are returned if requested.
 *
 * Note that this only handles standard COSE headers. There are no
 * facilities for custom headers, even though they are allowed.
 *
 * This will recognize the special key ID for short-circuit signing
 * and verify it if the \ref T_COSE_OPT_ALLOW_SHORT_CIRCUIT is set.
 *
 * Indefinite lengths strings are not supported. \ref T_COSE_ERR_SIGN1_FORMAT
 * will be returned if they are in the input \c COSE_Sign1 messages. For
 * example, if the payload is an indefinite length byte string.
 */
enum t_cose_err_t t_cose_sign1_verify(struct t_cose_sign1_verify_ctx *context,                                                                        struct q_useful_buf_c           sign1,
                                      struct q_useful_buf_c          *payload,
                                      struct t_cose_headers          *headers);




/* ------------------------------------------------------------------------
 * Inline implementations of public functions defined above.
 */
static inline void
t_cose_sign1_verify_init(struct t_cose_sign1_verify_ctx *me,
                         int32_t                option_flags)
{
    me->option_flags = option_flags;
    me->verification_key = T_COSE_NULL_KEY;
}


static inline void
t_cose_sign1_set_verification_key(struct t_cose_sign1_verify_ctx *me,
                            struct t_cose_key               verification_key)
{
    me->verification_key = verification_key;
}
#endif /* __T_COSE_SIGN1_VERIFY_H__ */
