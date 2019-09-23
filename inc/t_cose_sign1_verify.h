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
 * \brief Verify a COSE_Sign1
 *
 * This verifies a \c COSE_Sign1 in compliance with [COSE (RFC 8152)]
 * (https://tools.ietf.org/html/rfc8152). A \c COSE_Sign1 is a CBOR
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
 * platforms and OS's may support only signing with a particular set
 * of algorithms.
 *
 */


/**
 Pass this as \c option_flags to allow verification of
 short-circuit signatures. This should only be used as
 a test mode as short-circuit signatures are not secure.
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
 * This is useful to parse the COSE_Sign1 to get the key ID
 * so the key can be found and t_cose_sign1_verify() can
 * be called again, this time with the key.
 *
 * (Note that key ID look up can be part of the crypto adaptation layer
 * so it is not always necessary to use this option.)
 *
 */
#define T_COSE_OPT_PARSE_ONLY  0x00000008


/**
 * \brief Verify a COSE_Sign1
 *
 * \param[in] option_flags      Options controlling the verification.
 * \param[in] verification_key  The verification key to use. May be empty.
 * \param[in] sign1             Pointer and length of CBOR encoded \c COSE_Sign1
 *                              that is to be verified.
 * \param[out] payload          Pointer and length of the payload.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * Verification involves the following steps.
 *
 * The CBOR structure is parsed and verified. It makes sure \c sign1
 * is valid CBOR and that it is tagged as a \c COSE_Sign1.
 *
 * The signing algorithm is pulled out of the protected headers.
 *
 * The kid (key ID) is parsed out of the unprotected headers.
 *
 * The payload is identified. It doesn't have to be parsed in detail
 * because it is wrapped in a bstr.
 *
 * The expected hash, the "to-be-signed" bytes are computed. The hash
 * algorithm to use comes from the signing algorithm in the protected
 * headers. If the algorithm is not known or not supported this will
 * error out.
 *
 * The verification key can either be passed in as \c verification_key or looked up by
 * the key id in the header. Which depends on the way the crypto
 * library is integrated. In more simple integrations then key
 * must be passed in.
 *
 * Finally, the signature verification is performed.
 *
 * If it is successful, the pointer of the CBOR-encoded payload is
 * returned.
 *\ref  T_COSE_OPT_TAG_REQUIRED * This will recognize the special kid for short-circuit signing
 * and verify it if the \ref T_COSE_OPT_ALLOW_SHORT_CIRCUIT is set.
 */
enum t_cose_err_t t_cose_sign1_verify(int32_t option_flags,
                                      struct t_cose_key verification_key,
                                      struct q_useful_buf_c sign1,
                                      struct q_useful_buf_c *payload);


#endif /* __T_COSE_SIGN1_VERIFY_H__ */
