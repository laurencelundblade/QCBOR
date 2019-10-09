/*
 * t_cose_make_test_messages.h
 *
 * Copyright (c) 2019, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_MAKE_TEST_MESSAGES__
#define __T_COSE_MAKE_TEST_MESSAGES__

#include <stdint.h>
#include <stdbool.h>
#include "qcbor.h"
#include "t_cose_common.h"
#include "t_cose_sign1_sign.h"

#ifdef __cplusplus
extern "C" {
#endif


#define T_COSE_TEST_HEADER_LABEL 0x80000000

#define T_COSE_TEST_BAD_CRIT_HEADER   0x40000000

#define T_COSE_TEST_EXTRA_HEADER 0x20000000

#define T_COSE_TEST_NO_PROTECTED_HEADERS 0x10000000

#define T_COSE_TEST_NO_UNPROTECTED_HEADERS 0x08000000

#define T_COSE_TEST_NOT_WELL_FORMED_1 0x04000000

#define T_COSE_TEST_NOT_WELL_FORMED_2 0x02000000

#define T_COSE_TEST_UNKNOWN_CRIT_UINT_HEADER 0x01000000

#define T_COSE_TEST_CRIT_HEADER_EXIST 0x00800000

#define T_COSE_TEST_TOO_MANY_CRIT_HEADER_EXIST 0x00400000

#define T_COSE_TEST_BAD_CRIT_LABEL 0x00200000

#define T_COSE_TEST_CRIT_NOT_PROTECTED 0x00100000

#define T_COSE_TEST_TOO_MANY_UNKNOWN 0x00080000

#define T_COSE_TEST_UNKNOWN_CRIT_TSTR_HEADER 0x00040000

#define T_COSE_TEST_ALL_HEADERS 0x00020000

#define T_COSE_TEST_BAD_PROTECTED 0x00010000

#define T_COSE_TEST_UNPROTECTED_NOT_MAP 0x00008000

#define T_COSE_TEST_KID_IN_PROTECTED 0x00004000

#define T_COSE_TEST_TOO_LARGE_CONTENT_TYPE 0x00002000

#define T_COSE_TEST_UNCLOSED_PROTECTED 0x00001000

#define T_COSE_TEST_DUP_CONTENT_ID 0x00000800


/**
 * \file t_cose_sign1_sign.h
 *
 * \brief Create a \c COSE_Sign1 message, usually for EAT or CWT Token.
 *
 * This creates a \c COSE_Sign1 in compliance with [COSE (RFC 8152)]
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
 * - Signing functions like ECDSA
 *
 * There is a cryptographic adaptation layer defined in
 * t_cose_crypto.h.  An implementation can be made of the functions in
 * it for different cryptographic libraries. This means that different
 * integrations with different cryptographic libraries may support only
 * signing with a particular set
 * of algorithms. Key ID look up also varies by different cryptographic
 * library integrations.
 *
 * This \c COSE_Sign1 implementations is optimized for creating EAT
 * and CWT tokens.
 *
 * It should work for CWT and others use cases too. The main point of
 * the optimization is that only one output buffer is needed. There is
 * no need for one buffer to hold the payload and another to hold the
 * end result \c COSE_Sign1. The payload is encoded right into its final
 * place in the end result \c COSE_Sign1.
 */


/**
 * This is the context for creating a \c COSE_Sign1 structure. The caller
 * should allocate it and pass it to the functions here.  This is
 * about 72 bytes so it fits easily on the stack.
 */
struct t_cose_make_test_message {
    /* Private data structure */
    uint8_t               buffer_for_protected_headers[
                              T_COSE_SIGN1_MAX_PROT_HEADER+200];
    struct q_useful_buf_c protected_headers;
    int32_t               cose_algorithm_id;
    struct                t_cose_key signing_key;
    int32_t               option_flags;
    QCBOREncodeContext   *cbor_encode_ctx;
};


/**
 * \brief Start creating a \c COSE_Sign1 message by output the headers.
 *
 * \param[in] me                 The t_cose signing context.
 * \param[in] cbor_encode_ctx    The CBOR encoder context to output to.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * It is possible to use this to compute the exact size of the
 * resulting message so the exact sized buffer can be allocated. To do
 * this initialize the \c cbor_encode_ctx with \c UsefulBufC that has
 * a \c NULL pointer and large length like \c UINT32_MAX. Then run the
 * normal message creation.  The result will have a NULL pointer and the
 * length of the message that would have been created. When this is run
 * like this, the cryptographic functions will not actually run, but
 * the size of their output will be taken into account.
 *
 * The contents of signing_key depends on the crypto library t_cose is integrated with
 * With some libraries it might be a pointer to a structure with the key
 * and on others an integer handle or descriptor.
 *
 * Which signing algorithms are supported depends on the crypto library.
 * The header file t_cose_defines.h contains defined constants for
 * some of them. A typical example is \ref COSE_ALGORITHM_ES256 which
 * indicates ECDSA with the NIST P-256 curve and SHA-256.
 *
 * To use this, create a \c QCBOREncodeContext and initialize it with
 * an output buffer big enough to hold the payload and the COSE Sign 1
 * overhead. This overhead is about 30 bytes plus the size of the
 * signature and the size of the key ID. This is about 150 bytes
 * for ECDSA 256 with a 32-byte key id.
 *
 * After the \c QCBOREncodeContext is initialized, call
 * t_cose_sign1_init() on it.
 *
 * Next call various \c QCBOREncode_Addxxxx() methods to create the
 * payload.
 *
 * Next call t_cose_sign1_finish() with the pointer and length of the
 * payload.  This will do all the cryptography and complete the COSE
 * Sign1.
 *
 * Finally, call \c QCBOREncode_Finish() to get the pointer and length
 * of the complete message.
 *
 * This implements a special signing test mode called _short_
 * _circuit_ _signing_. This mode is useful when there is no signing
 * key available, perhaps because it has not been provisioned or
 * configured for the particular device. It may also be because the
 * public key cryptographic functions have not been connected up in
 * the cryptographic adaptation layer.
 *
 * To select it pass \ref T_COSE_OPT_SHORT_CIRCUIT_SIG as one of the
 * option_flags.
 *
 * It has no value for security at all. Data signed this way should
 * not be trusted as anyone can sign like this.
 *
 * In this mode the signature is the hash of that would normally be
 * signed by the public key algorithm. To make the signature the
 * correct size for the particular algorithm instances of the hash are
 * concatenated to pad it out.
 *
 * This mode is very useful for testing because all the code except
 * the actual signing algorithm is run exactly as it would if a proper
 * signing algorithm was run.
 */
enum t_cose_err_t t_cose_make_test_output_headers(struct t_cose_sign1_ctx *me,
                                    QCBOREncodeContext *cbor_encode_ctx);


/**
 * \brief Finish creation of the \c COSE_Sign1.
 *
 * \param[in] me       The t_cose signing context.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * Call this to complete creation of a signed message started with
 * t_cose_sign1_init().
 *
 * This is when the cryptographic signature algorithm is run.
 *
 * The completed \c COSE_Sign1 is retrieved from the \c
 * cbor_encode_ctx by calling \c QCBOREncode_Finish()
 */
enum t_cose_err_t
t_cose_make_test_output_signature(struct t_cose_sign1_ctx *me,
                                  QCBOREncodeContext *encode_ctx);


enum t_cose_err_t
t_cose_test_message_sign1_sign(struct t_cose_sign1_ctx *me,
                             struct q_useful_buf_c   payload,
                             struct q_useful_buf     out_buf,
                             struct q_useful_buf_c  *result);

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_MAKE_TEST_MESSAGES__ */
