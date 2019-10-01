/*
 * t_cose_sign1_sign.h
 *
 * Copyright (c) 2018-2019, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_SIGN1_H__
#define __T_COSE_SIGN1_H__

#include <stdint.h>
#include <stdbool.h>
#include "qcbor.h"
#include "t_cose_common.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * \file t_cose_sign1_sign.h
 *
 * \brief Create a \c COSE_Sign1, usually for EAT or CWT Token.
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
struct t_cose_sign1_ctx {
    /* Private data structure */
    uint8_t               buffer_for_protected_headers[T_COSE_SIGN1_MAX_PROT_HEADER];
    struct q_useful_buf_c protected_headers;
    int32_t               cose_algorithm_id;
    struct                t_cose_key signing_key;
    int32_t               option_flags;
    QCBOREncodeContext   *cbor_encode_ctx;
};


/**
 * An option_flag for t_cose_sign1_init() to request a short-ciruit signature
 */
#define T_COSE_OPT_SHORT_CIRCUIT_SIG 0x00000001


/**
 * An option_flag for t_cose_sign1_init() to not add the CBOR type 6 tag
 * for COSE_Sign1.
 */
#define T_COSE_OPT_OMIT_CBOR_TAG 0x00000002


/**
 * \brief  Initialize to start creating a \c COSE_Sign1.
 *
 * \param[in] me                 The t_cose signing context.
 * \param[in] option_flags       Select different signing options.
 * \param[in] cose_algorithm_id  The algorithm to sign with. The IDs are
 *                               defined in [COSE (RFC 8152)]
 *                               (https://tools.ietf.org/html/rfc8152) or
 *                               in the [IANA COSE Registry]
 *                           (https://www.iana.org/assignments/cose/cose.xhtml).
 * \param[in] signing_key        Which signing key to use.
 * \param[in] key_id             COSE kid header or \ref NULL_Q_USEFUL_BUF_C.
 * \param[in] cbor_encode_ctx    The CBOR encoder context to output to.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * It is possible to use this to compute the exact size of the
 * resulting token so the exact sized buffer can be allocated. To do
 * this initialize the \c cbor_encode_ctx with \c UsefulBufC that has
 * a \c NULL pointer and large length like \c UINT32_MAX. Then run the
 * normal token creation.  The result will have a NULL pointer and the
 * length of the token that would have been created. When this is run
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
 * of the complete token.
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
enum t_cose_err_t t_cose_sign1_init(struct t_cose_sign1_ctx *me,
                                    int32_t option_flags,
                                    int32_t cose_algorithm_id,
                                    struct t_cose_key signing_key,
                                    struct q_useful_buf_c key_id,
                                    QCBOREncodeContext *cbor_encode_ctx);


/**
 * \brief Finish creation of the \c COSE_Sign1.
 *
 * \param[in] me       The t_cose signing context.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * Call this to complete creation of a signed token started with
 * t_cose_sign1_init().
 *
 * This is when the cryptographic signature algorithm is run.
 *
 * The completed \c COSE_Sign1 is retrieved from the \c
 * cbor_encode_ctx by calling \c QCBOREncode_Finish()
 */
enum t_cose_err_t t_cose_sign1_finish(struct t_cose_sign1_ctx *me);


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_SIGN1_H__ */
