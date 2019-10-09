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
 * about 100 bytes so it fits easily on the stack.
 */
struct t_cose_sign1_ctx {
    /* Private data structure */
    uint8_t               protected_headers_buffer[T_COSE_SIGN1_MAX_PROT_HEADER];
    struct q_useful_buf_c protected_headers;
    int32_t               cose_algorithm_id;
    struct t_cose_key     signing_key;
    int32_t               option_flags;
    struct q_useful_buf_c kid;
#ifndef T_COSE_DISABLE_CONTENT_TYPE
    uint32_t              content_type_uint;
    const char *          content_type_tstr;
#endif
};


/**
 * This selects a signing test mode called _short_
 * _circuit_ _signing_. This mode is useful when there is no signing
 * key available, perhaps because it has not been provisioned or
 * configured for the particular device. It may also be because the
 * public key cryptographic functions have not been connected up in
 * the cryptographic adaptation layer.
 *
 * It has no value for security at all. Data signed this way MUST
 * NOT be trusted as anyone can sign like this.
 *
 * In this mode, the signature is the hash of that which would normally be
 * signed by the public key algorithm. To make the signature the
 * correct size for the particular algorithm, instances of the hash are
 * concatenated to pad it out.
 *
 * This mode is very useful for testing because all the code except
 * the actual signing algorithm is run exactly as it would if a proper
 * signing algorithm was run. This can be used for end-end system testing all
 * the way to a server or relying party, not just for testing device code.
 */
#define T_COSE_OPT_SHORT_CIRCUIT_SIG 0x00000001


/**
 * An option_flag for t_cose_sign1_init() to not add the CBOR type 6 tag
 * for COSE_Sign1 whose value is 18. Some uses of COSE may require
 * this flag be absent because it is know that it is a COSE_Sign1 from
 * surrounding context.
 *
 * Or said another way, per the COSE RFC, this code produces a
 * \c COSE_Sign1_Tagged by default and a \c COSE_Sign1 when this flag is set.
 * The only difference between these two is the CBOR tag.
 */
#define T_COSE_OPT_OMIT_CBOR_TAG 0x00000002




/**
 * \brief  Initialize to start creating a \c COSE_Sign1.
 *
 * \param[in] context            The t_cose signing context.
 * \param[in] option_flags       One of \c T_COSE_OPT_XXXX
 * \param[in] cose_algorithm_id  The algorithm to sign with. The IDs are
 *                               defined in [COSE (RFC 8152)]
 *                               (https://tools.ietf.org/html/rfc8152) or
 *                               in the [IANA COSE Registry]
 *                           (https://www.iana.org/assignments/cose/cose.xhtml).
 *
 * Initialize the \c t_cose_sign1_ctx context. Typically,
 * no \c option_flags are needed and 0 is passed. A
 * \c cose_algorithm_id must always be given.
 *
 * Which signing algorithms are supported depends on the crypto library.
 * The header file t_cose_defines.h contains defined constants for
 * some of them. A typical example is \ref COSE_ALGORITHM_ES256 which
 * indicates ECDSA with the NIST P-256 curve and SHA-256.
 *
 * Errors such as the passing of a bad \c cose_algorithm_id
 * are reported later when t_cose_sign1_sign() or t_cose_sign1_output_headers()
 * is called.
 */
static void
t_cose_sign1_init(struct t_cose_sign1_ctx *context,
                   int32_t                 option_flags,
                   int32_t                 cose_algorithm_id);


/**
 * \brief  Set the key and kid (key ID) for signing.
 *
 * \param[in] context      The t_cose signing context.
 * \param[in] signing_key  The signing key to use or \ref T_COSE_NULL_KEY.
 * \param[in] kid          COSE kid (key ID) header or \ref NULL_Q_USEFUL_BUF_C.
 *
 * This needs to be called to set the signing key to use. The
 * \c kid may be omitted.
 *
 * If short-circuit signing is used (\ref T_COSE_OPT_SHORT_CIRCUIT_SIG), then this does not need to be
 * called. If it is called the \c kid will be used, but the
 * \c signing_key is never used.
 */
static void
t_cose_sign1_set_key(struct t_cose_sign1_ctx *context,
                     struct t_cose_key        signing_key,
                     struct q_useful_buf_c    kid);


/**
 * \brief Set the payload content type using CoAP content types.
 *
 * \param[in] context      The t_cose signing context.
 * \param[in] content_type The content type of the payload as defined
 *                         in the IANA CoAP Content-Formats registry.
 * (https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats)
 *
 * It is not allowed to have both a CoAP and MIME content type. This
 * error will show up when t_cose_sign1_sign() or t_cose_sign1_output_headers()
 * is called.
 *
 */
static inline void
t_cose_sign1_set_content_type_uint(struct t_cose_sign1_ctx *context,
                                   uint16_t                 content_type);

/**
 * \brief Set the payload content type using MIME content types.
 *
 * \param[in] context      The t_cose signing context.
 * \param[in] content_type The content type of the payload as defined
 *                         in the IANA Media Types registry.
 * (https://www.iana.org/assignments/media-types/media-types.xhtml) These
 * have been known as MIME types in the past. 
 *
 * It is not allowed to have both a CoAP and MIME content type. This
 * error will show up when t_cose_sign1_sign() or t_cose_sign1_output_headers()
 * is called.
 */
static inline void
t_cose_sign1_set_content_type_tstr(struct t_cose_sign1_ctx *context,
                                   const char *             content_type);


/**
 * \brief  Create and sign a \c COSE_Sign1 with a payload.
 *
 * \param[in] context  The t_cose signing context.
 * \param[in] payload  Pointer and length of payload to sign.
 * \param[in] out_buf  Pointer and length of buffer to output to.
 * \param[out] result  Pointer and length of the resulting \c COSE_Sign1.
 *
 * The \c context must have been initialized with t_cose_sign1_init()
 * and the key set with t_cose_sign1_set_key() before this is called.
 *
 * This creates the COSE headers, hashes and signs the payload
 * and creates the signature. \c out_buf gives the pointer and
 * length memory into which the output is written. The pointer
 * and length of the actual \c COSE_Sign1 is returned in \c result.
 *
 * Typically the required size of \c out_buf is about 30 bytes plus the size of the
 * signature and the size of the key ID. This is about 150 bytes
 * for ECDSA 256 with a 32-byte key ID.
 *
 * To compute the size of the buffer needed before it is allocated
 * call this with \c out_buf containg a \c NULL pointer and large length like \c UINT32_MAX.
 * The algorithm and key, kid and such should be set up just as if
 * the real \c COSE_Sign1 were to be created as these values are needed
 * to compute the size correctly.
 * The contents of \c result will be a \c NULL pointer and the length
 * of the \c COSE_Sign1. When this is run
 * like this, the cryptographic functions will not actually run, but
 * the size of their output will be taken into account.
 *
 * This function requires the payload be completed formatted
 * in a contiguous buffer. The resulting \C COSE_Sign1 also
 * contains the payload preceeded by the headers and followed
 * by the signature, all CBOR formatted. This function
 * thus requires two copies of the payload to be in memory.
 * Alternatively t_cose_sign1_output_headers() and t_cose_sign1_output_signature()
 * can be used. They are more complex to use, but  avoid
 * the two copies of the payload.
 */
enum t_cose_err_t
t_cose_sign1_sign(struct t_cose_sign1_ctx *context,
                  struct q_useful_buf_c   payload,
                  struct q_useful_buf     out_buf,
                  struct q_useful_buf_c  *result);


/**
 * \brief  Output the \c COSE_Sign1 start and headers.
 *
 * \param[in] context  The t_cose signing context.
 * \param[in] cbor_encode_ctx  Encoding context to output to.
 *
 * This is the more complex and more memory efficient
 * alternative to t_cose_sign1_sign(). Like t_cose_sign1_sign()
 * t_cose_sign1_init() and t_cose_sign1_set_key() much be called
 * before calling this.
 *
 * When this is called the opening parts of the \c COSE_Sign1
 * are output to the \c cbor_encode_ctx.
 *
 * After this is called, the CBOR-formatted payload
 * is written to the \c cbor_encode_ctx by calling all the
 * various \c QCBOREncode_AddXxx calls. It can be as simple
 * or complex as needed.
 *
 * To complete the \c COSE_Sign1 call t_cose_sign1_output_signature().
 *
 * The \c cbor_encode_ctx must have been initialized with an
 * output buffer to hold the \c COSE_Sign1 headers, the payload
 * and the signature.
 *
 * This and t_cose_sign1_output_signature() can be used to
 * calculate the size of the \c COSE_Sign1 in the way
 * QCBOREncode is usually used to calculate sizes. In this
 * case the \c t_cose_sign1_ctx should be initialized with the
 * options, algorithm, key and kid just as normal as these are
 * needed to calculate the size. Then set up the QCBOR encoder
 * context with a \c NULL pointer and large length like \c UINT32_MAX.
 * Call t_cose_sign1_output_headers(), then format the payload into
 * the encoder context, then call t_cose_sign1_output_signature().
 * Finally call QCBOREncode_FinishGetSize() to get the length.
 */
enum t_cose_err_t
t_cose_sign1_output_headers(struct t_cose_sign1_ctx *context,
                            QCBOREncodeContext      *cbor_encode_ctx);


/**
 * \brief Finish creation of the \c COSE_Sign1.
 *
 * \param[in] context          The t_cose signing context.
 * \param[in] cbor_encode_ctx  Encoding context to output to.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * Call this to complete creation of a signed \c COSE_Sign1 started with
 * t_cose_sign1_output_headers().
 *
 * This is when the cryptographic signature algorithm is run.
 *
 * The completed \c COSE_Sign1 is retrieved from the \c
 * cbor_encode_ctx by calling \c QCBOREncode_Finish().
 */
enum t_cose_err_t
t_cose_sign1_output_signature(struct t_cose_sign1_ctx *context,
                              QCBOREncodeContext      *cbor_encode_ctx);






/* ------------------------------------------------------------------------
 * Inline implementations of public functions defined above.
 */
static inline void
t_cose_sign1_init(struct t_cose_sign1_ctx *me,
                   int32_t option_flags,
                   int32_t cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
#ifndef T_COSE_DISABLE_CONTENT_TYPE
    /* Only member for which 0 is not the empty state */
    me->content_type_uint = T_COSE_EMPTY_UINT_CONTENT_TYPE;
#endif

    me->cose_algorithm_id = cose_algorithm_id;
    me->option_flags      = option_flags;
}


static inline void
t_cose_sign1_set_key(struct t_cose_sign1_ctx *me,
                     struct t_cose_key signing_key,
                     struct q_useful_buf_c kid)
{
    me->kid         = kid;
    me->signing_key = signing_key;
}


#ifndef T_COSE_DISABLE_CONTENT_TYPE
static inline void
t_cose_sign1_set_content_type_uint(struct t_cose_sign1_ctx *me,
                                   uint16_t                 content_type)
{
    me->content_type_uint = content_type;
}


static inline void
t_cose_sign1_set_content_type_tstr(struct t_cose_sign1_ctx *me,
                                   const char *             content_type)
{
    me->content_type_tstr = content_type;
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_SIGN1_H__ */
