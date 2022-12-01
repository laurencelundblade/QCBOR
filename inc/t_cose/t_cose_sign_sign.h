/*
 * t_cose_sign_sign.h
 *
 * Copyright (c) 2018-2022, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2020, Michael Eckel
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_SIGN_SIGN_H__
#define __T_COSE_SIGN_SIGN_H__

#include <stdint.h>
#include <stdbool.h>
#include "qcbor/qcbor.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_parameters.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * \file t_cose_sign_sign.h
 *
 * \brief Create a \c COSE_Sign or \c COSE_Sign1 message.
 *
 * This creates a \c COSE_Sign1 of \c COSE_Sign message in compliance with
 * [COSE (RFC 8152)](https://tools.ietf.org/html/rfc8152).
 * A \c COSE_Sign1 or \c COSE_Sign message is a CBOR encoded binary blob that contains
 * header parameters, a payload and a signature or signatures.
 *
 * This implementation is intended to be small and portable to
 * different OS's and platforms. Its dependencies are:
 * - [QCBOR](https://github.com/laurencelundblade/QCBOR)
 * - <stdint.h>, <string.h>, <stddef.h>
 * - Hash functions like SHA-256
 * - Signing functions like ECDSA
 *
 * This must be configured with a signer, an instance of \ref t_cose_signature_sign,
 * to function. This signer is what produces the actual signature. An example
 * of a signer is \ref t_cose_signature_sign_ecdsa. See t_cose_sign_add_signer().
 *
 * There is a cryptographic adaptation layer defined in
 * t_cose_crypto.h.  An implementation can be made of the functions in
 * it for different cryptographic libraries. This means that different
 * integrations with different cryptographic libraries may support
 * only signing with a particular set of algorithms. Integration with
 * [OpenSSL](https://www.openssl.org) is supported.  Key ID look up
 * also varies by different cryptographic library integrations.
 *
 * This implementation has a mode where a CBOR-format payload can be
 * output directly into the output buffer. This saves having two
 * copies of the payload in memory. For this mode use
 * t_cose_sign_encode_start() and
 * t_cose_sign_encode_finish(). For a simpler API that just takes
 * the payload as an input buffer use t_cose_sign_sign().
 *
 * See t_cose_common.h for preprocessor defines to reduce object code
 * and stack use by disabling features.
 */


/**
 * This is the context for creating a \c COSE_Sign1 or \c COSE_Sign structure. The
 * caller should allocate it and pass it to the functions here.  This
 * is about 36  bytes so it fits easily on the stack.
 */
struct t_cose_sign_sign_ctx {
    /* Private data structure */
    struct q_useful_buf_c          protected_parameters; /* Encoded protected params */
    uint32_t                       option_flags;
    struct t_cose_signature_sign  *signers;
    struct t_cose_parameter       *added_body_parameters;
};


/**
 * TODO: maybe move support for this to the test signer object.
 * This selects a signing test mode called _short_ _circuit_
 * _signing_. This mode is useful when there is no signing key
 * available, perhaps because it has not been provisioned or
 * configured for the particular device. It may also be because the
 * public key cryptographic functions have not been connected up in
 * the cryptographic adaptation layer.
 *
 * It has no value for security at all. Data signed this way MUST NOT
 * be trusted as anyone can sign like this.
 *
 * In this mode, the signature is the hash of that which would
 * normally be signed by the public key algorithm. To make the
 * signature the correct size for the particular algorithm, instances
 * of the hash are concatenated to pad it out.
 *
 * This mode is very useful for testing because all the code except
 * the actual signing algorithm is run exactly as it would if a proper
 * signing algorithm was run. This can be used for end-end system
 * testing all the way to a server or relying party, not just for
 * testing device code as t_cose_sign1_verify() supports it too.
 */
#define T_COSE_OPT_SHORT_CIRCUIT_SIG 0x00002000



/**
 * \brief  Initialize to start creating a \c COSE_Sign1 or \c COSE_Sign.
 *
 * \param[in] context            The t_cose signing context.
 * \param[in] option_flags       One of \c T_COSE_OPT_XXXX.
 *
 * Initialize the \ref t_cose_sign_sign_ctx context. Typically, no
 * \c option_flags are needed and 0 can be passed. . See \ref T_COSE_OPT_MESSAGE_TYPE_SIGN1 and
 * related for possible option flags.
 *
 * The algorithm ID(s) is(are) set for in the t_cose_signature_sign instance(s).
 */
static void
t_cose_sign_sign_init(struct t_cose_sign_sign_ctx *context,
                      uint32_t                     option_flags);


/**
 * \brief  Add a signer that is configured with a key and algorithm ID.
 *
 * \param[in] context    The t_cose signing context.
 * \param[in] signer     An initialized instance of \ref t_cose_signature_sign.
 *
 * Call this at least once to configure one or more signers. The
 * signer, an instance of \ref t_cose_signature_sign, is an object
 * that is configured with the signing algorithm, signing key and
 * related.
 *
 * When producing a \c COSE_Sign1, this must be called only
 * once.  When producing a \c COSE_Sign, this must be called at least
 * once, but can be called many more times if there are to be multiple
 * signatures. Note that each call can be with a different key and/or
 * different signer implementations for different algorithm entirely.
 *
 * This must be called with a concrete instance, such as a \ref
 * t_cose_signature_sign_ecdsa. The concrete instance must be
 * configured with a key and algorithm ID before this is called.
 */
void
t_cose_sign_add_signer(struct t_cose_sign_sign_ctx   *context,
                       struct t_cose_signature_sign  *signer);


/**
 * \brief Add header parameters to the \c COSE_Sign or \c COSE_Sign1 main body.
 *
 * \param[in] context     The t_cose signing context.
 * \param[in] parameters  Array of parameters to add.
 *
 * For simple use cases it is not necessary to call this as the
 * algorithm ID, the only mandatory parameter, is automatically
 * added.
 *
 * It is not necessary to call this to add the kid either as that
 * is handled by configuring the \ref t_cose_signature_sign with the kid.
 *
 * This adds parameters to the \c COSE_Sign1 \c COSE_Sign
 * body. Parameters in \c COSE_Signatures in \c COSE_Sign are handed
 * through \ref t_cose_signature_sign.
 *
 * This adds an array of header parameters to the body. It is an array
 * terminated by a parameter with type \ref
 * T_COSE_PARAMETER_TYPE_NONE.
 *
 * Integer and string parameters are handled by filling in the
 * members of the array.
 *
 * All the parameters must have a label and a value.
 *
 * Alternatively, and particularly for parameters that are not
 * integers or strings the value may be a callback of type t_cose_parameter_encode_callback
 * in which case the callback will be called when it is time
 * to output the CBOR for the custom header. The callback should
 * output the CBOR for the particular parameter.
 *
 * This supports only integer labels. (String labels could be added
 * but would increase object code size).
 *
 * All parameters must be added in one call. Multiple calls to this
 * don't accumlate parameters.
 */
static void
t_cose_sign_add_body_header_params(struct t_cose_sign_sign_ctx   *context,
                                   struct t_cose_parameter *parameters);


/*
 t_cose_sign1_set_content_type_uint and t_cose_sign1_set_content_type_tstr
 are replaced with t_cose_sign1_add_body_header_parameters()
 */


/**
 * \brief  Create and sign a \c COSE_Sign1 or \c COSE_Sign message with a payload in one call.
 *
 * \param[in] context  The \ref t_cose signing context.
 * \param[in] aad      The Additional Authenticated Data or \c NULL_Q_USEFUL_BUF_C.
 * \param[in] payload  Pointer and length of payload to sign.
 * \param[in] out_buf  Pointer and length of buffer to output to.
 * \param[out] result  Pointer and length of the resulting \c COSE_Sign1 or \c COSE_Sign.
 *
 * The \c context must have been initialized with
 * t_cose_sign_sign_init() and the key set with
 * t_cose_sign_add_signer() before this is called.
 *
 * This creates the COSE header parameter, hashes and signs the
 * payload and creates the signature all in one go. \c out_buf gives
 * the pointer and length of the memory into which the output is
 * written. The pointer and length of the completed \c COSE_Sign1 is
 * returned in \c result.  (\c out_buf and \c result are used instead
 * of the usual in/out parameter for length because it is the
 * convention for q_useful_buf and is more const correct.)
 *
 * The size of \c out_buf must be the size of the payload plus
 * overhead for formating, the signature and the key id (if used). The
 * formatting overhead is minimal at about 30 bytes.The total overhead
 * is about 150 bytes for ECDSA 256 with a 32-byte key ID.
 *
 * To compute the size of the buffer needed before it is allocated
 * call this with \c out_buf containing a \c NULL pointer and large
 * length like \c UINT32_MAX.  The algorithm and key, kid and such
 * must be set up just as if the real \c COSE_Sign1 were to be created
 * as these values are needed to compute the size correctly.  The
 * contents of \c result will be a \c NULL pointer and the length of
 * the \c COSE_Sign1. When this is run like this, the cryptographic
 * functions will not actually run, but the size of their output will
 * be taken into account to give an exact size.
 *
 * This function requires the payload be complete and formatted in a
 * contiguous buffer. The resulting COSE message also
 * contains the payload preceded by the header parameters and followed
 * by the signature, all CBOR formatted. This function thus requires
 * two copies of the payload to be in memory.  Alternatively
 * t_cose_sign_encode_start() and
 * t_cose_sign_encode_finish() can be used. They are more complex
 * to use, but avoid the two copies of the payload and can reduce
 * memory requirements by close to half.
 *
 * See t_cose_sign_encode_signature_aad() for more details
 * about AAD.  For many use cases there is no AAD and \c aad is \c NULL_Q_USEFUL_BUF_C.
 */
static enum t_cose_err_t
t_cose_sign_sign(struct t_cose_sign_sign_ctx *context,
                 struct q_useful_buf_c        aad,
                 struct q_useful_buf_c        payload,
                 struct q_useful_buf          out_buf,
                 struct q_useful_buf_c       *result);


/**
 * \brief  Create and sign a \c COSE_Sign1 or \c COSE_Sign message with detached payload in one call.
 *
 * \param[in] context  The t_cose signing context.
 * \param[in] aad      The Additional Authenticated Data or \c NULL_Q_USEFUL_BUF_C.
 * \param[in] detached_payload  Pointer and length of the detached payload to sign.
 * \param[in] out_buf  Pointer and length of buffer to output to.
 * \param[out] result  Pointer and length of the resulting \c COSE_Sign1 or \c COSE_Sign.
 *
 * This is similar to, but not the same as t_cose_sign_sign(). Here
 * the payload is detached and conveyed separately.  The signature is
 * still over the payload as with t_cose_sign_sign(). The payload
 * must be conveyed to recipient by some other means than by being
 * inside the \c COSE_Sign1 or \c COSE_Sign. The recipient will be
 * unable to verify the received message without it.
 */
static enum t_cose_err_t
t_cose_sign_sign_detached(struct t_cose_sign_sign_ctx *context,
                          struct q_useful_buf_c        aad,
                          struct q_useful_buf_c        detached_payload,
                          struct q_useful_buf          out_buf,
                          struct q_useful_buf_c       *result);


/**
 * \brief  Output first part and parameters for a \c COSE_Sign1 or \c COSE_Sign message.
 *
 * \param[in] context          The t_cose signing context.
 * \param[in] payload_is_detached  If the payload is to be detached, this
 *                                 is \c true.
 * \param[in] cbor_encode_ctx  Encoding context to output to.
 *
 * This is the more complex and more memory efficient alternative to
 * t_cose_sign_sign(). Like t_cose_sign_sign(),
 * t_cose_sign_sign_init() and t_cose_sign_add_signer() must be called
 * before calling this.
 *
 * When this is called, the opening parts of the \c COSE_Sign1 or \c
 * COSE_Sign message are output to the \c cbor_encode_ctx.
 *
 * After this is called, the CBOR-formatted payload must be written to
 * the \c cbor_encode_ctx by calling all the various \c
 * QCBOREncode_AddXxx calls. It can be as simple or complex as needed.
 *
 * To complete the COSE message call t_cose_sign_encode_finish().
 *
 * The \c cbor_encode_ctx must have been initialized with an output
 * buffer to hold the \c COSE_Sign1 or \c COSE_Sign header parameters,
 * the payload and the signature.
 *
 * This and t_cose_sign_encode_finish() can be used to calculate the
 * size of the output message n the way \c QCBOREncode is usually used
 * to calculate sizes. In this case the \c t_cose_sign_ctx must be
 * initialized with the options, signer and additional header
 * parameters just as normal as these are needed to calculate the
 * size. Then set up the output buffer for \c cbor_encode_ctx with a
 * \c NULL pointer and large length like \c UINT32_MAX.  Call
 * t_cose_sign_encode_start(), then format the payload into the
 * encoder context, then call t_cose_sign_encode_finish().  Finally
 * call \c QCBOREncode_FinishGetSize() to get the length.
 */
enum t_cose_err_t
t_cose_sign_encode_start(struct t_cose_sign_sign_ctx *context,
                         bool                         payload_is_detached,
                         QCBOREncodeContext          *cbor_encode_ctx);


/**
 * \brief Finish a \c COSE_Sign1 message by outputting the signature.
 *
 * \param[in] context           The t_cose signing context.
 * \param[in] aad               The Additional Authenticated Data or \c NULL_Q_USEFUL_BUF_C.
 * \param[in] detached_payload  The detached payload or \c NULL_Q_USEFUL_BUF_C.
 * \param[in] cbor_encode_ctx   Encoding context to output to.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * Call this to complete creation of a signed \c COSE_Sign1 or \c
 * COSE_Sign started with t_cose_sign_encode_start().
 *
 * This is when the callback into the t_cose_signature_sign object(s)
 * is(are) called and when cryptographic signature algorithm is run.
 *
 * AAD is simply any data that should also be covered by the
 * signature.  The verifier of the \c COSE_Sign1 or \c COSE_Sign must
 * also have exactly this data to be able to successfully verify the
 * signature. Often this data is some parameters or fields in the
 * protocol carrying the COSE message.
 *
 * The completed \c COSE_Sign1 or \c COSE_Sign message is retrieved from the
 * \c cbor_encode_ctx by calling \c QCBOREncode_Finish().
 */
enum t_cose_err_t
t_cose_sign_encode_finish(struct t_cose_sign_sign_ctx *context,
                          struct q_useful_buf_c        aad,
                          struct q_useful_buf_c        detached_payload,
                          QCBOREncodeContext          *cbor_encode_ctx);



/* ------------------------------------------------------------------------
 * Inline implementations of public functions defined above.
 */
static inline void
t_cose_sign_sign_init(struct t_cose_sign_sign_ctx *me,
                      uint32_t                     option_flags)
{
    memset(me, 0, sizeof(*me));
    me->option_flags = option_flags;
}


/**
 * \brief Semi-private function that does a complete signing in one call.
 *
 * \param[in] context              The t_cose signing context.
 * \param[in] payload_is_detached  If \c true, then \c payload is detached.
 * \param[in] payload              The payload, inline or detached.
 * \param[in] aad                  The Additional Authenticated Data or
 *                                 \c NULL_Q_USEFUL_BUF_C.
 * \param[in] out_buf              Pointer and length of buffer to output to.
 * \param[out] result              Pointer and length of the resulting
 *                                 \c COSE_Sign1.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This is where the work actually gets done for signing that is done
 * all in one call with or without AAD and for included or detached
 * payloads.
 *
 * This is a private function internal to the implementation. Call
 * t_cose_sign_sign_aad() instead of this.
 */
enum t_cose_err_t
t_cose_sign_one_shot(struct t_cose_sign_sign_ctx *context,
                     bool                         payload_is_detached,
                     struct q_useful_buf_c        aad,
                     struct q_useful_buf_c        payload,
                     struct q_useful_buf          out_buf,
                     struct q_useful_buf_c       *result);


static inline enum t_cose_err_t
t_cose_sign_sign(struct t_cose_sign_sign_ctx *me,
                 struct q_useful_buf_c        aad,
                 struct q_useful_buf_c        payload,
                 struct q_useful_buf          out_buf,
                 struct q_useful_buf_c       *result)
{
    return t_cose_sign_one_shot(me,
                                false,
                                payload,
                                aad,
                                out_buf,
                                result);
}


static inline enum t_cose_err_t
t_cose_sign_sign_detached(struct t_cose_sign_sign_ctx *me,
                          struct q_useful_buf_c        aad,
                          struct q_useful_buf_c        detached_payload,
                          struct q_useful_buf          out_buf,
                          struct q_useful_buf_c       *result)
{
    return t_cose_sign_one_shot(me,
                                true,
                                detached_payload,
                                aad,
                                out_buf,
                                result);
}


static inline void
t_cose_sign_add_body_header_params(struct t_cose_sign_sign_ctx *me,
                                   struct t_cose_parameter *parameters)
{
    me->added_body_parameters = parameters;
}


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_SIGN_SIGN_H__ */
