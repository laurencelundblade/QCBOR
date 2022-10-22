/*
 *  t_cose_sign_verify.h
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Created by Laurence Lundblade on 7/17/22.
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_sign_verify_h
#define t_cose_sign_verify_h

#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_signature_verify.h"


#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif

/* Warning: this is still early development. Documentation may be incorrect. */


#define T_COSE_MAX_TAGS_TO_RETURN2 4




/**
 * The maximum number of unprocessed tags that can be returned by
 * t_cose_sign1_get_nth_tag(). The CWT
 * tag is an example of the tags that might returned. The COSE tags
 * that are processed, don't count here.
 */
#define T_COSE_MAX_TAGS_TO_RETURN 4


/**
 * Pass this as \c option_flags to allow verification of short-circuit
 * signatures. This should only be used as a test mode as
 * short-circuit signatures are not secure.
 *
 * See also \ref T_COSE_OPT_SHORT_CIRCUIT_SIG.
 */
#define T_COSE_OPT_ALLOW_SHORT_CIRCUIT 0x00004000




/**
 * Context for signature verification.
 */
struct t_cose_sign_verify_ctx {
    /* Private data structure */
    struct t_cose_signature_verify   *verifiers;
    uint32_t                          option_flags;
    uint64_t                          auTags[T_COSE_MAX_TAGS_TO_RETURN2];
    struct t_cose_parameter_storage   params;
    struct t_cose_parameter           __params[T_COSE_NUM_VERIFY_DECODE_HEADERS];
    struct t_cose_parameter_storage  *p_storage;
    t_cose_parameter_decode_callback *reader;
    void                             *reader_ctx;
};




/* ALL signatures must be verified successfully */
#define T_COSE_VERIFY_ALL                  0x0008000


/**
 * \brief Initialize for \c COSE_Sign and \c COSE_Sign1 message verification.
 *
 * \param[in,out]  context       The context to initialize.
 * \param[in]      option_flags  Options controlling the verification.
 *
 * This must be called before using the verification context.
 */
static void
t_cose_sign_verify_init(struct t_cose_sign_verify_ctx *context,
                        uint32_t                       option_flags);


/* Warning: this is still early development. Documentation may be incorrect. */


/* Add a verifier object.

 * Verifiers are objects that do the cryptographic operations
 * to verify a COSE_Sign or COSE_Sign1. This is both the
 * hashing and the public key cryptography. They also
 * implement the decoding of the COSE_Signature(s) in a
 * COSE_Sign.
 *
 * At least one verifier must be added in. Before they
 * are added in they should be configured with any key
 * material (the verification key) needed.
 *
 * By default the overall result is success if at least
 * one of the signatures verifies. TODO: think
 * more carefully through all the combinations of
 * multiple signatures and verifiers.
 */
void
t_cose_sign_add_verifier(struct t_cose_sign_verify_ctx  *context,
                         struct t_cose_signature_verify *verifier);


/*
 *
 * Use this to increase the number of header parameters that can be decoded
 * if the number expected is larger than \ref T_COSE_NUM_VERIFY_DECODE_HEADERS. If it is less than \ref T_COSE_NUM_VERIFY_DECODE_HEADERS,
 * the internal storage is used and there is no need to call this.
 *
 * There must be room to decode all the header parameters that
 * are in the body and in all in the COSE_Signatures. If not
 * \ref T_COSE_ERR_TOO_MANY_PARAMETERS will be returned by
 * t_cose_sign_verify() and similar.
 *
 * The storage can be partially used on in. The number
 * used is incremented and if there's room left, it can be
 * used elswhere.
 */
static void
t_cose_sign_add_param_storage(struct t_cose_sign_verify_ctx  *context,
                              struct t_cose_parameter_storage *param_storage);


/*
 * If customer headers that are not strings or integers needed to be
 * decoded and processed, then use this to set a call back handler.
 * Typically this is not needed.
 */
static void
t_cose_sign_set_header_reader(struct t_cose_sign_verify_ctx    *context,
                              t_cose_parameter_decode_callback *reader,
                              void                             *reader_ctx);


/**
 * \brief Verify a COSE_Sign1 or COSE_Sign.
 *
 * \param[in,out] context   The t_cose signature verification context.
 * \param[in] sign         Pointer and length of CBOR encoded \c COSE_Sign1
 *                          or \c COSE_Sign message that is to be verified.
 * \param[in] aad           The Additional Authenticated Data or \c NULL_Q_USEFUL_BUF_C.
 * \param[out] payload      Pointer and length of the payload that is returned.
 * \param[out] parameters   Place to return parsed parameters. May be \c NULL.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * See t_cose_sign1_set_verification_key() for discussion on where
 * the verification key comes from.
 *
 * Verification involves the following steps.
 *
 * - The CBOR-format \c COSE_Sign1 or \c COSE_Sign structure is parsed. This makes
 * sure the CBOR is valid and follows the required structure.
 *
 * - The protected header parameters are decoded, particular the algorithm id.
 *
 * - The unprotected headers parameters are decoded, particularly the kid.
 *
 * - The payload is identified. The internals of the payload are not decoded.
 *
 * - The expected hash, the "to-be-signed" bytes are computed. The hash
 * algorithm used comes from the signing algorithm. If the algorithm is
 * unknown or not supported this will error out.
 *
 * At least one verifier must be configured using t_cose_sign_add_verifier() to
 * be able to perform a success verification.
 *
 * - Finally, the signature verification is performed.
 *
 * If verification is successful, the pointer to the CBOR-encoded payload is
 * returned. The parameters are returned if requested. All pointers
 * returned are to memory in the \c sign1 passed in.
 *
 * Indefinite length CBOR strings are not supported by this
 * implementation.  \ref T_COSE_ERR_SIGN1_FORMAT will be returned if
 * they are in the input \c COSE_Sign1 messages. For example, if the
 * payload is an indefinite-length byte string, this error will be
 * returned.
 *
 * See also t_cose_sign_verify_detached().
 */
static enum t_cose_err_t
t_cose_sign_verify(struct t_cose_sign_verify_ctx *context,
                   struct q_useful_buf_c          sign,
                   struct q_useful_buf_c          aad,
                   struct q_useful_buf_c         *payload,
                   struct t_cose_parameter      **parameters);


/* This is the same as t_cose_sign_verify(), but the payload
 * is detached.
*/
static enum t_cose_err_t
t_cose_sign_verify_detached(struct t_cose_sign_verify_ctx *context,
                            struct q_useful_buf_c          sign,
                            struct q_useful_buf_c          aad,
                            struct q_useful_buf_c          payload,
                            struct t_cose_parameter      **parameters);




/* ------------------------------------------------------------------------
 * Private and inline implementations of public functions defined above.
 */

/**
 * \brief Semi-private function to verify a COSE_Sign1.
 *
 * \param[in,out] me   The t_cose signature verification context.
 * \param[in] sign         Pointer and length of CBOR encoded \c COSE_Sign1
 *                          or \c COSE_Sign message that is to be verified.
 * \param[in] aad           The Additional Authenticated Data or \c NULL_Q_USEFUL_BUF_C.
 * \param[in,out] payload   Pointer and length of the payload.
 * \param[out] parameters   Place to return parsed parameters. May be \c NULL.
 * \param[in] is_detached         Indicates the payload is detached.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This does the work for t_cose_sign1_verify(),
 * t_cose_sign1_verify_aad() and t_cose_sign1_verify_detached(). It is
 * a semi-private function which means its interface isn't guaranteed
 * so it should not to call it directly.
 */
enum t_cose_err_t
t_cose_sign_verify_private(struct t_cose_sign_verify_ctx *me,
                             struct q_useful_buf_c        sign,
                             struct q_useful_buf_c        aad,
                             struct q_useful_buf_c       *payload,
                             struct t_cose_parameter    **parameters,
                             bool                         is_detached);



static inline enum t_cose_err_t
t_cose_sign_verify(struct t_cose_sign_verify_ctx *me,
                   struct q_useful_buf_c          sign,
                   struct q_useful_buf_c          aad,
                   struct q_useful_buf_c         *payload,
                   struct t_cose_parameter      **parameters)
{
    return t_cose_sign_verify_private(me,
                                      sign,
                                      aad,
                                      payload,
                                      parameters,
                                      false);
}


static inline enum t_cose_err_t
t_cose_sign_verify_detached(struct t_cose_sign_verify_ctx *me,
                   struct q_useful_buf_c          sign,
                   struct q_useful_buf_c          aad,
                   struct q_useful_buf_c          detatched_payload,
                   struct t_cose_parameter      **parameters)
{
    return t_cose_sign_verify_private(me,
                                      sign,
                                      aad,
                                     &detatched_payload,
                                      parameters,
                                      true);
}


static inline void
t_cose_sign_verify_init(struct t_cose_sign_verify_ctx *me,
                        uint32_t                       option_flags)
{
    memset(me, 0, sizeof(*me));
    me->option_flags       = option_flags;
    me->params.storage     = me->__params;
    me->params.size        = sizeof(me->__params)/sizeof(struct t_cose_parameter);
    me->params.used        = 0;
    me->p_storage          = &(me->params);
}


static inline void
t_cose_sign_add_param_storage(struct t_cose_sign_verify_ctx  *me,
                              struct t_cose_parameter_storage *param_storage)
{
    me->p_storage = param_storage;
}


static inline void
t_cose_sign_set_header_reader(struct t_cose_sign_verify_ctx    *me,
                              t_cose_parameter_decode_callback *reader,
                              void                             *reader_ctx)
{
    me->reader     = reader;
    me->reader_ctx = reader_ctx;
}


#ifdef __cplusplus
}
#endif

#endif /* t_cose_sign_verify_h */
