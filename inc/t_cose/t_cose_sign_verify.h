/*
 * t_cose_sign_verify.h
 *
 * Copyright 2019-2023, Laurence Lundblade
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



/**
 * The maximum number of unprocessed tags that can be returned by
 * t_cose_xxx_get_nth_tag(). The CWT
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


/* Requires that ALL COSE_Signatures must be verified successfully. The default
 * is that only the one must verify.
 */
#define T_COSE_OPT_VERIFY_ALL_SIGNATURES  0x0008000




/**
 * Context for signature verification.
 */
struct t_cose_sign_verify_ctx {
    /* Private data structure */
    struct t_cose_signature_verify   *verifiers;
    uint32_t                          option_flags;
    uint64_t                          unprocessed_tag_nums[T_COSE_MAX_TAGS_TO_RETURN];
    struct t_cose_parameter_storage   params;
    struct t_cose_parameter           __params[T_COSE_NUM_VERIFY_DECODE_HEADERS];
    struct t_cose_parameter_storage  *p_storage;
    t_cose_param_special_decode_cb   *special_param_decode_cb;
    void                             *special_param_decode_ctx;
    struct t_cose_signature_verify   *last_verifier; /* Last verifier that didn't succeed */
};


/**
 * \brief Initialize for \c COSE_Sign and \c COSE_Sign1 message verification.
 *
 * \param[in,out]  context       The context to initialize.
 * \param[in]      option_flags  Options controlling the verification.
 *
 * This must be called before using the verification context.
 *
 * TODO: describe (and implement) selection of COSE_Sign1 vs COSE_Sign.
 */
static void
t_cose_sign_verify_init(struct t_cose_sign_verify_ctx *context,
                        uint32_t                       option_flags);


/**
 * \brief Add a verifier object.
 *
 * \param[in] context     Signed message verification context.
 * \param[in] verifier   Pointer to verifier object.

 * Verifiers are objects that do the cryptographic operations
 * to verify a COSE_Sign or COSE_Sign1. They do both the
 * hashing and the public key cryptography. They also
 * implement the decoding of the COSE_Signature(s) in a
 * COSE_Sign.
 *
 * At least one verifier must be added in. Before they
 * are added in they should be configured with any key
 * material (e.g., the verification key) needed.
 *
 * The verifiers added must be a complete concrete instance
 * such as t_cose_signature_verify_main or t_cose_signature_verify_eddsa,
 * not the abstract base object t_cose_signature_verify.
 * Some verifiers like t_cose_signature_verify_main handle multiple
 * cryptographic algorithms.
 *
 * For COSE_SIgn messages, t_cose_sign_verify() loops over
 * all the COSE_Signatures. By default the verification is a success
 * if one can be verified and there are no decoding errors. The
 * option \ref T_COSE_OPT_VERIFY_ALL_SIGNATURES can be set
 * to require that all the signatures verify for the overall COSE_Sign
 * to be a success.
 *
 * For COSE_Sign1 messages t_cose_sign_verify() calls
 * each verifier as described next.
 *
 * Each verifier added here is called on each COSE_Signature
 * until one succeeds. An individual verifier may decline to
 * attempt verification if it doesn't handle the particular
 * algorithm, the kid doesn't match or for other reasons it
 * may have after examining the header parameters in the
 * COSE_Signature. If it declines, the next verifier will be
 * invoked. If an individual verifier fails because of a CBOR
 * decoding issue or if it attempts the actual signature
 * cryptographic operation and that fails, processing of the
 * whole COSE_Sign will fail.
 *
 * The header parameters for all the COSE_Signatures are
 * returned in a linked list by t_cose_sign_verify().
 */
static void
t_cose_sign_add_verifier(struct t_cose_sign_verify_ctx  *context,
                         struct t_cose_signature_verify *verifier);


/**
 * \brief Add storage for header parameter decoding.
 *
 * \param[in] context     Signed message verification context.
 * \param[in] storage     The parameter storage to add.
 *
 * This is optionally called to increase the number of storage nodes
 * for COSE_Sign or COSE_Sign1 message with
 * T_COSE_NUM_VERIFY_DECODE_HEADERS header parameters.  Decoded
 * parameters are returned in a linked list of struct
 * t_cose_parameter.  The storage for the nodes in the list is not
 * dynamically allocated as there is no dynamic storage allocation
 * used here.
 *
 * It is assumed that the
 * number of parameters is small and/or can be anticipated.
 * There must be room to decode all the header parameters that
 * are in the body and in all in the COSE_Signatures. If not
 * \ref T_COSE_ERR_TOO_MANY_PARAMETERS will be returned by
 * t_cose_sign_verify() and similar.
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
t_cose_sign_add_param_storage(struct t_cose_sign_verify_ctx   *context,
                              struct t_cose_parameter_storage *storage);


/*
 * If custom headers that are not strings or integers needed to be
 * decoded and processed, then use this to set a call back handler.
 * Typically this is not needed.
 */
static void
t_cose_sign_set_special_param_decoder(struct t_cose_sign_verify_ctx  *context,
                                      t_cose_param_special_decode_cb *decode_cb,
                                      void                           *decode_ctx);


/**
 * \brief Verify a COSE_Sign1 or COSE_Sign.
 *
 * \param[in,out] context   The t_cose signature verification context.
 * \param[in] message       Pointer and length of CBOR encoded \c COSE_Sign1
 *                          or \c COSE_Sign message that is to be verified.
 * \param[in] aad           The Additional Authenticated Data or \c NULL_Q_USEFUL_BUF_C.
 * \param[out] payload      Pointer and length of the payload that is returned.
 *                          Must not be \c NULL.
 * \param[out] parameters   Place to return decoded parameters. May be \c NULL.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * See t_cose_sign_add_verifier() for discussion on where
 * the verification key comes from, algorithms, formats and
 * handling of multiple signatures and multiple verifiers.
 *
 * Verification involves the following steps.
 *
 * - The CBOR-format \c COSE_Sign1 or \c COSE_Sign structure is decoded. This
 * makes sure the CBOR is valid and follows the required structure.
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
 * If verification is successful, the pointer to the CBOR-encoded
 * payload is returned. The parameters are returned if requested. All
 * pointers returned are to memory in the \c message passed in.
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
                   struct q_useful_buf_c          message,
                   struct q_useful_buf_c          aad,
                   struct q_useful_buf_c         *payload,
                   struct t_cose_parameter      **parameters);


/* This is the same as t_cose_sign_verify(), but the payload
 * is detached.
*/
static enum t_cose_err_t
t_cose_sign_verify_detached(struct t_cose_sign_verify_ctx *context,
                            struct q_useful_buf_c          message,
                            struct q_useful_buf_c          aad,
                            struct q_useful_buf_c          payload,
                            struct t_cose_parameter      **parameters);



/**
 * \brief Return unprocessed tags from most recent signature verify.
 *
 * \param[in] context   The t_cose signature verification context.
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
 * needed for recursive processing of nested COSE signing and/or
 * encryption.
 */
static uint64_t
t_cose_sign_verify_nth_tag(const struct t_cose_sign_verify_ctx *context,
                           size_t                                n);



/* Get a pointer to the last verifier that was called, the one that
 * caused the error returned by t_cose_sign_verify(). */
// TODO: maybe this should return the signature index too?
static struct t_cose_signature_verify  *
t_cose_sign_verify_get_last(struct t_cose_sign_verify_ctx *context);




/* ------------------------------------------------------------------------
 * Private and inline implementations of public functions defined above.
 */

/**
 * \brief Semi-private function to verify a COSE_Sign or COSE_Sign1.
 *
 * \param[in,out] me   The t_cose signature verification context.
 * \param[in] message         Pointer and length of CBOR encoded \c COSE_Sign1
 *                          or \c COSE_Sign message that is to be verified.
 * \param[in] aad           The Additional Authenticated Data or \c NULL_Q_USEFUL_BUF_C.
 * \param[in] is_detached         Indicates the payload is detached.
 * \param[in,out] payload   Pointer and length of the payload.
 * \param[out] parameters   Place to return parsed parameters. May be \c NULL.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This does the work for t_cose_sign_verify() and
 * t_cose_sign_verify_detached(). It is a semi-private function which
 * means its interface isn't guaranteed so it should not be called
 * directly.
 */
enum t_cose_err_t
t_cose_sign_verify_private(struct t_cose_sign_verify_ctx *me,
                           struct q_useful_buf_c          message,
                           struct q_useful_buf_c          aad,
                           bool                           is_detached,
                           struct q_useful_buf_c         *payload,
                           struct t_cose_parameter      **parameters);



static inline enum t_cose_err_t
t_cose_sign_verify(struct t_cose_sign_verify_ctx *me,
                   struct q_useful_buf_c          message,
                   struct q_useful_buf_c          aad,
                   struct q_useful_buf_c         *payload,
                   struct t_cose_parameter      **parameters)
{
    return t_cose_sign_verify_private(me,
                                      message,
                                      aad,
                                      false,
                                      payload,
                                      parameters);
}


static inline enum t_cose_err_t
t_cose_sign_verify_detached(struct t_cose_sign_verify_ctx *me,
                            struct q_useful_buf_c          message,
                            struct q_useful_buf_c          aad,
                            struct q_useful_buf_c          detached_payload,
                            struct t_cose_parameter      **parameters)
{
    return t_cose_sign_verify_private(me,
                                      message,
                                      aad,
                                      true,
                                     &detached_payload,
                                      parameters);
}


static inline void
t_cose_sign_verify_init(struct t_cose_sign_verify_ctx *me,
                        uint32_t                       option_flags)
{
    memset(me, 0, sizeof(*me));
    T_COSE_PARAM_STORAGE_INIT(me->params, me->__params);
    me->option_flags       = option_flags;
    me->p_storage          = &(me->params);
}


static inline void
t_cose_sign_add_param_storage(struct t_cose_sign_verify_ctx   *me,
                              struct t_cose_parameter_storage *storage)
{
    me->p_storage = storage;
}


static inline void
t_cose_sign_set_special_param_decoder(struct t_cose_sign_verify_ctx  *me,
                                      t_cose_param_special_decode_cb *decode_cb,
                                      void                           *decode_ctx)
{
    me->special_param_decode_cb  = decode_cb;
    me->special_param_decode_ctx = decode_ctx;
}


static inline void
t_cose_sign_add_verifier(struct t_cose_sign_verify_ctx  *me,
                         struct t_cose_signature_verify *verifier)
{
    /* Use base class function to add a signer/recipient to the linked list. */
    t_cose_link_rs((struct t_cose_rs_obj **)&me->verifiers,
                   (struct t_cose_rs_obj *)verifier);
}


static inline struct t_cose_signature_verify *
t_cose_sign_verify_get_last(struct t_cose_sign_verify_ctx  *me)
{
    return me->last_verifier;
}


static inline uint64_t
t_cose_sign_verify_nth_tag(const struct t_cose_sign_verify_ctx *me,
                           size_t                                n)
{
    if(n > T_COSE_MAX_TAGS_TO_RETURN) {
        return CBOR_TAG_INVALID64;
    }
    return me->unprocessed_tag_nums[n];
}



#ifdef __cplusplus
}
#endif

#endif /* t_cose_sign_verify_h */
