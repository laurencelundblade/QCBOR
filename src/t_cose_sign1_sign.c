/*
 * t_cose_sign1_sign.c
 *
 * Copyright (c) 2018-2019, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose_sign1_sign.h"
#include "qcbor.h"
#include "t_cose_defines.h"
#include "t_cose_crypto.h"
#include "t_cose_util.h"


/**
 * \file t_cose_sign1_sign.c
 *
 * \brief This implements t_cose signing
 */


#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
/**
 * \brief Create a short-circuit signature
 *
 * \param[in] cose_alg_id       Algorithm ID. This is used only to make
 *                              the short-circuit signature the same size
 *                              as the real signature would be for the
 *                              particular algorithm.
 * \param[in] hash_to_sign      The bytes to sign. Typically, a hash of
 *                              a payload.
 * \param[in] signature_buffer  Pointer and length of buffer into which
 *                              the resulting signature is put.
 * \param[in] signature         Pointer and length of the signature
 *                              returned.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This creates the short-circuit signature that is a concatenation of
 * hashes up to the expected size of the signature. This is a test
 * mode only has it has no security value. This is retained in
 * commercial production code as a useful test or demo that can run
 * even if key material is not set up or accessible.
 */
static inline enum t_cose_err_t
short_circuit_sign(int32_t cose_alg_id,
                   struct q_useful_buf_c hash_to_sign,
                   struct q_useful_buf signature_buffer,
                   struct q_useful_buf_c *signature)
{
    /* approximate stack use on 32-bit machine: local use: 16
     */
    enum t_cose_err_t return_value;
    size_t            array_indx;
    size_t            amount_to_copy;
    size_t            sig_size;

    sig_size = t_cose_signature_size(cose_alg_id);

    if(sig_size > signature_buffer.len) {
        /* Buffer too small for this signature type */
        return_value = T_COSE_ERR_SIG_BUFFER_SIZE;
        goto Done;
    }

    /* Loop concatening copies of the hash to fill out to signature size */
    for(array_indx = 0; array_indx < sig_size; array_indx += hash_to_sign.len) {
        amount_to_copy = sig_size - array_indx;
        if(amount_to_copy > hash_to_sign.len) {
            amount_to_copy = hash_to_sign.len;
        }
        memcpy((uint8_t *)signature_buffer.ptr + array_indx,
               hash_to_sign.ptr,
               amount_to_copy);
    }
    signature->ptr = signature_buffer.ptr;
    signature->len = sig_size;
    return_value   = T_COSE_SUCCESS;

Done:
    return return_value;
}
#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */


/**
 * \brief  Makes the protected headers for COSE.
 *
 * \param[in] cose_alg_id  The COSE algorithm ID to put in the headers.
 *
 * \param[in] buffer_for_header  Pointer and length into which
 *                               the resulting encoded protected
 *                               headers is put.
 *
 * \return The pointer and length of the protected headers is
 * returned, or \c NULL_Q_USEFUL_BUF_C if this fails.
 *
 * The protected headers are returned in fully encoded CBOR format as
 * they are added to the \c COSE_Sign1 as a binary string. This is
 * different from the unprotected headers which are not handled this
 * way.
 *
 * This returns \c NULL_Q_USEFUL_BUF_C if buffer_for_header was too
 * small. See also definition of \ref T_COSE_SIGN1_MAX_PROT_HEADER
 */
static inline struct q_useful_buf_c
make_protected_header(int32_t cose_alg_id,
                      struct q_useful_buf buffer_for_header)
{
    /* approximate stack use on 32-bit machine:
     * local use: 170
     * with calls: 210
     */
    struct q_useful_buf_c protected_headers;
    QCBORError            qcbor_result;
    QCBOREncodeContext    cbor_encode_ctx;
    struct q_useful_buf_c return_value;

    QCBOREncode_Init(&cbor_encode_ctx, buffer_for_header);
    QCBOREncode_OpenMap(&cbor_encode_ctx);
    QCBOREncode_AddInt64ToMapN(&cbor_encode_ctx,
                               COSE_HEADER_PARAM_ALG,
                               cose_alg_id);
    QCBOREncode_CloseMap(&cbor_encode_ctx);
    qcbor_result = QCBOREncode_Finish(&cbor_encode_ctx, &protected_headers);

    if(qcbor_result == QCBOR_SUCCESS) {
        return_value = protected_headers;
    } else {
        return_value = NULL_Q_USEFUL_BUF_C;
    }

    return return_value;
}


/**
 * \brief Add the unprotected headers to a CBOR encoding context
 *
 * \param[in] cbor_encode_ctx  CBOR encoding context to output to
 * \param[in] kid              The key ID to go into the kid header.
 *
 * No error is returned. If an error occurred it will be returned when
 * \c QCBOR_Finish() is called on \c cbor_encode_ctx.
 *
 * The unprotected headers added by this are just the key ID
 */
static inline void add_unprotected_headers(QCBOREncodeContext *cbor_encode_ctx,
                                           struct q_useful_buf_c kid)
{
    QCBOREncode_OpenMap(cbor_encode_ctx);
    if(!q_useful_buf_c_is_null_or_empty(kid)) {
        QCBOREncode_AddBytesToMapN(cbor_encode_ctx, COSE_HEADER_PARAM_KID, kid);
    }
    QCBOREncode_CloseMap(cbor_encode_ctx);
}


/*
 * Public function. See t_cose_sign1_sign.h
 */
enum t_cose_err_t t_cose_sign1_init(struct t_cose_sign1_ctx *me,
                                    int32_t option_flags,
                                    int32_t cose_alg_id,
                                    struct t_cose_signing_key signing_key,
                                    struct q_useful_buf_c key_id,
                                    QCBOREncodeContext *cbor_encode_ctx)
{
    /* approximate stack use on 32-bit machine:
     * local use: 16
     * with calls inlined: 240
     */
    int32_t              hash_alg_id;
    enum t_cose_err_t    return_value;
    struct q_useful_buf  buffer_for_protected_header;

    /* Check the cose_alg_id now by getting the hash alg as an early
     error check even though it is not used until later. */
    hash_alg_id = hash_alg_id_from_sig_alg_id(cose_alg_id);
    if(hash_alg_id == INT32_MAX) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    /* Remember all the parameters in the context */
    me->cose_algorithm_id   = cose_alg_id;
    me->signing_key         = signing_key;
    me->option_flags        = option_flags;
    me->cbor_encode_ctx     = cbor_encode_ctx;

    /* Add the CBOR tag indicating COSE_Sign1 */
    if(!(option_flags & T_COSE_OPT_OMIT_CBOR_TAG)) {
        QCBOREncode_AddTag(cbor_encode_ctx, CBOR_TAG_COSE_SIGN1);
    }

    /* Get started with the tagged array that holds the four parts of
     a cose single signed message */
    QCBOREncode_OpenArray(cbor_encode_ctx);

    /* The protected headers, which are added as a wrapped bstr  */
    buffer_for_protected_header =
        Q_USEFUL_BUF_FROM_BYTE_ARRAY(me->buffer_for_protected_headers);
    me->protected_headers = make_protected_header(cose_alg_id,
                                                  buffer_for_protected_header);
    if(q_useful_buf_c_is_null(me->protected_headers)) {
        /* The sizing of storage for protected headers is
          off (should never happen in tested, released code) */
        return_value = T_COSE_SUCCESS;
        goto Done;
    }
    QCBOREncode_AddBytes(cbor_encode_ctx, me->protected_headers);

    /* The Unprotected headers */
    /* Get the key id because it goes into the headers that are about
     to be made. */
    if(option_flags & T_COSE_OPT_SHORT_CIRCUIT_SIG) {
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
        key_id = get_short_circuit_kid();
#else
        return_value = T_COSE_SHORT_CIRCUIT_SIG_DISABLED;
        goto Done;
#endif
    }
    add_unprotected_headers(cbor_encode_ctx, key_id);

    /* Any failures in CBOR encoding will be caught in finish
     when the CBOR encoding is closed off. No need to track
     here as the CBOR encoder tracks it internally. */

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}


/*
 * Public function. See t_cose_sign1_sign.h
 */
enum t_cose_err_t t_cose_sign1_finish(struct t_cose_sign1_ctx *me,
                                      struct q_useful_buf_c signed_payload)
{
    /* approximate stack use on 32-bit machine:
     *   local use: 150-260 depending on algs supported
     *   total use: 400 - 510 or more depending on crypto library
     */
    enum t_cose_err_t            return_value;
    QCBORError                   cbor_err;
    /* pointer and length of the completed tbs hash */
    struct q_useful_buf_c        tbs_hash;
    /* Pointer and length of the completed signature */
    struct q_useful_buf_c        signature;
    /* Buffer for the actual signature */
    Q_USEFUL_BUF_MAKE_STACK_UB(  buffer_for_signature,
                                     T_COSE_MAX_EC_SIG_SIZE);
    /* Buffer for the tbs hash. Only big enough for SHA256 */
    Q_USEFUL_BUF_MAKE_STACK_UB(  buffer_for_tbs_hash,
                                     T_COSE_CRYPTO_MAX_HASH_SIZE);

    /* Check there are no CBOR encoding errors before
     * proceeding with hashing and signing. This is
     * not actually necessary as the errors will be caught
     * correctly later, but it does make it a bit easier
     * for the caller to debug problems.
     */
    cbor_err = QCBOREncode_GetErrorState(me->cbor_encode_ctx);
    if(cbor_err == QCBOR_ERR_BUFFER_TOO_SMALL) {
        return_value = T_COSE_ERR_TOO_SMALL;
        goto Done;
    } else if(cbor_err != QCBOR_SUCCESS) {
        return_value = T_COSE_ERR_CBOR_FORMATTING;
        goto Done;
    }

    /* Create the hash of the to-be-signed bytes. Inputs to the hash
     * are the protected headers, the payload that is getting signed, the
     * cose signature alg from which the hash alg is determined. The
     * cose_algorithm_id was checked in t_cose_sign1_init() so it
     * doesn't need to be checked here.
     */
    return_value = create_tbs_hash(me->cose_algorithm_id,
                                   buffer_for_tbs_hash,
                                   &tbs_hash,
                                   me->protected_headers,
                                   T_COSE_TBS_PAYLOAD_IS_BSTR_WRAPPED,
                                   signed_payload);
    if(return_value) {
        goto Done;
    }

    /* Compute the signature using public key crypto. The key selector
     * and algorithm ID are passed in to know how and what to sign
     * with. The hash of the TBS bytes are what is signed. A buffer in
     * which to place the signature is passed in and the signature is
     * returned.
     *
     * Short-circuit signing is invoked if requested. It does no
     * public key operation and requires no key. It is just a test
     * mode that always works.
     */
    if(!(me->option_flags & T_COSE_OPT_SHORT_CIRCUIT_SIG)) {
        /* Normal, non-short-circuit signing */
        return_value = t_cose_crypto_pub_key_sign(me->cose_algorithm_id,
                                                  me->signing_key,
                                                  tbs_hash,
                                                  buffer_for_signature,
                                                  &signature);
    } else {
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
        return_value = short_circuit_sign(me->cose_algorithm_id,
                                          tbs_hash,
                                          buffer_for_signature,
                                          &signature);
#endif
    }

    if(return_value) {
        goto Done;
    }

    /* Add signature to CBOR and close out the array */
    QCBOREncode_AddBytes(me->cbor_encode_ctx, signature);
    QCBOREncode_CloseArray(me->cbor_encode_ctx);

    /* The layer above this must check for and handle CBOR
     * encoding errors CBOR encoding errors.  Some are
     * detected at the start of this function, but they
     * cannot all be deteced there.
     */
Done:
    return return_value;
}
