/*
 * t_cose_signature_sign_short.c
 *
 * Copyright (c) 2022, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose/t_cose_signature_sign_short.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_common.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"


static const uint8_t defined_short_circuit_kid[] = {
    0xef, 0x95, 0x4b, 0x4b, 0xd9, 0xbd, 0xf6, 0x70,
    0xd0, 0x33, 0x60, 0x82, 0xf5, 0xef, 0x15, 0x2a,
    0xf8, 0xf3, 0x5b, 0x6a, 0x6c, 0x00, 0xef, 0xa6,
    0xa9, 0xa7, 0x1f, 0x49, 0x51, 0x7e, 0x18, 0xc6};

static struct q_useful_buf_c short_circuit_kid;

/*
 * Public function.
 */
struct q_useful_buf_c
t_cose_get_short_circuit_kid_l(void)
{
    short_circuit_kid.len = sizeof(defined_short_circuit_kid);
    short_circuit_kid.ptr = defined_short_circuit_kid;

    return short_circuit_kid;
}


/*
 * Short-circuit signer can pretend to be ES256, ES384 or ES512.
 */
static inline enum t_cose_err_t
short_circuit_sig_size(int32_t cose_algorithm_id,
                       size_t *sig_size)
{
    *sig_size = cose_algorithm_id == T_COSE_ALGORITHM_ES256 ? T_COSE_EC_P256_SIG_SIZE :
                cose_algorithm_id == T_COSE_ALGORITHM_ES384 ? T_COSE_EC_P384_SIG_SIZE :
                cose_algorithm_id == T_COSE_ALGORITHM_ES512 ? T_COSE_EC_P512_SIG_SIZE :
                0;

    return *sig_size == 0 ? T_COSE_ERR_UNSUPPORTED_SIGNING_ALG : T_COSE_SUCCESS;
}


/**
 * \brief Create a short-circuit signature.
 *
 * \param[in] cose_algorithm_id Algorithm ID. This is used only to make
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
short_circuit_fake_sign(int32_t                cose_algorithm_id,
                        struct q_useful_buf_c  hash_to_sign,
                        struct q_useful_buf    signature_buffer,
                        struct q_useful_buf_c *signature)
{
    /* approximate stack use on 32-bit machine: local use: 16 bytes
     */
    enum t_cose_err_t return_value;
    size_t            array_indx;
    size_t            amount_to_copy;
    size_t            sig_size;

    return_value = short_circuit_sig_size(cose_algorithm_id, &sig_size);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* Check the signature length against buffer size */
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


/**
 * See \ref t_cose_signature_sign_h_callback of which this is an implementation.
 *
 * While this is a private function, it is called externally as a
 * callback via a function pointer that is set up in
 * t_cose_short_signer_init().
 */
static void
t_cose_short_headers(struct t_cose_signature_sign      *me_x,
                     struct t_cose_parameter **params)
{
    struct t_cose_signature_sign_short *me = (struct t_cose_signature_sign_short *)me_x;

    /* Output the configured kid or the never-changing kid for
     * short-circuit signatures. */
    struct q_useful_buf_c kid = me->kid;
    if(q_useful_buf_c_is_null(kid)) {
        kid = t_cose_get_short_circuit_kid_l();
    }

    /* Make the linked list of two parameters, the alg id and kid. */
    me->local_params[0] = t_cose_make_alg_id_parameter(me->cose_algorithm_id);
    me->local_params[1] = t_cose_make_kid_parameter(kid);
    me->local_params[0].next = &me->local_params[1];

    *params = me->local_params;
}


/**
 * See \ref t_cose_signature_sign_callback of which this is an implementation.
 *
 * While this is a private function, it is called externally as a
 * callback via a function pointer that is set up in
 * t_cose_short_signer_init().
 */
static enum t_cose_err_t
t_cose_short_sign(struct t_cose_signature_sign *me_x,
                  bool                          make_cose_signature,
                  const struct q_useful_buf_c   protected_body_headers,
                  const struct q_useful_buf_c   aad,
                  const struct q_useful_buf_c   signed_payload,
                  QCBOREncodeContext           *qcbor_encoder)
{
    struct t_cose_signature_sign_short *me = (struct t_cose_signature_sign_short *)me_x;
    enum t_cose_err_t                  return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(        buffer_for_tbs_hash, T_COSE_CRYPTO_MAX_HASH_SIZE);
    Q_USEFUL_BUF_MAKE_STACK_UB(        buffer_for_signature, T_COSE_MAX_SIG_SIZE);
    struct q_useful_buf_c              tbs_hash;
    struct q_useful_buf_c              signature;
    struct q_useful_buf_c              signer_protected_headers;
    size_t                             tmp_sig_size;
    struct t_cose_parameter           *parameter_list;

    /* Get the sig size to find out if this is an alg that short-circuit
     * signer can pretend to be.
     */
    return_value = short_circuit_sig_size(me->cose_algorithm_id, &tmp_sig_size);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* -- The headers if it is a COSE_Sign -- */
    signer_protected_headers = NULLUsefulBufC;
    if(make_cose_signature) { // TODO: better name for this variable
        /* COSE_Sign, so making a COSE_Signature  */
        /* Open the array enclosing the two header buckets and the sig. */
        QCBOREncode_OpenArray(qcbor_encoder);

        t_cose_short_headers(me_x, &parameter_list);
        t_cose_parameter_list_append(parameter_list, me->added_signer_params);

        t_cose_encode_headers(qcbor_encoder, parameter_list, &signer_protected_headers);
    }

    /* -- The signature -- */
    if (QCBOREncode_IsBufferNULL(qcbor_encoder)) {
        /* Size calculation mode */
        signature.ptr = NULL;
        short_circuit_sig_size(me->cose_algorithm_id, &signature.len);

        return_value = T_COSE_SUCCESS;

    } else {
        /* Run the crypto to produce the signature */

        /* Create the hash of the to-be-signed bytes. Inputs to the
         * hash are the protected parameters, the payload that is
         * getting signed, the cose signature alg from which the hash
         * alg is determined. The cose_algorithm_id was checked in
         * t_cose_sign1_init() so it doesn't need to be checked here.
         */
        return_value = create_tbs_hash(me->cose_algorithm_id,
                                       protected_body_headers,
                                       signer_protected_headers,
                                       signed_payload,
                                       aad,
                                       buffer_for_tbs_hash,
                                       &tbs_hash);
        if(return_value) {
            goto Done;
        }

        return_value = short_circuit_fake_sign(me->cose_algorithm_id,
                                               tbs_hash,
                                               buffer_for_signature,
                                              &signature);
    }
    QCBOREncode_AddBytes(qcbor_encoder, signature);


    /* -- If a COSE_Sign, close of the COSE_Signature */
    if(make_cose_signature) {
        /* Close the array enclosing the two header buckets and the sig. */
        QCBOREncode_CloseArray(qcbor_encoder);
    }
    // TODO: lots of error handling

Done:
    return return_value;
}


/*
 * Pubilc Function. See t_cose_signature_sign_short.h
 */
void
t_cose_signature_sign_short_init(struct t_cose_signature_sign_short *me,
                                 int32_t                             cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
    me->s.callback        = t_cose_short_sign;
    me->s.h_callback      = t_cose_short_headers;
    me->cose_algorithm_id = cose_algorithm_id;
}
