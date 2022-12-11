/*
 *  t_cose_test_crypto.c
 *
 * Copyright 2019-2020, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created 3/31/2019.
 */


#include "t_cose_crypto.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_test_crypto.h"


/*
 * This file is stub crypto for initial bring up and test of t_cose.
 * It is NOT intended for commercial use. When this file is used as
 * the crypto adapter, no external crypto library is necessary. This is
 * convenient because sometimes it takes a while to sort out the crypto
 * porting layer for a new platform. With this most of t_cose can be tested
 * and demo signatures (short-circuit signatures) can be generated to
 * simulate out this would work.
 *
 * This file uses no signature algorithm. It uses the Brad Conte hash
 * implementation that is bundled with t_cose for the purpose of this
 * testing, not for commercial use.
 */


/*
 * See documentation in t_cose_crypto.h
 *
 * This will typically not be referenced and thus not linked,
 * for deployed code. This is mainly used for test.
 */
bool
t_cose_crypto_is_algorithm_supported(int32_t cose_algorithm_id)
{
    static const int32_t supported_algs[] = {
        T_COSE_ALGORITHM_SHA_256,
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
        T_COSE_ALGORITHM_SHORT_CIRCUIT_256,
        T_COSE_ALGORITHM_SHORT_CIRCUIT_384,
        T_COSE_ALGORITHM_SHORT_CIRCUIT_512,
#endif /* !T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */
        T_COSE_ALGORITHM_NONE /* List terminator */
    };

    for(const int32_t *i = supported_algs; *i != T_COSE_ALGORITHM_NONE; i++) {
        if(*i == cose_algorithm_id) {
            return true;
        }
    }
    return false;
}


/* The Brad Conte hash implementaiton bundled with t_cose */
#include "sha256.h"

/* Use of this file requires definition of T_COSE_USE_B_CON_SHA256 when
 * making t_cose_crypto.h.
 *
 * This only implements SHA-256 as that is all that is needed for the
 * non signing and verification tests using short-circuit signatures.
 */

#ifdef T_COSE_ENABLE_HASH_FAIL_TEST
/* Global variable just for this particular test. Not thread
 * safe or good for commercial use.
 */
int hash_test_mode = 0;
#endif


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_sig_size(int32_t           cose_algorithm_id,
                       struct t_cose_key signing_key,
                       size_t           *sig_size)
{
    (void)signing_key;

    /* sizes are 2x to simulate an ECDSA signature */
    *sig_size =
        cose_algorithm_id == T_COSE_ALGORITHM_SHORT_CIRCUIT_256 ? 2 * 256/8 :
        cose_algorithm_id == T_COSE_ALGORITHM_SHORT_CIRCUIT_384 ? 2 * 384/8 :
        cose_algorithm_id == T_COSE_ALGORITHM_SHORT_CIRCUIT_512 ? 2 * 512/8 :
        0;

    return *sig_size == 0 ? T_COSE_ERR_UNSUPPORTED_SIGNING_ALG : T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_sign(int32_t                cose_algorithm_id,
                   struct t_cose_key      signing_key,
                   void                  *crypto_context,
                   struct q_useful_buf_c  hash_to_sign,
                   struct q_useful_buf    signature_buffer,
                   struct q_useful_buf_c *signature)
{
    enum t_cose_err_t return_value;
    size_t            array_index;
    size_t            amount_to_copy;
    size_t            sig_size;
    struct t_cose_test_crypto_context *cc = (struct t_cose_test_crypto_context *)crypto_context;

    /* This is used for testing the crypto context */
    if(cc != NULL && cc->test_error != T_COSE_SUCCESS) {
        return cc->test_error;
    }

    /* This makes the short-circuit signature that is a concatenation
     * of copies of the hash. */
    return_value = t_cose_crypto_sig_size(cose_algorithm_id, signing_key, &sig_size);
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
    for(array_index = 0; array_index < sig_size; array_index += hash_to_sign.len) {
        amount_to_copy = sig_size - array_index;
        if(amount_to_copy > hash_to_sign.len) {
            amount_to_copy = hash_to_sign.len;
        }
        memcpy((uint8_t *)signature_buffer.ptr + array_index,
               hash_to_sign.ptr,
               amount_to_copy);
    }
    signature->ptr = signature_buffer.ptr;
    signature->len = sig_size;
    return_value   = T_COSE_SUCCESS;

Done:
    return return_value;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_verify(int32_t                cose_algorithm_id,
                     struct t_cose_key      verification_key,
                     struct q_useful_buf_c  kid,
                     void                  *crypto_context,
                     struct q_useful_buf_c  hash_to_verify,
                     struct q_useful_buf_c  signature)
{
    struct q_useful_buf_c hash_from_sig;
    enum t_cose_err_t     return_value;
    struct t_cose_test_crypto_context *cc = (struct t_cose_test_crypto_context *)crypto_context;

    (void)verification_key;
    (void)kid;

    /* This is used for testing the crypto context */
    if(cc != NULL && cc->test_error != T_COSE_SUCCESS) {
        return cc->test_error;
    }

    if(!t_cose_algorithm_is_short_circuit(cose_algorithm_id)) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    hash_from_sig = q_useful_buf_head(signature, hash_to_verify.len);
    if(q_useful_buf_c_is_null(hash_from_sig)) {
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    }

    if(q_useful_buf_compare(hash_from_sig, hash_to_verify)) {
        return_value = T_COSE_ERR_SIG_VERIFY;
    } else {
        return_value = T_COSE_SUCCESS;
    }

Done:
    return return_value;
}




/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                         int32_t cose_hash_alg_id)
{
#ifdef T_COSE_ENABLE_HASH_FAIL_TEST
    if(hash_test_mode == 1) {
        return T_COSE_ERR_HASH_GENERAL_FAIL;
    }
#endif

    if(cose_hash_alg_id != T_COSE_ALGORITHM_SHA_256) {
        return T_COSE_ERR_UNSUPPORTED_HASH;
    }

    sha256_init(&(hash_ctx->b_con_hash_context));
    return 0;
}

/*
 * See documentation in t_cose_crypto.h
 */
void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c data_to_hash)
{
    if(data_to_hash.ptr) {
        sha256_update(&(hash_ctx->b_con_hash_context),
                      data_to_hash.ptr,
                      data_to_hash.len);
    }
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf buffer_to_hold_result,
                          struct q_useful_buf_c *hash_result)
{
#ifdef T_COSE_ENABLE_HASH_FAIL_TEST
    if(hash_test_mode == 2) {
        return T_COSE_ERR_HASH_GENERAL_FAIL;
    }
#endif

    sha256_final(&(hash_ctx->b_con_hash_context), buffer_to_hold_result.ptr);
    *hash_result = (UsefulBufC){buffer_to_hold_result.ptr, 32};

    return 0;
}


enum t_cose_err_t
t_cose_crypto_hmac_compute_setup(struct t_cose_crypto_hmac *hmac_ctx,
                                 struct t_cose_key          signing_key,
                                 const int32_t              cose_alg_id)
{
    (void)hmac_ctx;
    (void)signing_key;
    (void)cose_alg_id;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

enum t_cose_err_t
t_cose_crypto_hmac_update(struct t_cose_crypto_hmac *hmac_ctx,
                          struct q_useful_buf_c      payload)
{
    (void)hmac_ctx;
    (void)payload;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

enum t_cose_err_t
t_cose_crypto_hmac_compute_finish(struct t_cose_crypto_hmac *hmac_ctx,
                                  struct q_useful_buf        tag_buf,
                                  struct q_useful_buf_c     *tag)
{
    (void)hmac_ctx;
    (void)tag_buf;
    (void)tag;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

enum t_cose_err_t
t_cose_crypto_hmac_validate_setup(struct t_cose_crypto_hmac *hmac_ctx,
                                  const  int32_t             cose_alg_id,
                                  struct t_cose_key          validation_key)
{
    (void)hmac_ctx;
    (void)cose_alg_id;
    (void)validation_key;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

enum t_cose_err_t
t_cose_crypto_hmac_validate_finish(struct t_cose_crypto_hmac *hmac_ctx,
                                   struct q_useful_buf_c      tag)
{
    (void)hmac_ctx;
    (void)tag;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}


#ifndef T_COSE_DISABLE_EDDSA

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_sign_eddsa(struct t_cose_key      signing_key,
                         void                  *crypto_context,
                         struct q_useful_buf_c  tbs,
                         struct q_useful_buf    signature_buffer,
                         struct q_useful_buf_c *signature)
{
    (void)signing_key;
    (void)crypto_context;
    (void)tbs;
    (void)signature_buffer;
    (void)signature;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_verify_eddsa(struct t_cose_key     verification_key,
                           struct q_useful_buf_c kid,
                           void                 *crypto_context,
                           struct q_useful_buf_c tbs,
                           struct q_useful_buf_c signature)
{
    (void)verification_key;
    (void)kid;
    (void)crypto_context;
    (void)tbs;
    (void)signature;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_get_random(struct q_useful_buf    buffer,
                         size_t                 number,
                         struct q_useful_buf_c *random)
{
    if (number > buffer.len) {
        return(T_COSE_ERR_TOO_SMALL);
    }

    /* In test mode this just fills a buffer with 'x' */
    memset(buffer.ptr, 'x', number);

    random->ptr = buffer.ptr;
    random->len = number;

    return T_COSE_SUCCESS;
}

#endif /* T_COSE_DISABLE_EDDSA */
