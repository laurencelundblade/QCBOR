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


/*
 * This file is stub crypto for initial bring up and test of t_cose.
 * It is NOT intended for commercial use. When this file is used as
 * the crypto adapter, no external crypto library is necessary. This is
 * convenient because sometime it takes a while to sort out the crypto
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
        COSE_ALGORITHM_SHA_256,
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
enum t_cose_err_t t_cose_crypto_sig_size(int32_t           cose_algorithm_id,
                                         struct t_cose_key signing_key,
                                         size_t           *sig_size)
{
    (void)cose_algorithm_id;
    (void)signing_key;

    *sig_size = T_COSE_MAX_SIG_SIZE;

    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_sign(int32_t                cose_algorithm_id,
                   struct t_cose_key      signing_key,
                   struct q_useful_buf_c  hash_to_sign,
                   struct q_useful_buf    signature_buffer,
                   struct q_useful_buf_c *signature)
{
    (void)cose_algorithm_id;
    (void)signing_key;
    (void)hash_to_sign;
    (void)signature_buffer;
    (void)signature;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_verify(int32_t                cose_algorithm_id,
                     struct t_cose_key      verification_key,
                     struct q_useful_buf_c  kid,
                     struct q_useful_buf_c  hash_to_verify,
                     struct q_useful_buf_c  signature)
{
    (void)cose_algorithm_id;
    (void)verification_key;
    (void)kid;
    (void)hash_to_verify;
    (void)signature;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
int check_for_key_pair_leaks(void)
{
    /* No check for leaks with this stubbed out crypto. With this test
     crypto there is no file with code to make keys so there is no place
     but here for this function to live.
     */
    return 0;
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

    if(cose_hash_alg_id != COSE_ALGORITHM_SHA_256) {
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
t_cose_crypto_hmac_sign_setup(struct t_cose_crypto_hmac *hmac_ctx,
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
t_cose_crypto_hmac_sign_finish(struct t_cose_crypto_hmac *hmac_ctx,
                               struct q_useful_buf        tag_buf,
                               struct q_useful_buf_c     *tag)
{
    (void)hmac_ctx;
    (void)tag_buf;
    (void)tag;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

enum t_cose_err_t
t_cose_crypto_hmac_verify_setup(struct t_cose_crypto_hmac *hmac_ctx,
                                const  int32_t             cose_alg_id,
                                struct t_cose_key          verify_key)
{
    (void)hmac_ctx;
    (void)cose_alg_id;
    (void)verify_key;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

enum t_cose_err_t
t_cose_crypto_hmac_verify_finish(struct t_cose_crypto_hmac *hmac_ctx,
                                 struct q_useful_buf_c      tag)
{
    (void)hmac_ctx;
    (void)tag;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}
