/*
 *  t_cose_test_crypto.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created 3/31/2019.
 */


#include "t_cose_crypto.h"

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
t_cose_crypto_pub_key_sign(int32_t                cose_algorithm_id,
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

enum t_cose_err_t
t_cose_crypto_pub_key_verify(int32_t                cose_algorithm_id,
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
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
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
