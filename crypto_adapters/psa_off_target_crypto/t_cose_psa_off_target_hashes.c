/*
 * psa_off_target_hashes.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.mdE.
 */

#include "crypto.h" /* PSA crypto services */
#include "openssl/sha.h" /* OpenSSL hash functions */


/*
 This is a crude off-target implementation of psa_hash.
 Only one hash at a time. Not all the proper error handling.
 It is for off-target testing only.
 */
static SHA256_CTX g_s256_ctx;
static SHA512_CTX g_s512_ctx;


/* Track status of the single hash context */
typedef enum {IDLE, S256, S384, S512} off_target_hash_status_t;
static off_target_hash_status_t s_status = IDLE;

psa_status_t psa_hash_setup(psa_hash_operation_t *operation,
                            psa_algorithm_t       alg)
{
    int                      ossl_result;
    off_target_hash_status_t new_status;
    psa_status_t             return_value;

    if(s_status != IDLE) {
        return_value = PSA_ERROR_BAD_STATE;
        goto Done;
    }

    switch(alg) {
        case PSA_ALG_SHA_256:
            ossl_result = SHA256_Init(&g_s256_ctx);
            new_status = S256;
            break;

        case PSA_ALG_SHA_384:
            ossl_result = SHA384_Init(&g_s512_ctx);
            new_status = S384;
            break;

        case PSA_ALG_SHA_512:
            ossl_result = SHA512_Init(&g_s512_ctx);
            new_status = S512;
            break;

        default:
            return_value = PSA_ERROR_NOT_SUPPORTED;
            new_status = IDLE;
            goto Done;
            break;
    }

    if(!ossl_result) {
        return_value = PSA_ERROR_GENERIC_ERROR;
        goto Done;
    }

    operation->handle = new_status;
    s_status = new_status;
    return_value = PSA_SUCCESS;

  Done:
    return return_value;
}


psa_status_t psa_hash_update(psa_hash_operation_t *operation,
                             const uint8_t        *input,
                             size_t                input_length)
{
    int ossl_result;

    if(s_status !=  operation->handle) {
        /* Caller is out of sync with our one context */
        return PSA_ERROR_BAD_STATE;
    }

    switch((off_target_hash_status_t)operation->handle) {
        case IDLE:
            ossl_result = 0;
            break;

        case S256:
            ossl_result = SHA256_Update(&g_s256_ctx, input, input_length);
            break;

        case S384:
            ossl_result = SHA384_Update(&g_s512_ctx, input, input_length);
            break;

        case S512:
            ossl_result = SHA512_Update(&g_s512_ctx, input, input_length);
            break;
    }

    return ossl_result ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_hash_finish(psa_hash_operation_t *operation,
                             uint8_t              *hash,
                             size_t                hash_size,
                             size_t               *hash_length)
{
    int            ossl_result;
    psa_status_t   return_value;

    if(s_status !=  operation->handle) {
        /* Caller is out of sync with our one context */
        return PSA_ERROR_BAD_STATE;
    }

    switch((off_target_hash_status_t)operation->handle) {
        case IDLE:
            ossl_result = 0;
            break;

        case S256:
            if(hash_size < PSA_HASH_SIZE(PSA_ALG_SHA_256)) {
                return_value = PSA_ERROR_BUFFER_TOO_SMALL;
                goto Done;
            }
            ossl_result = SHA256_Final(hash, &g_s256_ctx);
            *hash_length = PSA_HASH_SIZE(PSA_ALG_SHA_256);
            break;

        case S384:
            if(hash_size < PSA_HASH_SIZE(PSA_ALG_SHA_384)) {
                return_value = PSA_ERROR_BUFFER_TOO_SMALL;
                goto Done;
            }
            ossl_result = SHA384_Final(hash, &g_s512_ctx);
            *hash_length = PSA_HASH_SIZE(PSA_ALG_SHA_384);
            break;

        case S512:
            if(hash_size < PSA_HASH_SIZE(PSA_ALG_SHA_512)) {
                return_value = PSA_ERROR_BUFFER_TOO_SMALL;
                goto Done;
            }
            ossl_result = SHA512_Final(hash, &g_s512_ctx);
            *hash_length = PSA_HASH_SIZE(PSA_ALG_SHA_512);
            break;
    }

    s_status = IDLE;

    return_value = ossl_result ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;
  Done:
    return return_value;
}


