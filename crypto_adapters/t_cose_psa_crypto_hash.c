/*
 * t_cose_psa_crypto_hash.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.mdE.
 */

#include "t_cose_crypto.h"
#include "psa_crypto.h"

/**
 * \brief Convert COSE algorithm ID to a PSA algorithm ID
 *
 * \param[in] cose_hash_alg_id   The COSE-based ID for the
 *
 * \return PSA-based hash algorithm ID, or MD4 in the case of error.
 *
 */
static inline psa_algorithm_t cose_hash_alg_id_to_psa(int32_t cose_hash_alg_id)
{
    psa_algorithm_t return_value;

    switch(cose_hash_alg_id) {

    case COSE_ALG_SHA256_PROPRIETARY:
        return_value = PSA_ALG_SHA_256;
        break;

    default:
        return_value = PSA_ALG_MD4;
        break;
    }

    return return_value;
}


/**
 * \brief Map a PSA error into a t_cose error.
 *
 * \param[in] status   The PSA status.
 *
 * \return The t_cose error.
 */
static inline enum t_cose_err_t psa_status_to_t_cose_error(psa_status_t status)
{
    switch(status) {

    case PSA_SUCCESS:
        return T_COSE_SUCCESS;

    case PSA_ERROR_NOT_SUPPORTED:
        return T_COSE_ERR_UNSUPPORTED_HASH;

    case PSA_ERROR_BUFFER_TOO_SMALL:
        return T_COSE_ERR_HASH_BUFFER_SIZE;

    default:
        return T_COSE_ERR_HASH_GENERAL_FAIL;
    }
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                                           int32_t cose_hash_alg_id)
{
    /* Here's how t_cose_crypto_hash is used with PSA hashes.
     *
     * If you look inside psa_hash.handle is just a uint32_t that is
     * used as a handle. To avoid modifying t_cose_crypto.h in a
     * PSA-specific way, this implementation just copies the PSA
     * handle from the generic t_cose_crypto_hash on entry to a hash
     * function, and back on exit.
     *
     * This could have been implemented by modifying t_cose_crypto.h
     * so that psa_hash_operation_t is a member of t_cose_crypto_hash.
     * It's nice to not have to modify t_cose_crypto.h.
     *
     * This would have been cleaner if psa_hash_operation_t didn't
     * exist and the PSA crypto just used a plain pointer or integer
     * handle.  If psa_hash_operation_t is changed to be different
     * than just the single uint32_t, then this code has to change.
     *
     * The status member of t_cose_crypto_hash is used to hold a
     * psa_status_t error code.
     */
    psa_hash_operation_t psa_hash;
    psa_algorithm_t      psa_alg;

    /* Copy the PSA handle out of the generic context */
    psa_hash.handle = (uint32_t)hash_ctx->context.handle;

    /* Map the algorithm ID */
    psa_alg = cose_hash_alg_id_to_psa(cose_hash_alg_id);

    /* Actually do the hash set up */
    hash_ctx->status = psa_hash_setup(&psa_hash, psa_alg);

    /* Copy the PSA handle back into the context */
    hash_ctx->context.handle = psa_hash.handle;

    /* Map errors and return */
    return psa_status_to_t_cose_error((psa_status_t)hash_ctx->status);
}

/*
 * See documentation in t_cose_crypto.h
 */
void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c data_to_hash)
{
    /* See t_cose_crypto_hash_start() for context handling details */
    psa_hash_operation_t psa_hash;

    /* Copy the PSA handle out of the generic context */
    psa_hash.handle = (uint32_t)hash_ctx->context.handle;

    if(hash_ctx->status != PSA_SUCCESS) {
        /* In error state. Nothing to do. */
        return;
    }

    if(data_to_hash.ptr == NULL) {
        /* This allows for NULL buffers to be passed in all the way at
         * the top of signer or message creator when all that is
         * happening is the size of the result is being computed.
         */
        return;
    }

    /* Actually hash the data */
    hash_ctx->status = psa_hash_update(&psa_hash,
                                       data_to_hash.ptr,
                                       data_to_hash.len);

    /* Copy the PSA handle back into the context. */
    hash_ctx->context.handle = psa_hash.handle;
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf buffer_to_hold_result,
                          struct q_useful_buf_c *hash_result)
{
    /* See t_cose_crypto_hash_start() for context handling details */
    psa_hash_operation_t psa_hash;

    /* Copy the PSA handle out of the generic context */
    psa_hash.handle = (uint32_t)hash_ctx->context.handle;

    if(hash_ctx->status != PSA_SUCCESS) {
        /* Error state. Nothing to do */
        goto Done;
    }

    /* Actually finish up the hash */
    hash_ctx->status = psa_hash_finish(&psa_hash,
                                       buffer_to_hold_result.ptr,
                                       buffer_to_hold_result.len,
                                       &(hash_result->len));

    hash_result->ptr = buffer_to_hold_result.ptr;

    /* Copy the PSA handle back into the context. */
    hash_ctx->context.handle = psa_hash.handle;

Done:
    return psa_status_to_t_cose_error((psa_status_t)hash_ctx->status);
}
