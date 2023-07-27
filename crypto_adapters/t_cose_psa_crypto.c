/*
 * t_cose_psa_crypto.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2020-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


/**
 * \file t_cose_psa_crypto.c
 *
 * \brief Crypto Adaptation for t_cose to use ARM's PSA.
 *
 * This connects up the abstract interface in t_cose_crypto.h to the
 * implementations of signing and hashing in ARM's Mbed TLS crypto
 * library that implements the Arm PSA 1.0 crypto API.
 *
 * This adapter layer doesn't bloat the implementation as everything
 * here had to be done anyway -- the mapping of algorithm IDs, the
 * data format rearranging, the error code translation.
 *
 * This code should just work out of the box if compiled and linked
 * against ARM's PSA crypto. No preprocessor #defines are needed.
 *
 * You can disable SHA-384 and SHA-512 to save code and space by
 * defining T_COSE_DISABLE_ES384 or T_COSE_DISABLE_ES512. This saving
 * is most in stack space in the main t_cose implementation. (It seems
 * likely that changes to PSA itself would be needed to remove the
 * SHA-384 and SHA-512 implementations to save that code. Lack of
 * reference and dead stripping the executable won't do it).
 */


#include "t_cose_crypto.h"  /* The interface this implements */
#include <psa/crypto.h>     /* PSA Crypto Interface to mbed crypto or such */
#include <mbedtls/aes.h> // TODO: Isn't there a PSA API for AES?

#ifndef T_COSE_DISABLE_KEYWRAP
#include <mbedtls/nist_kw.h>
#endif /* T_COSE_DISABLE_KEYWRAP */

#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

#include "t_cose_util.h"
#include "t_cose_psa_crypto.h"

#if MBEDTLS_VERSION_MAJOR < 3
#define NO_MBED_KW_API
#warning "AES key wrap is unavailable with MbedTLS versions below 3"
#warning "Use of COSE algorithms A128KW..A256KW will return an error"
#endif /* MBEDTLS_VERSION_MAJOR < 3 */


/* Avoid compiler warning due to unused argument */
#define ARG_UNUSED(arg) (void)(arg)


/*
 * See documentation in t_cose_crypto.h
 *
 * This will typically not be referenced and thus not linked,
 * for deployed code. This is mainly used for test.
 */
bool t_cose_crypto_is_algorithm_supported(int32_t cose_algorithm_id)
{
    /* Notably, this list does not include EDDSA, regardless of how
     * t_cose is configured, since PSA doesn't support it.
     */
    static const int32_t supported_algs[] = {
        T_COSE_ALGORITHM_SHA_256,
        T_COSE_ALGORITHM_SHA_384,
        T_COSE_ALGORITHM_SHA_512,
        T_COSE_ALGORITHM_ES256,
#ifndef T_COSE_DISABLE_ES384
        T_COSE_ALGORITHM_ES384,
#endif
#ifndef T_COSE_DISABLE_ES512
        T_COSE_ALGORITHM_ES512,
#endif
#ifndef T_COSE_DISABLE_PS256
        T_COSE_ALGORITHM_PS256,
#endif
#ifndef T_COSE_DISABLE_PS384
        T_COSE_ALGORITHM_PS384,
#endif
#ifndef T_COSE_DISABLE_PS512
        T_COSE_ALGORITHM_PS512,
#endif
        T_COSE_ALGORITHM_HMAC256,
        T_COSE_ALGORITHM_HMAC384,
        T_COSE_ALGORITHM_HMAC512,
        T_COSE_ALGORITHM_A128GCM,
        T_COSE_ALGORITHM_A192GCM,
        T_COSE_ALGORITHM_A256GCM,

#if !defined NO_MBED_KW_API & !defined T_COSE_DISABLE_KEYWRAP
        T_COSE_ALGORITHM_A128KW,
        T_COSE_ALGORITHM_A192KW,
        T_COSE_ALGORITHM_A256KW,
#endif /* !(NO_MBED_KW_API && T_COSE_DISABLE_KEYWRAP) */

        T_COSE_ALGORITHM_NONE /* List terminator */
    };

    return t_cose_check_list(cose_algorithm_id, supported_algs);
}



/**
 * \brief Map a COSE signing algorithm ID to a PSA signing algorithm ID
 *
 * \param[in] cose_alg_id  The COSE algorithm ID.
 *
 * \return The PSA algorithm ID or 0 if this doesn't map the COSE ID.
 */
static psa_algorithm_t cose_alg_id_to_psa_alg_id(int32_t cose_alg_id)
{
    /* The #ifdefs save a little code when algorithms are disabled */
    switch(cose_alg_id) {
        case T_COSE_ALGORITHM_ES256 : return PSA_ALG_ECDSA(PSA_ALG_SHA_256);
#ifndef T_COSE_DISABLE_ES384
        case T_COSE_ALGORITHM_ES384 : return PSA_ALG_ECDSA(PSA_ALG_SHA_384);
#endif
#ifndef T_COSE_DISABLE_ES512
        case T_COSE_ALGORITHM_ES512 : return PSA_ALG_ECDSA(PSA_ALG_SHA_512);
#endif
#ifndef T_COSE_DISABLE_PS256
        case T_COSE_ALGORITHM_PS256 : return PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
#endif
#ifndef T_COSE_DISABLE_PS384
        case T_COSE_ALGORITHM_PS384 : return PSA_ALG_RSA_PSS(PSA_ALG_SHA_384);
#endif
#ifndef T_COSE_DISABLE_PS512
        case T_COSE_ALGORITHM_PS512 : return PSA_ALG_RSA_PSS(PSA_ALG_SHA_512);
#endif
        default: return 0;
    }

    /* psa/crypto_values.h doesn't seem to define a "no alg" value,
     * but zero seems OK for that use in the signing context. */
}


/**
 * \brief Map a PSA error into a t_cose error for signing.
 *
 * \param[in] err   The PSA status.
 *
 * \return The \ref t_cose_err_t.
 */
static enum t_cose_err_t
psa_status_to_t_cose_error_signing(psa_status_t err)
{
    /* See documentation for t_cose_int16_map(). Its use gives smaller
     * object code than a switch statement here.
     */
    static const int16_t error_map[][2] = {
        { PSA_SUCCESS                    , T_COSE_SUCCESS},
        { PSA_ERROR_INVALID_SIGNATURE    , T_COSE_ERR_SIG_VERIFY},
        { PSA_ERROR_NOT_SUPPORTED        , T_COSE_ERR_UNSUPPORTED_SIGNING_ALG},
        { PSA_ERROR_INSUFFICIENT_MEMORY  , T_COSE_ERR_INSUFFICIENT_MEMORY},
        { PSA_ERROR_CORRUPTION_DETECTED  , T_COSE_ERR_TAMPERING_DETECTED},
#if PSA_CRYPTO_HAS_RESTARTABLE_SIGNING
        { PSA_OPERATION_INCOMPLETE       , T_COSE_ERR_SIG_IN_PROGRESS},
#endif /* PSA_CRYPTO_HAS_RESTARTABLE_SIGNING */
        { INT16_MIN                      , T_COSE_ERR_SIG_FAIL},
    };

    return (enum t_cose_err_t )t_cose_int16_map(error_map, (int16_t)err);
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_verify(int32_t               cose_algorithm_id,
                     struct t_cose_key     verification_key,
                     void                 *crypto_context,
                     struct q_useful_buf_c hash_to_verify,
                     struct q_useful_buf_c signature)
{
    psa_algorithm_t       psa_alg_id;
    psa_status_t          psa_result;
    enum t_cose_err_t     return_value;
    psa_key_handle_t      verification_key_psa;

    (void)crypto_context; /* This crypto-adapter doesn't use this */

    /* Convert to PSA algorithm ID scheme */
    psa_alg_id = cose_alg_id_to_psa_alg_id(cose_algorithm_id);
    if(!PSA_ALG_IS_ECDSA(psa_alg_id) && !PSA_ALG_IS_RSA_PSS(psa_alg_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    verification_key_psa = (psa_key_handle_t)verification_key.key.handle;

    psa_result = psa_verify_hash(verification_key_psa,
                                 psa_alg_id,
                                 hash_to_verify.ptr,
                                 hash_to_verify.len,
                                 signature.ptr,
                                 signature.len);

    return_value = psa_status_to_t_cose_error_signing(psa_result);

  Done:
    return return_value;
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
    enum t_cose_err_t     return_value;
    psa_status_t          psa_result;
    psa_algorithm_t       psa_alg_id;
    psa_key_handle_t      signing_key_psa;
    size_t                signature_len;

    (void)crypto_context; /* This crypto-adapter doesn't use this */

    psa_alg_id = cose_alg_id_to_psa_alg_id(cose_algorithm_id);
    if(!PSA_ALG_IS_ECDSA(psa_alg_id) && !PSA_ALG_IS_RSA_PSS(psa_alg_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    signing_key_psa = (psa_key_handle_t)signing_key.key.handle;

    /* It is assumed that this call is checking the signature_buffer
     * length and won't write off the end of it.
     */

    psa_result = psa_sign_hash(signing_key_psa,
                               psa_alg_id,
                               hash_to_sign.ptr,
                               hash_to_sign.len,
                               signature_buffer.ptr, /* Sig buf */
                               signature_buffer.len, /* Sig buf size */
                              &signature_len);       /* Sig length */

    return_value = psa_status_to_t_cose_error_signing(psa_result);

    if(return_value == T_COSE_SUCCESS) {
        /* Success, fill in the return useful_buf */
        signature->ptr = signature_buffer.ptr;
        signature->len = signature_len;
    }

  Done:
     return return_value;
}


#if PSA_CRYPTO_HAS_RESTARTABLE_SIGNING
/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_sign_restart(bool                   started,
                           int32_t                cose_algorithm_id,
                           struct t_cose_key      signing_key,
                           void                  *crypto_context,
                           struct q_useful_buf_c  hash_to_sign,
                           struct q_useful_buf    signature_buffer,
                           struct q_useful_buf_c *signature)
{
    enum t_cose_err_t     return_value;
    psa_status_t          psa_result;
    psa_algorithm_t       psa_alg_id;
    psa_key_handle_t      signing_key_psa;
    size_t                signature_len;
    struct t_cose_psa_crypto_context *psa_crypto_context;

    psa_alg_id = cose_alg_id_to_psa_alg_id(cose_algorithm_id);
    if(!PSA_ALG_IS_ECDSA(psa_alg_id) && !PSA_ALG_IS_RSA_PSS(psa_alg_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    signing_key_psa = (psa_key_handle_t)signing_key.key.handle;

    /* It is assumed that this call is checking the signature_buffer
     * length and won't write off the end of it.
     */

    if(!crypto_context) {
        return_value = T_COSE_ERR_FAIL;
        goto Done;
    }
    psa_crypto_context = (struct t_cose_psa_crypto_context *)crypto_context;

    if(!started) {
        psa_result = psa_sign_hash_start(
                            &psa_crypto_context->operation,
                            signing_key_psa,
                            psa_alg_id,
                            hash_to_sign.ptr,
                            hash_to_sign.len);
        if(psa_result != PSA_SUCCESS) {
            return_value = psa_status_to_t_cose_error_signing(psa_result);
            goto Done;
        }
    }
    psa_result = psa_sign_hash_complete(
                            &psa_crypto_context->operation,
                            signature_buffer.ptr, /* Sig buf */
                            signature_buffer.len, /* Sig buf size */
                            &signature_len);

    return_value = psa_status_to_t_cose_error_signing(psa_result);

    if(return_value == T_COSE_SUCCESS) {
        /* Success, fill in the return useful_buf */
        signature->ptr = signature_buffer.ptr;
        signature->len = signature_len;
    }

Done:
     return return_value;
}
#endif /* PSA_CRYPTO_HAS_RESTARTABLE_SIGNING */

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t t_cose_crypto_sig_size(int32_t           cose_algorithm_id,
                                         struct t_cose_key signing_key,
                                         size_t           *sig_size)
{
    enum t_cose_err_t     return_value;
    psa_algorithm_t       psa_alg_id;
    mbedtls_svc_key_id_t  signing_key_psa;
    psa_key_attributes_t  key_attributes;
    psa_key_type_t        key_type;
    size_t                key_len_bits;
    psa_status_t          status;

    psa_alg_id = cose_alg_id_to_psa_alg_id(cose_algorithm_id);
    if(!PSA_ALG_IS_ECDSA(psa_alg_id) && !PSA_ALG_IS_RSA_PSS(psa_alg_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    signing_key_psa = (psa_key_handle_t)signing_key.key.handle;
    key_attributes = psa_key_attributes_init();
    status = psa_get_key_attributes(signing_key_psa, &key_attributes);
    return_value = psa_status_to_t_cose_error_signing(status);
    if(return_value) {
        goto Done;
    }

    key_type = psa_get_key_type(&key_attributes);
    key_len_bits = psa_get_key_bits(&key_attributes);
    *sig_size = (size_t)PSA_SIGN_OUTPUT_SIZE(key_type,
                                             (int)key_len_bits,
                                             psa_alg_id);

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}


/**
 * \brief Convert COSE hash algorithm ID to a PSA hash algorithm ID
 *
 * \param[in] cose_hash_alg_id   The COSE-based ID for the
 *
 * \return PSA-based hash algorithm ID, or USHRT_MAX on error.
 *
 */
static psa_algorithm_t
cose_hash_alg_id_to_psa(int32_t cose_hash_alg_id)
{
    return cose_hash_alg_id == T_COSE_ALGORITHM_SHA_256 ? PSA_ALG_SHA_256 :
#if !defined(T_COSE_DISABLE_ES384) || !defined(T_COSE_DISABLE_PS384)
           cose_hash_alg_id == T_COSE_ALGORITHM_SHA_384 ? PSA_ALG_SHA_384 :
#endif
#if !defined(T_COSE_DISABLE_ES512) || !defined(T_COSE_DISABLE_PS512)
           cose_hash_alg_id == T_COSE_ALGORITHM_SHA_512 ? PSA_ALG_SHA_512 :
#endif
                                                        UINT16_MAX;
}


/**
 * \brief Map a PSA error into a t_cose error for hashes.
 *
 * \param[in] status   The PSA status.
 *
 * \return The \ref t_cose_err_t.
 */
static enum t_cose_err_t
psa_status_to_t_cose_error_hash(psa_status_t status)
{
    static const int16_t error_map[][2] = {
        { PSA_SUCCESS                    , T_COSE_SUCCESS},
        { PSA_ERROR_NOT_SUPPORTED        , T_COSE_ERR_UNSUPPORTED_HASH},
        { PSA_ERROR_INVALID_ARGUMENT     , T_COSE_ERR_UNSUPPORTED_HASH},
        { PSA_ERROR_BUFFER_TOO_SMALL     , T_COSE_ERR_HASH_BUFFER_SIZE},
        { INT16_MIN                      , T_COSE_ERR_HASH_GENERAL_FAIL},
    };

    return (enum t_cose_err_t )t_cose_int16_map(error_map, (int16_t)status);
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                                           int32_t cose_hash_alg_id)
{
    psa_algorithm_t      psa_alg;

    /* Map the algorithm ID */
    psa_alg = cose_hash_alg_id_to_psa(cose_hash_alg_id);

    /* initialize PSA hash context */
    hash_ctx->ctx = psa_hash_operation_init();

    /* Actually do the hash set up */
    hash_ctx->status = psa_hash_setup(&(hash_ctx->ctx), psa_alg);

    /* Map errors and return */
    return psa_status_to_t_cose_error_hash((psa_status_t)hash_ctx->status);
}


/*
 * See documentation in t_cose_crypto.h
 */
void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c      data_to_hash)
{
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
    hash_ctx->status = psa_hash_update(&(hash_ctx->ctx),
                                       data_to_hash.ptr,
                                       data_to_hash.len);
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf        buffer_to_hold_result,
                          struct q_useful_buf_c     *hash_result)
{
    if(hash_ctx->status != PSA_SUCCESS) {
        /* Error state. Nothing to do */
        goto Done;
    }

    /* Actually finish up the hash */
    hash_ctx->status = psa_hash_finish(&(hash_ctx->ctx),
                                         buffer_to_hold_result.ptr,
                                         buffer_to_hold_result.len,
                                       &(hash_result->len));

    hash_result->ptr = buffer_to_hold_result.ptr;

Done:
    return psa_status_to_t_cose_error_hash(hash_ctx->status);
}


/**
 * \brief Convert COSE algorithm ID to a PSA HMAC algorithm ID
 *
 * \param[in] cose_hmac_alg_id   The COSE-based ID for the
 *
 * \return PSA-based MAC algorithm ID, or a vendor flag in the case of error.
 *
 */
static psa_algorithm_t cose_hmac_alg_id_to_psa(int32_t cose_hmac_alg_id)
{
    switch(cose_hmac_alg_id) {
    case T_COSE_ALGORITHM_HMAC256:
        return PSA_ALG_HMAC(PSA_ALG_SHA_256);
    case T_COSE_ALGORITHM_HMAC384:
        return PSA_ALG_HMAC(PSA_ALG_SHA_384);
    case T_COSE_ALGORITHM_HMAC512:
        return PSA_ALG_HMAC(PSA_ALG_SHA_512);
    default:
        return PSA_ALG_VENDOR_FLAG;
    }
}


/**
 * \brief Map a PSA error into a t_cose error for HMAC.
 *
 * \param[in] status   The PSA status.
 *
 * \return The \ref t_cose_err_t.
 */
static enum t_cose_err_t
psa_status_to_t_cose_error_hmac(psa_status_t status)
{
    /* See documentation for t_cose_int16_map(). Its use gives smaller
     * object code than a switch statement here.
     */
    static const int16_t error_map[][2] = {
        { PSA_SUCCESS,                   T_COSE_SUCCESS},
        { PSA_ERROR_NOT_SUPPORTED,       T_COSE_ERR_UNSUPPORTED_HMAC_ALG},
        { PSA_ERROR_INVALID_ARGUMENT,    T_COSE_ERR_INVALID_ARGUMENT},
        { PSA_ERROR_INSUFFICIENT_MEMORY, T_COSE_ERR_INSUFFICIENT_MEMORY},
        { PSA_ERROR_BUFFER_TOO_SMALL,    T_COSE_ERR_TOO_SMALL},
        { PSA_ERROR_INVALID_SIGNATURE,   T_COSE_ERR_HMAC_VERIFY},
        { INT16_MIN,                     T_COSE_ERR_HMAC_GENERAL_FAIL},
    };

    return (enum t_cose_err_t )t_cose_int16_map(error_map, (int16_t)status);
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hmac_compute_setup(struct t_cose_crypto_hmac *hmac_ctx,
                                 struct t_cose_key          signing_key,
                                 const int32_t              cose_alg_id)
{
    psa_algorithm_t psa_alg;
    psa_status_t psa_ret;

    /* Map the algorithm ID */
    psa_alg = cose_hmac_alg_id_to_psa(cose_alg_id);
    if(!PSA_ALG_IS_MAC(psa_alg)) {
        return T_COSE_ERR_UNSUPPORTED_HMAC_ALG;
    }

    /*
     * Verify if HMAC algorithm is valid.
     * According to COSE (RFC 9053), only SHA-256, SHA-384 and SHA-512 are
     * supported in COSE_Mac0 with HMAC.
     */
    if((psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_256)) &&
       (psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_384)) &&
       (psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_512))) {
        return T_COSE_ERR_UNSUPPORTED_HMAC_ALG;
    }

    hmac_ctx->op_ctx = psa_mac_operation_init();

    psa_ret = psa_mac_sign_setup(&hmac_ctx->op_ctx,
                                  (psa_key_id_t)signing_key.key.handle,
                                  psa_alg);

    return psa_status_to_t_cose_error_hmac(psa_ret);
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hmac_update(struct t_cose_crypto_hmac *hmac_ctx,
                          struct q_useful_buf_c      payload)
{
    psa_status_t psa_ret;

    psa_ret = psa_mac_update(&hmac_ctx->op_ctx,
                              payload.ptr, payload.len);

    return psa_status_to_t_cose_error_hmac(psa_ret);
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hmac_compute_finish(struct t_cose_crypto_hmac *hmac_ctx,
                                  struct q_useful_buf        tag_buf,
                                  struct q_useful_buf_c     *tag)
{
    psa_status_t psa_ret;

    psa_ret = psa_mac_sign_finish(&hmac_ctx->op_ctx,
                                   tag_buf.ptr, tag_buf.len,
                                  &(tag->len));
    if(psa_ret == PSA_SUCCESS) {
        tag->ptr = tag_buf.ptr;
    }

    return psa_status_to_t_cose_error_hmac(psa_ret);
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hmac_validate_setup(struct t_cose_crypto_hmac *hmac_ctx,
                                  const  int32_t             cose_alg_id,
                                  struct t_cose_key          validation_key)
{
    psa_algorithm_t psa_alg;
    psa_status_t psa_ret;

    if(!hmac_ctx) {
        return T_COSE_ERR_INVALID_ARGUMENT;
    }

    /* Map the algorithm ID */
    psa_alg = cose_hmac_alg_id_to_psa(cose_alg_id);
    if(!PSA_ALG_IS_MAC(psa_alg)) {
        return T_COSE_ERR_UNSUPPORTED_HMAC_ALG;
    }

    /*
     * Verify if HMAC algorithm is valid.
     * According to COSE (RFC 9053), only SHA-256, SHA-384 and SHA-512 are
     * supported in HMAC.
     */
    if((psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_256)) &&
       (psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_384)) &&
       (psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_512))) {
        return T_COSE_ERR_UNSUPPORTED_HMAC_ALG;
    }

    hmac_ctx->op_ctx = psa_mac_operation_init();

    psa_ret = psa_mac_verify_setup(&hmac_ctx->op_ctx,
                                   (psa_key_id_t)validation_key.key.handle,
                                   psa_alg);

    return psa_status_to_t_cose_error_hmac(psa_ret);
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hmac_validate_finish(struct t_cose_crypto_hmac *hmac_ctx,
                                   struct q_useful_buf_c      tag)
{
    psa_status_t psa_ret;

    if(!hmac_ctx) {
        return T_COSE_ERR_INVALID_ARGUMENT;
    }

    psa_ret = psa_mac_verify_finish(&hmac_ctx->op_ctx, tag.ptr, tag.len);

    return psa_status_to_t_cose_error_hmac(psa_ret);
}


enum t_cose_err_t
t_cose_crypto_sign_eddsa(struct t_cose_key      signing_key,
                         void                 *crypto_context,
                         struct q_useful_buf_c  tbs,
                         struct q_useful_buf    signature_buffer,
                         struct q_useful_buf_c *signature)
{
    (void)signing_key;
    (void)crypto_context;
    (void)tbs;
    (void)signature_buffer;
    (void)signature;

    /* MbedTLS does not support EdDSA */
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}


enum t_cose_err_t
t_cose_crypto_verify_eddsa(struct t_cose_key     verification_key,
                           void                 *crypto_context,
                           struct q_useful_buf_c tbs,
                           struct q_useful_buf_c signature)
{
    (void)verification_key;
    (void)crypto_context;
    (void)tbs;
    (void)signature;

    /* MbedTLS does not support EdDSA */
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_generate_ec_key(const int32_t       cose_ec_curve_id,
                              struct t_cose_key  *key)
{
    psa_key_attributes_t key_attributes;
    psa_key_handle_t     key_handle;
    psa_key_type_t       type;
    size_t               key_bitlen;
    psa_status_t         status;

   switch (cose_ec_curve_id) {
    case T_COSE_ELLIPTIC_CURVE_P_256:
        type       = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_bitlen = 256;
        break;
    case T_COSE_ELLIPTIC_CURVE_P_384:
         type       = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
         key_bitlen = 384;
         break;
    case T_COSE_ELLIPTIC_CURVE_P_521:
         type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
         key_bitlen = 521;
         break;
    default:
        return(T_COSE_ERR_UNSUPPORTED_KEM_ALG);
    }

    /* generate ephemeral key pair */
    key_attributes = psa_key_attributes_init();
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&key_attributes, PSA_ALG_ECDH);
    psa_set_key_type(&key_attributes, type);
    psa_set_key_bits(&key_attributes, key_bitlen);

    status = psa_generate_key(&key_attributes, &key_handle);

    if (status != PSA_SUCCESS) {
        return T_COSE_ERR_KEY_GENERATION_FAILED;
    }

    key->key.handle = key_handle;

    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_get_random(struct q_useful_buf    buffer,
                         size_t                 number,
                         struct q_useful_buf_c *random)
{
    psa_status_t status;

    if (number > buffer.len) {
        return(T_COSE_ERR_TOO_SMALL);
    }

    /* Generate buffer.len bytes of random values */
    status = psa_generate_random(buffer.ptr, buffer.len);

    if (status != PSA_SUCCESS) {
        return(T_COSE_ERR_RNG_FAILED);
    }

    random->ptr = buffer.ptr;
    random->len = number;

    return(T_COSE_SUCCESS);
}


#ifndef T_COSE_DISABLE_KEYWRAP


static unsigned int
bits_in_kw_key(int32_t cose_algorithm_id)
{
    switch(cose_algorithm_id) {
        case T_COSE_ALGORITHM_A128KW: return 128;
        case T_COSE_ALGORITHM_A192KW: return 192;
        case T_COSE_ALGORITHM_A256KW: return 256;
        default: return UINT_MAX;
    }
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_kw_wrap(int32_t                 cose_algorithm_id,
                      struct t_cose_key       kek,
                      struct q_useful_buf_c   plaintext,
                      struct q_useful_buf     ciphertext_buffer,
                      struct q_useful_buf_c  *ciphertext_result)
{
#ifdef NO_MBED_KW_API
    /* Handle MbedTLS 2.28 that doesn't support key wrap by default */
    return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
#else
    mbedtls_nist_kw_context kw_context;
    enum t_cose_err_t       err;
    int                     ret;
    size_t                  ciphertext_len;
    unsigned int            kek_bits;
    unsigned int            expected_kek_bits;
    struct q_useful_buf_c   kek_bytes;
    Q_USEFUL_BUF_MAKE_STACK_UB( kek_bytes_buf, T_COSE_MAX_SYMMETRIC_KEY_LENGTH);


    /* Export the actual key bytes from t_cose_key (which might be a handle) */
    err = t_cose_crypto_export_symmetric_key(kek,
                                              kek_bytes_buf,
                                              &kek_bytes);
    if(err != T_COSE_SUCCESS) {
        return err;
    }

    /* Check the supplied kek and algorithm ID */
    if(kek_bytes.len > UINT_MAX / 8) {
        /* Integer math would overflow (and it would be an enormous key) */
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;
    }
    kek_bits = (unsigned int)(8 * kek_bytes.len);

    expected_kek_bits = bits_in_kw_key(cose_algorithm_id);
    if(expected_kek_bits == UINT_MAX) {
        return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }

    if(kek_bits != expected_kek_bits) {
        /* An unsupported algorithm will return UINT_MAX bits */
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;
    }

    mbedtls_nist_kw_init(&kw_context);

    /* Configure KEK to be externally supplied symmetric key */
    ret = mbedtls_nist_kw_setkey(&kw_context,
                                  MBEDTLS_CIPHER_ID_AES,
                                  kek_bytes.ptr,
                                  kek_bits,
                                  MBEDTLS_ENCRYPT
                                );

    if (ret != 0) {
        return T_COSE_ERR_KW_FAILED;
    }

    /* Encrypt CEK with the AES key wrap algorithm defined in RFC 3394. */
    ret = mbedtls_nist_kw_wrap(&kw_context,
                                MBEDTLS_KW_MODE_KW,
                                plaintext.ptr,
                                plaintext.len,
                                ciphertext_buffer.ptr,
                               &ciphertext_len,
                                ciphertext_buffer.len
                              );

    if (ret != 0) {
        return T_COSE_ERR_KW_FAILED;
    }

    ciphertext_result->ptr = ciphertext_buffer.ptr;
    ciphertext_result->len = ciphertext_len;

    // TODO: this needs to be called in error conditions

    mbedtls_nist_kw_free(&kw_context);

    return T_COSE_SUCCESS;

    /* Here's a personal commentary on the Mbed/PSA API -- it's worse
     * that the other Mbed/PSA APIs so this adaptor function is
     * actually kind of large. It would be better if it took
     * a key handle as input rather than a key. It would better if it
     * combined setkey and init to save a function call. It's
     * not clear fro the API documentation whether it does any
     * checking on the key size. */
#endif /* NO_MBED_KW_API */
}


enum t_cose_err_t
t_cose_crypto_kw_unwrap(int32_t                 cose_algorithm_id,
                        struct t_cose_key       kek,
                        struct q_useful_buf_c   ciphertext,
                        struct q_useful_buf     plaintext_buffer,
                        struct q_useful_buf_c  *plaintext_result)
{
#ifdef NO_MBED_KW_API
    return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
#else
    mbedtls_nist_kw_context kw_context;
    enum t_cose_err_t       err;
    int                     ret;
    size_t                  plaintext_len;
    unsigned int            kek_bits;
    unsigned int            expected_kek_bits;
    enum t_cose_err_t       return_value;
    struct q_useful_buf_c   kek_bytes;
    Q_USEFUL_BUF_MAKE_STACK_UB( kek_bytes_buf, T_COSE_MAX_SYMMETRIC_KEY_LENGTH);

    /* Export the actual key bytes from t_cose_key (which might be a handle) */
    /* Maybe someday there will be wrap API that takes a key handle as input. */
    err = t_cose_crypto_export_symmetric_key(kek,
                                             kek_bytes_buf,
                                            &kek_bytes);
    if(err != T_COSE_SUCCESS) {
        return err;
    }

    /* Check the supplied kek and algorithm ID */
    if(kek_bytes.len > UINT_MAX / 8) {
        /* Integer math would overflow (and it would be an enormous key) */
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;
    }
    kek_bits = (unsigned int)(8 * kek_bytes.len);

    /* This checks the algorithm ID in addition to getting the number of bits */
    expected_kek_bits = bits_in_kw_key(cose_algorithm_id);
    if(expected_kek_bits == UINT_MAX) {
        return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }

    if(kek_bits != expected_kek_bits) {
        /* An unsupported algorithm will return UINT_MAX bits */
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;
    }

    /* Initialize and configure KEK */
    mbedtls_nist_kw_init(&kw_context);
    ret = mbedtls_nist_kw_setkey(&kw_context,
                                 MBEDTLS_CIPHER_ID_AES,
                                 kek_bytes.ptr,
                                 kek_bits,
                                 MBEDTLS_DECRYPT
                                );
    if (ret != 0) {
        return_value = T_COSE_ERR_KW_FAILED;
        goto Done;
    }

    /* Encrypt CEK with the AES key wrap algorithm defined in RFC 3394. */
    ret = mbedtls_nist_kw_unwrap(&kw_context,
                                  MBEDTLS_KW_MODE_KW,
                                  ciphertext.ptr,
                                  ciphertext.len,
                                  plaintext_buffer.ptr,
                                 &plaintext_len,
                                  plaintext_buffer.len
                                );

    if(ret == MBEDTLS_ERR_CIPHER_AUTH_FAILED) {
        return_value = T_COSE_ERR_DATA_AUTH_FAILED;
        goto Done;
    }
    if (ret != 0) {
        return_value = T_COSE_ERR_KW_FAILED;
        goto Done;
    }
    plaintext_result->ptr = plaintext_buffer.ptr;
    plaintext_result->len = plaintext_len;

    return_value = T_COSE_SUCCESS;

Done:
    mbedtls_nist_kw_free(&kw_context);

    return return_value;
#endif /* NO_MBED_KW_API */
}
#endif /* !T_COSE_DISABLE_KEYWRAP */




/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_export_symmetric_key(struct t_cose_key      key,
                                   struct q_useful_buf    key_buffer,
                                   struct q_useful_buf_c *key_bytes)
{
    psa_status_t  status;

    if(key.key.handle == 0) {
        /* Not strictly necessary but helpful at time for the library
         * user to debug. PSA defines 0 as an invalid handle. Could
         * disable with usage guards disabled for smaller code size. */
        return T_COSE_ERR_EMPTY_KEY;
    }

    status = psa_export_key((mbedtls_svc_key_id_t)key.key.handle,
                             key_buffer.ptr,
                             key_buffer.len,
                            &key_bytes->len);
    key_bytes->ptr = key_buffer.ptr;

    // TODO: maybe error about buffer length?
    if (status != PSA_SUCCESS) {
        return(T_COSE_ERR_KEY_EXPORT_FAILED);
    }

    return(T_COSE_SUCCESS);
}


/*
 * See documentation in t_cose_crypto.h
 */
void
t_cose_crypto_free_symmetric_key(struct t_cose_key key)
{
    psa_close_key((psa_key_id_t)key.key.handle);
}



/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_make_symmetric_key_handle(int32_t               cose_algorithm_id,
                                        struct q_useful_buf_c symmetric_key,
                                        struct t_cose_key    *key_handle)
{
    psa_algorithm_t       psa_algorithm;
    psa_key_handle_t      psa_key_handle;
    psa_status_t          status;
    psa_key_attributes_t  attributes;
    size_t                key_bitlen;
    psa_key_type_t        psa_keytype;
    psa_key_usage_t       psa_key_usage;

    /* TODO: remove this and put it somewhere common. (It's OK to call twice,
     * so having it here doesn't cause a problem in the short term */
    psa_crypto_init();

    /* PSA always enforces policy for algorithms with no way to turn it off.
     * It is also strict on usage, but that can be relaxed by listing lots
     * of usages.  OpenSSL OTOH has no such enforcement (which means less
     * codes in the crypto layer).

     * Mbed TLS is inconsistent with the PSA API for key wrap that
     * necessitates setting PSA_KEY_USAGE_EXPORT here. There is no PSA API
     * for key wrap, only an MbedTLS API. That API takes key *bytes* not
     * a key handle (like PSA APIs). See t_cose_crypto_kw_wrap().
     *
     * Also see comments in t_cose_key.h and t_cose_crypto.h
     */

    switch (cose_algorithm_id) {
        case T_COSE_ALGORITHM_A128GCM:
        case T_COSE_ALGORITHM_A128KW:
            psa_algorithm = PSA_ALG_GCM;
            psa_keytype = PSA_KEY_TYPE_AES;
            psa_key_usage = PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT;
            key_bitlen = 128;
            break;

        case T_COSE_ALGORITHM_A192GCM:
        case T_COSE_ALGORITHM_A192KW:
            psa_algorithm = PSA_ALG_GCM;
            psa_keytype = PSA_KEY_TYPE_AES;
            psa_key_usage = PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT;
            key_bitlen = 192;
            break;

        case T_COSE_ALGORITHM_A256GCM:
        case T_COSE_ALGORITHM_A256KW:
            psa_algorithm = PSA_ALG_GCM;
            psa_keytype = PSA_KEY_TYPE_AES;
            psa_key_usage = PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT;
            key_bitlen = 256;
            break;

        case T_COSE_ALGORITHM_HMAC256:
            psa_keytype = PSA_KEY_TYPE_HMAC;
            psa_algorithm = PSA_ALG_HMAC(PSA_ALG_SHA_256);
            psa_key_usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
            key_bitlen = 256;
            break;

        case T_COSE_ALGORITHM_HMAC384:
            psa_keytype = PSA_KEY_TYPE_HMAC;
            psa_algorithm = PSA_ALG_HMAC(PSA_ALG_SHA_384);
            psa_key_usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
            key_bitlen = 384;
            break;

        case T_COSE_ALGORITHM_HMAC512:
            psa_keytype = PSA_KEY_TYPE_HMAC;
            psa_algorithm = PSA_ALG_HMAC(PSA_ALG_SHA_512);
            psa_key_usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
            key_bitlen = 512;
            break;

        default:
            return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }

    attributes = psa_key_attributes_init();
    psa_set_key_usage_flags(&attributes, psa_key_usage);
    psa_set_key_algorithm(&attributes, psa_algorithm);
    psa_set_key_type(&attributes, psa_keytype);
    psa_set_key_bits(&attributes, key_bitlen);

    status = psa_import_key(&attributes,        /* in: filled-in attributes struct */
                             symmetric_key.ptr, /* in: pointer to key bytes */
                             symmetric_key.len, /* in: length of key bytes  */
                            &psa_key_handle);   /* out: new key handle      */

    if (status != PSA_SUCCESS) {
        return T_COSE_ERR_SYMMETRIC_KEY_IMPORT_FAILED;
    }

    key_handle->key.handle = psa_key_handle;

    return T_COSE_SUCCESS;
}


/* Compute size of ciphertext, given size of plaintext. Returns
 * SIZE_MAX if the algorithm is unknown.
 */
static size_t
aead_byte_count(const int32_t cose_algorithm_id,
                size_t        plain_text_len)
{
    /* So far this just works for GCM AEAD algorithms, but can be
     * augmented for others.
     *
     * For GCM as used by COSE and HPKE, the authentication tag is
     * appended to the end of the cipher text and is always 16 bytes.
     * Since GCM is a variant of counter mode, the ciphertext length
     * is the same as the plaintext length. (This is not true of other
     * ciphers).
     * https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode
     */

    /* The same tag length for all COSE and HPKE AEAD algorithms supported.*/
    const size_t common_gcm_tag_length = 16;

    switch(cose_algorithm_id) {
        case T_COSE_ALGORITHM_A128GCM:
            return plain_text_len + common_gcm_tag_length;
        case T_COSE_ALGORITHM_A192GCM:
            return plain_text_len + common_gcm_tag_length;
        case T_COSE_ALGORITHM_A256GCM:
            return plain_text_len + common_gcm_tag_length;
        default: return SIZE_MAX;;
    }
}


static enum t_cose_err_t
aead_psa_status_to_t_cose_err(psa_status_t status, enum t_cose_err_t deflt)
{
    switch(status) {
        case PSA_SUCCESS : return  T_COSE_SUCCESS;

        case PSA_ERROR_NOT_SUPPORTED: return  T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;

        case PSA_ERROR_BUFFER_TOO_SMALL: return  T_COSE_ERR_TOO_SMALL;

        case PSA_ERROR_INVALID_HANDLE: return T_COSE_ERR_WRONG_TYPE_OF_KEY;

        case PSA_ERROR_INVALID_ARGUMENT: return T_COSE_ERR_WRONG_TYPE_OF_KEY;

        case PSA_ERROR_NOT_PERMITTED: return T_COSE_ERR_WRONG_TYPE_OF_KEY;

        case PSA_ERROR_INVALID_SIGNATURE: return T_COSE_ERR_DATA_AUTH_FAILED;

        default: return deflt;
    }
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_aead_encrypt(const int32_t          cose_algorithm_id,
                           struct t_cose_key      key,
                           struct q_useful_buf_c  nonce,
                           struct q_useful_buf_c  aad,
                           struct q_useful_buf_c  plaintext,
                           struct q_useful_buf    ciphertext_buffer,
                           struct q_useful_buf_c *ciphertext)
{
    psa_algorithm_t  psa_algorithm_id;
    psa_status_t     status;

    /* Pretty sure the optimizer will do good things with this switch. */
    switch (cose_algorithm_id) {
        case T_COSE_ALGORITHM_A128GCM:
            psa_algorithm_id = PSA_ALG_GCM;
            break;
        case T_COSE_ALGORITHM_A192GCM:
            psa_algorithm_id = PSA_ALG_GCM;
            break;
        case T_COSE_ALGORITHM_A256GCM:
            psa_algorithm_id = PSA_ALG_GCM;
            break;
        case T_COSE_ALGORITHM_AES128CCM_16_128:
            psa_algorithm_id = PSA_ALG_CCM;
            break;
        case T_COSE_ALGORITHM_AES256CCM_16_128:
            psa_algorithm_id = PSA_ALG_CCM;
            break;
        default:
            return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }

    if(ciphertext_buffer.ptr == NULL) {
        /* Called in length calculation mode. Return length & exit. */
        ciphertext->len = aead_byte_count(cose_algorithm_id,
                                          plaintext.len);;
        return T_COSE_SUCCESS;
    }

    status = psa_aead_encrypt((psa_key_handle_t)key.key.handle,
                              psa_algorithm_id,
                              nonce.ptr, nonce.len,
                              aad.ptr, aad.len,
                              plaintext.ptr, plaintext.len,
                              ciphertext_buffer.ptr, ciphertext_buffer.len,
                             &ciphertext->len);

    ciphertext->ptr = ciphertext_buffer.ptr;

    return aead_psa_status_to_t_cose_err(status, T_COSE_ERR_ENCRYPT_FAIL);

    /* If you want to feel good about how nice the PSA API for
     * AEAD is, go look at the AEAD crypto adaptor for OpenSSL.
     */
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_aead_decrypt(const int32_t          cose_algorithm_id,
                           struct t_cose_key      key,
                           struct q_useful_buf_c  nonce,
                           struct q_useful_buf_c  aad,
                           struct q_useful_buf_c  ciphertext,
                           struct q_useful_buf    plaintext_buffer,
                           struct q_useful_buf_c *plaintext)
{
    psa_algorithm_t  psa_algorithm_id;
    psa_status_t     status;

    switch (cose_algorithm_id) {
        case T_COSE_ALGORITHM_A128GCM:
            psa_algorithm_id = PSA_ALG_GCM;
            break;
        case T_COSE_ALGORITHM_A192GCM:
            psa_algorithm_id = PSA_ALG_GCM;
            break;
        case T_COSE_ALGORITHM_A256GCM:
            psa_algorithm_id = PSA_ALG_GCM;
            break;
        default:
            return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }


    status = psa_aead_decrypt((psa_key_handle_t)key.key.handle,
                              psa_algorithm_id,
                              nonce.ptr, nonce.len,
                              aad.ptr, aad.len,
                              ciphertext.ptr, ciphertext.len,
                              plaintext_buffer.ptr, plaintext_buffer.len,
                             &plaintext->len);
    plaintext->ptr = plaintext_buffer.ptr;

    return aead_psa_status_to_t_cose_err(status, T_COSE_ERR_DECRYPT_FAIL);
}



/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_ecdh(struct t_cose_key      private_key,
                   struct t_cose_key      public_key,
                   struct q_useful_buf    shared_key_buf,
                   struct q_useful_buf_c *shared_key)
{
    psa_status_t         psa_status;
    MakeUsefulBufOnStack(public_key_buf, T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE);
    size_t               pub_key_len;

    /* Export public key */
    psa_status = psa_export_public_key((mbedtls_svc_key_id_t)public_key.key.handle, /* in: Key handle     */
                                        public_key_buf.ptr,     /* in: PK buffer      */
                                        public_key_buf.len,     /* in: PK buffer size */
                                       &pub_key_len);           /* out: Result length */
    if(psa_status != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }


    psa_status = psa_raw_key_agreement(PSA_ALG_ECDH,
                                       (mbedtls_svc_key_id_t)private_key.key.handle,
                                       public_key_buf.ptr,
                                       pub_key_len,
                                       shared_key_buf.ptr,
                                       shared_key_buf.len,
                                       &(shared_key->len));
    if(psa_status != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    shared_key->ptr = shared_key_buf.ptr;

    return T_COSE_SUCCESS;
}





/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hkdf(const int32_t               cose_hash_algorithm_id,
                   const struct q_useful_buf_c salt,
                   const struct q_useful_buf_c ikm,
                   const struct q_useful_buf_c info,
                   const struct q_useful_buf   okm_buffer)
{
    int                       psa_result;
    const mbedtls_md_info_t  *md_info;
    mbedtls_md_type_t         hash_type;

    switch(cose_hash_algorithm_id) {
        case T_COSE_ALGORITHM_SHA_256:
            hash_type = MBEDTLS_MD_SHA256;
            break;
        case T_COSE_ALGORITHM_SHA_384:
            hash_type = MBEDTLS_MD_SHA384;
            break;
        case T_COSE_ALGORITHM_SHA_512:
            hash_type = MBEDTLS_MD_SHA512;
            break;
        default:
            hash_type = MBEDTLS_MD_NONE;
            break;
    }

    md_info = mbedtls_md_info_from_type(hash_type);
    if(md_info == NULL) {
        return T_COSE_ERR_UNSUPPORTED_HASH;
    }

    psa_result = mbedtls_hkdf(md_info,
                              salt.ptr, salt.len,
                              ikm.ptr, ikm.len,
                              info.ptr, info.len,
                              okm_buffer.ptr, okm_buffer.len);
    if(psa_result != PSA_SUCCESS) {
        return T_COSE_ERR_HKDF_FAIL;
    }

    return T_COSE_SUCCESS;
}




/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_import_ec2_pubkey(int32_t               cose_ec_curve_id,
                                struct q_useful_buf_c x_coord,
                                struct q_useful_buf_c y_coord,
                                bool                  y_bool,
                                struct t_cose_key    *key_handle)
{
    psa_status_t          status;
    psa_key_attributes_t  attributes;
    psa_key_type_t        type_public;
    struct q_useful_buf_c  import;
    // TODO: really make sure this size is right for the curve types supported
    UsefulOutBuf_MakeOnStack (import_form, T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE + 5);

    switch (cose_ec_curve_id) {
    case T_COSE_ELLIPTIC_CURVE_P_256:
         type_public  = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
         break;
    case T_COSE_ELLIPTIC_CURVE_P_384:
         type_public  = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
         break;
    case T_COSE_ELLIPTIC_CURVE_P_521:
         type_public  = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
         break;

    default:
         return T_COSE_ERR_UNSUPPORTED_ELLIPTIC_CURVE_ALG;
    }


    // TODO: are these attributes right?
    attributes = psa_key_attributes_init();
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_COPY);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa_set_key_type(&attributes, type_public);

    /* This converts to a serialized representation of an EC Point
     * described in
     * Certicom Research, "SEC 1: Elliptic Curve Cryptography", Standards for
     * Efficient Cryptography, May 2009, <https://www.secg.org/sec1-v2.pdf>.
     * The description is very mathematical and hard to read for us
     * coder types. It was much easier to understand reading Jim's
     * COSE-C implementation. See mbedtls_ecp_keypair() in COSE-C.
     *
     * This string is the format used by Mbed TLS to import an EC
     * public key.
     *
     * This does implement point compression. The patents for it have
     * run out so it's OK to implement. Point compression is commented
     * out in Jim's implementation, presumably because of the paten
     * issue.
     *
     * A simple English description of the format is this. The first
     * byte is 0x04 for no point compression and 0x02 or 0x03 if there
     * is point compression. 0x02 indicates a positive y and 0x03 a
     * negative y (or is the other way). Following the first byte
     * are the octets of x. If the first byte is 0x04 then following
     * x is the y value.
     *
     * UsefulOutBut is used to safely construct this string.
     */
    uint8_t first_byte;
    if(q_useful_buf_c_is_null(y_coord)) {
        /* This is point compression */
        first_byte = y_bool ? 0x03 : 0x02;
    } else {
        first_byte = 0x04;
    }

    // TODO: is padding of x necessary? Jim's code goes to
    // a lot of trouble to look up the group and get the length.

    UsefulOutBuf_AppendByte(&import_form, first_byte);
    UsefulOutBuf_AppendUsefulBuf(&import_form, x_coord);
    if(first_byte == 0x04) {
        UsefulOutBuf_AppendUsefulBuf(&import_form, y_coord);
    }
    import = UsefulOutBuf_OutUBuf(&import_form);


    status = psa_import_key(&attributes,
                            import.ptr, import.len,
                            (mbedtls_svc_key_id_t *)(&key_handle->key.handle));

    if (status != PSA_SUCCESS) {
        return T_COSE_ERR_PRIVATE_KEY_IMPORT_FAILED;
    }

    return T_COSE_SUCCESS;
}




enum t_cose_err_t
t_cose_crypto_export_ec2_key(struct t_cose_key      key_handle,
                             int32_t               *curve,
                             struct q_useful_buf    x_coord_buf,
                             struct q_useful_buf_c *x_coord,
                             struct q_useful_buf    y_coord_buf,
                             struct q_useful_buf_c *y_coord,
                             bool                  *y_bool)
{
    psa_status_t          psa_status;
    uint8_t               export_buf[T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE];
    size_t                export_len;
    struct q_useful_buf_c export;
    size_t                len;
    uint8_t               first_byte;
    psa_key_attributes_t  attributes;

    /* Export public key */
    psa_status = psa_export_public_key((mbedtls_svc_key_id_t)key_handle.key.handle, /* in: Key handle     */
                                        export_buf,     /* in: PK buffer      */
                                        sizeof(export_buf),     /* in: PK buffer size */
                                       &export_len);           /* out: Result length */
    if(psa_status != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }
    first_byte = export_buf[0];
    export = (struct q_useful_buf_c){export_buf+1, export_len-1};

    /* export_buf is one first byte, the x-coord and maybe the y-coord
     * per SEC1.
     */

    attributes = psa_key_attributes_init();
    psa_status = psa_get_key_attributes((mbedtls_svc_key_id_t)key_handle.key.handle,
                                        &attributes);
    if(PSA_KEY_TYPE_ECC_GET_FAMILY(psa_get_key_type(&attributes)) != PSA_ECC_FAMILY_SECP_R1) {
        return T_COSE_ERR_FAIL;
    }

    switch(psa_get_key_bits(&attributes)) {
    case 256:
        *curve = T_COSE_ELLIPTIC_CURVE_P_256;
        break;
    case 384:
        *curve = T_COSE_ELLIPTIC_CURVE_P_384;
        break;
    case 521:
        *curve = T_COSE_ELLIPTIC_CURVE_P_521;
        break;
    default:
        return T_COSE_ERR_FAIL;
    }


    switch(first_byte) {
        case 0x04:
            len = (export_len - 1 ) / 2;
            *y_coord = UsefulBuf_Copy(y_coord_buf, UsefulBuf_Tail(export, len));
            break;

        case 0x02:
            len = export_len - 1;
            *y_coord = NULL_Q_USEFUL_BUF_C;
            *y_bool = true;
            break;

        case 0x03:
            len = export_len - 1;
            *y_coord = NULL_Q_USEFUL_BUF_C;
            *y_bool = false;
            break;

        default:
            return T_COSE_ERR_FAIL;
    }

    *x_coord = UsefulBuf_Copy(x_coord_buf, UsefulBuf_Head(export, len));
    // TODO: errors when buffer is too small

    return T_COSE_SUCCESS;
}
