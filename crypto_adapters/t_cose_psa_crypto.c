/*
 * t_cose_psa_crypto.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2020-2022, Arm Limited. All rights reserved.
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

#ifndef T_COSE_DISABLE_AES_KW
// TODO: isn't there a PSA API for key wrap?
#include <mbedtls/nist_kw.h>
#endif /* T_COSE_DISABLE_AES_KW */



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
#ifndef T_COSE_DISABLE_MAC0
        T_COSE_ALGORITHM_HMAC256,
        T_COSE_ALGORITHM_HMAC384,
        T_COSE_ALGORITHM_HMAC512,
        T_COSE_ALGORITHM_A128GCM,
        T_COSE_ALGORITHM_A192GCM, /* For 9053 key wrap and direct, not HPKE */
        T_COSE_ALGORITHM_A256GCM,

#endif /* T_COSE_DISABLE_MAC0 */
        T_COSE_ALGORITHM_NONE /* List terminator */
    };

    return t_cose_check_list(cose_algorithm_id, supported_algs);
}


#ifndef T_COSE_DISABLE_SIGN1

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

    return cose_alg_id == T_COSE_ALGORITHM_ES256 ? PSA_ALG_ECDSA(PSA_ALG_SHA_256) :
#ifndef T_COSE_DISABLE_ES384
           cose_alg_id == T_COSE_ALGORITHM_ES384 ? PSA_ALG_ECDSA(PSA_ALG_SHA_384) :
#endif
#ifndef T_COSE_DISABLE_ES512
           cose_alg_id == T_COSE_ALGORITHM_ES512 ? PSA_ALG_ECDSA(PSA_ALG_SHA_512) :
#endif
#ifndef T_COSE_DISABLE_PS256
           cose_alg_id == T_COSE_ALGORITHM_PS256 ? PSA_ALG_RSA_PSS(PSA_ALG_SHA_256) :
#endif
#ifndef T_COSE_DISABLE_PS384
           cose_alg_id == T_COSE_ALGORITHM_PS384 ? PSA_ALG_RSA_PSS(PSA_ALG_SHA_384) :
#endif
#ifndef T_COSE_DISABLE_PS512
           cose_alg_id == T_COSE_ALGORITHM_PS512 ? PSA_ALG_RSA_PSS(PSA_ALG_SHA_512) :
#endif
                                                 0;
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
    /* Intentionally keeping to fewer mapped errors to save object code */
    return err == PSA_SUCCESS                   ? T_COSE_SUCCESS :
           err == PSA_ERROR_INVALID_SIGNATURE   ? T_COSE_ERR_SIG_VERIFY :
           err == PSA_ERROR_NOT_SUPPORTED       ? T_COSE_ERR_UNSUPPORTED_SIGNING_ALG:
           err == PSA_ERROR_INSUFFICIENT_MEMORY ? T_COSE_ERR_INSUFFICIENT_MEMORY :
           err == PSA_ERROR_CORRUPTION_DETECTED ? T_COSE_ERR_TAMPERING_DETECTED :
                                                  T_COSE_ERR_SIG_FAIL;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_verify(int32_t               cose_algorithm_id,
                     struct t_cose_key     verification_key,
                     struct q_useful_buf_c kid,
                     void                 *crypto_context,
                     struct q_useful_buf_c hash_to_verify,
                     struct q_useful_buf_c signature)
{
    psa_algorithm_t       psa_alg_id;
    psa_status_t          psa_result;
    enum t_cose_err_t     return_value;
    psa_key_handle_t      verification_key_psa;

    /* This implementation does no look up keys by kid in the key
     * store */
    ARG_UNUSED(kid);

    (void)crypto_context; /* This crypto-adapter doesn't use this */


    /* Convert to PSA algorithm ID scheme */
    psa_alg_id = cose_alg_id_to_psa_alg_id(cose_algorithm_id);
    if(!PSA_ALG_IS_ECDSA(psa_alg_id) && !PSA_ALG_IS_RSA_PSS(psa_alg_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    verification_key_psa = (psa_key_handle_t)verification_key.k.key_handle;

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

    signing_key_psa = (psa_key_handle_t)signing_key.k.key_handle;

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

    signing_key_psa = (psa_key_handle_t)signing_key.k.key_handle;
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
#endif /* !T_COSE_DISABLE_SIGN1 */


#if !defined(T_COSE_DISABLE_SIGN1)
/**
 * \brief Convert COSE hash algorithm ID to a PSA hash algorithm ID
 *
 * \param[in] cose_hash_alg_id   The COSE-based ID for the
 *
 * \return PSA-based hash algorithm ID, or USHRT_MAX on error.
 *
 */
static inline psa_algorithm_t
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
    /* Intentionally limited to just this minimum set of errors to
     * save object code as hashes don't really fail much
     */
    return status == PSA_SUCCESS                ? T_COSE_SUCCESS :
           status == PSA_ERROR_NOT_SUPPORTED    ? T_COSE_ERR_UNSUPPORTED_HASH :
           status == PSA_ERROR_INVALID_ARGUMENT ? T_COSE_ERR_UNSUPPORTED_HASH :
           status == PSA_ERROR_BUFFER_TOO_SMALL ? T_COSE_ERR_HASH_BUFFER_SIZE :
                                                  T_COSE_ERR_HASH_GENERAL_FAIL;
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
#endif /* !T_COSE_DISABLE_SIGN1 */



#ifndef T_COSE_DISABLE_MAC0
/**
 * \brief Convert COSE algorithm ID to a PSA HMAC algorithm ID
 *
 * \param[in] cose_hmac_alg_id   The COSE-based ID for the
 *
 * \return PSA-based MAC algorithm ID, or a vendor flag in the case of error.
 *
 */
static inline psa_algorithm_t cose_hmac_alg_id_to_psa(int32_t cose_hmac_alg_id)
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
    /* Intentionally limited to just this minimum set of errors to
     * save object code as hashes don't really fail much
     */
    return status == PSA_SUCCESS                   ? T_COSE_SUCCESS :
           status == PSA_ERROR_NOT_SUPPORTED       ? T_COSE_ERR_UNSUPPORTED_HASH :
           status == PSA_ERROR_INVALID_ARGUMENT    ? T_COSE_ERR_INVALID_ARGUMENT :
           status == PSA_ERROR_INSUFFICIENT_MEMORY ? T_COSE_ERR_INSUFFICIENT_MEMORY :
           status == PSA_ERROR_BUFFER_TOO_SMALL    ? T_COSE_ERR_TOO_SMALL :
           status == PSA_ERROR_INVALID_SIGNATURE   ? T_COSE_ERR_SIG_VERIFY :
                                                     T_COSE_ERR_FAIL;
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
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    /*
     * Verify if HMAC algorithm is valid.
     * According to COSE (RFC 9053), only SHA-256, SHA-384 and SHA-512 are
     * supported in COSE_Mac0 with HMAC.
     */
    if((psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_256)) &&
       (psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_384)) &&
       (psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_512))) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    hmac_ctx->op_ctx = psa_mac_operation_init();

    psa_ret = psa_mac_sign_setup(&hmac_ctx->op_ctx,
                                  (psa_key_id_t)signing_key.k.key_handle,
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
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    /*
     * Verify if HMAC algorithm is valid.
     * According to COSE (RFC 9053), only SHA-256, SHA-384 and SHA-512 are
     * supported in HMAC.
     */
    if((psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_256)) &&
       (psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_384)) &&
       (psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_512))) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    hmac_ctx->op_ctx = psa_mac_operation_init();

    psa_ret = psa_mac_verify_setup(&hmac_ctx->op_ctx,
                                   (psa_key_id_t)validation_key.k.key_handle,
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

#endif /* !T_COSE_DISABLE_MAC0 */


#ifndef T_COSE_DISABLE_EDDSA
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

    /* MbedTLS does not support EdDSA */
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}
#endif /* ! T_COSE_DISABLE_EDDSA */


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_generate_key(struct t_cose_key    *ephemeral_key,
                           int32_t               cose_algorithm_id)
{
    psa_key_attributes_t skE_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t     skE_handle = 0;
    psa_key_type_t       type;
    size_t               key_bitlen;
    psa_status_t         status;

   switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM:
        key_bitlen = 256;
        type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        break;
    case T_COSE_ALGORITHM_HPKE_P521_HKDF512_AES256_GCM:
        key_bitlen = 521;
        type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        break;
    default:
        return(T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG);
    }

    /* generate ephemeral key pair: skE, pkE */
    psa_set_key_usage_flags(&skE_attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&skE_attributes, PSA_ALG_ECDH);
    psa_set_key_type(&skE_attributes, type);
    psa_set_key_bits(&skE_attributes, key_bitlen);

    status = psa_generate_key(&skE_attributes, &skE_handle);

    if (status != PSA_SUCCESS) {
        return(T_COSE_ERR_KEY_GENERATION_FAILED);
    }

    ephemeral_key->k.key_handle = skE_handle;
    ephemeral_key->crypto_lib = T_COSE_CRYPTO_LIB_PSA;

    return(T_COSE_SUCCESS);
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


#ifndef T_COSE_DISABLE_AES_KW
/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_aes_kw(int32_t                 algorithm_id,
                     struct q_useful_buf_c   kek,
                     struct q_useful_buf_c   plaintext,
                     struct q_useful_buf     ciphertext_buffer,
                     struct q_useful_buf_c  *ciphertext_result)
{
    /* Mbed TLS AES-KW Variables */
    mbedtls_nist_kw_context ctx;
    int                     ret;
    size_t                  res_len;

    // TODO: this needs to check the algorithm ID
    (void)algorithm_id;

    mbedtls_nist_kw_init(&ctx);

    /* Configure KEK to be externally supplied symmetric key */
    ret = mbedtls_nist_kw_setkey(&ctx,                 // Key wrapping context
                                 MBEDTLS_CIPHER_ID_AES, // Block cipher
                                 kek.ptr,           // Key Encryption Key (KEK)
                                 (unsigned int)
                                    kek.len * 8,    // KEK size in bits
                                 MBEDTLS_ENCRYPT    // Operation within the context
                                );

    if (ret != 0) {
        return(T_COSE_ERR_AES_KW_FAILED);
    }

    /* Encrypt CEK with the AES key wrap algorithm defined in RFC 3394. */
    ret = mbedtls_nist_kw_wrap(&ctx,
                               MBEDTLS_KW_MODE_KW,
                               plaintext.ptr,
                               plaintext.len,
                               ciphertext_buffer.ptr,
                               &res_len,
                               ciphertext_buffer.len
                              );

    if (ret != 0) {
        return(T_COSE_ERR_AES_KW_FAILED);
    }

    ciphertext_result->ptr = ciphertext_buffer.ptr;
    ciphertext_result->len = res_len;

    mbedtls_nist_kw_free(&ctx);

    return(T_COSE_SUCCESS);
}
#endif

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_export_key(struct t_cose_key      key,
                         struct q_useful_buf    key_buffer,
                         size_t                *key_len)
{
    psa_status_t      status;

    status = psa_export_key( (mbedtls_svc_key_id_t)
                                key.k.key_handle,
                             (uint8_t *) key_buffer.ptr,
                             (size_t) key_buffer.len,
                             key_len);

    if (status != PSA_SUCCESS) {
        return(T_COSE_ERR_KEY_EXPORT_FAILED);
    }

    return(T_COSE_SUCCESS);
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_export_public_key(struct t_cose_key      key,
                                struct q_useful_buf    pk_buffer,
                                size_t                *pk_len)
{
    psa_status_t      status;

    /* Export public key */
    status = psa_export_public_key( (mbedtls_svc_key_id_t)
                                       key.k.key_handle,  /* Key handle */
                                    pk_buffer.ptr,        /* PK buffer */
                                    pk_buffer.len,        /* PK buffer size */
                                    pk_len);              /* Result length */

    if (status != PSA_SUCCESS) {
        return(T_COSE_ERR_PUBLIC_KEY_EXPORT_FAILED);
    }

    return(T_COSE_SUCCESS);
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_make_symmetric_key_handle(int32_t               cose_algorithm_id,
                                        struct q_useful_buf_c symmetric_key,
                                        struct t_cose_key    *key_handle)
{
    psa_algorithm_t        psa_algorithm;
    psa_key_handle_t       psa_key_handle;
    psa_status_t           status;
    psa_key_attributes_t   attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t                 key_bitlen;
    psa_key_type_t         psa_keytype;

    /* TODO: remove this and put it somewhere common. (It's OK to call twice,
     * so having it here doesn't cause a problem in the short term */
    psa_crypto_init();


    switch (cose_algorithm_id) {
        case T_COSE_ALGORITHM_A128GCM:
            psa_algorithm = PSA_ALG_GCM;
            psa_keytype = PSA_KEY_TYPE_AES;
            key_bitlen = 128;
            break;

        case T_COSE_ALGORITHM_A192GCM:
            psa_algorithm = PSA_ALG_GCM;
            psa_keytype = PSA_KEY_TYPE_AES;
            key_bitlen = 192;
            break;

        case T_COSE_ALGORITHM_A256GCM:
            psa_algorithm = PSA_ALG_GCM;
            psa_keytype = PSA_KEY_TYPE_AES;
            key_bitlen = 256;
            break;

        default:
            return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }

    /* t_cose doesn't make use of PSA's ability to check key usage. It
     * just sets all possible usages needed for t_cose here. While
     * this loses some guards, these are only guards against the
     * programmer doing something wrong, not against bad input. This
     * particular function is also used primarily for only the CEK in
     * t_cose. That means the programmer is the t_cose developer, not
     * the t_cose user. Very little is lost and the object code is
     * smaller.
     *
     * Note that all the key handles the user of t_cose passes into
     * t_cose from the public interface (not the ones set up here)
     * need to have key usage set right. These key handles pass
     * through t_cose and the crypto adapter, so if the crypto lib
     * enforces key usage like PSA does, they will be in effect.
     */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, psa_algorithm);
    psa_set_key_type(&attributes, psa_keytype);
    psa_set_key_bits(&attributes, key_bitlen);

    status = psa_import_key(&attributes,
                             symmetric_key.ptr,
                             symmetric_key.len,
                            &psa_key_handle);

    if (status != PSA_SUCCESS) {
        return T_COSE_ERR_KEY_IMPORT_FAILED;
    }

    key_handle->k.key_handle = psa_key_handle;
    key_handle->crypto_lib   = T_COSE_CRYPTO_LIB_PSA;

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
        default:
            return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }

    if(ciphertext_buffer.ptr == NULL) {
        /* Called in length calculation mode. Return length & exit. */
        ciphertext->len = aead_byte_count(cose_algorithm_id,
                                          plaintext.len);;
        return T_COSE_SUCCESS;
    }

    if(key.crypto_lib != T_COSE_CRYPTO_LIB_PSA) {
        return T_COSE_ERR_INCORRECT_KEY_FOR_LIB;
    }

    status = psa_aead_encrypt((psa_key_handle_t)key.k.key_handle,
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

    if(key.crypto_lib != T_COSE_CRYPTO_LIB_PSA) {
        return T_COSE_ERR_INCORRECT_KEY_FOR_LIB;
    }

    status = psa_aead_decrypt((psa_key_handle_t)key.k.key_handle,
                              psa_algorithm_id,
                              nonce.ptr, nonce.len,
                              aad.ptr, aad.len,
                              ciphertext.ptr, ciphertext.len,
                              plaintext_buffer.ptr, plaintext_buffer.len,
                             &plaintext->len);
    plaintext->ptr = plaintext_buffer.ptr;

    return aead_psa_status_to_t_cose_err(status, T_COSE_ERR_DECRYPT_FAIL);
}
