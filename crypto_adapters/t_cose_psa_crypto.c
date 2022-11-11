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
        T_COSE_ALGORITHM_SHA_384,
        T_COSE_ALGORITHM_SHA_512,
        T_COSE_ALGORITHM_ES256,
#ifndef T_COSE_DISABLE_ES384 /* The t_cose 1.0 macro. TODO: keep this? */
        T_COSE_ALGORITHM_ES384,
#endif /* T_COSE_DISABLE_ES384 */
#ifndef T_COSE_DISABLE_ES512
        T_COSE_ALGORITHM_ES512, /* The t_cose 1.0 macro. TODO: keep this? */
#endif /* T_COSE_DISABLE_ES512 */
        T_COSE_ALGORITHM_NONE /* List terminator */
    };

    for(const int32_t *i = supported_algs; *i != T_COSE_ALGORITHM_NONE; i++) {
        if(*i == cose_algorithm_id) {
            return true;
        }
    }
    return false;
}



/* Avoid compiler warning due to unused argument */
#define ARG_UNUSED(arg) (void)(arg)

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
                                                 0;
    /* psa/crypto_values.h doesn't seem to define a "no alg" value,
     * but zero seems OK for that use in the ECDSA context. */
}


/**
 * \brief Map a PSA error into a t_cose error for signing.
 *
 * \param[in] err   The PSA status.
 *
 * \return The \ref t_cose_err_t.
 */
static enum t_cose_err_t psa_status_to_t_cose_error_signing(psa_status_t err)
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
                     struct q_useful_buf_c hash_to_verify,
                     struct q_useful_buf_c signature)
{
    psa_algorithm_t       psa_alg_id;
    psa_status_t          psa_result;
    enum t_cose_err_t     return_value;
    psa_key_handle_t  verification_key_psa;

    /* This implementation does no look up keys by kid in the key
     * store */
    ARG_UNUSED(kid);

    /* Convert to PSA algorithm ID scheme */
    psa_alg_id = cose_alg_id_to_psa_alg_id(cose_algorithm_id);

    /* This implementation supports ECDSA and only ECDSA. The
     * interface allows it to support other, but none are implemented.
     * This implementation works for different keys lengths and
     * curves. That is the curve and key length as associated with the
     * signing_key passed in, not the cose_algorithm_id This check
     * looks for ECDSA signing as indicated by COSE and rejects what
     * is not. (Perhaps this check can be removed to save object code
     * if it is the case that psa_verify_hash() does the right
     * checks).
     */
    if(!PSA_ALG_IS_ECDSA(psa_alg_id)) {
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
                   struct q_useful_buf_c  hash_to_sign,
                   struct q_useful_buf    signature_buffer,
                   struct q_useful_buf_c *signature)
{
    enum t_cose_err_t     return_value;
    psa_status_t          psa_result;
    psa_algorithm_t       psa_alg_id;
    psa_key_handle_t      signing_key_psa;
    size_t                signature_len;

    psa_alg_id = cose_alg_id_to_psa_alg_id(cose_algorithm_id);

    /* This implementation supports ECDSA and only ECDSA. The
     * interface allows it to support other, but none are implemented.
     * This implementation works for different keys lengths and
     * curves. That is the curve and key length as associated with the
     * signing_key passed in, not the cose_algorithm_id This check
     * looks for ECDSA signing as indicated by COSE and rejects what
     * is not. (Perhaps this check can be removed to save object code
     * if it is the case that psa_verify_hash() does the right
     * checks).
     */
    if(!PSA_ALG_IS_ECDSA(psa_alg_id)) {
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
    psa_key_handle_t      signing_key_psa;
    size_t                key_len_bits;
    size_t                key_len_bytes;
    psa_key_attributes_t  key_attributes;
    psa_status_t          status;

    /* If desperate to save code, this can return the constant
     * T_COSE_MAX_SIG_SIZE instead of doing an exact calculation.  The
     * buffer size calculation will return too large of a value and
     * waste a little heap / stack, but everything will still work
     * (except the tests that test for exact values will fail). This
     * will save 100 bytes or so of object code.
     */

    if(!t_cose_algorithm_is_ecdsa(cose_algorithm_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    signing_key_psa = (psa_key_handle_t)signing_key.k.key_handle;
    key_attributes = psa_key_attributes_init();
    status = psa_get_key_attributes(signing_key_psa, &key_attributes);
    key_len_bits = psa_get_key_bits(&key_attributes);


    return_value = psa_status_to_t_cose_error_signing(status);
    if(return_value == T_COSE_SUCCESS) {
        /* Calculation of size per RFC 8152 section 8.1 -- round up to
         * number of bytes. */
        key_len_bytes = key_len_bits / 8;
        if(key_len_bits % 8) {
            key_len_bytes++;
        }
        /* Double because signature is made of up r and s values */
        *sig_size = key_len_bytes * 2;
    }

    return_value = T_COSE_SUCCESS;
Done:
    return return_value;
}
#endif /* !T_COSE_DISABLE_SIGN1 */


#if !defined(T_COSE_DISABLE_SHORT_CIRCUIT_SIGN) || \
    !defined(T_COSE_DISABLE_SIGN1)
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
#ifndef T_COSE_DISABLE_ES384
           cose_hash_alg_id == T_COSE_ALGORITHM_SHA_384 ? PSA_ALG_SHA_384 :
#endif
#ifndef T_COSE_DISABLE_ES512
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
#endif /* !T_COSE_DISABLE_SHORT_CIRCUIT_SIGN || !T_COSE_DISABLE_SIGN1 */

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
t_cose_crypto_hmac_sign_setup(struct t_cose_crypto_hmac *hmac_ctx,
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
     * According to COSE (RFC 8152), only SHA-256, SHA-384 and SHA-512 are
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
t_cose_crypto_hmac_sign_finish(struct t_cose_crypto_hmac *hmac_ctx,
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
t_cose_crypto_hmac_verify_setup(struct t_cose_crypto_hmac *hmac_ctx,
                                const  int32_t             cose_alg_id,
                                struct t_cose_key          verify_key)
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
     * According to COSE (RFC 8152), only SHA-256, SHA-384 and SHA-512 are
     * supported in HMAC.
     */
    if((psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_256)) &&
       (psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_384)) &&
       (psa_alg != PSA_ALG_HMAC(PSA_ALG_SHA_512))) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    hmac_ctx->op_ctx = psa_mac_operation_init();

    psa_ret = psa_mac_verify_setup(&hmac_ctx->op_ctx,
                                    (psa_key_id_t)verify_key.k.key_handle,
                                    psa_alg);

    return psa_status_to_t_cose_error_hmac(psa_ret);
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hmac_verify_finish(struct t_cose_crypto_hmac *hmac_ctx,
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
    ret = mbedtls_nist_kw_setkey(&ctx,                    // Key wrapping context
                                 MBEDTLS_CIPHER_ID_AES,   // Block cipher
                                 kek.ptr,                 // Key Encryption Key (KEK)
                                 (unsigned int)
                                    kek.len * 8,          // KEK size in bits
                                 MBEDTLS_ENCRYPT          // Operation within the context
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
t_cose_crypto_encrypt(int32_t                cose_algorithm_id,
                      struct q_useful_buf_c  key,
                      struct q_useful_buf_c  nonce,
                      struct q_useful_buf_c  add_data,
                      struct q_useful_buf_c  plaintext,
                      struct q_useful_buf    ciphertext_buffer,
                      size_t                 *ciphertext_output_len)
{
    psa_status_t           status;
    psa_algorithm_t        psa_algorithm;
    psa_key_type_t         psa_keytype;
    size_t                 key_bitlen;
    psa_key_handle_t       cek_handle = 0;
    psa_key_attributes_t   attributes = PSA_KEY_ATTRIBUTES_INIT;

    /* Set encryption algorithm information */
    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_A128GCM:
        psa_algorithm = PSA_ALG_GCM;
        psa_keytype = PSA_KEY_TYPE_AES;
        key_bitlen = 128;
        break;

    case T_COSE_ALGORITHM_A256GCM:
        psa_algorithm = PSA_ALG_GCM;
        psa_keytype = PSA_KEY_TYPE_AES;
        key_bitlen = 256;
        break;

    default:
        return(T_COSE_ERR_UNSUPPORTED_CIPHER_ALG);
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, psa_algorithm);
    psa_set_key_type(&attributes, psa_keytype);
    psa_set_key_bits(&attributes, key_bitlen);

    status = psa_import_key(&attributes,
                            key.ptr,
                            key.len,
                            &cek_handle);

    if (status != PSA_SUCCESS) {
        return(T_COSE_ERR_KEY_IMPORT_FAILED);
    }

    status = psa_aead_encrypt(
              cek_handle,                     // key
              psa_algorithm,                  // algorithm
              nonce.ptr, nonce.len,           // nonce
              (const uint8_t *)
                add_data.ptr,                 // additional data
              add_data.len,                   // additional data length
              plaintext.ptr, plaintext.len,   // plaintext
              ciphertext_buffer.ptr,          // ciphertext
              ciphertext_buffer.len,          // ciphertext length
              ciphertext_output_len );        // length of output


    if (status != PSA_SUCCESS) {
        return(T_COSE_ERR_ENCRYPT_FAIL);
    }

    return(T_COSE_SUCCESS);
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_get_cose_key(int32_t              cose_algorithm_id,
                           uint8_t              *cek,
                           size_t               cek_len,
                           uint8_t              flags,
                           struct t_cose_key    *key)
{
    psa_key_attributes_t   attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t           status;
    psa_algorithm_t        psa_algorithm;
    psa_key_type_t         psa_keytype;
    size_t                 key_bitlen;
    psa_key_usage_t        usage_flags = T_COSE_KEY_USAGE_FLAG_NONE;

    if (flags == T_COSE_KEY_USAGE_FLAG_DECRYPT) {
        usage_flags = PSA_KEY_USAGE_DECRYPT;
    } else if (flags == T_COSE_KEY_USAGE_FLAG_ENCRYPT) {
        usage_flags = PSA_KEY_USAGE_ENCRYPT;
    } else {
        return(T_COSE_ERR_UNSUPPORTED_KEY_USAGE_FLAGS);
    }

    /* Set algorithm information */
    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_A128GCM:
        key_bitlen = 128;
        psa_algorithm = PSA_ALG_GCM;
        psa_keytype = PSA_KEY_TYPE_AES;
        break;

    case T_COSE_ALGORITHM_A256GCM:
        key_bitlen = 256;
        psa_algorithm = PSA_ALG_GCM;
        psa_keytype = PSA_KEY_TYPE_AES;
        break;

    default:
        return(T_COSE_ERR_UNSUPPORTED_CIPHER_ALG);
    }

    psa_set_key_usage_flags(&attributes, usage_flags);
    psa_set_key_algorithm(&attributes, psa_algorithm);
    psa_set_key_type(&attributes, psa_keytype);
    psa_set_key_bits(&attributes, key_bitlen);

    status = psa_import_key(&attributes,
                            cek,
                            cek_len,
                            (mbedtls_svc_key_id_t *) &key->k.key_handle);

    if (status != PSA_SUCCESS) {
        return(T_COSE_ERR_UNKNOWN_KEY);
    }

    key->crypto_lib = T_COSE_CRYPTO_LIB_PSA;

    return(T_COSE_SUCCESS);
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_decrypt(int32_t                cose_algorithm_id,
                      struct t_cose_key      key,
                      struct q_useful_buf_c  nonce,
                      struct q_useful_buf_c  add_data,
                      struct q_useful_buf_c  ciphertext,
                      struct q_useful_buf    plaintext_buffer,
                      size_t *plaintext_output_len)
{
    psa_status_t           status;
    psa_algorithm_t        psa_algorithm;

    /* Set decryption algorithm information */
    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_A128GCM:
        psa_algorithm = PSA_ALG_GCM;
        break;

    case T_COSE_ALGORITHM_A256GCM:
        psa_algorithm = PSA_ALG_GCM;
        break;

    default:
        return(T_COSE_ERR_UNSUPPORTED_CIPHER_ALG);
    }

    status = psa_aead_decrypt( (mbedtls_svc_key_id_t)
                                key.k.key_handle,               // key handle
                                psa_algorithm,                  // algorithm
                                nonce.ptr, nonce.len,           // nonce
                                (const uint8_t *)
                                add_data.ptr,                   // additional data
                                add_data.len,                   // additional data length
                                ciphertext.ptr, ciphertext.len, // ciphertext
                                plaintext_buffer.ptr,           // plaintext
                                plaintext_buffer.len,           // plaintext length
                                plaintext_output_len );         // length of output

    if (status != PSA_SUCCESS) {
        return(T_COSE_ERR_DECRYPT_FAIL);
    }

    return(T_COSE_SUCCESS);
}
