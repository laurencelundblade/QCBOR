/*
 *  t_cose_openssl_crypto.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created 3/31/2019.
 */


#include "t_cose_crypto.h" /* The interface this code implements */

#include <openssl/ecdsa.h>
#include <openssl/err.h>

#include <openssl/sha.h>


/**
 * \file t_cose_openssl_crypto.c
 *
 * \brief Crypto Adaptation for t_cose to use openssl ECDSA and hashes.
 *
 * This connects up the abstracted crypto services defined in
 * t_cose_crypto.h to the OpenSSL implementation of them.
 *
 * This adapter layer doesn't bloat the implementation as everything here
 * had to be done anyway -- the mapping of algorithm IDs, the data format
 * rearranging, the error code translation.
 *
 * This code should just work out of the box if compiled and linked
 * against OpenSSL and with the T_COSE_USE_OPENSSL_CRYPTO preprocessor
 * define set for the build.
 *
 * You can disable SHA-384 and SHA-512 to save code and space by
 * defining T_COSE_DISABLE_ES384 or T_COSE_DISABLE_ES512. This saving
 * is most in stack space in the main t_cose implementation. (It seems
 * likely that changes to OpenSSL itself would be needed to remove
 * the SHA-384 and SHA-512 implementations to save that code).
 */



/**
 * \brief Convert OpenSSL ECDSA_SIG to serialized on-the-wire format
 *
 * \param[in] key_len             Size of the key in bytes -- governs sig size.
 * \param[in] ossl_signature      The OpenSSL signature to convert.
 * \param[in] signature_buffer    The buffer for output.
 *
 * \return The pointer and length of serialized signature in \c signature_buffer
           or NULL_Q_USEFUL_BUF_C on error.
 *
 * The serialized format is defined by COSE in RFC 8152 section
 * 8.1. The signature which consist of two integers, r and s,
 * are simply zero padded to the nearest byte length and
 * concatenated.
 *
 * This doesn't check inputs for NULL in ossl_signature or its
 * internals are NULL.
 */
static inline struct q_useful_buf_c
convert_ecdsa_signature_from_ossl(unsigned            key_len,
                                  const ECDSA_SIG    *ossl_signature,
                                  struct q_useful_buf signature_buffer)
{
    size_t                r_len;
    size_t                s_len;
    const BIGNUM         *ossl_signature_r_bn;
    const BIGNUM         *ossl_signature_s_bn;
    struct q_useful_buf_c signature;
    void                 *r_start_ptr;
    void                 *s_start_ptr;

    /* Zero the buffer so that bytes r and s are padded with zeros */
    q_useful_buf_set(signature_buffer, 0);

    /* Get the signature r and s as BIGNUMs */
    ossl_signature_r_bn = NULL;
    ossl_signature_s_bn = NULL;
    ECDSA_SIG_get0(ossl_signature, &ossl_signature_r_bn, &ossl_signature_s_bn);
    /* ECDSA_SIG_get0 returns void */

    /* Internal consistency check that the r and s values will fit
     * into the expected size. Be sure the output buffer is not
     * overrun.
     */
    /* Cast is safe because BN_num_bytes() is documented to not return
     * negative numbers.
     */
    r_len = (size_t)BN_num_bytes(ossl_signature_r_bn);
    s_len = (size_t)BN_num_bytes(ossl_signature_s_bn);
    if(r_len + s_len > signature_buffer.len) {
        signature = NULL_Q_USEFUL_BUF_C;
        goto Done;
    }

    /* Copy r and s of signature to output buffer and set length */
    r_start_ptr = (uint8_t *)(signature_buffer.ptr) + key_len - r_len;
    BN_bn2bin(ossl_signature_r_bn, r_start_ptr);

    s_start_ptr = (uint8_t *)signature_buffer.ptr + 2 * key_len - s_len;
    BN_bn2bin(ossl_signature_s_bn, s_start_ptr);

    signature = (UsefulBufC){signature_buffer.ptr, 2 * key_len};

Done:
    return signature;
}


/**
 * \brief Convert serialized on-the-wire sig to OpenSSL ECDSA_SIG.
 *
 * \param[in] key_len             Size of the key in bytes -- governs sig size.
 * \param[in] signature           The serialized input signature.
 * \param[out] ossl_sig_to_verify Place to return ECDSA_SIG.
 *
 * \return one of the \ref t_cose_err_t error codes.
 *
 * The serialized format is defined by COSE in RFC 8152 section
 * 8.1. The signature which consist of two integers, r and s,
 * are simply zero padded to the nearest byte length and
 * concatenated.
 */
static enum t_cose_err_t
convert_ecdsa_signature_to_ossl(unsigned               key_len,
                                struct q_useful_buf_c  signature,
                                ECDSA_SIG            **ossl_sig_to_verify)
{
    enum t_cose_err_t return_value;
    BIGNUM           *ossl_signature_r_bn = NULL;
    BIGNUM           *ossl_signature_s_bn = NULL;
    int               ossl_result;

    /* Check the signature length against expected */
    if(signature.len != key_len * 2) {
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    }

    /* Put the r and the s from the signature into big numbers */
    ossl_signature_r_bn = BN_bin2bn(signature.ptr, (int)key_len, NULL);
    if(ossl_signature_r_bn == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    ossl_signature_s_bn = BN_bin2bn(((const uint8_t *)signature.ptr)+key_len,
                                    (int)key_len,
                                    NULL);
    if(ossl_signature_s_bn == NULL) {
        BN_free(ossl_signature_r_bn);
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Put the signature bytes into an ECDSA_SIG */
    *ossl_sig_to_verify = ECDSA_SIG_new();
    if(ossl_sig_to_verify == NULL) {
        /* Don't leak memory in error condition */
        BN_free(ossl_signature_r_bn);
        BN_free(ossl_signature_s_bn);
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Put the r and s bignums into an ECDSA_SIG. Freeing
     * ossl_sig_to_verify will now free r and s.
     */
    ossl_result = ECDSA_SIG_set0(*ossl_sig_to_verify,
                                 ossl_signature_r_bn,
                                 ossl_signature_s_bn);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    return_value = T_COSE_SUCCESS;

Done:
    /* The BN's r and s get freed when ossl_sig_to_verify is freed */
    return return_value;
}




/**
 * \brief Common checks and conversions for signing and verification key.
 *
 * \param[in] t_cose_key                 The key to check and convert.
 * \param[out] return_ossl_ec_key        The OpenSSL key in memory.
 * \param[out] return_key_size_in_bytes  How big the key is.
 *
 * \return Error or \ref T_COSE_SUCCESS.
 *
 * It pulls the OpenSSL in-memory key out of \c t_cose_key and checks
 * it and figures out the number of bytes in the key rounded up. This
 * is also the size of r and s in the signature.
 */
static enum t_cose_err_t
ecdsa_key_checks(struct t_cose_key  t_cose_key,
                 EC_KEY           **return_ossl_ec_key,
                 unsigned          *return_key_size_in_bytes)
{
    enum t_cose_err_t  return_value;
    const EC_GROUP    *key_group;
    int                key_len_bits; /* type unsigned is conscious choice */
    unsigned           key_len_bytes; /* type unsigned is conscious choice */
    int                ossl_result; /* type int is conscious choice */
    EC_KEY            *ossl_ec_key;

    /* Check the signing key and get it out of the union */
    if(t_cose_key.crypto_lib != T_COSE_CRYPTO_LIB_OPENSSL) {
        return_value = T_COSE_ERR_INCORRECT_KEY_FOR_LIB;
        goto Done;
    }
    if(t_cose_key.k.key_ptr == NULL) {
        return_value = T_COSE_ERR_EMPTY_KEY;
        goto Done;
    }
    ossl_ec_key = (EC_KEY *)t_cose_key.k.key_ptr;

    /* Check the key to be sure it is OK */
    ossl_result = EC_KEY_check_key(ossl_ec_key);
    if(ossl_result == 0) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Get the key size, which depends on the group */
    key_group = EC_KEY_get0_group(ossl_ec_key);
    if(key_group == NULL) {
        return_value = T_COSE_ERR_WRONG_TYPE_OF_KEY;
        goto Done;
    }
    key_len_bits = EC_GROUP_get_degree(key_group);
    if(key_len_bits <= 0) {
        /* This is not expected to ever happen */
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Convert group size in bits to key size in bytes per RFC 8152
     * section 8.1. This is also the size of r and s in the
     * signature. This is by rounding up to the number of bytes to
     * hold the give number of bits. Cast is safe because of
     * check above.
     */
    key_len_bytes = (unsigned)key_len_bits / 8;
    if(key_len_bits % 8) {
        key_len_bytes++;
    }

    *return_key_size_in_bytes = key_len_bytes;
    *return_ossl_ec_key       = ossl_ec_key;

    return_value = T_COSE_SUCCESS;

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
    enum t_cose_err_t return_value;
    EC_KEY            *ossl_ec_key;
    unsigned           key_size;


    if(!t_cose_algorithm_is_ecdsa(cose_algorithm_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    return_value = ecdsa_key_checks(signing_key,
                                    &ossl_ec_key,
                                    &key_size);

    /* ECDSA signatures for COSE are twice the key size */
    *sig_size = 2*key_size;

Done:
    return return_value;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_pub_key_sign(int32_t                cose_algorithm_id,
                           struct t_cose_key      signing_key,
                           struct q_useful_buf_c  hash_to_sign,
                           struct q_useful_buf    signature_buffer,
                           struct q_useful_buf_c *serialized_signature)
{
    enum t_cose_err_t  return_value;
    EC_KEY            *ossl_ec_key;
    ECDSA_SIG         *ossl_signature;
    unsigned           key_len; /* in bytes; type unsigned is conscious choice */

    ossl_signature = NULL;

    /* This implementation supports ECDSA and only ECDSA. The
     * interface allows it to support other, but none are implemented.
     * This implementation works for different keys lengths and
     * curves. That is, the curve and key length as associated with
     * the \c signing_key passed in, not the \c cose_algorithm_id This
     * check looks for ECDSA signing as indicated by COSE and rejects
     * what is not since it only supports ECDSA.
     *
     * If RSA or such is to be added, it would be added here and
     * switch based on the cose_algorithm_id would select it.
     */
    if(!t_cose_algorithm_is_ecdsa(cose_algorithm_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    /* Check out a few things that are common between signing and
     * verification */
    return_value = ecdsa_key_checks(signing_key,
                                   &ossl_ec_key,
                                   &key_len);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* Actually do the EC signature over the hash */
    ossl_signature = ECDSA_do_sign(hash_to_sign.ptr,
                                   (int)hash_to_sign.len,
                                   ossl_ec_key);
    if(ossl_signature == NULL) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Convert signature from OSSL format to the serialized format in
     * a q_useful_buf. Presumably everything inside ossl_signature is
     * correct since it is not NULL.
     */
    *serialized_signature =
        convert_ecdsa_signature_from_ossl(key_len,
                                          ossl_signature,
                                          signature_buffer);
    if(q_useful_buf_c_is_null(*serialized_signature)) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Everything succeeded */
    return_value = T_COSE_SUCCESS;

Done:
    /* This (is assumed to) checks for NULL before free, so it is not
     * necessary to check for NULL here.
     */
    ECDSA_SIG_free(ossl_signature);

    return return_value;
}



/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_pub_key_verify(int32_t                cose_algorithm_id,
                             struct t_cose_key      verification_key,
                             struct q_useful_buf_c  kid,
                             struct q_useful_buf_c  hash_to_verify,
                             struct q_useful_buf_c  serialized_sig_to_verify)
{
    int               ossl_result;
    enum t_cose_err_t return_value;
    EC_KEY           *ossl_pub_key;
    ECDSA_SIG        *ossl_sig_to_verify;
    unsigned          key_len; /* in bytes; type unsigned is conscious choice */

    /* This implementation doesn't use any key store with the ability
     * to look up a key based on kid. */
    (void)kid;

    ossl_sig_to_verify = NULL;

    if(!t_cose_algorithm_is_ecdsa(cose_algorithm_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    /* Check out a few things that are common between signing and verification*/
    return_value = ecdsa_key_checks(verification_key,
                                   &ossl_pub_key,
                                   &key_len);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* Convert the serialized signature off the wire into the openssl
     * object / structure
     */
    return_value =
       convert_ecdsa_signature_to_ossl(key_len,
                                       serialized_sig_to_verify,
                                       &ossl_sig_to_verify);
    if(return_value) {
        goto Done;
    }

    /* Actually do the signature verification */
    ossl_result = ECDSA_do_verify(hash_to_verify.ptr,
                                  (int)hash_to_verify.len,
                                  ossl_sig_to_verify,
                                  ossl_pub_key);
    if(ossl_result == 0) {
        /* The operation succeeded, but the signature doesn't match */
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    } else if (ossl_result != 1) {
        /* Failed before even trying to verify the signature */
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Everything succeeded */
    return_value = T_COSE_SUCCESS;

Done:
    /* These (are assumed to) all check for NULL before they free, so
     * it is not necessary to check here */
    ECDSA_SIG_free(ossl_sig_to_verify);

    return return_value;
}




/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                                           int32_t cose_hash_alg_id)
{
    int ossl_result;

    switch(cose_hash_alg_id) {

    case COSE_ALGORITHM_SHA_256:
        ossl_result = SHA256_Init(&hash_ctx->ctx.sha_256);
        break;

#ifndef T_COSE_DISABLE_ES384
    case COSE_ALGORITHM_SHA_384:
        ossl_result = SHA384_Init(&hash_ctx->ctx.sha_512);
        break;
#endif

#ifndef T_COSE_DISABLE_ES512
    case COSE_ALGORITHM_SHA_512:
        ossl_result = SHA512_Init(&hash_ctx->ctx.sha_512);
        break;
#endif

    default:
        return T_COSE_ERR_UNSUPPORTED_HASH;

    }
    hash_ctx->cose_hash_alg_id = cose_hash_alg_id;
    hash_ctx->update_error = 1; /* 1 is success in OpenSSL */

    /* OpenSSL returns 1 for success, not 0 */
    return ossl_result ? T_COSE_SUCCESS : T_COSE_ERR_HASH_GENERAL_FAIL;
}


/*
 * See documentation in t_cose_crypto.h
 */
void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c data_to_hash)
{
    if(hash_ctx->update_error) { /* 1 is no error, 0 means error for OpenSSL */
        if(data_to_hash.ptr) {
            switch(hash_ctx->cose_hash_alg_id) {

            case COSE_ALGORITHM_SHA_256:
                hash_ctx->update_error = SHA256_Update(&hash_ctx->ctx.sha_256,
                                                       data_to_hash.ptr,
                                                       data_to_hash.len);
                break;

#ifndef T_COSE_DISABLE_ES384
            case COSE_ALGORITHM_SHA_384:
                hash_ctx->update_error = SHA384_Update(&hash_ctx->ctx.sha_512,
                                                       data_to_hash.ptr,
                                                       data_to_hash.len);
                break;
#endif

#ifndef T_COSE_DISABLE_ES512
            case COSE_ALGORITHM_SHA_512:
                hash_ctx->update_error = SHA512_Update(&hash_ctx->ctx.sha_512,
                                                       data_to_hash.ptr,
                                                       data_to_hash.len);
                break;
#endif
            }
        }
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
    size_t hash_result_len = 0;

    int ossl_result = 0; /* Assume failure; 0 == failure for OpenSSL */

    if(!hash_ctx->update_error) {
        return T_COSE_ERR_HASH_GENERAL_FAIL;
    }

    switch(hash_ctx->cose_hash_alg_id) {

    case COSE_ALGORITHM_SHA_256:
        ossl_result = SHA256_Final(buffer_to_hold_result.ptr,
                                   &hash_ctx->ctx.sha_256);
        hash_result_len = T_COSE_CRYPTO_SHA256_SIZE;
        break;

#ifndef T_COSE_DISABLE_ES384
    case COSE_ALGORITHM_SHA_384:
        ossl_result = SHA384_Final(buffer_to_hold_result.ptr,
                                   &hash_ctx->ctx.sha_512);
        hash_result_len = T_COSE_CRYPTO_SHA384_SIZE;
        break;
#endif

#ifndef T_COSE_DISABLE_ES512
    case COSE_ALGORITHM_SHA_512:
        ossl_result = SHA512_Final(buffer_to_hold_result.ptr,
                                   &hash_ctx->ctx.sha_512);
        hash_result_len = T_COSE_CRYPTO_SHA512_SIZE;
        break;
#endif
    }

    *hash_result = (UsefulBufC){buffer_to_hold_result.ptr, hash_result_len};

    /* OpenSSL returns 1 for success, not 0 */
    return ossl_result ? T_COSE_SUCCESS : T_COSE_ERR_HASH_GENERAL_FAIL;
}

