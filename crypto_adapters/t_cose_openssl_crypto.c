/*
 *  t_cose_openssl_crypto.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created 3/31/2019.
 */


#include "t_cose_standard_constants.h"
#include "t_cose_crypto.h"

#include "openssl/ecdsa.h"
#include "openssl/err.h"

#include "openssl/sha.h"


/**
 * \file t_cose_openssl_crypto.c
 *
 * \brief Crypto Adaptation for t_cose to use openssl ECDSA and hashes.
 */




/**
 * \brief Convert OpenSSL ECDSA_SIG to serialized on-the-wire format
 *
 * \param[in] cose_algorithm_id Signing algorithm identifier
 * \param[in] ossl_signature    The OpenSSL signature to convert
 * \param[in] signature_buffer  The buffer to put the output into
 *
 * \return The serialized signature or NULL_Q_USEFUL_BUF_C on error.
 *
 * This doesn't check inputs for NULL in ossl_signature or it's
 * internals are NULL.
 */
static inline struct q_useful_buf_c
convert_signature_from_ossl(int32_t             cose_algorithm_id,
                            const ECDSA_SIG    *ossl_signature,
                            struct q_useful_buf signature_buffer)
{
    size_t                r_len;
    size_t                s_len;
    const BIGNUM         *ossl_signature_r_bn;
    const BIGNUM         *ossl_signature_s_bn;
    size_t                sig_len;
    struct q_useful_buf_c signature;;

    /* Check the signature size and against the buffer size */
    sig_len = t_cose_signature_size(cose_algorithm_id);
    if(sig_len == 0) {
        /* Unknown algorithm */
        signature = NULL_Q_USEFUL_BUF_C;
        goto Done;
    }
    if(sig_len > signature_buffer.len) {
        /* Buffer given for signature is too small */
        signature = NULL_Q_USEFUL_BUF_C;
        goto Done;
    }

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
    void *r_start_ptr = (uint8_t *)signature_buffer.ptr + (sig_len / 2) - r_len;
    BN_bn2bin(ossl_signature_r_bn, r_start_ptr);

    void *s_start_ptr = (uint8_t *)signature_buffer.ptr + sig_len - s_len;
    BN_bn2bin(ossl_signature_s_bn, s_start_ptr);

    signature = (UsefulBufC){signature_buffer.ptr, sig_len};

Done:
    return signature;
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
    enum t_cose_err_t  return_value;
    EC_KEY            *ossl_ec_key;
    ECDSA_SIG         *ossl_signature = NULL;

    /* Check the algorithm identifier */
    if(cose_algorithm_id != COSE_ALGORITHM_ES256 &&
       cose_algorithm_id != COSE_ALGORITHM_ES384 &&
       cose_algorithm_id != COSE_ALGORITHM_ES512) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    /* Check the signing key and get it out of the union */
    if(signing_key.crypto_lib != T_COSE_CRYPTO_LIB_OPENSSL) {
        return_value = T_COSE_ERR_INCORRECT_KEY_FOR_LIB;
        goto Done;
    }
    if(signing_key.k.key_ptr == NULL) {
        return_value = T_COSE_ERR_EMPTY_KEY;
        goto Done;
    }
    ossl_ec_key = (EC_KEY *)signing_key.k.key_ptr;
    
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
    *signature = convert_signature_from_ossl(cose_algorithm_id,
                                             ossl_signature,
                                             signature_buffer);
    if(q_useful_buf_c_is_null(*signature)) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Everything succeeded */
    return_value = T_COSE_SUCCESS;
    
Done:
    /* These (are assumed to) all check for NULL before they free, so
     * it is not necessary to check for NULL here.
     */
    ECDSA_SIG_free(ossl_signature);
    
    return return_value;
}


/**
 * \brief Convert serialized on-the-wire sig to OpenSSL ECDSA_SIG.
 *
 * \param[in] cose_algorithm_id         Signing algorithm identifier.
 * \param[in] signature           The serialized input signature.
 * \param[out] ossl_sig_to_verify Place to return ECDSA_SIG.
 *
 * \return one of the \ref t_cose_err_t error codes.
 */
static  enum t_cose_err_t
convert_signature_to_ossl(int32_t                cose_algorithm_id,
                          struct q_useful_buf_c  signature,
                          ECDSA_SIG            **ossl_sig_to_verify)
{
    enum t_cose_err_t return_value;
    BIGNUM           *ossl_signature_r_bn = NULL;
    BIGNUM           *ossl_signature_s_bn = NULL;
    int               ossl_result;
    size_t            sig_size;
    int               half_sig_size;

    /* Check the signature length against expected */
    sig_size = t_cose_signature_size(cose_algorithm_id);
    if(sig_size == 0) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }
    if(signature.len != sig_size) {
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    }

    /* Cast to int is safe because of check against return from
     * t_cose_signature_size()
     */
    half_sig_size = (int)sig_size/2;

    /* Put the r and the s from the signature into big numbers */
    ossl_signature_r_bn = BN_bin2bn(signature.ptr, half_sig_size, NULL);
    if(ossl_signature_r_bn == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    ossl_signature_s_bn = BN_bin2bn(((uint8_t *)signature.ptr)+half_sig_size,
                                    half_sig_size,
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


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_pub_key_verify(int32_t                cose_algorithm_id,
                             struct t_cose_key      verification_key,
                             struct q_useful_buf_c  kid,
                             struct q_useful_buf_c  hash_to_verify,
                             struct q_useful_buf_c  signature)
{
    int               ossl_result;
    enum t_cose_err_t return_value;
    EC_KEY           *ossl_pub_key;
    ECDSA_SIG        *ossl_sig_to_verify = NULL;

    /* This implementation doesn't use any key store with the ability
     * to look up a key based on kid. */
    (void)kid;

    /* Check the algorithm identifier */
    if(cose_algorithm_id != COSE_ALGORITHM_ES256 &&
       cose_algorithm_id != COSE_ALGORITHM_ES384 &&
       cose_algorithm_id != COSE_ALGORITHM_ES512) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    /* Check the signing key and get it out of the union */
    if(verification_key.crypto_lib != T_COSE_CRYPTO_LIB_OPENSSL) {
        return_value = T_COSE_ERR_INCORRECT_KEY_FOR_LIB;
        goto Done;
    }
    if(verification_key.k.key_ptr == NULL) {
        return_value = T_COSE_ERR_EMPTY_KEY;
        goto Done;
    }
    ossl_pub_key = (EC_KEY *)verification_key.k.key_ptr;

    /* Convert the serialized signature off the wire into the openssl
     * object / structure
     */
    return_value = convert_signature_to_ossl(cose_algorithm_id,
                                             signature,
                                             &ossl_sig_to_verify);
    if(return_value) {
        goto Done;
    }
    
    /* Check the key to be sure it is OK */
    ossl_result = EC_KEY_check_key(ossl_pub_key);
    if(ossl_result == 0) {
        return_value = T_COSE_ERR_SIG_FAIL;
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
    if(hash_ctx->update_error) {
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

