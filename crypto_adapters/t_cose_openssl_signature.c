/*
 *  t_cose_openssl_signature.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created 3/31/2019.
 */


#include "t_cose_defines.h"
#include "t_cose_crypto.h"

#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h" /* for NID for EC curve */
#include "openssl/err.h"


/**
 * \file t_cose_openssl_signature.c
 *
 * \brief Glue code for t_cose to use openssl ECDSA
 */


static inline struct q_useful_buf_c
convert_signature_from_ossl(const ECDSA_SIG *ossl_signature,
                            struct q_useful_buf signature_buffer)
{
    int                   r_len;
    int                   s_len;
    const BIGNUM         *ossl_signature_r_bn = NULL;
    const BIGNUM         *ossl_signature_s_bn = NULL;
    int                   sig_len;
    struct q_useful_buf_c signature;;

    /* Get the signature r and s as big nums */
    ECDSA_SIG_get0(ossl_signature, &ossl_signature_r_bn, &ossl_signature_s_bn);
    // ECDSA_SIG_get0 returns void

    /* Check the lengths to see if fits in the output buffer */
    r_len = BN_num_bytes(ossl_signature_r_bn);
    s_len = BN_num_bytes(ossl_signature_s_bn);
    sig_len = r_len + s_len;
    if(sig_len < 0 && (size_t)sig_len > signature_buffer.len) {
        signature = NULL_Q_USEFUL_BUF_C;
        goto Done;
    }

    /* Copy r and s of signature to output buffer and set length */
    BN_bn2bin(ossl_signature_r_bn, signature_buffer.ptr);
    BN_bn2bin(ossl_signature_s_bn, (uint8_t *)signature_buffer.ptr + r_len);
    signature.len = r_len + s_len;
    signature.ptr = signature_buffer.ptr;

Done:
    return signature;
}


enum t_cose_err_t
t_cose_crypto_pub_key_sign(int32_t cose_alg_id,
                           struct t_cose_signing_key signing_key,
                           struct q_useful_buf_c hash_to_sign,
                           struct q_useful_buf signature_buffer,
                           struct q_useful_buf_c *signature)
{
    enum t_cose_err_t  return_value;
    EC_GROUP          *ossl_ec_group = NULL;
    EC_KEY            *ossl_ec_key = NULL;
    ECDSA_SIG         *ossl_signature = NULL;

    /*
     * The interpretation of openssl's errors could be more detailed
     * and helpful, but as of now this is used just for test purposes.
     */
    
    if(cose_alg_id != COSE_ALGORITHM_ES256) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    if(signing_key.crypto_lib != T_COSE_CRYPTO_LIB_OPENSSL) {
        return_value = T_COSE_INCORRECT_KEY_FOR_LIB;
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

    /* Convert signature from OSSL format to the serialized
       format in q useful buf
     */
    *signature = convert_signature_from_ossl(ossl_signature, signature_buffer);

    /* Everything succeeded */
    return_value = T_COSE_SUCCESS;
    
Done:
    /* These (are assumed to) all check for NULL before they free, so
     * it is not necessary to check here */
    EC_GROUP_free(ossl_ec_group);
    ECDSA_SIG_free(ossl_signature);
    
    return return_value;
}


/* Returns shit that has to be freed */
// TODO: check out error conditions
static  enum t_cose_err_t
convert_signature_to_ossl(struct q_useful_buf_c signature, ECDSA_SIG **ossl_sig_to_verify)
{
    enum t_cose_err_t return_value;
    BIGNUM           *ossl_signature_r_bn = NULL;
    BIGNUM           *ossl_signature_s_bn = NULL;
    int               ossl_result;

    /* Openssl frees BNs associated with a sig when the
     * sig is freed. That makes this error handling in
     * this code more complex as the BNs have to be freed
     * individuallly on errors before association.
     */

    /* Check the signature length (it will vary with algorithm when
     * multiple are supported */
    // TODO: fix signature lengths
    if(signature.len != 64) {
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done2;
    }

    /* Put the r and the s from the signature into big numbers */
    ossl_signature_r_bn = BN_bin2bn(signature.ptr, 32, NULL);
    if(ossl_signature_r_bn == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done2;
    }

    ossl_signature_s_bn = BN_bin2bn(((uint8_t *)signature.ptr)+32, 32, NULL);
    if(ossl_signature_s_bn == NULL) {
        BN_free(ossl_signature_r_bn);
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done2;
    }

    /* Put the signature bytes into an ECDSA_SIG */
    *ossl_sig_to_verify = ECDSA_SIG_new();
    if(ossl_sig_to_verify == NULL) {
        BN_free(ossl_signature_r_bn);
        BN_free(ossl_signature_s_bn);
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done2;
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
Done2:
    /* The BN's r and s get freed when ossl_sig_to_verify is freed */

    return return_value;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_pub_key_verify(int32_t cose_alg_id,
                             struct t_cose_signing_key signing_key,
                             struct q_useful_buf_c key_id,
                             struct q_useful_buf_c hash_to_verify,
                             struct q_useful_buf_c signature)
{
    (void)key_id;  /* unused parameter */

    int               ossl_result;
    enum t_cose_err_t return_value;
    EC_KEY           *ossl_pub_key = NULL;
    ECDSA_SIG        *ossl_sig_to_verify = NULL;

    /*
     * The interpretation of openssl's errors could be more detailed
     * and helpful, but as of now this is used just for test purposes.
     */

    /* Chek the algorithm identifier */
    if(cose_alg_id != COSE_ALGORITHM_ES256) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    /* Convert the serialized signature off the wire into the
       openssl object / structure */
    return_value = convert_signature_to_ossl(signature, &ossl_sig_to_verify);
    if(return_value) {
        goto Done;
    }

    /* Get the pub key out of the union passed in. It is
     assume the key is pointer to an openssl key object */
    ossl_pub_key = (EC_KEY *)signing_key.k.key_ptr;
    
    /* Check the key to be sure */
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
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    }
    
    /* Everything succeeded */
    return_value = T_COSE_SUCCESS;
    
Done:
    /* These (are assumed to) all check for NULL before they free, so
     * it is not necessary to check here */
    ECDSA_SIG_free(ossl_sig_to_verify);

Done2:
    return return_value;
}
