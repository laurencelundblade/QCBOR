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


/*
 * A fixed key pair until improvements are made.
 04:
 c5:d1:69:99:9d:ca:a9:33:09:20:78:5f:58:15:92:f0:c2:8d:87:8c:6d:cf:23:b9:f2:e0:6b:4a:91:e2:40:43:
 4e:8b:f8:72:61:52:db:ac:22:b4:7f:de:1b:e9:c7:74:a0:c1:d0:60:d4:07:85:b3:75:e2:55:5e:ab:46:d8:c2
 */
#define FIXED_PUBLIC_EC_KEY \
    "04c5d169999dcaa9330920785f581592f0c28d878c6dcf23b9f2e06b4a91e240434e8bf872" \
    "6152dbac22b47fde1be9c774a0c1d060d40785b375e2555eab46d8c2"

#define FIXED_PRIVATE_EC_KEY \
    "1e9a74f7c8d26dd2e90c14570e206431211da8c8c97a2c92834ff0ce3d31b289"


enum t_cose_err_t
t_cose_crypto_pub_key_sign(int32_t cose_alg_id,
                           int32_t key_select,
                           struct q_useful_buf_c hash_to_sign,
                           struct q_useful_buf signature_buffer,
                           struct q_useful_buf_c *signature)
{
    enum t_cose_err_t  return_value;
    int                ossl_result;
    EC_GROUP          *ossl_ec_group = NULL;
    EC_KEY            *ossl_ec_key = NULL;
    BIGNUM            *ossl_private_key_bn = NULL;
    ECDSA_SIG         *ossl_signature = NULL;
    const BIGNUM      *ossl_signature_r_bn = NULL;
    const BIGNUM      *ossl_signature_s_bn = NULL;
    int                r_len;
    int                s_len;
    int                sig_len;
    
    (void)key_select; /* unused variable */
    
    /*
     * The interpretation of openssl's errors could be more detailed
     * and helpful, but as of now this is used just for test purposes.
     */
    
    if(cose_alg_id != COSE_ALGORITHM_ES256) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }
    
    /* Make a group which is neeed because TODO */
    /* NID_X9_62_prime256v1 corresponds to COSE_ALGORITHM_ES256 */
    ossl_ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if(ossl_ec_group == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }
    
    /* Make an empty EC key object */
    ossl_ec_key = EC_KEY_new();
    if(ossl_ec_key == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }
    
    /* Associate group with key. */
    ossl_result = EC_KEY_set_group(ossl_ec_key, ossl_ec_group);
    if (!ossl_result) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }
    
    /* Make an instance of a big number to store the key */
    ossl_private_key_bn  = BN_new();
    if(ossl_private_key_bn == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }
    BN_zero(ossl_private_key_bn);
    
    /* Stuff the private key into the big num */
    ossl_result = BN_hex2bn(&ossl_private_key_bn, FIXED_PRIVATE_EC_KEY);
    if(ossl_private_key_bn == 0) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }
    
    /* Now associate the big num with the private key so we finally
     * have a key set up and ready for signing */
    ossl_result = EC_KEY_set_private_key(ossl_ec_key, ossl_private_key_bn);
    if (!ossl_result) {
        return_value = T_COSE_ERR_SIG_FAIL;
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
    
    /* Get the signature r and s as big nums */
    ECDSA_SIG_get0(ossl_signature, &ossl_signature_r_bn, &ossl_signature_s_bn);
    // ECDSA_SIG_get0 returns void
    
    /* Check the lengths to see if fits in the output buffer */
    r_len = BN_num_bytes(ossl_signature_r_bn);
    s_len = BN_num_bytes(ossl_signature_s_bn);
    sig_len = r_len + s_len;
    if(sig_len < 0 && (size_t)sig_len > signature_buffer.len) {
        return_value = T_COSE_ERR_SIG_BUFFER_SIZE;
        goto Done;
    }
    
    /* Copy r and s of signature to output buffer and set length */
    BN_bn2bin(ossl_signature_r_bn, signature_buffer.ptr);
    BN_bn2bin(ossl_signature_s_bn, (uint8_t *)signature_buffer.ptr + r_len);
    signature->len = r_len + s_len;
    signature->ptr = signature_buffer.ptr;
    
    /* Everything succeeded */
    return_value = T_COSE_SUCCESS;
    
Done:
    /* These (are assumed to) all check for NULL before they free, so
     * it is not necessary to check here */
    EC_KEY_free(ossl_ec_key);
    EC_GROUP_free(ossl_ec_group);
    ECDSA_SIG_free(ossl_signature);
    
    return return_value;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_pub_key_verify(int32_t cose_alg_id,
                             int32_t key_select,
                             struct q_useful_buf_c key_id,
                             struct q_useful_buf_c hash_to_verify,
                             struct q_useful_buf_c signature)
{
    int               ossl_result;
    enum t_cose_err_t return_value;
    EC_KEY           *ossl_pub_key = NULL;
    EC_GROUP         *ossl_ec_group = NULL;
    EC_POINT         *ossl_pub_key_point = NULL;
    ECDSA_SIG        *ossl_sig_to_verify = NULL;
    BIGNUM           *ossl_signature_r_bn = NULL;
    BIGNUM           *ossl_signature_s_bn = NULL;
    
    (void)key_select;  /* unused parameter */
    (void)key_id;  /* unused parameter */
    
    /*
     * The interpretation of openssl's errors could be more detailed
     * and helpful, but as of now this is used just for test purposes.
     */
    
    /* Openssl free BNs associated with a sig when the
     * sig is freed. That makes this error handling in
     * this code more complex as the BNs have to be freed
     * individuallly on errors before association.
     */
    
    /* Check the signature length (it will vary with algorithm when
     * multiple are supported */
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
    ossl_sig_to_verify = ECDSA_SIG_new();
    if(ossl_sig_to_verify == NULL) {
        BN_free(ossl_signature_r_bn);
        BN_free(ossl_signature_s_bn);
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done2;
    }
    
    /* Put the r and s bignums into an ECDSA_SIG. Freeing
     * ossl_sig_to_verify will now free r and s.
     */
    ossl_result = ECDSA_SIG_set0(ossl_sig_to_verify,
                                 ossl_signature_r_bn,
                                 ossl_signature_s_bn);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }
    
    /* Make an empty EC key object */
    ossl_pub_key = EC_KEY_new();
    if(ossl_pub_key == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }
    
    /* Chek the algorithm identifier */
    if(cose_alg_id != COSE_ALGORITHM_ES256) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }
    
    /* Make the EC group which says which type of key and curve */
    /* NID_X9_62_prime256v1 corresponds to COSE_ALGORITHM_ES256 */
    ossl_ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if(ossl_ec_group == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }
    
    /* Associate the group / curve with the EC_Key instance */
    ossl_result = EC_KEY_set_group(ossl_pub_key, ossl_ec_group);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }
    
    /* Make an empty EC point into which the key gets loaded */
    ossl_pub_key_point = EC_POINT_new(ossl_ec_group);
    if(ossl_pub_key_point == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }
    
    /* Turn the serialized public key into an EC point */
    ossl_pub_key_point = EC_POINT_hex2point(ossl_ec_group,
                                            FIXED_PUBLIC_EC_KEY,
                                            ossl_pub_key_point,
                                            NULL);
    if(ossl_pub_key_point == NULL) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }
    
    /* Associate the EC point with openssl's pub key structure */
    ossl_result = EC_KEY_set_public_key(ossl_pub_key, ossl_pub_key_point);
    if(ossl_result == 0) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }
    
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
    /* The BN's r and s get freed when ossl_sig_to_verify is freed */
    ECDSA_SIG_free(ossl_sig_to_verify);
    EC_KEY_free(ossl_pub_key);
    EC_GROUP_free(ossl_ec_group);
    EC_POINT_free(ossl_pub_key_point);
    
Done2:
    return return_value;
}


/* This is a stub implementation */
enum t_cose_err_t
t_cose_crypto_get_ec_pub_key(int32_t    key_select,
                             struct q_useful_buf_c kid,
                             int32_t   *cose_curve_id,
                             struct q_useful_buf buf_to_hold_x_coord,
                             struct q_useful_buf buf_to_hold_y_coord,
                             struct q_useful_buf_c  *x_coord,
                             struct q_useful_buf_c  *y_coord)
{
    /* This is just a stub that returns fake keys */
    struct q_useful_buf_c x;
    struct q_useful_buf_c y;
    
    (void)key_select;  /* unused parameter */
    (void)kid;  /* unused parameter */
    
    x = Q_USEFUL_BUF_FROM_SZ_LITERAL("xxxxxxxx9xxxxxxxxx9xxxxxxxxx9xx2");
    y = Q_USEFUL_BUF_FROM_SZ_LITERAL("yyyyyyyy9yyyyyyyyy9yyyyyyyyy9yy2");
    
    /* q_useful_buf_copy does size checking */
    *x_coord = q_useful_buf_copy(buf_to_hold_x_coord, x);
    *y_coord = q_useful_buf_copy(buf_to_hold_y_coord, y);
    
    if(q_useful_buf_c_is_null(*x_coord) ||
       q_useful_buf_c_is_null(*y_coord)) {
        return T_COSE_ERR_KEY_BUFFER_SIZE;
    }
    
    *cose_curve_id = COSE_ELLIPTIC_CURVE_P_256;
    
    return T_COSE_SUCCESS;
}


