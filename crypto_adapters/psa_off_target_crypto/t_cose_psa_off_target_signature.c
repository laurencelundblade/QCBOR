/*
 * t_cose_psa_off_target_signature.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.mdE.
 */


#include "psa/crypto.h" /* Interfaces implemented here */

#include <string.h> /* for memset */

/* openssl headers  */
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h" /* for NID for EC curve */
#include "openssl/err.h"


/*
 * A very degenerate key store that can hold just one key
 */
struct degenerate_key_pair {
    void *key_pair;
};

static struct degenerate_key_pair key_store[1];

/**
 * \brief Look up key in degenerate test-only key store
 *
 * \param[in] handle  The PSA key handle to look up
 *
 * \return An OpenSSSL \c EC_KEY
 *
 * This is so degenerate there is only one key
 * and that is all that is ever returned. It is good enough for the tests
 * needed.
 */
static EC_KEY *key_lookup(psa_key_handle_t handle)
{
    return (EC_KEY *)key_store[handle].key_pair;
}


/*
 * The rest of this is very minimal implementations
 * of PSA crypto APIs. This is for off-target testing
 * that uses OpenSSL to perform the necessary crypto
 */


/*
 * Public function. See documentation in psa/crypto.h
 */
psa_status_t psa_allocate_key(psa_key_handle_t *handle)
{
    *handle = 0;
    return PSA_SUCCESS;
}


/*
 * Public function. See documentation in psa/crypto.h
 */
psa_status_t psa_destroy_key(psa_key_handle_t handle)
{
    EC_KEY_free(key_store[handle].key_pair);

    key_store[handle] = (struct degenerate_key_pair){NULL};
    return PSA_SUCCESS;
}


/*
 * Public function. See documentation in psa/crypto.h
 */
psa_status_t psa_set_key_policy(psa_key_handle_t        handle,
                                const psa_key_policy_t *policy)
{
    /* just a stub. Don't need policy for our tests here */
    (void)handle;
    (void)policy;

    return PSA_SUCCESS;
}


/*
 * Public function. See documentation in psa/crypto.h
 */
void psa_key_policy_set_usage(psa_key_policy_t *policy,
                              psa_key_usage_t   usage,
                              psa_algorithm_t   alg)
{
    (void)policy;
    (void)usage;
    (void)alg;
}


/*
 * Public function. See documentation in psa/crypto.h
 */
psa_status_t psa_import_key(psa_key_handle_t handle,
                            psa_key_type_t   type,
                            const uint8_t   *data,
                            size_t           data_length)
{
    EC_GROUP     *ossl_ec_group = NULL;
    psa_status_t  return_value;
    BIGNUM       *ossl_private_key_bn = NULL;
    EC_KEY       *ossl_ec_key = NULL;
    int           ossl_result;
    EC_POINT     *ossl_pub_key_point = NULL;
    int           nid;

    /* Map PSA key type / curve to OpenSSL nid for the cure */
    nid = type == PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP256R1) ? NID_X9_62_prime256v1:
          type == PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP384R1) ? NID_secp384r1 :
          type == PSA_KEY_TYPE_ECC_KEYPAIR(PSA_ECC_CURVE_SECP521R1) ? NID_secp521r1 :
                                                                      0;

    if(nid == 0) {
        return_value = PSA_ERROR_NOT_SUPPORTED;
        goto Done;
    }

    /* Make a group for the particular EC algorithm */
    ossl_ec_group = EC_GROUP_new_by_curve_name(nid);
    if(ossl_ec_group == NULL) {
        return_value = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Make an empty EC key object */
    ossl_ec_key = EC_KEY_new();
    if(ossl_ec_key == NULL) {
        return_value = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Associate group with key object */
    ossl_result = EC_KEY_set_group(ossl_ec_key, ossl_ec_group);
    if (!ossl_result) {
        return_value = PSA_ERROR_GENERIC_ERROR;
        goto Done;
    }

    /* Make an instance of a big number to store the private key */
    ossl_private_key_bn = BN_new();
    if(ossl_private_key_bn == NULL) {
        return_value = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto Done;
    }
    BN_zero(ossl_private_key_bn);

    /* Stuff the specific private key into the big num */
    BIGNUM *x = BN_bin2bn(data, (int)data_length, ossl_private_key_bn);
    if(x == NULL || ossl_private_key_bn == 0) {
        return_value = PSA_ERROR_INVALID_ARGUMENT;
        goto Done;
    }

    /* BN_print_fp(stdout, ossl_private_key_bn); */

    /* Now associate the big num with the key object so we finally
     * have a key set up and ready for signing */
    ossl_result = EC_KEY_set_private_key(ossl_ec_key, ossl_private_key_bn);
    if (!ossl_result) {
        return_value = PSA_ERROR_INVALID_ARGUMENT;
        goto Done;
    }

    ossl_pub_key_point = EC_POINT_new(ossl_ec_group);
    if(ossl_pub_key_point == NULL) {
        return_value = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    ossl_result = EC_POINT_mul(ossl_ec_group,
                               ossl_pub_key_point, /* Output of mul goes here */
                               ossl_private_key_bn, /* The private key big num*/
                               NULL, /* const EC_POINT *q */
                               NULL, /* const BIGNUM *m */
                               NULL /* BN_CTX *ctx */
                               );

    ossl_result = EC_KEY_set_public_key(ossl_ec_key, ossl_pub_key_point);
    if(ossl_result == 0) {
        return_value = PSA_ERROR_INVALID_ARGUMENT;
        goto Done;
    }

    key_store[handle].key_pair = ossl_ec_key;

    return_value         = PSA_SUCCESS;

Done:
    return return_value;
}



/**
 * \brief Convert OpenSSL ECDSA_SIG to serialized on-the-wire format
 *
 * \param[in] key_len             Size of the key in bytes -- governs sig size.
 * \param[in] ossl_signature      The OpenSSL signature to convert.
 * \param[in] sig_buffer          The buffer for output.
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
static inline size_t
convert_ecdsa_signature_from_ossl(int                 key_len,
                                  const ECDSA_SIG    *ossl_signature,
                                  uint8_t            *sig_buffer,
                                  size_t              sig_buffer_len)
{
    size_t                r_len;
    size_t                s_len;
    const BIGNUM         *ossl_signature_r_bn;
    const BIGNUM         *ossl_signature_s_bn;
    void                 *r_start_ptr;
    void                 *s_start_ptr;
    size_t                return_length;

    /* Zero the buffer so that bytes r and s are padded with zeros */
    memset(sig_buffer, 0, sig_buffer_len);

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
    if(r_len + s_len > sig_buffer_len) {
        return_length = 0;
        goto Done;
    }

    /* Copy r and s of signature to output buffer and set length */
    r_start_ptr = sig_buffer + key_len - r_len;
    BN_bn2bin(ossl_signature_r_bn, r_start_ptr);

    s_start_ptr = sig_buffer + 2 * key_len - s_len;
    BN_bn2bin(ossl_signature_s_bn, s_start_ptr);

    return_length = 2 * key_len;

Done:
    return return_length;
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
psa_status_t
convert_ecdsa_signature_to_ossl(int             key_len,
                                const uint8_t  *signature,
                                size_t          signature_len,
                                ECDSA_SIG     **ossl_sig_to_verify)
{
    psa_status_t      return_value;
    BIGNUM           *ossl_signature_r_bn = NULL;
    BIGNUM           *ossl_signature_s_bn = NULL;
    int               ossl_result;

    /* Check the signature length against expected */
    if(signature_len != (size_t)key_len * 2) {
        return_value = PSA_ERROR_INVALID_SIGNATURE;
        goto Done;
    }

    /* Put the r and the s from the signature into big numbers */
    ossl_signature_r_bn = BN_bin2bn(signature, key_len, NULL);
    if(ossl_signature_r_bn == NULL) {
        return_value = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    ossl_signature_s_bn = BN_bin2bn(((uint8_t *)signature)+key_len,
                                    key_len,
                                    NULL);
    if(ossl_signature_s_bn == NULL) {
        BN_free(ossl_signature_r_bn);
        return_value = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Put the signature bytes into an ECDSA_SIG */
    *ossl_sig_to_verify = ECDSA_SIG_new();
    if(ossl_sig_to_verify == NULL) {
        /* Don't leak memory in error condition */
        BN_free(ossl_signature_r_bn);
        BN_free(ossl_signature_s_bn);
        return_value = PSA_ERROR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Put the r and s bignums into an ECDSA_SIG. Freeing
     * ossl_sig_to_verify will now free r and s.
     */
    ossl_result = ECDSA_SIG_set0(*ossl_sig_to_verify,
                                  ossl_signature_r_bn,
                                  ossl_signature_s_bn);
    if(ossl_result != 1) {
        return_value = PSA_ERROR_INVALID_SIGNATURE;
        goto Done;
    }

    return_value = PSA_SUCCESS;

Done:
    /* The BN's r and s get freed when ossl_sig_to_verify is freed */
    return return_value;
}



/**
 * \brief Common checks and conversions for signing and verification.
 *
 * \param[in] ossl_ec_key           The key to check and convert.
 * \param[out] return_key_size_in_bytes  How big the key is
 *
 * \return Error or \ref T_COSE_SUCCESS.
 *
 * It pulls the OpenSSL in-memory key out of \c t_cose_key
 * and checks it and figures out the number of bytes
 * in the key rounded up. This is also the size of r and s
 * in the signature.
 */
psa_status_t
ecdsa_key_checks(const EC_KEY  *ossl_ec_key,
                 int           *return_key_size_in_bytes)
{
    psa_status_t       return_value;
    const EC_GROUP    *key_group;
    int                key_len_bits; /* type int is conscious choice */
    int                key_len_bytes; /* type int is conscious choice */
    int                ossl_result; /* type int is conscious choice */

    /* Check the key to be sure it is OK */
    ossl_result = EC_KEY_check_key(ossl_ec_key);
    if(ossl_result == 0) {
        return_value = PSA_ERROR_INVALID_ARGUMENT;
        goto Done;
    }

    /* Get the key size, which depends on the group */
    key_group = EC_KEY_get0_group(ossl_ec_key);
    if(key_group == NULL) {
        return_value = PSA_ERROR_INVALID_ARGUMENT;
        goto Done;
    }
    key_len_bits = EC_GROUP_get_degree(key_group);

    /* Convert group size in bits to key size in bytes per
     * RFC 8152 section 8.1. This is also the size of
     * r and s in the signature. This is by rounding up
     * to the number of bytes to hold the give number of bits.
     */
    key_len_bytes = key_len_bits / 8;
    if(key_len_bits % 8) {
        key_len_bytes++;
    }

    *return_key_size_in_bytes = key_len_bytes;

    return_value = PSA_SUCCESS;

Done:
    return return_value;
}


/*
 * Public function. See documentation in psa/crypto.h
 */
psa_status_t  psa_get_key_information(psa_key_handle_t psa_key_handle,
                                      psa_key_type_t *type,
                                      size_t *key_size_bits)
{
    EC_KEY         *ossl_ec_key;
    psa_status_t    return_value;
    int             ossl_result; /* type int is conscious choice */
    const EC_GROUP *key_group;

    (void)type;

    ossl_ec_key = key_lookup(psa_key_handle);
    if(ossl_ec_key == NULL) {
        /* Maybe there is a better error code for a bad key handle */
        return_value = PSA_ERROR_INVALID_HANDLE;
        goto Done;
    }

    /* Check the key to be sure it is OK */
    ossl_result = EC_KEY_check_key(ossl_ec_key);
    if(ossl_result == 0) {
        return_value = PSA_ERROR_INVALID_ARGUMENT;
        goto Done;
    }

    /* Get the key size, which depends on the group */
    key_group = EC_KEY_get0_group(ossl_ec_key);
    if(key_group == NULL) {
        return_value = PSA_ERROR_INVALID_ARGUMENT;
        goto Done;
    }
    *key_size_bits = EC_GROUP_get_degree(key_group);

    return_value = PSA_SUCCESS;

Done:
    return 0;

}


/*
 * Public function. See documentation in psa/crypto.h
 */
psa_status_t psa_asymmetric_sign(psa_key_handle_t psa_key_handle,
                                 psa_algorithm_t  psa_algorithm_id,
                                 const uint8_t   *hash_to_sign,
                                 size_t           hash_to_sign_len,
                                 uint8_t         *signature_buffer,
                                 size_t           signature_buffer_len,
                                 size_t          *return_signature_len)
{
    ECDSA_SIG    *ossl_signature = NULL;
    EC_KEY       *ossl_ec_key;
    psa_status_t  return_value;
    int           key_len;

    /* Check the algorithm identifier */
    if(!PSA_ALG_IS_ECDSA(psa_algorithm_id)) {
        return_value = PSA_ERROR_NOT_SUPPORTED;
        goto Done;
    }

    ossl_ec_key = key_lookup(psa_key_handle);
    if(ossl_ec_key == NULL) {
        /* Maybe there is a better error code for a bad key handle */
        return_value = PSA_ERROR_INVALID_HANDLE;
        goto Done;
    }


    return_value = ecdsa_key_checks(ossl_ec_key, &key_len);
    if(return_value != PSA_SUCCESS) {
        goto Done;
    }

    /* Actually do the EC signature over the hash */
    ossl_signature = ECDSA_do_sign(hash_to_sign,
                                   (int)hash_to_sign_len,
                                   ossl_ec_key);
    if(ossl_signature == NULL) {
        return_value = PSA_ERROR_GENERIC_ERROR;
        goto Done;
    }

    /* Convert signature from OSSL format to the serialized format in
     * a q_useful_buf. Presumably everything inside ossl_signature is
     * correct since it is not NULL.
     */
    *return_signature_len = convert_ecdsa_signature_from_ossl(key_len,
                                                              ossl_signature,
                                                              signature_buffer,
                                                              signature_buffer_len);
    if(*return_signature_len) {
        return_value = PSA_SUCCESS;
    } else {
        /* Might be other than this, but this is the usual */
        return_value = PSA_ERROR_BUFFER_TOO_SMALL;
    }
Done:
    return return_value;
}


/*
 * Public function. See documentation in psa/crypto.h
 */
psa_status_t psa_asymmetric_verify(psa_key_handle_t psa_key_handle,
                                   psa_algorithm_t  psa_algorithm_id,
                                   const uint8_t   *hash_to_verify,
                                   size_t           hash_to_verify_len,
                                   const uint8_t   *signature_to_verify,
                                   size_t           signature_to_verify_len)
{
    int               ossl_result;
    psa_status_t      return_value;
    ECDSA_SIG        *ossl_sig_to_verify = NULL;
    EC_KEY           *ossl_ec_key;
    int               key_len;


    /* Check the algorithm identifier */
    if(!PSA_ALG_IS_ECDSA(psa_algorithm_id)) {
        return_value = PSA_ERROR_NOT_SUPPORTED;
        goto Done;
    }

    ossl_ec_key = key_lookup(psa_key_handle);
    if(ossl_ec_key == NULL) {
        /* Maybe there is a better error code for a bad key handle */
        return_value = PSA_ERROR_INVALID_HANDLE;
        goto Done;
    }

    return_value = ecdsa_key_checks(ossl_ec_key, &key_len);
    if(return_value != PSA_SUCCESS) {
        goto Done;
    }

    /* Convert the serialized signature off the wire into the openssl
     * object / structure
     */
    return_value = convert_ecdsa_signature_to_ossl(key_len,
                                                   signature_to_verify,
                                                   signature_to_verify_len,
                                                  &ossl_sig_to_verify);
    if(return_value) {
        goto Done;
    }

    /* Check the key to be sure it is OK */
    ossl_result = EC_KEY_check_key(ossl_ec_key);
    if(ossl_result == 0) {
        return_value = PSA_ERROR_INVALID_ARGUMENT;
        goto Done;
    }

    /* Actually do the signature verification */
    ossl_result = ECDSA_do_verify(hash_to_verify,
                                  (int)hash_to_verify_len,
                                  ossl_sig_to_verify,
                                  ossl_ec_key);
    if(ossl_result == 0) {
        /* The operation succeeded, but the signature doesn't match */
        return_value = PSA_ERROR_INVALID_SIGNATURE;
        goto Done;
    } else if (ossl_result != 1) {
        /* Failed before even trying to verify the signature */
        return_value = PSA_ERROR_GENERIC_ERROR;
        goto Done;
    }

    /* Everything succeeded */
    return_value = PSA_SUCCESS;

Done:
    /* These (are assumed to) all check for NULL before they free, so
     * it is not necessary to check here */
    ECDSA_SIG_free(ossl_sig_to_verify);

    return return_value;
}
