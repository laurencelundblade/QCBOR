/*
 * init_keys_ossl.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "init_keys.h"
#include "example_keys.h"

#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_key.h"

#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/x509.h"


/*
 *
 * The input bytes are what d2i_PrivateKey() will decode.
 * It's documentation is sparse. It says it must be DER
 * format and is related to PKCS #8. This seems to be
 * a set of DER-encoded ASN.1 data types such as:
 *
 *    ECPrivateKey defined in RFC 5915
 *
 * The key object returned by this is malloced and has to be freed by
 * by calling free_key(). This heap use is a part of
 * OpenSSL and not t_cose which does not use the heap.
 *
 *
 */
static enum t_cose_err_t
init_signing_key_der(int32_t               cose_algorithm_id,
                     struct q_useful_buf_c der_encoded,
                     struct t_cose_key    *key_pair)
{
    EVP_PKEY          *pkey;
    int                key_type;
    enum t_cose_err_t  return_value;
    long               der_length;

    switch (cose_algorithm_id) {
     case T_COSE_ALGORITHM_ES256:
     case T_COSE_ALGORITHM_ES384:
     case T_COSE_ALGORITHM_ES512:
         key_type = EVP_PKEY_EC;
         break;

     case T_COSE_ALGORITHM_PS256:
     case T_COSE_ALGORITHM_PS384:
     case T_COSE_ALGORITHM_PS512:
         key_type = EVP_PKEY_RSA;
         break;

     case T_COSE_ALGORITHM_EDDSA:
         key_type = EVP_PKEY_ED25519;
          break;

     default:
         return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
     }

    /* Safely convert size_t to long */
    if(der_encoded.len > LONG_MAX) {
        return T_COSE_ERR_FAIL;
    }
    der_length = (long)der_encoded.len;

    /* This imports the public key too */
    pkey = d2i_PrivateKey(key_type, /* in: type */
                          NULL, /* unused: defined as EVP_PKEY **a */
                          (const unsigned char **)&der_encoded.ptr, /*in: pointer to DER byes; out: unused */
                          der_length /* in: length of DER bytes */
                          );
    if(pkey == NULL) {
        // TODO: better error?
        return_value = T_COSE_ERR_FAIL;
        goto Done;
    }

    key_pair->key.ptr = pkey;
    return_value      = T_COSE_SUCCESS;

Done:
    return return_value;
}


/*
 * Public function, see init_key.h
 */
enum t_cose_err_t
init_fixed_test_signing_key(int32_t            cose_algorithm_id,
                            struct t_cose_key *key_pair)
{
    struct q_useful_buf_c der_encoded_key;

    /* Select the key bytes based on the algorithm */
    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        der_encoded_key = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(ec_P_256_key_pair_der);
        break;

    case T_COSE_ALGORITHM_ES384:
        der_encoded_key = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(ec_P_384_key_pair_der);
        break;

    case T_COSE_ALGORITHM_ES512:
        der_encoded_key = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(ec_P_521_key_pair_der);
        break;

    case T_COSE_ALGORITHM_PS256:
    case T_COSE_ALGORITHM_PS384:
    case T_COSE_ALGORITHM_PS512:
        der_encoded_key = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(RSA_2048_key_pair_der);
        break;

    case T_COSE_ALGORITHM_EDDSA:
        der_encoded_key = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(ed25519_key_pair_der);
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    /* Turn the DER bytes into a t_cose_key */
    return init_signing_key_der(cose_algorithm_id,
                                der_encoded_key,
                                key_pair);
}


/*
 * Public function, see init_keys.h
 */
void free_fixed_signing_key(struct t_cose_key key_pair)
{
    EVP_PKEY_free(key_pair.key.ptr);
}




static enum t_cose_err_t
init_encryption_key_der(struct q_useful_buf_c der_encoded,
                        struct t_cose_key    *key_pair)
{
    EVP_PKEY          *pkey;
    enum t_cose_err_t  return_value;
    long               der_length;

    /* Safely convert size_t to long */
    if(der_encoded.len > LONG_MAX) {
        return T_COSE_ERR_FAIL;
    }
    der_length = (long)der_encoded.len;

    /* This imports the public key too */
    pkey = d2i_PrivateKey(EVP_PKEY_EC, /* in: type */
                          NULL, /* unused: defined as EVP_PKEY **a */
                          (const unsigned char **)&der_encoded.ptr, /*in: pointer to DER byes; out: unused */
                          der_length /* in: length of DER bytes */
                          );
    if(pkey == NULL) {
        return_value = T_COSE_ERR_PRIVATE_KEY_IMPORT_FAILED;
        goto Done;
    }

    key_pair->key.ptr = pkey;
    return_value      = T_COSE_SUCCESS;

Done:
    return return_value;
}


#if 0
/* This isn't in use yet because something wasn't going right for it.
 * It would be good to have this working for the example.
 */
#include <openssl/x509.h>

static enum t_cose_err_t
init_encryption_pubkey_der(
                           struct q_useful_buf_c der_encoded,
                           struct t_cose_key    *key_pair)
{
    EVP_PKEY          *pkey;
    enum t_cose_err_t  return_value;


    EVP_PKEY          *apkey;
    EC_KEY            *ec_key;
    EC_GROUP          *ec_group;
    enum t_cose_err_t  return_value;
    long               der_length;
    int                nid;

    /* Safely convert size_t to long */
    if(der_encoded.len > LONG_MAX) {
        return T_COSE_ERR_FAIL;
    }
    der_length = (long)der_encoded.len;


    switch (cose_ec_curve_id) {
        case T_COSE_ELLIPTIC_CURVE_P_256:
             nid  = NID_X9_62_prime256v1;
             break;
        case T_COSE_ELLIPTIC_CURVE_P_384:
             nid  = NID_secp384r1;
             break;
        case T_COSE_ELLIPTIC_CURVE_P_521:
             nid  = NID_secp521r1;
             break;
        /* The only other registered for EC2 is secp256k1 */
        default:
             return T_COSE_ERR_UNSUPPORTED_ELLIPTIC_CURVE_ALG;
    }

    ec_key = EC_KEY_new();
    if(ec_key == NULL) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    ec_group = EC_GROUP_new_by_curve_name(nid);
    if(ec_group == NULL) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    // TODO: this and related are to be depreacted, so they say...
    ossl_result = EC_KEY_set_group(ec_key, ec_group);
    if(ossl_result != 1) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }


    apkey = EVP_PKEY_new();


    const uint8_t *pp = ec_P_256_pub_key_der;

    pkey = d2i_PUBKEY(NULL, /* unused: defined as EVP_PKEY **a */
                          (const unsigned char **)&pp, /* in: pointer to DER byes; out: unused */
                          sizeof(ec_P_256_pub_key_der) /* in: length of DER bytes */
                          );
    if(pkey == NULL) {
        return_value = T_COSE_ERR_PRIVATE_KEY_IMPORT_FAILED;
        goto Done;
    }

    key_pair->key.ptr = pkey;
    return_value      = T_COSE_SUCCESS;

Done:
    return return_value;
}
#endif



/*
 * Public function, see init_key.h
 */
enum t_cose_err_t
init_fixed_test_ec_encryption_key(int32_t            cose_ec_curve_id,
                                  struct t_cose_key *public_key,
                                  struct t_cose_key *private_key)
{
    enum t_cose_err_t     err;
    struct q_useful_buf_c der_encoded;

    switch(cose_ec_curve_id) {
        case T_COSE_ELLIPTIC_CURVE_P_256:
            der_encoded = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(cose_ex_P_256_key_pair_der);
            break;
        case T_COSE_ELLIPTIC_CURVE_P_384:
            der_encoded = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(ec_P_384_key_pair_der);
            break;
        case T_COSE_ELLIPTIC_CURVE_P_521:
            der_encoded = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(ec_P_521_key_pair_der);
            break;
        default:
            return T_COSE_ERR_PRIVATE_KEY_IMPORT_FAILED;
    }

    err = init_encryption_key_der(der_encoded, private_key);
    if(err) {
        return err;
    }

    /* Clone the private key since it also has the public key. Would be
     * good to give an example of public-key only import instead.*/
    *public_key = *private_key;
    EVP_PKEY_up_ref((EVP_PKEY *)public_key->key.ptr);

    return T_COSE_SUCCESS;
}


/*
 * Public function, see init_key.h
 */
void
free_fixed_test_ec_encryption_key(struct t_cose_key key)
{
    EVP_PKEY_free(key.key.ptr);
}



/*
 * Public function, see init_keys.h
 */
int check_for_key_allocation_leaks()
{
    /* So far no good way to do this for OpenSSL or malloc() in general
       in a nice portable way. The PSA version does check so there is
       some coverage of the code even though there is no check here.
     */
    return 0;
}
