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
 * The input bytes are what d2i_PrivateKey() will decode.  It's
 * documentation is sparse. It says it must be DER format and is
 * related to PKCS #8. This seems to be a set of DER-encoded ASN.1
 * data types such as:
 *
 *    ECPrivateKey defined in RFC 5915
 *
 * The key object returned by this is malloced and has to be freed by
 * by calling free_key(). This heap use is a part of OpenSSL and not
 * t_cose which does not use the heap.
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




/*
 * Public function, see init_key.h
 */
enum t_cose_err_t
init_fixed_test_ec_encryption_key(int32_t            cose_ec_curve_id,
                                  struct t_cose_key *public_key,
                                  struct t_cose_key *private_key)
{
    long                  pub_der_len;
    long                  priv_der_len;
    const unsigned char * priv_der_ptr;
    const unsigned char * pub_der_ptr;
    EVP_PKEY             *pkey;
    enum t_cose_err_t     return_value;

    /* The input key bytes are in ASN.1/DER format (RFC 5915 and RFC
     * 5480) since that is what d2i_PrivateKey() and d2i_PUBKEY()
     * accept.*/
    switch(cose_ec_curve_id) {
        case T_COSE_ELLIPTIC_CURVE_P_256:
            pub_der_ptr  = cose_ex_P_256_pub_der;
            pub_der_len  = sizeof(cose_ex_P_256_pub_der);
            priv_der_ptr = cose_ex_P_256_pair_der;
            priv_der_len = sizeof(cose_ex_P_256_pair_der);
            break;

        case T_COSE_ELLIPTIC_CURVE_P_521:
            pub_der_ptr  = cose_ex_P_521_pub_der;
            pub_der_len  = sizeof(cose_ex_P_521_pub_der);
            priv_der_ptr = cose_ex_P_521_pair_der;
            priv_der_len = sizeof(cose_ex_P_521_pair_der);
            break;

        default:
            return T_COSE_ERR_PRIVATE_KEY_IMPORT_FAILED;
    }

    /* d2i_PrivateKey documentation isn't very clear. What is known
     * from experimentation is that it does not support SEC1 raw keys
     * and that it does support RFC 5915 ASN.1/DER keys.
     */
    pkey = d2i_PrivateKey(EVP_PKEY_EC,  /* in: type */
                          NULL,         /* unused: defined as EVP_PKEY **a */
                         &priv_der_ptr, /* in: pointer to DER byes; out: unused */
                          priv_der_len  /* in: length of DER bytes */
                         );
    if(pkey == NULL) {
        return_value = T_COSE_ERR_PRIVATE_KEY_IMPORT_FAILED;
        goto Done;
    }
    private_key->key.ptr = pkey;


    /* d2i_PrivateKey documentation isn't very clear. What is known
     * from experimentation is that it does not support SEC1 raw keys
     * and that it does support RFC 5480 ASN.1/DER keys.
     */
    /* The openssl documentation says something about providing a
     * PKEY initialized with an EC Key of the right curve/group, but
     * that doesn't seem to be necessary. Probably because the RFC 5480
     * input provided here includes the curve identifier so it is
     * parsed out and set.
     */
    pkey = d2i_PUBKEY(NULL,        /* unused: defined as EVP_PKEY **a */
                     &pub_der_ptr, /* in: pointer to DER byes; out: unused */
                      pub_der_len  /* in: length of DER bytes */
                     );
    if(pkey == NULL) {
        EVP_PKEY_free(private_key->key.ptr);
        return_value = T_COSE_ERR_PRIVATE_KEY_IMPORT_FAILED;
        goto Done;
    }
    public_key->key.ptr = pkey;

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
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
    /* So far no good way to do this for OpenSSL or malloc() in
       general in a nice portable way. The PSA version does check so
       there is some coverage of the code even though there is no
       check here.
     */
    return 0;
}


/*
 char* e;
  long err = ERR_peek_last_error_line(NULL, NULL);
  e = ERR_error_string(err, NULL);

 */
