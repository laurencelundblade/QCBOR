/*
 * init_keys_psa.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_key.h"
#include "psa/crypto.h"


/*
 * Import a signing key. Not sure what all formats this actually
 * handles yet, but do know that just the private key works. Note that
 * the curve and algorithm type are specified here directly.
 */
static enum t_cose_err_t
init_signing_key_from_xx(int32_t               cose_algorithm_id,
                         struct q_useful_buf_c key_bytes,
                         struct t_cose_key    *key_pair)
{
    psa_key_type_t       key_type;
    psa_status_t         crypto_result;
    psa_key_handle_t     key_handle;
    psa_algorithm_t      key_alg;
    psa_key_attributes_t key_attributes;


    /* There is not a 1:1 mapping from COSE algorithm to key type, but
     * there is usually an obvious curve for an algorithm. That
     * is what this does.
     */

    switch(cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
        break;

    case T_COSE_ALGORITHM_ES384:
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
        break;

    case T_COSE_ALGORITHM_ES512:
        key_type        = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
        key_alg         = PSA_ALG_ECDSA(PSA_ALG_SHA_512);
        break;

    case T_COSE_ALGORITHM_PS256:
        key_type        = PSA_KEY_TYPE_RSA_KEY_PAIR;
        key_alg         = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
        break;

    case T_COSE_ALGORITHM_PS384:
        key_type        = PSA_KEY_TYPE_RSA_KEY_PAIR;
        key_alg         = PSA_ALG_RSA_PSS(PSA_ALG_SHA_384);
        break;

    case T_COSE_ALGORITHM_PS512:
        key_type        = PSA_KEY_TYPE_RSA_KEY_PAIR;
        key_alg         = PSA_ALG_RSA_PSS(PSA_ALG_SHA_512);
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }


    /* OK to call this multiple times */
    crypto_result = psa_crypto_init();
    if(crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }


    /* When importing a key with the PSA API there are two main things
     * to do.
     *
     * First you must tell it what type of key it is as this cannot be
     * discovered from the raw data (because the import is not of a
     * format like RFC 5915). The variable key_type contains that
     * information including the EC curve. This is sufficient for
     * psa_import_key() to succeed, but you probably want actually use
     * the key.
     *
     * Second, you must say what algorithm(s) and operations the key
     * can be used as the PSA Crypto Library has policy enforcement.
     */

    key_attributes = psa_key_attributes_init();

    /* The type of key including the EC curve */
    psa_set_key_type(&key_attributes, key_type);

    /* Say what algorithm and operations the key can be used with/for */
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attributes, key_alg);


    /* Import the private key. psa_import_key() automatically
     * generates the public key from the private so no need to import
     * more than the private key. With ECDSA the public key is always
     * deterministically derivable from the private key.
     */
    crypto_result = psa_import_key(&key_attributes,
                                   key_bytes.ptr,
                                   key_bytes.len,
                                   &key_handle);

    if(crypto_result != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL;
    }

    /* This assignment relies on
     * MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER not being defined. If
     * it is defined key_handle is a structure.  This does not seem to
     * be typically defined as it seems that is for a PSA
     * implementation architecture as a service rather than an linked
     * library. If it is defined, the structure will probably be less
     * than 64 bits, so it can still fit in a t_cose_key. */
    key_pair->key.handle = key_handle;

    return T_COSE_SUCCESS;
}


/*
 * These are the same keys as in init_keys_ossl.c so that messages
 * made with openssl-based tests and examples can be verified those
 * made by mbedtls tests and examples.  These were made with openssl
 * as detailed in init_keys_ossl.c.  Then just the private key was
 * pulled out to be put here because mbedtls just needs the private
 * key, unlike openssl for which there is a full rfc5915 DER
 * structure. These were pulled out of the DER by identifying the key
 * with openssl asn1parse and then finding those bytes in the C
 * variable holding the rfc5915 (perhaps there is a better way, but
 * it worked).
 */


#define PRIVATE_KEY_prime256v1 \
 0xd9, 0xb5, 0xe7, 0x1f, 0x77, 0x28, 0xbf, 0xe5, 0x63, 0xa9, 0xdc, 0x93, 0x75, \
 0x62, 0x27, 0x7e, 0x32, 0x7d, 0x98, 0xd9, 0x94, 0x80, 0xf3, 0xdc, 0x92, 0x41, \
 0xe5, 0x74, 0x2a, 0xc4, 0x58, 0x89

#define PRIVATE_KEY_secp384r1 \
 0x63, 0x88, 0x1c, 0xbf, \
 0x86, 0x65, 0xec, 0x39, 0x27, 0x33, 0x24, 0x2e, 0x5a, 0xae, 0x63, 0x3a, \
 0xf5, 0xb1, 0xb4, 0x54, 0xcf, 0x7a, 0x55, 0x7e, 0x44, 0xe5, 0x7c, 0xca, \
 0xfd, 0xb3, 0x59, 0xf9, 0x72, 0x66, 0xec, 0x48, 0x91, 0xdf, 0x27, 0x79, \
 0x99, 0xbd, 0x1a, 0xbc, 0x09, 0x36, 0x49, 0x9c

#define PRIVATE_KEY_secp521r1 \
 0x00, 0x4b, 0x35, 0x4d, \
 0xa4, 0xab, 0xf7, 0xa5, 0x4f, 0xac, 0xee, 0x06, 0x49, 0x4a, 0x97, 0x0e, \
 0xa6, 0x5f, 0x85, 0xf0, 0x6a, 0x2e, 0xfb, 0xf8, 0xdd, 0x60, 0x9a, 0xf1, \
 0x0b, 0x7a, 0x13, 0xf7, 0x90, 0xf8, 0x9f, 0x49, 0x02, 0xbf, 0x5d, 0x5d, \
 0x71, 0xa0, 0x90, 0x93, 0x11, 0xfd, 0x0c, 0xda, 0x7b, 0x6a, 0x5f, 0x7b, \
 0x82, 0x9d, 0x79, 0x61, 0xe1, 0x6b, 0x31, 0x0a, 0x30, 0x6f, 0x4d, 0xf3, \
 0x8b, 0xe3

/*
 * Public function, see init_keys.h
 */
enum t_cose_err_t
init_fixed_test_signing_key(int32_t            cose_algorithm_id,
                            struct t_cose_key *key_pair)
{
    struct q_useful_buf_c key_bytes;

    static const uint8_t private_key_256[]     = {PRIVATE_KEY_prime256v1};
    static const uint8_t private_key_384[]     = {PRIVATE_KEY_secp384r1};
    static const uint8_t private_key_521[]     = {PRIVATE_KEY_secp521r1};
    static const uint8_t private_key_rsa2048[] = {
#include "rsa_test_key.h"
    };

    /* PSA doesn't support EdDSA so no keys for it here (OpenSSL does). */

    switch(cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(private_key_256);
        break;

    case T_COSE_ALGORITHM_ES384:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(private_key_384);
        break;

    case T_COSE_ALGORITHM_ES512:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(private_key_521);
        break;

    case T_COSE_ALGORITHM_PS256:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(private_key_rsa2048);
        break;

    case T_COSE_ALGORITHM_PS384:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(private_key_rsa2048);
        break;

    case T_COSE_ALGORITHM_PS512:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(private_key_rsa2048);
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    return init_signing_key_from_xx(cose_algorithm_id, key_bytes, key_pair);
}


/*
 * Public function, see init_keys.h
 */
void free_fixed_signing_key(struct t_cose_key key_pair)
{
    psa_destroy_key((psa_key_handle_t)key_pair.key.handle);
}




/* I don't know how thes were generated. Pretty sure they are related
 * to each other and were generated at the same time (or they wouldn't
 * work).
 *
 * Would also like to know exactly what the format is here.  Obviously
 * not DER, but what about x9?
 */
/* Example ECC public key (P256r1) */
static const uint8_t fixed_test_p256r1_public_key[] = {
  0x04, 0x6d, 0x35, 0xe7, 0xa0, 0x75, 0x42, 0xc1, 0x2c, 0x6d, 0x2a, 0x0d,
  0x2d, 0x45, 0xa4, 0xe9, 0x46, 0x68, 0x95, 0x27, 0x65, 0xda, 0x9f, 0x68,
  0xb4, 0x7c, 0x75, 0x5f, 0x38, 0x00, 0xfb, 0x95, 0x85, 0xdd, 0x7d, 0xed,
  0xa7, 0xdb, 0xfd, 0x2d, 0xf0, 0xd1, 0x2c, 0xf3, 0xcc, 0x3d, 0xb6, 0xa0,
  0x75, 0xd6, 0xb9, 0x35, 0xa8, 0x2a, 0xac, 0x3c, 0x38, 0xa5, 0xb7, 0xe8,
  0x62, 0x80, 0x93, 0x84, 0x55
};

/* Example ECC private key (P256r1) */
static const uint8_t fixed_test_p256r1_private_key[] = {
  0x37, 0x0b, 0xaf, 0x20, 0x45, 0x17, 0x01, 0xf6, 0x64, 0xe1, 0x28, 0x57,
  0x4e, 0xb1, 0x7a, 0xd3, 0x5b, 0xdd, 0x96, 0x65, 0x0a, 0xa8, 0xa3, 0xcd,
  0xbd, 0xd6, 0x6f, 0x57, 0xa8, 0xcc, 0xe8, 0x09
};


enum t_cose_err_t
init_fixed_test_encryption_key(int32_t            cose_algorithm_id,
                               struct t_cose_key *public_key,
                               struct t_cose_key *private_key)
{
    (void)cose_algorithm_id; // TODO: probably need to check this
    psa_status_t status;
    psa_key_attributes_t pkR_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t pkR_handle = PSA_KEY_HANDLE_INIT;

    psa_key_attributes_t skR_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t skR_handle = PSA_KEY_HANDLE_INIT;


    psa_crypto_init();

    
    /* Set up the recipient's public key, pkR, used for encrypting messages */
    /* Import public key */
    psa_set_key_usage_flags(&pkR_attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&pkR_attributes, PSA_ALG_ECDSA_ANY);
    psa_set_key_type(&pkR_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&pkR_attributes, /* in: attributes */
                            fixed_test_p256r1_public_key, /* in: key bytes */
                            sizeof(fixed_test_p256r1_public_key), /* in: key length */
                            &pkR_handle); /* out: PSA key handle */
    if(status != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL; // TODO: better error code?
    }

    public_key->key.handle = pkR_handle;

    /* Import private key */
    psa_set_key_usage_flags(&skR_attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&skR_attributes, PSA_ALG_ECDH);
    psa_set_key_type(&skR_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&skR_attributes,
                             fixed_test_p256r1_private_key, sizeof(fixed_test_p256r1_private_key),
                             &skR_handle);

    if (status != PSA_SUCCESS) {
        return T_COSE_ERR_FAIL; // TODO: better error code?
    }

    private_key->key.handle = skR_handle;

    return T_COSE_SUCCESS;
}


/*
 * Public function, see init_keys.h
 */
void
free_fixed_test_encryption_key(struct t_cose_key key_pair)
{
    psa_destroy_key((psa_key_handle_t)key_pair.key.handle);
}




/*
 * Public function, see init_keys.h
 */
int check_for_key_allocation_leaks(void)
{
    return 0;
}

