/*
 *  t_cose_make_openssl_test_key.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose_make_test_pub_key.h" /* The interface implemented here */

#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/evp.h"



/*
 * Public function, see t_cose_make_test_pub_key.h
 */
/*
 * The key object returned by this is malloced and has to be freed by
 * by calling free_ecdsa_key_pair(). This heap use is a part of
 * OpenSSL and not t_cose which does not use the heap
 */
enum t_cose_err_t make_ecdsa_key_pair(int32_t            cose_algorithm_id,
                                      struct t_cose_key *key_pair)
{
    enum t_cose_err_t  return_value;
    int                ossl_result;
    int                ossl_nid;
    EVP_PKEY          *pkey = NULL;
    EVP_PKEY_CTX      *ctx;

    switch (cose_algorithm_id) {
    case T_COSE_ALGORITHM_ES256:
        ossl_nid  = NID_X9_62_prime256v1;
        break;

    case T_COSE_ALGORITHM_ES384:
        ossl_nid = NID_secp384r1;
        break;

    case T_COSE_ALGORITHM_ES512:
        ossl_nid = NID_secp521r1;
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if(ctx == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        return_value = T_COSE_ERR_FAIL;
        goto Done;
    }

    ossl_result = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, ossl_nid);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_FAIL;
        goto Done;
    }

    pkey = EVP_PKEY_new();

    ossl_result = EVP_PKEY_keygen(ctx, &pkey);

    if(ossl_result != 1) {
        return_value = T_COSE_ERR_FAIL;
        goto Done;
    }

    key_pair->k.key_ptr  = pkey;
    key_pair->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    return_value         = T_COSE_SUCCESS;

Done:
    return return_value;
}


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
void free_ecdsa_key_pair(struct t_cose_key key_pair)
{
    EVP_PKEY_free(key_pair.k.key_ptr);
}


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
int check_for_key_pair_leaks()
{
    /* So far no good way to do this for OpenSSL or malloc() in general
       in a nice portable way. The PSA version does check so there is
       some coverage of the code even though there is no check here.
     */
    return 0;
}



