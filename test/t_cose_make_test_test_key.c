/*
 *  t_cose_make_test_test_key.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose_make_test_pub_key.h" /* The interface implemented here */

#include "t_cose/t_cose_standard_constants.h"
#include <stddef.h>


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
/*
 * The main purpose of test keys is to test
 * t_cose using short-circuit signatures.
 * They are vacant because no key is required for
 * short circuit.
 */
enum t_cose_err_t make_key_pair(int32_t            cose_algorithm_id,
                                struct t_cose_key *key_pair)
{
    (void)cose_algorithm_id;
    
    key_pair->k.key_ptr  = NULL;
    key_pair->crypto_lib = T_COSE_CRYPTO_LIB_TEST;

    // TODO: track keys made, so it can be confirmed they are freed

    return T_COSE_SUCCESS;
}


/*
 * Public function, see t_cose_make_test_pub_key.h
 */
void free_key(struct t_cose_key key_pair)
{
    (void)key_pair;
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

enum t_cose_err_t make_hmac_key(int32_t cose_alg, struct t_cose_key *res_key)
{
    (void)cose_alg;
    (void)res_key;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}
