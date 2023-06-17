/*
 * init_keys_test.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_key.h"


/*
 * Public function, see init_keys.h
 */
enum t_cose_err_t
init_fixed_test_signing_key(int32_t            cose_ec_curve_id,
                            struct t_cose_key *key_pair)
{
    (void)cose_ec_curve_id;
    (void)key_pair;
    return T_COSE_SUCCESS;
}


/*
 * Public function, see init_keys.h
 */
void free_fixed_signing_key(struct t_cose_key key_pair)
{
    (void)key_pair;
}




/*
 * Public function, see init_key.h
 */
enum t_cose_err_t
init_fixed_test_ec_encryption_key(int32_t            cose_algorithm_id,
                                  struct t_cose_key *public_key,
                                  struct t_cose_key *private_key)
{
    (void)cose_algorithm_id;
    (void)public_key;
    (void)private_key;
    return T_COSE_SUCCESS;
}


/*
 * Public function, see init_key.h
 */
void
free_fixed_test_ec_encryption_key(struct t_cose_key key_pair)
{
    (void)key_pair;
}




/*
 * Public function, see init_keys.h
 */
int check_for_key_allocation_leaks(void)
{
    return 0;
}
