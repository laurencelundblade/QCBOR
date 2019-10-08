/*
 *  t_cose_hash_fail_test.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose_hash_fail_test.h"
#include "t_cose_sign1_sign.h"
#include "t_cose_sign1_verify.h"
#include "q_useful_buf.h"

/* Special global external reference to special crypto to test
 * handling of hash failures. They generally never fail so it requires
 * a hacked version of the hash adaptor to implement this test.
 */
extern int hash_test_mode;


int_fast32_t short_circuit_hash_fail_test()
{
    struct t_cose_sign1_ctx     sign_ctx;
    enum t_cose_err_t           return_value;
    struct q_useful_buf_c       wrapped_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB( signed_cose_buffer, 200);


    /* Set the global variable to cause the hash implementation to
     * error out so this test can see what happens
     */
    hash_test_mode = 1;

    t_cose_sign1_init(&sign_ctx, T_COSE_OPT_SHORT_CIRCUIT_SIG, COSE_ALGORITHM_ES256);

    return_value = t_cose_sign1_sign(&sign_ctx,
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"),
                                     signed_cose_buffer,
                                     &wrapped_payload);

    hash_test_mode = 0;

    if(return_value != T_COSE_ERR_UNSUPPORTED_HASH) {
        return 2000 + return_value;
    }


    /* Set the global variable to cause the hash implementation to
     * error out so this test can see what happens
     */
    hash_test_mode = 2;

    t_cose_sign1_init(&sign_ctx, T_COSE_OPT_SHORT_CIRCUIT_SIG, COSE_ALGORITHM_ES256);

    return_value = t_cose_sign1_sign(&sign_ctx,
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"),
                                     signed_cose_buffer,
                                     &wrapped_payload);

    hash_test_mode = 0;

    if(return_value != T_COSE_ERR_HASH_GENERAL_FAIL) {
        return 2000 + return_value;
    }

    return 0;
}
