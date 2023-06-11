/*
 * t_cose_test_crypto.h
 *
 * Copyright 2022, Laurence Lundblade
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 * Created by Laurence Lundblade on 12/9/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_test_crypto_h
#define t_cose_test_crypto_h

struct t_cose_test_crypto_context {
    /* This is used to test the crypto_context feature. If its
     * value is SUCCESS, then operation is as normal. If it's
     * value is something else, then that error is returned.
     */
    enum t_cose_err_t test_error;
    /* This is used to test the restartable behaviour of t_cose. If its value
     * is greater than 1 when operating in restartable mode, then
     * T_COSE_ERR_SIG_IN_PROGRESS is returned instead of T_COSE_SUCCESS.
     */
    size_t sign_iterations_left;
};

#endif /* t_cose_test_crypto_h */
