/*
 * t_cose_test_crypto.h
 *
 * Copyright 2022, Laurence Lundblade
 * Created by Laurence Lundblade on 12/9/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_test_crypto_h
#define t_cose_test_crypto_h

/* This is used to test the crypto_context feature. If its
 * value is SUCCESS, then operation is as normal. If it's
 * value is something else, then that error is returned. */
struct t_cose_test_crypto_context {
    enum t_cose_err_t test_error;
};

#endif /* t_cose_test_crypto_h */
