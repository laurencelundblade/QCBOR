/*
 *  t_cose_openssl_test.h
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_openssl_test_h
#define t_cose_openssl_test_h

#include <stdint.h>

/**
 * \brief Self test using openssl crypto.
 *
 * \return non-zero on failure.
 */
int_fast32_t openssl_self_test(void);


int_fast32_t openssl_sig_fail_test(void);

int_fast32_t openssl_make_cwt_test(void);


#endif /* t_cose_openssl_test */
