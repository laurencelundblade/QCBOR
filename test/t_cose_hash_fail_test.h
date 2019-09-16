/*
 *  t_cose_hash_fail_test.h
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_hash_fail_test_h
#define t_cose_hash_fail_test_h

#include <stdint.h>

/**
 * \brief Test correct handling of hash function failures.
 *
 * \return non-zero on failure.
 *
 * This requires a slightly hacked version of the
 * OpenSSL integrated crypto.
 *
 * This test doesn't need to be run for every integration and every
 * regression. It's not a difficult part of the code to get right.
 */

int_fast32_t short_circuit_hash_fail_test(void);


#endif /* t_cose_hash_fail_test_h */
