/*
 *  t_cose_test.h
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_test_h
#define t_cose_test_h

#include <stdint.h>

/**
 * \brief Minimal token creation test using a short-circuit signature.
 *
 * \return non-zero on failure.
 */
int_fast32_t minimal_test(void);


int_fast32_t early_error_test(void);



#endif /* t_cose_test_h */
