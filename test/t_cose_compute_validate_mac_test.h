/*
 *  t_cose_compute_validate_mac_test.h
 *
 * Copyright 2019, 2022, Laurence Lundblade
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_compute_validate_mac_test_h
#define t_cose_compute_validate_mac_test_h

#include <stdint.h>


/**
 * \file t_cose_compute_validate_mac_test.h
 *
 * \brief Tests that need symmetric key crypto to be implemented
 */


/**
 * \brief Self test using integrated crypto.
 *
 * \return non-zero on failure.
 */
int32_t compute_validate_mac_basic_test(void);


/*
 * Compute MAC of some data, perturb the data and see that MAC validation fails.
 */
int32_t compute_validate_mac_fail_test(void);


/*
 * Test the ability to calculate size of a COSE_Mac0.
 */
int32_t compute_validate_get_size_mac_test(void);


/*
 * Compute MAC of some data, perturb the data and see that MAC validation fails.
 */
int32_t compute_validate_detached_content_mac_fail_test(void);


/*
 * Test the ability to calculate size of a COSE_Mac0.
 */
int32_t compute_validate_get_size_detached_content_mac_test(void);

#endif /* t_cose_compute_validate_mac_test_h */
