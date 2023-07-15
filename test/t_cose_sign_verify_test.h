/*
 *  t_cose_sign_verify_test.h
 *
 * Copyright 2019, 2022, Laurence Lundblade
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_sign_verify_test_h
#define t_cose_sign_verify_test_h

#include <stdint.h>


/**
 * \file t_cose_sign_verify_test.h
 *
 * \brief Tests that need public key crypto to be implemented
 */


/**
 * \brief Self test using integrated  crypto.
 *
 * \return non-zero on failure.
 */
int32_t sign_verify_basic_test(void);


/*
 * Sign some data, perturb the data and see that sig validation fails
 */
int32_t sign_verify_sig_fail_test(void);


/*
 * Make a CWT and compare it to the one in the CWT RFC
 */
int32_t sign_verify_make_cwt_test(void);


/*
 * Test the ability to calculate size of a COSE_Sign1
 */
int32_t sign_verify_get_size_test(void);


/*
 * Test against known good messages.
 */
int32_t sign_verify_known_good_test(void);


/*
 * Test the return value when using an unsupported algorithm.
 */
int32_t sign_verify_unsupported_test(void);


/*
 * Test the return value when using a small or no auxiliary buffer.
 */
int32_t sign_verify_bad_auxiliary_buffer(void);


/*
 * Test creation and verification of COSE_Sign with multiple COSE_Signatures
 */
int32_t sign_verify_multi(void);



int32_t verify_multi_test(void);


/*
 * Test restartable behaviour
 */
int32_t restart_test_2_step(void);

#endif /* t_cose_sign_verify_test_h */
