/*
 *  t_cose_param_test.h
 *
 * Copyright 2022-2023, Laurence Lundblade
 * Created by Laurence Lundblade on 9/20/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef t_cose_param_test_h
#define t_cose_param_test_h

#include <stdint.h>


/* This tests the generic params encoding and decoding functions */
int32_t param_test(void);

/* This tests the utility functions for specific params like alg ID and iv */
int32_t common_params_test(void);

#endif /* t_cose_param_test_h */
