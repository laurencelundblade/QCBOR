/*
 * encryption_examples.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright 2023, Laurence Lundblade
 *
 * Created by Laurence Lundblade on 2/6/23 from previous files.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef encryption_examples_h
#define encryption_examples_h

#include <stdint.h>

int32_t key_wrap_example(void);

int32_t encrypt0_example(void);

int32_t esdh_example(void);

int32_t esdh_example_detached(void);

#endif /* encryption_examples_h */
