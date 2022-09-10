/*
 *  t_cose_make_test_pub_key.h
 *
 * Copyright 2019-2020, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/t_cose_common.h"
#include <stdint.h>

/**
 * \file t_cose_make_test_pub_key.h
 *
 * \brief This defines a simple interface to make keys for tests cases.
 *
 */


/**
 * \brief make an ECDSA key pair for testing suited to algorim
 *
 */
enum t_cose_err_t make_ecdsa_key_pair(int32_t            cose_algorithm_id,
                                      struct t_cose_key *key_pair);

enum t_cose_err_t make_hmac_key(uint8_t cose_alg, struct t_cose_key *key);

void free_key(struct t_cose_key key_pair);


/**
 \brief Called by test frame work to see if there were key pair or mem leaks.

 \return 0 if no leaks, non-zero if there is a leak.
 */
int check_for_key_pair_leaks(void);



