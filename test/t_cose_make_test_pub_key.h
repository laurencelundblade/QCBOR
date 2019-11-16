/*
 *  t_cose_make_test_pub_key.h
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose_common.h"
#include <stdint.h>


/**
 * \brief make an ECDSA key pair for testing suited to algorim
 *
 */
enum t_cose_err_t make_ecdsa_key_pair(int32_t            cose_algorithm_id,
                                      struct t_cose_key *key_pair);


void free_ecdsa_key_pair(struct t_cose_key key_pair);


