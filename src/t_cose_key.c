/*
 * t_cose_key.c
 *
 * Copyright 2023, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Created by Laurence Lundblade on 2/6/23.
 *
 * See BSD-3-Clause license in README.md
 */
#include "t_cose/t_cose_key.h"
#include "t_cose_crypto.h"


/*
 * Public function. See t_cose_key.h
 */
enum t_cose_err_t
t_cose_key_init_symmetric(int32_t                cose_algorithm_id,
                          struct q_useful_buf_c  symmetric_key,
                          struct t_cose_key     *key)
{
    return  t_cose_crypto_make_symmetric_key_handle(cose_algorithm_id,
                                                    symmetric_key,
                                                    key);
}


/*
 * Public function. See t_cose_key.h
 */
void
t_cose_key_free_symmetric(struct t_cose_key key)
{
    t_cose_crypto_free_symmetric_key(key);
}

