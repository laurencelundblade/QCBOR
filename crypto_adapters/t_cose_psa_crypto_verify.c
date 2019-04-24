/*
 * Copyright (c) 2019, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "t_cose_crypto.h"
#include "psa_crypto.h"

/* Avoid compiler warning due to unused argument */
#define ARG_UNUSED(arg) (void)(arg)

enum t_cose_err_t
t_cose_crypto_pub_key_verify(int32_t cose_alg_id,
                             int32_t key_select,
                             struct q_useful_buf_c key_id,
                             struct q_useful_buf_c hash_to_verify,
                             struct q_useful_buf_c signature)
{
    /* FIXME: Implement this function to call psa_asymmetric_verify() when
     *        it will be supported by Crypto service in TF-M.
     */
    ARG_UNUSED(cose_alg_id);
    ARG_UNUSED(key_select);
    ARG_UNUSED(key_id);
    ARG_UNUSED(hash_to_verify);
    ARG_UNUSED(signature);

    return T_COSE_SUCCESS;
}
