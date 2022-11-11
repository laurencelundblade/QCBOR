/*
 * t_cose_recipient_enc_hpke.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_RECIPIENT_ENC_HPKE_H__
#define __T_COSE_RECIPIENT_ENC_HPKE_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "t_cose_parameters.h"
#include "t_cose_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Creating a COSE recipient for use with HPKE.
 *
 * \param[in] context                COSE recipient context for use with HPKE
 * \param[in] cose_algorithm_id      Algorithm id
 * \param[in] recipient_key          Recipient key
 * \param[in] plaintext              Plaintext (typically the CEK)
 * \param[out] encrypt_ctx           Resulting encryption structure
 *
 * \retval T_COSE_SUCCESS
 *         Operation was successful.
 * \retval Error messages otherwise.
 */
enum t_cose_err_t t_cose_create_recipient_hpke(
                           void                                *context,
                           int32_t                              cose_algorithm_id,
                           struct t_cose_key                    recipient_key,
                           struct q_useful_buf_c                plaintext,
                           QCBOREncodeContext                  *encrypt_ctx);

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_ENC_HPKE_H__ */
