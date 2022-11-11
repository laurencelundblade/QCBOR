/*
 * t_cose_recipient_dec_hpke.h
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_RECIPIENT_DEC_HPKE_H__
#define __T_COSE_RECIPIENT_DEC_HPKE_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "t_cose_parameters.h"
#include "t_cose_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief HPKE Decrypt Wrapper
 *
 * \param[in] cose_algorithm_id   COSE algorithm id
 * \param[in] pkE                 pkE buffer
 * \param[in] pkR                 pkR key
 * \param[in] ciphertext          Ciphertext buffer
 * \param[in] plaintext           Plaintext buffer
 * \param[out] plaintext_len      Length of the returned plaintext
 *
 * \retval T_COSE_SUCCESS
 *         HPKE decrypt operation was successful.
 * \retval T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG
 *         An unsupported algorithm was supplied to the function call.
 * \retval T_COSE_ERR_HPKE_DECRYPT_FAIL
 *         Decrypt operation failed.
 */
enum t_cose_err_t
t_cose_crypto_hpke_decrypt(int32_t                            cose_algorithm_id,
                           struct q_useful_buf_c              pkE,
                           struct t_cose_key                  pkR,
                           struct q_useful_buf_c              ciphertext,
                           struct q_useful_buf                plaintext,
                           size_t                            *plaintext_len);


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_RECIPIENT_DEC_HPKE_H__ */
