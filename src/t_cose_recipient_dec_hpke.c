/**
 * \file t_cose_recipient_dec_hpke.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */


#ifndef T_COSE_DISABLE_HPKE

#include "t_cose/t_cose_recipient_dec_hpke.h"  /* Interface implemented */
#include "hpke.h"
#include "qcbor/qcbor.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_encrypt_enc.h"
#include <stdint.h>
#include <stdbool.h>
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_standard_constants.h"


/**
 * See definition in t_cose_recipient_dec_hpke.h
 */
enum t_cose_err_t
t_cose_crypto_hpke_decrypt(int32_t                cose_algorithm_id,
                           struct q_useful_buf_c  pkE,
                           struct t_cose_key      pkR,
                           struct q_useful_buf_c  ciphertext,
                           struct q_useful_buf    plaintext,
                           size_t                *plaintext_len)
{
    hpke_suite_t           suite;
    size_t                 key_bitlen;
    int                    ret;

    /* Setting key distribution parameters. */
    switch(cose_algorithm_id) {
    case T_COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM:
        key_bitlen = 128;
        suite.kem_id = HPKE_KEM_ID_P256;
        suite.kdf_id = HPKE_KDF_ID_HKDF_SHA256;
        suite.aead_id = HPKE_AEAD_ID_AES_GCM_128;
        break;

    case T_COSE_ALGORITHM_HPKE_P521_HKDF512_AES256_GCM:
        key_bitlen = 256;
        suite.kem_id = HPKE_KEM_ID_P521;
        suite.kdf_id = HPKE_KDF_ID_HKDF_SHA512;
        suite.aead_id = HPKE_AEAD_ID_AES_GCM_256;
        break;

    default:
        return(T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG);
    }

    /* Execute HPKE */
    *plaintext_len = plaintext.len;

    ret = mbedtls_hpke_decrypt(
            HPKE_MODE_BASE,                  // HPKE mode
            suite,                           // ciphersuite
            NULL, 0, NULL,                   // PSK for authentication
            0, NULL,                         // pkS
            (psa_key_handle_t)
            pkR.k.key_handle,                // skR handle
            pkE.len,                         // pkE_len
            (unsigned char *) pkE.ptr,       // pkE
            ciphertext.len,                  // Ciphertext length
            (unsigned char *)
                ciphertext.ptr,              // Ciphertext
            0, NULL,                         // Additional data
            0, NULL,                         // Info
            plaintext_len,                   // Plaintext length
            (uint8_t *) plaintext.ptr        // Plaintext
        );

    if (ret != 0) {
        return(T_COSE_ERR_HPKE_DECRYPT_FAIL);
    }

    return(T_COSE_SUCCESS);
}

#else /* T_COSE_DISABLE_HPKE */

/* Place holder for compiler tools that don't like files with no functions */
void t_cose_recipient_dec_hpke(void) {}

#endif /* T_COSE_DISABLE_HPKE */
