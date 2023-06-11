/*
 * t_cose_psa_crypto.h
 *
 * Copyright 2022, Laurence Lundblade
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_psa_crypto_h
#define t_cose_psa_crypto_h

#include <psa/crypto.h>

#define PSA_CRYPTO_HAS_RESTARTABLE_SIGNING \
    ((MBEDTLS_VERSION_MAJOR == 3 && MBEDTLS_VERSION_MINOR >= 4) || \
     MBEDTLS_VERSION_MAJOR > 3)

#if PSA_CRYPTO_HAS_RESTARTABLE_SIGNING
struct t_cose_psa_crypto_context {
    psa_sign_hash_interruptible_operation_t operation;
};
#endif /* PSA_CRYPTO_HAS_RESTARTABLE_SIGNING */

#endif /* t_cose_psa_crypto_h */
