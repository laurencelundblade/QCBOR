/*
 * t_cose_signature_main.h
 *
 * Copyright (c) 2019-2023, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef t_cose_signature_main_h
#define t_cose_signature_main_h

/**
 * The maximum needed to hold a hash. It is smaller and less stack is needed
 * if the larger hashes are disabled.
 */
#if !defined(T_COSE_DISABLE_ES512) || !defined(T_COSE_DISABLE_PS512)
    #define T_COSE_MAIN_MAX_HASH_SIZE T_COSE_CRYPTO_SHA512_SIZE
#else
    #if !defined(T_COSE_DISABLE_ES384) || !defined(T_COSE_DISABLE_PS384)
        #define T_COSE_MAIN_MAX_HASH_SIZE T_COSE_CRYPTO_SHA384_SIZE
    #else
        #define T_COSE_MAIN_MAX_HASH_SIZE T_COSE_CRYPTO_SHA256_SIZE
    #endif
#endif

#endif /* t_cose_signature_main_h */
