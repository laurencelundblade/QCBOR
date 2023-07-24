/*
 * t_cose_encrypt_decrypt_test.h
 *
 * Copyright 2023, Laurence Lundblade
 * Created by Laurence Lundblade on 2/26/23.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef t_cose_encrypt_decrypt_test_h
#define t_cose_encrypt_decrypt_test_h

#include <stdint.h>

int32_t base_encrypt_decrypt_test(void);

int32_t esdh_enc_dec_test(void);

int32_t decrypt_known_good(void);


#endif /* t_cose_encrypt_decrypt_test_h */
