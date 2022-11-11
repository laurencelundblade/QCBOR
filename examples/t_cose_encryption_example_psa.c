/*
 *  t_cose_encryption_example_psa.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_encrypt_dec.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_parameters.h"
#include "psa/crypto.h"
#include "t_cose_crypto.h"

#define DETACHED_PAYLOAD     1
#define INCLUDED_PAYLOAD     2

#define BUFFER_SIZE       1024

static void print_bytestr(const uint8_t *bytes, size_t len)
{
    for(unsigned int idx = 0; idx<len; idx++)
    {
        printf("%02X",bytes[idx]);
    }
}

/* PSKs */
uint8_t psk[] = "aaaaaaaaaaaaaaaa";
uint8_t psk2[] = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb";

/* PSK IDs */
uint8_t psk_kid[] = "kid-1";
uint8_t psk2_kid[] = "kid-1a";

/* Remove trailing null byte in the size calculations below */
size_t psk_key_len = sizeof(psk)-1;
size_t psk_kid_len = sizeof(psk_kid)-1;
size_t psk2_key_len = sizeof(psk2)-1;
size_t psk2_kid_len = sizeof(psk2_kid)-1;

/* Example ECC public key (P256r1) */
uint8_t public_key[] = {
  0x04, 0x6d, 0x35, 0xe7, 0xa0, 0x75, 0x42, 0xc1, 0x2c, 0x6d, 0x2a, 0x0d,
  0x2d, 0x45, 0xa4, 0xe9, 0x46, 0x68, 0x95, 0x27, 0x65, 0xda, 0x9f, 0x68,
  0xb4, 0x7c, 0x75, 0x5f, 0x38, 0x00, 0xfb, 0x95, 0x85, 0xdd, 0x7d, 0xed,
  0xa7, 0xdb, 0xfd, 0x2d, 0xf0, 0xd1, 0x2c, 0xf3, 0xcc, 0x3d, 0xb6, 0xa0,
  0x75, 0xd6, 0xb9, 0x35, 0xa8, 0x2a, 0xac, 0x3c, 0x38, 0xa5, 0xb7, 0xe8,
  0x62, 0x80, 0x93, 0x84, 0x55
};

/* Example ECC private key (P256r1) */
uint8_t private_key[] = {
  0x37, 0x0b, 0xaf, 0x20, 0x45, 0x17, 0x01, 0xf6, 0x64, 0xe1, 0x28, 0x57,
  0x4e, 0xb1, 0x7a, 0xd3, 0x5b, 0xdd, 0x96, 0x65, 0x0a, 0xa8, 0xa3, 0xcd,
  0xbd, 0xd6, 0x6f, 0x57, 0xa8, 0xcc, 0xe8, 0x09
};

/* ID for public key id */
uint8_t pk_kid[] = "kid-2";

/* Public key id length and Public key length */
size_t pk_key_len = sizeof(public_key);
size_t pk_kid_len = sizeof(pk_kid)-1;

int test_cose_encrypt(uint32_t options,
                      uint8_t *firmware, size_t firmware_len,
                      uint8_t *cose_encrypt_buf, size_t cose_encrypt_buf_len,
                      size_t *cose_encrypt_result_len,
                      uint8_t *encrypted_firmware, size_t encrypted_firmware_len,
                      size_t *encrypted_firmware_result_len,
                      int32_t algorithm,
                      int32_t key_exchange,
                      struct t_cose_key recipient_key,
                      struct q_useful_buf_c kid
                     )
{
    struct t_cose_encrypt_enc_ctx enc_ctx;
    enum t_cose_err_t result;
    struct q_useful_buf encrypted_firmware_final = {0,0};

    struct q_useful_buf_c encrypt_cose;

    /* Initialize encryption context */
    t_cose_encrypt_enc_init(&enc_ctx, options, algorithm);

    /* Add a recipient. */
    result = t_cose_encrypt_add_recipient(
                        &enc_ctx,
                        key_exchange,
                        recipient_key,
                        kid);

    if (result != 0) {
        printf("error adding recipient (%d)\n", result);
        return(EXIT_FAILURE);
    }

    result = t_cose_encrypt_enc(
                    &enc_ctx,
                    /* Pointer and length of payload to be
                     * encrypted.
                     */
                    (struct q_useful_buf_c)
                    {
                    .ptr = firmware,
                    .len = firmware_len
                    },
                    /* Non-const pointer and length of the
                     * buffer where the encrypted payload
                     * is written to. The length here is that
                     * of the whole buffer.
                     */
                    (struct q_useful_buf)
                    {
                    .ptr = encrypted_firmware,
                    .len = encrypted_firmware_len
                    },
                    /* Const pointer and actual length of
                     * the encrypted payload.
                     */
                    &encrypted_firmware_final,
                    /* Non-const pointer and length of the
                     * buffer where the completed output is
                     * written to. The length here is that
                     * of the whole buffer.
                     */
                    (struct q_useful_buf)
                    {
                    .ptr = cose_encrypt_buf,
                    .len = cose_encrypt_buf_len
                    },
                    /* Const pointer and actual length of
                     * the COSE_Encrypt message.
                     * This structure points into the
                     * output buffer and has the
                     * lifetime of the output buffer.
                     */
                    &encrypt_cose);

    if (result != 0) {
        printf("error encrypting (%d)\n", result);
        return(EXIT_FAILURE);
    }

    *cose_encrypt_result_len = encrypt_cose.len;
    *encrypted_firmware_result_len = encrypted_firmware_final.len;

    return(EXIT_SUCCESS);
}


int main(void)
{
    psa_status_t status;
    uint8_t firmware[] = "This is a real plaintext.";
    size_t firmware_len = sizeof(firmware);
    uint8_t encrypted_firmware[BUFFER_SIZE] = {0};
    size_t encrypted_firmware_len = sizeof(encrypted_firmware)-1;
    uint8_t buffer[BUFFER_SIZE] = {0};
    size_t result_len;
    size_t encrypted_firmware_result_len;
    int res = 0;
   psa_key_attributes_t psk_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t psk_handle = 0;

    /* Key id for PSK */
    struct q_useful_buf_c kid1 = {psk_kid, psk_kid_len};
    /* Key id for public key */
    /* Key id for PSK 2 */

    struct t_cose_key t_cose_psk_key;

#ifndef T_COSE_DISABLE_HPKE
    struct t_cose_key t_cose_pkR_key;
    psa_key_attributes_t pkR_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t pkR_handle = PSA_KEY_HANDLE_INIT;

    struct t_cose_key t_cose_skR_key;
    psa_key_attributes_t skR_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t skR_handle = PSA_KEY_HANDLE_INIT;
#endif

    /* -------------------------------------------------------------------------*/

    /* Initialize PSA Crypto  */
    // TODO: document that this is required or build it into the crypto layer
    // Note that was not required for signing
    status = psa_crypto_init();

    if (status != PSA_SUCCESS) {
        return(EXIT_FAILURE);
    }

#ifndef T_COSE_DISABLE_HPKE

    /* Import public key */
    psa_set_key_usage_flags(&pkR_attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&pkR_attributes, PSA_ALG_ECDSA_ANY);
    psa_set_key_type(&pkR_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&pkR_attributes,
                            public_key, pk_key_len,
                            &pkR_handle);

    if (status != PSA_SUCCESS) {
        printf("psa_import_key failed\n");
        return(EXIT_FAILURE);
    }

    t_cose_pkR_key.k.key_handle = pkR_handle;
    t_cose_pkR_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;


    /* Import private key */
    psa_set_key_usage_flags(&skR_attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&skR_attributes, PSA_ALG_ECDH);
    psa_set_key_type(&skR_attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&skR_attributes,
                            private_key, sizeof(private_key),
                            &skR_handle);

    if (status != PSA_SUCCESS) {
        printf("Import of key failed\n");
        return(EXIT_FAILURE);
    }

    t_cose_skR_key.k.key_handle = skR_handle;
    t_cose_skR_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;
    #endif

    /* Import PSK */
    psa_set_key_usage_flags(&psk_attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&psk_attributes, PSA_ALG_GCM);
    psa_set_key_type(&psk_attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&psk_attributes, 128);

    status = psa_import_key(&psk_attributes,
                            psk, psk_key_len,
                            &psk_handle);

    if (status != PSA_SUCCESS) {
        printf("Importing key failed\n");
        return(EXIT_FAILURE);
    }

    t_cose_psk_key.k.key_handle = psk_handle;
    t_cose_psk_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;


    /* -------------------------------------------------------------------------*/
#ifndef T_COSE_DISABLE_HPKE

    printf("\n-- 1a. Create COSE_Encrypt with detached payload using HPKE--\n\n");

    res = test_cose_encrypt(T_COSE_OPT_COSE_ENCRYPT_DETACHED,
                            firmware, firmware_len,
                            buffer, sizeof(buffer),
                            &result_len,
                            encrypted_firmware, encrypted_firmware_len,
                            &encrypted_firmware_result_len,
                            T_COSE_ALGORITHM_A128GCM,
                            T_COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM,
                            t_cose_pkR_key,
                            kid2);

    if (res != EXIT_SUCCESS) {
        return(EXIT_FAILURE);
    }

    printf("COSE: ");
    print_bytestr(buffer, result_len);

    printf("\n\nCiphertext: ");
    print_bytestr(encrypted_firmware, encrypted_firmware_result_len);
    printf("\n");

    printf("\n-- 1b. Process COSE_Encrypt with detached payload using HPKE --\n\n");

    t_cose_encrypt_dec_init(&dec_ctx, 0, T_COSE_KEY_DISTRIBUTION_HPKE);

    t_cose_encrypt_dec_set_private_key(&dec_ctx, t_cose_skR_key, kid2);

    ret = t_cose_encrypt_dec(&dec_ctx,
                             buffer, result_len, //sizeof(buffer),
                             encrypted_firmware, encrypted_firmware_result_len,
                             plaintext, sizeof(plaintext),
                             &plaintext_output_len);

    if (ret != T_COSE_SUCCESS) {
        printf("\nDecryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("\nPlaintext: ");
    printf("%s\n", plaintext);

    memset(buffer, 0, sizeof(buffer));
    memset(encrypted_firmware, 0, encrypted_firmware_len);
    memset(plaintext, 0, plaintext_output_len);

    /* -------------------------------------------------------------------------*/

    printf("\n-- 2a. Create COSE_Encrypt with included payload using HPKE--\n\n");
    test_cose_encrypt(0,
                      firmware, firmware_len,
                      buffer, sizeof(buffer),
                      &result_len,
                      encrypted_firmware, encrypted_firmware_len,
                      &encrypted_firmware_result_len,
                      T_COSE_ALGORITHM_A128GCM,
                      T_COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM,
                      t_cose_skR_key,
                      kid2);

    printf("COSE: ");
    print_bytestr(buffer, result_len);
    printf("\n");

    printf("\n-- 2b. Process COSE_Encrypt with included payload using HPKE --\n\n");

    t_cose_encrypt_dec_init(&dec_ctx, 0, T_COSE_KEY_DISTRIBUTION_HPKE);

    t_cose_encrypt_dec_set_private_key(&dec_ctx, t_cose_skR_key, kid2);

    ret = t_cose_encrypt_dec(&dec_ctx,
                             buffer, sizeof(buffer),
                             NULL, 0,
                             plaintext, sizeof(plaintext),
                             &plaintext_output_len);

    if (ret != T_COSE_SUCCESS) {
        printf("\nDecryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("\nPlaintext: ");
    printf("%s\n", plaintext);

    memset(buffer, 0, sizeof(buffer));
    memset(encrypted_firmware, 0, encrypted_firmware_len);
    memset(plaintext, 0, plaintext_output_len);
#endif /* T_COSE_DISABLE_HPKE */

    /* -------------------------------------------------------------------------*/

    printf("\n-- 3a. Create COSE_Encrypt0 with detached payload (direct encryption) --\n\n");

    res = test_cose_encrypt(T_COSE_OPT_COSE_ENCRYPT0 | T_COSE_OPT_COSE_ENCRYPT_DETACHED,
                            firmware, firmware_len,
                            buffer, sizeof(buffer),
                            &result_len,
                            encrypted_firmware, encrypted_firmware_len,
                            &encrypted_firmware_result_len,
                            T_COSE_ALGORITHM_A128GCM,
                            T_COSE_ALGORITHM_RESERVED,
                            t_cose_psk_key,
                            kid1);

    if (res != 0) {
        printf("\nEncryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("COSE: ");
    print_bytestr(buffer, result_len);
    printf("\n\nCiphertext: ");
    print_bytestr(encrypted_firmware, encrypted_firmware_result_len);
    printf("\n");
#ifndef T_COSE_DISABLE_HPKE

    printf("\n-- 3b. Process COSE_Encrypt0 with detached payload (direct encryption) --\n\n");
    /* This doesn't work and is disable with HPKE because the decryption
     * side is not refactored to separate out direct, KW and HPKE */


    t_cose_encrypt_dec_init(&dec_ctx, 0, T_COSE_KEY_DISTRIBUTION_DIRECT);

    t_cose_encrypt_dec_set_private_key(&dec_ctx, t_cose_psk_key, kid1);

    ret = t_cose_encrypt_dec(&dec_ctx,
                             buffer, sizeof(buffer),
                             encrypted_firmware, encrypted_firmware_result_len,
                             plaintext, sizeof(plaintext),
                             &plaintext_output_len);

    if (ret != T_COSE_SUCCESS) {
        printf("\nDecryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("\nPlaintext: ");
    printf("%s\n", plaintext);

    memset(buffer, 0, sizeof(buffer));
    memset(encrypted_firmware, 0, encrypted_firmware_len);
    memset(plaintext, 0, plaintext_output_len);
#endif /* T_COSE_DISABLE_HPKE */

#ifndef T_COSE_DISABLE_AES_KW
    /* -------------------------------------------------------------------------*/

    printf("\n-- 4a. Create COSE_Encrypt with detached payload using AES-KW --\n\n");

    res = test_cose_encrypt(T_COSE_OPT_COSE_ENCRYPT_DETACHED,
                            firmware, firmware_len,
                            buffer, sizeof(buffer),
                            &result_len,
                            encrypted_firmware, encrypted_firmware_len,
                            &encrypted_firmware_result_len,
                            T_COSE_ALGORITHM_A128GCM,
                            T_COSE_ALGORITHM_A128KW,
                            t_cose_psk_key,
                            kid1);

    if (res != 0) {
        printf("\nEncryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("COSE: ");
    print_bytestr(buffer, result_len);
    printf("\n\nCiphertext: ");
    print_bytestr(encrypted_firmware, encrypted_firmware_result_len);
    printf("\n");

    memset(buffer, 0, sizeof(buffer));
    memset(encrypted_firmware, 0, encrypted_firmware_len);
#ifndef T_COSE_DISABLE_HPKE
    memset(plaintext, 0, plaintext_output_len);
#endif /* T_COSE_DISABLE_HPKE */

#endif /* T_COSE_DISABLE_AES_KW */
    /* -------------------------------------------------------------------------*/

    psa_destroy_key(psk_handle);
#ifndef T_COSE_DISABLE_HPKE

    psa_destroy_key(skR_handle);
    psa_destroy_key(pkR_handle);
#endif

    return(0);
}
