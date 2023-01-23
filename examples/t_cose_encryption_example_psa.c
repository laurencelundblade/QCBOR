/*
 *  t_cose_encryption_example_psa.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright 2023, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


/* The point of this file is to give clear examples
 * to the user of the API, so each example type is
 * laid out separately. This results in some intentional
 * code duplication.
 *
 * Testing of encryption is elsewhere, but these will be (are)
 * run during test to test that the example code is correct.
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
#include "t_cose/t_cose_recipient_enc_hpke.h"

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

#define KID2 "kid2"


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

enum t_cose_err_t
make_psa_symmetric_key_handle(int32_t               cose_algorithm_id,
                              struct q_useful_buf_c symmetric_key,
                              struct t_cose_key    *key_handle)
{
    psa_algorithm_t        psa_algorithm;
    psa_key_handle_t       psa_key_handle;
    psa_status_t           status;
    psa_key_attributes_t   attributes = PSA_KEY_ATTRIBUTES_INIT;
    size_t                 key_bitlen;
    psa_key_type_t         psa_keytype;

    psa_crypto_init();


    switch (cose_algorithm_id) {
        case T_COSE_ALGORITHM_A128GCM:
            psa_algorithm = PSA_ALG_GCM;
            psa_keytype = PSA_KEY_TYPE_AES;
            key_bitlen = 128;
            break;

        case T_COSE_ALGORITHM_A192GCM:
            psa_algorithm = PSA_ALG_GCM;
            psa_keytype = PSA_KEY_TYPE_AES;
            key_bitlen = 192;
            break;

        case T_COSE_ALGORITHM_A256GCM:
            psa_algorithm = PSA_ALG_GCM;
            psa_keytype = PSA_KEY_TYPE_AES;
            key_bitlen = 256;
            break;

        default:
            return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }


    // TODO: PSA_KEY_USAGE_EXPORT required because of the way t_cose_crypto AES works. Maybe that should change
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, psa_algorithm);
    psa_set_key_type(&attributes, psa_keytype);
    psa_set_key_bits(&attributes, key_bitlen);

    status = psa_import_key(&attributes,
                             symmetric_key.ptr,
                             symmetric_key.len,
                            &psa_key_handle);

    if (status != PSA_SUCCESS) {
        return T_COSE_ERR_KEY_IMPORT_FAILED;
    }

    key_handle->k.key_handle = psa_key_handle;
    key_handle->crypto_lib   = T_COSE_CRYPTO_LIB_PSA;

    return T_COSE_SUCCESS;
}



/**
 * \brief  Free a PSA / MBed key.
 *
 * \param[in] key_pair   The key pair to close / deallocate / free.
 */
void free_psa_key(struct t_cose_key key_pair)
{
    psa_close_key((psa_key_id_t)key_pair.k.key_handle);
}


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
    struct t_cose_encrypt_enc enc_ctx;
    enum t_cose_err_t result;
    struct q_useful_buf_c encrypted_firmware_final;
    struct t_cose_recipient_enc_hpke recipient;
    struct q_useful_buf_c encrypt_cose;

    t_cose_recipient_enc_hpke_init(&recipient, key_exchange);
    t_cose_recipient_enc_hpke_set_key(&recipient,
                                       recipient_key,
                                       kid);

    /* Initialize encryption context */
    t_cose_encrypt_enc_init(&enc_ctx, options, algorithm);

    /* Add a recipient. */
    t_cose_encrypt_add_recipient(&enc_ctx,
                                 (struct t_cose_recipient_enc *)&recipient);


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


#include "t_cose/t_cose_recipient_enc_aes_kw.h"
static int key_wrap_example(void)
{
    struct t_cose_recipient_enc_keywrap kw_recipient;
    struct t_cose_encrypt_enc       enc_context;
    enum t_cose_err_t                   err;
    struct t_cose_key                   kek;
    struct q_useful_buf_c               encrypted_cose_message;
    struct q_useful_buf_c               encrypted_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB(         cose_message_buf, 1024);
    Q_USEFUL_BUF_MAKE_STACK_UB(         encrypted_payload_buf, 1024);


    printf("\n-- 4a. Create COSE_Encrypt with detached payload using AES-KW --\n\n");


    /* ---- Make key handle for wrapping key -----
     *
     * The wrapping key, the KEK, is just the bytes "aaaa....".  The
     * API requires input keys be struct t_cose_key so there's a
     * little work to do.
     */
    // TODO: should th algorithm ID be T_COSE_ALGORITHM_A128KW?
    make_psa_symmetric_key_handle(T_COSE_ALGORITHM_A128GCM,
                                  Q_USEFUL_BUF_FROM_SZ_LITERAL("aaaaaaaaaaaaaaaa"),
                                  &kek);

    /* ---- Set up keywrap recipient object ----
     *
     * The initializes an object of type struct
     * t_cose_recipient_enc_keywrap, the object/context for making a
     * COSE_Recipient for key wrap.
     *
     * We have to tell it the key wrap algorithm and give it the key
     * and kid.
     *
     * This object gets handed to the main encryption API which will
     * excersize it through a callback to create the COSE_Recipient.
     */
    t_cose_recipient_enc_keywrap_init(&kw_recipient, T_COSE_ALGORITHM_A128KW);
    t_cose_recipient_enc_keywrap_set_key(&kw_recipient,
                                          kek,
                                          Q_USEFUL_BUF_FROM_SZ_LITERAL("Kid A"));

    /* ----- Set up to make COSE_Encrypt ----
     *
     * Initialize. Have to say what algorithm is used to encrypt the
     * main content, the payload.
     *
     * Also tell the encryptor about the object to make the key wrap
     * COSE_Recipient by just giving it the pointer to it. It will get
     * called back in the next step.
     */
    t_cose_encrypt_enc_init(&enc_context, 0, T_COSE_ALGORITHM_A128GCM);
    t_cose_encrypt_add_recipient(&enc_context, (struct t_cose_recipient_enc *)&kw_recipient);


    /* ---- Actually Encrypt ----
     *
     * All the crypto gets called here including the encryption of the
     * payload and the key wrap.
     *
     * There are two buffers given, one for just the encrypted
     * payload and one for the COSE message. TODO: detached vs not and sizing.
     */
    err = t_cose_encrypt_enc(&enc_context,
                              Q_USEFUL_BUF_FROM_SZ_LITERAL("This is a real plaintext."),
                              encrypted_payload_buf,
                             &encrypted_payload,
                              cose_message_buf,
                             &encrypted_cose_message);


    if (err != 0) {
        printf("\nEncryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("COSE: ");
    print_bytestr(encrypted_cose_message.ptr, encrypted_cose_message.len);
    printf("\n\nCiphertext: ");
    print_bytestr(encrypted_payload.ptr, encrypted_payload.len);
    printf("\n");

    return 0;
}




static void
direct_detached_example(void)
{
    struct t_cose_encrypt_enc  enc_context;
    enum t_cose_err_t              err;
    struct t_cose_key              cek;
    struct q_useful_buf_c          encrypted_cose_message;
    struct q_useful_buf_c          decrypted_cose_message;
    struct q_useful_buf_c          encrypted_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB(    cose_message_buf, 1024);
    Q_USEFUL_BUF_MAKE_STACK_UB(    encrypted_payload_buf, 1024);
    Q_USEFUL_BUF_MAKE_STACK_UB(    decrypted_payload_buf, 1024);
    struct t_cose_encrypt_dec_ctx  dec_ctx;

    printf("\n-- 3a. Create COSE_Encrypt0 with detached payload (direct encryption) --\n\n");
    /* This is the simplest form of COSE encryption, a COSE_Encrypt0.
     * It has only headers and the ciphertext.
     *
     * Further in this example, the ciphertext is detached, so the
     * COSE_Encrypt0 only consists of the protected and unprotected
     * headers and a CBOR NULL where the ciphertext usually
     * occurs. The ciphertext is output separatly and conveyed
     * separately.
     *
     */
    t_cose_encrypt_enc_init(&enc_context,
                            T_COSE_OPT_COSE_ENCRYPT0 | T_COSE_OPT_COSE_ENCRYPT_DETACHED,
                            T_COSE_ALGORITHM_A128GCM);

    /* In direct encryption, we simply make a t_cose_key for the
     * content encryption key, the CEK, and give it to t_cose.  It's
     * the only key there is and it is simply a key to be used with
     * AES, a string of bytes. (It is still t_cose_key, not a byte string
     * so it can be a PSA key handle so it can be used with with
     * an encryption implementation that doesn't allow the key to
     * leave a protected domain, an HSM for example).
     *
     * There is no COSE_Recipient so t_cose_encrypt_add_recipient() is
     * not called.
     *
     * Direct encryption is always a COSE_Encrypt0 and a COSE_Encrypt0
     * is always direct encryption.
     *
     * The encryption key is conveyed separately.
     *
     * No kid is provided in line with the examples of Encrypt0
     * in RFC 9052. RFC 9052 text describing Encrypt0 also implies that
     * no kid should be needed, but it doesn't seem to prohibit
     * the kid header and t_cose will allow it to be present.
     */
    make_psa_symmetric_key_handle(T_COSE_ALGORITHM_A128GCM,
                                  Q_USEFUL_BUF_FROM_SZ_LITERAL("aaaaaaaaaaaaaaaa"),
                                  &cek);
    t_cose_encrypt_set_key(&enc_context, cek, NULL_Q_USEFUL_BUF_C);

    err = t_cose_encrypt_enc(&enc_context,
                              Q_USEFUL_BUF_FROM_SZ_LITERAL("This is a real plaintext."),
                              encrypted_payload_buf,
                             &encrypted_payload,
                              cose_message_buf,
                             &encrypted_cose_message);


    printf("COSE: ");
    print_bytestr(encrypted_cose_message.ptr, encrypted_cose_message.len);
    printf("\n\nCiphertext: ");
    print_bytestr(encrypted_payload.ptr, encrypted_payload.len);
    printf("\n");

    printf("\n-- 3b. Process COSE_Encrypt0 with detached payload (direct encryption) --\n\n");

    t_cose_encrypt_dec_init(&dec_ctx, 0, T_COSE_KEY_DISTRIBUTION_DIRECT);

    t_cose_encrypt_dec_set_private_key(&dec_ctx, cek, NULL_Q_USEFUL_BUF_C);

    // TODO: fix this cast to non-const
    err = t_cose_encrypt_dec(&dec_ctx,
                             (uint8_t *)(uintptr_t)encrypted_cose_message.ptr, encrypted_cose_message.len,
                             (uint8_t *)(uintptr_t)encrypted_payload.ptr, encrypted_payload.len,
                             decrypted_payload_buf.ptr, decrypted_payload_buf.len,
                             &decrypted_cose_message);

    if (err != T_COSE_SUCCESS) {
        printf("\nDecryption failed!\n");
        return;
    }

    printf("\nPlaintext: ");
    print_bytestr(decrypted_cose_message.ptr, decrypted_cose_message.len);
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
    struct t_cose_encrypt_dec_ctx dec_ctx;
    enum t_cose_err_t ret;

    uint8_t plaintext[400];

    struct q_useful_buf_c plain_text_ubc;

    /* Key id for PSK */
    // TODO: sort out which kid for PSK
    //struct q_useful_buf_c kid1 = {psk_kid, psk_kid_len};
    /* Key id for public key */
    /* Key id for PSK 2 */

    struct t_cose_key t_cose_psk_key;

    struct t_cose_key t_cose_pkR_key;
    psa_key_attributes_t pkR_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t pkR_handle = PSA_KEY_HANDLE_INIT;

    struct t_cose_key t_cose_skR_key;
    psa_key_attributes_t skR_attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t skR_handle = PSA_KEY_HANDLE_INIT;

    /* -------------------------------------------------------------------------*/

    /* Initialize PSA Crypto  */
    // TODO: document that this is required or build it into the crypto layer
    // Note that was not required for signing
    status = psa_crypto_init();

    if (status != PSA_SUCCESS) {
        return(EXIT_FAILURE);
    }


    /* Set up the recipient's public key, pkR, used for encrypting messages */
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


    /* Set up the recipient's secret key, skR, used for decrypting messages encrypted with pkR */

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

#ifndef T_COSE_DISABLE_HPKE

    /* -------------------------------------------------------------------------*/


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
                            Q_USEFUL_BUF_FROM_SZ_LITERAL(KID2));

    if (res != EXIT_SUCCESS) {
        return(EXIT_FAILURE);
    }

    free_psa_key(t_cose_pkR_key);

    printf("COSE: ");
    print_bytestr(buffer, result_len);

    printf("\n\nCiphertext: ");
    print_bytestr(encrypted_firmware, encrypted_firmware_result_len);
    printf("\n");


    printf("\n-- 1b. Process COSE_Encrypt with detached payload using HPKE --\n\n");




    t_cose_encrypt_dec_init(&dec_ctx, 0, T_COSE_KEY_DISTRIBUTION_HPKE);

    t_cose_encrypt_dec_set_private_key(&dec_ctx, t_cose_skR_key, Q_USEFUL_BUF_FROM_SZ_LITERAL(KID2));

    ret = t_cose_encrypt_dec(&dec_ctx,
                             buffer, result_len, //sizeof(buffer),
                             encrypted_firmware, encrypted_firmware_result_len,
                             plaintext, sizeof(plaintext),
                             &plain_text_ubc);

    if (ret != T_COSE_SUCCESS) {
        printf("\nDecryption failed!\n");
        return(EXIT_FAILURE);
    }

    printf("\nPlaintext: ");
    printf("%s\n", (const char *)plain_text_ubc.ptr); // TODO: probably shouldn't assume a NULL-terminated string here

    memset(buffer, 0, sizeof(buffer));
    memset(encrypted_firmware, 0, encrypted_firmware_len);
    memset(plaintext, 0, sizeof(plaintext));


    /* -------------------------------------------------------------------------*/

    printf("\n-- 2a. Create COSE_Encrypt with included payload using HPKE--\n\n");
    // TODO: check error code here
    test_cose_encrypt(0,
                      firmware, firmware_len,
                      buffer, sizeof(buffer),
                      &result_len,
                      encrypted_firmware, encrypted_firmware_len,
                      &encrypted_firmware_result_len,
                      T_COSE_ALGORITHM_A128GCM,
                      T_COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM,
                      t_cose_skR_key,
                      Q_USEFUL_BUF_FROM_SZ_LITERAL(KID2));

    printf("COSE: ");
    print_bytestr(buffer, result_len);
    printf("\n");

    printf("\n-- 2b. Process COSE_Encrypt with included payload using HPKE --\n\n");

    t_cose_encrypt_dec_init(&dec_ctx, 0, T_COSE_KEY_DISTRIBUTION_HPKE);

    t_cose_encrypt_dec_set_private_key(&dec_ctx, t_cose_skR_key, Q_USEFUL_BUF_FROM_SZ_LITERAL(KID2));


    ret = t_cose_encrypt_dec(&dec_ctx,
                             buffer, result_len,
                             NULL, 0,
                             plaintext, sizeof(plaintext),
                             &plain_text_ubc);

    if (ret != T_COSE_SUCCESS) {
        printf("\nDecryption failed!\n");
        return(EXIT_FAILURE);
    }

    free_psa_key(t_cose_skR_key);

    printf("\nPlaintext: ");
    printf("%s\n", (const char *)plain_text_ubc.ptr); // TODO: probably shouldn't assume a NULL-terminated string here

    memset(buffer, 0, sizeof(buffer));
    memset(encrypted_firmware, 0, encrypted_firmware_len);
    memset(plaintext, 0, sizeof(plaintext));
    /* -------------------------------------------------------------------------*/

#endif /* T_COSE_DISABLE_HPKE */


    direct_detached_example();


#ifndef T_COSE_DISABLE_AES_KW
    /* -------------------------------------------------------------------------*/

    key_wrap_example();

#endif /* T_COSE_DISABLE_AES_KW */
    /* -------------------------------------------------------------------------*/

    psa_destroy_key(psk_handle);

    psa_destroy_key(skR_handle);
    psa_destroy_key(pkR_handle);

    return(0);
}
