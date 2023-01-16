/*
 *  t_cose_crypto_test.c
 *
 * Copyright 2022-2023, Laurence Lundblade
 * Created by Laurence Lundblade on 12/28/22.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "t_cose_crypto_test.h"

#include "../src/t_cose_crypto.h" /* NOT a public interface so this test can't run against an installed library */

static const uint8_t test_key_0_128bit[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x010, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x010, 0x00};

/* Nonce / IV is typically 12 bytes for most usage */
static const uint8_t iv_0[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x010, 0x00,
    0x00, 0x00, 0x00, 0x00};

static const uint8_t aad[] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

#if 0
/* From the GCM standard, but it doesn't match. Would like to know why... */
static const uint8_t test_ciphertext[] = {
    0x72, 0x66, 0x23, 0x9A, 0x61, 0xCD, 0xB6, 0x6C, 0x3E, 0xB0, 0x8B, 0x58,
    0x72, 0x0D, 0x53, 0x4A, 0x0E, 0x4A, 0xEF, 0xC3, 0x55, 0xAC, 0x90, 0x4C,
    0x58, 0x1F
};
#endif


/* TODO: proper define to know about test crypto */
#ifndef T_COSE_USE_B_CON_SHA256
/* This is what is output by both OpenSSL and MbedTLS (but different than what is in the GCM standard). */
static const uint8_t expected_empty_tag[] = {
    0xC9, 0x4A, 0xA9, 0xF3, 0x22, 0x75, 0x73, 0x8C, 0xD5, 0xCC, 0x75, 0x01, 0xA4, 0x80, 0xBC, 0xF5};
#endif

int_fast32_t aead_test(void)
{
    enum t_cose_err_t      err;
    int32_t                cose_algorithm_id;
    struct t_cose_key      key;
    struct q_useful_buf_c  ciphertext;
    MakeUsefulBufOnStack(  ciphertext_buffer, 300);
    MakeUsefulBufOnStack(  plaintext_buffer, 300);
    struct q_useful_buf_c  plaintext;
    const struct q_useful_buf_c empty = {"", 0};


    cose_algorithm_id = T_COSE_ALGORITHM_A128GCM;

    err = t_cose_crypto_make_symmetric_key_handle(T_COSE_ALGORITHM_A128GCM,
                                                  UsefulBuf_FROM_BYTE_ARRAY_LITERAL(test_key_0_128bit),
                                                 &key);
    if(err) {
        return 1000 + (int_fast32_t)err;
    }

    /* First the simplest case, no payload, no aad, just the tag */
    err = t_cose_crypto_aead_encrypt(cose_algorithm_id,
                                     key,
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(iv_0),
                                     NULL_Q_USEFUL_BUF_C,
                                     empty,
                                     ciphertext_buffer,
                                     &ciphertext);
    if(err) {
        return 2000 + (int_fast32_t)err;
    }

    /* TODO: proper define to know about test crypto */
#ifndef T_COSE_USE_B_CON_SHA256
    /* Compare to the expected output.
     * PSA and OpenSSL are creating the same value here, but it doesn't
     * line up with the GCM test vectors from the GSM standard.
     * I don't know why. It seems like it should.
     */
    if(q_useful_buf_compare(Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(expected_empty_tag), ciphertext)) {
        return -2001;
    }
#else
    /* It's not really necessary to test the test crypto, but it is
     * helpful to validate it some. But the above is disabled as it
     * doesn't produce real AES-GCM results even though it can
     * fake encryption and decryption. */
#endif

    err = t_cose_crypto_aead_decrypt(cose_algorithm_id,
                                     key,
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(iv_0),
                                     NULL_Q_USEFUL_BUF_C,
                                     ciphertext,
                                     plaintext_buffer,
                                     &plaintext);

    if(err) {
        return 3000 + (int_fast32_t)err;
    }

    if(plaintext.len != 0) {
        return -3001;
    }


    /* Test with text and aad */
    err = t_cose_crypto_aead_encrypt(cose_algorithm_id,
                                     key,
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(iv_0),
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(aad),
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("plain text"),
                                     ciphertext_buffer,
                                     &ciphertext);
    if(err) {
        return 4000 + (int_fast32_t)err;
    }

    err = t_cose_crypto_aead_decrypt(cose_algorithm_id,
                                     key,
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(iv_0),
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(aad),
                                     ciphertext,
                                     plaintext_buffer,
                                     &plaintext);
    if(err) {
        return 5000 + (int_fast32_t)err;
    }

    if(q_useful_buf_compare(Q_USEFUL_BUF_FROM_SZ_LITERAL("plain text"), plaintext)) {
        return -5001;
    }

    /* TODO: test a lot more conditions like size calculation, overflow, modified tags...
     * Most of these tests are aimed at OpenSSL because it has a terrible API and
     * documentation for AEAD. */

    return 0;
}



#ifndef T_COSE_DISABLE_AES_KW

int_fast32_t kw_test(void)
{
    /* These are test vectors from RFC 3394 */
    const struct q_useful_buf_c kek = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(((const uint8_t []){0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}));
    
    const struct q_useful_buf_c key_data = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(((const uint8_t []){0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}));

    const struct q_useful_buf_c expected_wrap = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(((const uint8_t []){0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,  0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,  0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5}));

    enum t_cose_err_t e;
    Q_USEFUL_BUF_MAKE_STACK_UB (ciphertext_buffer, 9 * 8); /* sized for 256-bit key with authentication tag */
    Q_USEFUL_BUF_MAKE_STACK_UB (plaintext_buffer, 8 * 8); /* sized for 256-bit key */

    struct q_useful_buf_c ciphertext;
    struct q_useful_buf_c plaintext;

    if(!t_cose_is_algorithm_supported(T_COSE_ALGORITHM_A128KW)) {
        /* This is necessary because MbedTLS 2.28 doesn't have
         * nist KW enabled by default. The PSA crypto layer deals with
         * this dynamically. The below tests will correctly link
         * on 2.28, but will fail to run so this exception is needed.
         */
        return 0;
    }

    // TODO: test more sizes and algorithms

    e = t_cose_crypto_kw_wrap(T_COSE_ALGORITHM_A128KW,
                              kek,
                              key_data,
                              ciphertext_buffer,
                             &ciphertext);
    if(e != T_COSE_SUCCESS) {
        return 1;
    }

    /* TODO: proper define to know about test crypto */
#ifndef T_COSE_USE_B_CON_SHA256
    if(q_useful_buf_compare(ciphertext, expected_wrap)) {
        return 5;
    }
#else
    (void)expected_wrap;
    /* It's not really necessary to test the test crypto, but it is
     * helpful to validate it some. But the above is disabled as it
     * doesn't produce real key wra results even though it can
     * fake wrap and unwrap. */
#endif

    e = t_cose_crypto_kw_unwrap(T_COSE_ALGORITHM_A128KW,
                                kek,
                                ciphertext,
                                plaintext_buffer,
                                &plaintext);
    if(e != T_COSE_SUCCESS) {
        return 9;
    }

    if(q_useful_buf_compare(key_data, plaintext)) {
        return 15;
    }


    /* Now modify the cipher text so the integrity check will fail.  */
    /* It's only a test case so cheating a bit here by casting away const is not too big of a crime. */
    ((uint8_t *)(uintptr_t)ciphertext.ptr)[ciphertext.len-1] += 1;

    e = t_cose_crypto_kw_unwrap(T_COSE_ALGORITHM_A128KW,
                                kek,
                                ciphertext,
                                plaintext_buffer,
                                &plaintext);
    if(e != T_COSE_ERR_DATA_AUTH_FAILED) {
        return 27;
    }


    return 0;
}

#endif /* !T_COSE_DISABLE_AES_KW */
