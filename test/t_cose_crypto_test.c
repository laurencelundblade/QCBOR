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
#include "init_keys.h"

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

int32_t aead_test(void)
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
        return 1000 + (int32_t)err;
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
        return 2000 + (int32_t)err;
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
        return 3000 + (int32_t)err;
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
        return 4000 + (int32_t)err;
    }

    err = t_cose_crypto_aead_decrypt(cose_algorithm_id,
                                     key,
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(iv_0),
                                     Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(aad),
                                     ciphertext,
                                     plaintext_buffer,
                                     &plaintext);
    if(err) {
        return 5000 + (int32_t)err;
    }

    if(q_useful_buf_compare(Q_USEFUL_BUF_FROM_SZ_LITERAL("plain text"), plaintext)) {
        return -5001;
    }

    /* TODO: test a lot more conditions like size calculation, overflow, modified tags...
     * Most of these tests are aimed at OpenSSL because it has a terrible API and
     * documentation for AEAD. */

    t_cose_crypto_free_symmetric_key(key);

    return 0;
}



#ifndef T_COSE_DISABLE_KEYWRAP

int32_t kw_test(void)
{
    struct t_cose_key kek;
    /* These are test vectors from RFC 3394 */
    const struct q_useful_buf_c kek_x = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(((const uint8_t []){0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}));
    
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
        return INT32_MIN; /* Means no testing was actually done */
    }

    e = t_cose_crypto_make_symmetric_key_handle(T_COSE_ALGORITHM_A128GCM,
                                                kek_x,
                                               &kek);
    if(e != T_COSE_SUCCESS) {
        return 1;
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

    t_cose_crypto_free_symmetric_key(kek);


    return 0;
}

#endif /* !T_COSE_DISABLE_KEYWRAP */




/* The following are one of the test vectors from RFC 5869. One is
 * enough as the goal is just to validate the adaptor layer, not fully
 * test the HKDF implementation as it was presumably tested when the
 * crypto library was released. */
static const uint8_t tc1_ikm_bytes[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

static const uint8_t tc1_salt_bytes[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c
};

static const uint8_t tc1_info_bytes[] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9
};

#ifndef T_COSE_USE_B_CON_SHA256
static const uint8_t tc1_okm_bytes[] = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
    0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
    0x58, 0x65
};
#endif

int32_t hkdf_test(void)
{
    Q_USEFUL_BUF_MAKE_STACK_UB(tc1_okm, 42);
    enum t_cose_err_t          err;
    struct q_useful_buf_c      okm;

    err = t_cose_crypto_hkdf(T_COSE_ALGORITHM_SHA_256,
                         Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(tc1_salt_bytes),
                         Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(tc1_ikm_bytes),
                         Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(tc1_info_bytes),
                         tc1_okm);
    if(err) {
        return 1;
    }

    okm.len = tc1_okm.len;
    okm.ptr = tc1_okm.ptr;

#ifndef T_COSE_USE_B_CON_SHA256
    if(q_useful_buf_compare(Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(tc1_okm_bytes),
                            okm)) {
        return 2;
    }
#else
    (void)okm;
#endif

    return 0;
}

#ifndef T_COSE_USE_B_CON_SHA256 /* test crypto doesn't support ECDH */

/* Expected result for cose_ex_P_256_key_pair_der. */
static const uint8_t expected_ecdh_p256[] = {
    0xE6, 0xBE, 0xF9, 0xB9, 0x91, 0x0C, 0xD1, 0x5A,
    0x20, 0xEF, 0x49, 0xB2, 0x40, 0x31, 0x0C, 0x8B,
    0xFC, 0x81, 0xDB, 0xAD, 0xBE, 0x63, 0x92, 0x7E,
    0xB2, 0x15, 0xB5, 0xAE, 0x01, 0x1E, 0x51, 0xEB};

int32_t ecdh_test(void)
{
    enum t_cose_err_t           err;
    struct t_cose_key           public_key;
    struct t_cose_key           private_key;
    struct q_useful_buf_c       shared_key;
    Q_USEFUL_BUF_MAKE_STACK_UB( shared_key_buf, T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE);


    err = init_fixed_test_ec_encryption_key(T_COSE_ELLIPTIC_CURVE_P_256,
                                           &public_key,
                                           &private_key);
    if(err != T_COSE_SUCCESS) {
        return -1;
    }

    err = t_cose_crypto_ecdh(private_key,
                             public_key,
                             shared_key_buf,
                            &shared_key);

    if(err != T_COSE_SUCCESS) {
        return (int32_t)err;
    }

    /* The main point of this test is that the same result comes from
     * all the crypto libraries integrated. */
    if(q_useful_buf_compare(Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(expected_ecdh_p256), shared_key)) {
        return 44;
    }


    return 0;

}


/* X coordinate from cose_ex_P_256_key_pair_der. */
static const uint8_t x_coord_P_256[] = {
    0x65, 0xed, 0xa5, 0xa1, 0x25, 0x77, 0xc2, 0xba,
    0xe8, 0x29, 0x43, 0x7f, 0xe3, 0x38, 0x70, 0x1a,
    0x10, 0xaa, 0xa3, 0x75, 0xe1, 0xbb, 0x5b, 0x5d,
    0xe1, 0x08, 0xde, 0x43, 0x9c, 0x08, 0x55, 0x1d,
};

static const uint8_t y_coord_P_256[] = {
    0x1e, 0x52, 0xed, 0x75, 0x70, 0x11, 0x63, 0xf7,
    0xf9, 0xe4, 0x0d, 0xdf, 0x9f, 0x34, 0x1b, 0x3d,
    0xc9, 0xba, 0x86, 0x0a, 0xf7, 0xe0, 0xca, 0x7c,
    0xa7, 0xe9, 0xee, 0xcd, 0x00, 0x84, 0xd1, 0x9c,
};

int32_t ec_import_export_test(void)
{
    enum t_cose_err_t      err;
    struct t_cose_key      public_key;
    struct t_cose_key      private_key;
    struct t_cose_key      public_key_next;
    MakeUsefulBufOnStack(  x_coord_buf, T_COSE_BITS_TO_BYTES(T_COSE_ECC_MAX_CURVE_BITS));
    MakeUsefulBufOnStack(  y_coord_buf, T_COSE_BITS_TO_BYTES(T_COSE_ECC_MAX_CURVE_BITS));
    struct q_useful_buf_c  x_coord;
    struct q_useful_buf_c  y_coord;
    bool                   y_sign;
    int32_t                curve;

    err = init_fixed_test_ec_encryption_key(T_COSE_ELLIPTIC_CURVE_P_256,
                                           &public_key,
                                           &private_key);
    if(err) {
        return 1;
    }

    err = t_cose_crypto_export_ec2_key(public_key,
                                      &curve,
                                       x_coord_buf,
                                      &x_coord,
                                       y_coord_buf,
                                      &y_coord,
                                      &y_sign);
    if(err) {
        return 2;
    }

    err = t_cose_crypto_import_ec2_pubkey(curve,
                                          x_coord,
                                          y_coord,
                                          y_sign,
                                          &public_key_next);
    if(err) {
        return 3;
    }

    err = t_cose_crypto_export_ec2_key(public_key_next,
                                      &curve,
                                       x_coord_buf,
                                      &x_coord,
                                       y_coord_buf,
                                      &y_coord,
                                      &y_sign);
    if(err) {
        return 4;
    }

    if(curve != T_COSE_ELLIPTIC_CURVE_P_256) {
        return 5;
    }

    if(q_useful_buf_compare(x_coord, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(x_coord_P_256) )) {
        return 6;
    }


    if(q_useful_buf_compare(y_coord, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(y_coord_P_256) )) {
        return 6;
    }

    return 0;
}


#endif /* T_COSE_USE_B_CON_SHA256 */
