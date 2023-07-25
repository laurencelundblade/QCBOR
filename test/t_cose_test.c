/*
 *  t_cose_test.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose_test.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose_make_test_messages.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose_crypto.h" /* For signature size constant */
#include "t_cose_util.h" /* for get_short_circuit_kid */
#include "t_cose/t_cose_key.h"
#include "init_keys.h" /* Use the same test keys as examples */



/* String used by RFC 8152 and C-COSE tests and examples for payload */
#define SZ_CONTENT "This is the content."
static const struct q_useful_buf_c s_input_payload = {SZ_CONTENT, sizeof(SZ_CONTENT)-1};

/*
 * Public function, see t_cose_test.h
 */
int32_t short_circuit_self_test()
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;
    struct t_cose_key               key_pair;
    int32_t                         cose_algorithm_id;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_ES256)) {
        cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    } else {
        cose_algorithm_id = T_COSE_ALGORITHM_SHORT_CIRCUIT_256;
    }

    init_fixed_test_signing_key(cose_algorithm_id, &key_pair);

    /* --- Make COSE Sign1 object --- */
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    result = t_cose_sign1_sign(&sign_ctx,
                                s_input_payload,
                                signed_cose_buffer,
                                &signed_cose);
    if(result) {
        return 1000 + (int32_t)result;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Start verifying the COSE Sign1 object  --- */
    /* Select short circuit signing */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                /* COSE to verify */
                                signed_cose,
                                /* The returned payload */
                                &payload,
                                /* Don't return parameters */
                                NULL);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, s_input_payload)) {
        return 3000;
    }

    /* The check against the TBS value from COSE  C test cases
     * from t_cose 1.0 is removed because of the new way
     * short circuit signature work. They used to pretend
     * they were ECDSA and used the algorithm ID from ECDSA, but
     * now they have their own algorithm ID. Since the algorithm
     * ID is covered by the hash, the hash is not the same.
     */
    // TODO: create a test (elsewhere) that does check the TBS bytes from COSE C


    /* --- Done verifying the COSE Sign1 object  --- */


   /* --- Make COSE Sign1 object --- */
    t_cose_sign1_sign_init(&sign_ctx,0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    result = t_cose_sign1_sign_aad(&sign_ctx,
                                    s_input_payload,
                                    Q_USEFUL_BUF_FROM_SZ_LITERAL("some aad"),
                                    signed_cose_buffer,
                                   &signed_cose);
    if(result) {
        return 1000 + (int32_t)result;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Start verifying the COSE Sign1 object  --- */
    /* Select short circuit signing */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    /* Run the signature verification */
    result = t_cose_sign1_verify_aad(&verify_ctx,
                                     /* COSE to verify */
                                     signed_cose,
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("some aad"),
                                     /* The returned payload */
                                     &payload,
                                     /* Don't return parameters */
                                     NULL);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, s_input_payload)) {
        return 3000;
    }

    free_fixed_signing_key(key_pair);

    return 0;
}

/*
 * Public function, see t_cose_test.h
 */
int32_t short_circuit_self_detached_content_test()
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;
    struct t_cose_key               key_pair;
    int32_t                         cose_algorithm_id;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_ES256)) {
        cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    } else {
        cose_algorithm_id = T_COSE_ALGORITHM_SHORT_CIRCUIT_256;
    }

    init_fixed_test_signing_key(cose_algorithm_id, &key_pair);

    /* --- Make COSE Sign1 object --- */
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    result = t_cose_sign1_sign_detached(&sign_ctx,
                                          NULL_Q_USEFUL_BUF_C,
                                          s_input_payload,
                                          signed_cose_buffer,
                                         &signed_cose);
    if(result) {
        return 1000 + (int32_t)result;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Start verifying the COSE Sign1 object  --- */
    /* Select short circuit signing */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    /* The detached content */
    payload = s_input_payload;

    /* Run the signature verification */
    result = t_cose_sign1_verify_detached(&verify_ctx,
                                          /* COSE to verify */
                                          signed_cose,
                                          /* No AAD */
                                          NULL_Q_USEFUL_BUF_C,
                                          /* The detached payload */
                                          payload,
                                          /* Don't return parameters */
                                          NULL);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, s_input_payload)) {
        return 3000;
    }

    /* --- Done verifying the COSE Sign1 object  --- */

    return 0;
}


/*
 * Public function, see t_cose_test.h
 */
int32_t short_circuit_verify_fail_test()
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;
    size_t                          payload_offset;
    struct t_cose_key               key_pair;
    int32_t                         cose_algorithm_id;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_ES256)) {
        cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    } else {
        cose_algorithm_id = T_COSE_ALGORITHM_SHORT_CIRCUIT_256;
    }

    init_fixed_test_signing_key(cose_algorithm_id, &key_pair);


    /* --- Start making COSE Sign1 object  --- */
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    result = t_cose_sign1_sign(&sign_ctx,
                                     s_input_payload,
                                     signed_cose_buffer,
                                     &signed_cose);
    if(result) {
        return 1000 + (int32_t)result;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Start Tamper with payload  --- */
    /* Find the offset of the payload in COSE_Sign1 */
    payload_offset = q_useful_buf_find_bytes(signed_cose, s_input_payload);
    if(payload_offset == SIZE_MAX) {
        return 6000;
    }
    /* Change "payload" to "hayload" */
    struct q_useful_buf temp_unconst = q_useful_buf_unconst(signed_cose);
    ((char *)temp_unconst.ptr)[payload_offset] = 'h';
    /* --- Tamper with payload Done --- */


    /* --- Start verifying the COSE Sign1 object  --- */

    /* Select short circuit signing */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                       /* COSE to verify */
                                       signed_cose,
                                       /* The returned payload */
                                       &payload,
                                       /* Don't return parameters */
                                       NULL);
    if(result != T_COSE_ERR_SIG_VERIFY) {
        return 4000 + (int32_t)result;
    }
    /* --- Done verifying the COSE Sign1 object  --- */


    /* === AAD Verification Failure Test === */
    /* --- Start making COSE Sign1 object  --- */
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    result = t_cose_sign1_sign_aad(&sign_ctx,
                                    s_input_payload,
                                    Q_USEFUL_BUF_FROM_SZ_LITERAL("some aad"),
                                    signed_cose_buffer,
                                    &signed_cose);
    if(result) {
        return 1000 + (int32_t)result;
    }
    /* --- Done making COSE Sign1 object  --- */

    /* --- Start verifying the COSE Sign1 object  --- */

    /* Select short circuit signing */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    /* Run the signature verification */
    result = t_cose_sign1_verify_aad(&verify_ctx,
                                     /* COSE to verify */
                                     signed_cose,
                                     /* Slightly different AAD */
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("home aad"),
                                     /* The returned payload */
                                     &payload,
                                     /* Don't return parameters */
                                     NULL);
    if(result != T_COSE_ERR_SIG_VERIFY) {
        return 4000 + (int32_t)result;
    }
    /* --- Done verifying the COSE Sign1 object  --- */

    free_fixed_signing_key(key_pair);

    return 0;
}


/*
 * Public function, see t_cose_test.h
 */
// TODO: name of this tests isn't right.
int32_t short_circuit_signing_error_conditions_test()
{
    struct t_cose_sign1_sign_ctx sign_ctx;
    enum t_cose_err_t            result;
    Q_USEFUL_BUF_MAKE_STACK_UB(  signed_cose_buffer, 300);
    Q_USEFUL_BUF_MAKE_STACK_UB(  small_signed_cose_buffer, 15);
    struct q_useful_buf_c        signed_cose;
    int32_t                      cose_algorithm_id;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_ES256)) {
        cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    } else {
        cose_algorithm_id = T_COSE_ALGORITHM_SHORT_CIRCUIT_256;
    }

    /* -- Test bad algorithm ID 0 -- */
    /* Use reserved alg ID 0 to cause error. */
    t_cose_sign1_sign_init(&sign_ctx, 0, 0);

    result = t_cose_sign1_sign(&sign_ctx,
                                s_input_payload,
                                signed_cose_buffer,
                               &signed_cose);
    if(result != T_COSE_ERR_UNSUPPORTED_SIGNING_ALG) {
        return -1;
    }

    /* -- Test bad algorithm ID -4444444 -- */
    /* Use unassigned alg ID -4444444 to cause error. */
    t_cose_sign1_sign_init(&sign_ctx, 0, -4444444);

    result = t_cose_sign1_sign(&sign_ctx,
                                s_input_payload,
                                signed_cose_buffer,
                               &signed_cose);
    if(result != T_COSE_ERR_UNSUPPORTED_SIGNING_ALG) {
        return -2;
    }



    /* -- Tests detection of CBOR encoding error in the payload -- */
#ifndef T_COSE_DISABLE_USAGE_GUARDS
    QCBOREncodeContext   cbor_encode;

    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_SHORT_CIRCUIT_256);
    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);

    QCBOREncode_AddSZString(&cbor_encode, "payload");
    /* Force a CBOR encoding error by closing a map that is not open */
    QCBOREncode_CloseMap(&cbor_encode);

    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);

    if(result != T_COSE_ERR_CBOR_FORMATTING) {
        return -3;
    }
#endif /* !T_COSE_DISABLE_USAGE_GUARDS */


    /* -- Tests the output buffer being too small -- */
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);

    result = t_cose_sign1_sign(&sign_ctx,
                                s_input_payload,
                                small_signed_cose_buffer,
                               &signed_cose);

    if(result != T_COSE_ERR_TOO_SMALL) {
        return -4;
    }

    return 0;
}


/*
 * Public function, see t_cose_test.h
 */
int32_t short_circuit_make_cwt_test()
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    QCBOREncodeContext              cbor_encode;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;
    QCBORError                      cbor_error;
    struct t_cose_key               key_pair;
    int32_t                         cose_algorithm_id;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_ES256)) {
        cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    } else {
        cose_algorithm_id = T_COSE_ALGORITHM_SHORT_CIRCUIT_256;
    }

    init_fixed_test_signing_key(cose_algorithm_id, &key_pair);

    /* --- Start making COSE Sign1 object  --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    /* Do the first part of the the COSE_Sign1, the parameters */
    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 1, "coap://as.example.com");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 2, "erikw");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 3, "coap://light.example.com");
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 4, 1444064944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 5, 1443944944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 6, 1443944944);
    const uint8_t xx[] = {0x0b, 0x71};
    QCBOREncode_AddBytesToMapN(&cbor_encode, 7, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(xx));
    QCBOREncode_CloseMap(&cbor_encode);

    /* Finish up the COSE_Sign1. This is where the signing happens */
    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + (int32_t)cbor_error;
    }
    /* --- Done making COSE Sign1 object  --- */

    /* --- Compare to expected from CWT RFC --- */

    /* The first part, the intro and pararameters must be the same */
    struct q_useful_buf_c first_part_expected;
    struct q_useful_buf_c first_part_created;
    /* What is actually in the RFC */
    static const uint8_t fp_es[] = {0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0};
    /* A different algorithm ID than the RFC because it is short circuit sig */
    static const uint8_t fp_ss[] = {0xd2, 0x84, 0x47, 0xa1, 0x01, 0x3A,0x00, 0x0F, 0x43, 0x3F, 0xa0};
    if(cose_algorithm_id == T_COSE_ALGORITHM_ES256) {
        first_part_expected = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(fp_es);
    } else {
        first_part_expected = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(fp_ss);
    }
    first_part_created = q_useful_buf_head(signed_cose, first_part_expected.len);
    if(q_useful_buf_compare(first_part_created, first_part_expected)) {
        return -101;
    }

    /* Compare the payload */
    struct q_useful_buf_c created_payload;
    struct q_useful_buf_c expected_payload;
    const uint8_t rfc8392_payload_bytes[] = {
        0x58, 0x50, 0xa7, 0x01, 0x75, 0x63, 0x6f, 0x61, 0x70, 0x3a, 0x2f,
        0x2f, 0x61, 0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x2e, 0x63, 0x6f, 0x6d, 0x02, 0x65, 0x65, 0x72, 0x69, 0x6b, 0x77,
        0x03, 0x78, 0x18, 0x63, 0x6f, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x6c,
        0x69, 0x67, 0x68, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x04, 0x1a, 0x56, 0x12, 0xae, 0xb0,
        0x05, 0x1a, 0x56, 0x10, 0xd9, 0xf0, 0x06, 0x1a, 0x56, 0x10, 0xd9,
        0xf0, 0x07, 0x42, 0x0b, 0x71};
    expected_payload = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(rfc8392_payload_bytes);
    created_payload = q_useful_buf_head(q_useful_buf_tail(signed_cose,
                                                          first_part_expected.len),
                                        sizeof(rfc8392_payload_bytes));
    if(q_useful_buf_compare(created_payload, expected_payload)) {
        return -102;
    }
    /* Don't compare the signature because ECDSA signatures usually have a random
     * component and we're not using the same key (yet) */


    /* --- Start verifying the COSE Sign1 object  --- */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                       /* COSE to verify */
                                       signed_cose,
                                       /* The returned payload */
                                       &payload,
                                       /* Don't return parameters */
                                       NULL);
    if(result) {
        return 4000 + (int32_t)result;
    }

    /* Format the expected payload CBOR fragment */

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, q_useful_buf_tail(expected_payload, 2))) {
        return 5000;
    }
    /* --- Done verifying the COSE Sign1 object  --- */

    free_fixed_signing_key(key_pair);

    return 0;
}


/*
 * Public function, see t_cose_test.h
 */
int32_t short_circuit_decode_only_test()
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    QCBOREncodeContext              cbor_encode;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;
    Q_USEFUL_BUF_MAKE_STACK_UB(     expected_payload_buffer, 10);
    struct q_useful_buf_c           expected_payload;
    QCBORError                      cbor_error;
    struct t_cose_key               key_pair;
    int32_t                         cose_algorithm_id;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_ES256)) {
        cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    } else {
        cose_algorithm_id = T_COSE_ALGORITHM_SHORT_CIRCUIT_256;
    }

    init_fixed_test_signing_key(cose_algorithm_id, &key_pair);

    /* --- Start making COSE Sign1 object  --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);


    /* Do the first part of the the COSE_Sign1, the parameters */
    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_AddSZString(&cbor_encode, "payload");

    /* Finish up the COSE_Sign1. This is where the signing happens */
    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* Finally close of the CBOR formatting and get the pointer and
     * length of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + (int32_t)cbor_error;
    }
    /* --- Done making COSE Sign1 object  --- */

    /* --- Tweak signature bytes --- */
    /* The signature is the last thing so reach back that many bytes
     * and tweak so if signature verification were attempted, it would
     * fail (but this is a decode-only test so it won't fail).
     */
    const size_t last_byte_offset = signed_cose.len - T_COSE_EC_P256_SIG_SIZE;
    struct q_useful_buf temp_unconst = q_useful_buf_unconst(signed_cose);
    ((uint8_t *)temp_unconst.ptr)[last_byte_offset]++;


    /* --- Start verifying the COSE Sign1 object  --- */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_DECODE_ONLY);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                       /* COSE to verify */
                                       signed_cose,
                                       /* The returned payload */
                                       &payload,
                                       /* Don't return parameters */
                                       NULL);


    if(result) {
        return 4000 + (int32_t)result;
    }

    /* Format the expected payload CBOR fragment */
    QCBOREncode_Init(&cbor_encode, expected_payload_buffer);
    QCBOREncode_AddSZString(&cbor_encode, "payload");
    QCBOREncode_Finish(&cbor_encode, &expected_payload);

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, expected_payload)) {
        return 5000;
    }
    /* --- Done verifying the COSE Sign1 object  --- */

    free_fixed_signing_key(key_pair);

    return 0;
}


/*
 18( [
    / protected / h’a10126’ / {
        \ alg \ 1:-7 \ ECDSA 256 \
    }/ ,
    / unprotected / {
      / kid / 4:’11’
    },
    / payload / ’This is the content.’,

       / signature / h’8eb33e4ca31d1c465ab05aac34cc6b23d58fef5c083106c4
   d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5
   a4c345cacb36’
] )

 */

/* This comes from Appendix_C_2_1.json from COSE_C by Jim Schaad */
static const uint8_t rfc8152_example_2_1[] = {
    0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA1, 0x04,
    0x42, 0x31, 0x31, 0x54, 0x54, 0x68, 0x69, 0x73,
    0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x63, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x2E, /* end of hdrs and payload*/
    0x58, 0x40, 0x8E, 0xB3, 0x3E, 0x4C, 0xA3, 0x1D, /* Sig starts with 0x58 */
    0x1C, 0x46, 0x5A, 0xB0, 0x5A, 0xAC, 0x34, 0xCC,
    0x6B, 0x23, 0xD5, 0x8F, 0xEF, 0x5C, 0x08, 0x31,
    0x06, 0xC4, 0xD2, 0x5A, 0x91, 0xAE, 0xF0, 0xB0,
    0x11, 0x7E, 0x2A, 0xF9, 0xA2, 0x91, 0xAA, 0x32,
    0xE1, 0x4A, 0xB8, 0x34, 0xDC, 0x56, 0xED, 0x2A,
    0x22, 0x34, 0x44, 0x54, 0x7E, 0x01, 0xF1, 0x1D,
    0x3B, 0x09, 0x16, 0xE5, 0xA4, 0xC3, 0x45, 0xCA,
    0xCB, 0x36};


/*
 * Public function, see t_cose_test.h
 */
int32_t cose_example_test()
{
    enum t_cose_err_t             result;
    Q_USEFUL_BUF_MAKE_STACK_UB(   signed_cose_buffer, 200);
    struct q_useful_buf_c         output;
    struct t_cose_sign1_sign_ctx  sign_ctx;
    struct q_useful_buf_c         head_actual;
    struct q_useful_buf_c         head_exp;

    // TODO: revisit the key material for this test. Can we get the right key?
    // SHould we get rid of this test?
    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_SHORT_CIRCUIT_256);

   // t_cose_sign1_set_signing_key(&sign_ctx,
     //                            t_cose_key_empty(),
       //                          Q_USEFUL_BUF_FROM_SZ_LITERAL("11"));

    /* Make example C.2.1 from RFC 8152 */

    result = t_cose_sign1_sign(&sign_ctx,
                                      s_input_payload,
                                      signed_cose_buffer,
                                     &output);

    if(result != T_COSE_SUCCESS) {
        return (int32_t)result;
    }

    /* Compare only the headers and payload as this was not signed
     * with the same key as the example. The first 32 bytes contain
     * the header parameters and payload. */
    head_actual = q_useful_buf_head(output, 32);
    head_exp = q_useful_buf_head(Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(rfc8152_example_2_1), 32);

    if(q_useful_buf_compare(head_actual, head_exp)) {
        return -1000;
    }

    return (int32_t)result;
}


static enum t_cose_err_t run_test_sign_and_verify(uint32_t test_mess_options)
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    QCBOREncodeContext              cbor_encode;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;
    struct t_cose_parameters        old_parameters;
    struct t_cose_key               key_pair;
    int32_t                         cose_algorithm_id;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_ES256)) {
        cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    } else {
        cose_algorithm_id = T_COSE_ALGORITHM_SHORT_CIRCUIT_256;
    }

    init_fixed_test_signing_key(cose_algorithm_id, &key_pair);

    /* --- Start making COSE Sign1 object  --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    result =
        t_cose_test_message_sign1_sign(&sign_ctx,
                                       test_mess_options,
                                       Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"),
                                       signed_cose_buffer,
                                       &signed_cose);
    if(result) {
        return result;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Start verifying the COSE Sign1 object  --- */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                       /* COSE to verify */
                                       signed_cose,
                                       /* The returned payload */
                                       &payload,
                                       /* Don't return parameters */
                                       &old_parameters);

    free_fixed_signing_key(key_pair);

    return result;
}


#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
int32_t all_header_parameters_test()
{
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 300);
    struct q_useful_buf_c           output;
    struct q_useful_buf_c           payload;
    struct t_cose_parameters        parameters;
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    struct t_cose_key               key_pair;
    int32_t                         cose_algorithm_id;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_ES256)) {
        cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    } else {
        cose_algorithm_id = T_COSE_ALGORITHM_SHORT_CIRCUIT_256;
    }

    init_fixed_test_signing_key(cose_algorithm_id, &key_pair);


    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx,
                                 key_pair,
                                 Q_USEFUL_BUF_FROM_SZ_LITERAL("11"));

    result =
        t_cose_test_message_sign1_sign(&sign_ctx,
                                       T_COSE_TEST_ALL_PARAMETERS,
                                       s_input_payload,
                                       signed_cose_buffer,
                                      &output);
    if(result) {
        return 1;
    }

    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);


    result = t_cose_sign1_verify(&verify_ctx,
                                       /* COSE to verify */
                                       output,
                                       /* The returned payload */
                                       &payload,
                                       /* Get parameters for checking */
                                       &parameters);
    if(result) {
        return -2;
    }

    // Need to compare to short circuit kid
    if(q_useful_buf_compare(parameters.kid, Q_USEFUL_BUF_FROM_SZ_LITERAL("11"))) {
        return 2;
    }

    if(parameters.cose_algorithm_id != cose_algorithm_id) {
        return 3;
    }

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    if(parameters.content_type_uint != 1) {
        return 4;
    }
#endif /* T_COSE_DISABLE_CONTENT_TYPE */

    if(q_useful_buf_compare(parameters.iv,
                            Q_USEFUL_BUF_FROM_SZ_LITERAL("iv"))) {
        return 5;
    }

    free_fixed_signing_key(key_pair);


    return 0;
}
#endif /* !T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */

struct test_case {
    uint32_t           test_option;
    enum t_cose_err_t  result;
};

static struct test_case bad_parameters_tests_table[] = {
    // TODO: document that this is different than t_cose 1.0
    {T_COSE_TEST_EMPTY_PROTECTED_PARAMETERS, T_COSE_ERR_NO_ALG_ID},

    {T_COSE_TEST_UNCLOSED_PROTECTED, T_COSE_ERR_PARAMETER_CBOR},

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    {T_COSE_TEST_DUP_CONTENT_ID, T_COSE_ERR_DUPLICATE_PARAMETER},

    {T_COSE_TEST_TOO_LARGE_CONTENT_TYPE, T_COSE_ERR_BAD_CONTENT_TYPE},
#endif /* T_COSE_DISABLE_CONTENT_TYPE */

    {T_COSE_TEST_NOT_WELL_FORMED_2, T_COSE_ERR_CBOR_NOT_WELL_FORMED},

    {T_COSE_TEST_KID_IN_PROTECTED, T_COSE_ERR_DUPLICATE_PARAMETER},

#ifdef TODO_CRIT_PARAM_FIXED
    {T_COSE_TEST_TOO_MANY_UNKNOWN, T_COSE_ERR_TOO_MANY_PARAMETERS},
#endif

    {T_COSE_TEST_UNPROTECTED_NOT_MAP, T_COSE_ERR_PARAMETER_CBOR},

#ifdef TODO_CRIT_PARAM_FIXED
    {T_COSE_TEST_BAD_CRIT_PARAMETER, T_COSE_ERR_CRIT_PARAMETER},
#endif

    {T_COSE_TEST_NOT_WELL_FORMED_1, T_COSE_ERR_CBOR_NOT_WELL_FORMED},

    {T_COSE_TEST_NO_UNPROTECTED_PARAMETERS, T_COSE_ERR_PARAMETER_CBOR},

    {T_COSE_TEST_NO_PROTECTED_PARAMETERS, T_COSE_ERR_PARAMETER_CBOR},

    {T_COSE_TEST_EXTRA_PARAMETER, T_COSE_SUCCESS},

    {T_COSE_TEST_PARAMETER_LABEL, T_COSE_ERR_PARAMETER_CBOR},

    {T_COSE_TEST_BAD_PROTECTED, T_COSE_ERR_PARAMETER_CBOR},

    {0, 0}
};


/*
 * Public function, see t_cose_test.h
 */
int32_t bad_parameters_test()
{
    struct test_case *test;

    for(test = bad_parameters_tests_table; test->test_option; test++) {
        if(run_test_sign_and_verify(test->test_option) != test->result) {
            return (int32_t)(test - bad_parameters_tests_table + 1);
        }
    }

    return 0;
}



/* These test the processing of the crit param in a COSE_SIGN1 */
static struct test_case crit_tests_table[] = {
    /* Test existance of the critical header. Also makes sure that
     * it works with the max number of labels allowed in it.
     */
    {T_COSE_TEST_CRIT_PARAMETER_EXIST, T_COSE_SUCCESS},

    /* Exceed the max number of labels by one and get an error */
    {T_COSE_TEST_TOO_MANY_CRIT_PARAMETER_EXIST, T_COSE_ERR_CRIT_PARAMETER},

    /* A critical parameter exists in the protected section, but the
     * format of the internals of this parameter is not the expected CBOR
     */
    {T_COSE_TEST_BAD_CRIT_LABEL, T_COSE_ERR_CRIT_PARAMETER},

    /* A critical label is listed in the protected section, but
     * the label doesn't exist. This works for integer-labeled header params.
     */
    {T_COSE_TEST_UNKNOWN_CRIT_UINT_PARAMETER, T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER},
#if WE_HAVE_ADDED_STRING_LABELS
    /* A critical label is listed in the protected section, but
     * the label doesn't exist. This works for string-labeled header params.
     */
    {T_COSE_TEST_UNKNOWN_CRIT_TSTR_PARAMETER, T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER},
#endif /* WE_HAVE_ADDED_STRING_LABELS */

    /* The critical labels list is not protected */
    {T_COSE_TEST_CRIT_NOT_PROTECTED, T_COSE_ERR_PARAMETER_NOT_PROTECTED},

    {T_COSE_TEST_EMPTY_CRIT_PARAMETER, T_COSE_ERR_CRIT_PARAMETER},

#if WE_HAVE_ADDED_STRING_LABELS
    {T_COSE_TEST_TOO_MANY_TSTR_CRIT_LABLELS, T_COSE_ERR_CRIT_PARAMETER},
#endif /* WE_HAVE_ADDED_STRING_LABELS */

    {0, 0}
};


/*
 * Public function, see t_cose_test.h
 */
int32_t crit_parameters_test()
{
    unsigned index;

    for(index = 0; index < C_ARRAY_COUNT(crit_tests_table, struct test_case); index++) {
        struct test_case *test = &crit_tests_table[index];

        if(run_test_sign_and_verify(test->test_option) != test->result) {
            return (int32_t)(index * 1000 + 1);
        }
    }

    return 0;
}


#ifndef T_COSE_DISABLE_CONTENT_TYPE
/*
 * Public function, see t_cose_test.h
 */
int32_t content_type_test()
{
    struct t_cose_parameters        parameters;
    struct t_cose_sign1_sign_ctx    sign_ctx;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           output;
    struct q_useful_buf_c           payload;
    enum t_cose_err_t               result;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    struct t_cose_key               key_pair;
    int32_t                         cose_algorithm_id;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_ES256)) {
        cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    } else {
        cose_algorithm_id = T_COSE_ALGORITHM_SHORT_CIRCUIT_256;
    }

    init_fixed_test_signing_key(cose_algorithm_id, &key_pair);


    /* -- integer content type -- */
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    t_cose_sign1_set_content_type_uint(&sign_ctx, 42);

    result = t_cose_sign1_sign(&sign_ctx,
                                      s_input_payload,
                                      signed_cose_buffer,
                                     &output);
    if(result) {
        return 1;
    }

    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    result = t_cose_sign1_verify(&verify_ctx,
                                        output,
                                       &payload,
                                       &parameters);
    if(result) {
        return 2;
    }

    if(parameters.content_type_uint != 42) {
        return 5;
    }


    /* -- string content type -- */
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);


    t_cose_sign1_set_content_type_tstr(&sign_ctx, "text/plain");

    result = t_cose_sign1_sign(&sign_ctx,
                                     s_input_payload,
                                     signed_cose_buffer,
                                     &output);
    if(result) {
        return 1;
    }

    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    result = t_cose_sign1_verify(&verify_ctx,
                                       output,
                                       &payload,
                                       &parameters);
    if(result) {
        return 2;
    }

    if(q_useful_buf_compare(parameters.content_type_tstr, Q_USEFUL_BUF_FROM_SZ_LITERAL("text/plain"))) {
        return 6;
    }

#ifndef T_COSE_2
    /* This test is turned off for t_cose 2 because the behavior
     * when setting the content type twice is different. For
     * t_cose 2, the second call over writes the first. It is not
     * worth replicating the t_cose 1 behavior to pass this test
     * of a particular error. There are tests for duplicate
     * errors possible in t_cose 2 elsewhere.
     * TODO: implement these tests elsewhere
     */

    /* -- content type in error -- */
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);


    t_cose_sign1_set_content_type_tstr(&sign_ctx, "text/plain");
    t_cose_sign1_set_content_type_uint(&sign_ctx, 42);


    result = t_cose_sign1_sign(&sign_ctx,
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"),
                                     signed_cose_buffer,
                                     &output);
    if(result != T_COSE_ERR_DUPLICATE_PARAMETER) {
        return 1;
    }
#endif

    free_fixed_signing_key(key_pair);

    return 0;
}
#endif /* T_COSE_DISABLE_CONTENT_TYPE */


struct sign1_sample {
    struct q_useful_buf_c CBOR;
    enum t_cose_err_t     expected_error;
};

static struct sign1_sample sign1_sample_inputs[] = {
    /* 0. With an indefinite length string payload */
    { {(uint8_t[]){0x84, 0x40, 0xa0, 0x5f, 0x00, 0xff, 0x40}, 7}, T_COSE_ERR_CBOR_DECODE},
    /* 1. Too few items in unprotected header parameters bucket */
    { {(uint8_t[]){0x84, 0x40, 0xa3, 0x01, 0x40}, 5}, T_COSE_ERR_PARAMETER_CBOR},
    /* 2. Too few items in definite-length array */
    { {(uint8_t[]){0x83, 0x40, 0xa0, 0x40}, 4}, T_COSE_ERR_SIGN1_FORMAT},
    /* 3. Too-long signature */
    { {(uint8_t[]){0x84, 0x40, 0xa0, 0x40, 0x4f}, 5}, T_COSE_ERR_CBOR_NOT_WELL_FORMED},
    /* 4. Too-long payload */
    { {(uint8_t[]){0x84, 0x40, 0xa0, 0x4f, 0x40}, 5}, T_COSE_ERR_CBOR_NOT_WELL_FORMED},
    /* 5. Too-long protected parameters bucket */
    { {(uint8_t[]){0x84, 0x4f, 0xa0, 0x40, 0x40}, 5}, T_COSE_ERR_CBOR_NOT_WELL_FORMED},
    /* 6. Unterminated indefinite length */
    { {(uint8_t[]){0x9f, 0x40, 0xbf, 0xff, 0x40, 0x40}, 6}, T_COSE_ERR_SIGN1_FORMAT},
    /* 7. The smallest legal COSE_Sign1 using indefinite lengths */
    { {(uint8_t[]){0x9f, 0x40, 0xbf, 0xff, 0x40, 0x40, 0xff}, 7}, T_COSE_ERR_NO_ALG_ID},
    /* 8. The smallest legal COSE_Sign1 using definite lengths */
    { {(uint8_t[]){0x84, 0x40, 0xa0, 0x40, 0x40}, 5}, T_COSE_ERR_NO_ALG_ID},
    /* 9. Just one not-well-formed byte -- a reserved value */
    { {(uint8_t[]){0x3c}, 1}, T_COSE_ERR_CBOR_NOT_WELL_FORMED },
    /* 10. The smallest legal COSE_Sign1 using definite lengths */
    { {(uint8_t[]){0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0, 0x40, 0x40}, 8}, T_COSE_SUCCESS},
    /* terminate the list */
    { {NULL, 0}, 0 },
};

#include "t_cose/t_cose_parameters.h"
#include "qcbor/qcbor_spiffy_decode.h"

#ifndef T_COSE_DISABLE_COSE_SIGN

static enum t_cose_err_t
foo_encode_cb(const struct t_cose_parameter  *parameter,
              QCBOREncodeContext             *cbor_encoder)
{
    QCBOREncode_OpenMapInMapN(cbor_encoder, parameter->label);
    QCBOREncode_AddInt64ToMap(cbor_encoder, "xxx", 88);
    QCBOREncode_AddInt64ToMap(cbor_encoder, "yyy", 99);
    QCBOREncode_CloseMap(cbor_encoder);
    return T_COSE_SUCCESS;
}


static enum t_cose_err_t
foo_decode_cb(void                    *cb_context,
              QCBORDecodeContext      *cbor_decoder,
              struct t_cose_parameter *parameter)
{
    (void)cb_context; /* Intentionally unused */

    if(parameter->label == 66) {
        int64_t n1, n2;

        QCBORDecode_EnterMap(cbor_decoder, NULL);
        QCBORDecode_GetInt64InMapSZ(cbor_decoder, "xxx", &n1);
        QCBORDecode_GetInt64InMapSZ(cbor_decoder, "yyy", &n2);
        QCBORDecode_ExitMap(cbor_decoder);
        if(QCBORDecode_IsNotWellFormedError(QCBORDecode_GetError(cbor_decoder))) {
            return T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        }

        parameter->value.special_decode.value.little_buf[0] = (uint8_t)n1;
        parameter->value.special_decode.value.little_buf[1] = (uint8_t)n2;
        parameter->value_type = T_COSE_PARAMETER_TYPE_SPECIAL;

    } else if(parameter->label == 314) {
        double dd;
        QCBORDecode_GetDouble(cbor_decoder, &dd);

        parameter->value.special_decode.value.uint64 = UsefulBufUtil_CopyDoubleToUint64(dd);
        parameter->value_type = T_COSE_PARAMETER_TYPE_SPECIAL;

    } else {
        return T_COSE_ERR_DECLINE;
    }

    return T_COSE_SUCCESS;
}

static enum t_cose_err_t
float_encode_cb(const struct t_cose_parameter  *parameter,
                QCBOREncodeContext             *cbor_encoder)
{
    QCBOREncode_AddDoubleToMapN(cbor_encoder,
                                parameter->label,
                                UsefulBufUtil_CopyUint64ToDouble(parameter->value.special_encode.data.uint64));

    return T_COSE_SUCCESS;
}




static int32_t
make_complex_cose_sign(struct q_useful_buf cose_sign_buf, struct q_useful_buf_c *cose_sign)
{
    struct t_cose_sign_sign_ctx sign_encoder;
    struct t_cose_signature_sign_main  sig1_encoder;
    struct t_cose_signature_sign_main  sig2_encoder;
    struct t_cose_signature_sign_main  sig3_encoder;
    struct t_cose_parameter sig1_params[3];
    struct t_cose_parameter sig2_params[3];
    struct t_cose_parameter sig3_params[3];
    struct t_cose_key sig1_key;
    struct t_cose_key sig2_key;
    struct t_cose_key sig3_key;
    enum t_cose_err_t err;

    t_cose_sign_sign_init(&sign_encoder, T_COSE_OPT_MESSAGE_TYPE_SIGN);


    init_fixed_test_signing_key(T_COSE_ALGORITHM_ES256, &sig1_key);
    t_cose_signature_sign_main_init(&sig1_encoder, T_COSE_ALGORITHM_ES256);
    t_cose_signature_sign_main_set_signing_key(&sig1_encoder, sig1_key, Q_USEFUL_BUF_FROM_SZ_LITERAL("sig1"));
    sig1_params[0] = t_cose_param_make_ct_tstr(Q_USEFUL_BUF_FROM_SZ_LITERAL("app/foo"));
    sig1_params[1].critical         = false;
    sig1_params[1].in_protected     = false;
    sig1_params[1].location.index   = 0;
    sig1_params[1].location.nesting = 0;
    sig1_params[1].label            = 99;
    sig1_params[1].value_type       = T_COSE_PARAMETER_TYPE_INT64;
    sig1_params[1].value.int64      = INT64_MAX;
    sig1_params[1].next             = NULL;
    sig1_params[0].next = &sig1_params[1];

    sig1_params[2].critical         = false;
    sig1_params[2].in_protected     = false;
    sig1_params[2].location.index   = 0;
    sig1_params[2].location.nesting = 0;
    sig1_params[2].label            = 66;
    sig1_params[2].value_type       = T_COSE_PARAMETER_TYPE_SPECIAL;
    sig1_params[2].value.special_encode.encode_cb = foo_encode_cb;
    sig1_params[2].next             = NULL;
    sig1_params[1].next = &sig1_params[2];
    t_cose_signature_sign_main_set_header_parameter(&sig1_encoder, sig1_params);
    t_cose_sign_add_signer(&sign_encoder, t_cose_signature_sign_from_main(&sig1_encoder));

    init_fixed_test_signing_key(T_COSE_ALGORITHM_ES384, &sig2_key);
    t_cose_signature_sign_main_init(&sig2_encoder, T_COSE_ALGORITHM_ES384);
    t_cose_signature_sign_main_set_signing_key(&sig2_encoder, sig2_key, Q_USEFUL_BUF_FROM_SZ_LITERAL("sig2"));
    sig2_params[0] = t_cose_param_make_ct_tstr(Q_USEFUL_BUF_FROM_SZ_LITERAL("app/xxx"));
    sig2_params[1].critical         = false;
    sig2_params[1].in_protected     = false;
    sig2_params[1].location.index   = 0;
    sig2_params[1].location.nesting = 0;
    sig2_params[1].label            = 314;
    sig2_params[1].value_type       = T_COSE_PARAMETER_TYPE_SPECIAL;
    sig2_params[1].value.special_encode.encode_cb = float_encode_cb;
    sig2_params[1].value.special_encode.data.uint64 = UsefulBufUtil_CopyDoubleToUint64(3.14159);
    sig2_params[1].next             = NULL;
    sig2_params[0].next = &sig2_params[1];
    t_cose_signature_sign_main_set_header_parameter(&sig2_encoder, sig2_params);
    t_cose_sign_add_signer(&sign_encoder, t_cose_signature_sign_from_main(&sig2_encoder));

    init_fixed_test_signing_key(T_COSE_ALGORITHM_ES512, &sig3_key);
    t_cose_signature_sign_main_init(&sig3_encoder, T_COSE_ALGORITHM_ES512);
    t_cose_signature_sign_main_set_signing_key(&sig3_encoder, sig3_key, Q_USEFUL_BUF_FROM_SZ_LITERAL("sig3"));
    sig3_params[0] = t_cose_param_make_ct_uint(217);
    t_cose_signature_sign_main_set_header_parameter(&sig3_encoder, sig3_params);
    t_cose_sign_add_signer(&sign_encoder, t_cose_signature_sign_from_main(&sig3_encoder));


    err = t_cose_sign_sign(&sign_encoder,
                           Q_USEFUL_BUF_FROM_SZ_LITERAL("AAD"),
                           Q_USEFUL_BUF_FROM_SZ_LITERAL("PAYLOAD"),
                           cose_sign_buf,
                           cose_sign);
    if(err) {
        return 182;
    }

    free_fixed_signing_key(sig1_key);
    free_fixed_signing_key(sig2_key);
    free_fixed_signing_key(sig3_key);


    return 0;
}


/* This checks the value for all special headers by having the
 * expected values hard-coded in.
 */
static int32_t
match_special(const struct t_cose_parameter *p1)
{
    double dd;

    switch(p1->label) {
        case 66:
            if(p1->value.special_decode.value.little_buf[0] != 88 ||
               p1->value.special_decode.value.little_buf[1] != 99) {
                return 1;
            }
            break;

        case 314:
            dd = UsefulBufUtil_CopyUint64ToDouble(p1->value.special_decode.value.uint64);
            if(dd != 3.14159) {
                return 1;
            }
            break;

        default:
            /* In this test case, it is an error for there to be special
             * header parameters that are not understood.
             */
            return 1;
    }
    return 0;
}



/* return 0 on match, non-zero for no match*/
static int32_t
match_param_value(const struct t_cose_parameter *p1, const struct t_cose_parameter *p2)
{
    if(p1->value_type != p2->value_type) {
        return 1;
    }
    switch(p1->value_type) {
        case T_COSE_PARAMETER_TYPE_INT64:
            return !(p1->value.int64 == p2->value.int64);

        case T_COSE_PARAMETER_TYPE_TEXT_STRING:
        case T_COSE_PARAMETER_TYPE_BYTE_STRING:
            return q_useful_buf_compare(p1->value.string, p2->value.string);

        case T_COSE_PARAMETER_TYPE_SPECIAL:
            return match_special(p1);

        default:
            return 1;
    }

    return 0;
}


static int32_t
check_complex_sign_params(struct t_cose_parameter *params)
{
    struct expected_param {
        struct t_cose_parameter param;
        bool                    found;
    };

    struct expected_param expected[20];

    memset(expected, 0, sizeof(expected));

    expected[0].param.label = T_COSE_HEADER_PARAM_ALG;
    expected[0].param.value_type = T_COSE_PARAMETER_TYPE_INT64;
    expected[0].param.value.int64 = T_COSE_ALGORITHM_ES256;
    expected[0].param.location.nesting = 1;
    expected[0].param.location.index = 0; // Might not matter what the index is
    expected[0].param.in_protected = true;

    expected[1].param.label = T_COSE_HEADER_PARAM_ALG;
    expected[1].param.value_type = T_COSE_PARAMETER_TYPE_INT64;
    expected[1].param.value.int64 = T_COSE_ALGORITHM_ES384;
    expected[1].param.location.nesting = 1;
    expected[1].param.location.index = 1; // Might not matter what the index is
    expected[1].param.in_protected = true;

    expected[2].param.label = T_COSE_HEADER_PARAM_ALG;
    expected[2].param.value_type = T_COSE_PARAMETER_TYPE_INT64;
    expected[2].param.value.int64 = T_COSE_ALGORITHM_ES512;
    expected[2].param.location.nesting = 1;
    expected[2].param.location.index = 2; // Might not matter what the index is
    expected[2].param.in_protected = true;

    expected[3].param.label = T_COSE_HEADER_PARAM_KID;
    expected[3].param.value_type = T_COSE_PARAMETER_TYPE_BYTE_STRING;
    expected[3].param.value.string = Q_USEFUL_BUF_FROM_SZ_LITERAL("sig1");
    expected[3].param.location.nesting = 1;
    expected[3].param.location.index = 0; // Might not matter what the index is

    expected[4].param.label = T_COSE_HEADER_PARAM_KID;
    expected[4].param.value_type = T_COSE_PARAMETER_TYPE_BYTE_STRING;
    expected[4].param.value.string = Q_USEFUL_BUF_FROM_SZ_LITERAL("sig2");
    expected[4].param.location.nesting = 1;
    expected[4].param.location.index = 1; // Might not matter what the index is

    expected[5].param.label = T_COSE_HEADER_PARAM_KID;
    expected[5].param.value_type = T_COSE_PARAMETER_TYPE_BYTE_STRING;
    expected[5].param.value.string = Q_USEFUL_BUF_FROM_SZ_LITERAL("sig3");
    expected[5].param.location.nesting = 1;
    expected[5].param.location.index = 2; // Might not matter what the index is

    expected[6].param.label = T_COSE_HEADER_PARAM_CONTENT_TYPE;
    expected[6].param.value_type = T_COSE_PARAMETER_TYPE_TEXT_STRING;
    expected[6].param.value.string = Q_USEFUL_BUF_FROM_SZ_LITERAL("app/foo");
    expected[6].param.location.nesting = 1;
    expected[6].param.location.index = 0; // Might not matter what the index is

    expected[7].param.label = T_COSE_HEADER_PARAM_CONTENT_TYPE;
    expected[7].param.value_type = T_COSE_PARAMETER_TYPE_INT64;
    expected[7].param.value.int64 = 217;
    expected[7].param.location.nesting = 1;
    expected[7].param.location.index = 2; // Might not matter what the index is

    expected[8].param.label = T_COSE_HEADER_PARAM_CONTENT_TYPE;
    expected[8].param.value_type = T_COSE_PARAMETER_TYPE_TEXT_STRING;
    expected[8].param.value.string = Q_USEFUL_BUF_FROM_SZ_LITERAL("app/xxx");
    expected[8].param.location.nesting = 1;
    expected[8].param.location.index = 1; // Might not matter what the index is

    expected[9].param.label = 99;
    expected[9].param.value_type = T_COSE_PARAMETER_TYPE_INT64;
    expected[9].param.value.int64 = INT64_MAX;
    expected[9].param.location.nesting = 1;
    expected[9].param.location.index = 0; // Might not matter what the index is

    expected[10].param.label = 314;
    expected[10].param.value_type = T_COSE_PARAMETER_TYPE_SPECIAL;
    expected[10].param.location.nesting = 1;
    expected[10].param.location.index = 1; // Might not matter what the index is

    expected[11].param.label = 66;
    expected[11].param.value_type = T_COSE_PARAMETER_TYPE_SPECIAL;
    expected[11].param.location.nesting = 1;
    expected[11].param.location.index = 0; // Might not matter what the index is

    expected[12].param.label = INT64_MIN;

    int i;
    for(i = 0; expected[i].param.label != INT64_MIN; i++) {
        const struct t_cose_parameter *p;
        for(p = params; p != NULL; p = p->next) {
            if(p->label == expected[i].param.label &&
               p->location.nesting == expected[i].param.location.nesting &&
               match_param_value(p, &(expected[i].param)) == 0 &&
               p->critical == expected[i].param.critical &&
               p->in_protected == expected[i].param.in_protected &&
               p->location.index == expected[i].param.location.index) {
                if(expected[i].found == true) {
                    /* duplicate */
                    return -33;
                }
                expected[i].found = true;
                break;
            }
        }
    }

    /* Make sure they were all found */
    for(i = 0; expected[i].param.label != INT64_MIN; i++) {
        if(!expected[i].found){
            return i;
        }
    }


    return 0;
}
#endif /* !T_COSE_DISABLE_COSE_SIGN */



/*
 * Public function, see t_cose_test.h
 */
int32_t sign1_structure_decode_test(void)
{
    struct q_useful_buf_c           payload;
    enum t_cose_err_t               result;
    struct t_cose_sign1_verify_ctx  verify1_ctx;

#ifndef T_COSE_DISABLE_COSE_SIGN
    int32_t                         return_value;
    MakeUsefulBufOnStack(           cose_sign_buf, 900);
    struct q_useful_buf_c           cose_sign;
    struct t_cose_parameter        *decoded_params;
    struct t_cose_parameter        _params[20];
    struct t_cose_parameter_storage extra_params;


    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_ES256) &&
       t_cose_is_algorithm_supported(T_COSE_ALGORITHM_ES384)) {
        T_COSE_PARAM_STORAGE_INIT(extra_params, _params);

        /* Only works with real algorithms (so far). */

        return_value = make_complex_cose_sign(cose_sign_buf, &cose_sign);
        if(return_value != 0) {
            return return_value;
        }

        struct t_cose_sign_verify_ctx verify_ctx;
        struct t_cose_signature_verify_main verifier_main;

        t_cose_sign_verify_init(&verify_ctx, T_COSE_OPT_DECODE_ONLY);
        t_cose_sign_set_special_param_decoder(&verify_ctx,
                                               foo_decode_cb,
                                               NULL);

        t_cose_signature_verify_main_init(&verifier_main);
        t_cose_signature_verify_main_set_special_param_decoder(&verifier_main,
                                                               foo_decode_cb,
                                                               NULL);
        t_cose_sign_add_verifier(&verify_ctx, t_cose_signature_verify_from_main(&verifier_main));
        /* Don't need to set key because this is only decoding */

        t_cose_sign_add_param_storage(&verify_ctx, &extra_params);


        result = t_cose_sign_verify(&verify_ctx,
                                     cose_sign,
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL("AAD"),
                                    &payload,
                                    &decoded_params);
        if(result != T_COSE_SUCCESS) {
            return -99;
        }

        return_value = check_complex_sign_params(decoded_params);
        if(return_value != 0) {
            return return_value;
        }
    }
#endif  /* !T_COSE_DISABLE_T_COSE_SIGN */


    for(int i = 0; !q_useful_buf_c_is_null(sign1_sample_inputs[i].CBOR); i++) {
        if(i == 7) {
            result = 9;
        }

        t_cose_sign1_verify_init(&verify1_ctx, T_COSE_OPT_DECODE_ONLY);
        result = t_cose_sign1_verify(&verify1_ctx,
                                      sign1_sample_inputs[i].CBOR,
                                     &payload,
                                      NULL);

        if(result != sign1_sample_inputs[i].expected_error) {
            return i*100 + (int)result;
        }
    }

    return 0;
}


#ifdef T_COSE_ENABLE_HASH_FAIL_TEST

/* Linkage to global variable in t_cose_test_crypto.c. This is only
 * used for an occasional test in a non-threaded environment so a global
 * variable is safe. This test and the hacks in the crypto code are
 * never enabled for commercial deployments.
 */
extern int hash_test_mode;


/*
 * Public function, see t_cose_test.h
 */
int32_t short_circuit_hash_fail_test()
{
    struct t_cose_sign1_sign_ctx sign_ctx;
    enum t_cose_err_t            result;
    struct q_useful_buf_c        wrapped_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB(  signed_cose_buffer, 200);

    /* See test description in t_cose_test.h for a full description of
     * what this does and what it needs to run.
     */


    /* Set the global variable to cause the hash implementation to
     * error out so this test can see what happens
     */
    hash_test_mode = 1;

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_SHORT_CIRCUIT_256);

    result = t_cose_sign1_sign(&sign_ctx,
                                     s_input_payload,
                                     signed_cose_buffer,
                                     &wrapped_payload);

    hash_test_mode = 0;

    if(result != T_COSE_ERR_HASH_GENERAL_FAIL) {
        return 2000 + (int32_t)result;
    }


    /* Set the global variable to cause the hash implementation to
     * error out so this test can see what happens
     */
    hash_test_mode = 2;

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_SHORT_CIRCUIT_256);

    result = t_cose_sign1_sign(&sign_ctx,
                                     s_input_payload,
                                     signed_cose_buffer,
                                     &wrapped_payload);

    hash_test_mode = 0;

    if(result != T_COSE_ERR_HASH_GENERAL_FAIL) {
        return 2000 + (int32_t)result;
    }

    return 0;
}

#endif /* T_COSE_ENABLE_HASH_FAIL_TEST */


/*
 * Public function, see t_cose_test.h
 */
int32_t tags_test()
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    struct t_cose_sign1_verify_ctx  verify_ctx;
    QCBOREncodeContext              cbor_encode;
    enum t_cose_err_t               result;
    Q_USEFUL_BUF_MAKE_STACK_UB(     signed_cose_buffer, 200);
    struct q_useful_buf_c           signed_cose;
    struct q_useful_buf_c           payload;
    QCBORError                      cbor_error;
    uint64_t                        tag;
    struct t_cose_key               key_pair;
    int32_t                         cose_algorithm_id;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_ES256)) {
        cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    } else {
        cose_algorithm_id = T_COSE_ALGORITHM_SHORT_CIRCUIT_256;
    }

    init_fixed_test_signing_key(cose_algorithm_id, &key_pair);

    /* --- Start making COSE Sign1 object tagged 900(901(18())) --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    QCBOREncode_AddTag(&cbor_encode, 900);

    QCBOREncode_AddTag(&cbor_encode, 901);

    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);


    /* Do the first part of the the COSE_Sign1, the parameters */
    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 1, "coap://as.example.com");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 2, "erikw");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 3, "coap://light.example.com");
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 4, 1444064944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 5, 1443944944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 6, 1443944944);
    const uint8_t xx[] = {0x0b, 0x71};
    QCBOREncode_AddBytesToMapN(&cbor_encode, 7, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(xx));
    QCBOREncode_CloseMap(&cbor_encode);

    /* Finish up the COSE_Sign1. This is where the signing happens */
    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + (int32_t)cbor_error;
    }
    /* --- Done making COSE Sign1 object tagged 900(901(18(0))) --- */

    /* --- Compare to expected from CWT RFC --- */
    /* The first part, the intro and protected pararameters, must be the same.
     * This varies by algorithm ID so there's two. The one for ES256
     * is the same as what's in the RFC example.
     */
    struct q_useful_buf_c fp;
    if(cose_algorithm_id == T_COSE_ALGORITHM_ES256) {
        static const uint8_t fpx[] = {0xd9, 0x03, 0x84, 0xd9, 0x03, 0x85,
                                      0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0};
        fp = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(fpx);

    } else {
        /* A different algorithm ID than the RFC because it is short circuit sig */
        static const uint8_t fpx[] = {0xd9, 0x03, 0x84, 0xd9, 0x03, 0x85,
                                      0xd2, 0x84, 0x47, 0xa1, 0x01, 0x3A,
                                      0x00, 0x0F, 0x43, 0x3F, 0xa0};
        fp = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(fpx);
    }
    struct q_useful_buf_c head = q_useful_buf_head(signed_cose, fp.len);
    if(q_useful_buf_compare(head, fp)) {
        return -1;
    }

    /* Compare the payload */
    const uint8_t rfc8392_payload_bytes[] = {
        0x58, 0x50, 0xa7, 0x01, 0x75, 0x63, 0x6f, 0x61, 0x70, 0x3a, 0x2f,
        0x2f, 0x61, 0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x2e, 0x63, 0x6f, 0x6d, 0x02, 0x65, 0x65, 0x72, 0x69, 0x6b, 0x77,
        0x03, 0x78, 0x18, 0x63, 0x6f, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x6c,
        0x69, 0x67, 0x68, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x04, 0x1a, 0x56, 0x12, 0xae, 0xb0,
        0x05, 0x1a, 0x56, 0x10, 0xd9, 0xf0, 0x06, 0x1a, 0x56, 0x10, 0xd9,
        0xf0, 0x07, 0x42, 0x0b, 0x71};

    struct q_useful_buf_c fp2 = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(rfc8392_payload_bytes);

    struct q_useful_buf_c payload2 = q_useful_buf_tail(signed_cose, fp.len);
    struct q_useful_buf_c pl3 = q_useful_buf_head(payload2,
                                                  sizeof(rfc8392_payload_bytes));
    if(q_useful_buf_compare(pl3, fp2)) {
        return -2;
    }

    /* Skip the signature because ECDSA signatures usually have a random
     component */


    /* --- Start verifying the COSE Sign1 object  --- */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                 /* COSE to verify */
                                 signed_cose,
                                 /* The returned payload */
                                 &payload,
                                 /* Don't return parameters */
                                 NULL);
    if(result) {
        return 4000 + (int32_t)result;
    }

    tag = t_cose_sign1_get_nth_tag(&verify_ctx, 0);
    if(tag != 901) {
        return -3;
    }

    tag = t_cose_sign1_get_nth_tag(&verify_ctx, 1);
    if(tag != 900) {
        return -3;
    }

    tag = t_cose_sign1_get_nth_tag(&verify_ctx, 2);
    if(tag != CBOR_TAG_INVALID64) {
        return -4;
    }

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, q_useful_buf_tail(fp2, 2))) {
        return 5000;
    }
    /* --- Done verifying the COSE Sign1 object  --- */


    /* --- Start verifying the COSE Sign1 object, requiring tag--- */
    t_cose_sign1_verify_init(&verify_ctx,
                             T_COSE_OPT_ALLOW_SHORT_CIRCUIT | T_COSE_OPT_TAG_REQUIRED);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);


    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                 /* COSE to verify */
                                 signed_cose,
                                 /* The returned payload */
                                 &payload,
                                 /* Don't return parameters */
                                 NULL);
    if(result != T_COSE_SUCCESS) {
        return 4000 + (int32_t)result;
    }

    /* --- Done verifying the COSE Sign1 object  --- */



    /* --- Start verifying the COSE Sign1 object, prohibiting tag--- */
    t_cose_sign1_verify_init(&verify_ctx,
                             T_COSE_OPT_ALLOW_SHORT_CIRCUIT | T_COSE_OPT_TAG_PROHIBITED);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                 /* COSE to verify */
                                 signed_cose,
                                 /* The returned payload */
                                 &payload,
                                 /* Don't return parameters */
                                 NULL);
    if(result != T_COSE_ERR_INCORRECTLY_TAGGED) {
        return 4000 + (int32_t)result;
    }

    /* --- Done verifying the COSE Sign1 object  --- */



    /* --- Start making COSE Sign1 object  --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    QCBOREncode_AddTag(&cbor_encode, 900);
    QCBOREncode_AddTag(&cbor_encode, 901);
    QCBOREncode_AddTag(&cbor_encode, 902);
    QCBOREncode_AddTag(&cbor_encode, 903);
    QCBOREncode_AddTag(&cbor_encode, 904);

    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);


    /* Do the first part of the the COSE_Sign1, the parameters */
    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 1, "coap://as.example.com");
    QCBOREncode_CloseMap(&cbor_encode);

    /* Finish up the COSE_Sign1. This is where the signing happens */
    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + (int32_t)cbor_error;
    }
    /* --- Done making COSE Sign1 object  --- */

    /* --- Start verifying the COSE Sign1 object  --- */
    t_cose_sign1_verify_init(&verify_ctx, T_COSE_OPT_ALLOW_SHORT_CIRCUIT);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                 /* COSE to verify */
                                 signed_cose,
                                 /* The returned payload */
                                 &payload,
                                 /* Don't return parameters */
                                 NULL);
    if(result != T_COSE_ERR_TOO_MANY_TAGS) {
        return 4000 + (int32_t)result;
    }



    /* --- Start making COSE Sign1 object tagged 900(901()) --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    QCBOREncode_AddTag(&cbor_encode, 900);

    QCBOREncode_AddTag(&cbor_encode, 901);

    t_cose_sign1_sign_init(&sign_ctx,
                           T_COSE_OPT_OMIT_CBOR_TAG,
                           cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);


    /* Do the first part of the the COSE_Sign1, the parameters */
    result = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 1, "coap://as.example.com");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 2, "erikw");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 3, "coap://light.example.com");
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 4, 1444064944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 5, 1443944944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 6, 1443944944);
    const uint8_t xxy[] = {0x0b, 0x71};
    QCBOREncode_AddBytesToMapN(&cbor_encode, 7, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(xxy));
    QCBOREncode_CloseMap(&cbor_encode);

    /* Finish up the COSE_Sign1. This is where the signing happens */
    result = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + (int32_t)cbor_error;
    }
    /* --- Done making COSE Sign1 object tagged 900(901(18(0))) --- */


    /* --- Compare to expected from CWT RFC --- */
    /* The first part, the intro and protected pararameters must be the same,
     * except that the algorithm ID is -1000256 instead of -7 */
    /* The first part, the intro and pararameters must be the same */
    if(cose_algorithm_id == T_COSE_ALGORITHM_ES256) {
        // 0xd9, 0x03, 0x84, 0xd9, 0x03, 0x85
        static const uint8_t fpx[] = {0xd9, 0x03, 0x84, 0xd9, 0x03, 0x85,
                               0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0};
        fp = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(fpx);

    } else {
        /* A different algorithm ID than the RFC because it is short circuit sig */
        static const uint8_t fpx[] = {0xd9, 0x03, 0x84, 0xd9, 0x03, 0x85,
                               0x84, 0x47, 0xa1, 0x01, 0x3A,
                               0x00, 0x0F, 0x43, 0x3F};
        fp = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(fpx);
    }
    head = q_useful_buf_head(signed_cose, fp.len);
    if(q_useful_buf_compare(head, fp)) {
        return -1;
    }


    /* --- Start verifying the COSE Sign1 object, requiring tag--- */
    t_cose_sign1_verify_init(&verify_ctx,
                             T_COSE_OPT_ALLOW_SHORT_CIRCUIT | T_COSE_OPT_TAG_REQUIRED);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                 /* COSE to verify */
                                 signed_cose,
                                 /* The returned payload */
                                 &payload,
                                 /* Don't return parameters */
                                 NULL);
    if(result != T_COSE_ERR_INCORRECTLY_TAGGED) {
        return 4000 + (int32_t)result;
    }


    /* --- Start verifying the COSE Sign1 object, prohibiting tag--- */
    t_cose_sign1_verify_init(&verify_ctx,
                             T_COSE_OPT_ALLOW_SHORT_CIRCUIT | T_COSE_OPT_TAG_PROHIBITED);
    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    /* Run the signature verification */
    result = t_cose_sign1_verify(&verify_ctx,
                                 /* COSE to verify */
                                 signed_cose,
                                 /* The returned payload */
                                 &payload,
                                 /* Don't return parameters */
                                 NULL);
    if(result != T_COSE_SUCCESS) {
        return 4000 + (int32_t)result;
    }

    free_fixed_signing_key(key_pair);

    /* --- Done verifying the COSE Sign1 object  --- */

    return 0;
}


int32_t get_size_test()
{
    struct t_cose_sign1_sign_ctx   sign_ctx;
    QCBOREncodeContext             cbor_encode;
    enum t_cose_err_t              return_value;
    struct q_useful_buf            nil_buf;
    size_t                         calculated_size;
    QCBORError                     cbor_error;
    struct q_useful_buf_c          actual_signed_cose;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          payload;
    struct t_cose_key               key_pair;
    int32_t                         cose_algorithm_id;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_ES256)) {
        cose_algorithm_id = T_COSE_ALGORITHM_ES256;
    } else {
        cose_algorithm_id = T_COSE_ALGORITHM_SHORT_CIRCUIT_256;
    }

    init_fixed_test_signing_key(cose_algorithm_id, &key_pair);

    /* ---- Common Set up ---- */
    payload = Q_USEFUL_BUF_FROM_SZ_LITERAL("payload");

    /* ---- First calculate the size ----- */
    nil_buf = (struct q_useful_buf) {NULL, SIZE_MAX};
    QCBOREncode_Init(&cbor_encode, nil_buf);

    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    return_value = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + (int32_t)return_value;
    }

    QCBOREncode_AddEncoded(&cbor_encode, payload);

    return_value = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 3000 + (int32_t)return_value;
    }

    cbor_error = QCBOREncode_FinishGetSize(&cbor_encode, &calculated_size);
    if(cbor_error) {
        return 4000 + (int32_t)cbor_error;
    }

    /* ---- General sanity check ---- */
    size_t expected_min = payload.len + 64 /* sig */;

    if(calculated_size < expected_min || calculated_size > expected_min + 30) {
        return -1;
    }



    /* ---- Now make a real COSE_Sign1 and compare the size ---- */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);


    return_value = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + (int32_t)return_value;
    }

    QCBOREncode_AddEncoded(&cbor_encode, payload);

    return_value = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 3000 + (int32_t)return_value;
    }

    cbor_error = QCBOREncode_Finish(&cbor_encode, &actual_signed_cose);
    if(actual_signed_cose.len != calculated_size) {
        return -2;
    }

    /* ---- Again with one-call API to make COSE_Sign1 ---- */\
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    return_value = t_cose_sign1_sign(&sign_ctx,
                                     payload,
                                     signed_cose_buffer,
                                     &actual_signed_cose);
    if(return_value) {
        return 7000 + (int32_t)return_value;
    }

    if(actual_signed_cose.len != calculated_size) {
        return -3;
    }
    free_fixed_signing_key(key_pair);

    return 0;
}


/*
 * Public function, see t_cose_test.h
 */
int32_t indef_array_and_map_test()
{
    enum t_cose_err_t  return_value;
    #ifdef TODO_CRIT_PARAM_FIXED
    uint32_t           t_opts;
    #endif



    /* This makes some COSEs with
     *  - The main array of four indefinite length
     *  - The protected header parameters map indef
     *  - The unprotected header parameters map indef
     *  - The critical pamaraters array inde
     */

    /* General test with indefinite lengths */
    return_value = run_test_sign_and_verify(T_COSE_TEST_INDEFINITE_MAPS_ARRAYS);
    if(return_value != T_COSE_SUCCESS) {
        return 1000 + (int32_t) return_value;
    }

#ifdef TODO_CRIT_PARAM_FIXED
    /* Test critical parameters encoded as indefinite length */
    t_opts = T_COSE_TEST_INDEFINITE_MAPS_ARRAYS |
             T_COSE_TEST_UNKNOWN_CRIT_UINT_PARAMETER;
    return_value = run_test_sign_and_verify(t_opts);
    if(return_value != T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER) {
        return 2000 + (int32_t) return_value;
    }

    /* Another general test with indefinite lengths */
    t_opts = T_COSE_TEST_INDEFINITE_MAPS_ARRAYS |
             T_COSE_TEST_ALL_PARAMETERS;
    return_value = run_test_sign_and_verify(t_opts);
    if(return_value != T_COSE_SUCCESS) {
        return 3000 + (int32_t) return_value;
    }
#endif

    return 0;
}


#include "../crypto_adapters/t_cose_test_crypto.h"
/*
 * Public function, see t_cose_test.h
 */
int32_t crypto_context_test()
{
    struct t_cose_sign_sign_ctx         sign_ctx;
    struct t_cose_sign_verify_ctx       verify_ctx;
    enum t_cose_err_t                   result;
    Q_USEFUL_BUF_MAKE_STACK_UB(         good_signed_cose_buffer, 200);
    Q_USEFUL_BUF_MAKE_STACK_UB(         failed_signed_cose_buffer, 200);
    struct q_useful_buf_c               good_signed_cose;
    struct q_useful_buf_c               failed_signed_cose;
    struct q_useful_buf_c               payload;
    struct t_cose_key                   key_pair;
    struct t_cose_test_crypto_context   crypto_context;
    struct t_cose_signature_sign_main   signer;
    struct t_cose_signature_verify_main verifier;


    /* This only works for the test crypto because only it has
     * crypto context behavior tested here.
     */
    if(!t_cose_is_algorithm_supported(T_COSE_ALGORITHM_SHORT_CIRCUIT_256)) {
        return INT32_MIN; /* Means no testing was actually done */
    }
    init_fixed_test_signing_key(T_COSE_ALGORITHM_SHORT_CIRCUIT_256, &key_pair);


    /* __1__ Successfully make a COSE_Sign1 with a set crypto context */
    t_cose_signature_sign_main_init(&signer, T_COSE_ALGORITHM_SHORT_CIRCUIT_256);
    crypto_context.test_error = T_COSE_SUCCESS;
    t_cose_signature_sign_main_set_crypto_context(&signer, &crypto_context);
    t_cose_signature_sign_main_set_signing_key(&signer, key_pair, NULL_Q_USEFUL_BUF_C);
    t_cose_sign_sign_init(&sign_ctx, T_COSE_OPT_MESSAGE_TYPE_SIGN1);
    t_cose_sign_add_signer(&sign_ctx, t_cose_signature_sign_from_main(&signer));
    result = t_cose_sign_sign(&sign_ctx,
                              NULL_Q_USEFUL_BUF_C,
                              s_input_payload,
                              good_signed_cose_buffer,
                             &good_signed_cose);
    if(result != T_COSE_SUCCESS) {
        return 1000 + (int32_t)result;
    }


    /* __2__ Change the value in the crypto context and see a failure  */
    crypto_context.test_error = 18; /* 18 just picked to make test work */
    result = t_cose_sign_sign(&sign_ctx,
                              NULL_Q_USEFUL_BUF_C,
                              s_input_payload,
                              failed_signed_cose_buffer,
                             &failed_signed_cose);
    if(result != 18) {
        return 1000 + (int32_t)result;
    }


    /* __3__ Successfully verify with a set crypto context  */
    t_cose_signature_verify_main_init(&verifier);
    t_cose_signature_verify_main_set_key(&verifier, key_pair, NULL_Q_USEFUL_BUF_C);
    t_cose_signature_verify_main_set_crypto_context(&verifier, &crypto_context);
    crypto_context.test_error = T_COSE_SUCCESS;
    t_cose_sign_verify_init(&verify_ctx, T_COSE_OPT_MESSAGE_TYPE_SIGN1);
    t_cose_sign_add_verifier(&verify_ctx,
                             t_cose_signature_verify_from_main(&verifier));
    result = t_cose_sign_verify(&verify_ctx,
                                /* COSE to verify */
                                good_signed_cose,
                                NULL_Q_USEFUL_BUF_C,
                                /* The returned payload */
                                &payload,
                                /* Don't return parameters */
                                NULL);
    if(result) {
        return 2000 + (int32_t)result;
    }

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, s_input_payload)) {
        return 3000;
    }


    /* __4__ See failure when crypto context is set for failure  */
    crypto_context.test_error = 18; /* 18 just picked to make test work */
    /* Run the signature verification */
    result = t_cose_sign_verify(&verify_ctx,
                                /* COSE to verify */
                                good_signed_cose,
                                NULL_Q_USEFUL_BUF_C,
                                /* The returned payload */
                                &payload,
                                /* Don't return parameters */
                                NULL);
    if(result != 18) {
        return 2000 + (int32_t)result;
    }
    free_fixed_signing_key(key_pair);

    return 0;
}
