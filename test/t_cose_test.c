/*
 *  t_cose_test.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose_test.h"
#include "t_cose_sign1_sign.h"
#include "t_cose_sign1_verify.h"
#include "t_cose_rfc_constants.h"
#include "q_useful_buf.h"


int_fast32_t short_circuit_self_test()
{
    struct t_cose_sign1_ctx     sign_ctx;
    QCBOREncodeContext          cbor_encode;
    enum t_cose_err_t           return_value;
    struct q_useful_buf_c       wrapped_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB( signed_cose_buffer, 200);
    struct q_useful_buf_c       signed_cose;
    struct t_cose_signing_key   degenerate_key = {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}};
    struct q_useful_buf_c       payload;
    Q_USEFUL_BUF_MAKE_STACK_UB( expected_payload_buffer, 10);
    struct q_useful_buf_c       expected_payload;
    QCBORError                  cbor_error;

    /* --- Start making COSE Sign1 object  --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    /* Do the first part of the the COSE_Sign1, the headers */
    return_value =
        t_cose_sign1_init(/* Signing context carried betwteen _init and _finish
                           */
                          &sign_ctx,
                          /* The options flags. Select short-circuit signing */
                          T_COSE_OPT_SHORT_CIRCUIT_SIG,
                          /* The signing alg. It doesn't really matter what
                           * what it is for short-circuit, but it has to be
                           * something valid. Use ECDSA 256 with SHA 256 */
                          COSE_ALGORITHM_ES256,
                          /* No key necessary with short circuit */
                          degenerate_key,
                          /* No key ID needed with short circuit */
                          NULL_Q_USEFUL_BUF_C,
                          /* Pass in the CBOR encoder context that the output
                           * will be written to. For this part is it the
                           * opening array and headers */
                          &cbor_encode
                          );
    if(return_value) {
        return 1000 + return_value;
    }

    /* Do the payload of the COSE_Sign1. It must be bstr wrapped according
     * to the COSE standard */
    QCBOREncode_BstrWrap(&cbor_encode);
    QCBOREncode_AddSZString(&cbor_encode, "payload");
    QCBOREncode_CloseBstrWrap(&cbor_encode, &wrapped_payload);

    /* Finish up the COSE_Sign1. This is where the signing happens */
    return_value = t_cose_sign1_finish(&sign_ctx, wrapped_payload);
    if(return_value) {
        return 2000 + return_value;
    }

    /* Finally close of the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + cbor_error;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Start verifying the COSE Sign1 object  --- */
    /* Run the signature verification */
    return_value = t_cose_sign1_verify(T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                                       degenerate_key,
                                       signed_cose,
                                       &payload);
    if(return_value) {
        return 4000 + return_value;
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

    return 0;
}



int_fast32_t short_circuit_verify_fail_test()
{
    struct t_cose_sign1_ctx     sign_ctx;
    QCBOREncodeContext          cbor_encode;
    enum t_cose_err_t           return_value;
    struct q_useful_buf_c       wrapped_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB( signed_cose_buffer, 200);
    struct q_useful_buf_c       signed_cose;
    struct t_cose_signing_key   degenerate_key = {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}};
    struct q_useful_buf_c       payload;
    QCBORError                  cbor_error;
    size_t                      payload_offset;

    /* --- Start making COSE Sign1 object  --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    /* Do the first part of the the COSE_Sign1, the headers */
    return_value = t_cose_sign1_init(&sign_ctx, /* Signing context */
                                     T_COSE_OPT_SHORT_CIRCUIT_SIG, /* Select short-circuit */
                                     COSE_ALGORITHM_ES256, /* ECDSA 256 with SHA 256 */
                                     degenerate_key, /* No key necessary with short circuit */
                                     NULL_Q_USEFUL_BUF_C, /* No key ID needed with short circuit */
                                     &cbor_encode /* encoder context to output to */
                                     );
    if(return_value) {
        return 1000 + return_value;
    }

    /* Do the payload of the COSE_Sign1. It must be bstr wrapped according
     * to the COSE standard */
    QCBOREncode_BstrWrap(&cbor_encode);
    QCBOREncode_AddSZString(&cbor_encode, "payload");
    QCBOREncode_CloseBstrWrap(&cbor_encode, &wrapped_payload);

    /* Finish up the COSE_Sign1. This is where the signing happens */
    return_value = t_cose_sign1_finish(&sign_ctx, wrapped_payload);
    if(return_value) {
        return 2000 + return_value;
    }

    /* Finally close of the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + cbor_error;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Start Tamper with payload  --- */
    /* Find the offset of the payload in COSE_Sign1 */
    payload_offset = q_useful_buf_find_bytes(signed_cose, Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"));
    if(payload_offset == SIZE_MAX) {
        return 6000;
    }
    /* Change "payload" to "hayload" */
    ((char *)signed_cose.ptr)[payload_offset] = 'h';
    /* --- Tamper with payload Done --- */


    /* --- Start verifying the COSE Sign1 object  --- */
    /* Run the signature verification */
    return_value = t_cose_sign1_verify(T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                                       degenerate_key,
                                       signed_cose,
                                       &payload);
    if(return_value != T_COSE_ERR_SIG_VERIFY) {
        return 4000 + return_value;
    }
    /* --- Done verifying the COSE Sign1 object  --- */

    return 0;
}


int_fast32_t short_circuit_signing_error_conditions_test()
{
    struct t_cose_sign1_ctx sign_ctx;
    QCBOREncodeContext cbor_encode;
    enum t_cose_err_t  return_value;
    struct q_useful_buf_c wrapped_payload = NULL_Q_USEFUL_BUF_C;
    Q_USEFUL_BUF_MAKE_STACK_UB(foo, 500);
    struct t_cose_signing_key degenerate_key = {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}};


    /* Test bad algorithm ID 0 */
    QCBOREncode_Init(&cbor_encode, foo);

    return_value = t_cose_sign1_init(&sign_ctx,
                                     T_COSE_OPT_SHORT_CIRCUIT_SIG,
                                     0, /* Reserved alg ID 0 */
                                     degenerate_key,
                                     NULL_Q_USEFUL_BUF_C,
                                     &cbor_encode);
    if(return_value != T_COSE_ERR_UNSUPPORTED_SIGNING_ALG) {
        return -1;
    }


    /* Test bad algorithm ID -4444444 */
    QCBOREncode_Init(&cbor_encode, foo);

    return_value = t_cose_sign1_init(&sign_ctx,
                                     T_COSE_OPT_SHORT_CIRCUIT_SIG,
                                     -4444444, /* Picked an alg ID unlikely to be used */
                                     degenerate_key,
                                     NULL_Q_USEFUL_BUF_C,
                                     &cbor_encode);
    if(return_value != T_COSE_ERR_UNSUPPORTED_SIGNING_ALG) {
        return -1;
    }



    /* Tests detection of CBOR encoding error in the payload */
    QCBOREncode_Init(&cbor_encode, foo);

    return_value = t_cose_sign1_init(&sign_ctx,
                                     T_COSE_OPT_SHORT_CIRCUIT_SIG,
                                     COSE_ALGORITHM_ES256,
                                     degenerate_key,
                                     NULL_Q_USEFUL_BUF_C,
                                     &cbor_encode);

    QCBOREncode_BstrWrap(&cbor_encode);

    QCBOREncode_AddSZString(&cbor_encode, "payload");
    /* Force a CBOR encoding error by closing a bstr wrap with a map close */
    QCBOREncode_CloseMap(&cbor_encode);

    return_value = t_cose_sign1_finish(&sign_ctx, wrapped_payload);

    if(return_value != T_COSE_ERR_CBOR_FORMATTING) {
        return -33;
    }


    /* Tests the output buffer being too small */
    Q_USEFUL_BUF_MAKE_STACK_UB(foo2, 15);

    QCBOREncode_Init(&cbor_encode, foo2);

    return_value = t_cose_sign1_init(&sign_ctx, T_COSE_OPT_SHORT_CIRCUIT_SIG, COSE_ALGORITHM_ES256, degenerate_key, NULL_Q_USEFUL_BUF_C, &cbor_encode);

    QCBOREncode_BstrWrap(&cbor_encode);

    QCBOREncode_AddSZString(&cbor_encode, "payload");

    QCBOREncode_CloseMap(&cbor_encode);

    return_value = t_cose_sign1_finish(&sign_ctx, wrapped_payload);

    if(return_value != T_COSE_ERR_TOO_SMALL) {
        return -34;
    }

    return 0;
}



int_fast32_t short_circuit_make_cwt_test()
{
    struct t_cose_sign1_ctx     sign_ctx;
    QCBOREncodeContext          cbor_encode;
    enum t_cose_err_t           return_value;
    struct q_useful_buf_c       wrapped_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB( signed_cose_buffer, 200);
    struct q_useful_buf_c       signed_cose;
    struct t_cose_signing_key   degenerate_key = {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}};
    struct q_useful_buf_c       payload;
    QCBORError                  cbor_error;

    /* --- Start making COSE Sign1 object  --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    /* Do the first part of the the COSE_Sign1, the headers */
    return_value =
    t_cose_sign1_init(/* Signing context carried betwteen _init and _finish
                       */
                      &sign_ctx,
                      /* The options flags. Select short-circuit signing */
                      T_COSE_OPT_SHORT_CIRCUIT_SIG,
                      /* The signing alg. It doesn't really matter what
                       * what it is for short-circuit, but it has to be
                       * something valid. Use ECDSA 256 with SHA 256 */
                      COSE_ALGORITHM_ES256,
                      /* No key necessary with short circuit */
                      degenerate_key,
                      /* No key ID needed with short circuit */
                      NULL_Q_USEFUL_BUF_C,
                      /* Pass in the CBOR encoder context that the output
                       * will be written to. For this part is it the
                       * opening array and headers */
                      &cbor_encode
                      );
    if(return_value) {
        return 1000 + return_value;
    }

    /* Do the payload of the COSE_Sign1. It must be bstr wrapped according
     * to the COSE standard */
    QCBOREncode_BstrWrap(&cbor_encode);

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

    QCBOREncode_CloseBstrWrap(&cbor_encode, &wrapped_payload);

    /* Finish up the COSE_Sign1. This is where the signing happens */
    return_value = t_cose_sign1_finish(&sign_ctx, wrapped_payload);
    if(return_value) {
        return 2000 + return_value;
    }

    /* Finally close of the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + cbor_error;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* Compare to expected from CWT RFC */
    /* The first part, the intro and protected headers must be the same */
    const uint8_t rfc8392_first_part_bytes[] = {0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26};
    struct q_useful_buf_c fp = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(rfc8392_first_part_bytes);
    struct q_useful_buf_c head = q_useful_buf_head(signed_cose, sizeof(rfc8392_first_part_bytes));
    if(q_useful_buf_compare(head, fp)) {
        return -1;
    }

    /* Skip the key id, because this has the short-circuit key id */
    const size_t key_id_encoded_len =
       1 +
       1 +
       2 +
       32; // length of short-circuit key id

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

    /*0x58, 0x40, 0x54, 0x27, 0xc1, 0xff, 0x28, \
    0xd2, 0x3f, 0xba, 0xd1, 0xf2, 0x9c, 0x4c, 0x7c, 0x6a, 0x55, 0x5e, 0x60, 0x1d, 0x6f, 0xa2, 0x9f, 0x91, 0x79, 0xbc, 0x\
    3d, 0x74, 0x38, 0xba, 0xca, 0xca, 0x5a, 0xcd, 0x08, 0xc8, 0xd4, 0xd4, 0xf9, 0x61, 0x31, 0x68, 0x0c, 0x42, 0x9a, 0x01\
    , 0xf8, 0x59, 0x51, 0xec, 0xee, 0x74, 0x3a, 0x52, 0xb9, 0xb6, 0x36, 0x32, 0xc5, 0x72, 0x09, 0x12, 0x0e, 0x1c, 0x9e, \
    30 */


    struct q_useful_buf_c fp2 = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(rfc8392_payload_bytes);

    struct q_useful_buf_c payload2 = q_useful_buf_tail(signed_cose,
                                                       sizeof(rfc8392_first_part_bytes)+key_id_encoded_len);
    struct q_useful_buf_c pl3 = q_useful_buf_head(payload2, sizeof(rfc8392_payload_bytes));
    if(q_useful_buf_compare(pl3, fp2)) {
        return -1;
    }

    /* Skip the signature because ECDSA signatures usually have a random
     component */


    /* --- Start verifying the COSE Sign1 object  --- */
    /* Run the signature verification */
    return_value = t_cose_sign1_verify(T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                                       degenerate_key,
                                       signed_cose,
                                       &payload);
    if(return_value) {
        return 4000 + return_value;
    }

    /* Format the expected payload CBOR fragment */

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, q_useful_buf_tail(fp2, 2))) {
        return 5000;
    }
    /* --- Done verifying the COSE Sign1 object  --- */

    return 0;
}

