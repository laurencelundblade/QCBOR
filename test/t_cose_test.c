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
#include "t_cose_make_test_tokens.h"
#include "t_cose_sign1_verify.h"
#include "t_cose_standard_constants.h"
#include "q_useful_buf.h"
#include "t_cose_crypto.h" /* For signature size constant */


int_fast32_t short_circuit_self_test()
{
    struct t_cose_sign1_ctx     sign_ctx;
    QCBOREncodeContext          cbor_encode;
    enum t_cose_err_t           return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB( signed_cose_buffer, 200);
    struct q_useful_buf_c       signed_cose;
    struct t_cose_key           degenerate_key = {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}};
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

    /* Do the payload of the COSE_Sign1. */
    QCBOREncode_AddSZString(&cbor_encode, "payload");

    /* Finish up the COSE_Sign1. This is where the signing happens */
    return_value = t_cose_sign1_finish(&sign_ctx);
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
    return_value = t_cose_sign1_verify(/* Select short circuit signing */
                                       T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                                       /* No key necessary with short circuit */
                                       degenerate_key,
                                       /* COSE to verify */
                                       signed_cose,
                                       /* The returned payload */
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
    Q_USEFUL_BUF_MAKE_STACK_UB( signed_cose_buffer, 200);
    struct q_useful_buf_c       signed_cose;
    struct t_cose_key   degenerate_key = {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}};
    struct q_useful_buf_c       payload;
    QCBORError                  cbor_error;
    size_t                      payload_offset;

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
                          &cbor_encode); /* encoder context to output to */
    if(return_value) {
        return 1000 + return_value;
    }

    /* Do the payload of the COSE_Sign1. It must be bstr wrapped according
     * to the COSE standard */
    QCBOREncode_AddSZString(&cbor_encode, "payload");

    /* Finish up the COSE_Sign1. This is where the signing happens */
    return_value = t_cose_sign1_finish(&sign_ctx);
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
    return_value = t_cose_sign1_verify(/* Select short circuit signing */
                                       T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                                       /* No key necessary with short circuit */
                                       degenerate_key,
                                       /* COSE to verify */
                                       signed_cose,
                                       /* The returned payload */
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
    Q_USEFUL_BUF_MAKE_STACK_UB(foo, 500);
    struct t_cose_key degenerate_key = {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}};


    /* Test bad algorithm ID 0 */
    QCBOREncode_Init(&cbor_encode, foo);

    return_value =
        t_cose_sign1_init(/* Signing context carried betwteen _init and _finish
                           */
                          &sign_ctx,
                           /* The options flags. Select short-circuit signing */
                          T_COSE_OPT_SHORT_CIRCUIT_SIG,
                          /* Reserved alg ID 0 to cause error. */
                          0,
                          /* No key necessary with short circuit */
                          degenerate_key,
                          /* No key ID needed with short circuit */
                          NULL_Q_USEFUL_BUF_C,
                          /* Pass in the CBOR encoder context that the output
                           * will be written to. For this part is it the
                           * opening array and headers */
                          &cbor_encode);
    if(return_value != T_COSE_ERR_UNSUPPORTED_SIGNING_ALG) {
        return -1;
    }


    /* Test bad algorithm ID -4444444 */
    QCBOREncode_Init(&cbor_encode, foo);

    return_value =
        t_cose_sign1_init(/* Signing context carried betwteen _init and _finish
                          */
                          &sign_ctx,
                          /* The options flags. Select short-circuit signing */
                          T_COSE_OPT_SHORT_CIRCUIT_SIG,
                          /* alg ID to cause error. Unlikely to be a rea one */
                          -4444444,
                          /* No key necessary with short circuit */
                          degenerate_key,
                          /* No key ID needed with short circuit */
                          NULL_Q_USEFUL_BUF_C,
                          /* Pass in the CBOR encoder context that the output
                           * will be written to. For this part is it the
                           * opening array and headers */
                          &cbor_encode);
    if(return_value != T_COSE_ERR_UNSUPPORTED_SIGNING_ALG) {
        return -1;
    }



    /* Tests detection of CBOR encoding error in the payload */
    QCBOREncode_Init(&cbor_encode, foo);

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
                          &cbor_encode);


    QCBOREncode_AddSZString(&cbor_encode, "payload");
    /* Force a CBOR encoding error by closing a map that is not open */
    QCBOREncode_CloseMap(&cbor_encode);

    return_value = t_cose_sign1_finish(&sign_ctx);

    if(return_value != T_COSE_ERR_CBOR_FORMATTING) {
        return -33;
    }


    /* Tests the output buffer being too small */
    Q_USEFUL_BUF_MAKE_STACK_UB(foo2, 15);

    QCBOREncode_Init(&cbor_encode, foo2);

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
                         &cbor_encode);


    QCBOREncode_AddSZString(&cbor_encode, "payload");

    return_value = t_cose_sign1_finish(&sign_ctx);

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
    Q_USEFUL_BUF_MAKE_STACK_UB( signed_cose_buffer, 200);
    struct q_useful_buf_c       signed_cose;
    struct t_cose_key   degenerate_key = {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}};
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
                          &cbor_encode);
    if(return_value) {
        return 1000 + return_value;
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
    return_value = t_cose_sign1_finish(&sign_ctx);
    if(return_value) {
        return 2000 + return_value;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + cbor_error;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* --- Compare to expected from CWT RFC --- */
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
    return_value = t_cose_sign1_verify(/* Select short circuit signing */
                                       T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                                       /* No key necessary with short circuit */
                                       degenerate_key,
                                       /* COSE to verify */
                                       signed_cose,
                                       /* The returned payload */
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



int_fast32_t short_circuit_no_parse_test()
{
    struct t_cose_sign1_ctx     sign_ctx;
    QCBOREncodeContext          cbor_encode;
    enum t_cose_err_t           return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB( signed_cose_buffer, 200);
    struct q_useful_buf_c       signed_cose;
    struct t_cose_key           degenerate_key = {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}};
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


    QCBOREncode_AddSZString(&cbor_encode, "payload");

    /* Finish up the COSE_Sign1. This is where the signing happens */
    return_value = t_cose_sign1_finish(&sign_ctx);
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

    /* -- Tweak signature bytes -- */
    /* The signature is the last thing so reach back that many bytes and tweak
       so if signature verification were attempted, it would fail */
    const size_t last_byte_offset = signed_cose.len - T_COSE_EC_P256_SIG_SIZE;
    ((uint8_t *)signed_cose.ptr)[last_byte_offset] += 1;


    /* --- Start verifying the COSE Sign1 object  --- */
    /* Run the signature verification */
    return_value = t_cose_sign1_verify(/* Select short circuit signing */
                                       T_COSE_OPT_ALLOW_SHORT_CIRCUIT |
                                       /* Select no parsing option to test it */
                                       T_COSE_OPT_PARSE_ONLY,
                                       /* No key necessary with short circuit */
                                       degenerate_key,
                                       /* COSE to verify */
                                       signed_cose,
                                       /* The returned payload */
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


enum t_cose_err_t t_cose_sign1_sign(int32_t option_flags,
                                    int32_t cose_algorithm_id,
                                    struct t_cose_key signing_key,
                                    struct q_useful_buf_c key_id,
                                    struct q_useful_buf_c payload,
                                    struct q_useful_buf outbuf,
                                    struct q_useful_buf_c *result)
{
    struct t_cose_sign1_ctx  cose_context;
    QCBOREncodeContext       encode_context;
    enum t_cose_err_t        return_value;

    QCBOREncode_Init(&encode_context, outbuf);

    return_value = t_cose_sign1_init(&cose_context,
                                     option_flags,
                                     cose_algorithm_id,
                                     signing_key, key_id,
                                     &encode_context);
    if(return_value) {
        goto Done;
    }

    /* Payload may or may not actually be CBOR format here. This function
     * does the job just fine because it just adds bytes to the
     * encoded output without anything extra
     */
    QCBOREncode_AddEncoded( &encode_context, payload);

    return_value = t_cose_sign1_finish(&cose_context);
    if(return_value) {
        goto Done;
    }

    if(QCBOREncode_Finish(&encode_context, result)) {
        return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;

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

int easy_test()
{
    // TODO finish this test with comparison
    enum t_cose_err_t result;
    struct t_cose_key           degenerate_key = {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}};
    Q_USEFUL_BUF_MAKE_STACK_UB( signed_cose_buffer, 200);
    struct q_useful_buf_c output;

    /* Make example C.2.1 from RFC 8152 */

    result = t_cose_sign1_sign(T_COSE_OPT_SHORT_CIRCUIT_SIG,
                               COSE_ALGORITHM_ES256,
                               degenerate_key,
                               Q_USEFUL_BUF_FROM_SZ_LITERAL("11"),
                               Q_USEFUL_BUF_FROM_SZ_LITERAL("This is the content."),
                               signed_cose_buffer,
                               &output);

    return result;


}


static enum t_cose_err_t make_it(int32_t option)
{
    struct t_cose_make_test_token     sign_ctx;
    QCBOREncodeContext          cbor_encode;
    enum t_cose_err_t           return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB( signed_cose_buffer, 200);
    struct q_useful_buf_c       signed_cose;
    struct t_cose_key           degenerate_key = {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}};
    struct q_useful_buf_c       payload;
    QCBORError                  cbor_error;

    /* --- Start making COSE Sign1 object  --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    /* Do the first part of the the COSE_Sign1, the headers */
    return_value =
       t_cose_make_test_token_init(
                                /* Signing context carried betwteen _init and _finish
                                 */
                                &sign_ctx,
                                /* The options flags. Select short-circuit signing */
                                T_COSE_OPT_SHORT_CIRCUIT_SIG | option,
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

    /* Do the payload of the COSE_Sign1. */
    QCBOREncode_AddSZString(&cbor_encode, "payload");

    /* Finish up the COSE_Sign1. This is where the signing happens */
    return_value = t_cose_make_test_token_finish(&sign_ctx);
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
    return_value = t_cose_sign1_verify(/* Select short circuit signing */
                                       T_COSE_OPT_ALLOW_SHORT_CIRCUIT,
                                       /* No key necessary with short circuit */
                                       degenerate_key,
                                       /* COSE to verify */
                                       signed_cose,
                                       /* The returned payload */
                                       &payload);

    return return_value;
}




int_fast32_t bad_headers_test()
{
   /* This one isn't working yet
    if( make_it(XXX_NWFH_2) != T_COSE_ERR_CBOR_NOT_WELL_FORMED) {
        return -999555;
    }*/

    if( make_it(XXX_NWFH_1) != T_COSE_ERR_CBOR_NOT_WELL_FORMED) {
        return -999555;
    }

    if( make_it(XXX_NO_UNPROTECTED_HEADERS) != T_COSE_ERR_HEADER_CBOR) {
        return -999;
    }

    if( make_it(XXX_NO_PROTECTED_HEADERS) != T_COSE_ERR_SIGN1_FORMAT) {
        return -999;
    }

    if( make_it(XXX_EXTRA_HEADER) != T_COSE_SUCCESS) {
        return -999;
    }

    if( make_it(XXX_BAD_CRIT_HEADER) != T_COSE_ERR_HEADER_CBOR) {
        return -99977;
    }

    if( make_it(XXX_HEADER_LABEL_TEST) != T_COSE_ERR_HEADER_CBOR) {
        return -999;
    }



    return 0;
}



int_fast32_t critical_headers_test()
{
    if( make_it(XXX_UNKNOWN_CRIT_HEADER) != T_COSE_ERR_UNKNOWN_CRITICAL_HEADER) {
        return -955;
    }

    if( make_it(XXX_CRIT_HEADER_EXIST) != T_COSE_SUCCESS) {
        return -555;
    }

    /* Not passing yet
    if( make_it(XXX_TOO_MANY_CRIT_HEADER_EXIST) != T_COSE_ERR_TOO_MANY_HEADERS) {
        return -9556;
    }*/

    return 0;
}










