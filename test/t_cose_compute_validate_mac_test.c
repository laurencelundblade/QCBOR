/*
 *  t_cose_compute_validate_mac_test.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/t_cose_mac_compute.h"
#include "t_cose/t_cose_mac_validate.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose_make_test_pub_key.h"
#include "t_cose_compute_validate_mac_test.h"

#include "t_cose_crypto.h" /* Just for t_cose_crypto_sig_size() */

#ifndef T_COSE_DISABLE_MAC0

/*
 * Public function, see t_cose_compute_validate_mac_test.h
 */
int_fast32_t sign_verify_basic_test_alg_mac(uint8_t cose_alg)
{
    struct t_cose_mac_calculate_ctx   sign_ctx;
    int32_t                      return_value;
    enum t_cose_err_t            cose_res;
    Q_USEFUL_BUF_MAKE_STACK_UB(  signed_cose_buffer, 300);
    struct q_useful_buf_c        signed_cose;
    struct t_cose_key            key;
    struct q_useful_buf_c        in_payload = Q_USEFUL_BUF_FROM_SZ_LITERAL("payload");
    struct q_useful_buf_c        out_payload;
    struct t_cose_mac_validate_ctx verify_ctx;

    /* -- Get started with context initialization, selecting the alg -- */
    t_cose_mac_compute_init(&sign_ctx, 0, cose_alg);

    /* Make an HMAC key that will be used for both signing and
     * verification.
     */
    cose_res = make_hmac_key(cose_alg, &key);
    if(cose_res != T_COSE_SUCCESS) {
        return 1000 + (int32_t)cose_res;
    }
    t_cose_mac_set_computing_key(&sign_ctx, key, NULL_Q_USEFUL_BUF_C);

    cose_res = t_cose_mac_compute(&sign_ctx,
                                     NULL_Q_USEFUL_BUF_C,
                                     in_payload,
                                     signed_cose_buffer,
                                    &signed_cose);
    if(cose_res != T_COSE_SUCCESS) {
        return_value = 2000 + (int32_t)cose_res;
        goto Done;
    }

    /* Verification */
    t_cose_mac_validate_init(&verify_ctx, 0);

    t_cose_mac_set_validate_key(&verify_ctx, key);

    cose_res = t_cose_mac_validate(&verify_ctx,
                                  signed_cose, /* COSE to verify */
                                  NULL_Q_USEFUL_BUF_C,
                                 &out_payload, /* Payload from signed_cose */
                                  NULL);
    if(cose_res != T_COSE_SUCCESS) {
        return_value = 5000 + (int32_t)cose_res;
        goto Done;
    }

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(out_payload, in_payload)) {
        return_value = 6000;
        goto Done;
    }

    return_value = 0;

Done:
    /* Many crypto libraries allocate memory, slots, etc for keys */
    free_key(key);

    return return_value;
}


/*
 * Public function, see t_cose_compute_validate_mac_test.h
 */
int_fast32_t sign_verify_mac_basic_test()
{
    int_fast32_t return_value;

    return_value  = sign_verify_basic_test_alg_mac(T_COSE_ALGORITHM_HMAC256);
    if(return_value) {
        return 20000 + return_value;
    }

    return_value  = sign_verify_basic_test_alg_mac(T_COSE_ALGORITHM_HMAC384);
    if(return_value) {
        return 30000 + return_value;
    }

    return_value  = sign_verify_basic_test_alg_mac(T_COSE_ALGORITHM_HMAC512);
    if(return_value) {
        return 50000 + return_value;
    }

    return 0;
}


/*
 * Public function, see t_cose_compute_validate_mac_test.h
 */
int_fast32_t sign_verify_mac_sig_fail_test()
{
    struct t_cose_mac_calculate_ctx   sign_ctx;
    QCBOREncodeContext           cbor_encode;
    int32_t                      return_value;
    enum t_cose_err_t            result;
    Q_USEFUL_BUF_MAKE_STACK_UB(  signed_cose_buffer, 300);
    struct q_useful_buf_c        signed_cose;
    struct t_cose_key            key_pair;
    struct q_useful_buf_c        payload;
    QCBORError                   cbor_error;
    struct t_cose_mac_validate_ctx verify_ctx;
    size_t                       tamper_offset;


    /* Make an HMAC key that will be used for both signing and
     * verification.
     */
    result = make_hmac_key(T_COSE_ALGORITHM_HMAC256,&key_pair);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_mac_compute_init(&sign_ctx, 0, T_COSE_ALGORITHM_HMAC256);
    t_cose_mac_set_computing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    result = t_cose_mac_encode_parameters(&sign_ctx, &cbor_encode);
    if(result) {
        return_value = 2000 + (int32_t)result;
        goto Done;
    }

    QCBOREncode_AddSZString(&cbor_encode, "payload");

    result = t_cose_mac_encode_tag(&sign_ctx, &cbor_encode);
    if(result) {
        return_value = 3000 + (int32_t)result;
        goto Done;
    }

    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return_value = 4000 + (int32_t)cbor_error;
        goto Done;
    }

    /* tamper with the pay load to see that the signature verification fails */
    tamper_offset = q_useful_buf_find_bytes(signed_cose, Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"));
    if(tamper_offset == SIZE_MAX) {
        return_value = 99;
        goto Done;
    }
    /* Change "payload" to "hayload" */
    struct q_useful_buf temp_unconst = q_useful_buf_unconst(signed_cose);
    ((char *)temp_unconst.ptr)[tamper_offset] = 'h';

    t_cose_mac_validate_init(&verify_ctx, 0);

    t_cose_mac_set_validate_key(&verify_ctx, key_pair);

    result = t_cose_mac_validate(&verify_ctx,
                                signed_cose, /* COSE to verify */
                                NULL_Q_USEFUL_BUF_C,
                               &payload,     /* Payload from signed_cose */
                                NULL);

    if(result != T_COSE_ERR_SIG_VERIFY) {
        return_value = 5000 + (int32_t)result;
    }

    return_value = 0;

Done:
    free_key(key_pair);

    return return_value;
}

/*
 * Public function, see t_cose_compute_validate_mac_test.h
 */
static int size_test(int32_t               cose_algorithm_id,
                     struct q_useful_buf_c kid,
                     struct t_cose_key     key_pair)
{
    struct t_cose_mac_calculate_ctx sign_ctx;
    QCBOREncodeContext         cbor_encode;
    enum t_cose_err_t          return_value;
    struct q_useful_buf        nil_buf;
    size_t                     calculated_size;
    QCBORError                 cbor_error;
    struct q_useful_buf_c      actual_signed_cose;
    Q_USEFUL_BUF_MAKE_STACK_UB(signed_cose_buffer, 300);
    struct q_useful_buf_c      payload;

    /* ---- Common Set up ---- */
    payload = Q_USEFUL_BUF_FROM_SZ_LITERAL("payload");

    /* ---- First calculate the size ----- */
    nil_buf = (struct q_useful_buf) {NULL, INT32_MAX};
    QCBOREncode_Init(&cbor_encode, nil_buf);

    t_cose_mac_compute_init(&sign_ctx,  0,  cose_algorithm_id);
    t_cose_mac_set_computing_key(&sign_ctx, key_pair, kid);

    return_value = t_cose_mac_encode_parameters(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + (int32_t)return_value;
    }

    QCBOREncode_AddEncoded(&cbor_encode, payload);

    return_value = t_cose_mac_encode_tag(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 3000 + (int32_t)return_value;
    }

    cbor_error = QCBOREncode_FinishGetSize(&cbor_encode, &calculated_size);
    if(cbor_error) {
        return 4000 + (int32_t)cbor_error;
    }

    /* ---- Now make a real COSE_Mac0 and compare the size ---- */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_mac_compute_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_mac_set_computing_key(&sign_ctx, key_pair, kid);

    return_value = t_cose_mac_encode_parameters(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + (int32_t)return_value;
    }

    QCBOREncode_AddEncoded(&cbor_encode, payload);

    return_value = t_cose_mac_encode_tag(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 3000 + (int32_t)return_value;
    }

    cbor_error = QCBOREncode_Finish(&cbor_encode, &actual_signed_cose);
    if(actual_signed_cose.len != calculated_size) {
        return -2;
    }

    /* ---- Again with one-call API to make COSE_Mac0 ---- */\
    t_cose_mac_compute_init(&sign_ctx, 0, cose_algorithm_id);
    t_cose_mac_set_computing_key(&sign_ctx, key_pair, kid);
    return_value = t_cose_mac_compute(&sign_ctx,
                                         NULL_Q_USEFUL_BUF_C,
                                         payload,
                                         signed_cose_buffer,
                                        &actual_signed_cose);
    if(return_value) {
        return 7000 + (int32_t)return_value;
    }

    if(actual_signed_cose.len != calculated_size) {
        return -3;
    }

    return 0;
}


/*
 * Public function, see t_cose_compute_validate_mac_test.h
 */
int_fast32_t sign_verify_get_size_mac_test()
{
    enum t_cose_err_t return_value;
    struct t_cose_key key_pair;
    int32_t           result;

    return_value = make_hmac_key(T_COSE_ALGORITHM_HMAC256, &key_pair);
    if(return_value) {
        return 10000 + (int32_t)return_value;
    }

    result = size_test(T_COSE_ALGORITHM_HMAC256, NULL_Q_USEFUL_BUF_C, key_pair);
    free_key(key_pair);
    if(result) {
        return 20000 + result;
    }

    return_value = make_hmac_key(T_COSE_ALGORITHM_HMAC384, &key_pair);
    if(return_value) {
        return 30000 + (int32_t)return_value;
    }

    result = size_test(T_COSE_ALGORITHM_HMAC384, NULL_Q_USEFUL_BUF_C, key_pair);
    free_key(key_pair);
    if(result) {
        return 40000 + result;
    }

    return_value = make_hmac_key(T_COSE_ALGORITHM_HMAC512, &key_pair);
    if(return_value) {
        return 50000 + (int32_t)return_value;
    }

    result = size_test(T_COSE_ALGORITHM_HMAC512, NULL_Q_USEFUL_BUF_C, key_pair);
    if(result) {
        free_key(key_pair);
        return 60000 + result;
    }

    result = size_test(T_COSE_ALGORITHM_HMAC512,
                       Q_USEFUL_BUF_FROM_SZ_LITERAL("greasy kid stuff"),
                       key_pair);
    free_key(key_pair);
    if(result) {
        return 70000 + result;
    }

    return 0;
}

#endif /* !T_COSE_DISABLE_MAC0 */
