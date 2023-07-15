/*
 *  t_cose_compute_validate_mac_test.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/t_cose_mac_compute.h"
#include "t_cose/t_cose_mac_validate.h"
#include "t_cose/t_cose_key.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose_compute_validate_mac_test.h"


#define KEY_hmac256 \
0x0b, 0x2d, 0x6f, 0x32, 0x53, 0x67, 0x86, 0xb3, 0x8f, 0x83, 0x56, 0xaa, \
0xe0, 0x8c, 0x05, 0x52, 0x79, 0x31, 0xdd, 0x43, 0xef, 0xe9, 0xf4, 0x12, \
0x0c, 0x28, 0x19, 0x01, 0xba, 0x1f, 0x89, 0x39

#define KEY_hmac384 \
0x3f, 0x39, 0xb4, 0xe0, 0x78, 0x3e, 0x4c, 0x54, 0x82, 0x4f, 0xed, 0xee, \
0x37, 0x9a, 0x79, 0x66, 0xfe, 0xfa, 0x1d, 0xf6, 0x35, 0x30, 0xc8, 0xcf, \
0x60, 0xac, 0xef, 0x9d, 0x72, 0x08, 0x8d, 0x47, 0x41, 0x88, 0xeb, 0x7d, \
0xc6, 0x5f, 0xff, 0x63, 0x6f, 0x99, 0x8a, 0xcc, 0x24, 0xa2, 0x2c, 0xd0

#define KEY_hmac512 \
0x99, 0xf7, 0xab, 0xc8, 0x3f, 0xe8, 0x73, 0x90, 0xa9, 0x9f, 0x83, 0xa7, \
0xd4, 0xc2, 0xa1, 0xa8, 0xad, 0x64, 0xed, 0x54, 0xbb, 0x99, 0x96, 0xb5, \
0xb4, 0xd8, 0xec, 0x17, 0x93, 0xa6, 0x1b, 0x84, 0x7a, 0xfd, 0xd3, 0xba, \
0x05, 0x32, 0xef, 0x55, 0xa4, 0x4f, 0xae, 0x4c, 0x95, 0x39, 0xdf, 0x28, \
0x82, 0x27, 0x78, 0xe2, 0x35, 0x14, 0x13, 0x0c, 0x9d, 0x33, 0x96, 0xaa, \
0x22, 0xe4, 0x72, 0x7d

static const uint8_t key_256[] = {KEY_hmac256};
static const uint8_t key_384[] = {KEY_hmac384};
static const uint8_t key_512[] = {KEY_hmac512};

enum t_cose_err_t
make_hmac_key(int32_t cose_alg, struct t_cose_key *key)
{
    struct q_useful_buf_c key_bytes;

    switch(cose_alg) {
    case T_COSE_ALGORITHM_HMAC256:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(key_256);
        break;

    case T_COSE_ALGORITHM_HMAC384:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(key_384);
        break;

    case T_COSE_ALGORITHM_HMAC512:
        key_bytes = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(key_512);
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    return t_cose_key_init_symmetric(cose_alg, key_bytes, key);
}


/*
 * Compute and validate a test COSE_Mac0 message with the selected MAC algorithm.
 */
static int32_t compute_validate_basic_test_alg_mac(int32_t cose_alg)
{
    struct t_cose_mac_calculate_ctx   mac_ctx;
    struct t_cose_mac_validate_ctx    validate_ctx;
    int32_t                      return_value;
    enum t_cose_err_t            cose_res;
    Q_USEFUL_BUF_MAKE_STACK_UB(  maced_cose_buffer, 300);
    struct q_useful_buf_c        maced_cose;
    struct t_cose_key            key;
    struct q_useful_buf_c        in_payload = Q_USEFUL_BUF_FROM_SZ_LITERAL("payload");
    struct q_useful_buf_c        out_payload;

    /* -- Get started with context initialization, selecting the alg -- */
    t_cose_mac_compute_init(&mac_ctx, 0, cose_alg);

    /* Make an HMAC key that will be used for both computing the
     * authentication tag and validation.
     */
    cose_res = make_hmac_key(cose_alg, &key);
    if(cose_res != T_COSE_SUCCESS) {
        return 1000 + (int32_t)cose_res;
    }
    t_cose_mac_set_computing_key(&mac_ctx, key, NULL_Q_USEFUL_BUF_C);

    cose_res = t_cose_mac_compute(&mac_ctx,
                                   NULL_Q_USEFUL_BUF_C,
                                   in_payload,
                                   maced_cose_buffer,
                                  &maced_cose);
    if(cose_res != T_COSE_SUCCESS) {
        return_value = 2000 + (int32_t)cose_res;
        goto Done;
    }

    /* Validation */
    t_cose_mac_validate_init(&validate_ctx, 0);

    t_cose_mac_set_validate_key(&validate_ctx, key);

    cose_res = t_cose_mac_validate(&validate_ctx,
                                    maced_cose,  /* COSE to validate */
                                    NULL_Q_USEFUL_BUF_C,
                                   &out_payload, /* Payload from maced_cose */
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
    t_cose_key_free_symmetric(key);

    return return_value;
}


/*
 * Public function, see t_cose_compute_validate_mac_test.h
 */
int32_t compute_validate_mac_basic_test()
{
    int32_t return_value;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_HMAC256)) {
        return_value  = compute_validate_basic_test_alg_mac(
                                                    T_COSE_ALGORITHM_HMAC256);
        if(return_value) {
            return 20000 + return_value;
        }
    }

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_HMAC384)) {
        return_value  = compute_validate_basic_test_alg_mac(
                                                    T_COSE_ALGORITHM_HMAC384);
        if(return_value) {
            return 30000 + return_value;
        }
    }

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_HMAC512)) {
        return_value  = compute_validate_basic_test_alg_mac(
                                                    T_COSE_ALGORITHM_HMAC512);
        if(return_value) {
            return 50000 + return_value;
        }
    }

    return 0;
}


/*
 * Public function, see t_cose_compute_validate_mac_test.h
 */
int32_t compute_validate_mac_fail_test()
{
    struct t_cose_mac_calculate_ctx   mac_ctx;
    struct t_cose_mac_validate_ctx    validate_ctx;
    QCBOREncodeContext           cbor_encode;
    int32_t                      return_value;
    enum t_cose_err_t            result;
    Q_USEFUL_BUF_MAKE_STACK_UB(  maced_cose_buffer, 300);
    struct q_useful_buf_c        maced_cose;
    struct t_cose_key            key;
    struct q_useful_buf_c        payload;
    QCBORError                   cbor_error;
    size_t                       tamper_offset;

    if (!t_cose_is_algorithm_supported(T_COSE_ALGORITHM_HMAC256)) {
        return 0;
    }

    /* Make an HMAC key that will be used for both computing the
     * authentication tag and validation.
     */
    result = make_hmac_key(T_COSE_ALGORITHM_HMAC256, &key);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_Init(&cbor_encode, maced_cose_buffer);

    t_cose_mac_compute_init(&mac_ctx, 0, T_COSE_ALGORITHM_HMAC256);
    t_cose_mac_set_computing_key(&mac_ctx, key, NULL_Q_USEFUL_BUF_C);

    result = t_cose_mac_encode_parameters(&mac_ctx, &cbor_encode);
    if(result) {
        return_value = 2000 + (int32_t)result;
        goto Done;
    }

    QCBOREncode_BstrWrap(&cbor_encode);
    QCBOREncode_AddSZString(&cbor_encode, "payload");
    QCBOREncode_CloseBstrWrap2(&cbor_encode, false, &payload);

    result = t_cose_mac_encode_tag(&mac_ctx, payload, &cbor_encode);
    if(result) {
        return_value = 3000 + (int32_t)result;
        goto Done;
    }

    cbor_error = QCBOREncode_Finish(&cbor_encode, &maced_cose);
    if(cbor_error) {
        return_value = 4000 + (int32_t)cbor_error;
        goto Done;
    }

    /* Tamper with the pay load to see that the MAC validation fails */
    tamper_offset = q_useful_buf_find_bytes(maced_cose, Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"));
    if(tamper_offset == SIZE_MAX) {
        return_value = 99;
        goto Done;
    }
    /* Change "payload" to "hayload" */
    struct q_useful_buf temp_unconst = q_useful_buf_unconst(maced_cose);
    ((char *)temp_unconst.ptr)[tamper_offset] = 'h';

    t_cose_mac_validate_init(&validate_ctx, 0);

    t_cose_mac_set_validate_key(&validate_ctx, key);

    result = t_cose_mac_validate(&validate_ctx,
                                  maced_cose, /* COSE to validate */
                                  NULL_Q_USEFUL_BUF_C,
                                 &payload,    /* Payload from maced_cose */
                                  NULL);

    if(result != T_COSE_ERR_HMAC_VERIFY) {
        return_value = 5000 + (int32_t)result;
    }

    return_value = 0;

Done:
    t_cose_key_free_symmetric(key);

    return return_value;
}


static int size_test(int32_t               cose_algorithm_id,
                     struct q_useful_buf_c kid,
                     struct t_cose_key     key)
{
    struct t_cose_mac_calculate_ctx mac_ctx;
    QCBOREncodeContext         cbor_encode;
    enum t_cose_err_t          return_value;
    struct q_useful_buf        nil_buf;
    size_t                     calculated_size;
    QCBORError                 cbor_error;
    struct q_useful_buf_c      actual_maced_cose;
    Q_USEFUL_BUF_MAKE_STACK_UB(maced_cose_buffer, 300);
    struct q_useful_buf_c      payload;

    /* ---- Common Set up ---- */
    payload = Q_USEFUL_BUF_FROM_SZ_LITERAL("payload");

    /* ---- First calculate the size ----- */
    nil_buf = (struct q_useful_buf) {NULL, INT32_MAX};
    QCBOREncode_Init(&cbor_encode, nil_buf);

    t_cose_mac_compute_init(&mac_ctx, 0, cose_algorithm_id);
    t_cose_mac_set_computing_key(&mac_ctx, key, kid);

    return_value = t_cose_mac_encode_parameters(&mac_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + (int32_t)return_value;
    }

    QCBOREncode_AddBytes(&cbor_encode, payload);

    return_value = t_cose_mac_encode_tag(&mac_ctx, payload, &cbor_encode);
    if(return_value) {
        return 3000 + (int32_t)return_value;
    }

    cbor_error = QCBOREncode_FinishGetSize(&cbor_encode, &calculated_size);
    if(cbor_error) {
        return 4000 + (int32_t)cbor_error;
    }

    /* ---- Now make a real COSE_Mac0 and compare the size ---- */
    QCBOREncode_Init(&cbor_encode, maced_cose_buffer);

    t_cose_mac_compute_init(&mac_ctx, 0, cose_algorithm_id);
    t_cose_mac_set_computing_key(&mac_ctx, key, kid);

    return_value = t_cose_mac_encode_parameters(&mac_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + (int32_t)return_value;
    }

    QCBOREncode_AddBytes(&cbor_encode, payload);

    return_value = t_cose_mac_encode_tag(&mac_ctx, payload, &cbor_encode);
    if(return_value) {
        return 3000 + (int32_t)return_value;
    }

    cbor_error = QCBOREncode_Finish(&cbor_encode, &actual_maced_cose);
    if(actual_maced_cose.len != calculated_size) {
        return -2;
    }

    /* ---- Again with one-call API to make COSE_Mac0 ---- */\
    t_cose_mac_compute_init(&mac_ctx, 0, cose_algorithm_id);
    t_cose_mac_set_computing_key(&mac_ctx, key, kid);
    return_value = t_cose_mac_compute(&mac_ctx,
                                       NULL_Q_USEFUL_BUF_C,
                                       payload,
                                       maced_cose_buffer,
                                      &actual_maced_cose);
    if(return_value) {
        return 7000 + (int32_t)return_value;
    }

    if(actual_maced_cose.len != calculated_size) {
        return -3;
    }

    return 0;
}


/*
 * Public function, see t_cose_compute_validate_mac_test.h
 */
int32_t compute_validate_get_size_mac_test()
{
    enum t_cose_err_t return_value;
    struct t_cose_key key;
    int32_t           result;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_HMAC256)) {
        return_value = make_hmac_key(T_COSE_ALGORITHM_HMAC256, &key);
        if(return_value) {
            return 10000 + (int32_t)return_value;
        }

        result = size_test(T_COSE_ALGORITHM_HMAC256, NULL_Q_USEFUL_BUF_C, key);
        t_cose_key_free_symmetric(key);
        if(result) {
            return 20000 + result;
        }
    }

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_HMAC384)) {
        return_value = make_hmac_key(T_COSE_ALGORITHM_HMAC384, &key);
        if(return_value) {
            return 30000 + (int32_t)return_value;
        }

        result = size_test(T_COSE_ALGORITHM_HMAC384, NULL_Q_USEFUL_BUF_C, key);
        t_cose_key_free_symmetric(key);
        if(result) {
            return 40000 + result;
        }
    }

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_HMAC512)) {
        return_value = make_hmac_key(T_COSE_ALGORITHM_HMAC512, &key);
        if(return_value) {
            return 50000 + (int32_t)return_value;
        }

        result = size_test(T_COSE_ALGORITHM_HMAC512, NULL_Q_USEFUL_BUF_C, key);
        if(result) {
            t_cose_key_free_symmetric(key);
            return 60000 + result;
        }

        result = size_test(T_COSE_ALGORITHM_HMAC512,
                           Q_USEFUL_BUF_FROM_SZ_LITERAL("greasy kid stuff"),
                           key);
        t_cose_key_free_symmetric(key);
        if(result) {
            return 70000 + result;
        }
    }

    return 0;
}


/*
 * Public function, see t_cose_compute_validate_mac_test.h
 */
int32_t compute_validate_detached_content_mac_fail_test()
{
    struct t_cose_mac_calculate_ctx   mac_ctx;
    struct t_cose_mac_validate_ctx    validate_ctx;
    QCBOREncodeContext           cbor_encode;
    int32_t                      return_value;
    enum t_cose_err_t            result;
    Q_USEFUL_BUF_MAKE_STACK_UB(  maced_cose_buffer, 300);
    struct q_useful_buf_c        maced_cose;
    struct t_cose_key            key;
    QCBORError                   cbor_error;

    if (!t_cose_is_algorithm_supported(T_COSE_ALGORITHM_HMAC256)) {
        return 0;
    }

    /* ---- Set up ---- */

    /* Make an HMAC key that will be used for both computing the
     * authentication tag and validation.
     */
    result = make_hmac_key(T_COSE_ALGORITHM_HMAC256, &key);
    if(result) {
        return 1000 + (int32_t)result;
    }

    QCBOREncode_Init(&cbor_encode, maced_cose_buffer);

    t_cose_mac_compute_init(&mac_ctx, 0, T_COSE_ALGORITHM_HMAC256);
    t_cose_mac_set_computing_key(&mac_ctx, key, NULL_Q_USEFUL_BUF_C);

    result = t_cose_mac_encode_parameters(&mac_ctx, &cbor_encode);
    if(result) {
        return_value = 2000 + (int32_t)result;
        goto Done;
    }

    QCBOREncode_AddNULL(&cbor_encode);

    result = t_cose_mac_encode_tag(&mac_ctx,
                                   Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"),
                                   &cbor_encode);
    if(result) {
        return_value = 3000 + (int32_t)result;
        goto Done;
    }

    cbor_error = QCBOREncode_Finish(&cbor_encode, &maced_cose);
    if(cbor_error) {
        return_value = 4000 + (int32_t)cbor_error;
        goto Done;
    }

    /* Set up tampered detached payload */

    t_cose_mac_validate_init(&validate_ctx, 0);

    t_cose_mac_set_validate_key(&validate_ctx, key);

    result = t_cose_mac_validate_detached(&validate_ctx, /* in: me*/
                                           maced_cose, /* in: COSE message to validate */
                                           NULL_Q_USEFUL_BUF_C, /* in: AAD */
                                           Q_USEFUL_BUF_FROM_SZ_LITERAL("hayload"), /* in: detached payload */
                                          NULL); /* out: decoded parameters */

    if(result != T_COSE_ERR_HMAC_VERIFY) {
        return_value = 5000 + (int32_t)result;
        goto Done;
    }

    return_value = 0;

Done:
    t_cose_key_free_symmetric(key);

    return return_value;
}


static int detached_content_size_test(int32_t               cose_algorithm_id,
                                      struct q_useful_buf_c kid,
                                      struct t_cose_key     key)
{
    struct t_cose_mac_calculate_ctx mac_ctx;
    QCBOREncodeContext         cbor_encode;
    enum t_cose_err_t          return_value;
    struct q_useful_buf        nil_buf;
    size_t                     calculated_size;
    QCBORError                 cbor_error;
    struct q_useful_buf_c      actual_maced_cose;
    Q_USEFUL_BUF_MAKE_STACK_UB(maced_cose_buffer, 300);
    struct q_useful_buf_c      payload;

    /* ---- Common Set up ---- */
    payload = Q_USEFUL_BUF_FROM_SZ_LITERAL("payload");

    /* ---- First calculate the size ----- */
    nil_buf = (struct q_useful_buf) {NULL, INT32_MAX};
    QCBOREncode_Init(&cbor_encode, nil_buf);

    t_cose_mac_compute_init(&mac_ctx, 0, cose_algorithm_id);
    t_cose_mac_set_computing_key(&mac_ctx, key, kid);

    return_value = t_cose_mac_encode_parameters(&mac_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + (int32_t)return_value;
    }

    QCBOREncode_AddNULL(&cbor_encode);

    return_value = t_cose_mac_encode_tag(&mac_ctx, payload, &cbor_encode);
    if(return_value) {
        return 3000 + (int32_t)return_value;
    }

    cbor_error = QCBOREncode_FinishGetSize(&cbor_encode, &calculated_size);
    if(cbor_error) {
        return 4000 + (int32_t)cbor_error;
    }

    /* ---- Now make a real COSE_Mac0 and compare the size ---- */
    QCBOREncode_Init(&cbor_encode, maced_cose_buffer);

    t_cose_mac_compute_init(&mac_ctx, 0, cose_algorithm_id);
    t_cose_mac_set_computing_key(&mac_ctx, key, kid);

    return_value = t_cose_mac_encode_parameters(&mac_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + (int32_t)return_value;
    }

    QCBOREncode_AddNULL(&cbor_encode);

    return_value = t_cose_mac_encode_tag(&mac_ctx, payload, &cbor_encode);
    if(return_value) {
        return 3000 + (int32_t)return_value;
    }

    cbor_error = QCBOREncode_Finish(&cbor_encode, &actual_maced_cose);
    if(actual_maced_cose.len != calculated_size) {
        return -2;
    }

    /* ---- Again with one-call API to make COSE_Mac0 ---- */\
    t_cose_mac_compute_init(&mac_ctx, 0, cose_algorithm_id);
    t_cose_mac_set_computing_key(&mac_ctx, key, kid);
    return_value = t_cose_mac_compute_detached(&mac_ctx,
                                                NULL_Q_USEFUL_BUF_C,
                                                payload,
                                                maced_cose_buffer,
                                               &actual_maced_cose);
    if(return_value) {
        return 7000 + (int32_t)return_value;
    }

    if(actual_maced_cose.len != calculated_size) {
        return -3;
    }

    return 0;
}


/*
 * Public function, see t_cose_compute_validate_mac_test.h
 */
int32_t compute_validate_get_size_detached_content_mac_test()
{
    enum t_cose_err_t return_value;
    struct t_cose_key key;
    int32_t           result;

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_HMAC256)) {
        return_value = make_hmac_key(T_COSE_ALGORITHM_HMAC256, &key);
        if(return_value) {
            return 10000 + (int32_t)return_value;
        }

        result = detached_content_size_test(T_COSE_ALGORITHM_HMAC256, NULL_Q_USEFUL_BUF_C, key);
        t_cose_key_free_symmetric(key);
        if(result) {
            return 20000 + result;
        }
    }

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_HMAC384)) {
        return_value = make_hmac_key(T_COSE_ALGORITHM_HMAC384, &key);
        if(return_value) {
            return 30000 + (int32_t)return_value;
        }

        result = detached_content_size_test(T_COSE_ALGORITHM_HMAC384, NULL_Q_USEFUL_BUF_C, key);
        t_cose_key_free_symmetric(key);
        if(result) {
            return 40000 + result;
        }
    }

    if(t_cose_is_algorithm_supported(T_COSE_ALGORITHM_HMAC512)) {
        return_value = make_hmac_key(T_COSE_ALGORITHM_HMAC512, &key);
        if(return_value) {
            return 50000 + (int32_t)return_value;
        }

        result = detached_content_size_test(T_COSE_ALGORITHM_HMAC512, NULL_Q_USEFUL_BUF_C, key);
        if(result) {
            t_cose_key_free_symmetric(key);
            return 60000 + result;
        }

        result = detached_content_size_test(T_COSE_ALGORITHM_HMAC512,
                           Q_USEFUL_BUF_FROM_SZ_LITERAL("greasy kid stuff"),
                           key);
        t_cose_key_free_symmetric(key);
        if(result) {
            return 70000 + result;
        }
    }

    return 0;
}
