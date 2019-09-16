/*
 *  t_cose_openssl_test.c
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


extern int hash_test_mode;


int_fast32_t short_circuit_hash_fail_test()
{
    struct t_cose_sign1_ctx     sign_ctx;
    QCBOREncodeContext          cbor_encode;
    enum t_cose_err_t           return_value;
    struct q_useful_buf_c       wrapped_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB( signed_cose_buffer, 200);
    struct t_cose_signing_key   degenerate_key = {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}};


    /* --- Start making COSE Sign1 object  --- */

    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    hash_test_mode = 1;

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

    hash_test_mode = 0;

    if(return_value != T_COSE_ERR_UNSUPPORTED_HASH) {
        return 2000 + return_value;
    }




    /* The CBOR encoder instance that the COSE_Sign1 is output into */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    hash_test_mode = 2;

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

    hash_test_mode = 0;

    if(return_value != T_COSE_ERR_HASH_GENERAL_FAIL) {
        return 2000 + return_value;
    }

    return 0;
}
