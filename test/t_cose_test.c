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
#include "t_cose_defines.h"
#include "q_useful_buf.h"


int_fast16_t minimal_test()
{
    struct t_cose_sign1_ctx sign_ctx;
    QCBOREncodeContext cbor_encode;
    enum t_cose_err_t  return_value;
    struct q_useful_buf_c wrapped_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB(foo, 500);
    struct q_useful_buf_c signed_cose;
    
    
    
    QCBOREncode_Init(&cbor_encode, foo);
    
    
    return_value = t_cose_sign1_init(&sign_ctx, true, COSE_ALGORITHM_ES256, 0, &cbor_encode);
    
    QCBOREncode_BstrWrap(&cbor_encode);
    
    QCBOREncode_AddSZString(&cbor_encode, "payload");
    
    QCBOREncode_CloseBstrWrap(&cbor_encode, &wrapped_payload);
    
    return_value = t_cose_sign1_finish(&sign_ctx, wrapped_payload);
    
    QCBOREncode_Finish(&cbor_encode, &signed_cose);

    struct q_useful_buf_c payload;

    t_cose_sign1_verify(T_COSE_OPT_ALLOW_SHORT_CIRCUIT, 0, signed_cose, &payload);
    
    

    return 0;
}


int_fast16_t early_error_test()
{
    struct t_cose_sign1_ctx sign_ctx;
    QCBOREncodeContext cbor_encode;
    enum t_cose_err_t  return_value;
    struct q_useful_buf_c wrapped_payload = NULL_Q_USEFUL_BUF_C;
    Q_USEFUL_BUF_MAKE_STACK_UB(foo, 500);


    QCBOREncode_Init(&cbor_encode, foo);

    return_value = t_cose_sign1_init(&sign_ctx, true, COSE_ALGORITHM_ES256, 0, &cbor_encode);

    QCBOREncode_BstrWrap(&cbor_encode);

    QCBOREncode_AddSZString(&cbor_encode, "payload");

    QCBOREncode_CloseMap(&cbor_encode);

    return_value = t_cose_sign1_finish(&sign_ctx, wrapped_payload);

    if(return_value != T_COSE_ERR_CBOR_FORMATTING) {
        return -33;
    }


    Q_USEFUL_BUF_MAKE_STACK_UB(foo2, 15);

    QCBOREncode_Init(&cbor_encode, foo2);

    return_value = t_cose_sign1_init(&sign_ctx, true, COSE_ALGORITHM_ES256, 0, &cbor_encode);

    QCBOREncode_BstrWrap(&cbor_encode);

    QCBOREncode_AddSZString(&cbor_encode, "payload");

    QCBOREncode_CloseMap(&cbor_encode);

    return_value = t_cose_sign1_finish(&sign_ctx, wrapped_payload);

    if(return_value != T_COSE_ERR_TOO_SMALL) {
        return -34;
    }




    return 0;
}
