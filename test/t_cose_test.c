/*
 *  t_cose_test.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.mdE.
 */

#include "t_cose_test.h"
#include "t_cose_sign1_sign.h"
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
    
    
    
    
    
    return 0;
}
