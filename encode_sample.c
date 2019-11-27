//
//  encode_sample.c
//  encode_sample
//
//  Created by Laurence Lundblade on 10/29/19.
//  Copyright © 2019 Laurence Lundblade. All rights reserved.
//

#include "t_cose_common.h"
#include "t_cose_sign1_sign.h"
#include "t_cose_make_test_pub_key.h"
#include "q_useful_buf.h"

int main(int argc, const char * argv[])
{
    (void)argc; // Avoid unused parameter error
    (void)argv;

    
    struct t_cose_sign1_sign_ctx   sign_ctx;
    enum t_cose_err_t              return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct t_cose_key              key_pair;
    QCBOREncodeContext             cbor_encode;
    QCBORError                     cbor_error;



    /* -- Get started with context initialization, selecting the alg -- */
    t_cose_sign1_sign_init(&sign_ctx, 0, -7);

    /* Make an ECDSA key pair that will be used for both signing and
     * verification.
     */
    return_value = make_ecdsa_key_pair(-7, &key_pair);
    if(return_value) {
        return 1000 + return_value;
    }

    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);


    t_cose_sign1_set_signing_key(&sign_ctx, key_pair,  NULL_Q_USEFUL_BUF_C);

    return_value = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + return_value;
    }

    QCBOREncode_AddSZString(&cbor_encode, "payload");


    return_value = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 3000 + return_value;
    }

    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 4000 + cbor_error;
    }

    free_ecdsa_key_pair(key_pair);

    return 0;
}
