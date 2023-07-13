/*
 * t_cose_encrypt_decrypt_test.c
 *
 * Copyright 2023, Laurence Lundblade
 * Created by Laurence Lundblade on 2/26/23.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */


#include "t_cose_encrypt_decrypt_test.h"
#include "t_cose/t_cose_encrypt_dec.h"
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_recipient_dec_esdh.h"



#define PAYLOAD  "This is the payload"
#define TEST_KID "fixed_test_key_id"

#define AAD "100 bytes of AAD for test" \
            "100 bytes of AAD for test" \
            "100 bytes of AAD for test" \
            "100 bytes of AAD for test"

#define AAD2 ""

static bool
locations_equal(struct t_cose_header_location l1,
                       struct t_cose_header_location l2)
{
    if(l1.index != l2.index) {
        return false;
    }

    if(l1.nesting != l2.nesting) {
        return false;
    }
    return true;
}



static int32_t
check_headers(const struct t_cose_parameter *headers)
{
    const struct t_cose_header_location body_location = {0,0};
    bool got_alg = false;
    bool got_ct = false;
    bool got_xxx = false;
    bool got_iv = false;



    /* Make sure that all the expected headers occur,
     * that they occur only once and that no unexpected
     * headers occur
     */
    while(headers != NULL) {
        switch(headers->label) {
            case T_COSE_HEADER_PARAM_ALG:
                if(headers->in_protected == false  ||
                   !locations_equal(headers->location, body_location) ||
                   headers->value_type != T_COSE_PARAMETER_TYPE_INT64 ||
                   got_alg == true) {
                    return -100;
                }
                got_alg = true;
                break;

            case T_COSE_HEADER_PARAM_CONTENT_TYPE:
                if(headers->in_protected == true  ||
                    !locations_equal(headers->location, body_location) ||
                    headers->value_type != T_COSE_PARAMETER_TYPE_TEXT_STRING||
                    got_ct == true) {
                     return -101;
                 }
                 got_ct = true;
                 break;

            case INT16_MAX:
                if(headers->in_protected == true  ||
                    !locations_equal(headers->location, body_location) ||
                    headers->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING||
                    got_xxx == true) {
                     return -102;
                 }
                 got_xxx = true;
                 break;

          case T_COSE_HEADER_PARAM_IV:
                if(headers->in_protected == true  ||
                    !locations_equal(headers->location, body_location) ||
                    headers->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING||
                    got_iv == true) {
                     return -103;
                 }
                 got_iv = true;
                 break;

            default:
                return -110;

        }

        headers = headers->next;
    }

    if(!got_alg || !got_ct || !got_xxx || !got_iv) {
        /* Didn't get all the headers expected */
        return -120;
    }

    return 0;

}

int32_t encrypt0_enc_dec(int32_t cose_algorithm_id)
{
    struct t_cose_encrypt_enc      enc_context;
    enum t_cose_err_t              t_cose_err;
    int32_t                        return_value;
    struct t_cose_key              cek;
    struct q_useful_buf_c          cek_bytes;
    struct q_useful_buf_c          encrypted_cose_message;
    struct q_useful_buf_c          decrypted_payload;
    struct q_useful_buf_c          encrypted_detached;
    Q_USEFUL_BUF_MAKE_STACK_UB(    cose_message_buf, 1024);
    Q_USEFUL_BUF_MAKE_STACK_UB(    detached_encrypted_buf, 1024);
    Q_USEFUL_BUF_MAKE_STACK_UB(    decrypted_payload_buf, 1024);
    Q_USEFUL_BUF_MAKE_STACK_UB(    enc_struct_buf, 1024);
    struct t_cose_encrypt_dec_ctx  dec_ctx;
    struct t_cose_parameter        ps[2];
    struct t_cose_parameter       *decoded_parameters;

    struct t_cose_parameter_storage p_storage;
    struct t_cose_parameter         p_storage_array[10];

    switch(cose_algorithm_id) {
        case T_COSE_ALGORITHM_A128GCM:
            cek_bytes = Q_USEFUL_BUF_FROM_SZ_LITERAL("128-bit key xxxx");
            break;
        case T_COSE_ALGORITHM_A192GCM:
            cek_bytes = Q_USEFUL_BUF_FROM_SZ_LITERAL("192-bit key xxxxyyyyyyyy");
            break;
        case T_COSE_ALGORITHM_A256GCM:
            cek_bytes = Q_USEFUL_BUF_FROM_SZ_LITERAL("256-bit key xxxxyyyyyyyyzzzzzzzz");
            break;
        case T_COSE_ALGORITHM_AES128CCM_16_128:
            cek_bytes = Q_USEFUL_BUF_FROM_SZ_LITERAL("128-bit key xxxx");
            break;
        case T_COSE_ALGORITHM_AES256CCM_16_128:
            cek_bytes = Q_USEFUL_BUF_FROM_SZ_LITERAL("256-bit key xxxxyyyyyyyyzzzzzzzz");
            break;
        default:
            return -1;
    }

    t_cose_err = t_cose_key_init_symmetric(cose_algorithm_id,
                                           cek_bytes,
                                          &cek);
    if(t_cose_err) {
        return_value = 1000 + (int32_t) t_cose_err;
        goto Done2;
    }

    t_cose_encrypt_enc_init(&enc_context,
                            T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0,
                            cose_algorithm_id);


    t_cose_encrypt_set_cek(&enc_context, cek);

    ps[0] = t_cose_param_make_ct_tstr(Q_USEFUL_BUF_FROM_SZ_LITERAL("text/plain"));
    ps[0].next = &ps[1];
    ps[1].value_type = T_COSE_PARAMETER_TYPE_BYTE_STRING;
    ps[1].value.string = Q_USEFUL_BUF_FROM_SZ_LITERAL("xxxxxxxxxx");
    ps[1].label = INT16_MAX; /* Just a sort of big number */
    ps[1].in_protected = false;
    ps[1].critical = false;
    ps[1].next = NULL;
    // TODO: header callback

    t_cose_encrypt_enc_body_header_params(&enc_context, &ps[0]);

    t_cose_encrypt_set_enc_struct_buffer(&enc_context, enc_struct_buf);

    t_cose_err = t_cose_encrypt_enc(&enc_context,
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL(PAYLOAD),
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL(AAD),
                                     cose_message_buf,
                                    &encrypted_cose_message);
    if(t_cose_err) {
        return_value = 2000 + (int32_t)t_cose_err;
        goto Done;
    }


    t_cose_encrypt_dec_init(&dec_ctx, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0);

    t_cose_encrypt_dec_set_cek(&dec_ctx, cek);

    /* Test being able to set a big buffer for the internal
     * making of the enc_structure.
     */
    t_cose_decrypt_set_enc_struct_buffer(&dec_ctx, enc_struct_buf);


    /* Test being able to expand the pool of param storage
     * even though there's not that many parameters here.
     */
    T_COSE_PARAM_STORAGE_INIT(p_storage, p_storage_array);
    t_cose_encrypt_add_param_storage(&dec_ctx, &p_storage);

    // TODO: header callbacks

    t_cose_err = t_cose_encrypt_dec(&dec_ctx,
                                     encrypted_cose_message,
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL(AAD),
                                     decrypted_payload_buf,
                                    &decrypted_payload,
                                    &decoded_parameters);
    if(t_cose_err) {
        return_value = 3000 + (int32_t)t_cose_err;
        goto Done;
    }

    return_value = check_headers(decoded_parameters);
    if(return_value) {
        goto Done;
    }

    if(q_useful_buf_compare(decrypted_payload, Q_USEFUL_BUF_FROM_SZ_LITERAL(PAYLOAD))) {
        return_value = -5;
        goto Done;
    }

    /* ---- test detached ----- */
    t_cose_encrypt_enc_init(&enc_context,
                            T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0,
                            cose_algorithm_id);
    t_cose_encrypt_set_cek(&enc_context, cek);
    t_cose_err = t_cose_encrypt_enc_detached(&enc_context,
                                             Q_USEFUL_BUF_FROM_SZ_LITERAL(PAYLOAD),
                                             NULL_Q_USEFUL_BUF_C,
                                             detached_encrypted_buf,
                                             cose_message_buf,
                                             &encrypted_detached,
                                            &encrypted_cose_message);
    if(t_cose_err) {
        return_value = 6000 + (int32_t)t_cose_err;
        goto Done;
    }

    t_cose_encrypt_dec_init(&dec_ctx, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0);
    t_cose_encrypt_dec_set_cek(&dec_ctx, cek);
    t_cose_err = t_cose_encrypt_dec_detached(&dec_ctx,
                                              encrypted_cose_message,
                                              NULL_Q_USEFUL_BUF_C,
                                              encrypted_detached,
                                              decrypted_payload_buf,
                                             &decrypted_payload,
                                             NULL);
    if(t_cose_err) {
        return_value = 7000 + (int32_t)t_cose_err;
        goto Done;
    }
    if(q_useful_buf_compare(decrypted_payload, Q_USEFUL_BUF_FROM_SZ_LITERAL(PAYLOAD))) {
        return_value = -8;
        goto Done;
    }


Done:
    t_cose_key_free_symmetric(cek);

Done2:
    return return_value;
}




int32_t base_encrypt_decrypt_test(void)
{
    int32_t rv;
    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A128GCM);
    if(rv) {
        return rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A192GCM);
    if(rv) {
        return rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A256GCM);
    if(rv) {
        return rv;
    }

//    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_AES256CCM_16_128);
//    if(rv) {
//        return rv;
//    }


    return 0;

}


/* This is just a patched together example for the
 * purpose of verifying decoding. It will not
 * successully decrypt. */
unsigned char esdh_encrypt_sample[] = {
  0xd8, 0x60, 0x84, 0x43, 0xa1, 0x01, 0x01, 0xa1,
  0x05, 0x4c, 0xc9, 0xcf, 0x4d, 0xf2, 0xfe, 0x6c,
  0x63, 0x2b, 0xf7, 0x88, 0x64, 0x13, 0x58, 0x24,
  0x7a, 0xdb, 0xe2, 0x70, 0x9c, 0xa8, 0x18, 0xfb,
  0x41, 0x5f, 0x1e, 0x5d, 0xf6, 0x6f, 0x4e, 0x1a,
  0x51, 0x05, 0x3b, 0xa6, 0xd6, 0x5a, 0x1a, 0x0c,
  0x52, 0xa3, 0x57, 0xda, 0x7a, 0x64, 0x4b, 0x80,
  0x70, 0xa1, 0x51, 0xb0, 0x81, 0x83, 0x44, 0xa1,
  0x01, 0x38, 0x1c, 0xa2, 0x20, 0xa4, 0x01, 0x02,
  0x20, 0x03, 0x21, 0x58, 0x42, 0x00, 0x43, 0xb1,
  0x26, 0x69, 0xac, 0xac, 0x3f, 0xd2, 0x78, 0x98,
  0xff, 0xba, 0x0b, 0xcd, 0x2e, 0x6c, 0x36, 0x6d,
  0x53, 0xbc, 0x4d, 0xb7, 0x1f, 0x90, 0x9a, 0x75,
  0x93, 0x04, 0xac, 0xfb, 0x5e, 0x18, 0xcd, 0xc7,
  0xba, 0x0b, 0x13, 0xff, 0x8c, 0x76, 0x36, 0x27,
  0x1a, 0x69, 0x24, 0xb1, 0xac, 0x63, 0xc0, 0x26,
  0x88, 0x07, 0x5b, 0x55, 0xef, 0x2d, 0x61, 0x35,
  0x74, 0xe7, 0xdc, 0x24, 0x2f, 0x79, 0xc3, 0x22,
  0xf5, 0x04, 0x58, 0x1e, 0x62, 0x69, 0x6c, 0x62,
  0x6f, 0x2e, 0x62, 0x61, 0x67, 0x67, 0x69, 0x6e,
  0x73, 0x40, 0x68, 0x6f, 0x62, 0x62, 0x69, 0x74,
  0x6f, 0x6e, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
  0x6c, 0x65, 0x58, 0x28, 0x33, 0x9b, 0xc4, 0xf7,
  0x99, 0x84, 0xcd, 0xc6, 0xb3, 0xe6, 0xce, 0x5f,
  0x31, 0x5a, 0x4c, 0x7d, 0x2b, 0x0a, 0xc4, 0x66,
  0xfc, 0xea, 0x69, 0xe8, 0xc0, 0x7d, 0xfb, 0xca,
  0x5b, 0xb1, 0xf6, 0x61, 0xbc, 0x5f, 0x8e, 0x0d,
  0xf9, 0xe3, 0xef, 0xf5
};



#include "init_keys.h"

#ifndef T_COSE_USE_B_CON_SHA256 /* test crypto doesn't support ECDH */

int32_t dec_fixed(void)
{
    struct t_cose_encrypt_dec_ctx dec_ctx;
    MakeUsefulBufOnStack(plain_text_buf, 300);
    struct q_useful_buf_c decrypted_payload;
    enum t_cose_err_t t_cose_err;
    struct t_cose_key private_key;
    struct t_cose_key public_key;
    struct t_cose_recipient_dec_esdh esdh;


    t_cose_encrypt_dec_init(&dec_ctx, CBOR_TAG_COSE_ENCRYPT);

    t_cose_recipient_dec_esdh_init(&esdh);
    init_fixed_test_ec_encryption_key(T_COSE_ELLIPTIC_CURVE_P_521,
                                      &private_key,
                                      &public_key);
    t_cose_recipient_dec_esdh_set_key(&esdh,
                                      private_key,
                                      NULL_Q_USEFUL_BUF_C);


    t_cose_encrypt_dec_add_recipient(&dec_ctx, (struct t_cose_recipient_dec *)&esdh);

    t_cose_err = t_cose_encrypt_dec(&dec_ctx,
                                    UsefulBuf_FROM_BYTE_ARRAY_LITERAL(esdh_encrypt_sample),
                                    NULL_Q_USEFUL_BUF_C,
                                    plain_text_buf,
                                    &decrypted_payload,
                                    NULL);

    (void)t_cose_err;

    return 0;
}
#endif /* !T_COSE_USE_B_CON_SHA256 */
