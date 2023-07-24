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
#include "t_cose/t_cose_recipient_enc_esdh.h"



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

    return 0;

}




#include "init_keys.h"

#ifndef T_COSE_USE_B_CON_SHA256 /* test crypto doesn't support ECDH */



int32_t
esdh_enc_dec_test(void)
{
    enum t_cose_err_t                result;
    struct t_cose_key                privatekey;
    struct t_cose_key                publickey;
    struct t_cose_encrypt_enc        enc_ctx;
    struct t_cose_recipient_enc_esdh recipient;
    struct q_useful_buf_c            cose_encrypted_message;
    Q_USEFUL_BUF_MAKE_STACK_UB  (    cose_encrypt_message_buffer, 400);
    struct t_cose_encrypt_dec_ctx    dec_ctx;
    struct t_cose_recipient_dec_esdh dec_recipient;

    Q_USEFUL_BUF_MAKE_STACK_UB  (    decrypted_buffer, 400);
    struct q_useful_buf_c            decrypted_payload;
    struct t_cose_parameter         *params;

    if(!t_cose_is_algorithm_supported(T_COSE_ALGORITHM_A128KW)) {
        /* Mbed TLS 2.28 doesn't support key wrap. */
        /* TODO: check for other required algorithms here */
        return INT32_MIN;
    }

   /* Create a key pair.  This is a fixed test key pair. The creation
     * of this key pair is crypto-library dependent because t_cose_key
     * is crypto-library dependent. See t_cose_key.h and the examples
     * to understand key-pair creation better. */
    result = init_fixed_test_ec_encryption_key(T_COSE_ELLIPTIC_CURVE_P_256,
                                              &publickey, /* out: public key to be used for encryption */
                                              &privatekey); /* out: corresponding private key for decryption */
    if(result != T_COSE_SUCCESS) {
        goto Done;
    }

    /* Initialize the encryption context telling it we want
     * a COSE_Encrypt (not a COSE_Encrypt0) because we're doing ECDH with a
     * COSE_Recipient. Also tell it the AEAD algorithm for the
     * body of the message.
     */
    t_cose_encrypt_enc_init(&enc_ctx,
                             T_COSE_OPT_MESSAGE_TYPE_ENCRYPT,
                             T_COSE_ALGORITHM_A128GCM);

    /* Create the recipient object telling it the algorithm and the public key
     * for the COSE_Recipient it's going to make.
     */
    t_cose_recipient_enc_esdh_init(&recipient,
                                    T_COSE_ALGORITHM_ECDH_ES_A128KW, /* content key distribution id */
                                    T_COSE_ELLIPTIC_CURVE_P_256);    /* curve id */

    t_cose_recipient_enc_esdh_set_key(&recipient,
                                       publickey,
                                       Q_USEFUL_BUF_FROM_SZ_LITERAL(TEST_KID));

    /* Give the recipient object to the main encryption context.
     * (Only one recipient is set here, but there could be more).
     */
    t_cose_encrypt_add_recipient(&enc_ctx,
                                 (struct t_cose_recipient_enc *)&recipient);

    /* Now do the actual encryption */
    result = t_cose_encrypt_enc(&enc_ctx, /* in: encryption context */
                                 Q_USEFUL_BUF_FROM_SZ_LITERAL(PAYLOAD), /* in: payload to encrypt */
                                 NULL_Q_USEFUL_BUF_C, /* in/unused: AAD */
                                 cose_encrypt_message_buffer, /* in: buffer for COSE_Encrypt */
                                 &cose_encrypted_message); /* out: COSE_Encrypt */

    if (result != T_COSE_SUCCESS) {
        goto Done;
    }


    t_cose_encrypt_dec_init(&dec_ctx, 0);

    t_cose_recipient_dec_esdh_init(&dec_recipient);

    t_cose_recipient_dec_esdh_set_key(&dec_recipient, privatekey, NULL_Q_USEFUL_BUF_C);

    t_cose_encrypt_dec_add_recipient(&dec_ctx,
                                     (struct t_cose_recipient_dec *)&dec_recipient);

    result = t_cose_encrypt_dec(&dec_ctx,
                                cose_encrypted_message,
                                NULL_Q_USEFUL_BUF_C, /* in/unused: AAD */
                                decrypted_buffer,
                                &decrypted_payload,
                                &params);
    if(result != T_COSE_SUCCESS) {
        goto Done;
    }

Done:

    return (int32_t)result;
}


/* This comes from the COSE WG Examples repository */

static const uint8_t p256_wrap_128_02[] = {
    0xD8, 0x60, 0x84, 0x43, 0xA1, 0x01, 0x03, 0xA1,
    0x05, 0x4C, 0x02, 0xD1, 0xF7, 0xE6, 0xF2, 0x6C,
    0x43, 0xD4, 0x86, 0x8D, 0x87, 0xCE, 0x58, 0x24,
    0x25, 0x6B, 0x74, 0x8D, 0xEB, 0x64, 0x71, 0x31,
    0xC1, 0x2A, 0x10, 0xAC, 0x26, 0x1D, 0xA0, 0x62,
    0x8E, 0x42, 0x04, 0x92, 0xA3, 0x6F, 0x3D, 0xED,
    0x86, 0x42, 0xB4, 0xB6, 0xFA, 0x1E, 0xB1, 0x5D,
    0xCE, 0xC8, 0x0A, 0x0F, 0x81, 0x83, 0x44, 0xA1,
    0x01, 0x38, 0x1C, 0xA2, 0x20, 0xA4, 0x01, 0x02,
    0x20, 0x01, 0x21, 0x58, 0x20, 0xE1, 0x2C, 0x93,
    0x8B, 0x18, 0x22, 0x58, 0xC9, 0xD4, 0x47, 0xD4,
    0x18, 0x21, 0x71, 0x52, 0x61, 0xAE, 0x99, 0xAD,
    0x77, 0xD2, 0x41, 0x94, 0x3F, 0x4A, 0x12, 0xFF,
    0x20, 0xDD, 0x3C, 0xE4, 0x00, 0x22, 0x58, 0x20,
    0x48, 0xB0, 0x58, 0x89, 0x03, 0x36, 0x57, 0x33,
    0xB9, 0x8D, 0x38, 0x8C, 0x61, 0x36, 0xC0, 0x4B,
    0x7F, 0xFD, 0x1A, 0x77, 0x0C, 0xD2, 0x61, 0x11,
    0x89, 0xEE, 0x84, 0xE9, 0x94, 0x1A, 0x7E, 0x26,
    0x04, 0x58, 0x24, 0x6D, 0x65, 0x72, 0x69, 0x61,
    0x64, 0x6F, 0x63, 0x2E, 0x62, 0x72, 0x61, 0x6E,
    0x64, 0x79, 0x62, 0x75, 0x63, 0x6B, 0x40, 0x62,
    0x75, 0x63, 0x6B, 0x6C, 0x61, 0x6E, 0x64, 0x2E,
    0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x58,
    0x28, 0x50, 0x8F, 0xAD, 0x30, 0xA1, 0xA9, 0x5D,
    0x13, 0x80, 0xB5, 0x16, 0x7D, 0x03, 0x27, 0x99,
    0xC7, 0x24, 0x77, 0xAB, 0x60, 0x25, 0x8A, 0xBF,
    0xB7, 0x1C, 0x7A, 0xB6, 0x03, 0xA4, 0x89, 0x0E,
    0xF4, 0x4F, 0x13, 0x63, 0xED, 0x9F, 0x56, 0x9E,
    0x85};


int32_t decrypt_known_good(void)
{
    enum t_cose_err_t                result;
    struct t_cose_encrypt_dec_ctx    dec_ctx;
    struct t_cose_recipient_dec_esdh dec_recipient;
    Q_USEFUL_BUF_MAKE_STACK_UB  (    decrypted_buffer, 400);
    struct q_useful_buf_c            decrypted_payload;
    struct t_cose_parameter         *params;
    struct t_cose_key                privatekey;
    struct t_cose_key                pubkey;

    if(!t_cose_is_algorithm_supported(T_COSE_ALGORITHM_A128KW)) {
        /* Mbed TLS 2.28 doesn't support key wrap. */
        /* TODO: check for other required algorithms here */
        return INT32_MIN;
    }

    result = init_fixed_test_ec_encryption_key(T_COSE_ELLIPTIC_CURVE_P_256,
                                              &pubkey,      /* out: public key to be used for encryption */
                                              &privatekey); /* out: corresponding private key for decryption */
    if(result != T_COSE_SUCCESS) {
        return (int32_t)result + 1000;
    }


    t_cose_encrypt_dec_init(&dec_ctx, 0);

    t_cose_recipient_dec_esdh_init(&dec_recipient);

    t_cose_recipient_dec_esdh_set_key(&dec_recipient,
                                      privatekey, /* in: private key handle */
                                      NULL_Q_USEFUL_BUF_C); /* in: kid */

    t_cose_encrypt_dec_add_recipient(&dec_ctx,
                                     (struct t_cose_recipient_dec *)&dec_recipient);

    result = t_cose_encrypt_dec(&dec_ctx,
                                UsefulBuf_FROM_BYTE_ARRAY_LITERAL(p256_wrap_128_02), /* in: message to decrypt */
                                NULL_Q_USEFUL_BUF_C, /* in/unused: AAD */
                                decrypted_buffer,
                                &decrypted_payload,
                                &params);

    if(result != T_COSE_SUCCESS) {
        return (int32_t)result + 2000;
    }


    return 0;
}
#endif /* !T_COSE_USE_B_CON_SHA256 */
