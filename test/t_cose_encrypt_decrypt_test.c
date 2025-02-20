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
#include "t_cose/t_cose_recipient_dec_keywrap.h"
#include "t_cose/t_cose_recipient_enc_keywrap.h"
#include "t_cose_util.h"
#include "data/test_messages.h"



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
check_headers(const struct t_cose_parameter *headers, bool is_non_aead)
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
                if((headers->in_protected != !is_non_aead)  ||
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


int32_t encrypt0_enc_dec(int32_t cose_algorithm_id, bool enable_non_aead_encryption, bool enable_non_aead_decryption)
{
    struct t_cose_encrypt_enc      enc_context;
    uint32_t                       option_flags;
    bool                           is_non_aead = false;
    enum t_cose_err_t              t_cose_err;
    int32_t                        return_value;
    struct t_cose_key              cek;
    struct q_useful_buf_c          cek_bytes;
    struct q_useful_buf_c          encrypted_cose_message;
    struct q_useful_buf_c          decrypted_payload;
    struct q_useful_buf_c          encrypted_detached;
    struct q_useful_buf_c          ext_sup_data;
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
        case T_COSE_ALGORITHM_A128CTR:
        case T_COSE_ALGORITHM_A128CBC:
            is_non_aead = true;
        case T_COSE_ALGORITHM_A128GCM:
            cek_bytes = Q_USEFUL_BUF_FROM_SZ_LITERAL("128-bit key xxxx");
            break;
        case T_COSE_ALGORITHM_A192CTR:
        case T_COSE_ALGORITHM_A192CBC:
            is_non_aead = true;
        case T_COSE_ALGORITHM_A192GCM:
            cek_bytes = Q_USEFUL_BUF_FROM_SZ_LITERAL("192-bit key xxxxyyyyyyyy");
            break;
        case T_COSE_ALGORITHM_A256CTR:
        case T_COSE_ALGORITHM_A256CBC:
            is_non_aead = true;
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

    option_flags = T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0;
    if(enable_non_aead_encryption) {
        option_flags |= T_COSE_OPT_ENABLE_NON_AEAD;
    }
    t_cose_encrypt_enc_init(&enc_context,
                            option_flags,
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

    ext_sup_data = t_cose_alg_is_non_aead(cose_algorithm_id) ? NULL_Q_USEFUL_BUF_C :
                                                               Q_USEFUL_BUF_FROM_SZ_LITERAL(AAD);

    t_cose_err = t_cose_encrypt_enc(&enc_context,
                                     Q_USEFUL_BUF_FROM_SZ_LITERAL(PAYLOAD),
                                     ext_sup_data,
                                     cose_message_buf,
                                    &encrypted_cose_message);

    if(t_cose_err == T_COSE_ERR_NON_AEAD_DISABLED && is_non_aead && !enable_non_aead_encryption) {
        /* t_cose could prevent unintended use of non AEAD ciphers */
        return_value = 0;
        goto Done;
    }
    else if(t_cose_err) {
        return_value = 2000 + (int32_t)t_cose_err;
        goto Done;
    }

    option_flags = T_COSE_OPT_MESSAGE_TYPE_UNSPECIFIED;
    if(enable_non_aead_decryption) {
        option_flags |= T_COSE_OPT_ENABLE_NON_AEAD;
    }
    t_cose_encrypt_dec_init(&dec_ctx, option_flags);

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

    t_cose_err = t_cose_encrypt_dec_msg(&dec_ctx,
                                         encrypted_cose_message,
                                         ext_sup_data,
                                         decrypted_payload_buf,
                                        &decrypted_payload,
                                        &decoded_parameters,
                                         NULL);
    if(t_cose_err == T_COSE_ERR_NON_AEAD_DISABLED && is_non_aead && !enable_non_aead_decryption) {
        /* t_cose could prevent unintended use of non AEAD ciphers */
        return_value = 0;
        goto Done;
    }
    else if(t_cose_err) {
        return_value = 3000 + (int32_t)t_cose_err;
        goto Done;
    }

    return_value = check_headers(decoded_parameters,
                                 t_cose_alg_is_non_aead(cose_algorithm_id));
    if(return_value) {
        goto Done;
    }

    if(q_useful_buf_compare(decrypted_payload, Q_USEFUL_BUF_FROM_SZ_LITERAL(PAYLOAD))) {
        return_value = -5;
        goto Done;
    }

    /* ---- test detached ----- */
    t_cose_encrypt_enc_init(&enc_context,
                            option_flags,
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

    t_cose_encrypt_dec_init(&dec_ctx, option_flags);
    t_cose_encrypt_dec_set_cek(&dec_ctx, cek);
    t_cose_err = t_cose_encrypt_dec_detached_msg(&dec_ctx,
                                                  encrypted_cose_message,
                                                  NULL_Q_USEFUL_BUF_C,
                                                  encrypted_detached,
                                                  decrypted_payload_buf,
                                                 &decrypted_payload,
                                                  NULL,
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
    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A128GCM, false, false);
    if(rv) {
        return 10000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A192GCM, false, false);
    if(rv) {
        return 20000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A256GCM, false, false);
    if(rv) {
        return 30000 + rv;
    }

    /* Enable non-AEAD ciphers on both Sender and Recipient side.
     * Success on both side are expected.
     */
    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A128CTR, true, true);
    if(rv) {
        return 40000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A192CTR, true, true);
    if(rv) {
        return 50000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A256CTR, true, true);
    if(rv) {
        return 60000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A128CBC, true, true);
    if(rv) {
        return 70000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A192CBC, true, true);
    if(rv) {
        return 80000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A256CBC, true, true);
    if(rv) {
        return 90000 + rv;
    }

    /* Disable non-AEAD ciphers on both Sender and Recipient side.
     * Failure and early return on Sender side is expected.
     */
    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A128CTR, false, false);
    if(rv) {
        return 100000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A192CTR, false, false);
    if(rv) {
        return 110000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A256CTR, false, false);
    if(rv) {
        return 120000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A128CBC, false, false);
    if(rv) {
        return 130000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A192CBC, false, false);
    if(rv) {
        return 140000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A256CBC, false, false);
    if(rv) {
        return 150000 + rv;
    }

    /* Disable non-AEAD ciphers on only Recipient side.
     * Failure and early return on Recipient side is expected.
     */
    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A128CTR, true, false);
    if(rv) {
        return 160000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A192CTR, true, false);
    if(rv) {
        return 170000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A256CTR, true, false);
    if(rv) {
        return 180000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A128CBC, true, false);
    if(rv) {
        return 190000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A192CBC, true, false);
    if(rv) {
        return 200000 + rv;
    }

    rv = encrypt0_enc_dec(T_COSE_ALGORITHM_A256CBC, true, false);
    if(rv) {
        return 210000 + rv;
    }

    return 0;

}


#ifndef T_COSE_DISABLE_KEYWRAP

int32_t decrypt_key_wrap(struct q_useful_buf_c cose_encrypt_buffer, bool enable_non_aead)
{
    enum t_cose_err_t                   result;
    uint32_t                            option_flags;
    int32_t                             return_value = 0;
    struct t_cose_recipient_dec_keywrap kw_unwrap_recipient;
    struct t_cose_encrypt_dec_ctx       decrypt_context;
    struct t_cose_key                   kek;
    struct q_useful_buf_c               kek_bytes;
    Q_USEFUL_BUF_MAKE_STACK_UB(         decrypted_buffer, 1024);
    struct q_useful_buf_c               decrypted_payload;
    struct t_cose_parameter            *params;

    kek_bytes = Q_USEFUL_BUF_FROM_SZ_LITERAL("128-bit key xxxx");
    result = t_cose_key_init_symmetric(T_COSE_ALGORITHM_A128KW,
                                       kek_bytes,
                                       &kek);
    if(result != T_COSE_SUCCESS) {
        return_value = 1000 + (int32_t)result;
        goto Done2;
    }

    option_flags = T_COSE_OPT_MESSAGE_TYPE_UNSPECIFIED;
    if(enable_non_aead) {
        option_flags |= T_COSE_OPT_ENABLE_NON_AEAD;
    }
    t_cose_encrypt_dec_init(&decrypt_context, option_flags);
    t_cose_recipient_dec_keywrap_init(&kw_unwrap_recipient);
    t_cose_recipient_dec_keywrap_set_kek(&kw_unwrap_recipient, kek, NULL_Q_USEFUL_BUF_C);
    t_cose_encrypt_dec_add_recipient(&decrypt_context, (struct t_cose_recipient_dec *)&kw_unwrap_recipient);

    result = t_cose_encrypt_dec_msg(&decrypt_context,
                                     cose_encrypt_buffer,
                                     NULL_Q_USEFUL_BUF_C,
                                     decrypted_buffer,
                                    &decrypted_payload,
                                    &params,
                                     NULL);

    if(result != T_COSE_SUCCESS) {
        return_value = 2000 + (int32_t)result;
        goto Done1;
    }

    if(q_useful_buf_compare(decrypted_payload, Q_USEFUL_BUF_FROM_SZ_LITERAL(PAYLOAD))) {
        return_value = 3000;
        goto Done1;
    }

Done1:
    t_cose_key_free_symmetric(kek);
Done2:
    return return_value;
}

int32_t decrypt_known_good_aeskw_non_aead_test(void)
{
    int32_t return_value;

    if(!t_cose_is_algorithm_supported(T_COSE_ALGORITHM_A128KW)) {
        /* This is necessary because MbedTLS 2.28 doesn't have
         * nist KW enabled by default. The PSA crypto layer deals with
         * this dynamically. The below tests will correctly link
         * on 2.28, but will fail to run so this exception is needed.
         */
        return INT32_MIN; /* Means no testing was actually done */
    }

    return_value = decrypt_key_wrap(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_encrypt_a128ctr_a128kw), true);
    if(return_value != 0) {
        return return_value + 10000;
    }
    return_value = decrypt_key_wrap(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_encrypt_a128cbc_a128kw), true);
    if(return_value != 0) {
        return return_value + 20000;
    }
    return 0;
}

#endif /* !T_COSE_DISABLE_KEYWRAP */



#include "init_keys.h"

#ifndef T_COSE_USE_B_CON_SHA256 /* test crypto doesn't support ECDH */



static int32_t
esdh_enc_dec(int32_t curve, int32_t payload_cose_algorithm_id)
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

    if(!t_cose_is_algorithm_supported(curve)) {
        /* Mbed TLS 2.28 doesn't support key wrap. */
        /* TODO: check for other required algorithms here */
        return INT32_MIN;
    }

   /* Create a key pair.  This is a fixed test key pair. The creation
     * of this key pair is crypto-library dependent because t_cose_key
     * is crypto-library dependent. See t_cose_key.h and the examples
     * to understand key-pair creation better. */
    result = init_fixed_test_ec_encryption_key(curve,
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
                             T_COSE_OPT_MESSAGE_TYPE_ENCRYPT | T_COSE_OPT_ENABLE_NON_AEAD,
                             payload_cose_algorithm_id);

    /* Create the recipient object telling it the algorithm and the public key
     * for the COSE_Recipient it's going to make.
     */
    t_cose_recipient_enc_esdh_init(&recipient,
                                    T_COSE_ALGORITHM_ECDH_ES_A128KW, /* content key distribution id */
                                    curve);    /* curve id */

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


    t_cose_encrypt_dec_init(&dec_ctx, T_COSE_OPT_ENABLE_NON_AEAD);

    t_cose_recipient_dec_esdh_init(&dec_recipient);

    t_cose_recipient_dec_esdh_set_key(&dec_recipient, privatekey, NULL_Q_USEFUL_BUF_C);

    t_cose_encrypt_dec_add_recipient(&dec_ctx,
                                     (struct t_cose_recipient_dec *)&dec_recipient);

    result = t_cose_encrypt_dec_msg(&dec_ctx,
                                     cose_encrypted_message,
                                     NULL_Q_USEFUL_BUF_C, /* in/unused: AAD */
                                     decrypted_buffer,
                                    &decrypted_payload,
                                    &params,
                                     NULL);
    if(result != T_COSE_SUCCESS) {
        goto Done;
    }

Done:
    free_fixed_test_ec_encryption_key(publickey);
    free_fixed_test_ec_encryption_key(privatekey);

    return (int32_t)result;
}


int32_t
esdh_enc_dec_test(void)
{
    int32_t result;

    if(!t_cose_is_algorithm_supported(T_COSE_ALGORITHM_A128KW)) {
        /* Mbed TLS 2.28 doesn't support key wrap. */
        return INT32_MIN;
    }

    result = esdh_enc_dec(T_COSE_ELLIPTIC_CURVE_P_256, T_COSE_ALGORITHM_A128GCM);
    if(result) {
        return result;
    }
    result = esdh_enc_dec(T_COSE_ELLIPTIC_CURVE_P_256, T_COSE_ALGORITHM_A128CTR);
    if(result) {
        return result;
    }
    result = esdh_enc_dec(T_COSE_ELLIPTIC_CURVE_P_256, T_COSE_ALGORITHM_A128CBC);
    if(result) {
        return result;
    }
    result = esdh_enc_dec(T_COSE_ELLIPTIC_CURVE_P_521, T_COSE_ALGORITHM_A256GCM);
    if(result) {
        return result;
    }
    result = esdh_enc_dec(T_COSE_ELLIPTIC_CURVE_P_521, T_COSE_ALGORITHM_A256CTR);
    if(result) {
        return result;
    }
    result = esdh_enc_dec(T_COSE_ELLIPTIC_CURVE_P_521, T_COSE_ALGORITHM_A256CBC);
    if(result) {
        return result;
    }

    return 0;
}


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

    result = t_cose_encrypt_dec_msg(&dec_ctx,
                                     UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_encrypt_p256_wrap_128), /* in: message to decrypt */
                                     NULL_Q_USEFUL_BUF_C, /* in/unused: AAD */
                                     decrypted_buffer,
                                    &decrypted_payload,
                                    &params,
                                     NULL);

    if(result != T_COSE_SUCCESS) {
        return (int32_t)result + 2000;
    }


    free_fixed_test_ec_encryption_key(pubkey);
    free_fixed_test_ec_encryption_key(privatekey);

    return 0;
}




struct decrypt_test {
    const char           *sz_description;
    struct q_useful_buf_c message;
    enum t_cose_err_t     expected_return_value;
    int32_t              cose_ec_curve_id; /* For key */
    struct q_useful_buf_c expected_payload;
};


int32_t run_decrypt_test(const struct decrypt_test *test)
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

    result = init_fixed_test_ec_encryption_key(test->cose_ec_curve_id,
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

    result = t_cose_encrypt_dec_msg(&dec_ctx,
                                     test->message, /* in: message to decrypt */
                                     NULL_Q_USEFUL_BUF_C, /* in/unused: AAD */
                                     decrypted_buffer,
                                    &decrypted_payload,
                                    &params,
                                     NULL);

    free_fixed_test_ec_encryption_key(pubkey);
    free_fixed_test_ec_encryption_key(privatekey);

    if(result != test->expected_return_value) {
        return (int32_t)result + 2000;
    }

    return 0;

}


/*

 DONE unknown_symmetric_alg.diag: Unknown symmetric cipher alg
 DONE unknown_rcpt_alg.diag  Unknown recipient alg
 DONE cose_encrypt_crit.diag  Unknown critical header
 DONE wrong_tag.diag  Wrong CBOR tag number
 Header that is not valid CBOR
 DONE cose_encrypt_wrong_array.diag  Top-level CBOR wrong -- a map, not an array
 DONE tstr_ciphertext.diag:  Ciphertext is not the right type -- a text string
 DONE cose_encrypt_wrong_rcpt_array  Recipients area is a map, not an array
 HALF-DONE cose_encrypt_wrong_extra  Extra stuff at end of array of 4
 DONE aead_in_error.diag: AEAD integrity check fails
 DONE cose_encrypt_bad_iv.diag  IV header header is wrong type -- text string
 DONE cose_encrypt_bad_alg.diag Symmetric Algorithm ID is the wrong type -- a byte string
 DONE cose_encrypt_junk_recipient.diag:  Recipient is the wrong type -- a map, not an array
 The encrypted CEK is the wrong type -- text string, not byte string
 Extra stuff at end of recipient array
 Recipient header is not decodable CBOR
 Ephemeral key is an array, not a map
 Ephemeral key type is unknown
 Ephemeral curve is unknown
 Ephemeral key type is a byte string
 Ephemeral x coordinate is an integer, not a byte string
 Ephemeral y coordinate is an integer not a byte string
 */


/* Decided to use a function to initialize rather than attempt
 * static initialization. It's only a test.
 */
static int32_t
init_decrypt_test_list(struct decrypt_test tests[], int tests_count)
{
    int test_num;

#define NEXT_TEST if(++test_num >= tests_count) return -1

    test_num = 0;

    tests[test_num].sz_description   = "body symmetric alg id is not one that is a symmertic alg";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(unknown_symmetric_alg);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_UNSUPPORTED_ENCRYPTION_ALG;
    NEXT_TEST;

    tests[test_num].sz_description   = "cipher text is a tstr, not an bstr";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(tstr_ciphertext);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_ENCRYPT_FORMAT;
    NEXT_TEST;

    tests[test_num].sz_description   = "the aead ciphertext is modified so aead validation fails";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(aead_in_error);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_DATA_AUTH_FAILED;
    NEXT_TEST;

    tests[test_num].sz_description   = "the body unprot header params is an array, not a map";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(unprot_headers_wrong_type);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_PARAMETER_CBOR;
    NEXT_TEST;

    tests[test_num].sz_description   = "the array of recipients is a map, not an array";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_recipients_map_instead_of_array);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_ENCRYPT_FORMAT;
    NEXT_TEST;

    tests[test_num].sz_description   = "a recipient is a text string, not an array";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_encrypt_junk_recipient);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_RECIPIENT_FORMAT;
    NEXT_TEST;

    tests[test_num].sz_description   = "wrong tag number";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(wrong_tag);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_CANT_DETERMINE_MESSAGE_TYPE;
    NEXT_TEST;

    tests[test_num].sz_description   = "no tag number";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(no_tag);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_CANT_DETERMINE_MESSAGE_TYPE;
    NEXT_TEST;

    tests[test_num].sz_description   = "unknown recipient alg";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(unknown_rcpt_alg);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_DECLINE;
    NEXT_TEST;

/*
    tests[test_num].sz_description   = "extra stuff in COSE_Encrypt array of 4";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_encrypt_wrong_extra);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_CANT_DETERMINE_MESSAGE_TYPE;
    NEXT_TEST;
*/

    tests[test_num].sz_description   = "array of 4 is map of 2";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_encrypt_wrong_array);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_ENCRYPT_FORMAT;
    NEXT_TEST;

    tests[test_num].sz_description   = "one recipient array is a map";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_encrypt_wrong_rcpt_array);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_RECIPIENT_FORMAT;
    NEXT_TEST;

    tests[test_num].sz_description   = "unknown crit header in cose_encrypt";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_encrypt_crit);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER;
    NEXT_TEST;

    tests[test_num].sz_description   = "Protected headers are a text string";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_encrypt_bad_hdrs);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_PARAMETER_CBOR;
    NEXT_TEST;

    tests[test_num].sz_description   = "IV is a boolean not bstr";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_encrypt_bad_iv);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_BAD_IV;
    NEXT_TEST;

    tests[test_num].sz_description   = "algorthm ID is wrong type";
    tests[test_num].message          = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(cose_encrypt_bad_alg);
    tests[test_num].cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
    tests[test_num].expected_return_value = T_COSE_ERR_NO_ALG_ID;
    NEXT_TEST;

    tests[test_num].sz_description = NULL;

    return 0;
}


int32_t decrypt_known_bad(void)
{
    int32_t              result;
    struct decrypt_test  test_list[20];
    int32_t              i;

    result = init_decrypt_test_list(test_list, sizeof(test_list)/sizeof(struct decrypt_test));
    if(result) {
        return result;
    }

    for(i = 0; test_list[i].sz_description != NULL; i++) {
        const struct decrypt_test *t = &test_list[i];
        const char *test_to_break_on = "wrong tag";
        if(!strncmp(t->sz_description, test_to_break_on, strlen(test_to_break_on))){
            /* For setting break point for a particular test */
            result = 99;
        }

        result = run_decrypt_test(t);
        if(result) {
            return i * 10000 + (int32_t)result;
        }
    }

    return 0;
}


/* Input parameters for kdf_instance_test() */
struct kdf_context_test_input {
    struct q_useful_buf_c  party_u_ident;
    struct q_useful_buf_c  party_v_ident;
    bool                   do_not_send;
    struct q_useful_buf_c  supp_pub_other;
    struct q_useful_buf_c  supp_priv_info;
    size_t                 kdf_context_size;
    bool                   use_salt;
    struct q_useful_buf_c  salt_bytes;
};

static enum t_cose_err_t
kdf_instance_test(int32_t                             ecdh_alg,
                  const struct kdf_context_test_input *enc_items,
                  const struct kdf_context_test_input *dec_items)
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
    Q_USEFUL_BUF_MAKE_STACK_UB  (    kdf_ctx_buf, 400);
    struct t_cose_parameter          _params[10];
    struct t_cose_parameter_storage  param_storage;


    result = init_fixed_test_ec_encryption_key(ecdh_alg,
                                              &publickey, /* out: public key to be used for encryption */
                                              &privatekey); /* out: corresponding private key for decryption */
    if(result != T_COSE_SUCCESS) {
        result = T_COSE_ERR_FAIL;
        goto Done;
    }

    t_cose_encrypt_enc_init(&enc_ctx,
                             T_COSE_OPT_MESSAGE_TYPE_ENCRYPT,
                             T_COSE_ALGORITHM_A128GCM);

    t_cose_recipient_enc_esdh_init(&recipient,
                                    T_COSE_ALGORITHM_ECDH_ES_A128KW, /* content key distribution id */
                                    T_COSE_ELLIPTIC_CURVE_P_256);    /* curve id */

    t_cose_recipient_enc_esdh_set_key(&recipient,
                                       publickey,
                                       Q_USEFUL_BUF_FROM_SZ_LITERAL(TEST_KID));

    t_cose_recipient_enc_esdh_party_info(&recipient,
                                         enc_items->party_u_ident,
                                         enc_items->party_v_ident,
                                         enc_items->do_not_send);

    t_cose_recipient_enc_esdh_supp_info(&recipient,
                                        enc_items->supp_pub_other,
                                        enc_items->supp_priv_info);

    kdf_ctx_buf.len = enc_items->kdf_context_size;
    t_cose_recipient_enc_esdh_kdf_buf(&recipient, kdf_ctx_buf);

    t_cose_recipient_enc_esdh_salt(&recipient,
                                   enc_items->use_salt,
                                   enc_items->salt_bytes);

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
        result = T_COSE_ERR_FAIL;
        goto Done;
    }


    t_cose_encrypt_dec_init(&dec_ctx, 0);

    T_COSE_PARAM_STORAGE_INIT(param_storage, _params);
    t_cose_encrypt_add_param_storage(&dec_ctx, &param_storage);

    t_cose_recipient_dec_esdh_init(&dec_recipient);
    t_cose_recipient_dec_esdh_set_key(&dec_recipient, privatekey, NULL_Q_USEFUL_BUF_C);
    t_cose_encrypt_dec_add_recipient(&dec_ctx,
                                     (struct t_cose_recipient_dec *)&dec_recipient);
    t_cose_recipient_dec_esdh_party_info(&dec_recipient,
                                         dec_items->party_u_ident,
                                         dec_items->party_v_ident);
    t_cose_recipient_dec_esdh_supp_info(&dec_recipient,
                                        dec_items->supp_pub_other,
                                        dec_items->supp_priv_info);
    /* OK to re use the buffer here */
    kdf_ctx_buf.len = enc_items->kdf_context_size;
    t_cose_recipient_dec_esdh_kdf_buf(&dec_recipient, kdf_ctx_buf);

    result = t_cose_encrypt_dec_msg(&dec_ctx,
                                     cose_encrypted_message,
                                     NULL_Q_USEFUL_BUF_C, /* in/unused: AAD */
                                     decrypted_buffer,
                                    &decrypted_payload,
                                    &params,
                                     NULL);
Done:
    free_fixed_test_ec_encryption_key(publickey);
    free_fixed_test_ec_encryption_key(privatekey);

    return result;
}




int32_t kdf_context_test(void)
{
    struct kdf_context_test_input enc_in;
    struct kdf_context_test_input dec_in;
    enum t_cose_err_t             test_result;
    int32_t                       alg;

    alg = T_COSE_ELLIPTIC_CURVE_P_256; // TODO: run this test for other algs
    if(!t_cose_is_algorithm_supported(T_COSE_ALGORITHM_A128KW) ||
       !t_cose_is_algorithm_supported(T_COSE_ALGORITHM_A128GCM)) {
        /* Mbed TLS 2.28 doesn't support key wrap. */
        /* TODO: check for other required algorithms here */
        // TODO: check for ECDH or ECDH suite
        return INT32_MIN;
    }

    enc_in.party_u_ident    = Q_USEFUL_BUF_FROM_SZ_LITERAL("Party U Sample");
    enc_in.party_v_ident    = Q_USEFUL_BUF_FROM_SZ_LITERAL("Party V Sample");
    enc_in.do_not_send      = false;
    enc_in.supp_pub_other   = Q_USEFUL_BUF_FROM_SZ_LITERAL("Supplemental Public Info Sample");
    enc_in.supp_priv_info   = Q_USEFUL_BUF_FROM_SZ_LITERAL("Supplemental Private Info Sample");
    enc_in.kdf_context_size = 400;
    enc_in.use_salt         = false;
    enc_in.salt_bytes       = NULL_Q_USEFUL_BUF_C;

    dec_in.party_u_ident    = Q_USEFUL_BUF_FROM_SZ_LITERAL("Party U Sample");
    dec_in.party_v_ident    = Q_USEFUL_BUF_FROM_SZ_LITERAL("Party V Sample");
    dec_in.supp_pub_other   = Q_USEFUL_BUF_FROM_SZ_LITERAL("Supplemental Public Info Sample");
    dec_in.supp_priv_info   = Q_USEFUL_BUF_FROM_SZ_LITERAL("Supplemental Private Info Sample");
    dec_in.kdf_context_size = 400;

    /* Set all KDF context items and see success */
    test_result = kdf_instance_test(alg, &enc_in, &dec_in);
    if(test_result != T_COSE_SUCCESS) {
        return 1000 + (int32_t)test_result;
    }

    dec_in.party_u_ident    = Q_USEFUL_BUF_FROM_SZ_LITERAL("FAIL Party U Sample");
    /* Set all KDF context items with PartyU wrong and see failure */
    test_result = kdf_instance_test(alg, &enc_in, &dec_in);
    if(test_result != T_COSE_ERR_DATA_AUTH_FAILED) {
        return 2000 + (int32_t)test_result;
    }

    dec_in.party_u_ident    = Q_USEFUL_BUF_FROM_SZ_LITERAL("Party U Sample");
    dec_in.party_v_ident    = Q_USEFUL_BUF_FROM_SZ_LITERAL("FAIL Party V Sample");
    /* Set all KDF context items with PartyV wrong and see failure */
    test_result = kdf_instance_test(alg, &enc_in, &dec_in);
    if(test_result != T_COSE_ERR_DATA_AUTH_FAILED) {
        return 3000 + (int32_t)test_result;
    }

    dec_in.party_v_ident    = Q_USEFUL_BUF_FROM_SZ_LITERAL("Party V Sample");
    dec_in.supp_pub_other   = Q_USEFUL_BUF_FROM_SZ_LITERAL("FAIL Supplemental Public Info Sample");
    /* Set all KDF context items with supp_pub_other wrong and see failure */
    test_result = kdf_instance_test(alg, &enc_in, &dec_in);
    if(test_result != T_COSE_ERR_DATA_AUTH_FAILED) {
        return 4000 + (int32_t)test_result;
    }

    dec_in.supp_pub_other   = Q_USEFUL_BUF_FROM_SZ_LITERAL("Supplemental Public Info Sample");
    dec_in.supp_priv_info   = Q_USEFUL_BUF_FROM_SZ_LITERAL("FAIL Supplemental Private Info Sample");
    /* Set all KDF context items with supp_priv_info wrong and see failure */
    test_result = kdf_instance_test(alg, &enc_in, &dec_in);
    if(test_result != T_COSE_ERR_DATA_AUTH_FAILED) {
        return 5000 + (int32_t)test_result;
    }

    dec_in.supp_priv_info   = Q_USEFUL_BUF_FROM_SZ_LITERAL("Supplemental Private Info Sample");
    /* Don't send the PartyU and PartyV so as to confirm reliance on setting them explicitly */
    enc_in.do_not_send      = true;
    test_result = kdf_instance_test(alg, &enc_in, &dec_in);
    if(test_result != T_COSE_SUCCESS) {
        return 6000 + (int32_t)test_result;
    }

    /* Successful test relying on PartyU and PartyV headers decode */
    dec_in.party_u_ident    = NULL_Q_USEFUL_BUF_C;
    dec_in.party_v_ident    = NULL_Q_USEFUL_BUF_C;
    enc_in.do_not_send      = false;
    test_result = kdf_instance_test(alg, &enc_in, &dec_in);
    if(test_result != T_COSE_SUCCESS) {
        return 7000 + (int32_t)test_result;
    }

    /* Neither sent or set so fail */
    enc_in.do_not_send      = true;
    test_result = kdf_instance_test(alg, &enc_in, &dec_in);
    if(test_result != T_COSE_ERR_DATA_AUTH_FAILED) {
        return 8000 + (int32_t)test_result;
    }

    enc_in.party_u_ident    = NULL_Q_USEFUL_BUF_C;
    enc_in.party_v_ident    = NULL_Q_USEFUL_BUF_C;
    enc_in.do_not_send      = false;
    enc_in.supp_pub_other   = Q_USEFUL_BUF_FROM_SZ_LITERAL("Supplemental Public Info Sample");
    enc_in.supp_priv_info   = NULL_Q_USEFUL_BUF_C;
    enc_in.kdf_context_size = 400;
    enc_in.use_salt         = false;
    enc_in.salt_bytes       = NULL_Q_USEFUL_BUF_C;

    dec_in.party_u_ident    = NULL_Q_USEFUL_BUF_C;
    dec_in.party_v_ident    = NULL_Q_USEFUL_BUF_C;
    dec_in.supp_pub_other   = Q_USEFUL_BUF_FROM_SZ_LITERAL("Supplemental Public Info Sample");
    dec_in.supp_priv_info   = NULL_Q_USEFUL_BUF_C;

    /* Neither sent or set so fail */
    test_result = kdf_instance_test(alg, &enc_in, &dec_in);
    if(test_result != T_COSE_SUCCESS) {
        return 9000 + (int32_t)test_result;
    }

    dec_in.supp_pub_other   = Q_USEFUL_BUF_FROM_SZ_LITERAL("FAIL Supplemental Public Info Sample");
    test_result = kdf_instance_test(alg, &enc_in, &dec_in);
    if(test_result != T_COSE_ERR_DATA_AUTH_FAILED) {
        return 10000 + (int32_t)test_result;
    }

    /* Test with a RNG salt */
    enc_in.party_u_ident    = NULL_Q_USEFUL_BUF_C;
    enc_in.party_v_ident    = NULL_Q_USEFUL_BUF_C;
    enc_in.do_not_send      = false;
    enc_in.supp_pub_other   = Q_USEFUL_BUF_FROM_SZ_LITERAL("Supplemental Public Info Sample");
    enc_in.supp_priv_info   = NULL_Q_USEFUL_BUF_C;
    enc_in.kdf_context_size = 400;
    enc_in.use_salt         = true;
    enc_in.salt_bytes       = NULL_Q_USEFUL_BUF_C;

    dec_in.party_u_ident    = NULL_Q_USEFUL_BUF_C;
    dec_in.party_v_ident    = NULL_Q_USEFUL_BUF_C;
    dec_in.supp_pub_other   = Q_USEFUL_BUF_FROM_SZ_LITERAL("Supplemental Public Info Sample");
    dec_in.supp_priv_info   = NULL_Q_USEFUL_BUF_C;

    enc_in.salt_bytes = Q_USEFUL_BUF_FROM_SZ_LITERAL("SALT");
    /* Send a specific salt and use it. */
    test_result = kdf_instance_test(alg, &enc_in, &dec_in);
    if(test_result != T_COSE_SUCCESS) {
        return 11000 + (int32_t)test_result;
    }

    enc_in.salt_bytes = NULL_Q_USEFUL_BUF_C;
    /* A random generated salt. */
    test_result = kdf_instance_test(alg, &enc_in, &dec_in);
    if(test_result != T_COSE_SUCCESS) {
        return 12000 + (int32_t)test_result;
    }

    return 0;
}
#endif /* !T_COSE_USE_B_CON_SHA256 */
