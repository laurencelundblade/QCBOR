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

#ifndef T_COSE_DISABLE_HPKE
#include "t_cose/t_cose_recipient_enc_hpke.h"
#include "t_cose/t_cose_recipient_dec_hpke.h"
#include "init_keys.h"
#endif

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

    ps[0] = t_cose_make_ct_tstr_parameter(Q_USEFUL_BUF_FROM_SZ_LITERAL("text/plain"));
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

#ifndef T_COSE_DISABLE_HPKE
int32_t
encrypt_enc_dec(int32_t                cose_algorithm_id,
                uint32_t               kem_id,
                uint32_t               kdf_id,
                uint32_t               aead_id,
                struct q_useful_buf_c  kid,
                struct t_cose_key      skR,
                struct t_cose_key      pkR,
                struct q_useful_buf_c  payload,
                struct q_useful_buf_c  aad)
{
    struct t_cose_encrypt_enc        enc_ctx;
    enum t_cose_err_t                result;
    int32_t                          return_value=0;
    struct t_cose_recipient_enc_hpke recipient;
    struct q_useful_buf_c            cose_encrypted_message;
    struct q_useful_buf_c            decrypted_plain_text;

    Q_USEFUL_BUF_MAKE_STACK_UB  (    cose_encrypt_message_buffer, 200);
    Q_USEFUL_BUF_MAKE_STACK_UB  (    decrypted_plaintext_buffer, 100);
    struct t_cose_recipient_dec_hpke dec_recipient;
    struct t_cose_encrypt_dec_ctx    dec_ctx;

    /* Initialize the encryption context telling it we want
     * a COSE_Encrypt (not a COSE_Encrypt0) because we're doing HPKE with a
     * COSE_Recpipient. Also tell it the AEAD algorithm for the
     * body of the message.
     */
    t_cose_encrypt_enc_init(&enc_ctx,
                            T_COSE_OPT_MESSAGE_TYPE_ENCRYPT,
                            cose_algorithm_id);


    /* Create the recipient object telling it the algorithm and the public key
     * for the COSE_Recipient it's going to make. Then give that object
     * to the main encryption context. (Only one recipient is set here, but
     * there could be more)
     */
    t_cose_recipient_enc_hpke_init(&recipient,
                                    kem_id,   /* kem id */
                                    kdf_id,   /* kdf id */
                                    aead_id); /* aead id */

    t_cose_recipient_enc_hpke_set_key(&recipient,
                                       pkR,
                                       kid);
    t_cose_encrypt_add_recipient(&enc_ctx,
                                 (struct t_cose_recipient_enc *)&recipient);


    /* Now do the actual encryption */
    result = t_cose_encrypt_enc(&enc_ctx, /* in: encryption context */
                                 payload, /* in: payload to encrypt */
                                 aad,
                                 cose_encrypt_message_buffer, /* in: buffer for COSE_Encrypt */
                                 &cose_encrypted_message); /* out: COSE_Encrypt */

    if (result != T_COSE_SUCCESS) {
        return_value = 2000 + (int32_t)result;
        goto Done;
    }


    /* Set up the decryption context, telling it what type of
     * message to expect if there's no tag (that part isn't quite implemented right yet anyway).
     */
    t_cose_encrypt_dec_init(&dec_ctx, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT);


    /* Set up the recipient object with the key material. We happen to know
     * what the algorithm and key are in advance so we don't have to
     * decode the parameters first to figure that out (not that this part is
     * working yet). */
    t_cose_recipient_dec_hpke_init(&dec_recipient);
    t_cose_recipient_dec_hpke_set_skr(&dec_recipient,
                                      skR,
                                      kid);
    t_cose_encrypt_dec_add_recipient(&dec_ctx, (struct t_cose_recipient_dec *)&dec_recipient);

    result = t_cose_encrypt_dec(&dec_ctx,
                                cose_encrypted_message, /* in: the COSE_Encrypt message */
                                aad,
                                decrypted_plaintext_buffer,
                                &decrypted_plain_text,
                                NULL);

    if (result != T_COSE_SUCCESS) {
        return_value = 3000 + (int32_t)result;
        goto Done;
    }

    if(q_useful_buf_compare(decrypted_plain_text, payload)) {
        return_value = 1;
        goto Done;
    }
Done:
    return (int32_t)return_value;
}
#endif /* T_COSE_DISABLE_HPKE */


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

#ifndef T_COSE_DISABLE_HPKE
    /* Create a key pair.  This is a fixed test key pair. The creation
     * of this key pair is crypto-library dependent because t_cose_key
     * is crypto-library dependent. See t_cose_key.h and the examples
     * to understand key-pair creation better. */
    enum t_cose_err_t result;
    struct t_cose_key skR;
    struct t_cose_key pkR;

    /* Load public / private recipient key */
    result = init_fixed_test_encryption_key(T_COSE_ELLIPTIC_CURVE_P_256,
                                            &pkR, /* out: public key to be used for encryption */
                                            &skR); /* out: corresponding private key for decryption */
    if(result != T_COSE_SUCCESS) {
       return -7; /* return some error value */
    }

    rv = encrypt_enc_dec(T_COSE_ALGORITHM_A128GCM,
                         T_COSE_HPKE_KEM_ID_P256,
                         T_COSE_HPKE_KDF_ID_HKDF_SHA256,
                         T_COSE_HPKE_AEAD_ID_AES_GCM_128,
                         Q_USEFUL_BUF_FROM_SZ_LITERAL(TEST_KID),
                         skR,
                         pkR,
                         Q_USEFUL_BUF_FROM_SZ_LITERAL(PAYLOAD),
                         NULL_Q_USEFUL_BUF_C);
    if(rv) {
        return rv;
    }
    free_fixed_test_encryption_key(skR);
    free_fixed_test_encryption_key(pkR);
#endif /* T_COSE_DISABLE_HPKE */
    return 0;

}


