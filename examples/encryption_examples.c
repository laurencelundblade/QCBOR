/*
 * encryption_examples.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright 2023, Laurence Lundblade
 *
 * Created by Laurence Lundblade on 2/6/23 from previous files.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "encryption_examples.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_encrypt_dec.h"
#include "t_cose/t_cose_key.h"

#include <stdio.h>
#include "print_buf.h"
#include "init_keys.h"

#define PAYLOAD  "This is the payload"
#define TEST_SENDER_IDENTITY "sender"
#define TEST_RECIPIENT_IDENTITY "recipient"


/* This file is crypto-library independent. It works for OpenSSL, Mbed
* TLS and others. The key initialization, which *is* crypto-library
* dependent, has been separated.
*
* Each example should pretty much stand on its own and be pretty
* clean and well-commented code. Its purpose is to be an example
* (not a test case). Someone should be able to easily copy the
* example as a starting point for their use case.
*/



int32_t
encrypt0_example(void)
{
    struct t_cose_encrypt_enc  enc_context;
    enum t_cose_err_t              err;
    struct t_cose_key              cek;
    struct q_useful_buf_c          encrypted_cose_message;
    struct q_useful_buf_c          decrypted_cose_message;
    struct q_useful_buf_c          encrypted_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB(    cose_message_buf, 1024);
    Q_USEFUL_BUF_MAKE_STACK_UB(    encrypted_payload_buf, 1024);
    Q_USEFUL_BUF_MAKE_STACK_UB(    decrypted_payload_buf, 1024);
    struct t_cose_encrypt_dec_ctx  dec_ctx;

    printf("\n---- START EXAMPLE encrypt0  ----\n");
    printf("Create COSE_Encrypt0 with detached payload using A128GCM\n");

    /* This is the simplest form of COSE encryption, a COSE_Encrypt0.
     * It has only headers and the ciphertext.
     *
     * Further in this example, the ciphertext is detached, so the
     * COSE_Encrypt0 only consists of the protected and unprotected
     * headers and a CBOR NULL where the ciphertext usually
     * occurs. The ciphertext is output separatly and conveyed
     * separately.
     *
     */
    t_cose_encrypt_enc_init(&enc_context,
                            T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0,
                            T_COSE_ALGORITHM_A128GCM);

    /* For COSE_Encrypt0, we simply make a t_cose_key for the
     * content encryption key, the CEK, and give it to t_cose.  It's
     * the only key there is and it is simply a key to be used with
     * AES, a string of bytes. (It is still t_cose_key, not a byte string
     * so it can be a PSA key handle so it can be used with with
     * an encryption implementation that doesn't allow the key to
     * leave a protected domain, an HSM for example).
     *
     * There is no COSE_Recipient so t_cose_encrypt_add_recipient() is
     * not called.
     *
     * No kid is provided in line with the examples of Encrypt0
     * in RFC 9052. RFC 9052 text describing Encrypt0 also implies that
     * no kid should be needed, but it doesn't seem to prohibit
     * the kid header and t_cose will allow it to be present.
     */
    t_cose_key_init_symmetric(T_COSE_ALGORITHM_A128GCM,
                              Q_USEFUL_BUF_FROM_SZ_LITERAL("aaaaaaaaaaaaaaaa"),
                             &cek);
    t_cose_encrypt_set_cek(&enc_context, cek);

    err = t_cose_encrypt_enc_detached(&enc_context,
                              Q_USEFUL_BUF_FROM_SZ_LITERAL("This is a real plaintext."),
                                      NULL_Q_USEFUL_BUF_C,
                              encrypted_payload_buf,
                             cose_message_buf,
                             &encrypted_payload,
                             &encrypted_cose_message);
    if(err != T_COSE_SUCCESS) {
        goto Done;
    }

    print_useful_buf("COSE_Encrypt0: ", encrypted_cose_message);
    print_useful_buf("Detached ciphertext: ", encrypted_payload);
    printf("\n");

    printf("Completed encryption; starting decryption\n");

    t_cose_encrypt_dec_init(&dec_ctx, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0);

    t_cose_encrypt_dec_set_cek(&dec_ctx, cek);

    err = t_cose_encrypt_dec_detached(&dec_ctx,
                                      encrypted_cose_message,
                                      NULL_Q_USEFUL_BUF_C,
                                      encrypted_payload,
                                      decrypted_payload_buf,
                                     &decrypted_cose_message,
                                      NULL);

    if (err != T_COSE_SUCCESS) {
        printf("\nDecryption failed %d!\n", err);
        goto Done;
    }

    print_useful_buf("Plaintext: ", decrypted_cose_message);

Done:
    printf("---- %s EXAMPLE encrypt0 (%d) ----\n\n",
           err ? "FAILED" : "COMPLETED", err);
    return (int32_t)err;
}



#ifndef T_COSE_DISABLE_KEYWRAP
#include "t_cose/t_cose_recipient_enc_keywrap.h"
#include "t_cose/t_cose_recipient_dec_keywrap.h"


int32_t
key_wrap_example(void)
{
    struct t_cose_recipient_enc_keywrap kw_recipient;
    struct t_cose_encrypt_enc           enc_context;
    struct t_cose_recipient_dec_keywrap kw_unwrap_recipient;
    struct t_cose_encrypt_dec_ctx       dec_context;
    enum t_cose_err_t                   err;
    struct t_cose_key                   kek;
    struct q_useful_buf_c               encrypted_cose_message;
    struct q_useful_buf_c               encrypted_payload;
    struct q_useful_buf_c               decrypted_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB(         cose_message_buf, 1024);
    Q_USEFUL_BUF_MAKE_STACK_UB(         encrypted_payload_buf, 1024);
    Q_USEFUL_BUF_MAKE_STACK_UB(         decrypted_payload_buf, 1024);

    printf("\n---- START EXAMPLE key_wrap ----\n");
    printf("Create COSE_Encrypt with detached payload using AES-KW\n");


    /* ---- Make key handle for wrapping key -----
     *
     * The wrapping key, the KEK, is just the bytes "aaaa....".  The
     * API requires input keys be struct t_cose_key so there's a
     * little work to do here.
     */
    err = t_cose_key_init_symmetric(T_COSE_ALGORITHM_A128KW,
                                    Q_USEFUL_BUF_FROM_SZ_LITERAL("aaaaaaaaaaaaaaaa"),
                                   &kek);
    if(err) {
        goto Done;
    }

    /* ---- Set up keywrap recipient object ----
     *
     * The initializes an object of type struct
     * t_cose_recipient_enc_keywrap, the object/context for making a
     * COSE_Recipient for key wrap.
     *
     * We have to tell it the key wrap algorithm and give it the key
     * and kid.
     *
     * This object gets handed to the main encryption API which will
     * excersize it through a callback to create the COSE_Recipient.
     */
    t_cose_recipient_enc_keywrap_init(&kw_recipient, T_COSE_ALGORITHM_A128KW);
    t_cose_recipient_enc_keywrap_set_key(&kw_recipient,
                                          kek,
                                          Q_USEFUL_BUF_FROM_SZ_LITERAL("Kid A"));

    /* ----- Set up to make COSE_Encrypt ----
     *
     * Initialize. Have to say what algorithm is used to encrypt the
     * main content, the payload.
     *
     * Also tell the encryptor about the object to make the key wrap
     * COSE_Recipient by just giving it the pointer to it. It will get
     * called back in the next step.
     */
    t_cose_encrypt_enc_init(&enc_context, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT, T_COSE_ALGORITHM_A128GCM);
    t_cose_encrypt_add_recipient(&enc_context, (struct t_cose_recipient_enc *)&kw_recipient);


    /* ---- Actually Encrypt ----
     *
     * All the crypto gets called here including the encryption of the
     * payload and the key wrap.
     *
     * There are two buffers given, one for just the encrypted
     * payload and one for the COSE message. TODO: detached vs not and sizing.
     */
    err = t_cose_encrypt_enc_detached(&enc_context,
                                      Q_USEFUL_BUF_FROM_SZ_LITERAL("This is a real plaintext."),
                                      NULL_Q_USEFUL_BUF_C,
                                      encrypted_payload_buf,
                                      cose_message_buf,
                                     &encrypted_payload,
                                     &encrypted_cose_message);


    if (err != 0) {
        goto Done;
    }

    print_useful_buf("COSE_Encrypt: ", encrypted_cose_message);
    print_useful_buf("Detached Ciphertext: ", encrypted_payload);
    printf("\n");


    t_cose_encrypt_dec_init(&dec_context, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT);

    t_cose_recipient_dec_keywrap_init(&kw_unwrap_recipient);
    t_cose_recipient_dec_keywrap_set_kek(&kw_unwrap_recipient, kek, NULL_Q_USEFUL_BUF_C);

    t_cose_encrypt_dec_add_recipient(&dec_context, (struct t_cose_recipient_dec *)&kw_unwrap_recipient);

    err = t_cose_encrypt_dec_detached(&dec_context,
                              encrypted_cose_message, /* ciphertext */
                                      NULL_Q_USEFUL_BUF_C,
                              encrypted_payload,
                              decrypted_payload_buf,
                             &decrypted_payload,
                                      NULL);
    if(err) {
        goto Done;
    }

    print_useful_buf("Decrypted Payload:", decrypted_payload);


  Done:
    printf("---- %s EXAMPLE key_wrap (%d) ----\n\n",
           err ? "FAILED" : "COMPLETED", err);
    return (int32_t)err;
}

#endif /* !T_COSE_DISABLE_KEYWRAP */





#ifndef T_COSE_DISABLE_ESDH

#include "t_cose/t_cose_recipient_enc_esdh.h"
#include "t_cose/t_cose_recipient_dec_esdh.h"

int32_t
esdh_example(void)
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



    printf("\n---- START EXAMPLE ESDH ----\n");
    printf("Create COSE_Encrypt with attached payload using ESDH\n");

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
                                       Q_USEFUL_BUF_FROM_SZ_LITERAL(TEST_RECIPIENT_IDENTITY));

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
        printf("error encrypting (%d)\n", result);
        goto Done;
    }

    print_useful_buf("\nCOSE_Encrypt: ", cose_encrypted_message);


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

    print_useful_buf("Decrypted Payload:", decrypted_payload);


Done:
     printf("---- %s EXAMPLE ESDH (%d) ----\n\n",
             result ? "FAILED" : "COMPLETED", result);
         return (int32_t)result;
}

int32_t
esdh_example_detached(void)
{
    enum t_cose_err_t                result;
    struct t_cose_key                skR;
    struct t_cose_key                pkR;
    struct t_cose_encrypt_enc        enc_ctx;
    struct t_cose_recipient_enc_esdh recipient;
    struct q_useful_buf_c            cose_encrypted_message;
    Q_USEFUL_BUF_MAKE_STACK_UB  (    cose_encrypt_message_buffer, 400);
    struct q_useful_buf_c            encrypted_detached_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB  (    encrypted_detached_ciphertext_buffer, 50);

    printf("\n---- START EXAMPLE ESDH ----\n");
    printf("Create COSE_Encrypt with detached payload using ESDH\n");

    /* Create a key pair.  This is a fixed test key pair. The creation
     * of this key pair is crypto-library dependent because t_cose_key
     * is crypto-library dependent. See t_cose_key.h and the examples
     * to understand key-pair creation better. */
    result = init_fixed_test_ec_encryption_key(T_COSE_ELLIPTIC_CURVE_P_256,
                                           &pkR, /* out: public key to be used for encryption */
                                           &skR); /* out: corresponding private key for decryption */
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
                                       pkR,
                                       Q_USEFUL_BUF_FROM_SZ_LITERAL(TEST_RECIPIENT_IDENTITY));

 
    /* Give the recipient object to the main encryption context.
     * (Only one recipient is set here, but there could be more).
     */
    t_cose_encrypt_add_recipient(&enc_ctx,
                                 (struct t_cose_recipient_enc *)&recipient);

     /* Now do the actual encryption */
     result = t_cose_encrypt_enc_detached(&enc_ctx, /* in: encryption context */
                                          Q_USEFUL_BUF_FROM_SZ_LITERAL(PAYLOAD), /* in: payload to encrypt */
                                          NULL_Q_USEFUL_BUF_C, /* in/unused: AAD */
                                          encrypted_detached_ciphertext_buffer, /* in: buffer for detached ciphertext */
                                          cose_encrypt_message_buffer, /* in: buffer for COSE_Encrypt */
                                         &encrypted_detached_payload, /* out: encrypted detached */
                                         &cose_encrypted_message); /* out: COSE_Encrypt */

     if (result != T_COSE_SUCCESS) {
         printf("error encrypting (%d)\n", result);
         goto Done;
     }

     print_useful_buf("COSE_Encrypt: ", cose_encrypted_message);
     print_useful_buf("Detached Ciphertext: ", encrypted_detached_payload);

     /* TBD: Decryption goes in here.
      * Assume everything worked fine.
      */
     result = 0;

Done:
     printf("---- %s EXAMPLE ESDH (%d) ----\n\n",
             result ? "FAILED" : "COMPLETED", result);
         return (int32_t)result;

     /* Free test keys */
     free_fixed_test_ec_encryption_key(pkR);
     free_fixed_test_ec_encryption_key(skR);

}
#endif /* !T_COSE_DISABLE_ESDH */
