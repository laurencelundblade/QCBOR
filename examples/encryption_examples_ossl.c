/*
 *  encryption_examples_ossl.c
 *
 * Copyright 2023, Laurence Lundblade
 * Created by Laurence Lundblade on 1/20/23.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "encryption_examples_ossl.h"
#include <stdio.h>


#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_encrypt_dec.h"

// TODO: switch to a common general purpose version of this.
static void print_bytestr(const uint8_t *bytes, size_t len)
{
    for(unsigned int idx = 0; idx<len; idx++)
    {
        printf("%02X",bytes[idx]);
    }
}


static enum t_cose_err_t
make_ossl_symmetric_key_handle(int32_t               cose_algorithm_id,
                               struct q_useful_buf_c symmetric_key,
                               struct t_cose_key    *key_handle)
{
    (void)cose_algorithm_id; // TODO: maybe check the algorithm is symmetric
    key_handle->crypto_lib   = T_COSE_CRYPTO_LIB_OPENSSL;
    key_handle->k.key_buffer = symmetric_key;

    return T_COSE_SUCCESS;
}


void
direct_detached_example()
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

    printf("\n-- 3a. Create COSE_Encrypt0 with detached payload --\n\n");
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

    /* In direct encryption, we simply make a t_cose_key for the
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
     */
    make_ossl_symmetric_key_handle(T_COSE_ALGORITHM_A128GCM,
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


    printf("COSE: ");
    print_bytestr(encrypted_cose_message.ptr, encrypted_cose_message.len);
    printf("\n\nCiphertext: ");
    print_bytestr(encrypted_payload.ptr, encrypted_payload.len);
    printf("\n");

    printf("\n-- 3b. Process COSE_Encrypt0 with detached payload --\n\n");

    t_cose_encrypt_dec_init(&dec_ctx, T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0);

    t_cose_encrypt_dec_set_cek(&dec_ctx, cek);

    err = t_cose_encrypt_dec_detached(&dec_ctx,                 /* in: context */
                                      encrypted_cose_message,   /* in: message */
                                      NULL_Q_USEFUL_BUF_C,      /* in: aad */
                                      encrypted_payload,        /* in: detached ciphertext */
                                      decrypted_payload_buf,    /* in: buffer for decrypted payload */
                                     &decrypted_cose_message);  /* out: decrypted payload */

    if (err != T_COSE_SUCCESS) {
        printf("\nDecryption failed!\n");
        return;
    }

    printf("\nPlaintext: ");
    print_bytestr(decrypted_cose_message.ptr, decrypted_cose_message.len);
}

#include "t_cose/t_cose_recipient_enc_aes_kw.h"
void key_wrap_example()
{
    struct t_cose_recipient_enc_keywrap kw_recipient;
    struct t_cose_encrypt_enc       enc_context;
    enum t_cose_err_t                   err;
    struct t_cose_key                   kek;
    struct q_useful_buf_c               encrypted_cose_message;
    struct q_useful_buf_c               encrypted_payload;
    Q_USEFUL_BUF_MAKE_STACK_UB(         cose_message_buf, 1024);
    Q_USEFUL_BUF_MAKE_STACK_UB(         encrypted_payload_buf, 1024);


    printf("\n-- 4a. Create COSE_Encrypt with detached payload using AES-KW --\n\n");


    /* ---- Make key handle for wrapping key -----
     *
     * The wrapping key, the KEK, is just the bytes "aaaa....".  The
     * API requires input keys be struct t_cose_key so there's a
     * little work to do.
     */
    // TODO: should th algorithm ID be T_COSE_ALGORITHM_A128KW?
    make_ossl_symmetric_key_handle(T_COSE_ALGORITHM_A128GCM,
                                  Q_USEFUL_BUF_FROM_SZ_LITERAL("aaaaaaaaaaaaaaaa"),
                                  &kek);

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
        printf("\nEncryption failed!\n");
        return;
    }

    printf("COSE: ");
    print_bytestr(encrypted_cose_message.ptr, encrypted_cose_message.len);
    printf("\n\nCiphertext: ");
    print_bytestr(encrypted_payload.ptr, encrypted_payload.len);
    printf("\n");

    return;
}
