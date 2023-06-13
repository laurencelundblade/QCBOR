/*
 * signing_examples.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 *
 * Created by Laurence Lundblade on 2/20/23 from previous files.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "signing_examples.h"
#include "init_keys.h"

#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"

#include "t_cose/t_cose_sign_sign.h"
#include "t_cose/t_cose_signature_sign_main.h"

#include "t_cose/t_cose_sign_verify.h"
#include "t_cose/t_cose_signature_verify_main.h"

#include "print_buf.h"
#include <stdio.h>

/**
 * @file signing_examples.c
 *
 * @brief Several examples of different ways to use signing.
 *
 * Each function here is a self-contained example of how to
 * use the signing API.
 *
 * This file is crypto-library independent. It works for OpenSSL, Mbed
 * TLS and others. The key initialization, which *is* crypto-library
 * dependent, has been separated.
 *
 * Each example should pretty much stand on its own and be pretty
 * clean and well-commented code. Its purpose is to be an example (not
 * a test case). Someone should be able to easily copy the example as
 * a starting point for their use case.
 */


/**
 * \brief  Sign and verify example with one-step signing
 *
 * This example creates and verifies a COSE_SIgn1 with an inline
 * CBOR-encoded payload and no externally supplied AAD.
 *
 * This uses the one-step signing API. It is simpler than the
 * two-step API, but requires more memory.
 */
int32_t one_step_sign_example(void)
{
    enum t_cose_err_t                   return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(         signed_cose_buffer, 300);
    struct q_useful_buf_c               signed_cose;
    Q_USEFUL_BUF_MAKE_STACK_UB(         constructed_payload_buffer, 300);
    struct q_useful_buf_c               constructed_payload;
    struct q_useful_buf_c               returned_payload;
    QCBOREncodeContext                  cbor_encoder;
    QCBORError                          cbor_result;
    struct t_cose_sign_sign_ctx         sign_ctx;
    struct t_cose_sign_verify_ctx       verify_ctx;
    struct t_cose_key                   key_pair;
    struct t_cose_signature_sign_main   main_signer;
    struct t_cose_signature_verify_main main_verifier;


    printf("\n---- START EXAMPLE one_step_sign  ----\n");
    printf("Create COSE_Sign1 with ES256\n");

    /* ------   Construct the payload    ------
     *
     * The payload is constructed into its own continguous buffer.  In
     * this case the payload is CBOR-encoded so it uses QCBOR to
     * encode it, but CBOR is not required by COSE so it could be
     * anything at all.
     *
     * The payload constructed here is a map of some label-value pairs
     * similar to a CWT or EAT, but using string labels rather than
     * integers. It is just a little example.
     */
    QCBOREncode_Init(&cbor_encoder, constructed_payload_buffer);
    QCBOREncode_OpenMap(&cbor_encoder);
    QCBOREncode_AddSZStringToMap(&cbor_encoder, "BeingType", "Humanoid");
    QCBOREncode_AddSZStringToMap(&cbor_encoder, "Greeting", "We come in peace");
    QCBOREncode_AddInt64ToMap(&cbor_encoder, "ArmCount", 2);
    QCBOREncode_AddInt64ToMap(&cbor_encoder, "HeadCount", 1);
    QCBOREncode_AddSZStringToMap(&cbor_encoder, "BrainSize", "medium");
    QCBOREncode_AddBoolToMap(&cbor_encoder, "DrinksWater", true);
    QCBOREncode_CloseMap(&cbor_encoder);
    cbor_result = QCBOREncode_Finish(&cbor_encoder, &constructed_payload);

    printf("Encoded payload (size = %ld): %d (%s)\n",
           constructed_payload.len,
           cbor_result,
           cbor_result ? "fail" : "success");
    if(cbor_result) {
        return_value = (enum t_cose_err_t)cbor_result;
        goto Done;
    }


    /* ------   Make an ECDSA key pair    ------
     *
     * The key pair will be used for both signing and encryption. The
     * data type is struct t_cose_key on the outside, but internally
     * the format is that of the crypto library used, PSA in this
     * case. They key is just passed through t_cose to the underlying
     * crypto library.
     *
     * The implementation of init_fixed_test_signing_key() is
     * different for different crypto libraries. It is example code
     * like this, not an part of the t_cose library.
     */
    return_value = init_fixed_test_signing_key(T_COSE_ALGORITHM_ES256, &key_pair);

    printf("Made EC key with curve prime256v1: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Initialize for signing    ------
     *
     * Initialize the signing context by telling it the the type of
     * message, a COSE_Sign1.
     *
     * Then set up a signer object with the signing algorithm and key.
     * In this example no kid is given.
     *
     * The set-up signer object is then associated with the signing
     * context. Internally, a callback to the signer will fire when
     * t_cose_sign_sign() is called. This is when the signer does its
     * main work and the cryptographic algorithms are run.
     */

    t_cose_sign_sign_init(&sign_ctx, T_COSE_OPT_MESSAGE_TYPE_SIGN1);

    t_cose_signature_sign_main_init(&main_signer, T_COSE_ALGORITHM_ES256);

    t_cose_signature_sign_main_set_signing_key(&main_signer, key_pair, NULL_Q_USEFUL_BUF_C);

    t_cose_sign_add_signer(&sign_ctx, t_cose_signature_sign_from_main(&main_signer));

    printf("Initialized t_cose and configured signing key\n");


    /* ------   Sign    ------
     *
     * This performs encoding of the headers, the signing and
     * formatting in one API call.
     *
     * With this API, the payload ends up in memory twice, once as the
     * input here and once in the output. If the payload is large,
     * this needs about double the size of the payload to work.
     */
    return_value =
        t_cose_sign_sign(/* In: The context set up with signing key */
                         &sign_ctx,

                         /* In: No Externally Supplied AAD */
                         NULL_Q_USEFUL_BUF_C,

                         /* In: Pointer and length of payload to be
                          * signed.
                          */
                         constructed_payload,

                         /* In: Non-const pointer and length of the
                          * buffer where the completed output is
                          * written to. The length is that of the
                          * whole buffer.
                          */

                         signed_cose_buffer,

                         /* Out: Const pointer and actual length of
                          * the completed, signed and encoded
                          * COSE_Sign1 message. This points into the
                          * output buffer and has the lifetime of the
                          * output buffer.
                          */
                          &signed_cose);

    printf("Finished signing: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    print_useful_buf("COSE_Sign1 message:", signed_cose);
    printf("\n");


    /* ------   Set up for verification   ------
     *
     * Initialize the verification context. The type of message will
     * be discovered from the CBOR tag in this case.
     *
     * A verifier is set up with the key pair and again with no kid.
     * The key must be suitable for the signing algorithm. In this
     * case we know what the algorithm is from context so we know what
     * key to use.
     *
     * The verifier is then associated with the verification context.
     *
     * When t_cose_sign_verify is called, a callback to the verifier
     * will fire and the signature verification crypto will actually
     * run.
     */
    // TODO: replace T_COSE_OPT_MESSAGE_TYPE_SIGN1 with 0 when tags
    // determination works
    t_cose_sign_verify_init(&verify_ctx, T_COSE_OPT_MESSAGE_TYPE_SIGN1);

    t_cose_signature_verify_main_init(&main_verifier);

    t_cose_signature_verify_main_set_key(&main_verifier, key_pair, NULL_Q_USEFUL_BUF_C);

    t_cose_sign_add_verifier(&verify_ctx, t_cose_signature_verify_from_main(&main_verifier));


    printf("Initialized t_cose for verification and set verification key\n");


    /* ------   Perform the verification   ------
     *
     * Verification is relatively simple. The COSE_Sign1 message to
     * verify is passed in and the payload is returned if verification
     * is successful.  The key must be of the correct type for the
     * algorithm used to sign the COSE_Sign1.
     *
     * The COSE header parameters will be returned if requested, but
     * in this example they are not as NULL is passed for the location
     * to put them.
     */
    return_value =
        t_cose_sign_verify(/* In: The context set up with signing key */
                           &verify_ctx,

                           /* In: The signed and coded COSE message to verify */
                           signed_cose,

                           /* In: Externally Supplied Data (none here) */
                           NULL_Q_USEFUL_BUF_C,

                           /* Out: Pointer and length of verify payload */
                           &returned_payload,

                           /* Out: linked list of header parameters.
                            * Not requested in this case. */
                           NULL);

    printf("Verification complete: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    print_useful_buf("Verifyed payload:", returned_payload);


    /* ------   Free key pair   ------
     *
     * Most crypto libraries allocate memory or allocate a key
     * slot/handle for the representation of public key they are
     * requested operate on. See the source of this as an example of
     * what is needed to free a key for a particular crypto library.
     */
    free_fixed_signing_key(key_pair);

Done:
    printf("---- %s EXAMPLE one_step_sign (%d) ----\n\n",
           return_value ? "FAILED" : "COMPLETED", return_value);

    return (int32_t)return_value;
}



/**
 * \brief  Sign and verify detached payload with one-step signing.
 *
 * In this example, a detached non-CBOR payload is signed twice, once
 * with ECDSA and once with RSA. This makes a COSE_Sign, not a COSE_Sign1.
 */
int32_t one_step_multi_sign_detached_example(void)
{
    struct t_cose_sign_sign_ctx    sign_ctx;
    enum t_cose_err_t              return_value;
    struct q_useful_buf_c          aad;
    struct q_useful_buf_c          payload;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct t_cose_key              ecdsa_key_pair;
    struct t_cose_key              rsa_key_pair;
    struct t_cose_sign_verify_ctx  verify_ctx;
    struct t_cose_signature_sign_main   ecdsa_signer;
    struct t_cose_signature_verify_main ecdsa_verifier;
    struct t_cose_signature_sign_main   rsa_signer;
    struct t_cose_signature_verify_main rsa_verifier;


    /* The payload can be any sequence of bytes. It might be CBOR or
     * something completely different. There is no format requirement
     * at all. Here we make it out of a text string because that is
     * easy.  The same is true for the externally supplied AAD.  In
     * this example, the payload is detached which means it is outside
     * the COSE_Sign message. It must be transmitted the reciever some
     * how and supplied when performing verification.  The same is
     * true for the AAD. In this example the only difference between
     * the AAD and the payload is the name. They are both transmitted
     * outside the COSE message and both must be supplied to when
     * verifying the COSE message. The AAD is typically used for meta
     * data.
     */
    payload = Q_USEFUL_BUF_FROM_SZ_LITERAL("This is the payload");
    aad = Q_USEFUL_BUF_FROM_SZ_LITERAL("This externally supplied AAD");

    printf("\n---- START EXAMPLE one_step_multi_sign_detached  ----\n");
    printf("Create COSE_Sign with ES384 and PS256 signatures\n");


    /* ------   Make an ECDSA key pair    ------
     *
     * The key pair will be used for both signing and encryption. The
     * data type is struct t_cose_key on the outside, but internally
     * the format is that of the crypto library used, PSA in this
     * case. They key is just passed through t_cose to the underlying
     * crypto library.
     *
     * The implementation of init_fixed_test_signing_key() is
     * different for different crypto libraries. It is example code
     * like this, not an part of the t_cose library.
     */
    return_value = init_fixed_test_signing_key(T_COSE_ALGORITHM_ES384, &ecdsa_key_pair);
    printf("Made EC key with curve prime256v1: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done_free1;
    }

    return_value = init_fixed_test_signing_key(T_COSE_ALGORITHM_PS256, &rsa_key_pair);
    printf("Made RSA key: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
     if(return_value) {
         goto Done_free2;
     }

    /* ------   Initialize for signing    ------
     *
     * Initialize the signing context by telling it the the type of
     * message, COSE_Sign1.
     *
     * Then set up two signer objects with the signing algorithm and key.
     * In this example no kid is given.
     *
     * The signer objects are then associated with the signing
     * context. Internally, a callback to the signer will fire
     * when t_cose_sign_sign() is called and this does the real work.
     */

    t_cose_sign_sign_init(&sign_ctx, T_COSE_OPT_MESSAGE_TYPE_SIGN);

    t_cose_signature_sign_main_init(&ecdsa_signer, T_COSE_ALGORITHM_ES384);
    t_cose_signature_sign_main_set_signing_key(&ecdsa_signer, ecdsa_key_pair, NULL_Q_USEFUL_BUF_C);
    t_cose_sign_add_signer(&sign_ctx, t_cose_signature_sign_from_main(&ecdsa_signer));

    t_cose_signature_sign_main_init(&rsa_signer, T_COSE_ALGORITHM_ES384);
    t_cose_signature_sign_main_set_signing_key(&rsa_signer, ecdsa_key_pair, NULL_Q_USEFUL_BUF_C);
    t_cose_sign_add_signer(&sign_ctx, t_cose_signature_sign_from_main(&rsa_signer));

    printf("Initialized t_cose and configured signing key\n");


    /* ------   Sign    ------
     *
     * This performs encoding of the headers, the signing and CBOR
     * encoding in one API call.
     *
     * With this API, the payload ends up in memory twice, once as the
     * input here and once in the output. If the payload is large,
     * this needs about double the size of the payload to work.
     */
    return_value =
        t_cose_sign_sign_detached(/* In: The context set up with signing key */
                                  &sign_ctx,

                                  /* In: Externally Supplied AAD */
                                  aad,

                                  /* In: Pointer and length of payload
                                   * covered by the signature.
                                   */
                                  payload,

                                  /* In: Non-const pointer and length
                                   * of the buffer where the completed
                                   * output is written to. The length
                                   * here is that of the whole buffer.
                                   */
                                  signed_cose_buffer,

                                  /* Out: Const pointer and actual
                                   * length of the completed, signed
                                   * and encoded COSE_Sign1
                                   * message. This points into the
                                   * output buffer and has the
                                   * lifetime of the output buffer.
                                   */
                                  &signed_cose);

    printf("Finished signing: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done_free2;
    }

    print_useful_buf("COSE_Sign message with two COSE_Signatures:", signed_cose);
    printf("\n");


    /* ------   Set up for verification   ------
     *
     * Initialize the verification context.
     *
     * The verification key works the same way as the signing
     * key. Internally it must be in the format for the crypto library
     * used. It is passed straight through t_cose.
     *
     * Here two verifiers are set up, one for RSA
     */
    t_cose_sign_verify_init(&verify_ctx, 0);

    t_cose_signature_verify_main_init(&ecdsa_verifier);
    t_cose_signature_verify_main_set_key(&ecdsa_verifier, ecdsa_key_pair, NULL_Q_USEFUL_BUF_C);
    t_cose_sign_add_verifier(&verify_ctx, t_cose_signature_verify_from_main(&ecdsa_verifier));

    t_cose_signature_verify_main_init(&rsa_verifier);
    t_cose_signature_verify_main_set_key(&rsa_verifier, rsa_key_pair, NULL_Q_USEFUL_BUF_C);
    t_cose_sign_add_verifier(&verify_ctx, t_cose_signature_verify_from_main(&rsa_verifier));


    printf("Initialized t_cose for verification\n");


    /* ------   Perform the verification   ------
     *
     * Verification is relatively simple. The COSE_Sign message to
     * verify the detached payload and the aad are passed in.  The
     * error code indicates success or fail.
     *
     * The COSE header parameters will be returned if requested, but
     * in this example they are not as NULL is passed for the location
     * to put them.
     */
    return_value =
        t_cose_sign_verify_detached(/* In: The verification context. */
                                    &verify_ctx,

                                    /* In: The signed and encoded COSE
                                     * message to verify. */
                                    signed_cose,

                                    /* In: Externally Supplied AAD */
                                    aad,

                                    /* in: The detachd payload to verify */
                                    payload,

                                    /* Out: linked list of header
                                     * parameters.  Not requested in
                                     * this case. */
                                    NULL);

    printf("Verification complete: %d (%s)\n",
           return_value, return_value ? "fail" : "success");


    /* ------   Free key pair   ------
     *
     * Most crypto libraries allocate memory or allocate a key
     * slot/handle for the representation of public key they are
     * requested operate on. See the source of this as an example of
     * what is needed to free a key for a particular crypto library.
     */
Done_free2:
    free_fixed_signing_key(rsa_key_pair);
Done_free1:
    free_fixed_signing_key(ecdsa_key_pair);

    printf("---- %s EXAMPLE one_step_multi_sign_detached (%d) ----\n\n",
           return_value ? "FAILED" : "COMPLETED", return_value);

    return (int32_t)return_value;
}


/**
 * \brief  Sign and verify example with two-step signing
 *
 * The two-step (plus init and key set up) signing has the payload
 * constructed directly into the output buffer, uses less memory,
 * but is more complicated to use.
 */
int32_t two_step_sign_example(void)
{
    enum t_cose_err_t              return_value;
    struct t_cose_key              key_pair;
    QCBOREncodeContext             cbor_encoder;
    QCBORError                     cbor_error;
    struct t_cose_sign_sign_ctx    sign_ctx;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct q_useful_buf_c          payload;
    struct t_cose_sign_verify_ctx  verify_ctx;
    struct t_cose_signature_sign_main   main_signer;
    struct t_cose_signature_verify_main main_verifier;

    printf("\n---- START EXAMPLE two_step_sign  ----\n");
    printf("Create COSE_Sign1 with ES256\n");

    /* ------   Make an ECDSA key pair    ------
     *
     * The key pair will be used for both signing and encryption. The
     * data type is struct t_cose_key on the outside, but internally
     * the format is that of the crypto library used, PSA in this
     * case. They key is just passed through t_cose to the underlying
     * crypto library.
     *
     * The implementation of init_fixed_test_signing_key() is
     * different for different crypto libraries. It is example code
     * like this, not an part of the t_cose library.
     */
    return_value = init_fixed_test_signing_key(T_COSE_ALGORITHM_ES256, &key_pair);

    printf("Made EC key with curve prime256v1: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Initialize for signing    ------
     *
     * Set up the QCBOR encoding context with the output buffer. This
     * is where all the outputs including the payload goes. In this
     * case the maximum size is small and known so a fixed length
     * buffer is given. If it is not known then QCBOR and t_cose can
     * run without a buffer to calculate the needed size. In all
     * cases, if the buffer is too small QCBOR and t_cose will error
     * out gracefully and not overrun any buffers.
     *
     * Initialize the signing context by telling it the signing
     * algorithm and signing options. No options are set here hence
     * the 0 value.
     *
     * Set up the signing key and kid (key ID). No kid is passed here
     * hence the NULL_Q_USEFUL_BUF_C.
     */

    QCBOREncode_Init(&cbor_encoder, signed_cose_buffer);

    t_cose_sign_sign_init(&sign_ctx, T_COSE_OPT_MESSAGE_TYPE_SIGN1);

    t_cose_signature_sign_main_init(&main_signer, T_COSE_ALGORITHM_ES256);

    t_cose_signature_sign_main_set_signing_key(&main_signer, key_pair, NULL_Q_USEFUL_BUF_C);

    t_cose_sign_add_signer(&sign_ctx, t_cose_signature_sign_from_main(&main_signer));

    printf("Initialized QCBOR, t_cose and configured signing key\n");


    /* ------   Encode the headers    ------
     *
     * This just outputs the COSE_Sign1 header parameters.
     */
    return_value = t_cose_sign_encode_start(&sign_ctx, &cbor_encoder);

    printf("Encoded COSE headers: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Output the payload    ------
     *
     * Since the payload in COSE is a byte string, the the CBOR
     * payload must be byte string wrapped. QCBOR provides the means
     * to do this with QCBOREncode_BstrWrap().
     *
     * QCBOREncode functions are used to add the payload. It all goes
     * directly into the output buffer without any temporary copies.
     * The encoded CBOR here can be very large and complex. The only
     * limit is that the output buffer is large enough. If it is too
     * small, one of the following two calls will report the error as
     * QCBOR tracks encoding errors internally so the code calling it
     * doesn't have to.
     *
     * The payload constructed here is a map of some label-value pairs
     * similar to a CWT or EAT, but using string labels rather than
     * integers. It is just a little example.
     *
     * A simpler alternative is to call t_cose_sign_sign() instead of
     * t_cose_sign_encode_start() and t_cose_sign_encode_finish(),
     * however this requires memory to hold a copy of the payload and
     * the output COSE_Sign1 message. For that call the payload is
     * just passed in as a buffer.
     *
     * When all the CBOR is output, QCBOREncode_CloseBstrWrap2() must
     * be called to close the byte string. This also returns a pointer
     * and length of the encoded byte string so it can be passed to
     * t_cose_sign_encode_finish().
     */
    QCBOREncode_BstrWrap(&cbor_encoder);
    QCBOREncode_OpenMap(&cbor_encoder);
    QCBOREncode_AddSZStringToMap(&cbor_encoder, "BeingType", "Humanoid");
    QCBOREncode_AddSZStringToMap(&cbor_encoder, "Greeting", "We come in peace");
    QCBOREncode_AddInt64ToMap(&cbor_encoder, "ArmCount", 2);
    QCBOREncode_AddInt64ToMap(&cbor_encoder, "HeadCount", 1);
    QCBOREncode_AddSZStringToMap(&cbor_encoder, "BrainSize", "medium");
    QCBOREncode_AddBoolToMap(&cbor_encoder, "DrinksWater", true);
    QCBOREncode_CloseMap(&cbor_encoder);
    QCBOREncode_CloseBstrWrap2(&cbor_encoder, false, &payload);

    printf("Payload encoded\n");


    /* ------   Sign    ------
     *
     * This call causes the actual signature crypto to run and to
     * finish out the the CBOR encoding.
     */
    return_value =
        t_cose_sign_encode_finish(/* In: The context set up with signing key */
                                  &sign_ctx,

                                  /* In: No Externally Supplied AAD */
                                  NULL_Q_USEFUL_BUF_C,

                                  /* In: the payload covered by the signature */
                                  payload,

                                  /* In: the CBOR encoder to output to */
                                  &cbor_encoder);

    printf("Fnished signing: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Complete CBOR Encoding   ------
     *
     * This closes out the CBOR encoding returning any errors that
     * might have been recorded.
     *
     * The resulting signed message is returned in signed_cose. It is
     * a pointer and length into the buffer given to
     * QCBOREncode_Init().
     */
    cbor_error = QCBOREncode_Finish(&cbor_encoder, &signed_cose);
    printf("Finished CBOR encoding: %d (%s)\n",
           cbor_error, return_value ? "fail" : "success");
    if(cbor_error) {
        goto Done;
    }

    print_useful_buf("COSE_Sign1:", signed_cose);
    printf("\n");


    /* ------   Set up for verification   ------
     *
     * Initialize the verification context. The type of message will
     * be discovered from the CBOR tag in this case.
     *
     * A verifier is set up with the key pair and again with no kid.
     * The key must be suitable for the signing algorithm. In this
     * case we know what the algorithm is from context so we know what
     * key to use.
     *
     * The verifier is then associated with the verification context.
     *
     * When t_cose_sign_verify is called, a callback to the verifier
     * will fire and the signature verification crypto will actually
     * run.
     */
    t_cose_sign_verify_init(&verify_ctx, T_COSE_OPT_MESSAGE_TYPE_SIGN1);

    t_cose_signature_verify_main_init(&main_verifier);

    t_cose_signature_verify_main_set_key(&main_verifier, key_pair, NULL_Q_USEFUL_BUF_C);

    t_cose_sign_add_verifier(&verify_ctx, t_cose_signature_verify_from_main(&main_verifier));


    printf("Initialized t_cose for verification and set verification key\n");


    /* ------   Perform the verification   ------
     *
     * Verification is relatively simple. The COSE_Sign1 message to
     * verify is passed in and the payload is returned if verification
     * is successful.  The key must be of the correct type for the
     * algorithm used to sign the COSE_Sign1.
     *
     * The COSE header parameters will be returned if requested, but
     * in this example they are not as NULL is passed for the location
     * to put them.
     */
    return_value =
        t_cose_sign_verify(/* In: The context set up with signing key */
                           &verify_ctx,

                           /* In: The signed and coded COSE message to verify */
                           signed_cose,

                           /* In: Externally Supplied Data (none here) */
                           NULL_Q_USEFUL_BUF_C,

                           /* Out: Pointer and length of verify payload */
                           &payload,

                           /* Out: linked list of header parameters.
                            * Not requested in this case. */
                           NULL);

    printf("Verification complete: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    print_useful_buf("Verified payload:", payload);


    /* ------   Free key pair   ------
     *
     * Most crypto libraries allocate memory or allocate a key
     * slot/handle for the representation of public key they are
     * requested operate on. See the source of this as an example of
     * what is needed to free a key for a particular crypto library.
     */
    free_fixed_signing_key(key_pair);

Done:
    printf("---- %s EXAMPLE two_step_sign (%d) ----\n\n",
       return_value ? "FAILED" : "COMPLETED", return_value);
    return (int)return_value;
}



/**
 * \brief  Sign and verify example with old one-step signing
 *
 * This is for the t_cose_sign1, the t_cose v1 signing interface. It is still
 * supported by t_cose_sign_sign is preferred going forward.
 *
 * The one-step signing uses more memory, but
 * is simpler to use. In the code below constructed_payload_buffer is
 * the extra buffer that two-step signing avoids.
 */
int32_t old_one_step_sign_example(void)
{
    struct t_cose_sign1_sign_ctx   sign_ctx;
    enum t_cose_err_t              return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    Q_USEFUL_BUF_MAKE_STACK_UB(    constructed_payload_buffer, 300);
    struct q_useful_buf_c          constructed_payload;
    struct q_useful_buf_c          returned_payload;
    struct t_cose_key              key_pair;
    struct t_cose_sign1_verify_ctx verify_ctx;
    QCBOREncodeContext             cbor_encode;
    QCBORError                     qcbor_result;

    printf("\n---- START EXAMPLE one_step_sign  ----\n");
    printf("Create COSE_Sign1 with ES256\n");

    /* ------   Construct the payload    ------
     *
     * The payload is constructed into its own continguous buffer.
     * In this case the payload is CBOR formatm so it uses QCBOR to
     * encode it, but CBOR is not
     * required by COSE so it could be anything at all.
     *
     * The payload constructed here is a map of some label-value
     * pairs similar to a CWT or EAT, but using string labels
     * rather than integers. It is just a little example.
     */
    QCBOREncode_Init(&cbor_encode, constructed_payload_buffer);
    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMap(&cbor_encode, "BeingType", "Humanoid");
    QCBOREncode_AddSZStringToMap(&cbor_encode, "Greeting", "We come in peace");
    QCBOREncode_AddInt64ToMap(&cbor_encode, "ArmCount", 2);
    QCBOREncode_AddInt64ToMap(&cbor_encode, "HeadCount", 1);
    QCBOREncode_AddSZStringToMap(&cbor_encode, "BrainSize", "medium");
    QCBOREncode_AddBoolToMap(&cbor_encode, "DrinksWater", true);
    QCBOREncode_CloseMap(&cbor_encode);
    qcbor_result = QCBOREncode_Finish(&cbor_encode, &constructed_payload);

    printf("Encoded payload (size = %ld): %d (%s)\n",
           constructed_payload.len,
           qcbor_result,
           qcbor_result ? "fail" : "success");
    if(qcbor_result) {
        return_value = (enum t_cose_err_t)qcbor_result;
        goto Done;
    }


    /* ------   Make an ECDSA key pair    ------
     *
     * The key pair will be used for both signing and encryption. The
     * data type is struct t_cose_key on the outside, but internally
     * the format is that of the crypto library used, PSA in this
     * case. They key is just passed through t_cose to the underlying
     * crypto library.
     *
     * The making and destroying of the key pair is the only code
     * dependent on the crypto library in this file.
     */
    return_value = init_fixed_test_signing_key(T_COSE_ALGORITHM_ES256, &key_pair);

    printf("Made EC key with curve prime256v1: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Initialize for signing    ------
     *
     * Initialize the signing context by telling it the signing
     * algorithm and signing options. No options are set here hence
     * the 0 value.
     *
     * Set up the signing key and kid (key ID). No kid is passed here
     * hence the NULL_Q_USEFUL_BUF_C.
     */

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);

    t_cose_sign1_set_signing_key(&sign_ctx, key_pair,  NULL_Q_USEFUL_BUF_C);

    printf("Initialized t_cose and configured signing key\n");


    /* ------   Sign    ------
     *
     * This performs encoding of the headers, the signing and formatting
     * in one shot.
     *
     * With this API the payload ends up in memory twice, once as the
     * input and once in the output. If the payload is large, this
     * needs about double the size of the payload to work.
     */
    return_value = t_cose_sign1_sign(/* The context set up with signing key */
                                     &sign_ctx,
                                     /* Pointer and length of payload to be
                                      * signed.
                                      */
                                     constructed_payload,
                                     /* Non-const pointer and length of the
                                      * buffer where the completed output is
                                      * written to. The length here is that
                                      * of the whole buffer.
                                      */
                                     signed_cose_buffer,
                                     /* Const pointer and actual length of
                                      * the completed, signed and encoded
                                      * COSE_Sign1 message. This points
                                      * into the output buffer and has the
                                      * lifetime of the output buffer.
                                      */
                                     &signed_cose);

    printf("Finished signing: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    print_useful_buf("COSE_Sign1 message:", signed_cose);
    printf("\n");


    /* ------   Set up for verification   ------
     *
     * Initialize the verification context.
     *
     * The verification key works the same way as the signing
     * key. Internally it must be in the format for the crypto library
     * used. It is passed straight through t_cose.
     */
    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    printf("Initialized t_cose for verification and set verification key\n");


    /* ------   Perform the verification   ------
     *
     * Verification is relatively simple. The COSE_Sign1 message to
     * verify is passed in and the payload is returned if verification
     * is successful.  The key must be of the correct type for the
     * algorithm used to sign the COSE_Sign1.
     *
     * The COSE header parameters will be returned if requested, but
     * in this example they are not as NULL is passed for the location
     * to put them.
     */
    return_value =
        t_cose_sign1_verify(/* In: The context set up with signing key */
                            &verify_ctx,

                            /* In: The signed and encoded COSE
                             * message to verify. */
                            signed_cose,

                            /* Out: the payload from the COSE message */
                            &returned_payload,  /* Payload from signed_cose */

                            /* Out: linked list of header
                             * parameters.  Not requested in
                             * this case. */
                            NULL);

    printf("Verification complete: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    print_useful_buf("Verifyed payload:", returned_payload);


    /* ------   Free key pair   ------
     *
     * Some implementations of PSA allocate slots for the keys in
     * use. This call indicates that the key slot can be de allocated.
     */
    free_fixed_signing_key(key_pair);

Done:
    printf("---- %s EXAMPLE one_step_sign (%d) ----\n\n",
           return_value ? "FAILED" : "COMPLETED", return_value);

    return (int32_t)return_value;
}




/**
 * \brief  Sign and verify example with old two-step signing.
 *
 * This is for the t_cose_sign1, the t_cose v1 signing interface. It is still
 * supported but t_cose_sign_sign is preferred going forward.
 *
 * The two-step (plus init and key set up) signing has the payload
 * constructed directly into the output buffer, uses less memory,
 * but is more complicated to use.
 */
int32_t old_two_step_sign_example(void)
{
    struct t_cose_sign1_sign_ctx   sign_ctx;
    enum t_cose_err_t              return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct q_useful_buf_c          payload;
    struct t_cose_key              key_pair;
    QCBOREncodeContext             cbor_encode;
    QCBORError                     cbor_error;
    struct t_cose_sign1_verify_ctx verify_ctx;

    printf("\n---- START EXAMPLE two_step_sign  ----\n");
    printf("Create COSE_Sign1 with ES256\n");

    /* ------   Make an ECDSA key pair    ------
     *
     * The key pair will be used for both signing and encryption. The
     * data type is struct t_cose_key on the outside, but internally
     * the format is that of the crypto library used, PSA in this
     * case. They key is just passed through t_cose to the underlying
     * crypto library.
     *
     * The making and destroying of the key pair is the only code
     * dependent on the crypto library in this file.
     */
    return_value = init_fixed_test_signing_key(T_COSE_ALGORITHM_ES256, &key_pair);

    printf("Made EC key with curve prime256v1: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Initialize for signing    ------
     *
     * Set up the QCBOR encoding context with the output buffer. This
     * is where all the outputs including the payload goes. In this
     * case the maximum size is small and known so a fixed length
     * buffer is given. If it is not known then QCBOR and t_cose can
     * run without a buffer to calculate the needed size. In all
     * cases, if the buffer is too small QCBOR and t_cose will error
     * out gracefully and not overrun any buffers.
     *
     * Initialize the signing context by telling it the signing
     * algorithm and signing options. No options are set here hence
     * the 0 value.
     *
     * Set up the signing key and kid (key ID). No kid is passed here
     * hence the NULL_Q_USEFUL_BUF_C.
     */

    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx, 0, T_COSE_ALGORITHM_ES256);

    t_cose_sign1_set_signing_key(&sign_ctx, key_pair, NULL_Q_USEFUL_BUF_C);

    printf("Initialized QCBOR, t_cose and configured signing key\n");


    /* ------   Encode the headers    ------
     *
     * This just outputs the COSE_Sign1 header parameters and gets set
     * up for the payload to be output.
     */
    return_value = t_cose_sign1_encode_parameters(&sign_ctx, &cbor_encode);

    printf("Encoded COSE headers: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Output the payload    ------
     *
     * QCBOREncode functions are used to add the payload. It all goes
     * directly into the output buffer without any temporary copies.
     * QCBOR keeps track of the what is the payload is so t_cose knows
     * what to hash and sign.
     *
     * The encoded CBOR here can be very large and complex. The only
     * limit is that the output buffer is large enough. If it is too
     * small, one of the following two calls will report the error as
     * QCBOR tracks encoding errors internally so the code calling it
     * doesn't have to.
     *
     * The payload constructed here is a map of some label-value
     * pairs similar to a CWT or EAT, but using string labels
     * rather than integers. It is just a little example.
     *
     * A simpler alternative is to call t_cose_sign1_sign() instead of
     * t_cose_sign1_encode_parameters() and
     * t_cose_sign1_encode_signature(), however this requires memory
     * to hold a copy of the payload and the output COSE_Sign1
     * message. For that call the payload is just passed in as a
     * buffer.
     */
    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMap(&cbor_encode, "BeingType", "Humanoid");
    QCBOREncode_AddSZStringToMap(&cbor_encode, "Greeting", "We come in peace");
    QCBOREncode_AddInt64ToMap(&cbor_encode, "ArmCount", 2);
    QCBOREncode_AddInt64ToMap(&cbor_encode, "HeadCount", 1);
    QCBOREncode_AddSZStringToMap(&cbor_encode, "BrainSize", "medium");
    QCBOREncode_AddBoolToMap(&cbor_encode, "DrinksWater", true);
    QCBOREncode_CloseMap(&cbor_encode);

    printf("Payload added\n");


    /* ------   Sign    ------
     *
     * This call signals the end payload construction, causes the actual
     * signing to run.
     */
    return_value = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);

    printf("Fnished signing: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Complete CBOR Encoding   ------
     *
     * This closes out the CBOR encoding returning any errors that
     * might have been recorded.
     *
     * The resulting signed message is returned in signed_cose. It is
     * a pointer and length into the buffer give to
     * QCBOREncode_Init().
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    printf("Finished CBOR encoding: %d (%s)\n",
           cbor_error, return_value ? "fail" : "success");
    if(cbor_error) {
        goto Done;
    }

    print_useful_buf("COSE_Sign1:", signed_cose);
    printf("\n");


    /* ------   Set up for verification   ------
     *
     * Initialize the verification context.
     *
     * The verification key works the same way as the signing
     * key. Internally it must be in the format for the crypto library
     * used. It is passed straight through t_cose.
     */
    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, key_pair);

    printf("Initialized t_cose for verification and set verification key\n");


    /* ------   Perform the verification   ------
     *
     * Verification is relatively simple. The COSE_Sign1 message to
     * verify is passed in and the payload is returned if verification
     * is successful.  The key must be of the correct type for the
     * algorithm used to sign the COSE_Sign1.
     *
     * The COSE header parameters will be returned if requested, but
     * in this example they are not as NULL is passed for the location
     * to put them.
     */
    return_value =
        t_cose_sign1_verify(/* In: The context set up with signing key */
                            &verify_ctx,

                            /* In: The signed and encoded COSE
                             * message to verify. */
                            signed_cose,

                            /* Out: the payload from the COSE message */
                            &payload,  /* Payload from signed_cose */

                            /* Out: linked list of header
                             * parameters.  Not requested in
                             * this case. */
                            NULL);

    printf("Verification complete: %d (%s)\n",
           return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }

    print_useful_buf("Verified payload:", payload);


    /* ------   Free key pair   ------
     *
     * Some implementations of PSA allocate slots for the keys in
     * use. This call indicates that the key slot can be de allocated.
     */
    free_fixed_signing_key(key_pair);

Done:
    printf("---- %s EXAMPLE two_step_sign (%d) ----\n\n",
       return_value ? "FAILED" : "COMPLETED", return_value);
    return (int)return_value;
}
