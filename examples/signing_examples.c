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


/* This file is crypto-library independent. It works for OpenSSL, Mbed
 * TLS and others. The key initialization, which *is* crypto-library
 * dependent, has been separated.
 *
 * Each example should pretty much stand on its own and be pretty
 * clean and well-commented code. Its purpose is to be an example
 * (not a test case). Someone should be able to easily copy the
 * example as a starting point for their use case.
 */



/**
 * \brief  Sign and verify example with one-step signing
 *
 * The one-step (plus init and key set up) signing uses more memory, but
 * is simpler to use. In the code below constructed_payload_buffer is
 * the extra buffer that two-step signing avoids.
 */
int32_t one_step_sign_example(void)
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

    printf("Made EC key with curve prime256v1: %d (%s)\n", return_value, return_value ? "fail" : "success");
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

    printf("Finished signing: %d (%s)\n", return_value, return_value ? "fail" : "success");
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
    return_value = t_cose_sign1_verify(&verify_ctx,
                                       signed_cose,         /* COSE to verify */
                                       &returned_payload,  /* Payload from signed_cose */
                                       NULL);      /* Don't return parameters */

    printf("Verification complete: %d (%s)\n", return_value, return_value ? "fail" : "success");
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
 * \brief  Sign and verify example with two-step signing
 *
 * The two-step (plus init and key set up) signing has the payload
 * constructed directly into the output buffer, uses less memory,
 * but is more complicated to use.
 */
int32_t two_step_sign_example(void)
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

    printf("Made EC key with curve prime256v1: %d (%s)\n", return_value, return_value ? "fail" : "success");
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

    printf("Encoded COSE headers: %d (%s)\n", return_value, return_value ? "fail" : "success");
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

    printf("Fnished signing: %d (%s)\n", return_value, return_value ? "fail" : "success");
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
    printf("Finished CBOR encoding: %d (%s)\n", cbor_error, return_value ? "fail" : "success");
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
    return_value = t_cose_sign1_verify(&verify_ctx,
                                       signed_cose,         /* COSE to verify */
                                       &payload,  /* Payload from signed_cose */
                                       NULL);      /* Don't return parameters */

    printf("Verification complete: %d (%s)\n", return_value, return_value ? "fail" : "success");
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




/**
 * \brief  Sign and verify example with two-step signing
 *
 * The two-step (plus init and key set up) signing has the payload
 * constructed directly into the output buffer, uses less memory,
 * but is more complicated to use.
 */
int32_t two_step_sign_example_new(void)
{
    struct t_cose_sign_sign_ctx    sign_ctx;
    struct t_cose_signature_sign_main main_signer;
    enum t_cose_err_t              return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct q_useful_buf_c          payload;
    struct t_cose_key              key_pair;
    QCBOREncodeContext             cbor_encode;
    QCBORError                     cbor_error;
    struct t_cose_sign1_verify_ctx verify_ctx;

    printf("\n---- START EXAMPLE two_step_sign_new  ----\n");
    printf("Create COSE_Sign1 with ES256\n");
    printf("Create using new sign API, verify with old\n");

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

    printf("Made EC key with curve prime256v1: %d (%s)\n", return_value, return_value ? "fail" : "success");
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

    t_cose_sign_sign_init(&sign_ctx, T_COSE_OPT_MESSAGE_TYPE_SIGN1);

    t_cose_signature_sign_main_init(&main_signer, T_COSE_ALGORITHM_ES256);

    t_cose_signature_sign_main_set_signing_key(&main_signer, key_pair, NULL_Q_USEFUL_BUF_C);

    t_cose_sign_add_signer(&sign_ctx, t_cose_signature_sign_from_main(&main_signer));

    printf("Initialized QCBOR, t_cose and configured signing key\n");


    /* ------   Encode the headers    ------
     *
     * This just outputs the COSE_Sign1 header parameters and gets set
     * up for the payload to be output.
     */
    return_value = t_cose_sign_encode_start(&sign_ctx, false, &cbor_encode);

    printf("Encoded COSE headers: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Output the payload    ------
     *
     * QCBOREncode functions are used to add the payload. It all goes
     * directly into the output buffer without any temporary copies.
     * QCBOR keeps track of the what is the payload so t_cose knows
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
    return_value = t_cose_sign_encode_finish(&sign_ctx,
                                             NULL_Q_USEFUL_BUF_C,
                                             NULL_Q_USEFUL_BUF_C,
                                             &cbor_encode);

    printf("Fnished signing: %d (%s)\n", return_value, return_value ? "fail" : "success");
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
    printf("Finished CBOR encoding: %d (%s)\n", cbor_error, return_value ? "fail" : "success");
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
    return_value = t_cose_sign1_verify(&verify_ctx,
                                       signed_cose,         /* COSE to verify */
                                       &payload,  /* Payload from signed_cose */
                                       NULL);      /* Don't return parameters */

    printf("Verification complete: %d (%s)\n", return_value, return_value ? "fail" : "success");
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
    printf("---- %s EXAMPLE two_step_sign_new (%d) ----\n\n",
       return_value ? "FAILED" : "COMPLETED", return_value);
    return (int)return_value;
}




/**
 * \brief  Sign and verify example with two-step signing
 *
 * The two-step (plus init and key set up) signing has the payload
 * constructed directly into the output buffer, uses less memory,
 * but is more complicated to use.
 */
int32_t two_step_sign_example_new_verify(void)
{
    struct t_cose_sign1_sign_ctx    sign_ctx;
    enum t_cose_err_t              return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct q_useful_buf_c          payload;
    struct t_cose_key              key_pair;
    QCBOREncodeContext             cbor_encode;
    QCBORError                     cbor_error;
    struct t_cose_sign_verify_ctx verify_ctx;

    printf("\n---- START EXAMPLE two_step_sign_example_new_verify  ----\n");
    printf("Create COSE_Sign1 with ES256\n");
    printf("Create using old sign API, verify with new\n");

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

    printf("Made EC key with curve prime256v1: %d (%s)\n", return_value, return_value ? "fail" : "success");
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

    printf("Encoded COSE headers: %d (%s)\n", return_value, return_value ? "fail" : "success");
    if(return_value) {
        goto Done;
    }


    /* ------   Output the payload    ------
     *
     * QCBOREncode functions are used to add the payload. It all goes
     * directly into the output buffer without any temporary copies.
     * QCBOR keeps track of the what is the payload so t_cose knows
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

    printf("Fnished signing: %d (%s)\n", return_value, return_value ? "fail" : "success");
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
    printf("Finished CBOR encoding: %d (%s)\n", cbor_error, return_value ? "fail" : "success");
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
    t_cose_sign_verify_init(&verify_ctx, T_COSE_OPT_MESSAGE_TYPE_SIGN1);

    struct t_cose_signature_verify_main verifier;
    t_cose_signature_verify_main_init(&verifier);
    t_cose_signature_verify_main_set_key(&verifier, key_pair, NULL_Q_USEFUL_BUF_C);

    t_cose_sign_add_verifier(&verify_ctx, t_cose_signature_verify_from_main(&verifier));

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
    return_value = t_cose_sign_verify(&verify_ctx,
                                       signed_cose,         /* COSE to verify */
                                       NULL_Q_USEFUL_BUF_C,
                                       &payload,  /* Payload from signed_cose */
                                       NULL);      /* Don't return parameters */

    printf("Verification complete: %d (%s)\n", return_value, return_value ? "fail" : "success");
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

    printf("---- %s EXAMPLE two_step_sign_example_new_verify (%d) ----\n\n",
       return_value ? "FAILED" : "COMPLETED", return_value);
    return (int32_t)return_value;
}

