/*
 * t_cose_sign_sign.c
 *
 * Copyright (c) 2018-2023, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_sign_sign.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"


/**
 * \file t_cose_sign_sign.c
 *
 * \brief This implements creation of COSE_Sign and COSE_Sign1 messages.
 *
 * This relies on instances of t_cose_signature_sign to create the
 * actual signatures. The work done here is encoding the message with
 * the headers, payload and signature(s).
 */


/*
 * Pubilc Function. See t_cose_sign_sign.h
 */
enum t_cose_err_t
t_cose_sign_encode_start(struct t_cose_sign_sign_ctx *me,
                         QCBOREncodeContext          *cbor_encoder)
{
    enum t_cose_err_t              return_value;
    struct t_cose_signature_sign  *signer;
    struct t_cose_parameter       *parameters;
    uint64_t                       message_type_tag_number;

    /* --- Basic set up and error checks --- */
    signer = me->signers;
    message_type_tag_number = me->option_flags & T_COSE_OPT_MESSAGE_TYPE_MASK;
#ifndef T_COSE_DISABLE_USAGE_GUARDS
    if(message_type_tag_number != CBOR_TAG_COSE_SIGN1 &&
       message_type_tag_number != CBOR_TAG_COSE_SIGN) {
        /* Caller didn't ask for CBOR_TAG_COSE_SIGN or CBOR_TAG_COSE_SIGN1 */
        return T_COSE_ERR_BAD_OPT;
    }
    /* There must be at least one signer configured (a "signer" is an
     * object that makes a signature; see struct
     * t_cose_signature_sign). The signer object must be configured
     * with the key material and such.
     */
    if(signer == NULL) {
        /* No signers configured. */
        return T_COSE_ERR_NO_SIGNERS;
    }
    if(message_type_tag_number == CBOR_TAG_COSE_SIGN1 && signer->rs.next != NULL) {
        /* Only one signer allowed for COSE_Sign1 */
        return T_COSE_ERR_TOO_MANY_SIGNERS;
    }
#endif /* ! T_COSE_DISABLE_USAGE_GUARDS */


    /* --- Make list of the body header parameters --- */
    /* Form up the full list of body header parameters which may
     * include the COSE_Sign1 algorithm ID and kid. It may also
     * include the caller-added parameters like content type. */
    parameters = NULL;
    if(message_type_tag_number == CBOR_TAG_COSE_SIGN1) {
        /* For a COSE_Sign1, the parameters go in the main body header
         * parameter section, and the signature part just contains raw
         * signature bytes, not an array of COSE_Signature. This gets
         * the parameters from the signer. */
        signer->headers_cb(signer, &parameters);
    }
    t_cose_params_append(&parameters, me->added_body_parameters);

    /* --- Add the CBOR tag indicating COSE message type --- */
    if(!(me->option_flags & T_COSE_OPT_OMIT_CBOR_TAG)) {
        QCBOREncode_AddTag(cbor_encoder, message_type_tag_number);
    }

    /* --- Open array-of-four that holds all COSE_Sign(1) messages --- */
    QCBOREncode_OpenArray(cbor_encoder);

    /* --- Encode both protected and unprotected headers --- */
    return_value = t_cose_headers_encode(cbor_encoder,
                                         parameters,
                                         &me->encoded_prot_params);

    /* Failures in CBOR encoding will be caught in t_cose_sign_encode_finish()
     * or other. No need to track here as the QCBOR encoder tracks them internally.
     */
    return return_value;
}


/*
 * Public Function. See t_cose_sign_sign.h
 */
enum t_cose_err_t
t_cose_sign_encode_finish(struct t_cose_sign_sign_ctx *me,
                          struct q_useful_buf_c        aad,
                          struct q_useful_buf_c        signed_payload,
                          QCBOREncodeContext          *cbor_encoder)
{
    enum t_cose_err_t             return_value;
    struct t_cose_signature_sign *signer;
    struct t_cose_sign_inputs     sign_inputs;
    uint64_t                      message_type_tag_number;

#ifndef T_COSE_DISABLE_USAGE_GUARDS
    /* --- Early error check --- */
    /* Check that there are no CBOR encoding errors before proceeding
     * with hashing and signing. This is not actually necessary as the
     * errors will be caught correctly later, but it does make it a
     * bit easier for the caller to debug problems.
     */
    return_value = qcbor_encode_error_to_t_cose_error(cbor_encoder);
    if(return_value != T_COSE_SUCCESS) {
        return return_value;;
    }
#endif /* !T_COSE_DISABLE_USAGE_GUARDS */

    message_type_tag_number = me->option_flags & T_COSE_OPT_MESSAGE_TYPE_MASK;


    /* --- Signature for COSE_Sign1 or signatures for COSE_Sign --- */
    sign_inputs.body_protected = me->encoded_prot_params;
    sign_inputs.sign_protected = NULL_Q_USEFUL_BUF_C; /* filled in by sign_cb */
    sign_inputs.payload        = signed_payload;
    sign_inputs.aad            = aad;

    signer = me->signers;

    if(message_type_tag_number == CBOR_TAG_COSE_SIGN1) {
        /* --- Single signature for COSE_Sign1 --- */

        /* This calls the signer object to output the signature bytes
         * as a byte string to the CBOR encode context.
         */
        return_value = signer->sign1_cb(signer, &sign_inputs, cbor_encoder);
        if(return_value != T_COSE_SUCCESS) {
            if(return_value == T_COSE_ERR_SIG_IN_PROGRESS) {
                me->started = true;
            }
            goto Done;
        }

    } else {
#ifndef T_COSE_DISABLE_COSE_SIGN
        /* --- One or more COSE_Signatures for COSE_Sign --- */

        /* Output the arrray of signers, each of which is an array of
         * headers and signature. The surrounding array is handled
         * here.
         */
        return_value = T_COSE_ERR_NO_SIGNERS;
        QCBOREncode_OpenArray(cbor_encoder);
        while(signer != NULL) {
            return_value = signer->sign_cb(signer, &sign_inputs, cbor_encoder);
            if(return_value != T_COSE_SUCCESS) {
                return return_value;;
            }
            signer = (struct t_cose_signature_sign *)signer->rs.next;
        }
        QCBOREncode_CloseArray(cbor_encoder);
#else
        return_value = T_COSE_ERR_UNSUPPORTED;
#endif /* !T_COSE_DISABLE_COSE_SIGN */
    }


    /* --- Close out the array-of-four --- */
    QCBOREncode_CloseArray(cbor_encoder);

    /* The layer above this must check for and handle CBOR encoding
     * errors.  Some are detected at the start of this function, but
     * they cannot all be deteced there.
     */
Done:
    return return_value;
}


/*
 * Semi-private function. See t_cose_sign_sign.h
 */
enum t_cose_err_t
t_cose_sign_sign_private(struct t_cose_sign_sign_ctx *me,
                         bool                         payload_is_detached,
                         struct q_useful_buf_c        payload,
                         struct q_useful_buf_c        aad,
                         struct q_useful_buf          out_buf,
                         struct q_useful_buf_c       *result)
{
    QCBOREncodeContext cbor_encoder;
    enum t_cose_err_t  return_value;

    /* --- Initialize CBOR encoder context with output buffer --- */
    QCBOREncode_Init(&cbor_encoder, out_buf);

    /* --- Output the header parameters into the encoder context --- */
    return_value = t_cose_sign_encode_start(me, &cbor_encoder);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(payload_is_detached) {
        /* --- Output NULL for the payload --- */
        /* In detached content mode, the output COSE message does not
         * contain the payload. It is delivered in another channel.
         */
        QCBOREncode_AddNULL(&cbor_encoder);
    } else {
        /* --- Output the payload into the encoder context --- */
        /* Payload may or may not actually be CBOR format here. This
         * function does the job just fine because it just adds bytes
         * to the encoded output without anything extra.
         */

        QCBOREncode_AddBytes(&cbor_encoder, payload);
    }

    return_value = t_cose_sign_encode_finish(me,
                                             aad,
                                             payload,
                                            &cbor_encoder);
    if(return_value) {
        goto Done;
    }

    /* --- Close off and get the resulting encoded CBOR --- */
    if(QCBOREncode_Finish(&cbor_encoder, result)) {
        return_value = T_COSE_ERR_CBOR_FORMATTING;
        goto Done;
    }

Done:
    return return_value;
}
