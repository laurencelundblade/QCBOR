/*
 * t_cose_sign_sign.c
 *
 * Copyright (c) 2018-2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_sign_sign.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_parameters.h"


/**
 * \file t_cose_sign_sign.c
 *
 * \brief This implements creation of COSE_Sign and COSE_Sign1 messages.
 *
 * This relies on instances of t_cose_signature_sign to create the
 * actual signatures. The work done here is encoding the message with
 * the headers, payload and signature(s).
 *
 */


/*
 * Pubilc Function. See t_cose_sign_sign.h
 */
enum t_cose_err_t
t_cose_sign_encode_start(struct t_cose_sign_sign_ctx *me,
                         bool                         payload_is_detached,
                         QCBOREncodeContext          *cbor_encode_ctx)
{
    enum t_cose_err_t              return_value;
    struct t_cose_signature_sign  *signer;
    struct t_cose_parameter       *sign1_parameters;
    struct t_cose_parameter       *body_parameters;
    uint64_t                       message_type_tag_number;

    /* There must be at least one signer configured (a signer is an
     * object, a callback and context, that makes a signature). See
     * struct t_cose_signature_sign. Here the signer object is
     * expected to be configured with the key material and such.
     */
    signer = me->signers;
    if(signer == NULL) {
        /* No signers configured. */
        return_value = T_COSE_ERR_NO_SIGNERS;
        goto Done;
    }

    /* --- Is this COSE_Sign or COSE_Sign1? --- */
    message_type_tag_number = me->option_flags & T_COSE_OPT_MESSAGE_TYPE_MASK;

    /* --- Make list of the body header parameters --- */
    sign1_parameters = NULL;
    if(message_type_tag_number == CBOR_TAG_COSE_SIGN1) {
        /* For a COSE_Sign1, the header parameters go in the main body
         * header parameter section, and the signatures part just
         * contains a raw signature bytes, not an array of
         * COSE_Signature. This gets the parameters from the
         * signer. */
        signer->headers_cb(signer, &sign1_parameters);
        if(signer->rs.next != NULL) {
            /* In COSE_Sign1 mode, but too many signers configured.*/
            return_value = T_COSE_ERR_TOO_MANY_SIGNERS;
            goto Done;
        }
    }

    /* Form up the full list of body header parameters which may
     * include the COSE_Sign1 algorithm ID and kid. It may also
     * include the caller-added parameters like content type. */
    if(sign1_parameters == NULL) {
        body_parameters = me->added_body_parameters;
    } else {
        body_parameters = sign1_parameters;
        t_cose_parameter_list_append(body_parameters, me->added_body_parameters);
    }

    /* --- Add the CBOR tag indicating COSE message type --- */
    if(!(me->option_flags & T_COSE_OPT_OMIT_CBOR_TAG)) {
        QCBOREncode_AddTag(cbor_encode_ctx, message_type_tag_number);
    }

    /* --- Open array-of-four that holds all COSE_Sign(1) messages --- */
    QCBOREncode_OpenArray(cbor_encode_ctx);


    /* --- Encode both protected and unprotected headers --- */
    return_value = t_cose_encode_headers(cbor_encode_ctx,
                                         body_parameters,
                                         &me->protected_parameters);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --- Get started on the payload --- */
    if(!payload_is_detached) {
        /* The caller will encode the payload directly into the
         * QCBOREncoder. It is byte-string wrapped so, open the
         * wrapping. If the payload is detached, then it is sent
         * separately and there is nothing to do.
         */
        QCBOREncode_BstrWrap(cbor_encode_ctx);
    }

    /* Failures in CBOR encoding will be caught in
     * t_cose_sign_encode_finish() or other. No need to track here as the QCBOR
     * encoder tracks them internally.
     */

Done:
    return return_value;
}


/*
 * Pubilc Function. See t_cose_sign_sign.h
 */
enum t_cose_err_t
t_cose_sign_encode_finish(struct t_cose_sign_sign_ctx *me,
                          struct q_useful_buf_c        aad,
                          struct q_useful_buf_c        detached_payload,
                          QCBOREncodeContext          *cbor_encode_ctx)
{
    enum t_cose_err_t             return_value;
    QCBORError                    cbor_err;
    struct q_useful_buf_c         signed_payload;
    struct t_cose_signature_sign *signer;
    struct t_cose_sign_inputs     sign_inputs;

    /* --- Close off the payload --- */
    if(q_useful_buf_c_is_null(detached_payload)) {
        /* Payload is inline, not detached */
        QCBOREncode_CloseBstrWrap2(cbor_encode_ctx, false, &signed_payload);
    } else {
        signed_payload = detached_payload;
    }


    /* --- Early error check --- */
    /* Check that there are no CBOR encoding errors before proceeding
     * with hashing and signing. This is not actually necessary as the
     * errors will be caught correctly later, but it does make it a
     * bit easier for the caller to debug problems.
     */
    cbor_err = QCBOREncode_GetErrorState(cbor_encode_ctx);
    if(cbor_err == QCBOR_ERR_BUFFER_TOO_SMALL) {
        return_value = T_COSE_ERR_TOO_SMALL;
        goto Done;
    } else if(cbor_err != QCBOR_SUCCESS) {
        return_value = T_COSE_ERR_CBOR_FORMATTING;
        goto Done;
    }


    /* --- Signature for COSE_Sign1 or signatures for COSE_Sign --- */
    sign_inputs.body_protected = me->protected_parameters;
    sign_inputs.sign_protected = NULL_Q_USEFUL_BUF_C; /* filled in by sign_cb */
    sign_inputs.payload        = signed_payload;
    sign_inputs.aad            = aad;

    signer = me->signers;

    if(T_COSE_OPT_IS_SIGN(me->option_flags)) {
        /* --- One or more COSE_Signatures for COSE_Sign --- */

        /* Output the arrray of signers, each of which is an array of
         * Headers and signature. The surrounding array is handled here.
         */
        return_value = T_COSE_ERR_NO_SIGNERS;
        QCBOREncode_OpenArray(cbor_encode_ctx);
        while(signer != NULL) {
            return_value = signer->sign_cb(signer, &sign_inputs, cbor_encode_ctx);
            if(return_value != T_COSE_SUCCESS) {
                goto Done;
            }
            signer = (struct t_cose_signature_sign *)signer->rs.next;
        }
        QCBOREncode_CloseArray(cbor_encode_ctx);

    } else {
        /* --- Single signature for COSE_Sign1 --- */

        /* This calls the signer object to output the signature bytes
         * as a byte string to the CBOR encode context.
         */
        return_value = signer->sign1_cb(signer, &sign_inputs, cbor_encode_ctx);
    }
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    /* --- Close out the array-of-four --- */
    QCBOREncode_CloseArray(cbor_encode_ctx);

    /* The layer above this must check for and handle CBOR encoding
     * errors.  Some are detected at the start of
     * this function, but they cannot all be deteced there.
     */
Done:
    return return_value;
}


/*
 * Semi-private function. See t_cose_sign_sign.h
 */
enum t_cose_err_t
t_cose_sign_one_shot(struct t_cose_sign_sign_ctx *me,
                     bool                         payload_is_detached,
                     struct q_useful_buf_c        payload,
                     struct q_useful_buf_c        aad,
                     struct q_useful_buf          out_buf,
                     struct q_useful_buf_c       *result)
{
    QCBOREncodeContext encode_context;
    enum t_cose_err_t  return_value;

    /* --- Initialize CBOR encoder context with output buffer --- */
    QCBOREncode_Init(&encode_context, out_buf);

    /* --- Output the header parameters into the encoder context --- */
    return_value = t_cose_sign_encode_start(me,
                                            payload_is_detached,
                                           &encode_context);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(payload_is_detached) {
        /* --- Output NULL for the payload --- */
        /* In detached content mode, the output COSE message does not
         * contain the payload. It is delivered in another channel.
         */
        QCBOREncode_AddNULL(&encode_context);
    } else {
        /* --- Output the payload into the encoder context --- */
        /* Payload may or may not actually be CBOR format here. This
         * function does the job just fine because it just adds bytes
         * to the encoded output without anything extra.
         */
        QCBOREncode_AddEncoded(&encode_context, payload);
    }

    /* --- Sign and output signature to the encoder context --- */
    if(!payload_is_detached) {
        // TODO: combine with above?
        payload = NULL_Q_USEFUL_BUF_C;
    }
    return_value = t_cose_sign_encode_finish(me,
                                             aad,
                                             payload,
                                            &encode_context);
    if(return_value) {
        goto Done;
    }

    /* --- Close off and get the resulting encoded CBOR --- */
    if(QCBOREncode_Finish(&encode_context, result)) {
        return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }

Done:
    return return_value;
}

