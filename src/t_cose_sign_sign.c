/*
 * t_cose_sign_sign.c
 *
 * Copyright (c) 2018-2022, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/t_cose_sign_sign.h"
#include "qcbor/qcbor.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_parameters.h"


/**
 * \file t_cose_sign_sign.c
 *
 * \brief This implements t_cose signing
 *
 * Stack usage to sign is dependent on the signing alg and key size
 * and type of hash implementation. t_cose_sign1_finish() is the main
 * user of stack It is 384 for \ref T_COSE_ALGORITHM_ES256 and 778 for
 * \ref T_COSE_ALGORITHM_ES512.
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

    signer = me->signers;
    if(signer == NULL) {
        /* No signers configured. */
        return_value = T_COSE_ERR_NO_SIGNERS;
        goto Done;
    }

    sign1_parameters = NULL;
    if((me->option_flags & T_COSE_OPT_MESSAGE_TYPE_MASK) == T_COSE_OPT_MESSAGE_TYPE_SIGN1) {

        /* For a COSE_Sign1, the header parameters go in the
         * main body header parameter section, not in the
         * signatures. Ask the first sigher for the header
         * parameters it wants to output. */
        (signer->h_callback)(signer, &sign1_parameters);
        if(signer->next_in_list != NULL) {
            /* In COSE_Sign1 mode, but too many signers configured.*/
            return_value = T_COSE_ERR_TOO_MANY_SIGNERS;
            goto Done;
        }
    }

    if(sign1_parameters == NULL) {
        body_parameters = me->added_body_parameters;
    } else {
        body_parameters = sign1_parameters;
        t_cose_parameter_list_append(body_parameters, me->added_body_parameters);
    }

    /* --- parameters are now all in params_vector -- */


    /* --- Add the CBOR tag indicating COSE_Sign1 --- */
    if(!(me->option_flags & T_COSE_OPT_OMIT_CBOR_TAG)) {
        QCBOREncode_AddTag(cbor_encode_ctx, CBOR_TAG_COSE_SIGN1);
    }

    /* --- Open array-of-four that holds all signing messages --- */
    QCBOREncode_OpenArray(cbor_encode_ctx);


    /* --- Encode both proteced and unprotected headers --- */
    return_value = t_cose_encode_headers(cbor_encode_ctx,
                                         body_parameters,
                                         &me->protected_parameters);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --- Get started on the payload --- */
    if(!payload_is_detached) {
        QCBOREncode_BstrWrap(cbor_encode_ctx);
    }

    /* Any failures in CBOR encoding will be caught in finish when the
     * CBOR encoding is closed off. No need to track here as the CBOR
     * encoder tracks it internally.
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

    /* --- Close off the payload --- */
    if(q_useful_buf_c_is_null(detached_payload)) {
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


    /* --- Create the signature or signatures --- */
    signer = me->signers;
    if((me->option_flags & T_COSE_OPT_MESSAGE_TYPE_MASK) !=  T_COSE_OPT_MESSAGE_TYPE_SIGN1) {
        /* What is needed here is to output an arrray of signers, each
         * of which is an array of Headers and signature. The surrounding
         * array is handed here.
         */
        return_value = T_COSE_ERR_NO_SIGNERS;
        QCBOREncode_OpenArray(cbor_encode_ctx);
        while(signer != NULL) {
            return_value = (signer->callback)(signer,
                                              true,
                                              me->protected_parameters,
                                              signed_payload,
                                              aad,
                                              cbor_encode_ctx);
            if(return_value != T_COSE_SUCCESS) {
                goto Done;
            }
            signer = signer->next_in_list;
        }
        QCBOREncode_CloseArray(cbor_encode_ctx);

    } else {
        /* All that is needed here is to ouptput one signature bstr */
        return_value = (signer->callback)(signer,
                                          false,
                                          me->protected_parameters,
                                          signed_payload,
                                          aad,
                                          cbor_encode_ctx);
    }
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    /* --- Close out the array-of-four --- */
    QCBOREncode_CloseArray(cbor_encode_ctx);

    /* The layer above this must check for and handle CBOR encoding
     * errors CBOR encoding errors.  Some are detected at the start of
     * this function, but they cannot all be deteced there.
     */
Done:
    return return_value;
}


/*
 * Semi-private function. See t_cose_sign1_sign.h
 */
enum t_cose_err_t
t_cose_sign_one_short(struct t_cose_sign_sign_ctx *me,
                      bool                         payload_is_detached,
                      struct q_useful_buf_c        payload,
                      struct q_useful_buf_c        aad,
                      struct q_useful_buf          out_buf,
                      struct q_useful_buf_c       *result)
{
    // TODO: recompute
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                     8           4
     *   encode context                               168         148
     *   QCBOR   (guess)                               32          24
     *   max(encode_param, encode_signature)     224-1316    216-1024
     *   TOTAL                                   432-1524    392-1300
     */
    QCBOREncodeContext encode_context;
    enum t_cose_err_t  return_value;

    /* -- Initialize CBOR encoder context with output buffer -- */
    QCBOREncode_Init(&encode_context, out_buf);

    /* -- Output the header parameters into the encoder context -- */
    return_value = t_cose_sign_encode_start(me,
                                            payload_is_detached,
                                           &encode_context);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(payload_is_detached) {
        /* -- Output NULL for the payload -- */
        /* In detached content mode, the output COSE binary does not
         * contain the payload and it is be delivered
         * in another channel.
         */
        QCBOREncode_AddNULL(&encode_context);
    } else {
        /* -- Output the payload into the encoder context -- */
        /* Payload may or may not actually be CBOR format here. This
         * function does the job just fine because it just adds bytes to
         * the encoded output without anything extra.
         */
        QCBOREncode_AddEncoded(&encode_context, payload);
    }

    /* -- Sign and put signature in the encoder context -- */
    if(!payload_is_detached) {
        payload = NULL_Q_USEFUL_BUF_C;
    }
    return_value = t_cose_sign_encode_finish(me,
                                             aad,
                                             payload,
                                            &encode_context);
    if(return_value) {
        goto Done;
    }

    /* -- Close off and get the resulting encoded CBOR -- */
    if(QCBOREncode_Finish(&encode_context, result)) {
        return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }

Done:
    return return_value;
}


/*
* Public function. See t_cose_sign_sign.h
*/
void
t_cose_sign_add_signer(struct t_cose_sign_sign_ctx  *context,
                       struct t_cose_signature_sign *signer)
{
    // TODO: for COSE_Sign1 this can be tiny and inline

    if(context->signers == NULL) {
        context->signers = signer;
    } else {
        struct t_cose_signature_sign *t;
        for(t = context->signers; t->next_in_list != NULL; t = t->next_in_list);
        t->next_in_list = signer;
    }
}
