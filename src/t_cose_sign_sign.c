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
#include "t_cose_standard_constants.h"
#include "t_cose_crypto.h"
#include "t_cose_util.h"
#include "t_cose/t_cose_signature_sign.h"
#include "t_cose/t_cose_parameters.h"
/**
 * \file t_cose_sign_sign.c
 *
 * \brief This implements t_cose signing
 *
 * Stack usage to sign is dependent on the signing alg and key size
 * and type of hash implementation. t_cose_sign1_finish() is the main
 * user of stack It is 384 for \ref COSE_ALGORITHM_ES256 and 778 for
 * \ref COSE_ALGORITHM_ES512.
 */


/*
 * Semi-private function. See t_cose_sign_sign.h
 */
enum t_cose_err_t
t_cose_sign_encode_first_part(struct t_cose_sign_sign_ctx *me,
                              bool                         payload_is_detached,
                              QCBOREncodeContext          *cbor_encode_ctx)
{
    enum t_cose_err_t                 return_value;
    const struct t_cose_header_param *params_vector[3];
    int                               vector_index;
    struct t_cose_signature_sign     *signer;

    signer = me->signers;
    if(signer == NULL) {
        /* No signers configured. */
        return_value = 888;
        goto Done;
    }

    vector_index = 0;
    if(me->option_flags & T_COSE_OPT_COSE_SIGN1) {

        /* For a COSE_Sign1, the header parameters go in the
         * main body header parameter section, not in the
         * signatures. Ask the first sigher for the header
         * parameters it wants to output. */
        (signer->h_callback)(signer, &params_vector[0]);
        vector_index++;
        if(signer->next_in_list != NULL) {
            /* In COSE_Sign1 mode, but too many signers configured.*/
            return_value = 999;
            goto Done;
        }
    }
    params_vector[vector_index] = me->added_body_parameters;
    vector_index++;
    params_vector[vector_index] = NULL;
    /* --- parameters are now all in params_vector -- */


    /* --- Add the CBOR tag indicating COSE_Sign1 --- */
    if(!(me->option_flags & T_COSE_OPT_OMIT_CBOR_TAG)) {
        QCBOREncode_AddTag(cbor_encode_ctx, CBOR_TAG_COSE_SIGN1);
    }

    /* --- Open array-of-four that holds all signing messages --- */
    QCBOREncode_OpenArray(cbor_encode_ctx);


    /* --- Encode both proteced and unprotected headers --- */
    return_value = t_cose_encode_headers(cbor_encode_ctx,
                                         params_vector,
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
 * Semi-private function. See t_cose_sign_sign.h
 */
enum t_cose_err_t
t_cose_sign_encode_second_part(struct t_cose_sign_sign_ctx *me,
                               struct q_useful_buf_c         aad,
                               struct q_useful_buf_c         detached_payload,
                               QCBOREncodeContext           *cbor_encode_ctx)
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


    /* --- Create the signature --- */
    /* TODO: this comment is wrong. Compute the signature using public key crypto. The key and
     * algorithm ID are passed in to know how and what to sign
     * with. The hash of the TBS bytes is what is signed. A buffer
     * in which to place the signature is passed in and the
     * signature is returned.
     *
     * That or just compute the length of the signature if this
     * is only an output length computation.
     */
    signer = me->signers;
    if(!(me->option_flags & T_COSE_OPT_COSE_SIGN1)) {
        /* What is needed here is to output an arrray of signers, each
         * of which is an array of Headers and signature. The surrounding
         * array is handed here.
         */
        return_value = 888; // TODO: error code for no signers
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
                      struct q_useful_buf_c         payload,
                      struct q_useful_buf_c         aad,
                      struct q_useful_buf           out_buf,
                      struct q_useful_buf_c        *result)
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
    QCBOREncodeContext  encode_context;
    enum t_cose_err_t   return_value;

    /* -- Initialize CBOR encoder context with output buffer -- */
    QCBOREncode_Init(&encode_context, out_buf);

    /* -- Output the header parameters into the encoder context -- */
    return_value = t_cose_sign_encode_first_part(me,
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
    return_value = t_cose_sign_encode_second_part(me,
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

