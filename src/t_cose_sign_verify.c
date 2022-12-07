/*
 * t_cose_sign_verify.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "qcbor/qcbor_decode.h"
#ifndef QCBOR_SPIFFY_DECODE
#error This t_cose requires a version of QCBOR that supports spiffy decode
#endif
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_sign_verify.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_signature_verify.h"
#include "t_cose_util.h"

/* Warning: this is still early development. Documentation may be incorrect.*/


/**
 * \file t_cose_sign_verify.c
 *
 * \brief \c COSE_Sign and \c COSE_Sign1 verification implementation.
 */


/**
 * \brief Check the tagging of the COSE about to be verified.
 *
 * \param[in] me                 The verification context.
 * \param[in] decode_context     The decoder context to pull from.
 *
 * \return This returns one of the error codes defined by \ref
 *         t_cose_err_t.
 *
 * This must be called after decoding the opening array of four that
 * starts all COSE message that is the item that is the content of the
 * tags.
 *
 * This checks that the tag usage is as requested by the caller.
 *
 * This returns any tags that enclose the COSE message for processing
 * at the level above COSE.
 */
static inline enum t_cose_err_t
process_tags(struct t_cose_sign_verify_ctx *me,
             QCBORDecodeContext *decode_context)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    20          16
     *   TOTAL                                         20          16
     */
    uint64_t uTag;
    uint32_t item_tag_index = 0;
    int returned_tag_index;

    /* The 0th tag is the only one that might identify the type of the
     * CBOR we are trying to decode so it is handled special.
     */
    uTag = QCBORDecode_GetNthTagOfLast(decode_context, item_tag_index);
    item_tag_index++;
    if(me->option_flags & T_COSE_OPT_TAG_REQUIRED) {
        /* The protocol that is using COSE says the input CBOR must
         * be a COSE tag.
         */
        if(uTag != CBOR_TAG_COSE_SIGN1) {
            return T_COSE_ERR_INCORRECTLY_TAGGED;
        }
    }
    if(me->option_flags & T_COSE_OPT_TAG_PROHIBITED) {
        /* The protocol that is using COSE says the input CBOR must
         * not be a COSE tag.
         */
        if(uTag == CBOR_TAG_COSE_SIGN1) {
            return T_COSE_ERR_INCORRECTLY_TAGGED;
        }
    }
    /* If the protocol using COSE doesn't say one way or another about the
     * tag, then either is OK.
     */


    /* Initialize auTags, the returned tags, to CBOR_TAG_INVALID64 */
#if CBOR_TAG_INVALID64 != 0xffffffffffffffff
#error Initializing return tags array
#endif
    memset(me->auTags, 0xff, sizeof(me->auTags));

    returned_tag_index = 0;

    if(uTag != CBOR_TAG_COSE_SIGN1) {
        /* Never return the tag that this code is about to process. Note
         * that you can sign a COSE_SIGN1 recursively. This only takes out
         * the one tag layer that is processed here.
         */
        me->auTags[returned_tag_index] = uTag;
        returned_tag_index++;
    }

    while(1) {
        uTag = QCBORDecode_GetNthTagOfLast(decode_context, item_tag_index);
        item_tag_index++;
        if(uTag == CBOR_TAG_INVALID64) {
            break;
        }
        if(returned_tag_index > T_COSE_MAX_TAGS_TO_RETURN) {
            return T_COSE_ERR_TOO_MANY_TAGS;
        }
        me->auTags[returned_tag_index] = uTag;
        returned_tag_index++;
    }

    return T_COSE_SUCCESS;
}

/* No error stops the calling of further verifiers, but soft verify errors are never returned to the caller.*/
static bool
is_soft_verify_error(enum t_cose_err_t error)
{
    switch(error) {
        case T_COSE_ERR_UNSUPPORTED_SIGNING_ALG:
        case T_COSE_ERR_KID_UNMATCHED:
        case T_COSE_ERR_UNSUPPORTED_HASH:
            return true;
        default:
            return false;
    }
}


/*
 * A semi-private function. See t_cose_sign_verify.h
 */
enum t_cose_err_t
t_cose_sign_verify_private(struct t_cose_sign_verify_ctx  *me,
                           struct q_useful_buf_c           message,
                           struct q_useful_buf_c           aad,
                           struct q_useful_buf_c          *payload,
                           struct t_cose_parameter       **returned_parameters,
                           bool                            is_detached)
{
    QCBORDecodeContext              decode_context;
    struct q_useful_buf_c           protected_parameters;
    enum t_cose_err_t               return_value;
    enum t_cose_err_t               verify_error;
    struct q_useful_buf_c           signature;
    QCBORError                      qcbor_error;
    struct t_cose_signature_verify *verifier;
    struct t_cose_header_location   header_location;
    QCBORItem                       null_payload;
    struct t_cose_parameter        *decoded_body_parameter_list;
    struct t_cose_parameter        *decoded_sig_parameter_list;
    struct t_cose_sign_inputs       sign_inputs;


    /* --- Decoding of the array of four starts here --- */
    QCBORDecode_Init(&decode_context, message, QCBOR_DECODE_MODE_NORMAL);

    /* --- The array of 4 and tags --- */
    QCBORDecode_EnterArray(&decode_context, NULL);
    return_value = qcbor_decode_error_to_t_cose_error(QCBORDecode_GetError(&decode_context),
                                                      T_COSE_ERR_SIGN1_FORMAT);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    return_value = process_tags(me, &decode_context);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    /* --- The header parameters --- */
    /* The location of body header parameters is 0, 0 */
    header_location = (struct t_cose_header_location){.nesting = 0,
                                                      .index = 0};

    return_value = t_cose_headers_decode(&decode_context,
                                          header_location,
                                          me->reader,
                                          me->reader_ctx,
                                          me->p_storage,
                                         &decoded_body_parameter_list,
                                         &protected_parameters);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    /* --- The payload --- */
    if(is_detached) {
        QCBORDecode_GetNext(&decode_context, &null_payload);
        /* If there is a decode error here, null_payload.uDataType will be
         * QCBOR_TYPE_NONE
         */
        if (null_payload.uDataType != QCBOR_TYPE_NULL) {
            return_value = T_COSE_ERR_SIGN1_FORMAT;
            goto Done;
        }
        /* In detached content mode, the payload should be set by
         * function caller, so there is no need to set the payload.
         */
    } else {
        QCBORDecode_GetByteString(&decode_context, payload);
    }


    /* --- The signature or the COSE_Signature(s) --- */
    sign_inputs.body_protected = protected_parameters;
    sign_inputs.sign_protected = NULL_Q_USEFUL_BUF_C;
    sign_inputs.aad            = aad;
    sign_inputs.payload        = *payload;
    // TODO: allow tag determination
    if(T_COSE_OPT_IS_SIGN1(me->option_flags)) {
        /* --- The signature bytes for a COSE_Sign1, not COSE_Signatures */
        QCBORDecode_GetByteString(&decode_context, &signature);
        return_value = qcbor_decode_error_to_t_cose_error(QCBORDecode_GetError(&decode_context),
                                                    T_COSE_ERR_SIGN1_FORMAT);
        if(return_value != T_COSE_SUCCESS) {
            goto Done;
        }

        /* Loop over all the verifiers configured asking each
         * to verify until one succeeds. If none succeeded, the error
         * returned is from the last one called.  There are
         * intentionally no types of errors that one verifier can return
         * that ends the whole loop and blocks others from being called.
         */
        verify_error = T_COSE_ERR_NO_VERIFIERS;
        for(verifier = me->verifiers; verifier != NULL; verifier = verifier->next_in_list) {
            /* Actually do the signature verification by calling
             * the main method of the cose_signature_verify. This
             * will compute the tbs value and call the crypto.
             */
            verify_error = verifier->callback1(verifier,
                                               me->option_flags,
                                              &sign_inputs,
                                               decoded_body_parameter_list,
                                               signature);
            if(verify_error == T_COSE_SUCCESS) {
                break;
            }
            if(!is_soft_verify_error(verify_error)) {
                return_value = verify_error;
            }
        }
        if(return_value == T_COSE_SUCCESS && verify_error != T_COSE_SUCCESS) {
            /* Only a soft verification error occured. It is still an
             * error, not success, so it has to be returned. */
            return_value = verify_error;
        }

    } else {
        /* --- An array of COSE_Signatures --- */
        QCBORDecode_EnterArray(&decode_context, NULL);
        verifier = me->verifiers;
        /* Nesting level is 1, index starts at 0 and gets incremented */
        header_location = (struct t_cose_header_location){.nesting = 1,
                                                          .index   = 0 };
        while(1) { /* loop over COSE_Signatures */
            header_location.index++;

            // TODO: right now this doesn't work in some cases because
            // The signature verifier can't rewind the QCBOR decoder to
            // let the next verifier have a shot at it.  So just testing
            // with one signature for now...
            for(verifier = me->verifiers; verifier != NULL; verifier = verifier->next_in_list) {

                /* This call decodes one array entry containing a
                 * COSE_Signature. */
                return_value = verifier->callback(verifier,
                                                  me->option_flags,
                                                  header_location,
                                                  &sign_inputs,
                                                  me->p_storage,
                                                 &decode_context,
                                                 &decoded_sig_parameter_list);

                // TODO: this may not be in the right place
                t_cose_parameter_list_append(decoded_body_parameter_list,
                                             decoded_sig_parameter_list);

                if(return_value == T_COSE_SUCCESS) {
                     // TODO: correct flag value
                    if(me->option_flags & T_COSE_VERIFY_ALL) {
                        continue;
                    } else {
                        break; /* success. Don't need to try another verifier*/
                    }
#ifdef TODO_FIXME_MULTISIG
                } else if(return_value == 98) {
                    continue; /* Didn't know how to decode, try another  */
                } else if(return_value == 88) {
                    goto done_with_sigs;/* No more COSE_Signatures to be read*/
#endif
                } else {
                    goto Done2;
                }
            }
        }
#ifdef TODO_FIXME_MULTISIG
     done_with_sigs:
        QCBORDecode_ExitArray(&decode_context);
#endif
    }

    /* --- Finish up the CBOR decode --- */
    QCBORDecode_ExitArray(&decode_context);

    /* This check make sure the array only had the expected four
     * items. It works for definite and indefinte length arrays. Also
     * makes sure there were no extra bytes. Also that the payload
     * and signature were decoded correctly. */
    qcbor_error = QCBORDecode_Finish(&decode_context);
    if(qcbor_error != QCBOR_SUCCESS) {
        /* A decode error overrides other errors. */
        return_value = qcbor_decode_error_to_t_cose_error(qcbor_error,
                                                      T_COSE_ERR_SIGN1_FORMAT);
    }
    /* --- End of the decoding of the array of four --- */

Done2:
    if(returned_parameters != NULL) {
        *returned_parameters = decoded_body_parameter_list;
    }

Done:
    return return_value;
}


/*
 * Public function. See t_cose_sign_sign.h
 */
void
t_cose_sign_add_verifier(struct t_cose_sign_verify_ctx  *me,
                         struct t_cose_signature_verify *verifier)
{
    // TODO: for COSE_Sign1 this can be tiny and inline fo DISABLE_COSE_SIGN
    if(me->verifiers == NULL) {
        me->verifiers = verifier;
    } else {
        struct t_cose_signature_verify *t;
        for(t = me->verifiers; t->next_in_list != NULL; t = t->next_in_list);
        t->next_in_list = verifier;
    }
}
