/*
 * t_cose_sign_verify.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_sign_verify.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_key.h"
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


/* These error do not stop the calling of the further verifiers for
 * a given COSE_Signature.
 */
static bool
is_soft_verify_error(enum t_cose_err_t error)
{
    switch(error) {
        case T_COSE_ERR_UNSUPPORTED_SIGNING_ALG:
        case T_COSE_ERR_KID_UNMATCHED:
        case T_COSE_ERR_UNSUPPORTED_HASH:
        case T_COSE_ERR_DECLINE:
            return true;
        default:
            return false;
    }
}


enum sig_summary_error {
    VERIFY_ONE_SUCCESS,
    VERIFY_ONE_END_OF_SIGNATURES,
    VERIFY_ONE_UNABLE_TO_DECODE,
    VERIFY_ONE_DECLINE, /* algorithm or kid mismatch or other  */
    VERIFY_ONE_FAIL, /* The algorithm, kid and such matched and the actual verification of bytes via
                  crypto failed. */
};

/* It is assumed the compiler will inline this since it is called
 * only once. Makes the large number of parameters not so
 * bad. This is a seperate function for code readability. */
static enum sig_summary_error
verify_one_signature(struct t_cose_sign_verify_ctx       *me,
                     const struct t_cose_header_location  header_location,
                     struct t_cose_sign_inputs           *sign_inputs,
                     QCBORDecodeContext                  *qcbor_decoder,
                     struct t_cose_parameter            **decoded_sig_parameter_list,
                     enum t_cose_err_t                   *error_code)
{
    struct t_cose_signature_verify *verifier;

#ifdef QCBOR_FOR_T_COSE_2
    SaveDecodeCursor saved_cursor;

    QCBORDecode_SaveCursor(qcbor_decoder, &saved_cursor);
#endif

    for(verifier = me->verifiers; verifier != NULL; verifier = (struct t_cose_signature_verify *)verifier->rs.next) {
        *error_code = verifier->verify_cb(verifier,
                                           me->option_flags,
                                           header_location,
                                           sign_inputs,
                                           me->p_storage,
                                           qcbor_decoder,
                                           decoded_sig_parameter_list);
        if(*error_code == T_COSE_SUCCESS) {
            /* If here, then the decode was a success, the crypto
             * verified, and the signature CBOR was consumed. Nothing
             * to do but leave */
            return VERIFY_ONE_SUCCESS;
        }

        if(*error_code == T_COSE_ERR_NO_MORE) {
            return VERIFY_ONE_END_OF_SIGNATURES;
        }

        /* Remember the last verifier that failed. */
        me->last_verifier = verifier;

        if(*error_code == T_COSE_ERR_SIG_VERIFY) {
            /* The verifier was for the right algorithm and the
             * key was the right kid and such, but the actual
             * crypto failed to verify the bytes. In most
             * cases the caller will want to fail the whole
             * thing if this happens.
             */
            return VERIFY_ONE_FAIL;
        }


        if(!is_soft_verify_error(*error_code)) {
            /* Something is very wrong. Need to abort the entire
             * COSE mesage. */
            return VERIFY_ONE_UNABLE_TO_DECODE;
        }

        /* Go on to the next signature */
#ifdef QCBOR_FOR_T_COSE_2
        QCBORDecode_RestoreCursor(qcbor_decoder, &saved_cursor);
#else
        *error_code = T_COSE_ERR_CANT_PROCESS_MULTIPLE;
        return VERIFY_ONE_UNABLE_TO_DECODE;
#endif
    }

    /* Got to the end of the list without success. The last
     * verifier called will have consumed the CBOR for the
     * signature. We arrive here because there was no
     * verifier for the algorithm or the kid for the verification key
     * didn't match any of the signatures or general decline failure. */
    return VERIFY_ONE_DECLINE;
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
    struct q_useful_buf_c           signature;
    QCBORError                      qcbor_error;
    struct t_cose_signature_verify *verifier;
    struct t_cose_header_location   header_location;
    struct t_cose_parameter        *decoded_body_parameter_list;
    struct t_cose_parameter        *decoded_sig_parameter_list;
    struct t_cose_sign_inputs       sign_inputs;
    enum sig_summary_error          s_s_e;

    /* --- Decoding of the array of four starts here --- */
    QCBORDecode_Init(&decode_context, message, QCBOR_DECODE_MODE_NORMAL);

    /* --- The array of 4 and tags --- */
    QCBORDecode_EnterArray(&decode_context, NULL);
    if(QCBORDecode_GetError(&decode_context)) {
        return_value = T_COSE_SUCCESS; /* Needed to quiet warnings about lack of initialization even though it will get set below. The compiler doesn't know about QCBOR internal error state */
        goto Done3;
    }

    return_value = process_tags(me, &decode_context);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    /* --- The header parameters --- */
    /* The location of body header parameters is 0, 0 */
    header_location.nesting = 0;
    header_location.index   = 0;

    return_value = t_cose_headers_decode(&decode_context,
                                          header_location,
                                          me->param_decode_cb,
                                          me->param_decode_cb_context,
                                          me->p_storage,
                                         &decoded_body_parameter_list,
                                         &protected_parameters);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    /* --- The payload --- */
    if(is_detached) {
        QCBORDecode_GetNull(&decode_context);
        /* In detached content mode, the payload should be set by
         * function caller, so there is no need to set the payload.
         */
    } else {
        QCBORDecode_GetByteString(&decode_context, payload);
    }


    /* --- The signature or the COSE_Signature(s) --- */
    if(me->verifiers == NULL) {
        return T_COSE_ERR_NO_VERIFIERS;
    }
    sign_inputs.body_protected = protected_parameters;
    sign_inputs.sign_protected = NULL_Q_USEFUL_BUF_C;
    sign_inputs.aad            = aad;
    sign_inputs.payload        = *payload;
    // TODO: allow tag determination
    if(T_COSE_OPT_IS_SIGN1(me->option_flags)) {
        /* --- The signature bytes for a COSE_Sign1, not COSE_Signatures */
        QCBORDecode_GetByteString(&decode_context, &signature);
        if(QCBORDecode_GetError(&decode_context)) {
            goto Done3;
        }

        /* Loop over all the verifiers configured asking each
         * to verify until one succeeds. If none succeeded, the error
         * returned is from the last one called.
         */
        for(verifier = me->verifiers; verifier != NULL; verifier = (struct t_cose_signature_verify *)verifier->rs.next) {
            /* Call the verifyer to attempt a verification. It
             * will compute the tbs and try to run the crypto.
             */
            return_value = verifier->verify1_cb(verifier,
                                                me->option_flags,
                                               &sign_inputs,
                                                decoded_body_parameter_list,
                                                signature);
            if(return_value == T_COSE_SUCCESS) {
                break;
            }
            if(!is_soft_verify_error(return_value)) {
                /* An error like a decode error or a signature verification failure. */
                break;
            }

            /* Algorithm or kid didn't match or verifier declined, continue
             * trying other verifiers.
             */
        }

    } else {
        /* --- An array of COSE_Signatures --- */
        QCBORDecode_EnterArray(&decode_context, NULL);
        if(QCBORDecode_GetError(&decode_context)) {
            /* Not strictly necessary, but very helpful for error reporting. */
            goto Done3;
        }

        /* Nesting level is 1, index starts at 0 and gets incremented */
        header_location = (struct t_cose_header_location){.nesting = 1,
                                                          .index   = 0 };

        while(1) { /* loop over COSE_Signatures */
            header_location.index++;
            enum t_cose_err_t      sig_error_code;

            sig_error_code = 0; // Stops complaints of lack of initalization (are they true??)

            s_s_e = verify_one_signature(me,
                                         header_location,
                                         &sign_inputs,
                                         &decode_context,
                                         &decoded_sig_parameter_list,
                                         &sig_error_code);

            if(s_s_e == VERIFY_ONE_UNABLE_TO_DECODE || s_s_e == VERIFY_ONE_FAIL) {
                /* Exit entire message decode with failure */
                return_value = sig_error_code;
                goto Done;
            }
            if(s_s_e == VERIFY_ONE_END_OF_SIGNATURES) {
                break;
            }
            /* Now what's left is a success or decline */

            if(s_s_e == VERIFY_ONE_SUCCESS) {
                if(decoded_body_parameter_list == NULL) {
                    decoded_body_parameter_list = decoded_sig_parameter_list;
                } else {
                    t_cose_parameter_list_append(decoded_body_parameter_list,
                                                 decoded_sig_parameter_list);
                }
            }

            if(me->option_flags & T_COSE_VERIFY_ALL_SIGNATURES) {
                if(s_s_e == VERIFY_ONE_DECLINE) {
                    /* When verifying all, there can be no declines */
                    return_value = sig_error_code;
                    goto Done;
                } else {
                    /* success. Continue on to be sure the rest succeed. */
                }
            } else {
                if(s_s_e == VERIFY_ONE_SUCCESS) {
                    /* Just one success is enough to complete.*/
                    break;
                } else {
                    /* decline. Continue to try other COSE_Signatures. */
                }
            }
        }

        QCBORDecode_ExitArray(&decode_context);
    }


    /* --- Finish up the CBOR decode --- */
    QCBORDecode_ExitArray(&decode_context);

    if(returned_parameters != NULL) {
        *returned_parameters = decoded_body_parameter_list;
    }

Done3:
    /* This check make sure the array only had the expected four
     * items. It works for definite and indefinte length arrays. Also
     * makes sure there were no extra bytes. Also maps the error code
     * for other decode errors detected above. */
    qcbor_error = QCBORDecode_Finish(&decode_context);
    if(qcbor_error == QCBOR_ERR_NO_MORE_ITEMS) {
        // TODO: a bit worried whether this is the right thing to do
        goto Done;
    }
    if(qcbor_error != QCBOR_SUCCESS) {
        /* A decode error overrides other errors. */
        return_value = qcbor_decode_error_to_t_cose_error(qcbor_error,
                                                      T_COSE_ERR_SIGN1_FORMAT);
    }
    /* --- End of the decoding of the array of four --- */

Done:
    return return_value;
}
