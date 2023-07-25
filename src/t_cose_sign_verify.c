/*
 * t_cose_sign_verify.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2023, Arm Limited. All rights reserved.
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
#include "t_cose_qcbor_gap.h"


/**
 * \file t_cose_sign_verify.c
 *
 * \brief \c COSE_Sign and \c COSE_Sign1 verification implementation.
 */




/* These error do not stop the calling of the further verifiers for
 * a given COSE_Signature.
 */
static bool
is_soft_verify_error(enum t_cose_err_t error)
{
    switch(error) {
        case T_COSE_ERR_UNSUPPORTED_SIGNING_ALG:
        case T_COSE_ERR_NO_ALG_ID:
        case T_COSE_ERR_KID_UNMATCHED:
        case T_COSE_ERR_UNSUPPORTED_HASH:
        case T_COSE_ERR_DECLINE:
            return true;
        default:
            return false;
    }
}


#ifndef T_COSE_DISABLE_COSE_SIGN


/* Return the number of parameters in a linked list of parameters. */
static int
count_params(const struct t_cose_parameter  *params)
{
    int count = 0;

    while(params != NULL) {
        count++;
        params = params->next;
    }

    return count;
}


static size_t
squeeze_nodes(struct t_cose_parameter *new_ones,
              struct t_cose_parameter *old_ones)
{
    struct t_cose_parameter *p1, *p2;

    p1 = old_ones;
    p2 = new_ones;

    if(p1 > p2) {
        /* Check to make cast from ptrdiff_t to size_t safe */
        return 0;
    }
    size_t num_squeezed = (size_t)(p2 - p1);

    while(1) {
        *p1 = *p2;
        if(p2->next == NULL) {
            break;
        }
        p1++;
        p2++;
    }

    return num_squeezed;
}



/*
 * The work of this is to call multiple verifiers on one
 * signature until one succeeds.


 It is assumed the compiler will inline this since it is called
 * only once. Makes the large number of parameters not so
 * bad. This is a seperate function for code readability.

 * This needs to add the decoded parameters once and only once even
 * though multiple verifiers are called on the same signature.

 * Different verifiers may do better or worse job of decoding
 * the parameters to be returned. In particular, some may
 * have special parameter decode callbacks and some may not.
 * Note also that success, declining or failure of a verifier
 * may or may not be an indication of how well parameter
 * decoding went.
 *
 * What happens here is that parameters decoded by the verifier
 * that decoded the most parameters will be returned. The logic
 * is that integer and string value parameters will always be
 * be decoded by every verifier, but only some will be able
 * to decoded the special parameters. Those that do
 * decode the specials should be preferred and this is
 * indicated by their having a higher count. If two
 * verifiers both produce the same count, the parameters
 * decoded by the first one added will be preferred.
 */
static enum t_cose_err_t
verify_one_signature(struct t_cose_sign_verify_ctx       *me,
                     const struct t_cose_header_location  header_location,
                     struct t_cose_sign_inputs           *sign_inputs,
                     QCBORDecodeContext                  *cbor_decoder,
                     struct t_cose_parameter            **param_list)
{
    struct t_cose_signature_verify *verifier;
    enum t_cose_err_t               return_value;
    QCBORSaveDecodeCursor           saved_cursor;
    struct t_cose_parameter        *tmp_sig_param_list;
    struct t_cose_parameter        *best_sig_param_list;
    int                             param_count;
    int                             best_param_count;

    QCBORDecode_SaveCursor(cbor_decoder, &saved_cursor);

    best_param_count = 0;
    best_sig_param_list = NULL;

    /* Loop over verifier instances */
    for(verifier = me->verifiers;
        verifier != NULL;
        verifier = (struct t_cose_signature_verify *)verifier->rs.next) {

        /* Save state of parameters storage and list. */

        size_t saved = me->p_storage->used;

        tmp_sig_param_list = NULL;

        return_value =
            verifier->verify_cb(verifier,         /* in: verifier me context */
                                me->option_flags, /* in: option_flags */
                                header_location,  /* in: nesting/index */
                                sign_inputs,      /* in: everything covered by signature */
                                me->p_storage,    /* in: pool of t_cose_parameter structs */
                                cbor_decoder,     /* in: decoder */
                               &tmp_sig_param_list);  /* out: linked list of decoded params */


        param_count = count_params(tmp_sig_param_list);
        if(param_count > best_param_count) {
            /* Remove the old best out of the pool. */
            if( best_sig_param_list != NULL) {
                me->p_storage->used -= squeeze_nodes(best_sig_param_list,
                                                     tmp_sig_param_list);
            }
            best_param_count = param_count;
            best_sig_param_list = tmp_sig_param_list;
        } else {
            /* Put the nodes back in the pool */
            me->p_storage->used = saved;
        }


        if(return_value == T_COSE_SUCCESS) {
            /* If here, then the decode was a success, the crypto
             * verified, and the signature CBOR was consumed. Nothing
             * to do but leave */
            goto Done;;
        }

        if(return_value == T_COSE_ERR_NO_MORE) {
            goto Done;;
        }

        /* Remember the last verifier that failed. */
        me->last_verifier = verifier;

        if(return_value == T_COSE_ERR_SIG_VERIFY) {
            /* The verifier was for the right algorithm and the key
             * was the right kid and such, but the actual crypto
             * failed to verify the bytes. In most cases the caller
             * will want to fail the whole thing if this happens.
             */
            goto Done;;
        }


        if(!is_soft_verify_error(return_value)) {
            /* Something is very wrong. Need to abort the entire
             * COSE mesage. */
            goto Done;;
        }

        /* Go on to the next verifier */
        QCBORDecode_RestoreCursor(cbor_decoder, &saved_cursor);
    }

    /* Got to the end of the list without success. The last verifier
     * called will have consumed the CBOR for the signature. We arrive
     * here because there was no verifier for the algorithm or the kid
     * for the verification key didn't match any of the signatures or
     * general decline failure. */
    return_value = T_COSE_ERR_DECLINE;

Done:
    t_cose_params_append(param_list, best_sig_param_list);

    return return_value;
}





/*
 *
 * @param[in,out] decode_parameters param list to append newly decoded
 * params to
 *
 * Process all the COSE_Signatures in a COSE_Sign. The main job
 * here is knowing whether all signatures must be validated
 * or just one. */
static enum t_cose_err_t
process_cose_signatures(struct t_cose_sign_verify_ctx *me,
                        QCBORDecodeContext            *cbor_decoder,
                        struct t_cose_sign_inputs     *sign_inputs,
                        struct t_cose_parameter      **decode_parameters)
{
    enum t_cose_err_t               return_value;
    struct t_cose_header_location   header_location;
    struct t_cose_parameter       *sig_params;

    header_location.nesting = 1;

    /* --- loop over COSE_Signatures --- */
    for(header_location.index = 0;  ; header_location.index++) {

        sig_params = NULL;
        return_value = verify_one_signature(
                                me,              /* in: main sig verify cntxt */
                                header_location, /* in: for header decoding */
                                sign_inputs,     /* in: what to verify */
                                cbor_decoder,    /* in: CBOR decoder */
                                &sig_params      /* out: decoded params */
                                );

        if(return_value == T_COSE_ERR_NO_MORE) {
            /* End of the array of signatures. */
            // TODO: What about condition where there are no COSE_Signatures?
            (void)QCBORDecode_GetAndResetError(cbor_decoder);
            return_value = T_COSE_SUCCESS;
            break;
        }

        if(return_value != T_COSE_SUCCESS &&
           return_value != T_COSE_ERR_DECLINE) {
            /* Some error condition. Do not continue. */
            break;
        }

        /* Now what's left is a T_COSE_SUCCESS or T_COSE_ERR_DECLINE */

        t_cose_params_append(decode_parameters, sig_params);

        if(me->option_flags & (T_COSE_OPT_VERIFY_ALL_SIGNATURES | T_COSE_OPT_DECODE_ONLY)) {
            if(return_value == T_COSE_ERR_DECLINE) {
                /* When verifying all, there can be no declines.
                 * Also only decoding (not verifying) there can be
                 * no declines because every signature must be
                 * decoded so its parameters can be returned.
                 * TODO: is this really true? It might be OK to
                 * only decode some as long as the caller knows
                 * that some weren't decoded. How to indicate this
                 * if it happens? An error code? A special
                 * indicator parameter in the returned list?
                 */
                break;
            } else {
                /* success. Continue on to check that the rest succeed. */
            }
        } else {
            /* Not verifying all. Looking for one success */
            if(return_value == T_COSE_SUCCESS) {
                /* Just one success is enough to complete.*/
                break;
            } else {
                /* decline. Continue to try other COSE_Signatures. */
            }
        }
    }

    return return_value;
}
#endif /* !T_COSE_DISABLE_COSE_SIGN */




/**
 * \brief Run all the verifiers against a COSE_Sign1 signature
 *
 * \param[in] me                Signature verication context.
 * \param[in] body_params_list  Params from main COSE_SIgn body (not from
 *                              COSE_Recipients).
 * \param[in] sign_inputs       All the stuff (content, headers...) covered
 *                              by sig.
 * \param[in] signature         Actual bytes of the signature.
 */
static enum t_cose_err_t
call_sign1_verifiers(struct t_cose_sign_verify_ctx   *me,
                     const struct t_cose_parameter   *body_params_list,
                     const struct t_cose_sign_inputs *sign_inputs,
                     const struct q_useful_buf_c      signature)
{
    enum t_cose_err_t               return_value;
    struct t_cose_signature_verify *verifier;

    return_value = T_COSE_ERR_NO_VERIFIERS;

    for(verifier = me->verifiers;
        verifier != NULL;
        verifier = (struct t_cose_signature_verify *)(verifier)->rs.next) {

        /* Call the verifier to attempt a verification. It will
         * compute the tbs and try to run the crypto (unless
         * T_COSE_OPT_DECODE_ONLY is set). Note also that the only
         * reason that the verifier is called even when
         * T_COSE_OPT_DECODE_ONLY is set here for a COSE_Sign1 is
         * so the aux buffer size can be computed for EdDSA.
         */
        return_value =
        verifier->verify1_cb(verifier,         /* in/out: me pointer for this verifier */
                             me->option_flags, /* in: option flags from top-level caller */
                             sign_inputs,      /* in: everything covered by signing */
                             body_params_list, /* in: linked list of header params from body */
                             signature);       /* in: the signature */
        if(return_value == T_COSE_SUCCESS) {
            break;
        }
        if(!is_soft_verify_error(return_value)) {
            /* Decode error or a signature verification failure or such. */
            break;
        }

        /* Algorithm or kid didn't match or verifier
         * declined for some other reason. Continue trying other verifiers.
         */
    }

    return return_value;
}


/*
 * A semi-private function. See t_cose_sign_verify.h
 */
enum t_cose_err_t
t_cose_sign_verify_private(struct t_cose_sign_verify_ctx  *me,
                           const struct q_useful_buf_c     message,
                           const struct q_useful_buf_c     aad,
                           const bool                      is_detached,
                           struct q_useful_buf_c          *payload,
                           struct t_cose_parameter       **returned_params)
{
    QCBORDecodeContext              cbor_decoder;
    struct q_useful_buf_c           protected_params;
    enum t_cose_err_t               return_value;
    struct q_useful_buf_c           signature;
    QCBORError                      cbor_error;
    struct t_cose_header_location   header_location;
    struct t_cose_parameter        *decoded_params;
    struct t_cose_sign_inputs       sign_inputs;
    QCBORItem                       array_item;
    uint64_t                        message_type_tag_number;

    /* --- Get started with the array of four --- */
    QCBORDecode_Init(&cbor_decoder, message, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterArray(&cbor_decoder, &array_item);
    /* t_cose_headers_decode processes errors from this to save object code */

    /* --- The main body header parameters --- */
    header_location.nesting = 0; /* Location of body header */
    header_location.index   = 0; /* params is 0, 0          */
    decoded_params          = NULL;
    return_value = t_cose_headers_decode(&cbor_decoder,
                                          header_location,
                                          me->special_param_decode_cb,
                                          me->special_param_decode_ctx,
                                          me->p_storage,
                                         &decoded_params,
                                         &protected_params);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --- The tags and message type --- */
    const uint64_t signing_tag_nums[] = {T_COSE_OPT_MESSAGE_TYPE_SIGN1,
                                         T_COSE_OPT_MESSAGE_TYPE_SIGN,
                                         CBOR_TAG_INVALID64};
    return_value = t_cose_tags_and_type(signing_tag_nums,
                                        me->option_flags,
                                       &array_item,
                                       &cbor_decoder,
                                        me->unprocessed_tag_nums,
                                       &message_type_tag_number);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --- The payload --- */
    if(is_detached) {
        QCBORDecode_GetNull(&cbor_decoder);
        /* In detached content mode, the payload should be set by
         * function caller, so there is no need to set the payload.
         */
    } else {
        QCBORDecode_GetByteString(&cbor_decoder, payload);
    }


    /* --- The signature or COSE_Signature(s) --- */
    sign_inputs.body_protected = protected_params;
    sign_inputs.sign_protected = NULL_Q_USEFUL_BUF_C;
    sign_inputs.aad            = aad;
    sign_inputs.payload        = *payload;
    if(message_type_tag_number == T_COSE_OPT_MESSAGE_TYPE_SIGN1) {
        /* --- The signature bytes for a COSE_Sign1, not COSE_Signatures */
        QCBORDecode_GetByteString(&cbor_decoder, &signature);
        if(QCBORDecode_GetError(&cbor_decoder)) {
            /* Must have successfully decoded sig before verifying */
            /* Done2 re-uses CBOR->COSE error mapping code. */
            goto Done2;
        }

        /* Call the signature verifier(s) */
        return_value = call_sign1_verifiers(me,
                                            decoded_params,
                                           &sign_inputs,
                                            signature);
    } else {

#ifndef T_COSE_DISABLE_COSE_SIGN
        /* --- The array of COSE_Signatures --- */
        QCBORDecode_EnterArray(&cbor_decoder, NULL);

        return_value = process_cose_signatures(me,
                                               &cbor_decoder,
                                               &sign_inputs,
                                               &decoded_params);

        QCBORDecode_ExitArray(&cbor_decoder);
#else
        return_value = T_COSE_ERR_UNSUPPORTED;
#endif /* !T_COSE_DISABLE_COSE_SIGN */
    }

    /* --- Finish up the CBOR decode --- */
    QCBORDecode_ExitArray(&cbor_decoder);

    if(returned_params != NULL) {
        *returned_params = decoded_params;
    }

  Done2:
    /* This check makes sure the array only had the expected four
     * items. It works for definite and indefinte length arrays. Also
     * makes sure there were no extra bytes. Also maps the error code
     * for other decode errors detected above. */
    cbor_error = QCBORDecode_Finish(&cbor_decoder);
    if(cbor_error != QCBOR_SUCCESS) {
        /* A decode error overrides the other errors detected above. */
        return_value = qcbor_decode_error_to_t_cose_error(cbor_error,
                                                      T_COSE_ERR_SIGN1_FORMAT);
    }
    /* --- End of the decoding of the array of four --- */

    /* --- Check for critical params and other --- */
    if(return_value != T_COSE_SUCCESS) {
        /* param check must not override non-decoding errors. */
        goto Done;
    }

    if(!(me->option_flags & T_COSE_OPT_NO_CRIT_PARAM_CHECK)) {
        return_value = t_cose_params_check(decoded_params);
    }

  Done:
    return return_value;
}
