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


/**
 * \brief "Main" verifier of t_cose_signature_verify_cb.
 *
 * \param[in] cbor_decoder     The decoder instance from where the
 *                             COSE_Signature is decoded.
 * \param[in] loc              The location of the sig inside the COSE_Sign.
 * \param[in] param_storage    The place to put the decoded params.

 * \param[out] decoded_params  Returned linked list of decoded parameters.
 *
 * This CBOR-decodes a COSE_Signature, particularly the header
 * parameters.
 *
 * The return code is important here as it determines how decoding and
 * verification proceeds for COSE_Sign message with multiple
 * COSE_Signatures.
 *
 * Note that *decoded_params parameters should be NULL in most cases
 * when this is called.
 * Returns:  -- T_COSE_ERR_NO_MORE
          -- header decode errors
 -- Special header decode errors
 -- CBOR format errors
 *
 */
static enum t_cose_err_t
decode_cose_signature(QCBORDecodeContext                 *cbor_decoder,
                      const struct t_cose_header_location loc,
                      struct t_cose_parameter_storage    *param_storage,
                      t_cose_param_special_decode_cb     *special_decode_cb,
                      void                               *special_decode_ctx,
                      struct q_useful_buf_c              *protected_parameters,
                      struct t_cose_parameter           **decoded_params,
                      struct q_useful_buf_c              *signature)

{
    QCBORError               qcbor_error;
    static enum t_cose_err_t return_value;

    QCBORDecode_EnterArray(cbor_decoder, NULL);
    qcbor_error = QCBORDecode_GetError(cbor_decoder);
    if(qcbor_error == QCBOR_ERR_NO_MORE_ITEMS) {
        return T_COSE_ERR_NO_MORE;
    }

    return_value = t_cose_headers_decode(cbor_decoder,
                                         loc,
                                         special_decode_cb,
                                         special_decode_ctx,
                                         param_storage,
                                         decoded_params,
                                         protected_parameters);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --- The signature --- */
    QCBORDecode_GetByteString(cbor_decoder, signature);

    QCBORDecode_ExitArray(cbor_decoder);
    qcbor_error = QCBORDecode_GetError(cbor_decoder);
    if(qcbor_error != QCBOR_SUCCESS) {
        return_value = qcbor_decode_error_to_t_cose_error(qcbor_error, T_COSE_ERR_SIGNATURE_FORMAT);
        goto Done;
    }

Done:
    return return_value;
}


/*
 * The work of this is to call multiple verifiers on one
 * COSE_Signature until one verifier succeeds.
 *
 * It is assumed the compiler will inline this since it is called
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
    struct q_useful_buf_c           signature;

    /* --- Loop Initialization ---- */
    QCBORDecode_SaveCursor(cbor_decoder, &saved_cursor);
    best_param_count    = 0;
    best_sig_param_list = NULL;
    verifier            = me->verifiers;

    /* --- Loop over verifiers --- */
    while(1) {
        /* This loop will run partially even with no verifiers to
         * always at least decode the COSE_Signature. */

        /* --- Decode the COSE_Signature --- */
        size_t saved = me->p_storage->used;
        tmp_sig_param_list = NULL;
        return_value = decode_cose_signature(cbor_decoder,
                                             header_location,
                                             me->p_storage,
                                             verifier ? verifier->special_param_decode_cb : NULL,
                                             verifier ? verifier->special_param_decode_ctx : NULL,
                                            &sign_inputs->sign_protected,
                                            &tmp_sig_param_list,
                                            &signature);

        if(return_value != T_COSE_SUCCESS) {
            /* Either no more COSE_Signatures or COSE_Signature decode error */
            break;
        }

        /* --- Keep this header decode or last best decode? ---- */
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

        /* --- Is there a verifier to call? --- */
        /* Got to the end of the list without success or there were no verifiers.  We arrive
         * here because there was no verifier for the algorithm or the kid
         * for the verification key didn't match any of the signatures or
         * general decline failure. The decode above will have consumed
         * the COSE signature. */
        if(verifier == NULL) {
            return_value = T_COSE_ERR_DECLINE;
            break;
        }

        /* --- Attempt actual verification --- */
        return_value = verifier->verify_cb(verifier, /* in: verifier me context */
                                           me->option_flags, /* in: option_flags */
                                           sign_inputs, /* in: everything covered by signature */
                                           tmp_sig_param_list,
                                           signature);
        if(return_value == T_COSE_SUCCESS) {
            /* If here, then the decode was a success, the crypto
             * verified, and the signature CBOR was consumed.
             */
            break;
        }

        /* --- What kind of failure is this?--- */
        /* Remember the last verifier that failed. */
        me->last_verifier = verifier;

        if(return_value == T_COSE_ERR_SIG_VERIFY) {
            /* The verifier was for the right algorithm and the key
             * was the right kid and such, but the actual crypto
             * failed to verify the bytes. In most cases the caller
             * will want to fail the whole thing if this happens.
             */
            break;
        }

        if(!is_soft_verify_error(return_value)) {
            /* Something is very wrong. Need to abort the entire
             * COSE mesage. */
            break;
        }

        /* --- Loop "increment" to try next verifier --- */
        verifier = (struct t_cose_signature_verify *)verifier->rs.next;
        /* Reset CBOR decoder to try next verifer on the same COSE_Signature */
        QCBORDecode_RestoreCursor(cbor_decoder, &saved_cursor);
    }

    t_cose_params_append(param_list, best_sig_param_list);

    return return_value;
}


/*
 *
 * @param[in,out] decode_parameters param list to append newly decoded
 * params to
 *
 * Process all the COSE_Signatures in a COSE_Sign. */
static enum t_cose_err_t
process_cose_signatures(struct t_cose_sign_verify_ctx *me,
                        QCBORDecodeContext            *cbor_decoder,
                        struct t_cose_sign_inputs     *sign_inputs,
                        struct t_cose_parameter      **decode_parameters)
{
    enum t_cose_err_t              return_value;
    struct t_cose_header_location  header_location;
    struct t_cose_parameter       *sig_params;

    header_location.nesting = 1;

    /* The call to verify_one_signature() does quite a lot of
     * the work, but only for one COSE_Signature. What it doesn't
     * do is the loop over all signatures and the policy of
     * success from verifying one or from verifying all.
     */

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

        if(me->option_flags & T_COSE_OPT_DECODE_ONLY) {
            /* T_COSE_ERR_DECLINE never stops processing so all header
             * params are decoded, all aux buffers sizes calculated */
            continue;
        }

        if(me->option_flags & T_COSE_OPT_VERIFY_ALL_SIGNATURES ) {
            if(return_value == T_COSE_ERR_DECLINE) {
                /* When verifying all, there can be no declines. */
                break;
            } else {
                /* Success. Continue on to check that the rest succeed. */
            }
        } else {
            /* Not verifying all. Looking for one success */
            if(return_value == T_COSE_SUCCESS) {
                /* Just one success is enough to complete */
                break;
            } else {
                /* Decline. Continue to try other COSE_Signatures */
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
// TODO: how do special header decoders work for COSE_Sign1?
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
        verifier->verify_cb(verifier,         /* in/out: me pointer for this verifier */
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
