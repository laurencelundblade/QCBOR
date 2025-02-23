/*
 * t_cose_encrypt_dec.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */
#include <stdlib.h>
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_encrypt_dec.h"
#include "t_cose/t_cose_recipient_dec.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_crypto.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"
#include "t_cose_qcbor_gap.h"


/* These errors do not stop the calling of further verifiers for
 * a given COSE_Recipient.
 * TODO: see about make this common with signing
 * TODO: group unsupported error codes to make this less code
 * TODO: use t_cose_check_list for optimization?
 */
static bool
is_soft_verify_error(enum t_cose_err_t error)
{
    switch(error) {
        case T_COSE_ERR_UNSUPPORTED_SIGNING_ALG:
        case T_COSE_ERR_UNSUPPORTED_CONTENT_KEY_DISTRIBUTION_ALG:
        case T_COSE_ERR_UNSUPPORTED_ENCRYPTION_ALG:
        case T_COSE_ERR_UNSUPPORTED_CIPHER_ALG:
        case T_COSE_ERR_KID_UNMATCHED:
        case T_COSE_ERR_UNSUPPORTED_HASH:
        case T_COSE_ERR_DECLINE:
            return true;
        default:
            return false;
    }
}


/**
 * \brief Invoke recipient decoders on one COSE_Recipient
 *
 * \param[in] me     The big COSE decode context.
 * \param[in] header_location   Location in COSE_Encrypt of the COSE_Recipient
 * \param[in] cbor_decoder    The CBOR decode context.
 * \param[in] cek_buffer     Buffer to write CEK to.
 * \param[out] rcpnt_params_list  Linked list of decoded header params.
 * \param[out] cek    The decrypted content encryption key.
 *
 * While this is called only once, it is split out for code readability.
 *
 * This loops over all the configured recipient decoders calling them
 * until one succeeds or has a hard failure. This performs multiple
 * attempts at the CBOR decode of the COSE_Recipient.
 */
static enum t_cose_err_t
decrypt_one_recipient(struct t_cose_encrypt_dec_ctx      *me,
                      const struct t_cose_header_location header_location,
                      const struct t_cose_alg_and_bits    ce_alg,
                      QCBORDecodeContext                 *cbor_decoder,
                      struct q_useful_buf                 cek_buffer,
                      struct t_cose_parameter           **rcpnt_params_list,
                      struct q_useful_buf_c              *cek)
{
    struct t_cose_recipient_dec *rcpnt_decoder;
    enum t_cose_err_t            return_value;
    QCBORSaveDecodeCursor        saved_cursor;

    QCBORDecode_SaveCursor(cbor_decoder, &saved_cursor);

    /* Loop over the configured recipients */
    rcpnt_decoder = me->recipient_list;
    while(1) {

        // TODO: decode-only mode for recipients

        return_value =
            rcpnt_decoder->decode_cb(
                rcpnt_decoder,     /* in: me ptr of the recipient decoder */
                header_location,   /* in: header location to record */
                ce_alg,            /* in: alg & bits for COSE_KDF_Context construction */
                cbor_decoder,      /* in: CBOR decoder context */
                cek_buffer,        /* in: buffer to write CEK to */
                me->p_storage,     /* in: parameter nodes storage pool */
                rcpnt_params_list, /* out: linked list of decoded params */
                cek                /* out: the returned CEK */
           );

        if(return_value == T_COSE_SUCCESS) {
            /* Only need to find one success. This is it, so we are done.
             * We have the CEK. */
            break;
        }

        if(return_value == T_COSE_ERR_NO_MORE) {
            /* The end of the recipients array. No more COSE_Recipients. */
            return T_COSE_ERR_NO_MORE;
        }

        if(!is_soft_verify_error(return_value)) {
            return return_value;
            /* Something very wrong. */
        }

        /* Try going on to next configured recipient decoder if there is one */
        rcpnt_decoder = (struct t_cose_recipient_dec *)rcpnt_decoder->base_obj.next;
        if(rcpnt_decoder == NULL) {
            /* Got to end of list and no recipient decoder succeeded. */
            return T_COSE_ERR_DECLINE;
        }

        /* Loop continues on for the next recipient decoder */
        QCBORDecode_RestoreCursor(cbor_decoder, &saved_cursor);
    }

    /* Got to end of list and no recipient attempted to verify */
    return T_COSE_SUCCESS;
}


/*
 * Public Function. See t_cose_encrypt_dec.h
 */
enum t_cose_err_t
t_cose_encrypt_dec_main_private(struct t_cose_encrypt_dec_ctx* me,
                                QCBORDecodeContext            *cbor_decoder,
                                const struct q_useful_buf_c    ext_sup_data,
                                const struct q_useful_buf_c    detached_ciphertext,
                                struct q_useful_buf            plaintext_buffer,
                                struct q_useful_buf_c         *plaintext,
                                struct t_cose_parameter      **returned_parameters,
                                uint64_t                       tag_numbers[T_COSE_MAX_TAGS_TO_RETURN])
{
    enum t_cose_err_t              return_value;
    QCBORItem                      array_item;
    QCBORError                     cbor_error;
    uint64_t                       message_type;
    struct t_cose_header_location  header_location;
    struct t_cose_parameter       *body_params_list;
    struct q_useful_buf_c          nonce_cbor;
    struct q_useful_buf_c          protected_params;
    struct q_useful_buf_c          cipher_text;
    struct t_cose_alg_and_bits     ce_alg;
    struct q_useful_buf_c          cek;
    struct t_cose_key              cek_key;
    MakeUsefulBufOnStack(          cek_buf, T_COSE_MAX_SYMMETRIC_KEY_LENGTH);
    struct t_cose_parameter       *rcpnt_params_list;
    struct t_cose_parameter       *all_params_list;
    const char                    *msg_type_string;
    Q_USEFUL_BUF_MAKE_STACK_UB(    enc_struct_buffer, T_COSE_ENCRYPT_STRUCT_DEFAULT_SIZE);
    struct q_useful_buf_c          enc_structure;
    bool                           alg_id_prot;
    enum t_cose_err_t              previous_return_value;


    /* --- Tag number processing, COSE_Sign or COSE_Sign1? --- */
    message_type = me->option_flags & T_COSE_OPT_MESSAGE_TYPE_MASK;

#if QCBOR_VERSION_MAJOR >= 2
    if(message_type == T_COSE_OPT_MESSAGE_TYPE_UNSPECIFIED) {
        /* Caller didn't tell us what it is, get a tag number */
        QCBORDecode_VGetNextTagNumber(cbor_decoder, &message_type);
    }
#endif /* QCBOR_VERSION_MAJOR >= 2 */


    /* --- Get started decoding array of 4 and tags --- */
    QCBORDecode_EnterArray(cbor_decoder, &array_item);
    cbor_error = QCBORDecode_GetError(cbor_decoder);
    if(cbor_error != QCBOR_SUCCESS) {
        goto Done;
    }

#if QCBOR_VERSION_MAJOR == 1
    return_value = t_cose_process_tag_numbers_qcbor1(0,
                                                     false, /* Always t_cose v2 semantics, there was no decrypt in t_cose v1 */
                                                     cbor_decoder,
                                                     &array_item,
                                                     &message_type,
                                                     tag_numbers);
    if(return_value != T_COSE_SUCCESS) {
        return return_value;
    }
#else
    (void)tag_numbers;
#endif /* QCBOR_VERSION_MAJOR == 1 */

    /* --- Finish tag number & type processing, COSE_Encrypt or COSE_Encrypt0? --- */
    if(message_type != CBOR_TAG_COSE_ENCRYPT &&
       message_type != CBOR_TAG_COSE_ENCRYPT0) {
        return T_COSE_ERR_CANT_DETERMINE_MESSAGE_TYPE;
    }


    /* --- The header parameters --- */
    /* The location of body header parameters is 0, 0 */
    header_location.nesting = 0;
    header_location.index   = 0;
    body_params_list  = NULL;
    rcpnt_params_list = NULL;

    return_value =
        t_cose_headers_decode(
            cbor_decoder,     /* in: cbor decoder context */
            header_location,  /* in: location of headers in message */
            NULL,             /* TODO: in: header decode callback function */
            NULL,             /* TODO: in: header decode callback context */
            me->p_storage,    /* in: pool of nodes for linked list */
           &body_params_list, /* out: linked list of params */
           &protected_params  /* out: ptr & len of encoded protected params */
        );
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    nonce_cbor = t_cose_param_find_iv(body_params_list);
    if(q_useful_buf_c_is_empty(nonce_cbor)) {
        return T_COSE_ERR_BAD_IV;
    }

    ce_alg.cose_alg_id = t_cose_param_find_alg_id(body_params_list, &alg_id_prot);
    if(ce_alg.cose_alg_id == T_COSE_ALGORITHM_NONE) {
        return T_COSE_ERR_NO_ALG_ID;
    }
    if(t_cose_alg_is_non_aead(ce_alg.cose_alg_id)) {
        /* Make sure that the library caller (recipient) explicitly enables non AEAD ciphers*/
        if(!(me->option_flags & T_COSE_OPT_ENABLE_NON_AEAD)) {
            return T_COSE_ERR_NON_AEAD_DISABLED;
        }
        /* Make sure there are no protected headers for non-aead algorithms */
        if(!t_cose_params_empty(protected_params)) {
            return T_COSE_ERR_PROTECTED_NOT_ALLOWED;
        }
    } else {
        /* Make sure alg id is protected for aead algorithms */
        if(alg_id_prot != true) {
            return T_COSE_ERR_NO_ALG_ID;
        }
    }
    ce_alg.bits_in_key = bits_in_crypto_alg(ce_alg.cose_alg_id);
    if(ce_alg.bits_in_key == UINT32_MAX) {
        return T_COSE_ERR_UNSUPPORTED_ENCRYPTION_ALG;
    }

    all_params_list = body_params_list;


    /* --- The Ciphertext --- */
    if(!q_useful_buf_c_is_null(detached_ciphertext)) {
        QCBORDecode_GetNull(cbor_decoder);
        cipher_text = detached_ciphertext;
    } else {
        QCBORDecode_GetByteString(cbor_decoder, &cipher_text);
    }

    /* --- COSE_Recipients (if there are any) --- */
    if (message_type == T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0) {
        // TODO: test case where CEK is not set; improve error code?
        if(me->recipient_list != NULL) {
            return T_COSE_ERR_FAIL; // TODO: need better error here
        }
        cek_key = me->cek;

    } else if (message_type == T_COSE_OPT_MESSAGE_TYPE_ENCRYPT) {
        if(me->recipient_list == NULL) {
              return T_COSE_ERR_FAIL; // TODO: need better error here
        }

        header_location.nesting = 1;
        header_location.index   = 0;

        /* --- Enter array of recipients --- */
        QCBORDecode_EnterArray(cbor_decoder, NULL);
        cbor_error = QCBORDecode_GetError(cbor_decoder);
        if(cbor_error != QCBOR_SUCCESS) {
            goto Done;
        }

        /* Loop over the array of COSE_Recipients */
        while(1) {
            previous_return_value = return_value;

            return_value = decrypt_one_recipient(me,
                                                 header_location,
                                                 ce_alg,
                                                 cbor_decoder,
                                                 cek_buf,
                                                &rcpnt_params_list,
                                                 &cek);
            /* This will have consumed the CBOR of one recipient */

            if(return_value == T_COSE_SUCCESS) {
                /* One success is enough to get the CEK.
                 *
                 * Breaking here short circuits decoding
                 * further recipients. If they are not well-formed
                 * it will be detected by QCBORDecode_ExitArray(), but
                 * if they are well-formed and have the wrong CBOR
                 * types and such, it will not be detected. This is
                 * considered OK for this implementation. Perhaps
                 * some will disagree. However doing the error detection
                 * on all will add code and complexity.
                 */
                break;
            }

            if(return_value == T_COSE_ERR_NO_MORE) {
                /* Got to the end of the COSE_Recipients array without
                 * success, so return the error the previous recipient decoder
                 * returned. */
                return_value = previous_return_value;
                goto Done;
            }

            if(return_value != T_COSE_ERR_DECLINE) {
                /* Either we got to the end of the list and on
                 * recipient decoder attempted, or some decoder
                 * attemted and there was an error.  TODO: a lot of
                 * testing to be sure this is sufficient.
                 */
                goto Done;
            }

            /* Going on to try another recipient since this one wasn't
             * a success and wasn't a hard error -- all recipient
             * decoders declined to try it.
             */
            header_location.index++;
        }

        /* Successfully decoded one recipient */
        QCBORDecode_ExitArray(cbor_decoder);


        t_cose_params_append(&all_params_list, rcpnt_params_list);

        /* The decrypted cek bytes must be a t_cose_key for the AEAD API */
        return_value =
            t_cose_crypto_make_symmetric_key_handle(
                ce_alg.cose_alg_id,  /* in: algorithm ID */
                cek,                 /* in: CEK bytes */
                &cek_key             /* out: t_cose_key */
            );
        if(return_value != T_COSE_SUCCESS) {
            goto Done;
        }

    } else {
       /* This never happens because of type determination above */
    }

    /* --- Close of CBOR decode of the array of 4 --- */
    /* This tolerates extra items. Someday we'll have a better ExitArray()
     * and efficiently catch this (mostly harmless) error. */
    QCBORDecode_ExitArray(cbor_decoder);
    cbor_error = QCBORDecode_Finish(cbor_decoder);
    if(cbor_error != QCBOR_SUCCESS) {
        goto Done;
    }
    if(returned_parameters != NULL) {
        *returned_parameters = all_params_list;
    }

    /* --- Check for critical parameters --- */
    if(!(me->option_flags & T_COSE_OPT_NO_CRIT_PARAM_CHECK)) {
        return_value = t_cose_params_check(all_params_list);
        if(return_value != T_COSE_SUCCESS) {
            goto Done;
        }
    }

    /* A lot of stuff is done now: 1) All the CBOR decoding is done, 2) we
     * have the CEK, 3) all the headers are decoded and in a linked list
     */

    // TODO: stop here for decode-only mode */


    /* --- The body/content decryption --- */
    if(t_cose_alg_is_non_aead(ce_alg.cose_alg_id)) {
        return_value =
            t_cose_crypto_non_aead_decrypt(
                ce_alg.cose_alg_id,    /* in: cose alg id to decrypt payload */
                cek_key,               /* in: content encryption key */
                nonce_cbor,            /* in: iv / nonce for decrypt */
                cipher_text,           /* in: bytes to decrypt */
                plaintext_buffer,      /* in: buffer to output plaintext into */
                plaintext              /* out: the decrypted payload */
            );
    }
    else {
        /* --- Make the Enc_structure ---- */
        /* The Enc_structure from RFC 9052 section 5.3 that is input as AAD
        * to the AEAD to integrity-protect COSE headers and
        * parameters. */
        if(!q_useful_buf_is_null(me->extern_enc_struct_buffer)) {
            /* Caller gave us a (bigger) buffer for Enc_structure */
            enc_struct_buffer = me->extern_enc_struct_buffer;
        }
        msg_type_string = (message_type == T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0 ?
                            "Encrypt0" :
                            "Encrypt");
        return_value =
            create_enc_structure(
                msg_type_string,   /* in: message type context string */
                protected_params,  /* in: body protected parameters */
                ext_sup_data,      /* in: AAD from caller to integrity protect */
                enc_struct_buffer, /* in: buffer for encoded Enc_structure */
                &enc_structure     /* out: CBOR encoded Enc_structure */
            );
        if (return_value != T_COSE_SUCCESS) {
            goto Done;
        }

        return_value =
            t_cose_crypto_aead_decrypt(
                ce_alg.cose_alg_id,    /* in: cose alg id to decrypt payload */
                cek_key,               /* in: content encryption key */
                nonce_cbor,            /* in: iv / nonce for decrypt */
                enc_structure,         /* in: the AAD for the AEAD */
                cipher_text,           /* in: bytes to decrypt */
                plaintext_buffer,      /* in: buffer to output plaintext into */
                plaintext              /* out: the decrypted payload */
            );
    }
    if (message_type != T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0) {
        t_cose_crypto_free_symmetric_key(cek_key);
    }

Done:
    if(cbor_error != QCBOR_SUCCESS) {
         return_value = qcbor_decode_error_to_t_cose_error(cbor_error, T_COSE_ERR_ENCRYPT_FORMAT);
     }
    return return_value;
}


/*
 * Public Function. See t_cose_encrypt_dec.h
 */
enum t_cose_err_t
t_cose_encrypt_dec_msg(struct t_cose_encrypt_dec_ctx *me,
                       const struct q_useful_buf_c    cose_message,
                       const struct q_useful_buf_c    ext_sup_data,
                       struct q_useful_buf            plaintext_buffer,
                       struct q_useful_buf_c         *plaintext,
                       struct t_cose_parameter      **returned_parameters,
                       uint64_t                       returned_tag_numbers[T_COSE_MAX_TAGS_TO_RETURN])
{
    QCBORDecodeContext  cbor_decoder;
    enum t_cose_err_t   error;
    uint32_t            save_option_flags;

    QCBORDecode_Init(&cbor_decoder, cose_message, QCBOR_DECODE_MODE_NORMAL);

    save_option_flags = me->option_flags;

#if QCBOR_VERSION_MAJOR >= 2
    error = t_cose_private_process_msg_tag_nums(&cbor_decoder,
                                                T_COSE_ERR_ENCRYPT_FORMAT,
                                                &me->option_flags,
                                                returned_tag_numbers);
    if(error) {
        return error;
    }
#else
    /* QCBORv1 tag number processing is in t_cose_encrypt_dec() */
#endif /* QCBOR_VERSION_MAJOR >= 2 */

    error = t_cose_encrypt_dec_main_private(me,
                                           &cbor_decoder,
                                            ext_sup_data,
                                            NULL_Q_USEFUL_BUF_C,
                                            plaintext_buffer,
                                            plaintext,
                                            returned_parameters,
                                            returned_tag_numbers);

    me->option_flags = save_option_flags;

    return error;
}


/*
 * Public Function. See t_cose_encrypt_dec.h
 */
enum t_cose_err_t
t_cose_encrypt_dec_detached_msg(struct t_cose_encrypt_dec_ctx *me,
                                struct q_useful_buf_c          cose_message,
                                struct q_useful_buf_c          ext_sup_data,
                                struct q_useful_buf_c          detached_ciphertext,
                                struct q_useful_buf            plaintext_buffer,
                                struct q_useful_buf_c         *plaintext,
                                struct t_cose_parameter      **returned_parameters,
                                uint64_t                       returned_tag_numbers[T_COSE_MAX_TAGS_TO_RETURN])
{
    QCBORDecodeContext  cbor_decoder;
    enum t_cose_err_t   error;
    uint32_t            saved_option_flags;

    QCBORDecode_Init(&cbor_decoder, cose_message, QCBOR_DECODE_MODE_NORMAL);

    saved_option_flags = me->option_flags;

#if QCBOR_VERSION_MAJOR >= 2
    error = t_cose_private_process_msg_tag_nums(&cbor_decoder,
                                                T_COSE_ERR_ENCRYPT_FORMAT,
                                                &me->option_flags,
                                                returned_tag_numbers);
    if(error != T_COSE_SUCCESS) {
        return error;
    }
#else
    /* QCBORv1 tag number processing is in t_cose_encrypt_dec_detached() */
#endif /* QCBOR_VERSION_MAJOR >= 2 */

    error = t_cose_encrypt_dec_main_private(me,
                                           &cbor_decoder,
                                            ext_sup_data,
                                            detached_ciphertext,
                                            plaintext_buffer,
                                            plaintext,
                                            returned_parameters,
                                            returned_tag_numbers);

    me->option_flags = saved_option_flags;

    return error;
}
