/*
 * Copyright (c) 2018-2025, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2020-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_mac_validate.h"
#include "t_cose_util.h"
#include "t_cose_crypto.h"

/**
 * \file t_cose_mac_validate.c
 *
 * \brief This validates t_cose MAC authentication structure without
 *        a recipient structure (COSE_Mac0).
 *        Only HMAC is supported so far.
 */


/**
 * \brief Semi-private main function to validate a COSE_Mac0 message.
 *
 * \param[in] context   The context of COSE_Mac0 validation.
 * \param[in] cbor_decoder    Source of the input COSE message to validate.
 * \param[in] ext_sup_data       The Additional Authenticated Data or
 *                      \c NULL_Q_USEFUL_BUF_C.
 * \param[in] payload_is_detached  If \c true, indicates the \c payload
 *                                 is detached.
 * \param[out] payload             Pointer and length of the still CBOR
 *                                 encoded payload.
 * \param[out] return_params       Place to return decoded parameters.
 *                                 May be \c NULL.
 * \param[out] returned_tag_numbers  Place to return tag numbers or NULL. Always the order from the input encoded CBOR, outer most first.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * It is a semi-private function internal to the implementation which means its
 * interface isn't guaranteed so it should not be called directly. Call
 * t_cose_mac_validate() or t_cose_mac_validate_detached() instead of this.
 *
 * If returned_tag_numbers is NULL, that is because no tag numbers are expected except in  case
 * the caller doesn't indicate the message type.
 */
enum t_cose_err_t
t_cose_mac_validate_private(struct t_cose_mac_validate_ctx *me,
                            QCBORDecodeContext             *cbor_decoder,
                            struct q_useful_buf_c           ext_sup_data,
                            bool                            payload_is_detached,
                            struct q_useful_buf_c          *payload,
                            struct t_cose_parameter       **return_params,
                            uint64_t                        tag_numbers[T_COSE_MAX_TAGS_TO_RETURN])
{
    struct q_useful_buf_c         protected_parameters;
    QCBORError                    qcbor_error;
    enum t_cose_err_t             return_value;
    struct q_useful_buf_c         expected_mac_tag;
    struct q_useful_buf_c         computed_mac_tag;
    struct t_cose_parameter      *decoded_params;
    struct t_cose_sign_inputs     mac_input;
    QCBORItem                     array_item;
    uint64_t                      message_type_tag_number;
    Q_USEFUL_BUF_MAKE_STACK_UB(   mac_tag_buf, T_COSE_CRYPTO_HMAC_TAG_MAX_SIZE);

    decoded_params = NULL;

    /* --- Tag number processing, COSE_Sign or COSE_Sign1? --- */
    message_type_tag_number = me->option_flags & T_COSE_OPT_MESSAGE_TYPE_MASK;

#if QCBOR_VERSION_MAJOR >= 2
    if(message_type_tag_number == T_COSE_OPT_MESSAGE_TYPE_UNSPECIFIED) {
        /* Message type not specified, get a tag number */
        QCBORDecode_VGetNextTagNumber(cbor_decoder, &message_type_tag_number);
    }
#endif /* QCBOR_VERSION_MAJOR >= 2 */

    /* --- The array of 4, type determination and tags --- */
    QCBORDecode_EnterArray(cbor_decoder, &array_item);
    return_value = qcbor_decode_error_to_t_cose_error(
                                        QCBORDecode_GetError(cbor_decoder),
                                        T_COSE_ERR_MAC0_FORMAT);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

#if QCBOR_VERSION_MAJOR == 1
    return_value = t_cose_process_tag_numbers_qcbor1(0, /* option_flags, never used with v2 semantics */
                                                     false, /* Always t_cose v2 semantics, there was no mac in t_cose v1 */
                                                     cbor_decoder,
                                                     &array_item,
                                                     &message_type_tag_number,
                                                     tag_numbers);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
#else
    (void)tag_numbers;
#endif /* QCBOR_VERSION_MAJOR == 1 */

    if(message_type_tag_number != T_COSE_OPT_MESSAGE_TYPE_MAC0 ) {
        return T_COSE_ERR_CANT_DETERMINE_MESSAGE_TYPE;
    }
    

    /* --- The parameters --- */
    const struct t_cose_header_location l = {0,0};
    decoded_params = NULL;
    return_value = t_cose_headers_decode(cbor_decoder,
                                         l,
                                         me->special_param_decode_cb,
                                         me->special_param_decode_ctx,
                                         me->p_storage,
                                        &decoded_params,
                                        &protected_parameters);


    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --- The payload --- */
    if (payload_is_detached) {
        /* detached payload: the payload should be set by caller */
        QCBORDecode_GetNull(cbor_decoder);
    } else {
        QCBORDecode_GetByteString(cbor_decoder, payload);
    }

    /* --- The HMAC tag --- */
    QCBORDecode_GetByteString(cbor_decoder, &expected_mac_tag);

    /* --- Finish up the CBOR decode --- */
    QCBORDecode_ExitArray(cbor_decoder);

    /* This check makes sure the array only had the expected four
     * items. It works for definite and indefinte length arrays. Also
     * makes sure there were no extra bytes. Also that the payload
     * and authentication tag were decoded correctly. */
    qcbor_error = QCBORDecode_Finish(cbor_decoder);
    return_value = qcbor_decode_error_to_t_cose_error(qcbor_error,
                                                      T_COSE_ERR_MAC0_FORMAT);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* === End of the decoding of the array of four === */
    if((me->option_flags & T_COSE_OPT_REQUIRE_KID) &&
        q_useful_buf_c_is_null(t_cose_param_find_kid(decoded_params))) {
        return_value = T_COSE_ERR_NO_KID;
        goto Done;
    }

    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* -- Skip tag validation if requested --*/
    if(me->option_flags & T_COSE_OPT_DECODE_ONLY) {
        return_value = T_COSE_SUCCESS;
        goto Done;
    }

    /* -- Compute the ToBeMaced and compare -- */
    mac_input.ext_sup_data   = ext_sup_data;
    mac_input.payload        = *payload;
    mac_input.body_protected = protected_parameters;
    mac_input.sign_protected = NULL_Q_USEFUL_BUF_C; /* No sign-protected for MAC */

    return_value = create_tbm(t_cose_param_find_alg_id_prot(decoded_params),
                              me->validation_key,/* in: the key */
                              true,              /* in: is_mac0 (MAC vs MAC0) */
                             &mac_input,         /* in: struct of all TBM inputs */
                              mac_tag_buf,       /* in: buffer to output to */
                             &computed_mac_tag); /* out: the computed MAC tag */
    if(return_value) {
        goto Done;
    }

    if(q_useful_buf_compare(computed_mac_tag, expected_mac_tag)) {
        return_value = T_COSE_ERR_HMAC_VERIFY;
        goto Done;
    }


    /* --- Check for critical parameters --- */
    if(!(me->option_flags & T_COSE_OPT_NO_CRIT_PARAM_CHECK)) {
        return_value = t_cose_params_check(decoded_params);
    }

Done:
    if(return_params != NULL) {
        *return_params = decoded_params;
    }

    return return_value;
}


/* See t_cose_mac_validate_msg() and t_cose_mac_validate_detached_msg() */
enum t_cose_err_t
t_cose_mac_validate_msg_private(struct t_cose_mac_validate_ctx *me,
                                struct q_useful_buf_c           cose_mac,
                                struct q_useful_buf_c           ext_sup_data,
                                bool                            payload_is_detached,
                                struct q_useful_buf_c          *payload,
                                struct t_cose_parameter       **return_params,
                                uint64_t                        returned_tag_numbers[T_COSE_MAX_TAGS_TO_RETURN])
{
    QCBORDecodeContext  cbor_decoder;
    enum t_cose_err_t   error;
    uint32_t            saved_option_flags;

    QCBORDecode_Init(&cbor_decoder, cose_mac, QCBOR_DECODE_MODE_NORMAL);

    saved_option_flags = me->option_flags;
    
#if QCBOR_VERSION_MAJOR >= 2
    error = t_cose_private_process_msg_tag_nums(&cbor_decoder,
                                                T_COSE_ERR_MAC0_FORMAT,
                                                &me->option_flags,
                                                returned_tag_numbers);
    if(error != T_COSE_SUCCESS) {
        return error;
    }
#else
    /* QCBORv1 tag number processing is in t_cose_mac_validate_private() */
#endif /* QCBOR_VERSION_MAJOR >= 2 */

    error = t_cose_mac_validate_private(me,
                                       &cbor_decoder,
                                        ext_sup_data,
                                        payload_is_detached,
                                        payload,
                                        return_params,
                                        returned_tag_numbers);

    me->option_flags = saved_option_flags;

    return error;
}
