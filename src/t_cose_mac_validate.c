/*
 * Copyright (c) 2018-2023, Laurence Lundblade. All rights reserved.
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



/*
 * Semi-private function. See t_cose_mac_validate.h
 */
enum t_cose_err_t
t_cose_mac_validate_private(struct t_cose_mac_validate_ctx *me,
                            struct q_useful_buf_c           cose_mac,
                            struct q_useful_buf_c           ext_sup_data,
                            bool                            payload_is_detached,
                            struct q_useful_buf_c          *payload,
                            struct t_cose_parameter       **return_params)
{
    QCBORDecodeContext            decode_context;
    struct q_useful_buf_c         protected_parameters;
    QCBORError                    qcbor_error;
    enum t_cose_err_t             return_value;
    struct q_useful_buf_c         expected_mac_tag;
    struct q_useful_buf_c         computed_mac_tag;
    struct t_cose_parameter      *decoded_params;
    struct t_cose_sign_inputs     mac_input;
    QCBORItem                     item;
    uint64_t                      message_type;
    Q_USEFUL_BUF_MAKE_STACK_UB(   mac_tag_buf, T_COSE_CRYPTO_HMAC_TAG_MAX_SIZE);

    decoded_params = NULL;

    QCBORDecode_Init(&decode_context, cose_mac, QCBOR_DECODE_MODE_NORMAL);

    /* --- The array of 4, type determination and tags --- */
    QCBORDecode_EnterArray(&decode_context, &item);
    return_value = qcbor_decode_error_to_t_cose_error(
                                        QCBORDecode_GetError(&decode_context),
                                        T_COSE_ERR_MAC0_FORMAT);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    const uint64_t mac_tag_nums[] = {T_COSE_OPT_MESSAGE_TYPE_MAC0,
                                     CBOR_TAG_INVALID64};
    return_value = t_cose_tags_and_type(mac_tag_nums,
                                        me->option_flags,
                                        &item,
                                        &decode_context,
                                        me->unprocessed_tag_nums,
                                        &message_type);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    /* --- The parameters --- */
    const struct t_cose_header_location l = {0,0};
    decoded_params = NULL;
    return_value = t_cose_headers_decode(&decode_context,
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
        QCBORDecode_GetNull(&decode_context);
    } else {
        QCBORDecode_GetByteString(&decode_context, payload);
    }

    /* --- The HMAC tag --- */
    QCBORDecode_GetByteString(&decode_context, &expected_mac_tag);

    /* --- Finish up the CBOR decode --- */
    QCBORDecode_ExitArray(&decode_context);

    /* This check makes sure the array only had the expected four
     * items. It works for definite and indefinte length arrays. Also
     * makes sure there were no extra bytes. Also that the payload
     * and authentication tag were decoded correctly. */
    qcbor_error = QCBORDecode_Finish(&decode_context);
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
