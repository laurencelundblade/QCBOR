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
                            struct q_useful_buf_c           aad,
                            bool                            payload_is_detached,
                            struct q_useful_buf_c          *payload,
                            struct t_cose_parameter       **return_params)
{
    QCBORDecodeContext            decode_context;
    struct q_useful_buf_c         protected_parameters;
    QCBORError                    qcbor_error;

    enum t_cose_err_t             return_value;
    struct q_useful_buf_c         tag = NULL_Q_USEFUL_BUF_C;
    struct q_useful_buf_c         tbm_first_part;
    /* Buffer for the ToBeMaced */
    Q_USEFUL_BUF_MAKE_STACK_UB(   tbm_first_part_buf,
                                  T_COSE_SIZE_OF_TBM);
    struct t_cose_crypto_hmac     hmac_ctx;
    struct t_cose_parameter      *decoded_params;
    struct t_cose_sign_inputs     mac_input;
    QCBORItem                     item;
    uint64_t                      message_type;

    decoded_params = NULL;

    QCBORDecode_Init(&decode_context, cose_mac, QCBOR_DECODE_MODE_NORMAL);

    /* --- The array of 4 and type determination and tags --- */
    QCBORDecode_EnterArray(&decode_context, &item);
    return_value = qcbor_decode_error_to_t_cose_error(
                                        QCBORDecode_GetError(&decode_context),
                                        T_COSE_ERR_MAC0_FORMAT);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    const uint64_t mac_tag_nums[] = {T_COSE_OPT_MESSAGE_TYPE_MAC0, CBOR_TAG_INVALID64};
    return_value = t_cose_tags_and_type(mac_tag_nums,
                                        me->option_flags,
                                        &item,
                                        &decode_context,
                                        me->unprocessed_tag_nums,
                                        &message_type);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    /* --- The protected parameters --- */
    const struct t_cose_header_location l = {0,0};
    decoded_params = NULL;
    t_cose_headers_decode(&decode_context,
                          l,
                          NULL,
                          NULL,
                          &me->parameter_storage,
                          &decoded_params,
                          &protected_parameters);

    /* --- The payload --- */
    if (payload_is_detached) {
        /* detached payload: the payload should be set by caller */
        QCBORDecode_GetNull(&decode_context);
    } else {
        QCBORDecode_GetByteString(&decode_context, payload);
    }

    /* --- The HMAC tag --- */
    QCBORDecode_GetByteString(&decode_context, &tag);

    /* --- Finish up the CBOR decode --- */
    QCBORDecode_ExitArray(&decode_context);

    /* This check make sure the array only had the expected four
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

    /* -- Compute the ToBeMaced -- */
    mac_input.aad = aad;
    mac_input.payload = *payload;
    mac_input.body_protected = protected_parameters;
    mac_input.sign_protected = NULL_Q_USEFUL_BUF_C; /* Never sign-protected for MAC */
    return_value = create_tbm(&mac_input,
                              tbm_first_part_buf,
                              &tbm_first_part);
    if(return_value) {
        goto Done;
    }

    /*
     * Start the HMAC validation.
     * Calculate the tag of the first part of ToBeMaced and the wrapped
     * payload, to save a bigger buffer containing the entire ToBeMaced.
     */
    return_value = t_cose_crypto_hmac_validate_setup(&hmac_ctx,
                                  t_cose_param_find_alg_id(decoded_params, true),
                                  me->validation_key);

    if(return_value) {
        goto Done;
    }

    /* Compute the tag of the first part. */
    return_value = t_cose_crypto_hmac_update(&hmac_ctx,
                                         q_useful_buf_head(tbm_first_part,
                                                           tbm_first_part.len));
    if(return_value) {
        goto Done;
    }

    return_value = t_cose_crypto_hmac_update(&hmac_ctx, *payload);
    if(return_value) {
        goto Done;
    }

    return_value = t_cose_crypto_hmac_validate_finish(&hmac_ctx, tag);
    if(return_value != T_COSE_SUCCESS) {
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
