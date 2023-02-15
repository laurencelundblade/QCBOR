/*
 * Copyright (c) 2018-2023, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2020-2022, Arm Limited. All rights reserved.
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

#ifndef T_COSE_DISABLE_MAC0

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
process_tags(struct t_cose_mac_validate_ctx *me,
             QCBORDecodeContext             *decode_context)
{
    /* Aproximate stack usage
     *                  64-bit      32-bit
     *   local vars     20          16
     *   TOTAL          20          16
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
        if(uTag != CBOR_TAG_COSE_MAC0) {
            return T_COSE_ERR_INCORRECTLY_TAGGED;
        }
    }
    if(me->option_flags & T_COSE_OPT_TAG_PROHIBITED) {
        /* The protocol that is using COSE says the input CBOR must
         * not be a COSE tag.
         */
        if(uTag == CBOR_TAG_COSE_MAC0) {
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

    if(uTag != CBOR_TAG_COSE_MAC0) {
        /* Never return the tag that this code is about to process. Note
         * that you can sign a COSE_MAC0 recursively. This only takes out
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

/**
 * \file t_cose_mac_validate.c
 *
 * \brief This verifies t_cose Mac authentication structure without a recipient
 *        structure.
 *        Only HMAC is supported so far.
 */

/*
 * Public function. See t_cose_mac.h
 */
enum t_cose_err_t
t_cose_mac_validate_private(struct t_cose_mac_validate_ctx *context,
                            struct q_useful_buf_c           cose_mac,
                            struct q_useful_buf_c           aad,
                            bool                            payload_is_detached,
                            struct q_useful_buf_c          *payload,
                            struct t_cose_parameter       **return_params)
{
    (void)payload_is_detached;
  
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
    struct t_cose_sign_inputs    sign_input;


    *payload = NULL_Q_USEFUL_BUF_C;
    decoded_params = NULL; // TODO: check that this is right and necessary

    QCBORDecode_Init(&decode_context, cose_mac, QCBOR_DECODE_MODE_NORMAL);

    /* --- The array of 4 and tags --- */
    QCBORDecode_EnterArray(&decode_context, NULL);
    return_value = qcbor_decode_error_to_t_cose_error(
                                        QCBORDecode_GetError(&decode_context),
                                        T_COSE_ERR_MAC0_FORMAT);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    return_value = process_tags(context, &decode_context);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    const struct t_cose_header_location l = {0,0};
    /* --- The protected parameters --- */
    t_cose_headers_decode(&decode_context,
                          l,
                          NULL,
                          NULL,
                          &context->parameter_storage,
                          &decoded_params,
                          &protected_parameters);

    /* --- The payload --- */
    if (payload_is_detached) {
        /* detached payload: the payload should be set by caller */
        QCBORDecode_GetNull(&decode_context);
    }
    else {
        QCBORDecode_GetByteString(&decode_context, payload);
    }

    /* --- The tag --- */
    QCBORDecode_GetByteString(&decode_context, &tag);

    /* --- Finish up the CBOR decode --- */
    QCBORDecode_ExitArray(&decode_context);

    /* This check make sure the array only had the expected four
     * items. It works for definite and indefinte length arrays. Also
     * makes sure there were no extra bytes. Also that the payload
     * and signature were decoded correctly. */
    qcbor_error = QCBORDecode_Finish(&decode_context);
    return_value = qcbor_decode_error_to_t_cose_error(qcbor_error,
                                                      T_COSE_ERR_MAC0_FORMAT);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* === End of the decoding of the array of four === */
    if((context->option_flags & T_COSE_OPT_REQUIRE_KID) &&
        q_useful_buf_c_is_null(t_cose_find_parameter_kid(decoded_params))) {
        return_value = T_COSE_ERR_NO_KID;
        goto Done;
    }

    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* -- Skip tag verification if requested --*/
    if(context->option_flags & T_COSE_OPT_DECODE_ONLY) {
        return_value = T_COSE_SUCCESS;
        goto Done;
    }

    /* -- Compute the ToBeMaced -- */
    sign_input.aad = aad;
    sign_input.payload = *payload;
    sign_input.body_protected = protected_parameters;
    sign_input.sign_protected = NULL_Q_USEFUL_BUF_C; /* Never sign-protected for MAC */
    return_value = create_tbm(&sign_input,
                              tbm_first_part_buf,
                              &tbm_first_part);
    if(return_value) {
        goto Done;
    }

    /*
     * Start the HMAC verification.
     * Calculate the tag of the first part of ToBeMaced and the wrapped
     * payload, to save a bigger buffer containing the entire ToBeMaced.
     */
    return_value = t_cose_crypto_hmac_validate_setup(&hmac_ctx,
                                  t_cose_find_parameter_alg_id(decoded_params),
                                  context->verification_key);
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

Done:
    if(return_params != NULL) {
        *return_params = decoded_params;
    }

    return return_value;
}

#else /* !T_COSE_DISABLE_MAC0 */

/* So some of the build checks don't get confused by an empty object file */
void t_cose_mac_validate_placeholder(void)
{}

#endif /* !T_COSE_DISABLE_MAC0 */
