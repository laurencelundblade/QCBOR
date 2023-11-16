/*
 * Copyright (c) 2018-2023, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2020-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor.h"
#include "t_cose/t_cose_mac_compute.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"
#include "t_cose_crypto.h"

/**
 * \file t_cose_mac_compute.c
 *
 * \brief This creates t_cose MAC authentication structure without a recipient
 *        structure.
 *        Only HMAC is supported so far.
 */


/*
 * Public function. See t_cose_mac_compute.h
 */
enum t_cose_err_t
t_cose_mac_encode_parameters(struct t_cose_mac_calculate_ctx *me,
                             QCBOREncodeContext              *cbor_encode_ctx)
{
    size_t                  tag_len;
    enum t_cose_err_t       return_value;
    struct t_cose_parameter param_storage[2];
    struct t_cose_parameter *p_tmp;

    /*
     * Check the algorithm now by getting the algorithm as an early
     * error check even though it is not used until later.
     */
    tag_len = t_cose_tag_size(me->cose_algorithm_id);
    if(tag_len == INT32_MAX) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    /* Add the CBOR tag indicating COSE_Mac0 */
    if(!(me->option_flags & T_COSE_OPT_OMIT_CBOR_TAG)) {
        QCBOREncode_AddTag(cbor_encode_ctx, CBOR_TAG_COSE_MAC0);
    }

    /*
     * Get started with the tagged array that holds the
     * parts of a COSE_Mac0 message
     */
    QCBOREncode_OpenArray(cbor_encode_ctx);

    param_storage[0] = t_cose_param_make_alg_id(me->cose_algorithm_id);
    if (!q_useful_buf_c_is_null(me->kid)) {
        param_storage[1] = t_cose_param_make_kid(me->kid);
        param_storage[0].next = &param_storage[1];
    }
    p_tmp = &param_storage[0];

    t_cose_params_append(&p_tmp, me->added_body_parameters);

    return_value = t_cose_headers_encode(cbor_encode_ctx,
                                         &param_storage[0],
                                         &me->protected_parameters);

    /*
     * Any failures in CBOR encoding will be caught in finish
     * when the CBOR encoding is closed off. No need to track
     * here as the CBOR encoder tracks it internally.
     */

    return return_value;
}

/*
 * Public function. See t_cose_mac_compute.h
 */
enum t_cose_err_t
t_cose_mac_encode_tag(struct t_cose_mac_calculate_ctx *me,
                      struct q_useful_buf_c            ext_sup_data,
                      struct q_useful_buf_c            payload,
                      QCBOREncodeContext              *cbor_encode_ctx)
{
    enum t_cose_err_t            return_value;
    QCBORError                   cbor_err;
    struct q_useful_buf_c        computed_mac_tag;
    Q_USEFUL_BUF_MAKE_STACK_UB(  mac_tag_buf,
                                 T_COSE_CRYPTO_HMAC_TAG_MAX_SIZE);
    struct t_cose_sign_inputs    mac_input;

    /*
     * Check that there are no CBOR encoding errors before proceeding
     * with hashing and tagging. This is not actually necessary as the
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

    if(QCBOREncode_IsBufferNULL(cbor_encode_ctx)) {
        /* Just calculating sizes. All that is needed is the tag size. */
        computed_mac_tag.ptr = NULL;
        computed_mac_tag.len = t_cose_tag_size(me->cose_algorithm_id);
        return_value = T_COSE_SUCCESS;
        goto CloseArray;
    }

    /*
     * Create the hash of the ToBeMaced bytes. Inputs to the
     * MAC are the protected parameters, the payload that is
     * getting MACed.
     */
    mac_input.ext_sup_data   = ext_sup_data;
    mac_input.payload        = payload;
    mac_input.body_protected = me->protected_parameters;
    mac_input.sign_protected = NULL_Q_USEFUL_BUF_C; /* Never sign-protected for MAC */

    return_value = create_tbm(me->cose_algorithm_id, /* in: algorithm ID*/
                              me->mac_key, /* in: key */
                              true,        /* in: is_mac0 (MAC vs MAC0) */
                             &mac_input,   /* in: struct of all TBM inputs */
                              mac_tag_buf, /* in: buffer to output to */
                             &computed_mac_tag); /* out: the computed MAC tag */
    if(return_value) {
        goto Done;
    }

CloseArray:
    /* Add tag to CBOR and close out the array */
    QCBOREncode_AddBytes(cbor_encode_ctx, computed_mac_tag);
    QCBOREncode_CloseArray(cbor_encode_ctx);

    /* CBOR encoding errors are tracked in the CBOR encoding context
     * and handled in the layer above this
     */

Done:
    return return_value;
}

/*
 * Semi-private function. See t_cose_mac_compute.h
 */
enum t_cose_err_t
t_cose_mac_compute_private(struct t_cose_mac_calculate_ctx *me,
                           bool                             payload_is_detached,
                           struct q_useful_buf_c            ext_sup_data,
                           struct q_useful_buf_c            payload,
                           struct q_useful_buf              out_buf,
                           struct q_useful_buf_c           *result)
{
    QCBOREncodeContext  encode_ctx;
    enum t_cose_err_t   return_value;

    /* -- Initialize CBOR encoder context with output buffer -- */
    QCBOREncode_Init(&encode_ctx, out_buf);

    /* -- Output the header parameters into the encoder context -- */
    return_value = t_cose_mac_encode_parameters(me, &encode_ctx);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(payload_is_detached) {
        /* detached: the payload should be transfered in another channel */
        QCBOREncode_AddNULL(&encode_ctx);
    } else {
        /* --- Get started on the payload --- */
        QCBOREncode_AddBytes(&encode_ctx, payload);
    }

    return_value = t_cose_mac_encode_tag(me, ext_sup_data, payload, &encode_ctx);
    if(return_value) {
        goto Done;
    }

    /* -- Close off and get the resulting encoded CBOR -- */
    if(QCBOREncode_Finish(&encode_ctx, result)) {
        return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }

Done:
    return return_value;
}
