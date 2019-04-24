/*
 *  t_cose_sign1_verify.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md.
 */


#include "t_cose_sign1_verify.h"
#include "qcbor.h"
#include "t_cose_crypto.h"
#include "t_cose_defines.h"
#include "q_useful_buf.h"
#include "t_cose_util.h"
#include <stdbool.h>
#include "qcbor_util.h"


/**
 * \file t_cose_sign1_verify.c
 *
 * \brief \c COSE_Sign1 verification implementation.
 */


/**
 *  \brief Verify a short-circuit signature
 *
 * \param[in] cose_alg_id     The COSE signature algorithm to use.
 * \param[in] hash_to_verify  Pointer and length of hash to verify.
 * \param[in] signature       Pointer and length of signature
 *
 * \return This returns one of the error codes defined by \ref
 *         t_cose_err_t.
 *
 * See t_cose_sign1_init() for description of the short-circuit
 * signature.
 */
static inline enum t_cose_err_t
t_cose_crypto_short_circuit_verify(int32_t cose_alg_id,
                                   struct q_useful_buf_c hash_to_verify,
                                   struct q_useful_buf_c signature)
{
    struct q_useful_buf_c hash_from_sig;
    enum t_cose_err_t   return_value;

    (void)cose_alg_id; /* unused variable */

    hash_from_sig = q_useful_buf_head(signature, hash_to_verify.len);
    if(q_useful_buf_c_is_null(hash_from_sig)) {
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    }

    if(q_useful_buf_compare(hash_from_sig, hash_to_verify)) {
        return_value = T_COSE_ERR_SIG_VERIFY;
    } else {
        return_value = T_COSE_SUCCESS;
    }

Done:
    return return_value;
}




/**
 * \brief Parse the unprotected headers.
 *
 * \param[in] protected_headers Pointer and length of CBOR-encoded
 *                              protected headers to parse.
 * \param[out] cose_alg_id      Place to return the COSE algorithm ID
 *
 * \returns 0 on success, non-zero on failure.
 *
 * This parses the contents of the protected headers after the bstr
 * wrapping is removed.  It only looks for the COSE algorithm ID and
 * ignores any other headers.
 *
 * This will error out if the CBOR is not well-formed, the protected
 * headers are not a map the algorithm ID is not found, or the
 * algorithm ID is larger than \c INT32_MAX or smaller than \c
 * INT32_MIN.
 */
static int parse_protected_headers(struct q_useful_buf_c protected_headers,
                                   int32_t *cose_alg_id)
{
    QCBORDecodeContext  decode_context;
    QCBORItem           item;

    QCBORDecode_Init(&decode_context, protected_headers, 0);

    if(qcbor_util_get_item_in_map(&decode_context,
                                 COSE_HEADER_PARAM_ALG,
                                 &item)) {
        return 1;
    }

    if(QCBORDecode_Finish(&decode_context)) {
        return 1;
    }

    if(item.uDataType != QCBOR_TYPE_INT64 || item.val.int64 > INT32_MAX) {
        return 1;
    }

    *cose_alg_id = (int32_t)item.val.int64;

    return 0;
}


/**
 * \brief Parse the unprotected COSE header to find the kid
 *
 * \param[in,out] decode_context The CBOR decoding context to read the
 *                               unprotected headers from.
 * \param[out] kid               Pointer and length of the kid found.
 *                               The storage for the kid is whatever was
 *                               passed to the decoder.
 *
 * \retval -1
 *         CBOR was not well-formed
 * \retval 0
 *         Success
 * \retval 1
 *         Was not a CBOR map or no kid was found
 *
 * This will consume the entire map containing the unprotected
 * headers. Any headers except the kid will be ignored.
 */
static int parse_unprotected_headers(QCBORDecodeContext *decode_context,
                                     struct q_useful_buf_c *kid)
{
    struct qcbor_util_items_to_get_t   items[2];
    int                     return_value;

    items[0].label = COSE_HEADER_PARAM_KID; /* kid */
    items[1].label = 0; /* terminate list */

    return_value = qcbor_util_get_items_in_map(decode_context, items);
    if(return_value) {
        goto Done;
    }

    /* did we get a proper kid */
    if(items[0].item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        /* have to get a kid, or is it fail */
        return_value = 1;
        goto Done;
    }

    *kid = items[0].item.val.string;

Done:
    return return_value; /* have to get a kid, or is it fail */
}


/*
 * Public function. See t_cose_sign1_verify.h
 */
enum t_cose_err_t t_cose_sign1_verify(int32_t option_flags,
                                      int32_t key_select,
                                      struct q_useful_buf_c cose_sign1,
                                      struct q_useful_buf_c *payload)
{
    QCBORDecodeContext            decode_context;
    QCBORItem                     item;
    struct q_useful_buf_c         protected_headers;
    int32_t                       cose_algorithm_id;
    struct q_useful_buf_c         kid;
    enum t_cose_err_t             return_value;
    int                           result;
    /* Buffer for the tbs hash. Only big enough for SHA256 */
    Q_USEFUL_BUF_MAKE_STACK_UB(   buffer_for_tbs_hash,
                                      T_COSE_CRYPTO_SHA256_SIZE);
    struct q_useful_buf_c         tbs_hash;
    struct q_useful_buf_c         signature;
    Q_USEFUL_BUF_MAKE_STACK_UB   (buf_for_short_circuit_kid,
                                      T_COSE_SHORT_CIRCUIT_KID_SIZE);
    struct q_useful_buf_c         short_circuit_kid;

    *payload = NULL_Q_USEFUL_BUF_C;

    QCBORDecode_Init(&decode_context, cose_sign1, QCBOR_DECODE_MODE_NORMAL);

    /* --  The array of four -- */
    QCBORDecode_GetNext(&decode_context, &item);
    if(item.uDataType != QCBOR_TYPE_ARRAY || item.val.uCount != 4 ||
       !QCBORDecode_IsTagged(&decode_context, &item, CBOR_TAG_COSE_SIGN1)) {
        return_value = T_COSE_ERR_SIGN1_FORMAT;
        goto Done;
    }


    /* --  Get the protected headers -- */
    QCBORDecode_GetNext(&decode_context, &item);
    if(item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return_value = T_COSE_ERR_SIGN1_FORMAT;
        goto Done;
    }

    protected_headers = item.val.string;

    result = parse_protected_headers(protected_headers, &cose_algorithm_id);
    if(result == -1) {
        return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    } else if (result == 1) {
        return_value = T_COSE_ERR_NO_ALG_ID;
        goto Done;
    }

    /* --  Get the unprotected headers -- */
    result = parse_unprotected_headers(&decode_context, &kid);
    if(result == -1) {
        return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    } else if (result == 1) {
        return_value = T_COSE_ERR_NO_KID;
        goto Done;
    }


    /* -- Get the payload -- */
    QCBORDecode_GetNext(&decode_context, &item);
    if(item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return_value = T_COSE_ERR_SIGN1_FORMAT;
        goto Done;
    }
    *payload = item.val.string;


    /* -- Get the signature -- */
    QCBORDecode_GetNext(&decode_context, &item);
    if(item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return_value = T_COSE_ERR_SIGN1_FORMAT;
        goto Done;
    }
    signature = item.val.string;


    /* -- Compute the TBS bytes -- */
    return_value = create_tbs_hash(cose_algorithm_id,
                                   buffer_for_tbs_hash,
                                   &tbs_hash,
                                   protected_headers,
                                   T_COSE_TBS_BARE_PAYLOAD,
                                   *payload);
    if(return_value) {
        goto Done;
    }


    /* -- Check for short-circuit signature and verify if it exists -- */
    return_value = get_short_circuit_kid(buf_for_short_circuit_kid,
                                           &short_circuit_kid);
    if(!return_value && !q_useful_buf_compare(kid, short_circuit_kid)) {
        if(!(option_flags & T_COSE_OPT_ALLOW_SHORT_CIRCUIT)) {
            return_value = T_COSE_ERR_SHORT_CIRCUIT_SIG;
            goto Done;
        }

        return_value = t_cose_crypto_short_circuit_verify(cose_algorithm_id,
                                                          tbs_hash,
                                                          signature);
        goto Done;
    }


    /* -- Verify the signature -- */
    return_value = t_cose_crypto_pub_key_verify(cose_algorithm_id,
                                                key_select,
                                                kid,
                                                tbs_hash,
                                                signature);

Done:
    return return_value;
}
