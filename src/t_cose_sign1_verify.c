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


static inline QCBORError
consume_item(QCBORDecodeContext *decode_context,
             const QCBORItem    *item_to_consume,
             uint_fast8_t       *next_nest_level)
{
    /* Stack use: 4 + 56 = 60 */
    QCBORError return_value;
    QCBORItem  item;

    if(item_to_consume->uDataType == QCBOR_TYPE_MAP ||
       item_to_consume->uDataType == QCBOR_TYPE_ARRAY) {
        /* There is only real work to do for maps and arrays */

        /* This works for definite and indefinite length
         * maps and arrays by using the nesting level
         */
        do {
            return_value = QCBORDecode_GetNext(decode_context, &item);
            if(return_value != QCBOR_SUCCESS) {
                goto Done;
            }
        } while(item.uNextNestLevel >= item_to_consume->uNextNestLevel);

        *next_nest_level = item.uNextNestLevel;
        return_value = QCBOR_SUCCESS;

    } else {
        /* item_to_consume is not a map or array */
        /* Just pass the nesting level through */
        *next_nest_level = item_to_consume->uNextNestLevel;
        return_value = QCBOR_SUCCESS;
    }

Done:
    return return_value;
}


/*
 Size on 64-bit machine: 4 + (4 * 16) + 4pad = 72
 Size on 32-bit machine: 4 + (4 * 8) = 36
 */
struct t_cose_headers {
    int32_t               cose_alg_id; // TODO: text versions of this
    struct q_useful_buf_c kid;
    struct q_useful_buf_c iv;
    struct q_useful_buf_c partial_iv;
    struct q_useful_buf_c content_type; // TODO: integer versions of this
};


/* A list of COSE headers labels, both integer and string.

   It is fixed size to avoid the complexity of memory management
   and because the number of headers is assumed to be small.

   On a 64-bit machine it is 24 * HEADER_LIST_MAX which is
   244 bytes. That accommodates 10 string headers and 10
 integer headers and is small enough to go on the stack.

 On a 32-bit machine: 16 * HEADER_LIST_MAX = 176

 */
#define HEADER_LIST_MAX 11  // 10 slots plus a list terminator
#define HEADER_ALG_LIST_TERMINATOR 0 // TODO: check this is an invalid alg ID
struct t_cose_header_list {
    // Terminated by value HEADER_ALG_LIST_TERMINATOR
    uint64_t int_headers[HEADER_LIST_MAX];
    // Terminated by a NULL_Q_USEFUL_BUF_C
    struct q_useful_buf_c tstr_headers[HEADER_LIST_MAX];
};


static void clear_header_list(struct t_cose_header_list *list)
{
    // TODO: is this initialization good for int_headers?
    memset(list, 0, sizeof(struct t_cose_header_list));
}


/*
 Parse the header that contains the list of critical headers and return
 the list of critical headers.
 */
enum t_cose_err_t parse_critical_headers(QCBORDecodeContext *decode_context,
                                         struct t_cose_header_list *critical_headers)
{
    /* Stack use 64-bit: 56 + 12 = 68 */
    QCBORItem         item;
    uint_fast8_t      num_int_headers;
    uint_fast8_t      num_tstr_headers;
    enum t_cose_err_t return_value;
    QCBORError        cbor_result;
    uint_fast8_t      nest_level;

    clear_header_list(critical_headers);
    num_int_headers  = 0;
    num_tstr_headers = 0;

    nest_level = 0;

    while(1) {
        cbor_result = QCBORDecode_GetNext(decode_context, &item);
        if(cbor_result != QCBOR_SUCCESS) {
            return_value = 999;
            goto Done;
        }
        if(nest_level == 0) {
            // Record nesting level of first item
            // When nesting level is not this
            // then at end of array.
            nest_level = item.uNestingLevel;
        }

        if(item.uDataType == QCBOR_TYPE_INT64) {
            if(num_int_headers == HEADER_LIST_MAX) {
                return_value = 99; // Too many
                goto Done;
            }
            critical_headers->int_headers[num_int_headers++] = item.val.int64;
        } else if(item.uDataType == QCBOR_TYPE_BYTE_STRING) {
            if(num_tstr_headers == HEADER_LIST_MAX) {
                return_value = 99; // Too many
                goto Done;
            }
            critical_headers->tstr_headers[num_tstr_headers++] = item.val.string;
        } else {
            return_value = 888; // Wrong type
            goto Done;
        }

        if(nest_level != item.uNestingLevel) {
            /* Successful exit from the loop */
            // TODO:....
            return_value = T_COSE_SUCCESS;
            break;
        }
    }

Done:
    return return_value;
}

/*

 Return an error if one headers in the unknown list is in the critical headers list.
 */
static inline enum t_cose_err_t check_critical_headers(const struct t_cose_header_list *critical_headers, const struct t_cose_header_list *unknown_headers)
{
    enum t_cose_err_t return_value;
    uint_fast8_t      num_unknown_headers;
    uint_fast8_t      num_critical_headers;

    /* Assume success until an unhandled critical headers is found */
    return_value = T_COSE_SUCCESS;

    // Iterate over integer unknown headers
    for(num_unknown_headers = 0; unknown_headers->int_headers[num_unknown_headers]; num_unknown_headers++) {
        // iterate over critical integer headers looking for the unknown header
        for(num_critical_headers = 0; critical_headers->int_headers[num_critical_headers]; num_critical_headers++) {
            if(critical_headers->int_headers[num_critical_headers] == unknown_headers->int_headers[num_unknown_headers]) {
                return_value = 3989384;
                goto Done;
            }
        }
        /* Normal exit from loop means unknown header wasn't critical */
    }

    // Iterate over string unknown headers
    for(num_unknown_headers = 0; !q_useful_buf_c_is_null(unknown_headers->tstr_headers[num_unknown_headers]); num_unknown_headers++) {
        // iterate over critical integer headers looking for the unknown header
        for(num_critical_headers = 0; !q_useful_buf_c_is_null(critical_headers->tstr_headers[num_critical_headers]); num_critical_headers++) {
            if(!q_useful_buf_compare(critical_headers->tstr_headers[num_critical_headers], unknown_headers->tstr_headers[num_unknown_headers])) {
                return_value = 3989384;
                goto Done;
            }
        }
        /* Normal exit from loop means unknown header wasn't critical */
    }

Done:
    return return_value;
}


static inline enum t_cose_err_t add_header_label_to_list(const QCBORItem *item, struct t_cose_header_list *header_list)
{
    enum t_cose_err_t return_value;
    uint_fast8_t      num_headers;

    /* Assume success until an error adding is encountered. */
    return_value = T_COSE_SUCCESS;

    if(item->uDataType == QCBOR_TYPE_INT64) {
        /* Add an integer-labeled header to the end of the list */
        for(num_headers = 0; header_list->int_headers[num_headers]; num_headers++);
        if(num_headers == HEADER_LIST_MAX) {
            /* List is full -- error out */
            return_value = 999;
            goto Done;
        }
        header_list->int_headers[num_headers] = item->val.int64;

    } else if(item->uDataType == QCBOR_TYPE_BYTE_STRING) {
        /* Add a string-labeled header to the end of the list */
        for(num_headers = 0; !q_useful_buf_c_is_null(header_list->tstr_headers[num_headers]); num_headers++);
        if(num_headers == HEADER_LIST_MAX) {
            /* List is full -- error out */
            return_value = 999;
            goto Done;
        }
        header_list->tstr_headers[num_headers] = item->val.string;
    } else {
        /* error because header is neither integer or string */
        return_value = 9999;
    }

Done:
    return return_value;
}


static enum t_cose_err_t process_unknown_header(QCBORDecodeContext *decode_context,
                                                const QCBORItem *unknown_header,
                                                struct t_cose_header_list *unknown_headers,
                                                uint_fast8_t *next_nest_level)
{
    enum t_cose_err_t return_value;

    return_value = add_header_label_to_list(unknown_header, unknown_headers);
    if(return_value) { // TODO:
        goto Done;
    }
    /* The unknown header must be consumed. It could be
     complex deeply-nested CBOR */
    if(consume_item(decode_context, unknown_header, next_nest_level)) {
        return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }

Done:
    return return_value;
}


static enum t_cose_err_t parse_cose_headers(QCBORDecodeContext *decode_context,
                              struct t_cose_headers *returned_headers)
{
    /* Stack use 64-bit: 56 + 1 + 1 + 1 + 244 = 304
       Stack use 32-bit: 32 + 1 + 1 + 1 + 176 = 212 */
    QCBORItem                 item;
    enum t_cose_err_t         return_value;
    uint_fast8_t              map_nest_level;
    uint_fast8_t              next_nest_level;
    struct t_cose_header_list unknown_headers, critical_headers;


    // clear usefulbufs to NULL and algorithm ID to COSE_ALGORITHM_INVALID
#if COSE_ALGORITHM_INVALID != 0
#error Invalid algorithm designator not 0. Header list initialization fails.
#endif
    memset(returned_headers, 0, sizeof(struct t_cose_headers));

    clear_header_list(&unknown_headers);

    /* This assumes the next thing to decode is the map
     */
    /* Get the data item that is the map that is being searched */
    QCBORDecode_GetNext(decode_context, &item);
    if(item.uDataType != QCBOR_TYPE_MAP) {
        return_value = 88; // TODO: proper error cod
        goto Done;
    }

    /* Loop over all the items in the map. They could be
     * deeply nested and this should handle both definite
     * and indefinite length maps and arrays, so this
     * adds some complexity. */
    map_nest_level = item.uNextNestLevel;

    while(1) {
        if(QCBORDecode_GetNext(decode_context, &item) != QCBOR_SUCCESS) {
            /* Got non-well-formed CBOR */
            return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
            goto Done;
        }

        if(item.uLabelType != QCBOR_TYPE_INT64) {
            // Non integer label. We don't handle those...
            return_value = process_unknown_header(decode_context, &item, &unknown_headers, &next_nest_level);
            if(return_value) {
                goto Done;
            }

        } else {
            next_nest_level = item.uNextNestLevel;
            switch(item.label.int64) {

                case COSE_HEADER_PARAM_ALG:
                    if(item.uDataType != QCBOR_TYPE_INT64) {
                        return_value = 99; // TODO: error -- can't handle text string alg IDs
                        goto Done;
                    }
                    returned_headers->cose_alg_id = (int32_t)item.val.int64; // todo: test for overflow
                    break;

                case COSE_HEADER_PARAM_KID:
                    if(item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                        return_value = 99; // TODO:
                        goto Done;
                    }
                    returned_headers->kid = item.val.string;
                    break;

                case COSE_HEADER_PARAM_IV:
                    if(item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                        return_value = 99; // TODO:
                        goto Done;
                    }
                    returned_headers->iv = item.val.string;
                    break;

                case COSE_HEADER_PARAM_PARTIAL_IV:
                    if(item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                        return_value = 99; // TODO:
                        goto Done;
                    }
                    returned_headers->iv = item.val.string;
                    break;

                case COSE_HEADER_PARAM_CRIT:
                    if(item.uDataType != QCBOR_TYPE_ARRAY) {
                        return_value = 99; // TODO:
                        goto Done;
                    }
                    return_value = parse_critical_headers(decode_context, &critical_headers);
                    if(return_value != 3) { // TODO:
                        goto Done;
                    }

                default:
                    /* The header is not recognized. It has to be added to the
                       the list of unknown headers so it can be checked against
                       the list of critical headers */
                    return_value = process_unknown_header(decode_context, &item, &unknown_headers, &next_nest_level);

                    if(return_value) { // TODO:
                        goto Done;
                    }
            }
        }
        if(next_nest_level < map_nest_level) {
            /* Got all the items in the map. This is the non-error exit
             * from the loop. */

            /* Last thing to do is to check that there were
                no unknown critical headers
             */
            return_value = check_critical_headers(&critical_headers, &unknown_headers);
            break;
        }
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
 * \returns 0 on success, non-zero on failure. TODO: fix this
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
static enum t_cose_err_t parse_protected_headers(const struct q_useful_buf_c protected_headers,
                                                        int32_t *cose_alg_id)
{
    /* Stack use 64-bit: 144 + 72 + 1 = 217
     Stack use 32-bit:   108 + 36 + 1 = 145 */
    QCBORDecodeContext     decode_context;
    struct t_cose_headers  parsed_protected_headers;
    enum t_cose_err_t      return_value;

    QCBORDecode_Init(&decode_context, protected_headers, 0);

    return_value =  parse_cose_headers(&decode_context, &parsed_protected_headers);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(QCBORDecode_Finish(&decode_context)) {
        return_value = 99; // TODO: fix this
        goto Done;
    }

    if(parsed_protected_headers.cose_alg_id == COSE_ALGORITHM_INVALID ||
       parsed_protected_headers.cose_alg_id > INT32_MAX) {
        return 1; // TODO: error code
    }

    *cose_alg_id = (int32_t)parsed_protected_headers.cose_alg_id;
Done:
    return return_value;
}


/*
 * Public function. See t_cose_sign1_verify.h
 */
enum t_cose_err_t t_cose_sign1_verify(int32_t option_flags,
                                      int32_t key_select,
                                      struct q_useful_buf_c cose_sign1,
                                      struct q_useful_buf_c *payload)
{
    /* Stack use:
         144     108
          56      52
          16       8
           4       4
           8       4
          32      32
          16       8
          16       8
          32      32
          16       8
          72      36
         ---     ---
         396     300
     */
    QCBORDecodeContext            decode_context;
    QCBORItem                     item;
    struct q_useful_buf_c         protected_headers;
    int32_t                       cose_algorithm_id;
    enum t_cose_err_t             return_value;
    /* Buffer for the tbs hash. Only big enough for SHA256 */
    Q_USEFUL_BUF_MAKE_STACK_UB(   buffer_for_tbs_hash,
                                      T_COSE_CRYPTO_SHA256_SIZE);
    struct q_useful_buf_c         tbs_hash;
    struct q_useful_buf_c         signature;
    Q_USEFUL_BUF_MAKE_STACK_UB   (buf_for_short_circuit_kid,
                                      T_COSE_SHORT_CIRCUIT_KID_SIZE);
    struct q_useful_buf_c         short_circuit_kid;
    struct t_cose_headers         unprotected_headers;

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

    return_value = parse_protected_headers(protected_headers, &cose_algorithm_id);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --  Get the unprotected headers -- */
    return_value = parse_cose_headers(&decode_context, &unprotected_headers);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    } else if (q_useful_buf_c_is_null(unprotected_headers.kid)) {
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
    if(!return_value && !q_useful_buf_compare(unprotected_headers.kid, short_circuit_kid)) {
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
                                                unprotected_headers.kid,
                                                tbs_hash,
                                                signature);

Done:
    return return_value;
}
