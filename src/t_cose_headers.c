/*
 * t_cose_headers.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose_headers.h"
#include "t_cose_standard_constants.h"


/**
 * \brief Consume a CBOR map or array.
 *
 * \param[in] decode_context  Context to read data items from.
 * \param[in] item_to_consume The already-read item that is being consumed.
 * \param[out] next_nest_level Nesting level of the next item that will be read.
 *
 * \returns A CBOR decoding error or QCBOR_SUCCESS.
 *
 * The primary purpose of this is to consume (read) all the members of
 * a map or an array, however deeply nested it is.
 *
 * This doesn't do much work for non-nested data items.
 */
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




/**
 * A list of COSE headers labels, both integer and string.
 *
 * It is fixed size to avoid the complexity of memory management and
 * because the number of headers is assumed to be small.
 *
 * On a 64-bit machine it is 24 * HEADER_LIST_MAX which is 244
 * bytes. That accommodates 10 string headers and 10 integer headers
 * and is small enough to go on the stack.
 *
 * On a 32-bit machine: 16 * HEADER_LIST_MAX = 176
 *
 * This is a big consumer of stack in this implementation.  Some
 * cleverness with a union could save almost 200 bytes of stack, as
 * this is on the stack twice.
*/
struct t_cose_header_list {
    /* Terminated by value HEADER_ALG_LIST_TERMINATOR */
    int64_t int_header_labels[T_COSE_HEADER_LIST_MAX+1];
    /*  Terminated by a NULL_Q_USEFUL_BUF_C */
    struct q_useful_buf_c tstr_header_labels[T_COSE_HEADER_LIST_MAX+1];
};


/*
 * The IANA COSE Header Parameters registry lists label 0 as
 * "reserved". This means it can be used, but only by a revision of
 * the COSE standard if it is deemed necessary for some large and good
 * reason. It cannot just be allocated by IANA as any normal
 * assignment. See [IANA COSE Registry]
 * (https://www.iana.org/assignments/cose/cose.xhtml).  It is thus
 * considered safe to use as the list terminator.
 */
#define HEADER_ALG_LIST_TERMINATOR 0


/**
 * \brief Clear a header list to empty.
 *
 * \param[in,out] list The list to clear.
 */
static void inline
clear_header_list(struct t_cose_header_list *list)
{
    memset(list, 0, sizeof(struct t_cose_header_list));
}


/**
 * \brief Add a new header to the end of the header list.
 *
 * \param[in] item             Data item to add to the header list.
 * \param[in,out] header_list  The list to add to.
 *
 * \retval T_COSE_SUCCESS If added correctly.
 * \retval T_COSE_ERR_TOO_MANY_HEADERS  Header list is full.
 * \retval T_COSE_ERR_HEADER_CBOR  The item to add doesn't have a label type that is understood
 *
 * The label / key from \c item is added to \c header_list.
 */
static inline enum t_cose_err_t
add_header_label_to_list(const QCBORItem           *item,
                         struct t_cose_header_list *header_list)
{
    enum t_cose_err_t return_value;
    uint_fast8_t      num_headers;

    /* Assume success until an error adding is encountered. */
    return_value = T_COSE_SUCCESS;

    if(item->uLabelType == QCBOR_TYPE_INT64) {
        /* Add an integer-labeled header to the end of the list */
        for(num_headers = 0; header_list->int_header_labels[num_headers] != HEADER_ALG_LIST_TERMINATOR; num_headers++);
        if(num_headers == T_COSE_HEADER_LIST_MAX+1) {
            /* List is full -- error out */
            return_value = T_COSE_ERR_TOO_MANY_HEADERS;
            goto Done;
        }
        header_list->int_header_labels[num_headers] = item->label.int64;

    } else if(item->uLabelType == QCBOR_TYPE_BYTE_STRING) {
        /* Add a string-labeled header to the end of the list */
        for(num_headers = 0; !q_useful_buf_c_is_null(header_list->tstr_header_labels[num_headers]); num_headers++);
        if(num_headers == T_COSE_HEADER_LIST_MAX+1) {
            /* List is full -- error out */
            return_value = T_COSE_ERR_TOO_MANY_HEADERS;
            goto Done;
        }
        header_list->tstr_header_labels[num_headers] = item->label.string;
    } else {
        /* error because header is neither integer or string */
        return_value = T_COSE_ERR_HEADER_CBOR;
    }

Done:
    return return_value;
}




/**
 * \brief Decodes the header containing the labels of headers considered critical.
 *
 * \param[in,out]  decode_context          The decode context to read critical header list from.
 * \param[out]     critical_header_labels  List of labels of critical headers.
 *
 * \retval T_COSE_ERR_CBOR_NOT_WELL_FORMED Undecodable CBOR.
 * \retval T_COSE_ERR_TOO_MANY_HEADERS  More critical headers than this implementation can handle.
 * \retval T_COSE_ERR_CBOR_STRUCTURE  CBOR data type of listed header is not int or string.
 */
static inline enum t_cose_err_t
decode_critical_headers(QCBORDecodeContext       *decode_context,
                       const QCBORItem           *crit_header_item,
                       struct t_cose_header_list *critical_header_labels,
                       uint_fast8_t              *return_next_nest_level)
{
    /* Stack use 64-bit: 56 + 40 = 96
     *           32-bit: 52 + 20 = 72
     */
    QCBORItem         item;
    uint_fast8_t      num_int_headers;
    uint_fast8_t      num_tstr_headers;
    enum t_cose_err_t return_value;
    QCBORError        cbor_result;
    uint_fast8_t      next_nest_level;
    uint_fast8_t      array_nest_level;

    clear_header_list(critical_header_labels);
    num_int_headers  = 0;
    num_tstr_headers = 0;

    array_nest_level = crit_header_item->uNestingLevel;
    next_nest_level  = crit_header_item->uNextNestLevel;

    if(crit_header_item->uDataType != QCBOR_TYPE_ARRAY) {
        return_value = T_COSE_ERR_HEADER_CBOR;
        goto Done;
    }

    while(next_nest_level > array_nest_level) {
        cbor_result = QCBORDecode_GetNext(decode_context, &item);
        if(cbor_result != QCBOR_SUCCESS) {
            return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
            goto Done;
        }

        if(item.uDataType == QCBOR_TYPE_INT64) {
            if(num_int_headers == T_COSE_HEADER_LIST_MAX+1) {
                return_value = T_COSE_ERR_TOO_MANY_HEADERS;
                goto Done;
            }
            critical_header_labels->int_header_labels[num_int_headers++] = item.val.int64;
        } else if(item.uDataType == QCBOR_TYPE_BYTE_STRING) {
            if(num_tstr_headers == T_COSE_HEADER_LIST_MAX+1) {
                return_value = T_COSE_ERR_TOO_MANY_HEADERS;
                goto Done;
            }
            critical_header_labels->tstr_header_labels[num_tstr_headers++] = item.val.string;
        } else {
            return_value = T_COSE_ERR_HEADER_CBOR;
            goto Done;
        }
        next_nest_level = item.uNextNestLevel;
    }

    return_value = T_COSE_SUCCESS;

Done:
    *return_next_nest_level = next_nest_level;
    return return_value;
}


/**
 * \brief Check the unknown headers against the critical header list.
 *
 * \param[in] critical_headers The list of critical headers.
 * \param[in] unknown_headers  The unknown headers that occurred.
 *
 * \retval T_COSE_SUCCESS None of the unknown headers are critical.
 * \retval T_COSE_UNKNOWN_CRITICAL_HEADER At least one of the unknown headers is critical.
 *
 * Both lists are of header labels (CBOR keys). Check to see none of
 * the header labels in the unknown list occur in the critical list.
 */
static inline enum t_cose_err_t
check_critical_headers(const struct t_cose_header_list *critical_headers,
                       const struct t_cose_header_list *unknown_headers)
{
    enum t_cose_err_t return_value;
    uint_fast8_t      num_unknown_headers;
    uint_fast8_t      num_critical_headers;

    /* Assume success until an unhandled critical headers is found */
    return_value = T_COSE_SUCCESS;

    /* Iterate over unknown integer headers */
    for(num_unknown_headers = 0; unknown_headers->int_header_labels[num_unknown_headers]; num_unknown_headers++) {
        /* iterate over critical integer headers looking for the unknown header */
        for(num_critical_headers = 0; critical_headers->int_header_labels[num_critical_headers]; num_critical_headers++) {
            if(critical_headers->int_header_labels[num_critical_headers] == unknown_headers->int_header_labels[num_unknown_headers]) {
                /* Found a critical header that is unknown to us */
                return_value = T_COSE_ERR_UNKNOWN_CRITICAL_HEADER;
                goto Done;
            }
        }
        /* Normal exit from loop here means all unknown headers were not critical */
    }

    /* Iterate over unknown string headers */
    for(num_unknown_headers = 0; !q_useful_buf_c_is_null(unknown_headers->tstr_header_labels[num_unknown_headers]); num_unknown_headers++) {
        /* iterate over critical string headers looking for the unknown header */
        for(num_critical_headers = 0; !q_useful_buf_c_is_null(critical_headers->tstr_header_labels[num_critical_headers]); num_critical_headers++) {
            if(!q_useful_buf_compare(critical_headers->tstr_header_labels[num_critical_headers], unknown_headers->tstr_header_labels[num_unknown_headers])) {
                /* Found a critical header that is unknown to us */
                return_value = T_COSE_ERR_UNKNOWN_CRITICAL_HEADER;
                goto Done;
            }
        }
        /* Normal exit from loop here means all unknown headers were not critical */
    }

Done:
    return return_value;
}


/**
 * \brief Add unknown header to unknown header list and fully consume it
 *
 * \param[in] decode_context  CBOR decode context to read from
 * \param[in] unknown_header  The data item for the unknown header
 * \param[in,out] unknown_headers  The list of unknown headers to which to add this new unknown header to
 * \param[out] next_nest_level The nest level of the next item that will be fetched. Helps to know if at end of list.

 * \retval T_COSE_ERR_CBOR_NOT_WELL_FORMED  The CBOR is not well-formed.
 * \retval T_COSE_ERR_TOO_MANY_HEADERS  The unknown header list is full.
 * \retval T_COSE_ERR_CBOR_STRUCTURE The CBOR structure is not as expected.
 */
static enum t_cose_err_t
process_unknown_header(QCBORDecodeContext        *decode_context,
                       const QCBORItem           *unknown_header,
                       struct t_cose_header_list *unknown_headers,
                       uint_fast8_t              *next_nest_level)
{
    enum t_cose_err_t return_value;

    return_value = add_header_label_to_list(unknown_header, unknown_headers);
    if(return_value) {
        goto Done;
    }

    /* The full unknown header must be consumed. It could be
     complex deeply-nested CBOR */
    if(consume_item(decode_context, unknown_header, next_nest_level)) {
        return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
    }

Done:
    return return_value;
}




/**
 * \brief Clear a struct t_cose_headers to empty
 *
 * \param[in,out] headers  Header list to clear.
 */
static inline void clear_cose_headers(struct t_cose_headers *headers)
{
#if COSE_ALGORITHM_RESERVED != 0
#error Invalid algorithm designator not 0. Header list initialization fails.
#endif

    /* This clears all the useful bufs to NULL_Q_USEFUL_BUF_C
       and the cose_alg_id to COSE_ALGORITHM_RESERVED
     */
    memset(headers, 0, sizeof(struct t_cose_headers));

    /* The only non-zero clear-state value. (0 is plain text in CoAP content format) */
    headers->content_type_uint =  T_COSE_EMPTY_UINT_CONTENT_TYPE;
}


/**
 * Public function. See t_cose_headers.h
 */
enum t_cose_err_t
parse_cose_headers(QCBORDecodeContext    *decode_context,
                   struct t_cose_headers *returned_headers)
{
    /* Local stack use 64-bit: 56 + 24 + 488 = 568
     * Local stack use 32-bit: 52 + 12 + 352 = 414
     * Total stack use 64-bit: 568 + 96 + 50 = 694
     * Total stack use 32-bit: 414 + 72 + 25 = 501
     */
    QCBORItem                 item;
    enum t_cose_err_t         return_value;
    uint_fast8_t              map_nest_level;
    uint_fast8_t              next_nest_level;
    struct t_cose_header_list unknown_headers;
    struct t_cose_header_list critical_headers;

    clear_cose_headers(returned_headers);
    clear_header_list(&unknown_headers);
    clear_header_list(&critical_headers);

    /* Get the data item that is the map that is being searched */
    QCBORDecode_GetNext(decode_context, &item);
    if(item.uDataType != QCBOR_TYPE_MAP) {
        return_value = T_COSE_ERR_HEADER_CBOR;
        goto Done;
    }

    /* Loop over all the items in the map. The map may contain further
     * maps and arrays. This also needs to handle definite and
     * indefinite length maps and array.
     *
     * map_nest_level is the nesting level of the data item opening
     * the map that is being scanned. All data items inside this map
     * have a nesting level greater than it. The data item following
     * the map being scanned has a nesting level that is equal to or
     * higher than map_nest_level.
     */
    map_nest_level  = item.uNestingLevel;
    next_nest_level = item.uNextNestLevel;
    while(next_nest_level > map_nest_level) {

        if(QCBORDecode_GetNext(decode_context, &item) != QCBOR_SUCCESS) {
            /* Got not-well-formed CBOR */
            return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
            goto Done;
        }

        if(item.uLabelType != QCBOR_TYPE_INT64) {
            /* Non integer label. We don't handle those. */
            return_value = process_unknown_header(decode_context,
                                                  &item,
                                                  &unknown_headers,
                                                  &next_nest_level);
            if(return_value) {
                goto Done;
            }

        } else {
            next_nest_level = item.uNextNestLevel;
            switch(item.label.int64) {

                case COSE_HEADER_PARAM_ALG:
                    if(item.uDataType != QCBOR_TYPE_INT64) {
                        return_value = T_COSE_ERR_NON_INTEGER_ALG_ID;
                        goto Done;
                    }
                    if(item.val.int64 == COSE_ALGORITHM_RESERVED ||
                       item.val.int64 > INT32_MAX) {
                        return T_COSE_ERR_NON_INTEGER_ALG_ID;
                    }
                    returned_headers->cose_alg_id = (int32_t)item.val.int64;
                    break;

                case COSE_HEADER_PARAM_KID:
                    if(item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                        return_value = T_COSE_ERR_HEADER_CBOR;
                        goto Done;
                    }
                    returned_headers->kid = item.val.string;
                    break;

                case COSE_HEADER_PARAM_IV:
                    if(item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                        return_value = T_COSE_ERR_HEADER_CBOR;
                        goto Done;
                    }
                    returned_headers->iv = item.val.string;
                    break;

                case COSE_HEADER_PARAM_PARTIAL_IV:
                    if(item.uDataType != QCBOR_TYPE_BYTE_STRING) {
                        return_value = T_COSE_ERR_HEADER_CBOR;
                        goto Done;
                    }
                    returned_headers->iv = item.val.string;
                    break;

                case COSE_HEADER_PARAM_CRIT:
                    /* parse_critical_headers() consumes all the items in the critical headers array */
                    return_value = decode_critical_headers(decode_context,
                                                           &item,
                                                           &critical_headers,
                                                           &next_nest_level);
                    if(return_value) {
                        goto Done;
                    }

                case COSE_HEADER_PARAM_CONTENT_TYPE:
                    if(item.uDataType == QCBOR_TYPE_TEXT_STRING) {
                        returned_headers->content_type_tstr = item.val.string;
                    } else if(item.uDataType == QCBOR_TYPE_INT64) {
                        if(item.val.int64 < 0 || item.val.int64 > UINT16_MAX) {
                            return_value = T_COSE_ERR_BAD_CONTENT_TYPE;
                            goto Done;
                        }
                        returned_headers->content_type_uint = (uint32_t)item.val.int64;
                    } else {
                        return_value = T_COSE_ERR_BAD_CONTENT_TYPE;
                        goto Done;
                    }

                default:
                    /* The header is not recognized. It has to be
                     * added to the the list of unknown headers so it
                     * can be checked against the list of critical
                     * headers
                     */
                    return_value = process_unknown_header(decode_context,
                                                          &item,
                                                          &unknown_headers,
                                                          &next_nest_level);
                    if(return_value) {
                        goto Done;
                    }
            }
        }
    }
    return_value = check_critical_headers(&critical_headers, &unknown_headers);

Done:
    return return_value;
}


/**
 * Public function. See t_cose_headers.h
 */
enum t_cose_err_t
parse_protected_headers(const struct q_useful_buf_c protected_headers,
                        struct t_cose_headers      *parsed_protected_headers)
{
    /* Local stack use 64-bit: 144 + 8 = 152
     * Local stack use 32-bit: 108 + 4 = 112
     * Total stack use 64-bit: 694 + 144 = 838
     * Total stack use 32-bit: 501 + 112 = 613
     */
    QCBORDecodeContext decode_context;
    enum t_cose_err_t  return_value;

    QCBORDecode_Init(&decode_context, protected_headers, 0);

    return_value = parse_cose_headers(&decode_context, parsed_protected_headers);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(QCBORDecode_Finish(&decode_context)) {
        /* A CBOR error here is always not-well-formed */
        return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
    }

Done:
    return return_value;
}
