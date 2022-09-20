/*
 * t_cose_parameters.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose/t_cose_parameters.h"
#include "t_cose_standard_constants.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose_util.h"


/**
 * \file t_cose_parameters.c
 *
 * \brief Implementation of COSE header parameter decoding.
 *
 */

#ifdef TODO_CRIT_PARAM_FIXED

/**
 * \brief Add a new label to the end of the label list.
 *
 * \param[in] item             Data item to add to the label list.
 * \param[in,out] label_list   The list to add to.
 *
 * \retval T_COSE_SUCCESS                  If added correctly.
 * \retval T_COSE_ERR_TOO_MANY_PARAMETERS  Label list is full.
 * \retval T_COSE_ERR_PARAMETER_CBOR       The item to add doesn't have a label
 *                                         type that is understood
 *
 * The label / key from \c item is added to \c label_list.
 */
static enum t_cose_err_t
add_label_to_list(const QCBORItem *item, struct t_cose_label_list *label_list)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    16           8
     *   TOTAL                                         16           8
     */
    /* Stack use: 16 bytes for 64-bit */
    enum t_cose_err_t return_value;
    uint_fast8_t      n;

    /* Assume success until an error adding is encountered. */
    return_value = T_COSE_SUCCESS;

    if(item->uLabelType == QCBOR_TYPE_INT64) {
        /* Add an integer-labeled parameter to the end of the list */
        for(n = 0; label_list->int_labels[n] != LABEL_LIST_TERMINATOR; n++);
        if(n == T_COSE_PARAMETER_LIST_MAX) {
            /* List is full -- error out */
            return_value = T_COSE_ERR_TOO_MANY_PARAMETERS;
            goto Done;
        }
        label_list->int_labels[n] = item->label.int64;

    } else if(item->uLabelType == QCBOR_TYPE_TEXT_STRING) {
        /* Add a string-labeled parameter to the end of the list */
        for(n = 0; !q_useful_buf_c_is_null(label_list->tstr_labels[n]); n++);
        if(n == T_COSE_PARAMETER_LIST_MAX) {
            /* List is full -- error out */
            return_value = T_COSE_ERR_TOO_MANY_PARAMETERS;
            goto Done;
        }
        label_list->tstr_labels[n] = item->label.string;

    } else {
        /* error because label is neither integer or string */
        /* Should never occur because this is caught earlier, but
         * leave it to be safe and because inlining and optimization
         * should take out any unneeded code
         */
        return_value = T_COSE_ERR_PARAMETER_CBOR;
    }

Done:
    return return_value;
}


/**
 * \brief Indicate whether label list is clear or not.
 *
 * \param[in,out] list  The list to check.
 *
 * \return true if the list is clear.
 */
inline static bool
is_label_list_clear(const struct t_cose_label_list *list)
{
    return list->int_labels[0] == 0 &&
               q_useful_buf_c_is_null_or_empty(list->tstr_labels[0]);
}
#endif

static bool
is_in_list(const struct t_cose_label_list *critical_labels, int64_t label)
{
    for(int num_critical = 0;
        critical_labels->int_labels[num_critical];
        num_critical++) {
        if(critical_labels->int_labels[num_critical] == label) {
            return true;
        }
    }

    return false;
}


#ifdef TODO_CRIT_PARAM_FIXED

/**
 * \brief Decode the parameter containing the labels of parameters considered
 *        critical.
 *
 * \param[in,out]  decode_context          Decode context to read critical
 *                                         parameter list from.
 * \param[out]     critical_labels         List of labels of critical
 *                                         parameters.
 *
 * \retval T_COSE_ERR_CBOR_NOT_WELL_FORMED  Undecodable CBOR.
 * \retval T_COSE_ERR_TOO_MANY_PARAMETERS   More critical labels than this
 *                                          implementation can handle.
 * \retval T_COSE_ERR_PARAMETER_CBOR        Unexpected CBOR data type.
 */
static enum t_cose_err_t
decode_critical_parameter(QCBORDecodeContext       *decode_context,
                          struct t_cose_label_list *critical_labels)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   QCBORItem                                     56          52
     *   local vars                                    32          16
     *   TOTAL                                         88          68
     */
    QCBORItem         item;
    uint_fast8_t      num_int_labels;
    uint_fast8_t      num_tstr_labels;
    enum t_cose_err_t return_value;
    QCBORError        cbor_result;

    /* Assume that decoder has been entered into the parameters map */

    /* Find and enter the array that is the critical parameters parameter */
    QCBORDecode_EnterArrayFromMapN(decode_context, COSE_HEADER_PARAM_CRIT);

    cbor_result = QCBORDecode_GetAndResetError(decode_context);
    if(cbor_result == QCBOR_ERR_LABEL_NOT_FOUND) {
        /* Critical paratmeters parameter doesn't exist */
        return_value = T_COSE_SUCCESS;
        goto Done;
    } else if(cbor_result != QCBOR_SUCCESS) {
        return_value = T_COSE_ERR_CRIT_PARAMETER;
        goto Done;
    }

    if(critical_labels == NULL) {
        /* crit parameter occuring in non-protected bucket */
        return_value = T_COSE_ERR_PARAMETER_NOT_PROTECTED;
        goto Done;
    }

    num_int_labels  = 0;
    num_tstr_labels = 0;

    while(1) {
        cbor_result = QCBORDecode_GetNext(decode_context, &item);
        if(cbor_result == QCBOR_ERR_NO_MORE_ITEMS) {
            /* successful exit from loop */
            break;
        }
        if(cbor_result != QCBOR_SUCCESS) {
            return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
            goto Done;
        }

        if(item.uDataType == QCBOR_TYPE_INT64) {
            if(num_int_labels >= T_COSE_PARAMETER_LIST_MAX) {
                return_value = T_COSE_ERR_CRIT_PARAMETER;
                goto Done;
            }
            critical_labels->int_labels[num_int_labels++] = item.val.int64;
        } else if(item.uDataType == QCBOR_TYPE_TEXT_STRING) {
            if(num_tstr_labels >= T_COSE_PARAMETER_LIST_MAX) {
                return_value = T_COSE_ERR_CRIT_PARAMETER;
                goto Done;
            }
            critical_labels->tstr_labels[num_tstr_labels++] = item.val.string;
        } else {
            return_value = T_COSE_ERR_CRIT_PARAMETER;
            goto Done;
        }
    }

    /* Exit out of array back up to parameters map */
    QCBORDecode_ExitArray(decode_context);

    if(is_label_list_clear(critical_labels)) {
        /* Per RFC 8152 crit parameter can't be empty */
        return_value = T_COSE_ERR_CRIT_PARAMETER;
        goto Done;
    }

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}


/**
 * Public function. See t_cose_parameters.h
 */
static enum t_cose_err_t
check_critical_labels(const struct t_cose_label_list *critical_labels,
                      const struct t_cose_label_list *unknown_labels)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    24          12
     *   TOTAL                                         24          12
     */
    enum t_cose_err_t return_value;
    uint_fast8_t      num_unknown;
    uint_fast8_t      num_critical;

    /* Assume success until an unhandled critical label is found */
    return_value = T_COSE_SUCCESS;

    /* Iterate over unknown integer parameters */
    for(num_unknown = 0; unknown_labels->int_labels[num_unknown]; num_unknown++) {
        /* Iterate over critical int labels looking for the unknown label */
        for(num_critical = 0;
            critical_labels->int_labels[num_critical];
            num_critical++) {
            if(critical_labels->int_labels[num_critical] == unknown_labels->int_labels[num_unknown]) {
                /* Found a critical label that is unknown to us */
                return_value = T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER;
                goto Done;
            }
        }
        /* Exit from loop here means all no unknown label was critical */
    }

    /* Iterate over unknown string labels */
    for(num_unknown = 0; !q_useful_buf_c_is_null(unknown_labels->tstr_labels[num_unknown]); num_unknown++) {
        /* iterate over critical string labels looking for the unknown param */
        for(num_critical = 0; !q_useful_buf_c_is_null(critical_labels->tstr_labels[num_critical]); num_critical++) {
            if(!q_useful_buf_compare(critical_labels->tstr_labels[num_critical],
                                     unknown_labels->tstr_labels[num_unknown])){
                /* Found a critical label that is unknown to us */
                return_value = T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER;
                goto Done;
            }
        }
        /* Exit from loop here means all no unknown label was critical */
    }

Done:
    return return_value;
}
#endif


static void
encode_crit_parameter(QCBOREncodeContext                      *encode_context,
                      const struct t_cose_header_param *const *parameters)
{
    const struct t_cose_header_param *const *p_vector;
    const struct t_cose_header_param        *p_param;

    QCBOREncode_OpenArrayInMapN(encode_context, COSE_HEADER_PARAM_CRIT);
    for(p_vector = parameters; *p_vector != NULL; p_vector++) {
        for(p_param = *p_vector; p_param->parameter_type != T_COSE_PARAMETER_TYPE_NONE; p_param++) {
            if(p_param->critical) {
                QCBOREncode_AddInt64(encode_context, p_param->label);
            }
        }
    }
    QCBOREncode_CloseMap(encode_context);
}





static inline uint8_t
cbor_type_to_parameter_type(uint8_t qcbor_data_type)
{
    // improvement: maybe this can be optimized to use less object code.
    switch(qcbor_data_type) {
        case QCBOR_TYPE_INT64:
        case QCBOR_TYPE_UINT64:
        case QCBOR_TYPE_TEXT_STRING:
        case QCBOR_TYPE_BYTE_STRING:
        case QCBOR_TYPE_TRUE:
            /* parameter types picked so they map directly from QCBOR types */
            return qcbor_data_type;

        case QCBOR_TYPE_FALSE:
            return T_COSE_PARAMETER_TYPE_BOOL;

        default:
            return T_COSE_PARAMETER_TYPE_NONE;
    }
}



static enum t_cose_err_t
decode_parameters_bucket(QCBORDecodeContext         *decode_context,
                         struct header_location      location,
                         bool                        is_protected,
                         t_cose_header_reader       *cb,
                         void                       *cb_context,
                         const struct header_param_storage param_storage)
{
    QCBORError                  qcbor_error;
    enum t_cose_err_t           return_value;
    struct t_cose_label_list    critical_parameter_labels;
    struct t_cose_header_param *params;
    QCBORItem                   item;

    clear_label_list(&critical_parameter_labels);
    QCBORDecode_EnterMap(decode_context, NULL);

#ifdef TODO_CRIT_PARAM_FIXED
    /* TODO: There is a bug in QCBOR where mixing of get by
     * label and traversal don't work together right.
     * When it is fixed, this code can be re enabled.
     * For now there is no decoding of crit.
     */
    if(is_protected) {
        // TODO: should there be an error check for crit
        // parameter occuring in an unprotected bucket?
        clear_label_list(&critical_parameter_labels);
        return_value = decode_critical_parameter(decode_context,
                                                &critical_parameter_labels);
        if(return_value != T_COSE_SUCCESS) {
            goto Done;
        }
    }
#endif

    for(params = param_storage.storage;
        params->parameter_type != QCBOR_TYPE_NONE;
        params++);

    while(1) {
        QCBORDecode_VPeekNext(decode_context, &item);
        qcbor_error = QCBORDecode_GetAndResetError(decode_context);
        if(qcbor_error == QCBOR_ERR_NO_MORE_ITEMS) {
            /* An unclosed map is caught in check after ExitMap(). */
            break;
        }
        if(qcbor_error != QCBOR_SUCCESS) {
            return_value = qcbor_decode_error_to_t_cose_error(qcbor_error, T_COSE_ERR_PARAMETER_CBOR);
            goto Done;
        }


        // TODO: test this at boundary condition!
        if(params > &param_storage.storage[param_storage.storage_size-1]) {
            return_value = T_COSE_ERR_TOO_MANY_PARAMETERS;
            goto Done;
        }

        if(item.uLabelType != T_COSE_PARAMETER_TYPE_INT64) {
            return_value = T_COSE_ERR_PARAMETER_CBOR;
            goto Done;
        }

        bool crit = is_in_list(&critical_parameter_labels, item.label.int64);

        const uint8_t header_type = cbor_type_to_parameter_type(item.uDataType);

        if(header_type != T_COSE_PARAMETER_TYPE_NONE) {
            params->parameter_type = header_type;
            params->location       = location;
            params->label          = item.label.int64;
            params->prot           = is_protected;
            params->critical       = crit;

            switch (item.uDataType) {
                case T_COSE_PARAMETER_TYPE_BYTE_STRING:
                case T_COSE_PARAMETER_TYPE_TEXT_STRING:
                    params->value.string = item.val.string;
                    break;

                case T_COSE_PARAMETER_TYPE_INT64:
                    params->value.i64 = item.val.int64;
                    break;
            }

            /* Actually consume it */
            QCBORDecode_GetNext(decode_context, &item);
            params++;

        } else if (item.label.int64 == COSE_HEADER_PARAM_CRIT) {
            QCBORDecode_VGetNextConsume(decode_context, &item);
            /* ignore crit param because it was already processed .*/
            continue;

        } else {
            /* Parameter is of a type not returned in the array of t_cose_header_param */
            if(cb == NULL) {
                /* No callback configured to handle these unknown */
                if(crit) {
                    /* It is critical and unknown, so must error out */
                    return_value = T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER;
                    goto Done;
                } else {
                    /* Not critical. Just skip over it. */
                    QCBORDecode_VGetNextConsume(decode_context, &item);
                }
            } else {
                /* Process by a call back. */
                return_value = (cb)(cb_context, decode_context, location, is_protected, crit);
                if(return_value != T_COSE_SUCCESS) {
                    break;
                }
            }
        }
    }
    params->parameter_type = T_COSE_PARAMETER_TYPE_NONE;

    QCBORDecode_ExitMap(decode_context);
    qcbor_error = QCBORDecode_GetAndResetError(decode_context);
    if(qcbor_error != QCBOR_SUCCESS) {
        return_value = qcbor_decode_error_to_t_cose_error(qcbor_error, T_COSE_ERR_PARAMETER_CBOR);
        goto Done;
    }

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}


/*
 * Public function. See t_cose_parameters.h
 */
enum t_cose_err_t
t_cose_ignore_param_cb(void *cb,
                       QCBORDecodeContext *decode_context,
                       struct header_location location,
                       bool is_protected,
                       bool is_crit)
{
    (void)cb;
    (void)decode_context;
    (void)location;
    (void)is_protected;
    /* If the caller wants to ignore critical parameters, they
     * have to do the work to implement there own function. */
    return is_crit ? T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER : T_COSE_SUCCESS;
}



static bool
dup_detect_target(const struct t_cose_header_param *params,
            const struct t_cose_header_param *target)
{
    for(;params->parameter_type != T_COSE_PARAMETER_TYPE_NONE; params++) {
        if(params->label == target->label && params != target) {
            return true;
        }
    }

    return false;
}


static bool
dup_detect_array(const struct t_cose_header_param *params)
{
    const struct t_cose_header_param *target;

    for(target = params; target->parameter_type != T_COSE_PARAMETER_TYPE_NONE; target++) {
        if(dup_detect_target(params, target)) {
            return true;
        }
    }
    return false;
}


static bool
dup_detect_vector_array(const struct t_cose_header_param *target,
            const struct t_cose_header_param * const *params_vector)
{
    const struct t_cose_header_param * const *p1;
    /* loop over the vector */
    for(p1 = params_vector; *p1 != NULL; p1++) {
        /* loop over the vector or param arrays */
        dup_detect_target(*p1, target);
    }
    return false;
}


static bool
dup_detect_vector(const struct t_cose_header_param * const *params_vector)
{
    const struct t_cose_header_param * const *p1;
    const struct t_cose_header_param         *p2;

    /* n ^ 2 algorithm, but n is very small. */
    /* loop over the vector or param arrays */
    for(p1 = params_vector; *p1 != NULL; p1++) {
        /* loop over array of parameters */
        for(p2 = *p1; p2->parameter_type != T_COSE_PARAMETER_TYPE_NONE; p2++) {
            if(dup_detect_vector_array(p2, params_vector)) {
                return true;
            }
        }
    }
    return false;
}


/*
 * Public function. See t_cose_parameters.h
 */
enum t_cose_err_t
t_cose_headers_decode(QCBORDecodeContext          *decode_context,
                      struct header_location       location,
                      t_cose_header_reader        *cb,
                      void                        *cb_context,
                      const struct header_param_storage  param_storage,
                      struct q_useful_buf_c       *protected_parameters)
{
    QCBORError        qcbor_error;
    enum t_cose_err_t return_value;

    /* --- The protected parameters --- */
     QCBORDecode_EnterBstrWrapped(decode_context,
                                  QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
                                  protected_parameters);

     if(protected_parameters->len) {
         return_value = decode_parameters_bucket(decode_context,
                                                 location,
                                                 true,
                                                 cb,
                                                 cb_context,
                                                 param_storage);

         if(return_value != T_COSE_SUCCESS) {
             goto Done;
         }
     }
     QCBORDecode_ExitBstrWrapped(decode_context);

     /* ---  The unprotected parameters --- */
    return_value = decode_parameters_bucket(decode_context,
                                            location,
                                            false,
                                            cb,
                                            cb_context,
                                            param_storage);

    /* This check covers all the CBOR decode errors. */
    qcbor_error = QCBORDecode_GetError(decode_context);
    if(qcbor_error != QCBOR_SUCCESS) {
        return_value = qcbor_decode_error_to_t_cose_error(qcbor_error, T_COSE_ERR_PARAMETER_CBOR);
        goto Done;
    }

    if(dup_detect_array(param_storage.storage)) {
        return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
        goto Done;
    }

Done:
    return return_value;
}



/**
 * \brief Encode a bucket of header parameters
 *
 * \param[in]  encode_context    QCBOR encoder context to output to.
 * \param[in]  params_vector      A vector of arrays of parameters to encode.
 * \param[in]  is_protected_header  \c true if output the protected bucket, \c false if not.
 *
 * This iterates of the vector of parameter arrays output each one. When \c is_protected_header
 * is true the parameters marked as protected will be output and vice versa.
 *
 * The callback will be invoked for parameters that are to be output by a callback function.
 * This is required for parameters that are not strings or integers
 *
 * If there are any parameters marked critical in the input, the critical parameters
 * header will be constructed about output.
 **/
static enum t_cose_err_t
encode_parameters_bucket(QCBOREncodeContext                       *encode_context,
                         const struct t_cose_header_param * const *params_vector,
                         const bool                                is_protected_header)
{
    const struct t_cose_header_param * const *p_vector;
    const struct t_cose_header_param         *p_param;
    bool                                      criticals_present;
    enum t_cose_err_t                         return_value;

    /* Protected and unprotected parameters are a map of label/value pairs */
    QCBOREncode_OpenMap(encode_context);

    criticals_present = false;
    /* loop over the vector of param arrays */
    for(p_vector = params_vector; *p_vector != NULL; p_vector++) {
        /* loop over array of parameters */
        for(p_param = *p_vector; p_param->parameter_type != T_COSE_PARAMETER_TYPE_NONE; p_param++) {
            if(is_protected_header && !p_param->prot) {
                continue;
            }
            if(!is_protected_header && p_param->prot) {
                continue;
            }

            switch(p_param->parameter_type) {
                case T_COSE_PARAMETER_TYPE_INT64:
                    QCBOREncode_AddInt64ToMapN(encode_context, p_param->label, p_param->value.i64);
                    break;

                case T_COSE_PARAMETER_TYPE_TEXT_STRING:
                    QCBOREncode_AddTextToMapN(encode_context, p_param->label, p_param->value.string);
                    break;

                case T_COSE_PARAMETER_TYPE_BYTE_STRING:
                    QCBOREncode_AddBytesToMapN(encode_context, p_param->label, p_param->value.string);
                    break;

                case T_COSE_PARAMETER_TYPE_CALLBACK:
                    /* Intentionally no check for NULL callback pointer to
                     * save a little object code. Caller should never
                     * indicate a callback without supplying the pointer
                     */
                    return_value = (p_param->value.writer.call_back)(p_param, encode_context);
                    if(return_value != T_COSE_SUCCESS) {
                        goto Done;
                    }
                    break;

                default:
                    // TODO: allow disabling this check to save object code
                    return_value = T_COSE_ERR_INVALID_PARAMETER_TYPE;
                    goto Done;
            }

            if(p_param->critical) {
                criticals_present = true;
            }
        }
    }

    if(criticals_present) {
        if(is_protected_header) {
            encode_crit_parameter(encode_context, params_vector);
        } else {
            /* Asking for critical parameters unprotected header bucket */
            // TODO: allow disabling this check to save object code
            return_value = T_COSE_ERR_CRIT_PARAMETER_IN_UNPROTECTED;
            goto Done;
        }
    }

    QCBOREncode_CloseMap(encode_context);

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}


/*
 * Public function. See t_cose_parameters.h
 */
enum t_cose_err_t
t_cose_encode_headers(QCBOREncodeContext                       *encode_context,
                      const struct t_cose_header_param * const *parameters,
                      struct q_useful_buf_c                    *protected_parameters)
{
    enum t_cose_err_t return_value;

    // TODO: allow disabling this check to save object code
    if(dup_detect_vector(parameters)) {
        return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
        goto Done;
    }

    /* --- Protected Headers --- */
    QCBOREncode_BstrWrap(encode_context);
    return_value = encode_parameters_bucket(encode_context,
                                            parameters,
                                            true);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    QCBOREncode_CloseBstrWrap2(encode_context, false, protected_parameters);


    /* --- Unprotected Parameters --- */
    return_value = encode_parameters_bucket(encode_context,
                                            parameters,
                                            false);
Done:
    return return_value;
}


// TODO: test all these functions below
/*
 * Public function. See t_cose_parameters.h
 */
const struct t_cose_header_param *
t_cose_find_parameter(const struct t_cose_header_param *p, int64_t label)
{
    while(p->parameter_type != T_COSE_PARAMETER_TYPE_NONE) {
        if(p->label == label) {
            return p;
        }
        p++;
    }

    return NULL;
}


/*
 * Public function. See t_cose_parameters.h
 */
int32_t
t_cose_find_parameter_alg_id(const struct t_cose_header_param *p)
{
    const struct t_cose_header_param *p_found;

    p_found = t_cose_find_parameter(p, COSE_HEADER_PARAM_ALG);
    if(p_found != NULL &&
       p_found->parameter_type == T_COSE_PARAMETER_TYPE_INT64 &&
       p_found->prot &&
       p_found->value.i64 != COSE_ALGORITHM_RESERVED &&
       p_found->value.i64 < INT32_MAX) {
        return (int32_t)p_found->value.i64;
    } else {
        return T_COSE_ALGORITHM_NONE;
    }
}


#ifndef T_COSE_DISABLE_CONTENT_TYPE
/*
 * Public function. See t_cose_parameters.h
 */
uint32_t
t_cose_find_parameter_content_type_int(const struct t_cose_header_param *p)
{
    const struct t_cose_header_param *p_found;

    p_found = t_cose_find_parameter(p, COSE_HEADER_PARAM_CONTENT_TYPE);
    if(p_found != NULL &&
       p_found->parameter_type == T_COSE_PARAMETER_TYPE_INT64 &&
       p_found->value.u64 < UINT16_MAX) {
        return (uint32_t)p_found->value.u64;
    } else {
        return T_COSE_EMPTY_UINT_CONTENT_TYPE;
    }
}


/*
 * Public function. See t_cose_parameters.h
 */
struct q_useful_buf_c
t_cose_find_parameter_content_type_tstr(const struct t_cose_header_param *p)
{
    const struct t_cose_header_param *p_found;

    p_found = t_cose_find_parameter(p, COSE_HEADER_PARAM_CONTENT_TYPE);
    if(p_found != NULL &&
       p_found->parameter_type == T_COSE_PARAMETER_TYPE_TEXT_STRING) {
        return p_found->value.string;
    } else {
        return NULL_Q_USEFUL_BUF_C;
    }
}
#endif /* T_COSE_DISABLE_CONTENT_TYPE */


/*
 * Public function. See t_cose_parameters.h
 */
struct q_useful_buf_c
t_cose_find_parameter_kid(const struct t_cose_header_param *p)
{
    const struct t_cose_header_param *p_found;

    p_found = t_cose_find_parameter(p, COSE_HEADER_PARAM_KID);
    if(p_found != NULL &&
       p_found->parameter_type == T_COSE_PARAMETER_TYPE_BYTE_STRING) {
        return p_found->value.string;
    } else {
        return NULL_Q_USEFUL_BUF_C;
    }
}


/*
 * Public function. See t_cose_parameters.h
 */
struct q_useful_buf_c
t_cose_find_parameter_iv(const struct t_cose_header_param *p)
{
    const struct t_cose_header_param *p_found;

    p_found = t_cose_find_parameter(p, COSE_HEADER_PARAM_IV);
    if(p_found != NULL &&
       p_found->parameter_type == T_COSE_PARAMETER_TYPE_BYTE_STRING) {
        return p_found->value.string;
    } else {
        return NULL_Q_USEFUL_BUF_C;
    }
}


/*
 * Public function. See t_cose_parameters.h
 */
struct q_useful_buf_c
t_cose_find_parameter_partial_iv(const struct t_cose_header_param *p)
{
    const struct t_cose_header_param *p_found;

    p_found = t_cose_find_parameter(p, COSE_HEADER_PARAM_PARTIAL_IV);
    if(p_found != NULL &&
       p_found->parameter_type == T_COSE_PARAMETER_TYPE_BYTE_STRING) {
        return p_found->value.string;
    } else {
        return NULL_Q_USEFUL_BUF_C;
    }
}



