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
#include "t_cose/t_cose_standard_constants.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose_util.h"


// TODO: test the parameter write callback
// TODO: test the parameter read callback
// TODO: check in on stack usage of label list
// TODO: check on in stack usage in general here
// TODO: documentation
// TODO: test the find parameter functions
// TODO: put the encode stuff first in the file

/**
 * \file t_cose_parameters.c
 *
 * \brief Implementation of COSE header parameter decoding.
 *
 */

/**
 *
 * \brief A list of critical parameter labels, both integer and string.
 *
 * It is fixed size to avoid the complexity of memory management and
 * because the number of parameters is assumed to be small.
 *
 * On a 64-bit machine it is 24 * (T_COSE_MAX_CRITICAL_PARAMS+1) which
 * is 120 bytes. That accommodates 4 string parameters and 4 integer
 * parameters and is small enough to go on the stack.
 *
 * On a 32-bit machine: 16 * (PARAMETER_LIST_MAX+1) = 80
 *
 * This is a big consumer of stack in this implementation.  Some
 * cleverness with a union could save some bytes of stack.
 */
struct t_cose_label_list {
    /* Terminated by value LABEL_LIST_TERMINATOR */
    int64_t int_labels[T_COSE_MAX_CRITICAL_PARAMS+1];
    /*  Terminated by a NULL_Q_USEFUL_BUF_C */
    struct q_useful_buf_c tstr_labels[T_COSE_MAX_CRITICAL_PARAMS+1];
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
#define LABEL_LIST_TERMINATOR 0


/**
 * \brief Clear a label list to empty.
 *
 * \param[in,out] list The list to clear.
 */
static inline void
clear_label_list(struct t_cose_label_list *list)
{
    memset(list, 0, sizeof(struct t_cose_label_list));
}



#ifdef TODO_CRIT_PARAM_FIXED


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

static inline bool
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
static inline enum t_cose_err_t
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
    QCBORDecode_EnterArrayFromMapN(decode_context, T_COSE_HEADER_PARAM_CRIT);

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
            if(num_int_labels >= T_COSE_MAX_CRITICAL_PARAMS) {
                return_value = T_COSE_ERR_CRIT_PARAMETER;
                goto Done;
            }
            critical_labels->int_labels[num_int_labels++] = item.val.int64;
        } else if(item.uDataType == QCBOR_TYPE_TEXT_STRING) {
            if(num_tstr_labels >= T_COSE_MAX_CRITICAL_PARAMS) {
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
static inline enum t_cose_err_t
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
        /* Exit from loop here means no unknown label was critical */
    }

Done:
    return return_value;
}
#endif


static inline void
encode_crit_parameter(QCBOREncodeContext            *encode_context,
                      const struct t_cose_parameter *parameters)
{
    const struct t_cose_parameter *p_param;

    QCBOREncode_OpenArrayInMapN(encode_context, T_COSE_HEADER_PARAM_CRIT);
    for(p_param = parameters; p_param != NULL; p_param = p_param->next) {
        if(p_param->critical) {
            QCBOREncode_AddInt64(encode_context, p_param->label);
        }
    }
    QCBOREncode_CloseArray(encode_context);
}



static enum t_cose_err_t
decode_parameters_bucket(QCBORDecodeContext               *decode_context,
                         struct t_cose_header_location     location,
                         bool                              is_protected,
                         t_cose_parameter_decode_callback *callback,
                         void                             *cb_context,
                         struct t_cose_parameter_storage  *param_storage,
                         struct t_cose_parameter         **decoded_parameters)
{
    /* Stack usage:
      Item   56
      vars   24
     crit list :120
     QCBORpeek: 200 (The largest subroutine called)


     TOTAL 400

     */
    QCBORError                qcbor_error;
    enum t_cose_err_t         return_value;
    struct t_cose_label_list  critical_parameter_labels;
    struct t_cose_parameter  *parameter;
    struct t_cose_parameter  *preceding_parameter;
    QCBORItem                 item;

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

    /* Loop reading entries out of the map until the end of the map. */
    *decoded_parameters = NULL;
    parameter = NULL;
    while(1) {
        QCBORDecode_VPeekNext(decode_context, &item);
        qcbor_error = QCBORDecode_GetAndResetError(decode_context);
        if(qcbor_error == QCBOR_ERR_NO_MORE_ITEMS) {
            /* This is the successful exit from the loop */
            /* An unclosed map is caught in check after ExitMap(). */
            break;
        }
        if(qcbor_error != QCBOR_SUCCESS) {
            return_value = qcbor_decode_error_to_t_cose_error(qcbor_error, T_COSE_ERR_PARAMETER_CBOR);
            goto Done;
        }

        if(item.uLabelType != T_COSE_PARAMETER_TYPE_INT64) {
            return_value = T_COSE_ERR_PARAMETER_CBOR;
            goto Done;
        }

        if (item.label.int64 == T_COSE_HEADER_PARAM_CRIT) {
            QCBORDecode_VGetNextConsume(decode_context, &item);
            /* ignore crit param because it was already processed .*/
            continue;
        }
        
        // TODO: test this at boundary condition!
        if(param_storage->used >= param_storage->size) {
            return_value = T_COSE_ERR_TOO_MANY_PARAMETERS;
            goto Done;
        }

        preceding_parameter = parameter;
        parameter = &param_storage->storage[param_storage->used];
        param_storage->used++;
        if(*decoded_parameters == NULL) {
            *decoded_parameters = parameter;
        } else {
            preceding_parameter->next = parameter;
        }


        parameter->value_type = item.uDataType;
        parameter->location   = location;
        parameter->label      = item.label.int64;
        parameter->in_protected  = is_protected;
        parameter->critical   = is_in_list(&critical_parameter_labels, item.label.int64);;
        parameter->next       = NULL;

        switch (item.uDataType) {
            case T_COSE_PARAMETER_TYPE_BYTE_STRING:
            case T_COSE_PARAMETER_TYPE_TEXT_STRING:
                parameter->value.string = item.val.string;
                QCBORDecode_VGetNextConsume(decode_context, &item);
                break;

            case T_COSE_PARAMETER_TYPE_INT64:
                parameter->value.i64 = item.val.int64;
                QCBORDecode_VGetNextConsume(decode_context, &item);
                break;

            default:
                if(callback == NULL) {
                    /* No callback configured to handle the unknown */
                    if(parameter->critical) {
                        /* It is critical and unknown, so must error out */
                        return_value = T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER;
                        goto Done;
                    } else {
                        /* Not critical. Just skip over it. */
                        QCBORDecode_VGetNextConsume(decode_context, &item);
                    }
                } else {
                    /* Processed and consumed by the callback. */
                    return_value = callback(cb_context, decode_context, parameter);
                    if(return_value != T_COSE_SUCCESS) {
                        break;
                    }
                }
        }
    }

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




static bool
dup_detect_list_2(const struct t_cose_parameter *target,
                  const struct t_cose_parameter *params_list)
{
    const struct t_cose_parameter *p1;

    for(p1 = params_list; p1 != NULL; p1 = p1->next) {
        if(p1->label == target->label && p1 != target) {
            return true;
        }
    }
    return false;
}


static bool
dup_detect_list(const struct t_cose_parameter *params_list)
{
    const struct t_cose_parameter *p1;

    /* n ^ 2 algorithm, but n is very small. */
    for(p1 = params_list; p1 != NULL; p1 = p1->next) {
        if(dup_detect_list_2(p1, params_list)) {
            return true;
        }
    }
    return false;
}


/*
 * Public function. See t_cose_parameters.h
 */
enum t_cose_err_t
t_cose_headers_decode(QCBORDecodeContext               *decode_context,
                      struct t_cose_header_location     location,
                      t_cose_parameter_decode_callback *callback,
                      void                             *callback_context,
                      struct t_cose_parameter_storage  *param_storage,
                      struct t_cose_parameter         **decoded_parameter_list,
                      struct q_useful_buf_c            *protected_parameters)
{
    /* stack usage:
     vars: 16
     decode_bucket  324

     */

    QCBORError                qcbor_error;
    enum t_cose_err_t         return_value;
    struct t_cose_parameter  *decoded_protected;
    struct t_cose_parameter  *decoded_unprotected;


    /* --- The protected parameters --- */
     QCBORDecode_EnterBstrWrapped(decode_context,
                                  QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
                                  protected_parameters);

     decoded_protected = NULL;
     if(protected_parameters->len) {
         return_value = decode_parameters_bucket(decode_context,
                                                 location,
                                                 true,
                                                 callback,
                                                 callback_context,
                                                 param_storage,
                                                 &decoded_protected);

         if(return_value != T_COSE_SUCCESS) {
             goto Done;
         }
     }
     QCBORDecode_ExitBstrWrapped(decode_context);

     /* ---  The unprotected parameters --- */
    return_value = decode_parameters_bucket(decode_context,
                                            location,
                                            false,
                                            callback,
                                            callback_context,
                                            param_storage,
                                            &decoded_unprotected);

    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* This check covers all the CBOR decode errors. */
    qcbor_error = QCBORDecode_GetError(decode_context);
    if(qcbor_error != QCBOR_SUCCESS) {
        return_value = qcbor_decode_error_to_t_cose_error(qcbor_error, T_COSE_ERR_PARAMETER_CBOR);
        goto Done;
    }

    if(decoded_protected == NULL) {
        *decoded_parameter_list = decoded_unprotected;
    } else {
        *decoded_parameter_list = decoded_protected;
        t_cose_parameter_list_append(*decoded_parameter_list, decoded_unprotected);
    }

    if(dup_detect_list(*decoded_parameter_list)) {
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
 * \param[in]  parameters      A linked list of parameters to encode.
 * \param[in]  is_protected_bucket  \c true if output the protected bucket, \c false if not.
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
encode_parameters_bucket(QCBOREncodeContext            *encode_context,
                         const struct t_cose_parameter *parameters,
                         const bool                     is_protected_bucket)
{
    const struct t_cose_parameter  *p_parameter;
    bool                            criticals_present;
    enum t_cose_err_t               return_value;

    /* Protected and unprotected parameters are a map of label/value pairs */
    QCBOREncode_OpenMap(encode_context);

    criticals_present = false;
    for(p_parameter = parameters; p_parameter != NULL; p_parameter = p_parameter->next) {
        if(is_protected_bucket && !p_parameter->in_protected) {
            continue;
        }
        if(!is_protected_bucket && p_parameter->in_protected) {
            continue;
        }

        switch(p_parameter->value_type) {
            case T_COSE_PARAMETER_TYPE_INT64:
                QCBOREncode_AddInt64ToMapN(encode_context, p_parameter->label, p_parameter->value.i64);
                break;

            case T_COSE_PARAMETER_TYPE_TEXT_STRING:
                QCBOREncode_AddTextToMapN(encode_context, p_parameter->label, p_parameter->value.string);
                break;

            case T_COSE_PARAMETER_TYPE_BYTE_STRING:
                QCBOREncode_AddBytesToMapN(encode_context, p_parameter->label, p_parameter->value.string);
                break;

            case T_COSE_PARAMETER_TYPE_CALLBACK:
                /* Intentionally no check for NULL callback pointer to
                 * save a little object code. Caller should never
                 * indicate a callback without supplying the pointer
                 */
                return_value = p_parameter->value.custom_encoder.callback(p_parameter, encode_context);
                if(return_value != T_COSE_SUCCESS) {
                    goto Done;
                }
                break;

            default:
                // TODO: allow disabling this check to save object code
                return_value = T_COSE_ERR_INVALID_PARAMETER_TYPE;
                goto Done;
        }

        if(p_parameter->critical) {
            criticals_present = true;
        }
    }

    if(criticals_present) {
        if(is_protected_bucket) {
            encode_crit_parameter(encode_context, parameters);
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
t_cose_encode_headers(QCBOREncodeContext            *encode_context,
                      const struct t_cose_parameter *parameters,
                      struct q_useful_buf_c         *protected_parameters)
{
    enum t_cose_err_t return_value;

    // TODO: allow disabling this check to save object code
    if(dup_detect_list(parameters)) {
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
const struct t_cose_parameter *
t_cose_find_parameter(const struct t_cose_parameter *parameter_list, int64_t label)
{
    for(; parameter_list != NULL; parameter_list = parameter_list->next) {
        if(parameter_list->label == label) {
            return parameter_list;
        }
    }

    return NULL;
}


/*
 * Public function. See t_cose_parameters.h
 */
int32_t
t_cose_find_parameter_alg_id(const struct t_cose_parameter *parameter_list)
{
    const struct t_cose_parameter *p_found;

    p_found = t_cose_find_parameter(parameter_list, T_COSE_HEADER_PARAM_ALG);
    if(p_found != NULL &&
       p_found->value_type == T_COSE_PARAMETER_TYPE_INT64 &&
       p_found->in_protected &&
       p_found->value.i64 != T_COSE_ALGORITHM_RESERVED &&
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
t_cose_find_parameter_content_type_int(const struct t_cose_parameter *parameter_list)
{
    const struct t_cose_parameter *p_found;

    p_found = t_cose_find_parameter(parameter_list, T_COSE_HEADER_PARAM_CONTENT_TYPE);
    if(p_found != NULL &&
       p_found->value_type == T_COSE_PARAMETER_TYPE_INT64 &&
       p_found->value.i64 < UINT16_MAX) {
        return (uint32_t)p_found->value.i64;
    } else {
        return T_COSE_EMPTY_UINT_CONTENT_TYPE;
    }
}


/*
 * Public function. See t_cose_parameters.h
 */
struct q_useful_buf_c
t_cose_find_parameter_content_type_tstr(const struct t_cose_parameter *parameter_list)
{
    const struct t_cose_parameter *p_found;

    p_found = t_cose_find_parameter(parameter_list, T_COSE_HEADER_PARAM_CONTENT_TYPE);
    if(p_found != NULL &&
       p_found->value_type == T_COSE_PARAMETER_TYPE_TEXT_STRING) {
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
t_cose_find_parameter_kid(const struct t_cose_parameter *parameter_list)
{
    const struct t_cose_parameter *p_found;

    p_found = t_cose_find_parameter(parameter_list, T_COSE_HEADER_PARAM_KID);
    if(p_found != NULL &&
       p_found->value_type == T_COSE_PARAMETER_TYPE_BYTE_STRING) {
        return p_found->value.string;
    } else {
        return NULL_Q_USEFUL_BUF_C;
    }
}


/*
 * Public function. See t_cose_parameters.h
 */
struct q_useful_buf_c
t_cose_find_parameter_iv(const struct t_cose_parameter *parameter_list)
{
    const struct t_cose_parameter *p_found;

    p_found = t_cose_find_parameter(parameter_list, T_COSE_HEADER_PARAM_IV);
    if(p_found != NULL &&
       p_found->value_type == T_COSE_PARAMETER_TYPE_BYTE_STRING) {
        return p_found->value.string;
    } else {
        return NULL_Q_USEFUL_BUF_C;
    }
}


/*
 * Public function. See t_cose_parameters.h
 */
struct q_useful_buf_c
t_cose_find_parameter_partial_iv(const struct t_cose_parameter *parameter_list)
{
    const struct t_cose_parameter *p_found;

    p_found = t_cose_find_parameter(parameter_list, T_COSE_HEADER_PARAM_PARTIAL_IV);
    if(p_found != NULL &&
       p_found->value_type == T_COSE_PARAMETER_TYPE_BYTE_STRING) {
        return p_found->value.string;
    } else {
        return NULL_Q_USEFUL_BUF_C;
    }
}



/**
 * \brief Clear a struct t_cose_parameters to empty
 *
 * \param[in,out] parameters   Parameter list to clear.
 */
static inline void clear_cose_parameters(struct t_cose_parameters *parameters)
{
#if T_COSE_ALGORITHM_RESERVED != 0
#error Invalid algorithm designator not 0. Parameter list initialization fails.
#endif

#if T_COSE_ALGORITHM_NONE != T_COSE_ALGORITHM_RESERVED
#error Constant for unset algorithm ID not aligned with T_COSE_ALGORITHM_RESERVED
#endif

    /* This clears all the useful_bufs to NULL_Q_USEFUL_BUF_C
     * and the cose_algorithm_id to T_COSE_ALGORITHM_RESERVED
     */
    memset(parameters, 0, sizeof(struct t_cose_parameters));

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    /* The only non-zero clear-state value. (0 is plain text in CoAP
     * content format) */
    parameters->content_type_uint =  T_COSE_EMPTY_UINT_CONTENT_TYPE;
#endif
}


/*
 * Public function. See t_cose_parameters.h
 */
enum t_cose_err_t
t_cose_common_header_parameters(const struct t_cose_parameter *decoded_params,
                                struct t_cose_parameters      *returned_parameters)
{
    enum t_cose_err_t              return_value = T_COSE_SUCCESS;
    const struct t_cose_parameter *p;

    clear_cose_parameters(returned_parameters);

    /* No duplicate detection is necessary because t_cose_headers_decode()
     * does it. */
    for(p = decoded_params; p != NULL; p = p->next) {
        if(p->label == T_COSE_HEADER_PARAM_KID) {
            if(p->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
                return_value = T_COSE_ERR_PARAMETER_CBOR;
                goto Done;
            }
            returned_parameters->kid = p->value.string;

        } else if(p->label == T_COSE_HEADER_PARAM_ALG) {
            if(p->value_type != T_COSE_PARAMETER_TYPE_INT64) {
                return_value = T_COSE_ERR_PARAMETER_CBOR;
                goto Done;
            }
            if(!p->in_protected) {
                return_value = T_COSE_ERR_PARAMETER_NOT_PROTECTED;
                goto Done;
            }
            if(p->value.i64 == T_COSE_ALGORITHM_RESERVED || p->value.i64 > INT32_MAX) {
                return_value = T_COSE_ERR_NON_INTEGER_ALG_ID;
                goto Done;
            }
            returned_parameters->cose_algorithm_id = (int32_t)p->value.i64;

        } else if(p->label == T_COSE_HEADER_PARAM_IV) {
            if(p->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
                return_value = T_COSE_ERR_PARAMETER_CBOR;
                goto Done;
            }
            returned_parameters->iv = p->value.string;

        } else if(p->label == T_COSE_HEADER_PARAM_PARTIAL_IV) {
            if(p->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
                return_value = T_COSE_ERR_PARAMETER_CBOR;
                goto Done;
            }
            returned_parameters->partial_iv = p->value.string;

#ifndef T_COSE_DISABLE_CONTENT_TYPE
        } else if(p->label == T_COSE_HEADER_PARAM_CONTENT_TYPE) {
            if(p->value_type == T_COSE_PARAMETER_TYPE_TEXT_STRING) {
                returned_parameters->content_type_tstr = p->value.string;

            } else if(p->value_type == T_COSE_PARAMETER_TYPE_INT64) {
                if(p->value.i64 < 0 || p->value.i64 > UINT16_MAX) {
                      return_value = T_COSE_ERR_BAD_CONTENT_TYPE;
                      goto Done;
                }
                returned_parameters->content_type_uint = (uint32_t)p->value.i64;

            } else {
                return_value = T_COSE_ERR_BAD_CONTENT_TYPE;
            }
#endif /* T_COSE_DISABLE_CONTENT_TYPE */
        }
    }

    Done:
        return return_value;
}
