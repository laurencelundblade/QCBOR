/*
 * t_cose_parameters.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_util.h"


// TODO: put the encode stuff first in the file

/**
 * \file t_cose_parameters.c
 *
 * \brief Implementation of COSE header parameter encoding and decoding..
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
 * \param[in,out] label_list The list to clear.
 */
static void
label_list_clear(struct t_cose_label_list *label_list)
{
    memset(label_list, 0, sizeof(struct t_cose_label_list));
}


/**
 * \brief Indicate whether label list is clear or not.
 *
 * \param[in,out] label_list  The list to check.
 *
 * \return true if the list is clear.
 */
static bool
label_list_is_clear(const struct t_cose_label_list *label_list)
{
    return label_list->int_labels[0] == 0 &&
               q_useful_buf_c_is_null_or_empty(label_list->tstr_labels[0]);
}

/**
 * \brief Returns true if a label is in the label list.
 *
 * \param[in] label_list  The list to check.
 * \param[in] label    The label to check for.
 *
 * \return true if label is in the list.
 *
 * This works only for integer labels.
 */
static bool
label_list_is_in(const struct t_cose_label_list *label_list, int64_t label)
{
    unsigned count;

    for(count = 0; label_list->int_labels[count]; count++) {
        if(label_list->int_labels[count] == label) {
            return true;
        }
    }

    return false;
}




/**
 * \brief This encodes the critical parameters parameter.
 *
 * \param[in] cbor_encoder Encoder to which the critical parameters parameter
 *                         is output.
 * \param[in] parameters   Linked list of parameters, some of which might be
 *                         critical
 *
 * This outputs the critical parameters parameter by traversling the
 * linked list. This always outputs the critical parameters parameter
 * so the list should be checked to be sure it has critical parameters
 * in it before this is called.
 */
static void
encode_crit_parameter(QCBOREncodeContext            *cbor_encoder,
                      const struct t_cose_parameter *parameters)
{
    const struct t_cose_parameter *p_param;

    QCBOREncode_OpenArrayInMapN(cbor_encoder, T_COSE_HEADER_PARAM_CRIT);
    for(p_param = parameters; p_param != NULL; p_param = p_param->next) {
        if(p_param->critical) {
            QCBOREncode_AddInt64(cbor_encoder, p_param->label);
        }
    }
    QCBOREncode_CloseArray(cbor_encoder);
}


/**
 * \brief Decode the parameter containing the labels of parameters considered
 *        critical.
 *
 * \param[in,out]  cbor_decoder          Decode context to read critical
 *                                         parameter list from.
 * \param[out]     crit_labels         List of labels of critical
 *                                         parameters.
 *
 * \retval T_COSE_ERR_CBOR_NOT_WELL_FORMED  Undecodable CBOR.
 * \retval T_COSE_ERR_TOO_MANY_PARAMETERS   More critical labels than this
 *                                          implementation can handle.
 * \retval T_COSE_ERR_PARAMETER_CBOR        Unexpected CBOR data type.
 */
static enum t_cose_err_t
decode_crit_param(QCBORDecodeContext       *cbor_decoder,
                  struct t_cose_label_list *crit_labels)
{
    /* Aproximate stack usage
     *                                             64-bit      32-bit
     *   QCBORItem                                     56          52
     *   local vars                                    32          16
     *   TOTAL                                         88          68
     */
    QCBORItem         item;
    unsigned          num_int_labels;
    unsigned          num_tstr_labels;
    enum t_cose_err_t return_value;
    QCBORError        cbor_result;

    /* Assumes that the next item is map holding crit params list */

    /* Enter the array that is the crit parameters parameter */
    QCBORDecode_EnterArray(cbor_decoder, NULL);

    num_int_labels  = 0;
    num_tstr_labels = 0;

    while(1) {
        QCBORDecode_VGetNext(cbor_decoder, &item);
        cbor_result = QCBORDecode_GetAndResetError(cbor_decoder);
        if(cbor_result == QCBOR_ERR_NO_MORE_ITEMS) {
            /* successful exit from loop */
            break;
        }
        if(cbor_result != QCBOR_SUCCESS) {
            /* Don't bother mapping CBOR errors into detailed t_cose errors.
             * It's probably more useful to know its the crit param. */
            return_value = T_COSE_ERR_CRIT_PARAMETER;
            goto Done;
        }

        if(item.uDataType == QCBOR_TYPE_INT64) {
            if(num_int_labels >= T_COSE_MAX_CRITICAL_PARAMS) {
                return_value = T_COSE_ERR_CRIT_PARAMETER;
                goto Done;
            }
            crit_labels->int_labels[num_int_labels++] = item.val.int64;
        } else if(item.uDataType == QCBOR_TYPE_TEXT_STRING) {
            if(num_tstr_labels >= T_COSE_MAX_CRITICAL_PARAMS) {
                return_value = T_COSE_ERR_CRIT_PARAMETER;
                goto Done;
            }
            crit_labels->tstr_labels[num_tstr_labels++] = item.val.string;
        } else {
            return_value = T_COSE_ERR_CRIT_PARAMETER;
            goto Done;
        }
    }

    /* Exit out of array back up to parameters map */
    QCBORDecode_ExitArray(cbor_decoder);

    if(label_list_is_clear(crit_labels)) {
        /* Per RFC 9052, crit parameter can't be empty */
        return_value = T_COSE_ERR_CRIT_PARAMETER;
        goto Done;
    }

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}

/*
 *
 * Set the crit member for every parameter in the list
 * based on whether it is listed in \c crit_labels.
 */
static void
mark_crit_params(struct t_cose_parameter        *parameters,
                 const struct t_cose_label_list *crit_labels)
{
    struct t_cose_parameter *p_param;

    for(p_param = parameters; p_param != NULL; p_param = p_param->next) {
        if(label_list_is_in(crit_labels, p_param->label)) {
            p_param->critical = true;
        }
    }
}


/*
 * Public function. See t_cose_parameters.h
 */
enum t_cose_err_t
t_cose_params_check(const struct t_cose_parameter *parameters)
{
    const struct t_cose_parameter *p_param;
    bool                           iv_present;

    iv_present = false;
    for(p_param = parameters; p_param != NULL; p_param = p_param->next) {
        if(p_param->critical && !(p_param->label >= T_COSE_HEADER_PARAM_ALG &&
                                  p_param->label <= T_COSE_HEADER_PARAM_PARTIAL_IV)) {
            return T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER;
        }
        if(p_param->label == T_COSE_HEADER_PARAM_IV ||
           p_param->label == T_COSE_HEADER_PARAM_PARTIAL_IV) {
            if(iv_present) {
                return T_COSE_ERR_DUPLICATE_PARAMETER;
            } else {
                iv_present = true;
            }
        }
    }

    return T_COSE_SUCCESS;
}


/**
 * \brief  Decode a bucket of parameters.
 *
 * \param[in] cbor_decoder        CBOR decode context to pull from.
 * \param[in] location            Location in CBOR message of the bucket of
 *                                parameters being decoded.
 * \param[in] is_protected        \c true if bucket is protected.
 * \param[in] special_decode_cb   Function called for parameters that are not
 *                                strings or integers.
 * \param[in] special_decode_ctx  Context for the \c specials callback function.
 * \param [in] param_storage      Pool of nodes from which to allocate.
 * \param[in,out] returned_params Linked list of parameters to which
 *                                the decoded params will be added.
 *
 * This decodes a CBOR map of parameters (a "bucket") into a linked
 * list. The nodes are allocated out of \c param_storage.
 *
 * The decoded parameters are added to the list in \c
 * *decoded_parameters.  \c *decoded_parameters may be \c NULL if there is
 * no linked list to add do.
 *
 * If \c is_protected is set then every parameter decode is marked
 * as protected and vice versa.
 *
 * The \c location passed in is assigned to every parameter in the list. It
 * indicates whether the parameters are in the main body, in a signature or
 * a recipient.
 *
 * String and integer parameters are fully decoded without help. For
 * others, the \c special_decode_cb is called.
 */
static enum t_cose_err_t
t_cose_params_decode(QCBORDecodeContext                 *cbor_decoder,
                     const struct t_cose_header_location location,
                     const bool                          is_protected,
                     t_cose_param_special_decode_cb     *special_decode_cb,
                     void                               *special_decode_ctx,
                     struct t_cose_parameter_storage    *param_storage,
                     struct t_cose_parameter           **returned_params)
{
    /* Approximate stack usage
     *                                             64-bit      32-bit
     *   QCBORItem                                     56          52
     *   local vars                                    24          12
     *   crit list                                    120          80
     *   largest function call, QCBORDecode_VPeekNext 200         200
     *   TOTAL                                        400         344
     */
    QCBORError                cbor_error;
    enum t_cose_err_t         return_value;
    struct t_cose_label_list  crit_param_labels;
    struct t_cose_parameter  *decoded_param;
    QCBORItem                 item;

    QCBORDecode_EnterMap(cbor_decoder, NULL);

    label_list_clear(&crit_param_labels);

    /* --- Main loop to decode the parameters in the map --- */
    while(1) {
        /* --- Peek at next parameter and do some checks --- */
        /* Can't consume because it might be special to be consumed by callback */
        QCBORDecode_VPeekNext(cbor_decoder, &item);
        cbor_error = QCBORDecode_GetAndResetError(cbor_decoder);
        if(cbor_error == QCBOR_ERR_NO_MORE_ITEMS) {
            /* This is the successful exit from the loop */
            /* An unclosed map is caught in check after ExitMap(). */
            break;
        }
        if(cbor_error != QCBOR_SUCCESS) {
            return_value = qcbor_decode_error_to_t_cose_error(cbor_error, T_COSE_ERR_PARAMETER_CBOR);
            goto Done;
        }

        if(item.uLabelType != T_COSE_PARAMETER_TYPE_INT64) {
            return_value = T_COSE_ERR_PARAMETER_CBOR;
            goto Done;
        }

        if(item.label.int64 == T_COSE_HEADER_PARAM_CRIT) {
            /* Process "crit" parameter */
            if(!is_protected) {
                return_value = T_COSE_ERR_PARAMETER_NOT_PROTECTED;
                goto Done;
            }
            return_value = decode_crit_param(cbor_decoder, &crit_param_labels);
            if(return_value != T_COSE_SUCCESS) {
                goto Done;
            }
            continue;
        }

        /* ---- Allocate a node for it --- */
        // TODO: test this at boundary condition!
        if(param_storage->used >= param_storage->size) {
            return_value = T_COSE_ERR_TOO_MANY_PARAMETERS;
            goto Done;
        }
        decoded_param = &param_storage->storage[param_storage->used];
        param_storage->used++;

        /* --- Fill in the decoded values --- */
        decoded_param->value_type    = item.uDataType;
        decoded_param->location      = location;
        decoded_param->label         = item.label.int64;
        decoded_param->in_protected  = is_protected;
        decoded_param->critical      = false;
        decoded_param->next          = NULL;

        switch (item.uDataType) {
            case T_COSE_PARAMETER_TYPE_BYTE_STRING:
            case T_COSE_PARAMETER_TYPE_TEXT_STRING:
                decoded_param->value.string = item.val.string;
                break;

            case T_COSE_PARAMETER_TYPE_INT64:
                decoded_param->value.int64 = item.val.int64;
                break;

            default:
               if(special_decode_cb != NULL) {
                    return_value = special_decode_cb(special_decode_ctx,
                                                     cbor_decoder,
                                                     decoded_param);
                    if(return_value == T_COSE_SUCCESS) {
                        goto Next;
                    } else if(return_value != T_COSE_ERR_DECLINE) {
                        goto Done;
                    } else {
                        /* Not decoded or consumed continue loop
                         * normally and ignore.  A t_cose_parameter
                         * will go into the list for it so crit check
                         * for it can occur. */
                    }
                }
        }

        /* --- Consume it from the CBOR input ---- */
        QCBORDecode_VGetNextConsume(cbor_decoder, &item);

    Next:
        /* --- Put it in the list --- */
        /* Insert at the head of the list because it is a less
         * code. The list returned is in reverse order from the
         * encoded params, but that is OK.
         */
        if(*returned_params == NULL) {
            *returned_params = decoded_param;
        } else {
            decoded_param->next = *returned_params;
            *returned_params = decoded_param;
        }
    }

    QCBORDecode_ExitMap(cbor_decoder);
    cbor_error = QCBORDecode_GetAndResetError(cbor_decoder);
    if(cbor_error != QCBOR_SUCCESS) {
        return_value = qcbor_decode_error_to_t_cose_error(cbor_error, T_COSE_ERR_PARAMETER_CBOR);
        goto Done;
    }

    mark_crit_params(*returned_params, &crit_param_labels);

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}



/* Return true if there is a second occurance of target in param_list */
static bool
param_dup_detect_2(const struct t_cose_parameter *target,
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

/* Returns true if there is any duplicate label in a parameters list. */
static bool
param_dup_detect(const struct t_cose_parameter *params_list)
{
    const struct t_cose_parameter *p1;

    /* n ^ 2 algorithm, but n is very small. */
    for(p1 = params_list; p1 != NULL; p1 = p1->next) {
        if(param_dup_detect_2(p1, params_list)) {
            return true;
        }
    }
    return false;
}


/*
 * Public function. See t_cose_parameters.h
 */
enum t_cose_err_t
t_cose_headers_decode(QCBORDecodeContext                 *cbor_decoder,
                      const struct t_cose_header_location location,
                      t_cose_param_special_decode_cb     *special_decode_cb,
                      void                               *special_decode_ctx,
                      struct t_cose_parameter_storage    *param_storage,
                      struct t_cose_parameter           **decoded_params,
                      struct q_useful_buf_c              *protected_parameters)
{
     /* Approximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    24          12
     *   largest call, t_cose_params_decode           416         352
     *   TOTAL                                        440         364
     */

    QCBORError                cbor_error;
    enum t_cose_err_t         return_value;
    struct t_cose_parameter  *newly_decode_params;

    newly_decode_params = NULL;

    /* --- The protected parameters --- */
    QCBORDecode_EnterBstrWrapped(cbor_decoder,
                                 QCBOR_TAG_REQUIREMENT_NOT_A_TAG,
                                 protected_parameters);

    if(protected_parameters->len) {
        return_value = t_cose_params_decode(cbor_decoder,
                                            location,
                                            true,
                                            special_decode_cb,
                                            special_decode_ctx,
                                            param_storage,
                                           &newly_decode_params);
        if(return_value != T_COSE_SUCCESS) {
            goto Done;
        }
    }
    QCBORDecode_ExitBstrWrapped(cbor_decoder);

    /* ---  The unprotected parameters --- */
    return_value = t_cose_params_decode(cbor_decoder,
                                        location,
                                        false,
                                        special_decode_cb,
                                        special_decode_ctx,
                                        param_storage,
                                       &newly_decode_params);

    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* This check covers all the CBOR decode errors. */
    cbor_error = QCBORDecode_GetError(cbor_decoder);
    if(cbor_error != QCBOR_SUCCESS) {
        return_value = qcbor_decode_error_to_t_cose_error(cbor_error, T_COSE_ERR_PARAMETER_CBOR);
        goto Done;
    }


    if(param_dup_detect(newly_decode_params)) {
        return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
        goto Done;
    }

    t_cose_params_append(decoded_params, newly_decode_params);

  Done:
    return return_value;
}



/**
 * \brief Encode a bucket of header parameters.
 *
 * \param[in]  cbor_encoder         QCBOR encoder context to output to.
 * \param[in]  parameters           A linked list of parameters to encode.
 * \param[in]  is_protected_bucket  \c true if output the protected bucket,
 *                                  \c false if not.
 *
 * This iterates over the linked list of parameters outputing each
 * one. When \c is_protected_header is true the parameters marked as
 * protected will be output and vice versa.
 *
 * The callback will be invoked for parameters that are to be output
 * by a callback function.  This is required for parameters that are
 * not strings or integers
 *
 * If there are any parameters marked critical in the input, the
 * critical parameters header will be constructed and output.
 **/
static enum t_cose_err_t
t_cose_params_encode(QCBOREncodeContext            *cbor_encoder,
                     const struct t_cose_parameter *parameters,
                     const bool                     is_protected_bucket)
{
    /* Approximate stack usage
     *                                             64-bit      32-bit
     *   local vars                                    24          12
     *   largest call, t_cose_params_decode             8           4
     *   TOTAL                                         32          16
     */

    const struct t_cose_parameter  *p_param;
    bool                            criticals_present;
    enum t_cose_err_t               return_value;

    /* Protected and unprotected parameters are a map of label-value pairs */
    QCBOREncode_OpenMap(cbor_encoder);

    criticals_present = false;
    for(p_param = parameters; p_param != NULL; p_param = p_param->next) {
        if(is_protected_bucket && !p_param->in_protected) {
            continue;
        }
        if(!is_protected_bucket && p_param->in_protected) {
            continue;
        }

        switch(p_param->value_type) {
            case T_COSE_PARAMETER_TYPE_INT64:
                QCBOREncode_AddInt64ToMapN(cbor_encoder, p_param->label, p_param->value.int64);
                break;

            case T_COSE_PARAMETER_TYPE_TEXT_STRING:
                QCBOREncode_AddTextToMapN(cbor_encoder, p_param->label, p_param->value.string);
                break;

            case T_COSE_PARAMETER_TYPE_BYTE_STRING:
                QCBOREncode_AddBytesToMapN(cbor_encoder, p_param->label, p_param->value.string);
                break;

            case T_COSE_PARAMETER_TYPE_SPECIAL:
                /* Intentionally no check for NULL callback pointer to
                 * save a little object code. Caller should never
                 * indicate a callback without supplying the pointer
                 */
                return_value = p_param->value.special_encode.encode_cb(p_param, cbor_encoder);
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

    if(criticals_present) {
        if(is_protected_bucket) {
            encode_crit_parameter(cbor_encoder, parameters);
        } else {
            /* Asking for critical parameters unprotected header bucket */
            // TODO: allow disabling this check to save object code
            return_value = T_COSE_ERR_CRIT_PARAMETER_IN_UNPROTECTED;
            goto Done;
        }
    }

    QCBOREncode_CloseMap(cbor_encoder);

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}


/*
 * Public function. See t_cose_parameters.h
 */
enum t_cose_err_t
t_cose_headers_encode(QCBOREncodeContext            *cbor_encoder,
                      const struct t_cose_parameter *parameters,
                      struct q_useful_buf_c         *protected_parameters)
{
    /* Approximate stack usage
     *                                             64-bit    32-bit
     *   local vars                                     8         4
     *   largest call, t_cose_params_decode            32        16
     *   TOTAL                                         40        20
     */

    enum t_cose_err_t return_value;

    // TODO: allow disabling this check to save object code
    if(param_dup_detect(parameters)) {
        return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
        goto Done;
    }

    /* --- Protected Headers --- */
    QCBOREncode_BstrWrap(cbor_encoder);
    return_value = t_cose_params_encode(cbor_encoder,
                                            parameters,
                                            true);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    QCBOREncode_CloseBstrWrap2(cbor_encoder, false, protected_parameters);


    /* --- Unprotected Parameters --- */
    return_value = t_cose_params_encode(cbor_encoder, parameters, false);
Done:
    return return_value;
}


/*
 * Public function. See t_cose_parameters.h
 */
const struct t_cose_parameter *
t_cose_param_find(const struct t_cose_parameter *parameter_list, int64_t label)
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
t_cose_param_find_alg_id(const struct t_cose_parameter *parameter_list, bool prot)
{
    const struct t_cose_parameter *p_found;

    p_found = t_cose_param_find(parameter_list, T_COSE_HEADER_PARAM_ALG);
    if(p_found == NULL ||
        p_found->value_type != T_COSE_PARAMETER_TYPE_INT64 ||
        p_found->value.int64 == T_COSE_ALGORITHM_RESERVED ||
        p_found->value.int64 >= INT32_MAX) {
        return T_COSE_ALGORITHM_NONE;
    }

    if(prot != p_found->in_protected) { /* effective exclusive OR */
        return T_COSE_ALGORITHM_NONE;
    }

    return (int32_t)p_found->value.int64;
}


/*
 * Public function. See t_cose_parameters.h
 */
uint32_t
t_cose_param_find_content_type_uint(const struct t_cose_parameter *parameter_list)
{
    const struct t_cose_parameter *p_found;

    p_found = t_cose_param_find(parameter_list, T_COSE_HEADER_PARAM_CONTENT_TYPE);
    if(p_found != NULL &&
       p_found->value_type == T_COSE_PARAMETER_TYPE_INT64 &&
       p_found->value.int64 >= 0 &&
       p_found->value.int64 < UINT16_MAX) {
        return (uint32_t)p_found->value.int64;
    } else {
        return T_COSE_EMPTY_UINT_CONTENT_TYPE;
    }
}


/*
 * Public function. See t_cose_parameters.h
 */
struct q_useful_buf_c
t_cose_param_find_content_type_tstr(const struct t_cose_parameter *parameter_list)
{
    const struct t_cose_parameter *p_found;

    p_found = t_cose_param_find(parameter_list, T_COSE_HEADER_PARAM_CONTENT_TYPE);
    if(p_found != NULL &&
       p_found->value_type == T_COSE_PARAMETER_TYPE_TEXT_STRING) {
        return p_found->value.string;
    } else {
        return NULL_Q_USEFUL_BUF_C;
    }
}


struct q_useful_buf_c
t_cose_param_find_bstr(const struct t_cose_parameter *parameter_list, int64_t label)
{
    const struct t_cose_parameter *p_found;

    p_found = t_cose_param_find(parameter_list, label);
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
t_cose_param_find_kid(const struct t_cose_parameter *parameter_list)
{
    const struct t_cose_parameter *p_found;

    p_found = t_cose_param_find(parameter_list, T_COSE_HEADER_PARAM_KID);
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
t_cose_param_find_iv(const struct t_cose_parameter *parameter_list)
{
    const struct t_cose_parameter *p_found;

    p_found = t_cose_param_find(parameter_list, T_COSE_HEADER_PARAM_IV);
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
t_cose_param_find_partial_iv(const struct t_cose_parameter *parameter_list)
{
    const struct t_cose_parameter *p_found;

    p_found = t_cose_param_find(parameter_list, T_COSE_HEADER_PARAM_PARTIAL_IV);
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
static void
clear_cose_parameters(struct t_cose_parameters *parameters)
{
#if T_COSE_ALGORITHM_RESERVED != 0
#error Invalid algorithm designator not 0. Parameter list initialization fails.
#endif

#if T_COSE_ALGORITHM_NONE != T_COSE_ALGORITHM_RESERVED
#error Constant for unset alg ID not aligned with T_COSE_ALGORITHM_RESERVED
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
t_cose_params_common(const struct t_cose_parameter *decoded_params,
                     struct t_cose_parameters      *returned_params)
{
    enum t_cose_err_t              return_value;
    const struct t_cose_parameter *p;

    clear_cose_parameters(returned_params);
    return_value = T_COSE_SUCCESS;

    /* No duplicate detection is necessary because t_cose_headers_decode()
     * does it. */
    for(p = decoded_params; p != NULL; p = p->next) {
        if(p->label == T_COSE_HEADER_PARAM_KID) {
            if(p->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
                return_value = T_COSE_ERR_PARAMETER_CBOR;
                goto Done;
            }
            returned_params->kid = p->value.string;

        } else if(p->label == T_COSE_HEADER_PARAM_ALG) {
            if(p->value_type != T_COSE_PARAMETER_TYPE_INT64) {
                return_value = T_COSE_ERR_PARAMETER_CBOR;
                goto Done;
            }
            if(!p->in_protected) {
                return_value = T_COSE_ERR_PARAMETER_NOT_PROTECTED;
                goto Done;
            }
            if(p->value.int64 == T_COSE_ALGORITHM_RESERVED || p->value.int64 > INT32_MAX) {
                return_value = T_COSE_ERR_NON_INTEGER_ALG_ID;
                goto Done;
            }
            returned_params->cose_algorithm_id = (int32_t)p->value.int64;

        } else if(p->label == T_COSE_HEADER_PARAM_IV) {
            if(p->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
                return_value = T_COSE_ERR_PARAMETER_CBOR;
                goto Done;
            }
            if(!q_useful_buf_c_is_null(returned_params->partial_iv)) {
                /* RFC 9052 prohibits both iv and partial iv */
                return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
                goto Done;
            }
            returned_params->iv = p->value.string;

        } else if(p->label == T_COSE_HEADER_PARAM_PARTIAL_IV) {
            if(p->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
                return_value = T_COSE_ERR_PARAMETER_CBOR;
                goto Done;
            }
            if(!q_useful_buf_c_is_null(returned_params->iv)) {
                /* RFC 9052 prohibits both iv and partial iv */
                return_value = T_COSE_ERR_DUPLICATE_PARAMETER;
                goto Done;
            }
            returned_params->partial_iv = p->value.string;

#ifndef T_COSE_DISABLE_CONTENT_TYPE
        } else if(p->label == T_COSE_HEADER_PARAM_CONTENT_TYPE) {
            if(p->value_type == T_COSE_PARAMETER_TYPE_TEXT_STRING) {
                returned_params->content_type_tstr = p->value.string;

            } else if(p->value_type == T_COSE_PARAMETER_TYPE_INT64) {
                if(p->value.int64 < 0 || p->value.int64 > UINT16_MAX) {
                      return_value = T_COSE_ERR_BAD_CONTENT_TYPE;
                      goto Done;
                }
                returned_params->content_type_uint = (uint32_t)p->value.int64;

            } else {
                return_value = T_COSE_ERR_BAD_CONTENT_TYPE;
            }
#endif /* T_COSE_DISABLE_CONTENT_TYPE */
        }
    }

    Done:
        return return_value;
}
