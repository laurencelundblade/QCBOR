/*
 * t_cose_mac_validate.h
 *
 * Copyright (c) 2019, 2025, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2020-2023 Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __T_COSE_MAC_VALIDATE_H_
#define __T_COSE_MAC_VALIDATE_H_

#include <stdint.h>
#include "t_cose/q_useful_buf.h"
#include "qcbor/qcbor.h"
#include "t_cose_common.h"
#include "t_cose/t_cose_key.h"
#include "t_cose/t_cose_parameters.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Context for tag validation.  It is about 360 bytes on a
 * 64-bit machine.
 */
struct t_cose_mac_validate_ctx {
    /* Private data structure */
    struct t_cose_key                validation_key;
    uint32_t                         option_flags;
    struct t_cose_parameter          __params[T_COSE_NUM_DECODE_HEADERS];
    struct t_cose_parameter_storage  parameter_storage;
    struct t_cose_parameter_storage *p_storage;
    t_cose_param_special_decode_cb  *special_param_decode_cb;
    void                            *special_param_decode_ctx;
};


/**
 * \brief Initialize for \c COSE_Mac0 message validation.
 *
 * \param[in,out] context       The t_cose MAC context to initialize.
 * \param[in]     option_flags  Options controlling the validation.
 *
 * This must be called before using the validation context.
 */
static void
t_cose_mac_validate_init(struct t_cose_mac_validate_ctx *context,
                         uint32_t                        option_flags);


/**
 * \brief Set key for \c COSE_Mac0 message validation.
 *
 * \param[in,out] context       The context of COSE_Mac0 validation.
 * \param[in]     validate_key  The MAC validation key to use.
 *
 * Look up by kid parameter and fetch the key for MAC validation.
 * Setup the \ref validate_key structure and fill it in \ref context.
 */
static void
t_cose_mac_set_validate_key(struct t_cose_mac_validate_ctx *context,
                            struct t_cose_key               validate_key);

/**
 * \brief Add storage for header parameter decoding.
 *
 * \param[in] context     Signed message verification context.
 * \param[in] storage     The parameter storage to add.
 *
 * This is optionally called to increase the number of storage nodes
 * for COSE_Mac message with
 * \ref T_COSE_NUM_VERIFY_DECODE_HEADERS header parameters.  Decoded
 * parameters are returned in a linked list of struct
 * t_cose_parameter.  The storage for the nodes in the list is not
 * dynamically allocated as there is no dynamic storage allocation
 * used here.
 *
 * It is assumed that the
 * number of parameters is small and/or can be anticipated.
 * There must be room to decode all the header parameters that
 * are in the body and in all in the COSE_Signatures. If not
 * \ref T_COSE_ERR_TOO_MANY_PARAMETERS will be returned by
 * t_cose_sign_verify() and similar.
 *
 * By default, if this is not called there is internal storage for
 * \ref T_COSE_NUM_DECODE_HEADERS headers. If this is not
 * enough call this function to use external storage instead of the
 * internal. This replaces the internal storage. It does not add to
 * it.
 *
 * t_cose_parameter_storage allows for the storage to be partially
 * used when it is passed in and whatever is not used by this
 * decode can be used elsewhere. It internall keeps track of how
 * many nodes were used.
 */
static void
t_cose_mac_add_param_storage(struct t_cose_mac_validate_ctx  *context,
                             struct t_cose_parameter_storage *storage);


/*
 * If custom headers that are not strings or integers needed to be
 * decoded and processed, then use this to set a call back handler.
 * Typically this is not needed.
 */
static void
t_cose_mac_set_special_param_decoder(struct t_cose_mac_validate_ctx *context,
                                     t_cose_param_special_decode_cb *decode_cb,
                                     void                           *decode_ctx);

/**
 * \brief Validate a \c COSE_Mac0 message.
 *
 * \param[in] context         The context of COSE_Mac0 validation.
 * \param[in] cbor_decoder    Source of the input COSE message to validate.
 * \param[in] ext_sup_data    Externally supplied data or \c NULL_Q_USEFUL_BUF_C.
 * \param[out] payload        Pointer and length of the payload.
 * \param[out] return_params  Place to return decoded parameters.
 *                            May be \c NULL.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This is the base method for MAC validation. It links the least object code. See t_cose_mac_validate_msg() for
 * a method that takes the message from a buffer and does
 * more tag number processing.
 *
 * The COSE message to be validated is decoded from the given QCBOR
 * decode context.
 *
 * If the validation context is configured
 * with T_COSE_OPT_MESSAGE_TYPE_MAC0 in \c option,
 * then this will error out if  any tag numbers are present.
 * If configured with T_COSE_OPT_MESSAGE_TYPE_UNSPECIFIED
 * one tag number identifying the type of COSE Mac message
 * must be present. As this currently only supports COSE_Mac0,
 * this will error out if the tag number is other than that
 * for COSE_Mac0.
 *
 * The MAC algorithm is pulled out of the protected header.
 *
 * The kid (key ID) is parsed out of the unprotected header if it exists.
 *
 * The payload is identified. It doesn't have to be parsed in detail
 * because it is wrapped in a bstr.
 *
 * Finally, the MAC validation is performed if \ref T_COSE_OPT_DECODE_ONLY
 * is not set in option flag. Otherwise, the validation will be skipped.
 * The MAC algorithm to use comes from the algorithm field in the
 * protected header.
 * If the algorithm is not known or not supported this will error out.
 *
 * If it is successful, the pointer of the CBOR-encoded payload is returned.
 *
 * See also t_cose_mac_validate_detached().
 */
static enum t_cose_err_t
t_cose_mac_validate(struct t_cose_mac_validate_ctx *context,
                    QCBORDecodeContext             *cbor_decoder,
                    struct q_useful_buf_c           ext_sup_data,
                    struct q_useful_buf_c          *payload,
                    struct t_cose_parameter       **return_params);


/**
 * \brief Validate a \c COSE_Mac0 message with detached payload.
 *
 * \param[in] context         The context of COSE_Mac0 validation.
 * \param[in] cbor_decoder        Source of the input message to validate.
 * \param[in] ext_sup_data    Externally supplied data or \c NULL_Q_USEFUL_BUF_C.
 * \param[in] detached_payload        Pointer and length of the payload.
 * \param[out] return_params  Place to return decoded parameters.
 *                            May be \c NULL.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This is the same as t_cose_mac_validate() except the payload is detached.
 * The payload is not in the COSE message. It is external and thus supplied
 * for validation as an input parameter.
 */
static enum t_cose_err_t
t_cose_mac_validate_detached(struct t_cose_mac_validate_ctx *context,
                             QCBORDecodeContext             *cbor_decoder,
                             struct q_useful_buf_c           ext_sup_data,
                             struct q_useful_buf_c           detached_payload,
                             struct t_cose_parameter       **return_params);


/**
 * \brief Validate a \c COSE_Mac0 message.
 *
 * \param[in] context         The context of COSE_Mac0 validation.
 * \param[in] cose_mac        Pointer and length of CBOR encoded \c COSE_Mac0
 *                            that is to be validated.
 * \param[in] ext_sup_data    Externally supplied data or \c NULL_Q_USEFUL_BUF_C.
 * \param[out] payload        Pointer and length of the still
 *                            CBOR encoded payload.
 * \param[out] return_params  Place to return decoded parameters.
 *                            May be \c NULL.
 * \param[out] tag_numbers Place to return preceding tag numbers or NULL.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This is a wrapper around t_cose_mac_validate().
 *
 * Internally, this creates an instance of the CBOR decoder and initializes it with
 * the COSE message.
 *
 * All tag numbers preceding the message are consumed.
 * \ref T_COSE_OPT_MESSAGE_TYPE_MAC0 and \ref T_COSE_OPT_MESSAGE_TYPE_UNSPECIFIED
 * are used the same as t_cose_mac_validate(),
 * Tag numbers not used in determing the message type
 * are returned in \c tag_numbers
 * so they can be checked by the caller.  Tag numbers are usually not optional an
 * should not be ignored. If
 * tag numbers are present in the input and \c tag_numbers is NULL, an
 * error occurs.
 */
static enum t_cose_err_t
t_cose_mac_validate_msg(struct t_cose_mac_validate_ctx *context,
                        struct q_useful_buf_c           cose_message,
                        struct q_useful_buf_c           ext_sup_data,
                        struct q_useful_buf_c          *payload,
                        struct t_cose_parameter       **return_params,
                        uint64_t                        tag_numbers[T_COSE_MAX_TAGS_TO_RETURN]);


static enum t_cose_err_t
t_cose_mac_validate_detached_msg(struct t_cose_mac_validate_ctx *context,
                                 struct q_useful_buf_c           cose_message,
                                 struct q_useful_buf_c           ext_sup_data,
                                 struct q_useful_buf_c           detached_payload,
                                 struct t_cose_parameter       **return_params,
                                 uint64_t                        tag_numbers[T_COSE_MAX_TAGS_TO_RETURN]);



/* ------------------------------------------------------------------------
 * Private and inline implementations of public functions defined above.
 * ------------------------------------------------------------------------ */

/** @private  Semi-private function. See t_cose_mac_validate.c */
enum t_cose_err_t
t_cose_mac_validate_private(struct t_cose_mac_validate_ctx *me,
                            QCBORDecodeContext             *cbor_decoder,
                            struct q_useful_buf_c           ext_sup_data,
                            bool                            payload_is_detached,
                            struct q_useful_buf_c          *payload,
                            struct t_cose_parameter       **return_params,
                            uint64_t                        tag_numbers[T_COSE_MAX_TAGS_TO_RETURN]);

/** @private  Semi-private function. See t_cose_mac_validate.c */
enum t_cose_err_t
t_cose_mac_validate_msg_private(struct t_cose_mac_validate_ctx *context,
                                struct q_useful_buf_c           cose_message,
                                struct q_useful_buf_c           ext_sup_data,
                                bool                            payload_is_detached,
                                struct q_useful_buf_c          *payload,
                                struct t_cose_parameter       **return_params,
                                uint64_t                        tag_numbers[T_COSE_MAX_TAGS_TO_RETURN]);


static inline void
t_cose_mac_validate_init(struct t_cose_mac_validate_ctx *me,
                         uint32_t                        option_flags)
{
    memset(me, 0, sizeof(*me));
    me->option_flags = option_flags;
    T_COSE_PARAM_STORAGE_INIT(me->parameter_storage, me->__params);
    me->p_storage          = &(me->parameter_storage);
}


static inline void
t_cose_mac_set_validate_key(struct t_cose_mac_validate_ctx *me,
                            struct t_cose_key               validate_key)
{
    me->validation_key = validate_key;
}

static inline void
t_cose_mac_add_param_storage(struct t_cose_mac_validate_ctx  *me,
                             struct t_cose_parameter_storage *storage)
{
    me->p_storage = storage;
}

static inline void
t_cose_mac_set_special_param_decoder(struct t_cose_mac_validate_ctx *me,
                                     t_cose_param_special_decode_cb *decode_cb,
                                     void                           *decode_ctx)
{
    me->special_param_decode_cb  = decode_cb;
    me->special_param_decode_ctx = decode_ctx;
}

static inline enum t_cose_err_t
t_cose_mac_validate(struct t_cose_mac_validate_ctx *me,
                    QCBORDecodeContext             *cbor_decoder,
                    struct q_useful_buf_c           ext_sup_data,
                    struct q_useful_buf_c          *payload,
                    struct t_cose_parameter       **return_params)
{
    return t_cose_mac_validate_private(me,
                                       cbor_decoder,
                                       ext_sup_data,
                                       false,
                                       payload,
                                       return_params,
                                       NULL);
}

static inline enum t_cose_err_t
t_cose_mac_validate_detached(struct t_cose_mac_validate_ctx *me,
                             QCBORDecodeContext             *cbor_decoder,
                             struct q_useful_buf_c           ext_sup_data,
                             struct q_useful_buf_c           detached_payload,
                             struct t_cose_parameter       **return_params)
{
    return t_cose_mac_validate_private(me,
                                       cbor_decoder,
                                       ext_sup_data,
                                       true,
                                       &detached_payload,
                                       return_params,
                                       NULL);
}

static inline enum t_cose_err_t
t_cose_mac_validate_msg(struct t_cose_mac_validate_ctx *me,
                        struct q_useful_buf_c           cose_message,
                        struct q_useful_buf_c           ext_sup_data,
                        struct q_useful_buf_c          *payload,
                        struct t_cose_parameter       **return_params,
                        uint64_t                        tag_numbers[T_COSE_MAX_TAGS_TO_RETURN])
{
    return t_cose_mac_validate_msg_private(me,
                                           cose_message,
                                           ext_sup_data,
                                           false,
                                           payload,
                                           return_params,
                                           tag_numbers);
}

static inline enum t_cose_err_t
t_cose_mac_validate_detached_msg(struct t_cose_mac_validate_ctx *me,
                                 struct q_useful_buf_c           cose_message,
                                 struct q_useful_buf_c           ext_sup_data,
                                 struct q_useful_buf_c           detached_payload,
                                 struct t_cose_parameter       **return_params,
                                 uint64_t                        tag_numbers[T_COSE_MAX_TAGS_TO_RETURN])
{
    return t_cose_mac_validate_msg_private(me,
                                           cose_message,
                                           ext_sup_data,
                                           true,
                                           &detached_payload,
                                           return_params,
                                           tag_numbers);
}



#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_MAC_VALIDATE_H_ */
