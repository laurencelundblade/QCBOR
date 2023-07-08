/*
 * t_cose_mac_validate.h
 *
 * Copyright (c) 2019, Laurence Lundblade. All rights reserved.
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
 * The maximum number of unprocessed tags that can be returned by
 * t_cose_sign1_get_nth_tag(). The CWT
 * tag is an example of the tags that might returned. The COSE tags
 * that are processed, don't count here.
 */
#define T_COSE_MAX_TAGS_TO_RETURN 4

/**
 * Context for tag validation.  It is about 24 bytes on a
 * 64-bit machine and 12 bytes on a 32-bit machine.
 */
struct t_cose_mac_validate_ctx {
    /* Private data structure */
    struct t_cose_key                validation_key;
    uint32_t                         option_flags;
    uint64_t                         unprocessed_tag_nums[T_COSE_MAX_TAGS_TO_RETURN];
    struct t_cose_parameter          __params[T_COSE_NUM_VERIFY_DECODE_HEADERS];
    struct t_cose_parameter_storage  parameter_storage;
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
 * \brief Validate a \c COSE_Mac0 message.
 *
 * \param[in] context   The context of COSE_Mac0 validation.
 * \param[in] cose_mac  Pointer and length of CBOR encoded \c COSE_Mac0
 *                      that is to be validated.
 * \param[in] aad       The Additional Authenticated Data or
 *                      \c NULL_Q_USEFUL_BUF_C.
 * \param[out] payload        Pointer and length of the still
 *                            CBOR encoded payload.
 * \param[out] return_params  Place to return decoded parameters.
 *                            May be \c NULL.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * The validation involves the following steps.
 *
 * The CBOR structure is parsed and validated. It makes sure \c COSE_Mac0
 * is valid CBOR and that it is tagged as a \c COSE_Mac0.
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
                    struct q_useful_buf_c           cose_mac,
                    struct q_useful_buf_c           aad,
                    struct q_useful_buf_c          *payload,
                    struct t_cose_parameter       **return_params);

/*
 * This is the same as t_cose_mac_validate(), but the payload is detached.
 * See t_cose_mac_compute_detached() for more details in t_cose_mac_compute.h
 */
static enum t_cose_err_t
t_cose_mac_validate_detached(struct t_cose_mac_validate_ctx *context,
                             struct q_useful_buf_c           cose_mac,
                             struct q_useful_buf_c           aad,
                             struct q_useful_buf_c           detached_payload,
                             struct t_cose_parameter       **return_params);


/**
 * \brief Return unprocessed tags from most recent MAC validate.
 *
 * \param[in] context   The t_cose mac validation context.
 * \param[in] n         Index of the tag to return.
 *
 * \return  The tag value or \ref CBOR_TAG_INVALID64 if there is no tag
 *          at the index or the index is too large.
 *
 * The 0th tag is the one for which the COSE message is the content. Loop
 * from 0 up until \ref CBOR_TAG_INVALID64 is returned. The maximum
 * is \ref T_COSE_MAX_TAGS_TO_RETURN.
 *
 * It will be necessary to call this for a general implementation
 * of a CWT since sometimes the CWT tag is required. This is also
 * useful for recursive processing of nested COSE signing, mac
 * and encryption.
 */
static inline uint64_t
t_cose_mac_validate_nth_tag(const struct t_cose_mac_validate_ctx *context,
                            size_t                                n);



/* ------------------------------------------------------------------------
 * Private and inline implementations of public functions defined above.
 * ------------------------------------------------------------------------ */


/**
 * \brief Semi-private function to validate a COSE_Mac0 message.
 *
 * \param[in] context   The context of COSE_Mac0 validation.
 * \param[in] cose_mac  Pointer and length of CBOR encoded \c COSE_Mac0
 *                      that is to be validated.
 * \param[in] aad       The Additional Authenticated Data or
 *                      \c NULL_Q_USEFUL_BUF_C.
 * \param[in] payload_is_detached  If \c true, indicates the \c payload
 *                                 is detached.
 * \param[out] payload             Pointer and length of the still CBOR
 *                                 encoded payload.
 * \param[out] return_params       Place to return decoded parameters.
 *                                 May be \c NULL.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * It is a semi-private function internal to the implementation which means its
 * interface isn't guaranteed so it should not be called directly. Call
 * t_cose_mac_validate() or t_cose_mac_validate_detached() instead of this.
 */
enum t_cose_err_t
t_cose_mac_validate_private(struct t_cose_mac_validate_ctx *context,
                            struct q_useful_buf_c           cose_mac,
                            struct q_useful_buf_c           aad,
                            bool                            payload_is_detached,
                            struct q_useful_buf_c          *payload,
                            struct t_cose_parameter       **return_params);


static inline void
t_cose_mac_validate_init(struct t_cose_mac_validate_ctx *me,
                         uint32_t                        option_flags)
{
    memset(me, 0, sizeof(*me));
    me->option_flags = option_flags;
    T_COSE_PARAM_STORAGE_INIT(me->parameter_storage, me->__params);
}


static inline void
t_cose_mac_set_validate_key(struct t_cose_mac_validate_ctx *me,
                            struct t_cose_key               validate_key)
{
    me->validation_key = validate_key;
}


static inline enum t_cose_err_t
t_cose_mac_validate(struct t_cose_mac_validate_ctx *me,
                    struct q_useful_buf_c           cose_mac,
                    struct q_useful_buf_c           aad,
                    struct q_useful_buf_c          *payload,
                    struct t_cose_parameter       **return_params)
{
    return t_cose_mac_validate_private(me,
                                       cose_mac,
                                       aad,
                                       false,
                                       payload,
                                       return_params);
}


static inline enum t_cose_err_t
t_cose_mac_validate_detached(struct t_cose_mac_validate_ctx *me,
                             struct q_useful_buf_c           cose_mac,
                             struct q_useful_buf_c           aad,
                             struct q_useful_buf_c           detached_payload,
                             struct t_cose_parameter       **return_params)
{
    return t_cose_mac_validate_private(me,
                                       cose_mac,
                                       aad,
                                       true,
                                      &detached_payload,
                                       return_params);
}


static inline uint64_t
t_cose_mac_validate_nth_tag(const struct t_cose_mac_validate_ctx *me,
                            size_t                                n)
{
    if(n > T_COSE_MAX_TAGS_TO_RETURN) {
        return CBOR_TAG_INVALID64;
    }
    return me->unprocessed_tag_nums[n];
}


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_MAC_VALIDATE_H_ */
