/*
 * t_cose_mac_compute.h
 *
 * Copyright (c) 2018-2019, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2020-2023 Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __T_COSE_MAC_COMPUTE_H_
#define __T_COSE_MAC_COMPUTE_H_

#include <stdint.h>
#include "t_cose/q_useful_buf.h"
#include "qcbor/qcbor_encode.h"
#include "t_cose_common.h"
#include "t_cose/t_cose_key.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This is the context for creating a \c COSE_Mac structure. The caller
 * should allocate it and pass it to the functions here.  This is
 * about 32 bytes so it fits easily on the stack.
 */
struct t_cose_mac_calculate_ctx {
    /* Private data structure */
    uint8_t                protected_parameters_buffer[
                                    T_COSE_MAC0_MAX_SIZE_PROTECTED_PARAMETERS];
    struct q_useful_buf_c  protected_parameters; /* The encoded protected parameters */
    int32_t                cose_algorithm_id;
    struct t_cose_key      mac_key;
    uint32_t               option_flags;
    struct q_useful_buf_c  kid;
    struct t_cose_parameter *added_body_parameters;
};


/**
 * \brief Initialize to start creating a \c COSE_Mac0.
 *
 * \param[in] context            The t_cose MAC context.
 * \param[in] option_flags       One of \c T_COSE_OPT_XXXX.
 * \param[in] cose_algorithm_id  The algorithm to generate the authentication
 *                               tag, for example \ref T_COSE_ALGORITHM_HMAC256.
 *
 * Initialize the \ref t_cose_mac_calculate_ctx context. Typically, no
 * \c option_flags are needed and 0 is passed. A \c cose_algorithm_id
 * must always be given.
 *
 * The algorithm ID space is from
 * [COSE (RFC9053)](https://tools.ietf.org/html/rfc9053) and the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 * \ref T_COSE_ALGORITHM_HMAC256 is defined here for convenience.
 * So far, only HMAC is supported in \c COSE_Mac0.
 *
 * Errors such as the passing of an unsupported \c cose_algorithm_id
 * are reported when t_cose_mac_encode_parameters() is called.
 */
static void
t_cose_mac_compute_init(struct t_cose_mac_calculate_ctx *context,
                        uint32_t                         option_flags,
                        int32_t                          cose_algorithm_id);


/**
 * \brief Set the key and kid (key ID) for computing MAC.
 *
 * \param[in] context      The t_cose MAC context.
 * \param[in] mac_key      The MAC key to use or an empty key.
 * \param[in] kid          COSE key ID parameter or \c NULL_Q_USEFUL_BUF_C.
 *
 * This needs to be called to set the MAC key to use. The \c kid
 * may be omitted by giving \c NULL_Q_USEFUL_BUF_C.
 *
 * TODO: is empty key really OK?
 */
static void
t_cose_mac_set_computing_key(struct t_cose_mac_calculate_ctx *context,
                             struct t_cose_key                mac_key,
                             struct q_useful_buf_c            kid);


/**
 * \brief Add header parameters to the \c COSE_Mac0 message.
 *
 * \param[in] context     The t_cose MAC context.
 * \param[in] parameters  Linked list of parameters to add.
 *
 * For simple use cases it is not necessary to call this as the
 * algorithm ID, the only mandatory parameter, is automatically
 * added.
 *
 * It is not necessary to call this to add the kid either as that
 * is handled by the t_cose_mac_set_computing_key() function.
 *
 * This is called only once to add a linked list of \ref t_cose_parameter.
 * Each node is filled in with the type, value, criticality and protectedness
 * of the parameter. Integer and strings values go in the node. Other types are
 * allowed through a parameter encode callback.
 * Only integer parameter labels are supported (so far).
 */
static void
t_cose_mac_add_body_header_params(struct t_cose_mac_calculate_ctx *context,
                                  struct t_cose_parameter         *parameters);


/**
 * \brief Output first part and parameters for a \c COSE_Mac0 message.
 *
 * \param[in] context          The t_cose MAC context.
 * \param[in] cbor_encode_ctx  Encoding context to output to.
 *
 * t_cose_mac_compute_init() and t_cose_mac_set_computing_key() must be
 * called before calling this.
 *
 * When this is called, the opening parts of the \c COSE_Mac0 message
 * are output to the \c cbor_encode_ctx.
 *
 * After this is called, the CBOR-formatted payload must be written to
 * the \c cbor_encode_ctx by calling all the various \c QCBOREncode_AddXxx
 * calls. It can be as simple or complex as needed.
 *
 * To complete the \c COSE_Mac0 message call t_cose_mac_encode_tag().
 *
 * The \c cbor_encode_ctx must have been initialized with an output
 * buffer to hold the \c COSE_Mac0 header parameters, the payload and
 * the authentication tag.
 *
 * This and t_cose_mac_encode_tag() can be used to calculate
 * the size of the \c COSE_Mac0 in the way \c QCBOREncode is usually
 * used to calculate sizes. In this case the \c t_cose_mac_calculate_ctx must
 * be initialized with the options, algorithm, key and kid just as
 * normal as these are needed to calculate the size. Then set up the
 * QCBOR encoder context with a \c NULL pointer and large length like
 * \c UINT32_MAX.  Call t_cose_mac_encode_parameters(), format
 * the payload into the encoder context, then call t_cose_mac_encode_tag().
 * Finally call \c QCBOREncode_FinishGetSize() to get the length.
 */
enum t_cose_err_t
t_cose_mac_encode_parameters(struct t_cose_mac_calculate_ctx *context,
                             QCBOREncodeContext              *cbor_encode_ctx);


/**
 * \brief Finish a \c COSE_Mac0 message by outputting the authentication tag.
 *
 * \param[in] context          The t_cose MAC context.
 * \param[in] payload          Pointer and length of payload to be MACed.
 * \param[in] cbor_encode_ctx  Encoding context to output to.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * Call this to complete creation of a tagged \c COSE_Mac0 started
 * with t_cose_mac_encode_parameters().
 *
 * This is when the cryptographic MAC algorithm is run.
 *
 * The completed \c COSE_Mac0 message is retrieved from the
 * \c cbor_encode_ctx by calling \c QCBOREncode_Finish().
 */
enum t_cose_err_t
t_cose_mac_encode_tag(struct t_cose_mac_calculate_ctx *context,
                      struct q_useful_buf_c            payload,
                      QCBOREncodeContext              *cbor_encode_ctx);


/**
 * \brief Create and compute a \c COSE_Mac0 message with a payload in one call.
 *
 * \param[in] context  The t_cose MAC context.
 * \param[in] aad      The Additional Authenticated Data or
 *                     \c NULL_Q_USEFUL_BUF_C.
 * \param[in] payload  Pointer and length of payload to be MACed.
 * \param[in] out_buf  Pointer and length of buffer to output to.
 * \param[out] result  Pointer and length of the resulting \c COSE_Mac0.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * The \c context must have been initialized with t_cose_mac_compute_init() and
 * the key set with t_cose_mac_set_computing_key() before this is called.
 *
 * This creates the COSE header parameter, hashes and computes the MAC
 * authentication tag of the payload in one go. \c out_buf gives
 * the pointer and length of the memory into which the output is
 * written. The pointer and length of the completed \c COSE_Mac0 is
 * returned in \c result.  (\c out_buf and \c result are used instead
 * of the usual in/out parameter for length because it is the
 * convention for q_useful_buf and is more const correct.)
 *
 * The size of \c out_buf must be the size of the payload plus
 * overhead for formatting, the authentication tag and the key id (if used).
 *
 * To compute the size of the buffer needed before it is allocated
 * call this with \c out_buf containing a \c NULL pointer and large
 * length like \c UINT32_MAX.  The algorithm and key, kid and such
 * must be set up just as if the real \c COSE_Mac0 were to be created
 * as these values are needed to compute the size correctly.  The
 * contents of \c result will be a \c NULL pointer and the length of
 * the \c COSE_Mac0. When run like this, the cryptographic functions
 * will not actually run, but the size of their output will
 * be taken into account to give an exact size.
 *
 * This function requires the payload be complete and formatted in a
 * contiguous buffer. The resulting \c COSE_MAc0 message also
 * contains the payload preceded by the header parameters and followed
 * by the tags, all CBOR formatted. This function thus requires
 * two copies of the payload to be in memory.  Alternatively
 * t_cose_mac_encode_parameters() and
 * t_cose_mac_encode_tag() can be used. They are more complex
 * to use, but avoid the two copies of the payload and can reduce
 * memory requirements by close to half.
 */
static enum t_cose_err_t
t_cose_mac_compute(struct t_cose_mac_calculate_ctx *context,
                   struct q_useful_buf_c            aad,
                   struct q_useful_buf_c            payload,
                   struct q_useful_buf              out_buf,
                   struct q_useful_buf_c           *result);


/**
 * \brief Create and compute a \c COSE_Mac0 message with detached
 *        payload in one call.
 *
 * \param[in] context  The t_cose MAC context.
 * \param[in] aad      The Additional Authenticated Data or
 *                     \c NULL_Q_USEFUL_BUF_C.
 * \param[in] datached_payload  Pointer and length of the detached payload
 *                              to be MACed.
 * \param[in] out_buf  Pointer and length of buffer to output to.
 * \param[out] result  Pointer and length of the resulting \c COSE_Mac0.
 *
 *  * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This is similar to, but not the same as t_cose_mac_compute(). Here
 * the payload is detached and conveyed separately. The hash and authentication
 * tag is still computed over the payload as with t_cose_mac_compute(). The
 * payload must be conveyed to recipient by some other means than by being
 * inside the \c COSE_Mac0 message. The recipient will be unable to validate
 * the received message without it.
 */
static enum t_cose_err_t
t_cose_mac_compute_detached(struct t_cose_mac_calculate_ctx *context,
                            struct q_useful_buf_c            aad,
                            struct q_useful_buf_c            datached_payload,
                            struct q_useful_buf              out_buf,
                            struct q_useful_buf_c           *result);


/* ------------------------------------------------------------------------
 * Private and inline implementations of public functions defined above.
 * ------------------------------------------------------------------------ */
#include "t_cose/t_cose_parameters.h" // TODO: maybe remove this?


/**
 * \brief Semi-private function that creates and computes a \c COSE_Mac0
 *        message in one call.
 *
 * \param[in] context              The t_cose MAC context.
 * \param[in] payload_is_detached  If \c true, then \c payload is detached.
 * \param[in] aad                  The Additional Authenticated Data or
 *                                 \c NULL_Q_USEFUL_BUF_C.
 * \param[in] payload              The payload to be MACed, inline or detached.
 * \param[in] out_buf              Pointer and length of buffer to output to.
 * \param[out] result              Pointer and length of the resulting
 *                                 \c COSE_Mac0.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * This is where the work actually gets done for computing MAC that is done
 * all in one call with or without AAD and for included or detached payloads.
 *
 * This is a private function internal to the implementation. Call
 * t_cose_mac_compute() or t_cose_mac_compute_detached() instead of this.
 */
enum t_cose_err_t
t_cose_mac_compute_private(struct t_cose_mac_calculate_ctx *context,
                           bool                             payload_is_detached,
                           struct q_useful_buf_c            aad,
                           struct q_useful_buf_c            payload,
                           struct q_useful_buf              out_buf,
                           struct q_useful_buf_c           *result);


static inline void
t_cose_mac_compute_init(struct t_cose_mac_calculate_ctx *me,
                        uint32_t                         option_flags,
                        int32_t                          cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
    me->cose_algorithm_id = cose_algorithm_id;
    me->option_flags      = option_flags;
}


static inline void
t_cose_mac_set_computing_key(struct t_cose_mac_calculate_ctx *me,
                             struct t_cose_key                mac_key,
                             struct q_useful_buf_c            kid)
{
    me->kid     = kid;
    me->mac_key = mac_key;
}


static inline void
t_cose_mac_add_body_header_params(struct t_cose_mac_calculate_ctx *me,
                                  struct t_cose_parameter         *parameters)
{
    me->added_body_parameters = parameters;
}


static inline enum t_cose_err_t
t_cose_mac_compute(struct t_cose_mac_calculate_ctx *me,
                   struct q_useful_buf_c            aad,
                   struct q_useful_buf_c            payload,
                   struct q_useful_buf              out_buf,
                   struct q_useful_buf_c           *result)
{
    return t_cose_mac_compute_private(me,
                                      false,
                                      aad,
                                      payload,
                                      out_buf,
                                      result);
}


static inline enum t_cose_err_t
t_cose_mac_compute_detached(struct t_cose_mac_calculate_ctx *me,
                            struct q_useful_buf_c            aad,
                            struct q_useful_buf_c            detached_payload,
                            struct q_useful_buf              out_buf,
                            struct q_useful_buf_c           *result)
{
    (void)aad;
    return t_cose_mac_compute_private(me,
                                      true,
                                      NULL_Q_USEFUL_BUF_C,
                                      detached_payload,
                                      out_buf,
                                      result);
}


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_MAC_COMPUTE_H_ */
