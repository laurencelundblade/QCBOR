/*
 * t_cose_parameters.h
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2022 Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_parameters_h
#define t_cose_parameters_h

#include <stdint.h>
#include "qcbor/qcbor.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_key.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @file t_cose_parameters.h
 *
 * @brief Parameter encoding and decoding.
 *
 * Parameter encoding and decoding centers on \ref t_cose_parameter
 * and functions for encoding and decoding linked lists of it. Users
 * of the t_cose public APIs for verifying signing, encrypting,
 * decrypting and MACing will mainly use struct t_cose_parameter, not
 * the encoding and decoding functions.
 *
 * Struct \ref t_cose_parameter holds a single parameter that
 * is to be encoded or has been decoded. The same structure is used
 * for both. Most parameter values are either integers or strings and
 * are held directly in struct t_cose_parameter. Parameters that are
 * not integers or strings are special and must be encoded or decoded
 * by a callback. "Special" here is only a characteristic of t_cose
 * not anything in the COSE standard.
 *
 * Only integer parameter labels are supported (so far).
 *
 * For many encoding use cases the needed header parameters will be
 * automatically generated and there is no need for use of anything in
 * this file.
 *
 * When decoding a COSE message (verification, decryption, ...) the
 * full set of header parameters decoded are returned as linked list of
 * struct t_cose_parameter. In many cases the caller will not need to
 * examine what is returned.
 *
 * If the caller wishes to examine them, they can iterate over the
 * linked list searching by label. The data type, protected-ness and
 * criticality of the parameters in the returned list is not
 * checked. It is up to the caller examining these to check.  Some
 * functions for examining headers in the array are provided. See
 * t_cose_find_parameter(), t_cose_find_parameter_kid(), etc… These do
 * fully check the protected-ness, criticality and type of the
 * parameter.
 *
 * Some COSE messages, COSE_Sign1, COSE_Mac0 and COSE_Encrypt0 have
 * just one set of headers, those for the main body.  Other
 * messages, COSE_Sign, COSE_Encrypt and COSE_Mac, have body headers
 * and additionally headers per recipient or signer. The data
 * structures and functions here handle all of these.
 *
 * When encoding, multiple header sets are handled in the
 * interface for signing, encrypting and such. There are separate
 * functions for passing in the body header and the header per signer
 * and per recipient.
 *
 * When decoding, all the headers for the entire message are returned
 * in one list. Each bucket of headers is assigned a location
 * (t_cose_header_location) that indicates nesting level and
 * index in the COSE message.
 *
 * The nodes for the linked lists are allocated out of a pool that
 * is represented by t_cose_parameter_storage. It is a very
 * simple allocation scheme that takes nodes out of the pool
 * as the COSE message is decoded. There is not a
 * free operation. The whole pool is just destroyed when
 * all processing on a COSE message is complete. The
 * actual memory for the pool can be allocated by any
 * means, but it is allocated all at once up front.
 *
 * Each message decoder (e.g., verifier, decryptor) has a small pool
 * built into their context that is enough for simple message. A
 * larger pool can be added for complex messages with lots of
 * parameters.
 */

/**
 * The maximum number of critical header parameters that can be
 * handled during decoding (e.g., during verification, decryption,
 * ...). \ref T_COSE_ERR_TOO_MANY_PARAMETERS will be returned if the
 * input message has more.
 *
 * There can be both \ref T_COSE_MAX_CRITICAL_PARAMS integer-labeled
 * parameters and \ref T_COSE_MAX_CRITICAL_PARAMS string-labeled
 * parameters.
 *
 * This is a hard maximum so the implementation doesn't need
 * malloc. This constant can be increased if needed. Doing so will
 * increase stack usage.
 */
#define T_COSE_MAX_CRITICAL_PARAMS 4



/* Forward declaration. See actual definition below. */
struct t_cose_parameter;


/**
 * \brief Type of callback to output the encoded CBOR of a special parameter.
 *
 * \param[in] parameter      A single parameter to encode.
 * \param[in] cbor_encoder  The encoder instance to output to.
 *
 * A callback pointer of this type is placed in struct
 * t_cose_parameter. It is called back when t_cose_encode_headers()
 * gets to encoding the particular parameter. It is typically used for
 * encoding special parameters that are not integers or strings, but can be
 * used for them too. For most use cases, this is not needed.
 *
 * When called it should output the CBOR for the header parameter to
 * the CBOR encoder context including the header label.
 *
 * If this returns an error, encoding of the COSE message will stop and
 * error out with the error it returned.
 *
 * If desired there can be several implementations of this for several
 * different parameters or types of parameters.
 */
typedef enum t_cose_err_t
t_cose_param_special_encode_cb(const struct t_cose_parameter  *parameter,
                               QCBOREncodeContext             *cbor_encoder);


/**
 * \brief Type of callback to decode a special parameter.
 *
 * \param[in] cb_context     Context for callback.
 * \param[in] cbor_decoder   QCBOR decoder to pull from.
 * \param[in,out] parameter  On input, label and other. On output
 *                           the decoded value.

 * \retval T_COSE_SUCCESS   Decoded and input consumed
 * \retval T_COSE_DECLINE   Not decoded and input was NOT consumed
 * \retval other            Any other error will stop the decode and return that
 *                          error up to top-level message decode.
 *
 * This is called back from t_cose_decode_headers() when a parameter
 * that is not an integer or string is encountered.
 *
 * On input, the label, protected, critical and value_type are set
 * based on peeking at the first data item in the header. The value is
 * not set and none of the items in the parameter have been consumed.
 *
 * A callback can decided not to process the parameter by checking the
 * parameter label and such passed in. If it ia not to be process
 * return \ref T_COSE_ERR_DECLINE.  The parameter will be ignored. If
 * a critical parameter is declined, this will be noticed and the COSE
 * message processing will error out with \ref
 * T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER.
 *
 * For a successful decode, all of the CBOR items for the parameter must
 * be consumed from the cbor decoder. T_COSE_SUCCESS should be
 * returned. The decoded value(s) is(are)  put into \c parameter.value.
 * Any of the the members of \c parameter.value may be used,
 * particularly \c parameter.value.special_decode.
 *
 * For an unsuccesful decode return an appropriate error like
 * T_COSE_ERR_NOT_WELL_FORMED. It will halt processing
 * of the message flow and be returned to the top level call.
 *
 * Unlike t_cose_special_param_encode_cb() only one of these may be set.
 * Implementation of this switche on the label to know which parameter
 * to output.
 */
typedef enum t_cose_err_t
t_cose_param_special_decode_cb(void                    *cb_context,
                               QCBORDecodeContext      *cbor_decoder,
                               struct t_cose_parameter *parameter);


struct t_cose_param_special_encode {
    t_cose_param_special_encode_cb *encode_cb;
    /** Encoder callbacks can use any one of these types that
     * they see fit. The variety is for the convenience of the
     * encoder callback. */
    union {
        void                 *context;
        int64_t               int64;
        uint64_t              uint64;
        struct q_useful_buf_c string;
        uint8_t               little_buf[8];
        struct t_cose_key     key;
    } data;
};


struct t_cose_param_special_decode {
    /** Decoder callbacks of type t_cose_special_param_encode_cb can
     * use any one of these types that they see fit. The variety is
     * for the convenience of the decoder callback. */
    union {
        void                 *context;
        int64_t               int64;
        uint64_t              uint64;
        struct q_useful_buf_c string;
        uint8_t               little_buf[8];
        struct t_cose_key     key;
    } value;
};


/** Where in a COSE message a header was found. */
struct t_cose_header_location {
    /** 0 means the body, 1 means the first level of signer/recipient, 2,
     * the second level.*/
    uint8_t  nesting;
    /** For signers and recipients, the index within the nesting level
     * starting from 0. */
    uint8_t  index;
};


/**
 * This holds one parameter such as an algorithm ID or kid. When that
 * one parameter is not an integer or string, this holds a callback to
 * output it. It typically takes up 40 bytes.
 *
 * This is used both for to-be-encoded parameters and decoded
 * parameters. It is also used for header parameters and key
 * parameters.
 *
 * Collections of parameters are represented by a linked
 * list of these.
 */
struct t_cose_parameter {
    /** Label indicating which parameter it is. Typically, one of
     * T_COSE_HEADER_PARAM_XXXXX, such as \ref T_COSE_HEADER_PARAM_ALG,
     * but may also be a proprietary label.
     */
    int64_t label;

    /** Indicates parameter is to be encoded in the protected header
     * bucket or was decoded from the protected header bucket. */
    bool    in_protected;
    /** Indicates parameter should be listed in the critical headers
     * when encoding. When encoding the parameter's label was
     * listed in the crit parameter.*/
    bool    critical;
    /** When decoding, the location. Ignored when encoding. */
    struct t_cose_header_location location;

    /** One of \ref T_COSE_PARAMETER_TYPE_INT64, ... This is the
     * selector for the contents of the union \c value. On encoding, the
     * caller fills this in to say what they want encoded.  On
     * decoding it is filled in by the decoder for strings and
     * integers. When it is not a string or integer, the decode call
     * back is called and it is filled in by the decode callback. */
    uint8_t value_type;

    /** The value of the parameter. */
    union {
        int64_t                            int64;
        struct q_useful_buf_c              string;
        struct t_cose_param_special_encode special_encode;
        struct t_cose_param_special_decode special_decode;
    } value;

    /** next parameter in the linked list or NULL at the end of the list. */
    struct t_cose_parameter *next;
};


#define T_COSE_PARAMETER_TYPE_NONE         0
#define T_COSE_PARAMETER_TYPE_INT64        2
#define T_COSE_PARAMETER_TYPE_BYTE_STRING  6
#define T_COSE_PARAMETER_TYPE_TEXT_STRING  7
#define T_COSE_PARAMETER_TYPE_SPECIAL    100
// TODO: add a parameters type to recursively encode because COSE_Keys are
// parameter sets too and they go into headers.


/**
 * The value of an unsigned integer content type indicating no content
 * type.  See \ref t_cose_parameters.
 */
#define T_COSE_EMPTY_UINT_CONTENT_TYPE UINT16_MAX+1


/**
 * This is primarily for backwards compatibility with t_cose v1. Instead
 * use the linked list of parameters returned and functions like
 * t_cose_find_parameter_alg_id().
 *
 * This holds the common header parameters defined in section 3 of RFC
 * 9052. It was the only way that parameters were returned in t_cose
 * 1.x which did not support any parameters but these. For t_cose 2.x
 * parameters are returned as linked lists of struct t_cose_parameter.
 *
 * Approximate size on a 64-bit machine is 80 bytes and on a 32-bit
 * machine is 40.
 */
struct t_cose_parameters {
    /** The algorithm ID. \ref T_COSE_ALGORITHM_NONE if the algorithm
     * ID parameter is not present. String type algorithm IDs are not
     * supported.  See the [IANA COSE
     * Registry](https://www.iana.org/assignments/cose/cose.xhtml) for
     * the algorithms corresponding to the integer values.
     */
    int32_t               cose_algorithm_id;

    /** The COSE key ID. \c NULL_Q_USEFUL_BUF_C if parameter is not
     * present */
    struct q_useful_buf_c kid;

    /** The initialization vector. \c NULL_Q_USEFUL_BUF_C if parameter
     * is not present */
    struct q_useful_buf_c iv;

    /** The partial initialization vector. \c NULL_Q_USEFUL_BUF_C if
     * parameter is not present */
    struct q_useful_buf_c partial_iv;

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    /** The content type as a MIME type like
     * "text/plain". \c NULL_Q_USEFUL_BUF_C if parameter is not present */
    struct q_useful_buf_c content_type_tstr;

    /** The content type as a CoAP Content-Format
     * integer. \ref T_COSE_EMPTY_UINT_CONTENT_TYPE if parameter is not
     * present. Allowed range is 0 to UINT16_MAX per RFC 7252. */
    uint32_t              content_type_uint;
#endif /* T_COSE_DISABLE_CONTENT_TYPE */
};


/** A structure to hold a pool of struct \ref t_cose_parameter.  See
 * \ref T_COSE_PARAM_STORAGE_INIT(). Typically this structure and an
 * array ot t_cose_parameter are allocated in the decode context so
 * the return parameters from a decode have a lifetime of the decode
 * context. They can also be allocated on the stack or elsewhere as
 * long a s the lifetitime is as needed.*/
struct t_cose_parameter_storage {
    /** The number of t_cose_parameter, used and unused. */
    size_t                   size;
    /** The number of used t_cose_parameter */
    size_t                   used;
    /** Array that is the actual pool. */
    struct t_cose_parameter *storage;
};

/** Macro to initialize parameter storage with some storage provided
 * as an array of struct t_cose_parameter that can be used with
 * sizeof().*/
#define T_COSE_PARAM_STORAGE_INIT(p_storage, p_array) \
    p_storage.storage = p_array; \
    p_storage.used = 0; \
    p_storage.size = sizeof(p_array) / sizeof(struct t_cose_parameter)




/**
 * \brief Encode both the protected and unprotected header buckets.
 *
 * \param[in] cbor_encoder           Encoder context for header output.
 * \param[in] parameters             The list of parameters to output.
 * \param[out] protected_parameters  Place to put pointer and length of
 *                                   encoded protected headers. May be NULL.
 *
 * For most COSE message creation (e.g., signing a COSE_Sign1), this is not
 * needed. It use is more for implementors of t_cose_signature_sign.
 *
 * This encodes COSE "Headers" that are used in COSE_Sign, COSE_Sign1,
 * COSE_Signature, COSE_Encrypt, COSE_Encrypt0, COSE_Mac, COSE_Mac0
 * and COSE_Recipient.
 *
 * The input to this is a linked list of struct t_cose_parameter
 * containing both protected and unprotected header parameters. They
 * will be encoded and output to the CBOR encoder context first into
 * the protected header bucket and second the unprotected header
 * bucket.
 *
 * The input set is a linked list through the \c next member
 * of struct t_cose_parameter and ends with a \c NULL pointer.
 *
 * \c t_cose_parameter.protected indicates whether the parameter should
 * go into the protected or unprotected bucket. The order of the
 * parameters in the input doesn't matter.
 *
 * Each parameter has a label, data type and value.  Only integer
 * label types are supported (so far). Most header parameters will be
 * either an integer or string, (T_COSE_PARAMETER_TYPE_INT64,
 * T_COSE_PARAMETER_TYPE_BYTE_STRING or
 * T_COSE_PARAMETER_TYPE_TEXT_STRING).
 *
 * The parameter type may also be T_COSE_PARAMETER_TYPE_SPECIAL in
 * which case the a callback function and context are supplied that
 * will be called when it is time to encode that parameter. This is
 * typically needed for parameter types that are not integers or
 * strings, but can be used for them too.
 *
 * The crit header parameter will be automatically added if there are
 * any protected parameters that are marked as critical. If there are
 * none, then it will not be added. There is no limit to the number of
 * critical parameters to encode.
 *
 * A pointer and length of the protected header byte string is
 * returned so that it can be covered by what ever protection
 * mechanism is in used (e.g., hashing or AEAD encryption).
 */
enum t_cose_err_t
t_cose_headers_encode(QCBOREncodeContext            *cbor_encoder,
                      const struct t_cose_parameter *parameters,
                      struct q_useful_buf_c         *protected_parameters);


/**
 * \brief Decode protected and unprotected header buckets.
 *
 * \param[in] cbor_decoder           QCBOR decoder to decode from.
 * \param[in] location               Location in message of the parameters.
 * \param[in] special_decode_cb      Callback for non-integer and
 *                                   non-string parameters.
 * \param[in] special_decode_ctx     Context for the above callback
 * \param[in] parameter_storage      Storage pool for parameter list nodes.
 * \param[in,out] decoded_params     Pointer to parameter list to append to or
 *                                   to  \c NULL.
 * \param[out] protected_parameters  Pointer and length of encoded protected
 *                                   parameters.
 *
 * For most COSE message decoding (e.g. verification of a COSE_SIgn1),
 * this is not needed. This is mainly used internally or by
 * implemention of a new \c t_cose_signature_verify or \c
 * t_cose_recipient_decrypt object.
 *
 * Use this to decode "Headers" that occurs throughout COSE. The QCBOR
 * decoder should be positioned so the protected header bucket is the
 * next item to be decoded. This then consumes the CBOR for the two
 * header parameter buckets leaving the decoder positioned for what
 * ever comes after.
 *
 * The decoded headers are put into a linked list the
 * nodes for which are allocated out of \c parameter_storage.
 * They are appended to the list in \c *decoded_params. It may
 * be an empty list (e.g., \c NULL) or a linked list to append to.
 *
 * In order to handle parameters that are not integers or strings a
 * callback of type \ref special_decode_cb must be
 * given. There is only one of these callbacks for all the
 * non-integer and non-string header parameters. It typically switches
 * on the parameter label.
 *
 * The crit parameter will be decoded and any parameter label
 * listed in it will be marked as crit in the list returned. It is up
 * to the caller to check the list for crit parameters and error
 * out if they are not processed. See t_cose_params_check().
 *
 * The number of parameters in the crititical parameters parameter is
 * limited to \ref T_COSE_MAX_CRITICAL_PARAMS for each bucket of
 * headers. \ref T_COSE_ERR_TOO_MANY_PARAMETERS is returned if this is
 * exceeded and the decode of all the header ends.  Note that this
 * only the limit for one header bucket, not the aggregation of all
 * the headers buckets. For example it limits the crit list in for one
 * COSE_Signer, not the the total of all COSE_Signers. This is a hard
 * limit that can only be increased by changing the size and re
 * building the t_cose library.
 */
enum t_cose_err_t
t_cose_headers_decode(QCBORDecodeContext                 *cbor_decoder,
                      const struct t_cose_header_location location,
                      t_cose_param_special_decode_cb     *special_decode_cb,
                      void                               *special_decode_ctx,
                      struct t_cose_parameter_storage    *parameter_storage,
                      struct t_cose_parameter           **decoded_params,
                      struct q_useful_buf_c              *protected_parameters);


/**
 * \brief Check parameter list, particularly for unknown critical parameters
 *
 * \param[in] parameters   Linked list of parameters to check.
 *
 * \retval  T_COSE_SUCCESS  Nothing wrong in parameter list.
 * \retval T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER   A parameter was marked
 * critical that is not one of the standard common parameters handled by t_cose
 * (T_COSE_HEADER_PARAM_ALG through T_COSE_HEADER_PARAM_PARTIAL_IV).
 * \retval  T_COSE_ERR_DUPLICATE_PARAMETER  Both IV and partial IV parameters are present
 *
 * This is used by t_cose_sign_verify() and such to check there are no
 * critical parameters except that it allows the standard parameters
 * that are decoded by default to be marked critical..
 */
enum t_cose_err_t
t_cose_params_check(const struct t_cose_parameter *parameters);


/**
 * \brief Append one list of parameters to another.
 *
 * \param[in] existing        A pointer to the head of a parameter linked list
 *                            to which \c to_be_appended is added to the end or a
 *                            pointer to \c NULL.
 * \param[in] to_be_appended  A parameter linked list which it is to added.
 *
 * If \c *existing is not \c NULL, this finds the end of \c *existing
 * and sets the \c next member in the last node to \c to_be_appended.
 * If it is \c NULL, this just assigns \c to_be_appended to \c *existing.
 *
 * \c to_be_appended may be \c NULL.
 */
static void
t_cose_params_append(struct t_cose_parameter **existing,
                     struct t_cose_parameter *to_be_appended);




/**
 * Make a struct t_cose_parameter for algorithm ID
 *
 * \param[in] alg_id    The COSE algorithm ID
 *
 * \return An initialized struct t_cose_parameter.
 *
 * This fills in all the elements in a struct t_cose_parameter for an
 * algorithm ID. In particular, it is always in the protected bucket
 * and not critical (because all COSE implementations MUST
 * understand this parameter).
 *
 * struct t_cose_parameter is usually used as a node in a linked
 * list. This initializes the \c next pointer to \c NULL. If it's not
 * the last item in a linked list it will have to be set. For example:
 *
 *   struct t_cose_parameter params[2];
 *   params[0] = t_cose_make_alg_id_parameter(cose_algorithm_id);
 *   params[1] = t_cose_make_kid_parameter(kid);
 *   params[0].next = &params[1];
 *
 * This is implemented as an inline function so it usually compiles
 * down to some assignments (an inline function works in C and C++
 * where an initializer or a compound literal does not, particularly
 * because there is a union involved and C++ can't initialize unions
 * at all).
 */
static struct t_cose_parameter
t_cose_param_make_alg_id(int32_t alg_id);

/**
 * Make a struct t_cose_parameter for an unsigned integer content typ.
 *
 * \param[in] content_type    Unsigned integer content type.
 *
 * \return An initialized struct t_cose_parameter.
 *
 * See t_cose_param_make_alg_id(). This works the same,
 * except it is an unsigned integer content type.
 */
static struct t_cose_parameter
t_cose_param_make_ct_uint(uint32_t content_type);

/**
 * Make a struct t_cose_parameter for a string content type.
 *
 * \param[in] content_type    String content type.
 *
 * \return An initialized struct t_cose_parameter.
 *
 * See t_cose_param_make_alg_id(). This works the same,
 * except it is a string content type.
 */
static struct t_cose_parameter
t_cose_param_make_ct_tstr(struct q_useful_buf_c content_type);

/**
 * Make a struct t_cose_parameter for a key identifier (kid).
 *
 * \param[in] kid    Key identifier.
 *
 * \return An initialized struct t_cose_parameter.
 *
 * See t_cose_param_make_alg_id(). This works the same,
 * except it is for a key ID (kid).
 */
static struct t_cose_parameter
t_cose_param_make_kid(struct q_useful_buf_c kid);

/**
 * Make a struct t_cose_parameter for an initialization vector.
 *
 * \param[in] iv    Initialization vector.
 *
 * \return An initialized struct t_cose_parameter.
 *
 * See t_cose_param_make_alg_id(). This works the same,
 * except it is for an initialization vector.
 */
static struct t_cose_parameter
t_cose_param_make_iv(struct q_useful_buf_c iv);

/**
 * Make a struct t_cose_parameter for an partial initialization vector.
 *
 * \param[in] iv    Partial initialization vector.
 *
 * \return An initialized struct t_cose_parameter.
 *
 * See t_cose_param_make_alg_id(). This works the same,
 * except it is for a partial initialization vector.
 */
static struct t_cose_parameter
t_cose_param_make_partial_iv(struct q_useful_buf_c iv);




/**
 * \brief  Find a parameter by label in linked list.
 *
 * \param[in] parameter_list   The linked list to search.
 * \param[in] label   The label to search for.
 *
 * \return The found parameter or NULL.
 */
const struct t_cose_parameter *
t_cose_param_find(const struct t_cose_parameter *parameter_list, int64_t label);


struct q_useful_buf_c
t_cose_param_find_bstr(const struct t_cose_parameter *parameter_list, int64_t label);


/**
 * \brief Find the algorithm ID parameter in a linked list
 *
 * \param[in] parameter_list  The parameter list to search.
 * \param[in] prot  If \c true, parameter must be protected and vice versa.
 *
 * \return The algorithm ID or \ref T_COSE_ALGORITHM_NONE.
 *
 * This returns \ref T_COSE_ALGORITHM_NONE on all errors including
 * errors such as the parameter not being present, the parameter being
 * of the wrong type and the parameter not being protected.
 */
int32_t
t_cose_param_find_alg_id(const struct t_cose_parameter *parameter_list, bool prot);


/**
 * \brief Find the text string content type parameter in a linked list
 *
 * \param[in] parameter_list  The parameter list to search.
 *
 * \return The content type or \ref NULL_Q_USEFUL_BUF_C.
 *
 * This returns \ref NULL_Q_USEFUL_BUF_C on all errors including
 * errors such as the parameter not being present, the parameter not
 * being a string. It doesn't matter if the parameter is protected.
 * or not. See also t_cose_param_find_content_type_int().
 */
struct q_useful_buf_c
t_cose_param_find_content_type_tstr(const struct t_cose_parameter *parameter_list);


/**
 * \brief Find the CoAP content type parameter in a linked list.
 *
 * \param[in] parameter_list  The parameter list to search.
 *
 * \return The content type or \ref T_COSE_EMPTY_UINT_CONTENT_TYPE.
 *
 * This returns \ref T_COSE_EMPTY_UINT_CONTENT_TYPE on all errors
 * including errors such as the parameter not being present, the
 * parameter not being an integer. It doesn't matter if the parameter
 * is protected.  or not. See also
 * t_cose_param_find_content_type_tstr().
 */
uint32_t
t_cose_param_find_content_type_uint(const struct t_cose_parameter *parameter_list);


/**
 * \brief Find the key ID (kid) parameter in a linked list.
 *
 * \param[in] parameter_list  The parameter list to search.
 *
 * \return The content type or \ref NULL_Q_USEFUL_BUF_C.
 *
 * This returns \ref NULL_Q_USEFUL_BUF_C on all errors including
 * errors such as the parameter not being present, the parameter not
 * being a byte string. It doesn't matter if the parameter is
 * protected.  or not.
 */
struct q_useful_buf_c
t_cose_param_find_kid(const struct t_cose_parameter *parameter_list);


/**
 * \brief Find the initialization vector parameter in a linked list.
 *
 * \param[in] parameter_list  The parameter list to search.
 *
 * \return The content type or \ref NULL_Q_USEFUL_BUF_C.
 *
 * This returns \ref NULL_Q_USEFUL_BUF_C on all errors including
 * errors such as the parameter not being present, the parameter not
 * being a byte string. It doesn't matter if the parameter is
 * protected.  or not.
 *
 * Note that the IV and partial IV parameters should not both be
 * present. This does not check for that condition, but
 * t_cose_params_check() does and is called by functions like
 * t_cose_sign_verify().
 */
struct q_useful_buf_c
t_cose_param_find_iv(const struct t_cose_parameter *parameter_list);


/**
 * \brief Find the initialization vector parameter in a linked list.
 *
 * \param[in] parameter_list  The parameter list to search.
 *
 * \return The content type or \ref NULL_Q_USEFUL_BUF_C.
 *
 * This returns \ref NULL_Q_USEFUL_BUF_C on all errors including
 * errors such as the parameter not being present, the parameter not being
 * a byte string. It doesn't matter if the parameter is protected.
 * or not.
 *
 * Note that the IV and partial IV parameters should not both be
 * present. This does not check for that condition, but
 * t_cose_params_check() does and is called by functions like
 * t_cose_sign_verify().
 */
struct q_useful_buf_c
t_cose_param_find_partial_iv(const struct t_cose_parameter *parameter_list);


/**
 * \brief Fill in structure with common header parameters.
 *
 * \param[in] decoded_params    Linked list of decoded parameters.
 * \param[out] returned_params  A filled in structure with the common
 *                              header parameters.
 *
 * \c decoded_params is traversed and any of the common headers
 * parameters found in it are filled into \c returned_parameters.
 * Unknown header parameters are ignored, even critical ones.
 *
 * This is called by t_cose_sign1_verify() internally to convert the
 * linked list parameters format in t_cose 2.x to t_cose_parameters
 * used in t_cose 1.x.
 *
 * Note that the parameters processed by this are the set defined in
 * section 3.1 of RFC 9052 and are sole parameters used in RFC 9052
 * and 9053.
 *
 * This will return \ref T_COSE_ERR_DUPLICATE_PARAMETER if both iv and
 * partial_iv parameters are present.
 */
enum t_cose_err_t
t_cose_params_common(const struct t_cose_parameter *decoded_params,
                     struct t_cose_parameters      *returned_params);




/* ------------------------------------------------------------------------
 * Inline implementations of public functions defined above.
 */


static inline struct t_cose_parameter
t_cose_param_make_alg_id(int32_t alg_id)
{
    /* The weird world of initializers, compound literals for
     * C and C++...
     *
     * There are three contexts where it would be nice to assign /
     * initialize with a filled-in t_cose_parameter.
     *
     * 1) Assignments -- an expression is required
     * 2) Initialization of a variable upon its declaration.
     * 3) Initialization of a static const data structure -- initialized
     *        data in data sections of executable object code
     *
     * The inline functions here provide 1) and 2) for C and C++, but not 3).
     *
     * The macros like this
     * #define T_COSE_MAKE_ALG_ID_PARAM(alg_id) \
     *    {T_COSE_HEADER_PARAM_ALG, \
     *     true,\
     *     false,\
     *     {0,0},\
     *     T_COSE_PARAMETER_TYPE_INT64,\
     *     .value.int64 = alg_id }
     * is an initializer. Both C and C++ have initializers,
     * but in C++ they can't use designated initializers,
     * the part where .value.int64 = alg_id.
     *
     * The following is a compound literal.
     * #define T_COSE_MAKE_ALG_ID_PARAM(alg_id) \
     *   (struct t_cose_parameter){T_COSE_HEADER_PARAM_ALG, \
     *     true,\
     *     false,\
     *     {0,0},\
     *     T_COSE_PARAMETER_TYPE_INT64,\
     *     .value.int64 = alg_id }
     *
     * It looks like a cast but it is not. You can take the address of
     * it and it is an lvalue. These exist only in C, not in C++,
     * though c++ compilers do support them, but warnings will ensue
     * if -Wpendatic is used so this code doesn't use them with c++
     *
     * https://stackoverflow.com/questions/28116467/are-compound-literals-standard-c
     *
     * See also the definition of NULLUsefulBufC in UsefulBuf.h in QCBOR.
     *
     * In the end, I expect the optimizer produces good code for all
     * of these constructs. For example the code produces whether this
     * is created by a function, an initializer or a compound literal
     * is hopefully the same.
     */

    struct t_cose_parameter parameter;

    parameter.critical         = false;
    parameter.in_protected     = true;
    parameter.location.index   = 0;
    parameter.location.nesting = 0;
    parameter.label            = T_COSE_HEADER_PARAM_ALG;
    parameter.value_type       = T_COSE_PARAMETER_TYPE_INT64;
    parameter.value.int64      = alg_id;
    parameter.next             = NULL;

    return parameter;
}

static inline struct t_cose_parameter
t_cose_param_make_unprot_bstr(struct q_useful_buf_c string, int32_t label)
{
    struct t_cose_parameter parameter;

    parameter.critical         = false;
    parameter.in_protected     = false;
    parameter.location.index   = 0;
    parameter.location.nesting = 0;
    parameter.label            = label;
    parameter.value_type       = T_COSE_PARAMETER_TYPE_BYTE_STRING;
    parameter.value.string     = string;
    parameter.next             = NULL;

    return parameter;
}

static inline struct t_cose_parameter
t_cose_param_make_ct_uint(uint32_t content_type)
{
    struct t_cose_parameter parameter;

    parameter.critical         = false;
    parameter.in_protected     = false;
    parameter.location.index   = 0;
    parameter.location.nesting = 0;
    parameter.label            = T_COSE_HEADER_PARAM_CONTENT_TYPE;
    parameter.value_type       = T_COSE_PARAMETER_TYPE_INT64;
    parameter.value.int64      = (int32_t)content_type;
    parameter.next             = NULL;

    return parameter;
}

static inline struct t_cose_parameter
t_cose_param_make_ct_tstr(struct q_useful_buf_c content_type)
{
    struct t_cose_parameter parameter;

    parameter.critical         = false;
    parameter.in_protected     = false;
    parameter.location.index   = 0;
    parameter.location.nesting = 0;
    parameter.label            = T_COSE_HEADER_PARAM_CONTENT_TYPE;
    parameter.value_type       = T_COSE_PARAMETER_TYPE_TEXT_STRING;
    parameter.value.string     = content_type;
    parameter.next             = NULL;

    return parameter;
}

static inline struct t_cose_parameter
t_cose_param_make_kid(struct q_useful_buf_c kid)
{
    struct t_cose_parameter parameter;

    parameter.critical         = false;
    parameter.in_protected     = false;
    parameter.location.index   = 0;
    parameter.location.nesting = 0;
    parameter.label            = T_COSE_HEADER_PARAM_KID;
    parameter.value_type       = T_COSE_PARAMETER_TYPE_BYTE_STRING;
    parameter.value.string     = kid;
    parameter.next             = NULL;

    return parameter;
}

static inline struct t_cose_parameter
t_cose_param_make_iv(struct q_useful_buf_c iv)
{
    struct t_cose_parameter parameter;

    parameter.critical         = false;
    parameter.in_protected     = false;
    parameter.location.index   = 0;
    parameter.location.nesting = 0;
    parameter.label            = T_COSE_HEADER_PARAM_IV;
    parameter.value_type       = T_COSE_PARAMETER_TYPE_BYTE_STRING;
    parameter.value.string     = iv;
    parameter.next             = NULL;

    return parameter;
}

static inline struct t_cose_parameter
t_cose_param_make_partial_iv(struct q_useful_buf_c iv)
{
    struct t_cose_parameter parameter;

    parameter.critical         = false;
    parameter.in_protected     = false;
    parameter.location.index   = 0;
    parameter.location.nesting = 0;
    parameter.label            = T_COSE_HEADER_PARAM_PARTIAL_IV;
    parameter.value_type       = T_COSE_PARAMETER_TYPE_BYTE_STRING;
    parameter.value.string     = iv;
    parameter.next             = NULL;

    return parameter;
}



static inline void
t_cose_params_append(struct t_cose_parameter **existing,
                             struct t_cose_parameter *to_be_appended)
{
    /* Improvement: will overall code size be smaller if this is not inline? */
    struct t_cose_parameter *ex;

    if(*existing == NULL) {
        *existing = to_be_appended;
    } else {
        ex = *existing;
        while(ex->next != NULL) {
            ex = ex->next;
        }

        ex->next = to_be_appended;
    }
}


#ifdef __cplusplus
}
#endif

#endif /* t_cose_parameters_h */
