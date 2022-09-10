/*
 * t_cose_parameters.h
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2022 Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_parameters_h
#define t_cose_parameters_h

#include <stdint.h>
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_sign1_verify.h" // TODO: remove this
#include "qcbor/qcbor.h"



/*
 * Header parameter encoding and decoding hinges around struct
 * t_cose_header_param plus primary functions for encoding and decoding
 * the header. Users of the t_cose public API for verifying signing,
 * encrypting, decrypting and MACing will mainly use struct
 * t_cose_header_param.
 *
 * Struct t_cose_header_param holds a single header parameter that is
 * to be encoded or has been decoded. The same structure is used for
 * both. Most parameters are either integers, strings or Booleans and
 * are held directly in struct t_cose_header_param. A callback is used
 * for more complex parameters.
 *
 * The struct t_cose_header_param also holds:
 *   * Whether the parameter is protected or not
 *   * Whether the parameter is critical
 *   * The label for the parameter
 *   * The data type of the parameter
 *   * The location of the parameter in the COSE message
 *
 * Only integer parameter labels are supported.
 *
 * When encoding a COSE message and only the kid and algorithm id are
 * needed, there is no need to use the header parameter structure as
 * those are handled internally. If further parameters are needed when
 * encoding further the caller creates an array of struct
 * t_cose_header_param passes it in with xxxx_add_parameters(). This
 * array is terminated by a header parameter structure with type
 * T_COSE_PARAMETER_TYPE_NONE. This array can contain only one, or a large number of
 * parameters, can contain protected or unprotected headers, critical
 * or not-critical headers and headers of any data type.
 *
 * If the data type to encode is complex, for example the parameter
 * itself is a map, then an encoding callback must be implemented that
 * will output the parameter to a QCBOR encode context.  The pointer to
 * this function goes in the struct t_cose_header_param. It will be
 * called back during the encoding of the COSE message.
 *
 * If any header parameters for encoding are marked critical, the crit
 * header parameter will be automatically added to the COSE message.
 *
 * When decoding a COSE message (verification or decryption) the full
 * set of header parameters decoded are returned as a pointer to an
 * array of struct t_cose_header_param terminated by one with the type
 * T_COSE_PARAMETER_TYPE_NONE. In many cases the caller will not need to examine what is
 * returned.
 *
 * If the caller wishes to examine them, they can iterate over the
 * array searching by label to find the parameter of interest. The data
 * type, protected-ness and criticality of the parameters is not
 * checked. It is up to the caller examining these to check.
 *
 * Some functions for examining headers in the array are provided. See
 * t_cose_find_parameter(), t_cose_find_parameter_kid(), etc… These do
 * fully check the protected-ness, criticality and type of the
 * parameter.
 *
 * When the data type of the header parameter is not an integer,
 * string or boolean, then a read callback must be supplied. This will
 * be called during the decoding of the COSE message with a QCBOR
 * decode context. The callback must alway correctly consume the whole
 * encoded CBOR. The callback can store what it decodes in a
 * context. The callback must do checking for criticality and
 * protractedness of the parameter and error out if they are not
 * correct.
 *
 * If fewer than 10 (TBD) header parameters are in the COSE message,
 * then storage for the returned header parameter structures is
 * provided from the verifier/decryptor context. If more are
 * encountered, the message decode will error out.
 *
 * If it is expected that more than 10 parameters may occur, the
 * caller should provide a larger storage array for header parameters
 * by calling t_cose_xxxx_add_parameter_storage().
 *
 * Some COSE messages, COSE_Sign1, COSE_Mac0 and COSE_Encrypt0 have
 * just one set of headers those for the main body. The other messages,
 * COSE_Sign, COSE_Encrypt and COSE_Mac have body headers and
 * additionally headers per recipient or signer. These scenarios are
 * also handled here.
 *
 * When encoding, the multiple header sets are handled in the
 * interface for signing, encrypting and such. There are separate
 * functions for passing in the body header and the header per signer
 * and per recipient.
 *
 * When decoding all the headers for the entire message are returned
 * in one. The caller can know which parameters are for the body and an
 * index number for the recipient or signer. Even the nesting of
 * recipients within recipients is indicated.
 *
 * Note that decoding messages with many signers or recipients is when
 * you will probably have to add storage for header parameters. Even
 * though the algorithm ID is handled internally, there is still
 * storage needed for it for every signer or recipient.
 *
 * As mentioned in the beginning there is one main function for
 * encoding headers, t_cose_encode_headers() and a complimentary one
 * for decoding headers, t_cose_decode_headers(). These are mostly used
 * internally to implement the main public APIs for signing, encrypting
 * and MACing, but they are also available publicly for add-on
 * implementations of different types of signers and recipients.
 *
 * The primary input to t_cose_encode_headers() is a list of struct
 * t_cose_header_param to encode and the QCBOR encoder context to
 * output them too. Similarly the primary input to
 * t_cose_decode_headers() is a QCBOR decoder context to decode from
 * the output is an array of struct t_cose_header_param. Both of these
 * functions handle both the protected and unprotected headers all in
 * one call (since they always occur together in COSE).
 */



/* Forward declaration. See actual definition below. */
struct t_cose_header_param;



/*
 * Callback to output the encoded CBOR of a header parameter
 *
 * This callback pointer is placed in struct t_cose_header_param. It is called
 * back when t_cose_encode_headers() gets to encoding
 * the particular parameter. It is typically used for
 * encoding parameters that are not integers, strings
 * or a boolean, but can be used for them too. For most
 * use cases, this is not needed.
 *
 * When called it should output the QCBOR for the headers
 * parameter to the encoder context.
 *
 * If it returns an error encoding of the COSE message
 * will stop and error out with the error it returned.
 */
typedef enum t_cose_err_t
(t_cose_header_writer)(const struct t_cose_header_param  *param,
                       QCBOREncodeContext                *qcbor_encoder);



/* Where in a COSE message a header was found. */
struct header_location {
    /* 0 means the body, 1 means the first level of signer/recipient, 2,
     * the second level.*/
    uint8_t  nesting;
    /* For signers and recipienets, the index within the nesting level
     * starting from 0. */
    uint8_t  index;
};


/*
 * This holds one header parameter such as an algorithm ID
 * or kid. When that one header parameter is not an
 * integer, string or boolean, this holds a callback to
 * output it. It typically takes up 32 bytes.
 */
struct t_cose_header_param {
    /* Label indicating which parameter it is. One of COSE_HEADER_PARAM_ALG,
     * ...
     */
    int64_t label;
    /* One of T_COSE_PARAMETER_TYPE_INT64, ... This is the selector
     * for the contents of the value union. */
    uint8_t parameter_type;

    /* Indicates parameter is to be encoded in the protected header
     * bucket was decoded from the protected header bucket. */
    bool    prot;
    /* Indicates parameter should be listed in the critical headers
     * when encoding. Not used while decoding.*/
    bool    critical;
    /* When decoding the location. Ignored when encoding. */
    struct header_location location;
    /* The value of the parameter. */
    union {
        int64_t    i64;
        uint64_t   u64;
        UsefulBufC string;
        bool       b;
        struct {
            void                 *context;
            t_cose_header_writer *call_back;
        } writer;
    } value;
};


#define T_COSE_PARAMETER_TYPE_NONE         0

#define T_COSE_PARAMETER_TYPE_INT64        2
#define T_COSE_PARAMETER_TYPE_UINT64       3
#define T_COSE_PARAMETER_TYPE_BYTE_STRING  6
#define T_COSE_PARAMETER_TYPE_TEXT_STRING  7
#define T_COSE_PARAMETER_TYPE_BOOL        21

#define T_COSE_PARAMETER_TYPE_CALLBACK   100



/* These are struct t_cose_header_parameter inializers for the standard
 * header parameters. They set the type and typical protection level.
 *
 * Example use:
 *    struct t_cose_header_param params[2];
 *    params[0] = T_COSE_MAKE_ALG_ID_PARAM(T_COSE_ALGORITHM_ES256);
 *    params[1] = T_COSE_END_PARAM;
 */
#define T_COSE_MAKE_ALG_ID_PARAM(x) \
    (struct t_cose_header_param){COSE_HEADER_PARAM_ALG, \
                                 T_COSE_PARAMETER_TYPE_INT64,\
                                 true,\
                                 false,\
                                 {0,0},\
                                 .value.i64 = x }

#define T_COSE_CT_INT_PARAM(x) \
    (struct t_cose_header_param){T_COSE_PARAMETER_TYPE_INT64, \
                                 false, \
                                 false, \
                                 COSE_HEADER_PARAM_CONTENT_TYPE, \
                                 .value.i64 = x }

#define T_COSE_CT_TSTR_PARAM(x) \
    (struct t_cose_header_param){T_COSE_PARAMETER_TYPE_TEXT_STRING, \
                                 false, \
                                 false, \
                                 COSE_HEADER_PARAM_CONTENT_TYPE, \
                                 .value.string = x }

#define T_COSE_KID_PARAM(kid) \
    (struct t_cose_header_param){COSE_HEADER_PARAM_KID, \
                                 T_COSE_PARAMETER_TYPE_BYTE_STRING, \
                                 false, \
                                 false, \
                                 {0,0},\
                                 .value.string = kid }

#define T_COSE_END_PARAM  \
    (struct t_cose_header_param){0,\
                                 T_COSE_PARAMETER_TYPE_NONE, \
                                 false, \
                                 false, \
                                 {0,0},\
                                .value.string = NULL_Q_USEFUL_BUF_C }


/* Find a parameter by label in array of parameters returned by verify */
const struct t_cose_header_param *
t_cose_find_parameter(const struct t_cose_header_param *p, int64_t label);

int32_t
t_cose_find_parameter_alg_id(const struct t_cose_header_param *p);

UsefulBufC
t_cose_find_parameter_kid(const struct t_cose_header_param *p);

uint32_t
t_cose_find_content_id_int(const struct t_cose_header_param *p);

// TODO: add more of these


/*
 *
 * This is called back from t_cose_decode_headers() when
 * a parameter that is not an integer, string or boolean is
 * encountered. The call back must consume all the CBOR
 * that makes up the particular parameter and no more.
 *
 * If this is encountered when decoding a protected header
 * then prot is true.
 *
 * If this header is in the list of critical headers, then
 * crit is true. If a crit parameter can't be decoded because
 * it is unknown, this function must return an error to error
 * out the whole COSE decode.
 *
 *
 */
typedef enum t_cose_err_t
(t_cose_header_reader)(void                   *call_back_context,
                       QCBORDecodeContext     *qcbor_decoder,
                       struct header_location  location,
                       bool                    is_protected,
                       bool                    is_crit);


/* A structure to hold an array of struct t_cose_header_param
 * of a given length, typically an empty structure that is
 * not yet terminated by T_COSE_PARAMETER_TYPE_NONE. */
struct header_param_storage {
    size_t                      storage_size;
    struct t_cose_header_param *storage;
};


/*
 * \brief Decode both protected and unprotected Headers.
 *
 * Use this to decode "Headers" that occurs
 * through out COSE. The QCBOR decoder should be positioned
 * so the protected header bucket is the next item to
 * be decoded. This then consumes the CBOR for the two headers
 * leaving the decoder position for what ever comes after.
 *
 * The decoded headers are placed in an array of
 * struct t_cose_header_param which is in the
 * function parameter named params. Params
 * is functions as [in,out]. The decoded
 * COSE header params are in params.storage
 * terminated by TYPE_NONE.
 *
 * The number of parameters list in the crit
 * parameter is limited to XX for each bucket
 * of headers. T_COSE_ERR_TOO_MANY_PARAMETERS is returned
 * if this is exceeded and the decode of all the
 * header ends.  Note that this only the limit
 * for one header bucket, not the aggregation of
 * all the headers buckets. For example it limits
 * the crit list in for one COSE_Signer, not the
 * the total of all COSE_Signers. This is a hard
 * limt that can only be increased by changing
 * the size and re building the t_cose library.
 *
 */
enum t_cose_err_t
t_cose_headers_decode(QCBORDecodeContext         *decode_context,
                      struct header_location      location,
                      t_cose_header_reader       *cb,
                      void                       *cb_context,
                      const struct header_param_storage params,
                      struct q_useful_buf_c      *protected_parameters);





/*
 * \brief Encode both the protected and unprotected Headers
 *
 * The input to this is a set of struct t_cose_header_param containing both
 * protected and unprotected header parameters. They will
 * be encoded and output to the encoder context into
 * first the protected header bucket and then the unprotected
 * header bucket.
 *
 * The input set is in the form of an array of pointers to arrays of
 * xxxxx (i.e. a scatter/gather list). The array of pointers is
 * terminated by a NULL pointer. The arrays of xxxx are terminated
 * by a xxxx of type xxxx_NONE.
 *
 * Xxxxx.prot indicated whether the parameter should go into
 * the protected or unprotected bucket. The order of the parameters
 * in the input doesn't matter as to whether the protected
 * parameters go first or not.
 *
 * Each parameter has a label, data type and value.
 * Only integer label types are supported. Most
 * header parameters will be either an integer, string or Boolean.
 * Types are provided for these.
 *
 * The parameter type may also be yyyy in which case the
 * a callback function and context are supplied that will be
 * called when it is time to encode that parameter. This is
 * typically needed for parameter types tha are not integers,
 * strings or booleans, but can be used for them too.
 *
 * The crit header parameter will be automatically added
 * if there are any protected parameters that are marked
 * as critical. If there are none, then it will not be
 * added.
 *
 * A pointer and length of the protected header byte string
 * is returned so that it can be covered by what ever protection
 * mechanism is in used (e.g., hashing or AEAD encryption).
 */
enum t_cose_err_t
t_cose_encode_headers(QCBOREncodeContext                *encode_context,
                      const struct t_cose_header_param * const *parameters,
                      struct q_useful_buf_c             *protected_parameters);



/* Convenience callback to ignore headers that are not understood.
 *
 * This does NOT ignore critical parameters. (But you
 * can write your own version of this function that does
 * ignore critical parameters if you want). */
enum t_cose_err_t
t_cose_ignore_param_cb(void                  *callback_context,
                       QCBORDecodeContext    *decode_context,
                       struct header_location location,
                       bool                   is_protected,
                       bool                   is_crit);









/* TODO: remove these design notes
A callback supply by the caller that is called for 1) body and signer headers
 and 2) protected and unprotected headers.

It is called repeatedely for each until the call back says done.

 It is given a decode context to output the headers to

 It is given a headers gen context that is caller defined


 More simply the caller may fill in a simple_header struct and
 call register header.

 Have to distinguish which header goes with which signer.
 TODO: how should this work?

On verifying...

 Can register a call back that is called on every header. Two
 types of call backs
  - One for those that need decoding
  - One for those can be presented as a simple_header


 A header set object?
 - protected and non protected
 - a list of headers
 - some are data structures with pointers
 - some have to be done with call back for reading and writing





 When writing parameters,
 - Fill in HP structure, protected or not
 - - Can be specific like algID
 - - Can be general (label and value)
 - - Can be a function that writes them out

 - Add them to the recipient, signer or body instance

 Memory for HP's is allocated by the caller


 When reading parameters, it is more complicated...
 - 4 are supplied by default
 - The caller supplies an array of HP structures
 - They are filled in
 - There is an error if enough are not supplied

 Call back while verifying and/or while decoding-only. Will
 have to seek to value or caller has to get the
 label in the call back.

5 parameters supported by default -- adds about 150 bytes
 to memory requirements.

 Allow supplying of a bigger buffer if needed.

 Which is it
  - linked list
  - array is cleanest
  - accessor function


 What about decoding complicated headers?

 - Could return a bstr with the header value, but that would require
 a change to QCBOR. The caller has to run a new QCBORDecoder on it,
 but otherwise it is very clean. It can go into the header
 structure we have. No call backs needed!

 - Could have a callback with the decoder context positioned to read the
 header. They would get the label and value. They have to
 consume the whole header correctly to not mess up the decode.

 return a decoder context and expect the caller to
 decode. It would be hard to stop the decoder at the value.
 They'd get the label and the value. Could be fixed with a change
 to QCBOR.

 -


 */

/*
 Call back to decode a header parameter.

 Internal loop
   - First call internal processor
   - - It will process algorithm ID
   - - It will bundle others into the generic header parameter
   - In some cases this call back will be run
     - when the stuff is too complicate
     - when the caller requests it



 Just loop over items in the header maps calling this.



 Context 0 is the body.



 */



/**
 * \file t_cose_parameters.h
 *
 * \brief A list of COSE parameter labels, both integer and string.
 *
 * It is fixed size to avoid the complexity of memory management and
 * because the number of parameters is assumed to be small.
 *
 * On a 64-bit machine it is 24 * PARAMETER_LIST_MAX which is 244
 * bytes. That accommodates 10 string parameters and 10 integer parameters
 * and is small enough to go on the stack.
 *
 * On a 32-bit machine: 16 * PARAMETER_LIST_MAX = 176
 *
 * This is a big consumer of stack in this implementation.  Some
 * cleverness with a union could save almost 200 bytes of stack, as
 * this is on the stack twice.
 */
struct t_cose_label_list {
    /* Terminated by value LABEL_LIST_TERMINATOR */
    int64_t int_labels[T_COSE_PARAMETER_LIST_MAX+1];
    /*  Terminated by a NULL_Q_USEFUL_BUF_C */
    struct q_useful_buf_c tstr_labels[T_COSE_PARAMETER_LIST_MAX+1];
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
inline static void clear_label_list(struct t_cose_label_list *list)
{
    memset(list, 0, sizeof(struct t_cose_label_list));
}




enum t_cose_err_t
check_critical_labels(const struct t_cose_label_list *critical_labels,
                      const struct t_cose_label_list *unknown_labels);



enum t_cose_err_t
parse_cose_header_parameters(QCBORDecodeContext        *decode_context,
                             struct t_cose_parameters  *returned_parameters,
                             struct t_cose_label_list  *critical_labels,
                             struct t_cose_label_list  *unknown_labels);


/**
 * \brief Clear a struct t_cose_parameters to empty
 *
 * \param[in,out] parameters   Parameter list to clear.
 */
static inline void clear_cose_parameters(struct t_cose_parameters *parameters)
{
#if COSE_ALGORITHM_RESERVED != 0
#error Invalid algorithm designator not 0. Parameter list initialization fails.
#endif

#if T_COSE_UNSET_ALGORITHM_ID != COSE_ALGORITHM_RESERVED
#error Constant for unset algorithm ID not aligned with COSE_ALGORITHM_RESERVED
#endif

    /* This clears all the useful_bufs to NULL_Q_USEFUL_BUF_C
     * and the cose_algorithm_id to COSE_ALGORITHM_RESERVED
     */
    memset(parameters, 0, sizeof(struct t_cose_parameters));

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    /* The only non-zero clear-state value. (0 is plain text in CoAP
     * content format) */
    parameters->content_type_uint =  T_COSE_EMPTY_UINT_CONTENT_TYPE;
#endif
}


#endif /* t_cose_parameters_h */
