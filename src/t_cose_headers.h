/*
 * t_cose_headers.h
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_headers_h
#define t_cose_headers_h

#include "q_useful_buf.h"
#include "t_cose_common.h"
#include <stdint.h>
#include "qcbor.h"


// TODO: can critical headers be mixed across protected and unprotected?

/**
 The result of parsing a set of COSE headers.

 Size on 64-bit machine: 4 + (4 * 16) + 4pad = 72
 Size on 32-bit machine: 4 + (4 * 8) = 36
 */
struct t_cose_headers {
    /** The algorithm ID. COSE_ALGORITHM_RESERVED if the algorithm ID
     * header is not present. String type algorithm IDs are not
     * supported */
    int32_t               cose_alg_id;
    /** The COSE key ID. NULL_Q_USEFUL_BUF_C if header is not
	present */
    struct q_useful_buf_c kid;
    /** The COSE initialization vector. NULL_Q_USEFUL_BUF_C if header
	is not present */
    struct q_useful_buf_c iv;
    /** The COSE partial initialization vector. NULL_Q_USEFUL_BUF_C if
	header is not present */
    struct q_useful_buf_c partial_iv;
    /** The content type as a MIME type like
	"text/plain". NULL_Q_USEFUL_BUF_C if header is not present */
    struct q_useful_buf_c content_type_tstr;
    /** The content type as a CoAP Content-Format
	integer. T_COSE_EMPTY_UINT_CONTENT_TYPE if header is not
	present. Allowed range is 0 to UINT16_MAX per RFC 7252. */
    uint32_t              content_type_uint;
};


/**
 This value indicates no integer content type was specified. It is
 outside the allowed range of 0 to UINT16_MAX.
 */
#define T_COSE_EMPTY_UINT_CONTENT_TYPE UINT16_MAX+1


/**
 * \brief Parse some COSE headers.
 *
 * \param[in] decode_context     The QCBOR decode context to read from.
 * \param[out] returned_headers  The parsed headers being returned.
 *
 *
 * \retval T_COSE_SUCCESS              The headers were parsed correctly.
 * \retval T_COSE_ERR_HEADER_CBOR      CBOR is parsable, but not the right
 *                                     structure (e.g. array instead of a map)
 * \retval T_COSE_ERR_TOO_MANY_HEADERS More than \ref T_COSE_HEADER_LIST_MAX
 *                                     headers.
 * \retval T_COSE_ERR_CBOR_NOT_WELL_FORMED    The CBOR is not parsable.
 * \retval T_COSE_ERR_NON_INTEGER_ALG_ID      The algorithm ID is not an
 *                                            integer. This implementation
 *                                            doesn't support string algorithm
 *                                            IDs.
 * \retval T_COSE_ERR_BAD_CONTENT_TYPE        Error in content type header.
 * \retval T_COSE_ERR_UNKNOWN_CRITICAL_HEADER A header marked critical is
 *                                            present and not understood.
 *
 * No headers are mandatory. Which headers were present or not is
 * indicated in \c returned_headers.  It is OK for there to be no
 * headers at all.
 *
 * The first item to be read from the decode_context must be the map
 * data item that contains the headers.
 */
enum t_cose_err_t
parse_cose_headers(QCBORDecodeContext *decode_context,
                   struct t_cose_headers *returned_headers);


/**
 * \brief Parse the unprotected COSE headers.
 *
 * \param[in] decode_context     CBOR decode context to read the header from.
 * \param[out] returned_headers  The parsed headers.
 *
 * \returns The same as parse_cose_headers().
 *
 * No headers are mandatory. Which headers were present or not is
 * indicated in \c returned_headers.  It is OK for there to be no
 * headers at all.
 *
 * The first item to be read from the decode_context must be the map
 * data item that contains the headers.
 */
static enum t_cose_err_t
parse_unprotected_headers(QCBORDecodeContext *decode_context,
                          struct t_cose_headers *returned_headers);



/**
 * \brief Parse the protected headers.
 *
 * \param[in] protected_headers Pointer and length of CBOR-encoded
 *                              protected headers to parse.
 * \param[out] returned_headers The parsed headers that are returned.
 *
 * \retval T_COSE_SUCCESS                  Protected headers parsed.
 * \retval T_COSE_ERR_CBOR_NOT_WELL_FORMED The CBOR formatting of the protected
 *                                         headers is unparsable.
 *
 * This parses the contents of the protected headers after the bstr
 * wrapping is removed.
 *
 * This will error out if the CBOR is not well-formed, the protected
 * headers are not a map, the algorithm ID is not found, or the
 * algorithm ID is larger than \c INT32_MAX or smaller than \c
 * INT32_MIN.
 */
enum t_cose_err_t
parse_protected_headers(const struct q_useful_buf_c protected_headers,
                        struct t_cose_headers *returned_headers);




/*
 * Static inline implementation. See documentation above.
 */
static inline enum t_cose_err_t
parse_unprotected_headers(QCBORDecodeContext *decode_context,
                          struct t_cose_headers *returned_headers)
{
    return parse_cose_headers(decode_context, returned_headers);
}

#endif /* t_cose_headers_h */
