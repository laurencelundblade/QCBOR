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

#include "t_cose_sign1_verify.h"
#include "q_useful_buf.h"
#include "t_cose_common.h"
#include <stdint.h>
#include "qcbor.h"


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
struct t_cose_label_list {
    /* Terminated by value LABEL_LIST_TERMINATOR */
    int64_t int_labels[T_COSE_HEADER_LIST_MAX+1];
    /*  Terminated by a NULL_Q_USEFUL_BUF_C */
    struct q_useful_buf_c tstr_labels[T_COSE_HEADER_LIST_MAX+1];
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
 * \brief Clear a header list to empty.
 *
 * \param[in,out] list The list to clear.
 */
static void
clear_header_list(struct t_cose_label_list *list);


/**
 * \brief Check the unknown headers against the critical header list.
 *
 * \param[in] critical_labels The list of critical headers.
 * \param[in] unknown_labels  The unknown headers that occurred.
 *
 * \retval T_COSE_SUCCESS                  None of the unknown headers are
 *                                         critical.
 * \retval T_COSE_UNKNOWN_CRITICAL_HEADER  At least one of the unknown headers is
 *                                         critical.
 *
 * Both lists are of header labels (CBOR keys). Check to see none of
 * the header labels in the unknown list occur in the critical list.
 */
enum t_cose_err_t
check_critical_header_labels(const struct t_cose_label_list *critical_labels,
                             const struct t_cose_label_list *unknown_labels);



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
enum t_cose_err_t
parse_unprotected_headers(QCBORDecodeContext       *decode_context,
                          struct t_cose_headers    *returned_headers,
                          struct t_cose_label_list *unknown);


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
                        struct t_cose_headers      *returned_headers,
                        struct t_cose_label_list   *critical,
                        struct t_cose_label_list   *unknown);


/**
 * \brief Copy and combine protected and unprotected headers.
 *
 * \param[in] protected          The protected headers to copy.
 * \param[in] unprotected        The unprotected headers to copy.
 * \param[out] returned_headers  Destination for copy.
 *
 * \retval T_COSE_ERR_DUPLICATE_HEADER  If the same header occurs in both
 *                                      protected and unprotected.
 * \retval T_COSE_SUCCESS               If there were no duplicates and the
 *                                      copy and combine succeeded.
 *
 * This merges the protected and unprotected headers. The COSE standard
 * does not allow a header to duplicated in protected and unprotected so
 * this checks and returns an error if so.
 */
enum t_cose_err_t
check_and_copy_headers(const struct t_cose_headers  *protected,
                       const struct t_cose_headers  *unprotected,
                       struct t_cose_headers        *returned_headers);



/* ------------------------------------------------------------------------
 * Inline implementations of public functions defined above.
 */
static void inline clear_header_list(struct t_cose_label_list *list)
{
    memset(list, 0, sizeof(struct t_cose_label_list));
}


static bool inline
is_header_list_clear(const struct t_cose_label_list *list)
{
    return list->int_labels[0] == 0 &&
                q_useful_buf_c_is_null_or_empty(list->tstr_labels[0]);
}

#endif /* t_cose_headers_h */
