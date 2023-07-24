/*
 *  t_cose_util.h
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2020-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef __T_COSE_UTIL_H__
#define __T_COSE_UTIL_H__

#include <stdint.h>
#include "qcbor/qcbor_common.h" /* For QCBORError */
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file t_cose_util.h
 *
 * \brief Utility functions used internally by the t_cose implementation.
 *
 */




/*
 * \brief Process CBOR tag numbers and figure out message type.
 *
 * \param[in] relevant_cose_tag_nums  List of tag numbers relevant for
 *                                    message type being processed, ending
 *                                    with \ref CBOR_TAG_INVALID64
 * \param[in] option_flags            Flags passed to xxxx_init() that
 *                                    say how to process tag nums, plus
 *                                    optional default message type.
 * \param[in] item                    The QCBORItem of the array that
 *                                    opens the message so the tag
 *                                    numbers on it can be processed.
 * \param[in] cbor_decoder            Needed to process the tag numbers
 *                                    on item.
 * \param[out] unprocessed_tag_nums   Any additional tag numbers that were
 *                                    not used to determine the message
 *                                    type.
 * \param[out] cost_tag_num           The end result message type.
 *
 * Either this will error out or \c cose_tag_num will identify the
 * message type and be one of those listed in \c relevant_cose_tag_nums.
 * This also puts any additional tag numbers that are not the
 * one returned in \c cose_tag_num in \c unprocessed_tag_nums. This
 * genric processor can be used for all the CBOR message types with
 * tag numbers (e.g., COSE_Sign1, COSE_Encrypt,...)
 *
 * \c option_flags are a critical input. It may contain the
 * tag number of the expected type and option flags that say
 * how the tag numbers are to be interpreted and error conditions.
 */
enum t_cose_err_t
t_cose_tags_and_type(const uint64_t     *relevant_cose_tag_nums,
                     uint32_t            option_flags,
                     const QCBORItem    *item,
                     QCBORDecodeContext *cbor_decoder,
                     uint64_t            unprocessed_tag_nums[T_COSE_MAX_TAGS_TO_RETURN],
                     uint64_t           *cose_tag_num);



/**
 * This value represents an invalid or in-error algorithm ID.  The
 * value selected is 0 as this is reserved in the IANA COSE algorithm
 * registry and is very unlikely to ever be used.  (It would take am
 * IETF standards-action to put it to use).
 */
#define T_COSE_INVALID_ALGORITHM_ID T_COSE_ALGORITHM_RESERVED

/*
 * Format of ToBeMaced bytes
 * This is defined in COSE (RFC 8152) section 6.2. It is the input to the HMAC
 * operation.
 *
 * MAC_structure = [
 *      context : "MAC0",
 *      protected : empty_or_serialized_map,
 *      external_aad : bstr,
 *      payload : bstr
 * ]
 */

/**
 * This is the size of the first part of the CBOR encoded ToBeMaced
 * bytes. It is around 30 bytes.
 */
#define T_COSE_SIZE_OF_TBM \
    1 + /* For opening the array */ \
    sizeof(COSE_MAC_CONTEXT_STRING_MAC0) + /* "MAC0" */ \
    2 + /* Overhead for encoding string */ \
    T_COSE_MAC0_MAX_SIZE_PROTECTED_PARAMETERS + /* entire protected headers */ \
    1 + /* Empty bstr for absent external_aad */ \
    9 /* The max CBOR length encoding for start of payload */


/**
 * \brief Return hash algorithm ID from a signature algorithm ID
 *
 * \param[in] cose_algorithm_id  A COSE signature algorithm identifier.
 *
 * \return \c T_COSE_INVALID_ALGORITHM_ID when the signature algorithm ID
              is not known, or if the signature algorithm does not have
              an associated hash algorithm (eg. EDDSA).
 *
 * This works off of algorithm identifiers defined in the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 * Corresponding local integer constants are defined in
 * t_cose_standard_constants.h.
 *
 * COSE signing algorithms are the combination of public key
 * algorithm, hash algorithm and hash size and imply an appropriate
 * key size.  They are simple integers making them convenient for
 * direct use in code.
 *
 * This function returns an identifier for only the hash algorithm
 * from the combined identifier.
 *
 * If the needed algorithm identifiers are not in the IANA registry,
 * they can be added to it. This will take some time and work.  It is
 * also fine to use algorithms in the COSE proprietary space.
 */
int32_t hash_alg_id_from_sig_alg_id(int32_t cose_algorithm_id);


/**
 * \brief Returns the key length (in bits) of a given encryption algo.
 *
 * @param cose_algorithm_id  Crypto algorithm.
 *
 * Returns the key length (in bits) or UINT_MAX in case of an
 * unknown algorithm id.
 */
uint32_t
bits_in_crypto_alg(int32_t cose_algorithm_id);



/**
 * \brief Create the ToBeMaced (TBM) structure bytes for COSE.
 *
 * \param[in] mac_inputs          The input to be mac'd -- payload, aad,
 *                                protected headers.
 * \param[in]  tbm_first_part_buf The buffer to contain the first part.
 * \param[out] tbm_first_part     Pointer and length of buffer into which
 *                                the resulting TBM is put.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * \retval T_COSE_ERR_SIG_STRUCT
 *         Most likely this is because the protected_headers passed in
 *         is larger than \ref T_COSE_MAC0_MAX_PROT_HEADER.
 * \retval T_COSE_ERR_UNSUPPORTED_HASH
 *         If the hash algorithm is not known.
 * \retval T_COSE_ERR_HASH_GENERAL_FAIL
 *         In case of some general hash failure.
 */
enum t_cose_err_t create_tbm(const struct t_cose_sign_inputs *mac_inputs,
                             struct q_useful_buf              tbm_first_part_buf,
                             struct q_useful_buf_c           *tbm_first_part);


/**
 * Serialize the to-be-signed (TBS) bytes for COSE.
 *
 * \param[in] sign_inputs           The payload, AAD and header params to hash.
 * \param[in] buffer_for_tbs        Pointer and length of buffer into which
 *                                  the resulting TBS bytes is put.
 * \param[out] tbs                  Pointer and length of the
 *                                  resulting TBS bytes.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 * \retval T_COSE_ERR_TOO_SMALL
 *         The output buffer is too small.
 * \retval T_COSE_ERR_CBOR_FORMATTING
 *         Something went wrong formatting the CBOR.
 *
 * The input to the public key signature algorithm in COSE is a CBOR
 * encoded structure containing the protected parameters algorithm ID
 * and a few other things. These are known as the to-be-signed or "TBS"
 * bytes. The exact specification is in [RFC 8152 section
 * 4.4](https://tools.ietf.org/html/rfc8152#section-4.4).
 */
enum t_cose_err_t create_tbs(const struct t_cose_sign_inputs *sign_inputs,
                             struct q_useful_buf              buffer_for_tbs,
                             struct q_useful_buf_c           *tbs);


/**
 * \brief Create the hash of the to-be-signed (TBS) bytes for COSE.
 *
 * \param[in] cose_algorithm_id  The COSE signing algorithm ID. Used to
 *                               determine which hash function to use.
 * \param[in] sign_inputs        The payload, AAD and header params to hash.
 * \param[in] buffer_for_hash    Pointer and length of buffer into which the
 *                               resulting hash is put.
 * \param[out] hash              Pointer and length of the resulting hash.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 * \retval T_COSE_ERR_UNSUPPORTED_HASH
 *         If the hash algorithm is not known.
 * \retval T_COSE_ERR_HASH_BUFFER_SIZE
 *         \c buffer_for_tbs is too small.
 * \retval T_COSE_ERR_HASH_GENERAL_FAIL
 *         In case of some general hash failure.
 *
 * The input to the public key signature algorithm in COSE is the hash
 * of a CBOR encoded structure containing the protected parameters
 * algorithm ID and a few other things. This formats that structure
 * and computes the hash of it. These are known as the to-be-signed or
 * "TBS" bytes. The exact specification is in [RFC 8152 section
 * 4.4](https://tools.ietf.org/html/rfc8152#section-4.4).  This is for
 * both COSE_Sign1 and COSE_Sign. \c sign_inputs->sign_protected is
 * \ref NULL_Q_USEFUL_BUF_C to indicate COSE_Sign1.
 *
 * \c cose_algorithm_id is a signing algorithm, not a hash algorithm.
 * The hash algorithm will be determined from it.
 *
 * See also create_tbs() which does the same, but outputs the full
 * encoded structure rather than a hash of the structure as needed for
 * EdDSA.
 */
enum t_cose_err_t
create_tbs_hash(int32_t                          cose_algorithm_id,
                const struct t_cose_sign_inputs *sign_inputs,
                struct q_useful_buf              buffer_for_hash,
                struct q_useful_buf_c           *hash);


/*
 * Create the Enc_structure for COSE_Encrypt as described
 * in RFC 9052 section 5.2.
 */
enum t_cose_err_t
create_enc_structure(const char             *context_string,
                     struct q_useful_buf_c   protected_headers,
                     struct q_useful_buf_c   aad,
                     struct q_useful_buf     buffer_for_enc,
                     struct q_useful_buf_c  *enc_structure);


/*
 * Create the KDF context info structure for ESDH content key
 * distribution as described RFC 9053 section 5. This doesn't allow
 * for filling in some fields like pary U/V nonce. The prevelance of
 * good RNGs makes them less important. They are filled in as NULLs in
 * compliance with RFC 9053.
 */
enum t_cose_err_t
create_kdf_context_info(const struct t_cose_alg_and_bits  next_alg,
                        const struct q_useful_buf_c       party_u_identity,
                        const struct q_useful_buf_c       party_v_identity,
                        const struct q_useful_buf_c       protected_headers,
                        const struct q_useful_buf_c       supp_pub_other,
                        const struct q_useful_buf_c       supp_priv_info,
                        const struct q_useful_buf         buffer_for_info,
                        struct q_useful_buf_c            *kdf_context_info);


#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN

/**
 * Size of the key returned by get_short_circuit_kid(). It is always
 * this size.
 */
#define T_COSE_SHORT_CIRCUIT_KID_SIZE 32


/**
 * \brief Get the special kid for short-circuit signing.
 *
 * \returns Buffer with the kid.
 *
 * This always returns the same kid. It always indicates short-circuit
 * signing. It is OK to hard code this kid value as the probability of
 * collision with this ID is extremely low and the same as for
 * collision between any two key IDs (kids) of any sort.
 *
 * This always returns a pointer to the same memory as the result
 * returned by this never changes.
 *
 * This is the value of the kid.
 *
 *        0xef, 0x95, 0x4b, 0x4b, 0xd9, 0xbd, 0xf6, 0x70,
 *        0xd0, 0x33, 0x60, 0x82, 0xf5, 0xef, 0x15, 0x2a,
 *        0xf8, 0xf3, 0x5b, 0x6a, 0x6c, 0x00, 0xef, 0xa6,
 *        0xa9, 0xa7, 0x1f, 0x49, 0x51, 0x7e, 0x18, 0xc6
 *
 */
struct q_useful_buf_c get_short_circuit_kid(void);
#endif /* !T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */


/**
 * \brief Map QCBOR decode error to COSE errors.
 *
 * \param[in] qcbor_error   The QCBOR error to map.
 *
 * \return This returns one of the error codes defined by
 *         \ref t_cose_err_t.
 */
enum t_cose_err_t
qcbor_decode_error_to_t_cose_error(QCBORError qcbor_error, enum t_cose_err_t format_error);


enum t_cose_err_t
qcbor_encode_error_to_t_cose_error(QCBOREncodeContext *cbor_encoder);


/**
 * \brief Look for an integer in a zero-terminated list of integers.
 *
 * \param[in] cose_algorithm_id    The algorithm ID to check.
 * \param[in] list                 zero-terminated list of algorithm IDs.
 *
 * \returns This returns \c true if an integer is in the list, \c false if not.
 *
 * Search a list terminated by \ref T_COSE_ALGORITHM_NONE (0) for
 * \c cose_algorithm_id. It is typically used to determine if an algorithm
 * is supported or not by looking it up in a list of algorithms.
 */
bool
t_cose_check_list(int32_t cose_algorithm_id, const int32_t *list);


/**
 * \brief Map a 16-bit integer like an error code to another.
 *
 * \param[in] map    Two-dimentional array that is the mapping.
 * \param[in] query  The input to map
 *
 * \returns The output of the mapping.
 *
 * This function maps one 16-bit integer to another and is
 * mostly used for mapping error codes and sometimes for
 * mapping algorithm IDs. The map is an array of two-element
 * arrays. The first element is matched against \c query.
 * The second is returned on a match. The input map is terminated
 * when the first element is INT16_MIN. When there is not
 * match the value paired with the terminating INT16_MIN is returned.
 *
 * Both gcc and clang are good at optimizing switch statements
 * that map one integer to another so for some but not all uses the switch
 * statement generates less code than making a mapping array
 * and using this function. Particularly, smaller mappings that
 * are called once and get inlined are better as a case statement.
 */
int16_t
t_cose_int16_map(const int16_t map[][2], int16_t query);


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_UTIL_H__ */
