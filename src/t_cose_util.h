/*
 *  t_cose_util.h
 *
 * Copyright 2019-2025, Laurence Lundblade
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
#include "t_cose/t_cose_key.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file t_cose_util.h
 *
 * \brief Utility functions used internally by the t_cose implementation.
 *
 */




#if QCBOR_VERSION_MAJOR >= 2

/**
 * \brief Consume all the tag numbers preceding an item.
 *
 * \param[in] cbor_decoder  Decoder to read the tag numbers from.
 * \param[out] tag_numbers  The tag numbers consumed. Order is outer-most first.
 * \param[out] last_tag_index   Index of the inner-most tag number.
 *
 * Used with QCBOR v2 where tag numbers are to be consumed.
 *
 * If the value of tag_numbers[*last_tag_index] != INVALID, then
 * there is a last tag number; that is tag_numbers isn't empty.
 */
QCBORError
t_cose_private_consume_tag_nums(QCBORDecodeContext *cbor_decoder,
                                uint64_t            tag_numbers[QCBOR_MAX_TAGS_PER_ITEM],
                                int                *last_tag_index);


/**
 * \brief A common processor for tag numbers for the _msg methods
 *
 * \param[in] cbor_decoder Decoder to read the tag numbers from.
 * \param[in,out] option_flags
 * \param[out] returned_tag_numbers   The tag numbers decoded. May be NULL.
 *
 * Used by the methods that consume and return all the tag numbers.
 *
 * This consumes all the tag numbers before the first item in the COSE message.
 * The option_flags are examined to know if there should be a tag number
 * to indicate the message type. If so it is put into the option_flags.
 * Any remaining tag_numbers are returned. If there are any and
 * returned_tag_numbers is NULL, it is an error.
 *
 */
enum t_cose_err_t
t_cose_private_process_msg_tag_nums(QCBORDecodeContext  *cbor_decoder,
                                    enum t_cose_err_t    error_format,
                                    uint32_t            *option_flags,
                                    uint64_t             returned_tag_numbers[T_COSE_MAX_TAGS_TO_RETURN]);

#endif /* QCBOR_VERSION_MAJOR >= 2 */


#if QCBOR_VERSION_MAJOR == 1

/**
 * \brief Process tag numbers when linked against QCBOR v1.
 *
 * \param[in] option_flags   Option flags from initialization of context
 * \param[in] v1_semantics   If true t_cose v1, if false t_cose v2 semantics
 * \param[in] cbor_decoder   Decoder instance needed to unmap tag numbers in QCBOR v1
 * \param[in] item           Decoded first item that has tag numbers associated
 * \param[out] message_type  The type of COSE message
 * \param[out] tag_numbers   The returned tag numbers.
 *
 * This determines the message type from option_flags and the
 * encoded tag numbers. This returns the tag numbers not consumed
 * in determining the message type.
 *
 * This is only for use when linked against QCBOR v1. This mainly provides
 * t_cose v2 tag semantics when linked against QCBOR v1, but also provides
 * t_cose v1 tag semantics to for the backwards compatibility for  t_cose_sign1
 * which is supported in t_cose v2.
 */
enum t_cose_err_t
t_cose_process_tag_numbers_qcbor1(uint32_t             option_flags,
                                  bool                 v1_semantics,
                                  QCBORDecodeContext  *cbor_decoder,
                                  const QCBORItem     *item,
                                  uint64_t            *message_type,
                                  uint64_t             tag_numbers[T_COSE_MAX_TAGS_TO_RETURN]);

#endif /* QCBOR_VERSION_MAJOR == 1 */




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
 * \brief Returns the IV length (in bits) of a given encryption algo.
 *
 * @param cose_algorithm_id  Crypto algorithm.
 *
 * Returns the IV length (in bits) or UINT_MAX in case of an
 * unknown algorithm id.
 */
uint32_t
bits_iv_alg(int32_t cose_algorithm_id);


/**
 * \brief Create the ToBeMaced (TBM) structure bytes for COSE.
 *
 * \param[in] cose_alg_id  Which MAC algorithm to use.
 * \param[in] mac_key      Key used to perform MAC.
 * \param[in] mac_inputs   The input to be mac'd -- payload, ext supp data,
 *                         protected headers.
 * \param[in]  is_mac0     COSE_MAC0 or COSE_MAC.
 * \param[out] tag_buf     Pointer and length of buffer into which the
 *                         computed HMAC tag is put.
 * \param[out] mac_tag     Pointer and length of computed tag.
 *
 * \return This returns one of the error codes defined by \ref t_cose_err_t.
 *
 * \retval T_COSE_ERR_UNSUPPORTED_HMAC
 *         If the hash algorithm is not known.
 * \retval T_COSE_ERR_HMAC_GENERAL_FAIL
 *         In case of some general hash failure.
 */
enum t_cose_err_t
create_tbm(const int32_t                    cose_alg_id,
           struct t_cose_key                mac_key,
           bool                             is_mac0,
           const struct t_cose_sign_inputs *mac_inputs,
           const struct q_useful_buf        tag_buf,
           struct q_useful_buf_c           *mac_tag);


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
 * \brief Map QCBOR decode error to t_cose errors.
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

/**
 * \brief Judge whether the algorithm id describes non AEAD cipher.
 *
 * \param[in] cose_algorithm_id     The COSE algorithm id.
 *
 * \returns true of false.
 */
bool
t_cose_alg_is_non_aead(int32_t cose_algorithm_id);

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_UTIL_H__ */
