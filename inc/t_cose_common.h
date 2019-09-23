/*
 * t_cose_common.h
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef __T_COSE_COMMON_H__
#define __T_COSE_COMMON_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file t_cose_common.h
 *
 * \brief Defines common to all public t_cose interfaces.
 *
 *  Configuration Options
 *
 *  T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
 *
 * This disables short-circuit signing test mode. This saves
 * a small amount of object code
 *
 * T_COSE_DISABLE_ES512
 * Disables the COSE algorithm ES512 algorithm. This saves a tiny
 * amount of code and a few hundred bytes of stack. It saves more than
 * T_COSE_DISABLE_ES384.
 *
 * T_COSE_DISABLE_ES384
 * Disables the COSE algorithm ES384 algorithm. This saves a tiny
 * amount of code and a few hundred bytes of stack. No stack will be
 * saved if T_COSE_DISABLE_ES512 is not also defined.
 */


/**
 * Indicates the cryptographic library the key the struct t_cose_key is
 * intended for. Usually only one cryptographic library is integrated
 * so this serves as a cross-check.
 *
 */
enum t_cose_crypto_lib_t {
    /** can be used for integrations
     * that don't have or don't want to have any cross-check.
     */
    T_COSE_CRYPTO_LIB_UNIDENTIFIED = 0,
    /** key_ptr points to a malloced OpenSSL EC_KEY. The caller
     * needs to free it after the operation is done. */
    T_COSE_CRYPTO_LIB_OPENSSL = 1,
     /** key_handle is a psa_key_handle_t in Arm's Trustfirmware M. */
    T_COSE_CRYPTO_LIB_TF_M = 2
};


/**
 * This is used to indicate or pass a key through
 * the t_cose implementation to the underlying,
 * platform-specific cryptography libraries for
 * signing and verifying signature.
 *
 */
struct t_cose_key {
    /** Identifies the crypto library this key was created for.
     * The crypto library knows if it uses the handle or
     * the pointer so this indirectly selects the union
     * member. */
    enum t_cose_crypto_lib_t crypto_lib;
    union {
        /** For libraries that use a pointer to the key or
         * key handle. NULL indicates empty. */
        void *key_ptr;
        /** For libraries that use an integer handle to the key */
        uint64_t key_handle;
    } k;
};




/* Private value. Intentionally not documented for Doxygen.
 * This is the size allocated for the encoded protected headers.  It
 * needs to be big enough for make_protected_header() to succeed. It
 * currently sized for one header with an algorithm ID up to 32 bits
 * long -- one byte for the wrapping map, one byte for the label, 5
 * bytes for the ID. If this is made accidentially too small, QCBOR will
 * only return an error, and not overrun any buffers.
 *
 * 9 extra bytes are added, rounding it up to 16 total, in case some
 * other protected header is to be added.
 */
#define T_COSE_SIGN1_MAX_PROT_HEADER (1+1+5+9)


/**
 * Error codes return by t_cose.
 *
 * Do not reorder these. It is OK to add
 * new ones at the end.
 */
enum t_cose_err_t {
    /** Operation completed successfully */
    T_COSE_SUCCESS = 0,

    /** The requested signing algorithm is not supported.  */
    T_COSE_ERR_UNSUPPORTED_SIGNING_ALG = 1,

    /** Error constructing the protected headers. */
    T_COSE_ERR_PROTECTED_HEADERS = 2,

    /** The hash algorithm needed is not supported. Note that the
     * signing algorithm identifier identifies the hash
     * algorithm. */
    T_COSE_ERR_UNSUPPORTED_HASH = 3,

    /** Some system failure when running the hash algorithm. */
    T_COSE_ERR_HASH_GENERAL_FAIL = 4,

    /** The buffer to receive a hash result is too small. */
    T_COSE_ERR_HASH_BUFFER_SIZE = 5,

    /** The buffer to receive result of a signing operation is too
     * small. */
    T_COSE_ERR_SIG_BUFFER_SIZE = 6,

    /** The buffer to receive to receive a key is too small. */
    T_COSE_ERR_KEY_BUFFER_SIZE = 7,

    /** When verifying a \c COSE_Sign1, the CBOR is "well-formed", but something is wrong with the
     * format of the CBOR outside of the headers. For example, it is missing something like
     * the payload or something is of an unexpected type. */
    T_COSE_ERR_SIGN1_FORMAT = 8,

    /** When decoding some CBOR like a \c COSE_Sign1, the CBOR was not
     * "well-formed". Most likely what was supposed to be CBOR was is
     * either not or it has been corrupted. The CBOR is can't be decoded. */
    T_COSE_ERR_CBOR_NOT_WELL_FORMED = 9,

    /** The CBOR is "well-formed", but something is wrong with format
     * in the headers. See also \ref T_COSE_ERR_SIGN1_FORMAT. For example,
     * a header is labeled with other than an integer or string or
     * the value is an integer when a byte string is expected. */
    T_COSE_ERR_HEADER_CBOR = 10,

    /** No algorithm ID was found when one is needed. For example, when
     * verifying a \c COSE_Sign1. */
    T_COSE_ERR_NO_ALG_ID = 11,

    /** No key ID was found when one is needed. For example, when
     * verifying a \c COSE_Sign1. */
    T_COSE_ERR_NO_KID = 12,

    /** Signature verification failed. For example, the cryptographic
     * operations completed successfully but hash wasn't as expected. */
    T_COSE_ERR_SIG_VERIFY = 13,

    /** Verification of a short-circuit signature failed. */
    T_COSE_ERR_BAD_SHORT_CIRCUIT_KID = 14,

    /** Some (unspecified) argument was not valid. */
    T_COSE_ERR_INVALID_ARGUMENT = 15,

    /** Out of heap memory. Originates in crypto library as
     * t_cose does not use malloc. */
    T_COSE_ERR_INSUFFICIENT_MEMORY = 16,

    /** General unspecific failure. */
    T_COSE_ERR_FAIL = 17,

    /** Equivalent to \c PSA_ERROR_TAMPERING_DETECTED. */
    T_COSE_ERR_TAMPERING_DETECTED = 18,

    /** The key identified by a key slot of a key ID was not found. */
    T_COSE_ERR_UNKNOWN_KEY = 19,

    /** The key was found, but it was the wrong type for the operation. */
    T_COSE_ERR_WRONG_TYPE_OF_KEY = 20,

    /** Error constructing the \c Sig_structure when signing or verify. */
    T_COSE_ERR_SIG_STRUCT = 21,

    /** Signature was short-circuit. The option
     * \ref T_COSE_OPT_ALLOW_SHORT_CIRCUIT to allow verification
     * of short-circuit signatures was not set.  */
    T_COSE_ERR_SHORT_CIRCUIT_SIG = 22,

    /** Something generally went wrong when signing or verifying.  */
    T_COSE_ERR_SIG_FAIL = 23,

    /** Something went wrong formatting the CBOR, most likely the
     * payload has maps or arrays that are not closed. */
    T_COSE_ERR_CBOR_FORMATTING = 24,

     /** The buffer passed in to receive the output is too small. */
    T_COSE_ERR_TOO_SMALL = 25,

    /** More headers (more than T_COSE_HEADER_LIST_MAX) than this implementation can handle. Note that
     * all headers need to be checked for criticality so all
     * headers need to be examined. */
    T_COSE_ERR_TOO_MANY_HEADERS= 26,

    /** A header was encountered that was unknown and also listed in the
      * critical headers header. */
    T_COSE_ERR_UNKNOWN_CRITICAL_HEADER = 27,

    /** A request was made to signed with a short-ciruit sig,
     * \ref T_COSE_OPT_SHORT_CIRCUIT_SIG, but short circuit signature are
     * disabled (compiled out) for this implementation.  */
    T_COSE_ERR_SHORT_CIRCUIT_SIG_DISABLED = 28,

    /** The key type in a t_cose_signing_key is wrong for the
     cryptographic library used by this integration of t_cose.
     */
    T_COSE_ERR_INCORRECT_KEY_FOR_LIB = 29,
    /** This implementation only handles integer COSE algorithm IDs with
     values less than \c INT32_MAX. */

    T_COSE_ERR_NON_INTEGER_ALG_ID = 30,
    /** The content type header contains a content type that neither integer
     * or text string or it is an integer not in the range of 0
     * to \c UINT16_MAX. */
    T_COSE_ERR_BAD_CONTENT_TYPE = 31,

    /** If the option \ref T_COSE_OPT_TAG_REQUIRED is set for
     * t_cose_sign1_verify() and the tag is absent, this error is returned. */
    T_COSE_ERR_INCORRECTLY_TAGGED = 32,

    /** The signing or verification key given is empty. */
    T_COSE_ERR_EMPTY_KEY = 33,
};


/** The maximum number of headers this implementation can handle.
 * The limit is T_COSE_HEADER_LIST_MAX for integer labeled-
 * headers and the same additional for tstr-labeled headers.
 * This is a hard maximum so the implementation doesn't need
 * malloc. This constant can be increased if needed. Doing so
 * will increase stack usage.
 */
#define T_COSE_HEADER_LIST_MAX 10


#ifdef __cplusplus
}
#endif


#endif /* __T_COSE_COMMON_H__ */
