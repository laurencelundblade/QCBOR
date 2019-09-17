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
 */


/*

 T_COSE_DISABLE_SHORT_CIRCUIT_SIGN

 */
//#define T_COSE_DISABLE_SHORT_CIRCUIT_SIGN





enum t_cose_crypto_lib_t {
    T_COSE_CRYPTO_LIB_UNIDENTIFIED = 0,
    T_COSE_CRYPTO_LIB_OPENSSL = 1,
    T_COSE_CRYPTO_LIB_TF_M = 2
};


/*
 * This is used to indicate or pass a key through
 * the t_cose implementation to the underlying,
 * platform-specific cryptography libraries for
 * signing and verifying signature.
 *
 *
 */
struct t_cose_signing_key {
    enum t_cose_crypto_lib_t crypto_lib;
    union {
        void *key_ptr;
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
    /**
     * Operation completed successfully
     */
    T_COSE_SUCCESS = 0,
    /**
     * The requested signing algorithm is not supported.
     */
    T_COSE_ERR_UNSUPPORTED_SIGNING_ALG,
    /**
     * Error constructing the protected headers.
     */
    T_COSE_ERR_PROTECTED_HEADERS,
    /**
     * The hash algorithm needed is not supported. Note that the
     * signing algorithm identifier usually identifies the hash
     * algorithm.
     */
    T_COSE_ERR_UNSUPPORTED_HASH,
    /**
     * Some system failure when running the hash algorithm.
     */
    T_COSE_ERR_HASH_GENERAL_FAIL,
    /**
     * The buffer to receive a hash result is too small.
     */
    T_COSE_ERR_HASH_BUFFER_SIZE,
    /**
     * The buffer to receive result of a signing operation is too
     * small.
     */
    T_COSE_ERR_SIG_BUFFER_SIZE,
    /**
     * The buffer to receive to receive a key is too small.
     */
    T_COSE_ERR_KEY_BUFFER_SIZE,
    /**
     * When verifying a \c COSE_Sign1, something is wrong with the
     * format of the CBOR. For example, it is missing something like
     * the payload or something is of an unexpected type.
     */
    T_COSE_ERR_SIGN1_FORMAT,
    /**
     * When decoding some CBOR like a \c COSE_Sign1, the CBOR was not
     * "well-formed". Most likely what was supposed to be CBOR was is
     * either not or it has been corrupted.
     */
    T_COSE_ERR_CBOR_NOT_WELL_FORMED,
    /**
     * The CBOR is "well-formed", but the structure is not right. For example
     * an array occurs when a map is expected, or a string occurs when an
     * integer is expected */
    T_COSE_ERR_CBOR_STRUCTURE,
    /**
     * No algorithm ID was found when one is needed. For example, when
     * verifying a \c COSE_Sign1.
     */
    T_COSE_ERR_NO_ALG_ID,
    /**
     * No key ID was found when one is needed. For example, when
     * verifying a \c COSE_Sign1.
     */
    T_COSE_ERR_NO_KID,
    /**
     * Signature verification failed. For example, the cryptographic
     * operations completed successfully but hash wasn't as expected.
     */
    T_COSE_ERR_SIG_VERIFY,
    /**
     * Verification of a short-circuit signature failed.
     */
    T_COSE_ERR_BAD_SHORT_CIRCUIT_KID,
    /**
     * Some (unspecified) argument was not valid.
     */
    T_COSE_ERR_INVALID_ARGUMENT,
    /**
     * Out of heap memory.
     */
    T_COSE_ERR_INSUFFICIENT_MEMORY,
    /**
     * General unspecific failure.
     */
    T_COSE_ERR_FAIL,
    /**
     * Equivalent to \c PSA_ERROR_TAMPERING_DETECTED.
     */
    T_COSE_ERR_TAMPERING_DETECTED,
    /**
     * The key identified by a key slot of a key ID was not found.
     */
    T_COSE_ERR_UNKNOWN_KEY,
    /**
     * The key was found, but it was the wrong type for the operation.
     */
    T_COSE_ERR_WRONG_TYPE_OF_KEY,
    /**
     * Error constructing the \c Sig_structure when signing or verify.
     */
    T_COSE_ERR_SIG_STRUCT,
    /**
      * Signature was short-circuit. The option
       \ref T_COSE_OPT_ALLOW_SHORT_CIRCUIT to allow verification
      * of short-circuit signatures was not set.
     */
    T_COSE_ERR_SHORT_CIRCUIT_SIG,
    /**
     * Something generally went wrong when signing or verifying.
     */
    T_COSE_ERR_SIG_FAIL,
    /** Something went wrong formatting the CBOR, most likely the
     payload has maps or arrays that are not closed. */
    T_COSE_ERR_CBOR_FORMATTING,
     /** The buffer passed in to receive the output is too small. */
    T_COSE_ERR_TOO_SMALL,
    /** More headers (more than T_COSE_HEADER_LIST_MAX) than this implementation can handle. Note that
        all headers need to be checked for criticality so all
        headers need to be examined. */
    T_COSE_ERR_TOO_MANY_HEADERS,
    /** A header was encountered that was unknown and also listed in the critical headers header. */
    T_COSE_UNKNOWN_CRITICAL_HEADER,
    /** A request was made to signed with a short-ciruit sig,
        \ref T_COSE_OPT_SHORT_CIRCUIT_SIG, but short circuit signature are
        disabled (compiled out) for this implementation  */
    T_COSE_SHORT_CIRCUIT_SIG_DISABLED,

    /** The key type in a t_cose_signing_key is wrong for the
     cryptographic library used by this integration of t_cose.
     */
    T_COSE_INCORRECT_KEY_FOR_LIB,
    /** This implementation only handles integer COSE algorithm IDs with
     values less than INT32_MAX */
    T_COSE_NON_INTEGER_ALG_ID,
    /** The content type header contains a content type that neither integer or text string or it is an integer not in the range of 0 to UINT16_MAX. */
    T_COSE_BAD_CONTENT_TYPE,
};


/* The maximum number of headers this implementation can handle.
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
