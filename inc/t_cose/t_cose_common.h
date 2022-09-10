/*
 * t_cose_common.h
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2020-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef __T_COSE_COMMON_H__
#define __T_COSE_COMMON_H__

#include <stdint.h>
#include <stdbool.h>
#include "t_cose/q_useful_buf.h"
#ifdef __cplusplus
extern "C" {
#endif


/*
 * API Design Overview
 * 
 * t_cose is made up of a collection of objects (in the
 * object-oriented programming sense) that correspond to the main
 * objects defined in CDDL by the COSE standard (RFC 9052). These
 * objects come in pairs, one for the sendi *ng/signing/encrypting
 * side and the other for the receiving/verifying/decrypting
 * side. Following is a high-level description of all of these and how
 * they connect up to each other.
 *
 * Some of this is implemented and some of this is a design proposal,
 * so it is subject to some change, renaming and such as the
 * implementation completes.
 *
 *
 * COSE_Sign and COSE_Sign1
 *
 * t_cose_sign_sign() and t_cose_sign_verify() are the pair that
 * implements both COSE_Sign and COSE_Sign1 COSE messages.
 *
 * They rely on implementations of t_cose_signature_sign and
 * t_cose_signature_verify to create and to verify the
 * COSE_Signature(s) that are in a COSE_Sign. They are also used to
 * create the signature for COSE_Sign1. These two are an abstract
 * base class they are just an interface without an implementation.
 *
 * t_cose_headers_decode() and t_cose_headers_encode() are also used
 * by the t_cose_sign pair. These process both the protected and
 * unprotected header parameter buckets called Headers in COSE.
 *
 *
 * COSE_Encrypt and COSE_Encrypt0
 *
 * t_cose_encrypt_enc() and t_cose_encrypt_dec() are the pair for
 * COSE_Encrypt and COSE_Encrypt0.
 *
 * t_cose_headers_decode() and t_cose_headers_encode() are used for
 * the header parameters.
 *
 * This makes use of implementations of t_cose_recipient_enc and
 * t_cose_recipient_dec for COSE_recipient used by COSE_Encrypt. They
 * are not needed for COSE_Encrypt0.
 *
 *
 * COSE_Mac and COSE_Mac0
 *
 * t_cose_mac_auth() and t_cose_mac_check() are the pair for COSE_Mac
 * and COSE_Mac0.
 *
 * t_cose_headers_decode() and t_cose_headers_encode() are used for
 * the header parameters.
 *
 * For COSE_Mac, t_cose_recipient_enc() and t_cose_recipient_dec()
 * implement COSE_recipient. (I’m pretty sure sharing t_cose_recipient
 * between COSE_MAC and COSE_Encrypt can work, but this needs to be
 * checked by actually de *signing and implementing it). These are not
 * needed for COSE_Mac0.
 *
 * 
 * COSE_Message
 *
 * t_cose_message_create() and t_cose_message_decode handle
 * COSE_Message. This is for handling COSE messages that might signed,
 * encrypted, MACed or some combination of these. In the simplest case
 * they decode the CBOR tag n *umber and switch off to one of the
 * above handlers. In more complicated cases they recursively handled
 * nested signing, encrypting and MACing. (Lots of work to do on
 * this…)
 *
 *
 * Headers
 *
 * t_cose_headers_decode() and t_cose_headers_encode() handle the
 * protected and unprotected header parameter buckets that are used by
 * all the COSE messages.
 *
 * This also defines a data structure, t_cose_header_parameter that
 * holds one single parameter, for example an algorithm ID or a
 * kid. This structure is used to pass the parameters in and out of
 * all the methods above. It fa *cilitates the general header
 * parameter implementation and allows for custom and specialized
 * headers.
 *
 *
 * COSE_signature
 *
 * t_cose_signature_sign and t_cose_signature_verify are abstract
 * bases classes for a set of implementations of COSE_Signature. This
 * design is chosen because there are a variety of signature schemes
 * to implement. Mostly th *ese correspond to different signing
 * algorithms, but there is enough variation from algorithm to
 * algorithm that the use of an abstract base class here makes sense.
 *
 * The concrete classes will generally correspond to groups of
 * algorithms. For example, there will likely be one for ECDSA,
 * t_cose_signature_sign_ecdsa, another for RSAPSS and a variety for
 * PQ. Perhaps there will be one fo *r counter signatures of
 * particular types.
 *
 * The user of t_cose will create instances of t_cose_signature and
 * configure them into t_cose_sign_sign() and t_cose_sign_verify().
 *
 *
 * COSE_recipient
 *
 * t_cose_recipient_enc and t_cose_recipient_dec are abstract base
 * classes for the set of concrete implementations of
 * COSE_recipient. Because the variation in one type of COSE_recipient
 * to another is so varied, this is whe *re the abstract base class is
 * necessary.
 *
 * Note that this use object-orientation here gives some very nice
 * modularity and extensibility. New types of COSE_recipient can be
 * added to COSE_Encrypt and COSE_Mac without changing their
 * implementation at all. It is als *o possible to add new types of
 * recipients without even modifying the main t_cose library.
 *
 * 
 * COSE_Key 
 *
 * Some formats of COSE_recipient have parameters that are in the
 * COSE_key format. It would be useful to have some library code to
 * handle these, in particular to encode and decode from the key data
 * structure used by the cr *ypto library (OpenSSL, PSA, …).
 */


  
/**
 * \file t_cose_common.h
 *
 * \brief This file contains definitions common to all public t_cose
 * interfaces.
 *
 * t_cose_common.h contains the definitions common to all public
 * t_cose interfaces, particularly the error codes, algorithm
 * identification constants and the structure containing a key.
 *
 * **Compile Time Configuration Options**
 *
 * \c T_COSE_DISABLE_SHORT_CIRCUIT_SIGN -- This disables short-circuit
 * signing test mode. This saves a small amount of object code
 *
 * \c T_COSE_DISABLE_ES512 -- Disables the COSE algorithm ES512
 * algorithm. This saves a tiny amount of code and a few hundred bytes
 * of stack. It saves more than \c T_COSE_DISABLE_ES384.
 *
 * \c T_COSE_DISABLE_ES384 -- Disables the COSE algorithm ES384
 * algorithm. This saves a tiny amount of code and a few hundred bytes
 * of stack. No stack will be saved if \c T_COSE_DISABLE_ES512 is not
 * also defined.
 *
 * \c T_COSE_DISABLE_CONTENT_TYPE -- Disables the content type
 * parameters for both signing and verifying.
 */




/**
 * \def T_COSE_ALGORITHM_ES256
 *
 * \brief Indicates ECDSA with SHA-256.
 *
 * This value comes from the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 *
 * The COSE standard recommends a key using the secp256r1 curve with
 * this algorithm. This curve is also known as prime256v1 and P-256.
 */
#define T_COSE_ALGORITHM_ES256 -7

/**
 * \def T_COSE_ALGORITHM_ES384
 *
 * \brief Indicates ECDSA with SHA-384.
 *
 * This value comes from the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 *
 * The COSE standard recommends a key using the secp384r1 curve with
 * this algorithm. This curve is also known as P-384.
 */
#define T_COSE_ALGORITHM_ES384 -35

/**
 * \def T_COSE_ALGORITHM_ES512
 *
 * \brief Indicates ECDSA with SHA-512.
 *
 * This value comes from the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 *
 * The COSE standard recommends a key using the secp521r1 curve with
 * this algorithm. This curve is also known as P-521.
 */
#define T_COSE_ALGORITHM_ES512 -36

/**
 * \def T_COSE_ALGORITHM_HMAC256
 *
 * \brief Indicates HMAC with SHA256
 *
 * This value comes from the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 *
 * Value for \ref COSE_HEADER_PARAM_ALG to indicate HMAC w/ SHA-256
 */
#define T_COSE_ALGORITHM_HMAC256 5

/**
 * \def T_COSE_ALGORITHM_HMAC384
 *
 * \brief Indicates HMAC with SHA384
 *
 * This value comes from the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 *
 * Value for \ref COSE_HEADER_PARAM_ALG to indicate HMAC w/ SHA-384
 */
#define T_COSE_ALGORITHM_HMAC384 6

/**
 * \def T_COSE_ALGORITHM_HMAC512
 *
 * \brief Indicates HMAC with SHA512
 *
 * This value comes from the
 * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml).
 *
 * Value for \ref COSE_HEADER_PARAM_ALG to indicate HMAC w/ SHA-512
 */
#define T_COSE_ALGORITHM_HMAC512 7

#define T_COSE_ALGORITHM_NONE 0



/**
 * Indicates the cryptographic library the \ref t_cose_key is intended
 * for. Usually only one cryptographic library is integrated so this
 * serves as a cross-check.
 */
enum t_cose_crypto_lib_t {
    /** can be used for integrations
     * that don't have or don't want to have any cross-check.
     */
    T_COSE_CRYPTO_LIB_UNIDENTIFIED = 0,
    /** \c key_ptr points to a malloced OpenSSL EC_KEY. The caller
     * needs to free it after the operation is done. */
    T_COSE_CRYPTO_LIB_OPENSSL = 1,
     /** \c key_handle is a \c psa_key_handle_t in Arm's Platform Security
      * Architecture */
    T_COSE_CRYPTO_LIB_PSA = 2
};


/**
 * This structure is used to indicate or pass a key through the t_cose
 * implementation to the underlying, platform-specific cryptography
 * libraries for signing and verifying signature. You must know the
 * cryptographic library that is integrated with t_cose to know how to
 * fill in this data structure.
 *
 * For example, in the OpenSSL integration, \ref key_ptr should point
 * to an OpenSSL \c EVP_KEY type.
 */
struct t_cose_key {
    /** Identifies the crypto library this key was created for.  The
     * crypto library knows if it uses the handle or the pointer so
     * this indirectly selects the union member. */
    enum t_cose_crypto_lib_t crypto_lib;
    union {
        /** For libraries that use a pointer to the key or key
         * handle. \c NULL indicates empty. */
        void *key_ptr;
        /** For libraries that use an integer handle to the key */
        uint64_t key_handle;
    } k;
};


/** An empty or \c NULL \c t_cose_key */
/*
 * This has to be definied differently in C than C++ because there is
 * no common construct for a literal structure.
 *
 * In C compound literals are used.
 *
 * In C++ list initalization is used. This only works
 * in C++11 and later.
 *
 * Note that some popular C++ compilers can handle compound
 * literals with on-by-default extensions, however
 * this code aims for full correctness with strict
 * compilers so they are not used.
 */
#ifdef __cplusplus
#define T_COSE_NULL_KEY {T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}}
#else
#define T_COSE_NULL_KEY \
    ((struct t_cose_key){T_COSE_CRYPTO_LIB_UNIDENTIFIED, {0}})
#endif


/* Private value. Intentionally not documented for Doxygen.  This is
 * the size allocated for the encoded protected header parameters.  It
 * needs to be big enough for encode_protected_parameters() to
 * succeed. It currently sized for one parameter with an algorithm ID
 * up to 32 bits long -- one byte for the wrapping map, one byte for
 * the label, 5 bytes for the ID. If this is made accidentially too
 * small, QCBOR will only return an error, and not overrun any
 * buffers.
 *
 * 17 extra bytes are added, rounding it up to 24 total, in case some
 * other protected header parameter is to be added and so the test
 * using T_COSE_TEST_CRIT_PARAMETER_EXIST can work.
 */
#define T_COSE_SIGN1_MAX_SIZE_PROTECTED_PARAMETERS (1+1+5+17)

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
#define T_COSE_MAC0_MAX_SIZE_PROTECTED_PARAMETERS (1 + 1 + 5 + 9)

#define T_COSE_NUM_VERIFY_DECODE_HEADERS 8
/**
 * Error codes return by t_cose.
 */
/*
 * Do not reorder these. It is OK to add new ones at the end.
 *
 * Explicit values are included because some tools like debuggers show
 * only the value, not the symbol, and it is hard to count up through
 * 35 lines to figure out the actual value.
 */
enum t_cose_err_t {
    /** Operation completed successfully. */
    T_COSE_SUCCESS = 0,

    /** The requested signing algorithm is not supported.  */
    T_COSE_ERR_UNSUPPORTED_SIGNING_ALG = 1,

    /** Internal error when encoding protected parameters, usually
     * because they are too big. It is internal because the caller
     * can't really affect the size of the protected parameters. */
    T_COSE_ERR_MAKING_PROTECTED = 2,

    /** The hash algorithm needed is not supported. Note that the
     * signing algorithm identifier identifies the hash algorithm. */
    T_COSE_ERR_UNSUPPORTED_HASH = 3,

    /** Some system failure when running the hash algorithm. */
    T_COSE_ERR_HASH_GENERAL_FAIL = 4,

    /** The buffer to receive a hash result is too small. */
    T_COSE_ERR_HASH_BUFFER_SIZE = 5,

    /** The buffer to receive result of a signing operation is too
     * small. */
    T_COSE_ERR_SIG_BUFFER_SIZE = 6,

    /** When verifying a \c COSE_Sign1, the CBOR is "well-formed", but
     * something is wrong with the format of the CBOR outside of the
     * header parameters. For example, it is missing something like
     * the payload or something is of an unexpected type. */
    T_COSE_ERR_SIGN1_FORMAT = 8,

    /** When decoding some CBOR like a \c COSE_Sign1, the CBOR was not
     * "well-formed". Most likely what was supposed to be CBOR is
     * either not or is corrupted. The CBOR is can't be decoded. */
    T_COSE_ERR_CBOR_NOT_WELL_FORMED = 9,

    /** The CBOR is "well-formed", but something is wrong with format
     * in the header parameters.  For example, a parameter is labeled
     * with other than an integer or string or the value is an integer
     * when a byte string is expected. */
    T_COSE_ERR_PARAMETER_CBOR = 10,

    /** No algorithm ID was found when one is needed. For example,
     * when verifying a \c COSE_Sign1. */
    T_COSE_ERR_NO_ALG_ID = 11,

    /** No kid (key ID) was found when one is needed. For example,
     * when verifying a \c COSE_Sign1. */
    T_COSE_ERR_NO_KID = 12,

    /** Signature verification failed. For example, the cryptographic
     * operations completed successfully but hash wasn't as
     * expected. */
    T_COSE_ERR_SIG_VERIFY = 13,

    /** Verification of a short-circuit signature failed. */
    T_COSE_ERR_BAD_SHORT_CIRCUIT_KID = 14,

    /** Some (unspecified) argument was not valid. */
    T_COSE_ERR_INVALID_ARGUMENT = 15,

    /** Out of heap memory. This originates in crypto library as
     * t_cose does not use malloc. */
    T_COSE_ERR_INSUFFICIENT_MEMORY = 16,

    /** General unspecific failure. */
    T_COSE_ERR_FAIL = 17,

    /** Equivalent to \c PSA_ERROR_CORRUPTION_DETECTED. */
    T_COSE_ERR_TAMPERING_DETECTED = 18,

    /** The key identified by a \ref t_cose_key or a key ID was not
     * found. */
    T_COSE_ERR_UNKNOWN_KEY = 19,

    /** The key was found, but it was the wrong type for the
      * operation. */
    T_COSE_ERR_WRONG_TYPE_OF_KEY = 20,

    /** Error constructing the COSE \c Sig_structure when signing or
     *  verify. */
    T_COSE_ERR_SIG_STRUCT = 21,

    /** Signature was short-circuit. The option \ref
     * T_COSE_OPT_ALLOW_SHORT_CIRCUIT to allow verification of
     * short-circuit signatures was not set.  */
    T_COSE_ERR_SHORT_CIRCUIT_SIG = 22,

    /** Something generally went wrong in the crypto adaptor when
      * signing or verifying. */
    T_COSE_ERR_SIG_FAIL = 23,

    /** Something went wrong formatting the CBOR.  Possibly the
     * payload has maps or arrays that are not closed when using
     * t_cose_sign1_encode_parameters() and
     * t_cose_sign1_encode_signature() to sign a \c COSE_Sign1. */
    T_COSE_ERR_CBOR_FORMATTING = 24,

     /** The buffer passed in to receive the output is too small. */
    T_COSE_ERR_TOO_SMALL = 25,

    /** More parameters (more than \ref T_COSE_PARAMETER_LIST_MAX)
     * than this implementation can handle. Note that all parameters
     * need to be checked for criticality so all parameters need to be
     * examined. */
    T_COSE_ERR_TOO_MANY_PARAMETERS = 26,

    /** A parameter was encountered that was unknown and also listed in
      * the crit labels parameter. */
    T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER = 27,

    /** A request was made to signed with a short-circuit sig, \ref
     * T_COSE_OPT_SHORT_CIRCUIT_SIG, but short circuit signature are
     * disabled (compiled out) for this implementation.  */
    T_COSE_ERR_SHORT_CIRCUIT_SIG_DISABLED = 28,

    /** The key type in a \ref t_cose_key is wrong for the
     * cryptographic library used by this integration of t_cose.
     */
    T_COSE_ERR_INCORRECT_KEY_FOR_LIB = 29,
    /** This implementation only handles integer COSE algorithm IDs with
     * values less than \c INT32_MAX. */

    T_COSE_ERR_NON_INTEGER_ALG_ID = 30,
    /** The content type parameter contains a content type that is
     * neither integer or text string or it is an integer not in the
     * range of 0 to \c UINT16_MAX. */
    T_COSE_ERR_BAD_CONTENT_TYPE = 31,

    /** If the option \ref T_COSE_OPT_TAG_REQUIRED is set for
     * t_cose_sign1_verify() and the tag is absent, this error is
     * returned. */
    T_COSE_ERR_INCORRECTLY_TAGGED = 32,

    /** The signing or verification key given is empty. */
    T_COSE_ERR_EMPTY_KEY = 33,

    /** A header parameter occurs twice, perhaps once in protected and
     * once in unprotected. Duplicate header parameters are not
     * allowed in COSE.
     */
    T_COSE_ERR_DUPLICATE_PARAMETER = 34,

    /** A header parameter that should be protected (alg id or crit)
     * is not. This occurs when verifying a \c COSE_Sign1 that is
     * improperly constructed. */
    T_COSE_ERR_PARAMETER_NOT_PROTECTED = 35,

    /** Something is wrong with the crit parameter. */
    T_COSE_ERR_CRIT_PARAMETER = 36,

    /** More than \ref T_COSE_MAX_TAGS_TO_RETURN unprocessed tags when
     * verifying a signature. */
    T_COSE_ERR_TOO_MANY_TAGS = 37,

    /** When decoding a header parameter that is not a string, integer or boolean
     * was encountered with no callback set handle it. See t_cose_ignore_param_cb()
     * and related. */
    T_COSE_ERR_UNHANDLED_HEADER_PARAMETER = 38,

    /* When encoding parameters, struct t_cose_header_parameter.parameter_type
     * is not a valid type.
     */
    T_COSE_ERR_INVALID_PARAMETER_TYPE = 39,

    /* Can't put critical parameters in the non-protected
     * header bucket. */
    T_COSE_ERR_CRIT_PARAMETER_IN_UNPROTECTED = 40,

    T_COSE_ERR_INSUFFICIENT_SPACE_FOR_PARAMETERS = 41,

    /**
     * When verifying a \c COSE_Mac0, something is wrong with the
     * format of the CBOR. For example, it is missing something like
     * the payload.
     */
    T_COSE_ERR_MAC0_FORMAT = 42,
};

/**
 * The maximum number of header parameters that can be handled during
 * verification of a \c COSE_Sign1 message. \ref
 * T_COSE_ERR_TOO_MANY_PARAMETERS will be returned by
 * t_cose_sign1_verify() if the input message has more.
 *
 * There can be both \ref T_COSE_PARAMETER_LIST_MAX integer-labeled
 * parameters and \ref T_COSE_PARAMETER_LIST_MAX string-labeled
 * parameters.
 *
 * This is a hard maximum so the implementation doesn't need
 * malloc. This constant can be increased if needed. Doing so will
 * increase stack usage.
 */
#define T_COSE_PARAMETER_LIST_MAX 10



/**
 * The value of an unsigned integer content type indicating no content
 * type.  See \ref t_cose_parameters.
 */
#define T_COSE_EMPTY_UINT_CONTENT_TYPE UINT16_MAX+1

/**
 * The result of parsing a set of COSE header parameters. The pointers
 * in this are all back into the \c COSE_Sign1 blob passed in to
 * t_cose_sign1_verify() as the \c sign1 parameter.
 *
 * Approximate size on a 64-bit machine is 80 bytes and on a 32-bit
 * machine is 40.
 */
struct t_cose_parameters {
    /** The algorithm ID. \ref T_COSE_UNSET_ALGORITHM_ID if the algorithm ID
     * parameter is not present. String type algorithm IDs are not
     * supported.  See the
     * [IANA COSE Registry](https://www.iana.org/assignments/cose/cose.xhtml)
     * for the algorithms corresponding to the integer values.
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

/**
 * An \c option_flag to not add the CBOR type 6 tag for a COSE message.
 * Some uses of COSE may require this tag be absent because its COSE
 * message type is known from surrounding context.
 *
 * Or said another way, per the COSE RFC, this code produces a \c
 * COSE_Sign1_Tagged/ \c COSE_Mac0_Tagged by default and
 * a \c COSE_Sign1/ \c COSE_Mac0 when this flag is set.
 * The only difference between these two is the CBOR tag.
 */
#define T_COSE_OPT_OMIT_CBOR_TAG 0x00000002


/**
 * Pass this as \c option_flags to allow verification of short-circuit
 * signatures. This should only be used as a test mode as
 * short-circuit signatures are not secure.
 *
 * See also \ref T_COSE_OPT_SHORT_CIRCUIT_SIG.
 */
#define T_COSE_OPT_ALLOW_SHORT_CIRCUIT 0x00000001


/**
 * The error \ref T_COSE_ERR_NO_KID is returned if the kid parameter
 * is missing. Note that the kid parameter is primarily passed on to
 * the crypto layer so the crypto layer can look up the key. If the
 * verification key is determined by other than the kid, then it is
 * fine if there is no kid.
 */
#define T_COSE_OPT_REQUIRE_KID 0x00000002


/**
 * Normally this will decode the CBOR presented as a \c COSE_Sign1
 * or a \c COSE_Mac0 message whether it is tagged using QCBOR tagging
 * as such or not.
 * If this option is set, then \ref T_COSE_ERR_INCORRECTLY_TAGGED is
 * returned if it is not tagged.
 */
#define T_COSE_OPT_TAG_REQUIRED  0x00000004


/**
 * This option disables cryptographic signature verification.  With
 * this option the \c verification_key is not needed.  This is useful
 * to decode the a COSE message to get the kid (key ID).  The
 * verification key can be looked up or otherwise obtained by the
 * caller. Once the key in in hand, the verification function can be
 * called again to perform the full verification.
 *
 * The payload will always be returned whether this is option is given
 * or not, but it should not be considered secure when this option is
 * given.
 *
 */
#define T_COSE_OPT_DECODE_ONLY  0x00000008

/**
 * \brief  Check whether an algorithm is supported.
 *
 * \param[in] cose_algorithm_id        COSE Integer algorithm ID.
 *
 * \returns \c true if algorithm is supported, \c false if not.
 *
 * Algorithms identifiers are from COSE algorithm registry:
 *   https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 *
 * A primary use for this is to determine whether or not to run a test case.
 * It is often unneccessary for regular use, because all the APIs will return
 * T_COSE_ERR_UNSUPPORTED_XXXX if the algorithm is not supported.
 */
bool
t_cose_is_algorithm_supported(int32_t cose_algorithm_id);

#ifdef __cplusplus
}
#endif


#endif /* __T_COSE_COMMON_H__ */
