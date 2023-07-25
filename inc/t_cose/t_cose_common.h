/*
 * t_cose_common.h
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2020-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef __T_COSE_COMMON_H__
#define __T_COSE_COMMON_H__

#include <stdint.h>
#include <stdbool.h>
#include "t_cose/q_useful_buf.h" /* For t_cose_key and t_cose_sign_inputs */


#ifdef __cplusplus
extern "C" {
#endif


/*
 * API Design Overview
 *
 * t_cose is made up of a collection of objects (in the
 * object-oriented programming sense) that correspond to the main
 * objects defined in CDDL by the COSE standard (RFC 9052). These
 * objects come in pairs, one for the sending/signing/encrypting
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
 * checked by actually designing and implementing it). These are not
 * needed for COSE_Mac0.
 *
 *
 * COSE_Message
 *
 * t_cose_message_create() and t_cose_message_decode handle
 * COSE_Message. This is for handling COSE messages that might be signed,
 * encrypted, MACed or some combination of these. In the simplest case
 * they decode the CBOR tag number and switch off to one of the
 * above handlers. In more complicated cases they recursively handle
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
 * all the methods above. It facilitates the general header
 * parameter implementation and allows for custom and specialized
 * headers.
 *
 *
 * COSE_signature
 *
 * t_cose_signature_sign and t_cose_signature_verify are abstract
 * bases classes for a set of implementations of COSE_Signature. This
 * design is chosen because there are a variety of signature schemes
 * to implement. Mostly these correspond to different signing
 * algorithms, but there is enough variation from algorithm to
 * algorithm that the use of an abstract base class here makes sense.
 *
 * Currently there is a "main" signer/verify that supports RSA
 * and ECDSA. There is another one for EdDSA, because it is
 * structurally different in not using a hash. Future
 * signer/verifiers might include one for counter signatures
 * and one for PQ.
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
 *
 * Notes on objects
 *
 * Note that this use object-orientation here gives some very nice
 * modularity and extensibility. New types of COSE_recipient can be
 * added to COSE_Encrypt and COSE_Mac without changing their
 * implementation at all. It is als *o possible to add new types of
 * recipients without even modifying the main t_cose library.
 *
 * This effectively gives dynamic linking for a lot of code that
 * makes dead-stripping by the linker more effective and requires
 * less use of #defines to reduce object code size. For example,
 * if a switch were used to select EdDSA, all the EdDSA code would
 * always be linked unless it was #ifdef'd out. With this design
 * not calling the EdDSA signer init function removes all reference
 * to EdDSA and it will be dead-stripped.
 *
 * This design should faciliate a lot of variance and innovation
 * in signers and encryptors, for example faciliating key
 * database look ups, use of certificates, counter signatures
 * and such, all without changing the source or even object
 * code of the core t_cose library.
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
 * \c T_COSE_DISABLE_PS256 -- Disables the COSE algorithm PS256
 * algorithm.
 *
 * \c T_COSE_DISABLE_PS384 -- Disables the COSE algorithm PS384
 * algorithm.
 *
 * \c T_COSE_DISABLE_PS512 -- Disables the COSE algorithm PS512
 * algorithm.
 *
 * \c T_COSE_DISABLE_CONTENT_TYPE -- Disables the content type
 * parameters for both signing and verifying.
 */


/**
 * This indicates this is t_cose 2.x, not 1.x. It should be forward compatible
 * with 1.x, but this is available in case it is not.
 */
#define T_COSE_2


/* Definition of algorithm IDs is moved to t_cose_standard_constants.h */


/* Definition of struct t_cose_key is moved to t_cose_key.h */


/**
 * The size of the output of SHA-256.
 *
 * (It is safe to define these independently here as they are
 * well-known and fixed. There is no need to reference
 * platform-specific headers and incur messy dependence.)
 */
#define T_COSE_CRYPTO_SHA256_SIZE 32

/**
 * The size of the output of SHA-384 in bytes.
 */
#define T_COSE_CRYPTO_SHA384_SIZE 48

/**
 * The size of the output of SHA-512 in bytes.
 */
#define T_COSE_CRYPTO_SHA512_SIZE 64

// TODO: this may not belong in common.h
enum t_cose_key_usage_flags {
    T_COSE_KEY_USAGE_FLAG_NONE = 0,
    T_COSE_KEY_USAGE_FLAG_DECRYPT = 1,
    T_COSE_KEY_USAGE_FLAG_ENCRYPT = 2
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
#define T_COSE_MAC0_MAX_SIZE_PROTECTED_PARAMETERS (1 + 1 + 5 + 9)

/* Six: an alg id, a kid, an iv, a content type, one custom, crit list */
#define T_COSE_NUM_VERIFY_DECODE_HEADERS 6


/**
 * Error codes return by t_cose.
 */
/*
 * Do not reorder these. It is OK to add new ones at the end.
 *
 * Explicit values are included because some tools like debuggers show
 * only the value, not the symbol, and it is hard to count up through
 * 50-plus lines to figure out the actual value.
 */
// TODO: renumber grouping unsupported algorithm errors together
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

    /** Signature verification or data authentication failed. For
     * example, the cryptographic operations completed successfully
     * but hash wasn't as expected. */
    T_COSE_ERR_SIG_VERIFY = 13,
    T_COSE_ERR_DATA_AUTH_FAILED = 13,

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

    /** More than \ref T_COSE_MAX_CRITICAL_PARAMS parameters
     * listed in the "crit" parameter. TODO: This is not just for crit params
     */
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

    /** The a struct t_cose_key is not set.  */
    T_COSE_ERR_EMPTY_KEY = 33,

    /** A header parameter occurs twice, perhaps once in protected and
     * once in unprotected. Duplicate header parameters are not
     * allowed in COSE.
     */
    T_COSE_ERR_DUPLICATE_PARAMETER = 34,

    /** A header parameter that should be protected (alg id or crit)
     * is not. This occurs when verifying, decrypting,.... */
    T_COSE_ERR_PARAMETER_NOT_PROTECTED = 35,

    /** Something is wrong with the crit parameter. It may be not well-formed,
     * invalid, have more than \ref T_COSE_MAX_CRITICAL_PARAMS values and
     * other. */
    T_COSE_ERR_CRIT_PARAMETER = 36,

    /** More than \ref T_COSE_MAX_TAGS_TO_RETURN unprocessed tags when
     * verifying a signature. */
    T_COSE_ERR_TOO_MANY_TAGS = 37,

    /** When decoding a header parameter that is not a string, integer or boolean
     * was encountered with no callback set handle it. See t_cose_ignore_param_cb()
     * and related. */
    T_COSE_ERR_UNHANDLED_HEADER_PARAMETER = 38,

    /** When encoding parameters, struct t_cose_header_parameter.parameter_type
     * is not a valid type.
     */
    T_COSE_ERR_INVALID_PARAMETER_TYPE = 39,

    /** Can't put critical parameters in the non-protected
     * header bucket per section 3.1 of RFC 9052. */
    T_COSE_ERR_CRIT_PARAMETER_IN_UNPROTECTED = 40,

    T_COSE_ERR_INSUFFICIENT_SPACE_FOR_PARAMETERS = 41,

    /* A header parameter with a string label occurred and there
     * is no support enabled for string labeled header parameters.
     */
    T_COSE_ERR_STRING_LABELED_PARAM = 42,

    /** No signers as in struct t_cose_signature_sign are  configured.
     */
    T_COSE_ERR_NO_SIGNERS = 43,

    /** More than one signer configured when signing a
     * COSE_Sign1 (multiple signers are OK for COSE_SIGN). */
    T_COSE_ERR_TOO_MANY_SIGNERS = 44,

    /** Mostly a verifier that is configured to look for kids
     * before it acts didn't match the kid in the message. */
    T_COSE_ERR_KID_UNMATCHED = 45,

    /** General CBOR decode error. */
    T_COSE_ERR_CBOR_DECODE = 46,

    /** A COSE_Signature contains unexected data or types. */
    T_COSE_ERR_SIGNATURE_FORMAT = 47,

    /**
     * When verifying a \c COSE_Mac0, something is wrong with the
     * format of the CBOR. For example, it is missing something like
     * the payload.
     */
    T_COSE_ERR_MAC0_FORMAT = 48,

    /** The requested content key distribution algorithm is not supported.  */
    T_COSE_ERR_UNSUPPORTED_CONTENT_KEY_DISTRIBUTION_ALG = 46,

    /** The requested encryption algorithm is not supported.  */
    T_COSE_ERR_UNSUPPORTED_ENCRYPTION_ALG = 47,

    /** The requested key length is not supported.  */
    T_COSE_ERR_UNSUPPORTED_KEY_LENGTH = 48,

    /** Adding a recipient to the COSE_Encrypt0 structure is not allowed.  */
    T_COSE_ERR_RECIPIENT_CANNOT_BE_ADDED = 49,

    /** The requested cipher algorithm is not supported.  */
    T_COSE_ERR_UNSUPPORTED_CIPHER_ALG = 50,

    /** Something went wrong in the crypto adaptor when
     * encrypting data. */
    T_COSE_ERR_ENCRYPT_FAIL = 51,

    /** Something went wrong in the crypto adaptor when
     * decrypting data. */
    T_COSE_ERR_DECRYPT_FAIL = 52,

    /** Something went wrong in the crypto adaptor when
     * invoking HPKE to encrypt data. */
    T_COSE_ERR_HPKE_ENCRYPT_FAIL = 53,

    /** Something went wrong in the crypto adaptor when
     * invoking HPKE to decrypt data. */
    T_COSE_ERR_HPKE_DECRYPT_FAIL = 54,

    /** When decoding a CBOR structure, a mandatory field
     *  was not found. */
    T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING = 55,

    /** When decoding the HPKE_sender_info structure, the included
     * information is either incorrect or of unexpected size. */
    T_COSE_ERR_HPKE_SENDER_INFO_INCORRECT = 56,

    /** Cryptographic operations may require a key usage flags
     * to be indicated. If the provided flags are unsupported,
     * this error is returned. */
    T_COSE_ERR_UNSUPPORTED_KEY_USAGE_FLAGS = 57,

    /** The private key import failed. */
    T_COSE_ERR_PRIVATE_KEY_IMPORT_FAILED = 58,

    /** Obtaining random bytes failed. */
    T_COSE_ERR_RNG_FAILED = 59,

    /** Export of the public key failed. */
    T_COSE_ERR_PUBLIC_KEY_EXPORT_FAILED = 60,

    /** Generating asymmetric key pair failed. */
    T_COSE_ERR_KEY_GENERATION_FAILED = 61,

    /** Export of the key failed. */
    T_COSE_ERR_KEY_EXPORT_FAILED = 62,

    /** Something went wrong with Key Wrap. */
    T_COSE_ERR_KW_FAILED = 63,
    /** The signature algorithm needs an extra buffer, but none was provided.
     * See \ref t_cose_sign1_verify_set_auxiliary_buffer for more details.
     */
    T_COSE_ERR_NEED_AUXILIARY_BUFFER = 64,

    /** The auxiliary buffer is too small */
    T_COSE_ERR_AUXILIARY_BUFFER_SIZE = 65,

    T_COSE_ERR_NO_VERIFIERS = 66,

    /* When \ref T_COSE_OPT_VERIFY_ALL_SIGNATURES is requested, one of the
     * signatures could not be verified because no verifier was configured
     * to handle it, typically because there was not verify for the algorithm.
     * Also returned by a verifier when it declines to verify a COSE_Signature for a reason other
     * than algorithm ID or kid. */
    T_COSE_ERR_DECLINE = 67,

    /* Trying to protect a parameter when not possible, for example,
     * in an AES Keywrap COSE_Recipient. */
    T_CODE_ERR_PROTECTED_PARAM_NOT_ALLOWED = 68,

    T_COSE_ERR_RECIPIENT_FORMAT = 69,

    /* No more COSE_Signatures or COSE_Recipients. Returned by
     * COSE_Signature and COSE_Recipient implementations. */
    T_COSE_ERR_NO_MORE = 70,

    /* A newer version of QCBOR is needed to processes multiple
     * COSE_Signature or COSE_Recipients.  (As of Jan 2023, this
     * QCBOR is not released) */
    T_COSE_ERR_CANT_PROCESS_MULTIPLE = 71,

    /** The specific elliptic curve is not supported.  */
    T_COSE_ERR_UNSUPPORTED_ELLIPTIC_CURVE_ALG = 72,

    /** The public key import failed. */
    T_COSE_ERR_PUBLIC_KEY_IMPORT_FAILED = 73,

    /** The symmetric key import failed. */
    T_COSE_ERR_SYMMETRIC_KEY_IMPORT_FAILED = 74,

    /** The specific KEM is not supported.  */
    T_COSE_ERR_UNSUPPORTED_KEM_ALG = 75,

    /** HKDF failed. */
    T_COSE_ERR_HKDF_FAIL = 76,

    /** The length of an input is invalid. In particular, this occurs with the OpenSSL crypto
     * adaptor when a size greater than MAX_INT is given because OpenSSL
     * input lengths are type int rather than size_t. */
    T_COSE_ERR_INVALID_LENGTH = 77,

    /** The HMAC algorithm is not supported.  */
    T_COSE_ERR_UNSUPPORTED_HMAC_ALG = 78,

    /** The HMAC algorithm is not supported.  */
    T_COSE_ERR_HMAC_GENERAL_FAIL = 79,

    /** The HMAC did not successfully verify.  */
    T_COSE_ERR_HMAC_VERIFY = 80,

    /** The key agreement failed.  */
    T_COSE_ERR_KEY_AGREEMENT_FAIL = 81,

    /** General unsupported operation failure. */
    T_COSE_ERR_UNSUPPORTED = 82,

    /* A signing operation is in progress. The function returning this value
     * can be called again until it returns \ref T_COSE_SUCCESS or error.
     */
    T_COSE_ERR_SIG_IN_PROGRESS = 83,

    /* A T_COSE_OPT_XXX is invalid in some way. */
    T_COSE_ERR_BAD_OPT = 84,

    T_COSE_ERR_CANT_DETERMINE_MESSAGE_TYPE = 85,

    T_COSE_ERR_WRONG_COSE_MESSAGE_TYPE = 86,

    T_COSE_ERR_KDF_BUFFER_TOO_SMALL = 87,

    /* Probably need to set a KDF context info buffer
     * to be larger because there are too many protected
     * headers, party u/v identities were added or
     * supp info was added. TODO: see xxxx*/
    T_COSE_ERR_KDF_CONTEXT_SIZE = 88
};


/**
 * TODO: this may not be implmented correctly yet
 *
 * In this tag decoding mode, there must be a tag number present in
 * the input CBOR. That tag number solely determines the COSE message
 * type that decoding expects.
 *
 * It is an error if there is no tag number.
 *
 * If a message type option like \ref T_COSE_OPT_MESSAGE_TYPE_SIGN is
 * set in the options, it is ignored.
 *
 * If there are nested tags, the inner most tag number, the one
 * closest to the array item (all COSE messages are arrays) is used.
 *
 * See also \ref T_COSE_OPT_TAG_PROHIBITED for another tag decoding
 * mode.
 *
 * If neither this or \ref T_COSE_OPT_TAG_PROHIBITED is set then the
 * message type will be determined by either the tag or or message
 * type option like \ref T_COSE_OPT_MESSAGE_TYPE_SIGN.  If neither are
 * available, then it is an error as the message type can't be
 * determined. If both are set, then the message type option overrules
 * the tag number. This is the default, but it is discouraged by
 * the CBOR standard as it is a bit ambigous and protocol definitions
 * should clearly state which they use. It is left as the default
 * here in t_cose because it will usually work out of the box.
 *
 * See t_cose_sign1_get_nth_tag() to get further tags that enclose
 * the COSE message.
 */
#define T_COSE_OPT_TAG_REQUIRED  0x00000100


/**
 * TODO: this may not be implmented correctly yet
 *
 * In this tag decoding mode, there must be no tag number present in
 * the input CBOR.  Message type options like \ref
 * T_COSE_OPT_MESSAGE_TYPE_SIGN are solely relied on.
 *
 * If a tag number is present, then \ref T_COSE_ERR_INCORRECTLY_TAGGED
 * is returned.
 *
 * If no Message type options like \ref T_COSE_OPT_MESSAGE_TYPE_SIGN
 * is set the TODO error is returned.
 *
 * See discussion on @ref T_COSE_OPT_TAG_REQUIRED.
 */
#define T_COSE_OPT_TAG_PROHIBITED  0x00000200


/**
 * An \c option_flag to not add the CBOR type 6 tag number when
 * encoding a COSE message.  Some uses of COSE may require this tag
 * number be absent because its COSE message type is known from
 * surrounding context.
 *
 * Or said another way \c COSE_Xxxx_Tagged message is produced by
 * default and a \c COSE_Xxxx is produced when this flag is set (where
 * COSE_Xxxx is COSE_Sign, COSE_Mac0, ... as specified in CDDL in RFC
 * 9052).  The only difference is the presence of the CBOR tag number.
 */
#define T_COSE_OPT_OMIT_CBOR_TAG 0x00000400


/**
 * When verifying or signing a COSE message, cryptographic operations
 * like verification and decryption will not be performed. Keys needed
 * for these operations are not needed. This is useful to decode a
 * COSE message to get the header parameter(s) to lookup/find/identify
 * the required key(s) (e.g., the kid parameter).  Then the key(s)
 * are/is configured and the message is decoded again without this
 * option.
 *
 * Note that anything returned (parameters, payload) will not have
 * been verified and should be considered untrusted.
 */
#define T_COSE_OPT_DECODE_ONLY  0x00000800


/**
 * Functions like t_cose_sign_verify() and t_cose_encrypt_dec() will
 * error out with \ref T_COSE_ERR_UNKNOWN_CRITICAL_PARAMETER if there
 * are any critical header parameters. Since the header parameters for
 * verification, decryption and similar are all standard, don't need
 * to be marked critical and understood by this implementation, this
 * error is not returned.
 *
 * This option turns off the check for critical parameters for use
 * cases that use them. In that case the caller of t_cose takes
 * responsibility for checking all the parameters decoded to be sure
 * there are no critical parameters that are not understood.
 */
#define T_COSE_OPT_NO_CRIT_PARAM_CHECK  0x00001000


/**
 * The maximum number of unprocessed tags that can be returned by
 * t_cose_xxx_get_nth_tag(). The CWT
 * tag is an example of the tags that might returned. The COSE tags
 * that are processed, don't count here.
 */
#define T_COSE_MAX_TAGS_TO_RETURN 4



/* The lower 8 bits of the options give the type of the
 * COSE message to decode.
 * TODO: this may not be implmented correctly yet
 */
#define T_COSE_OPT_MESSAGE_TYPE_MASK 0x000000ff

/* The following are possble values for the lower 8 bits
 * of option_flags. They are used to indicated what
 * type of messsage to output and what type of message
 * to expect when decoding and the tag number is
 * absent or being overriden. */
#define T_COSE_OPT_MESSAGE_TYPE_UNSPECIFIED 00
#define T_COSE_OPT_MESSAGE_TYPE_SIGN        98
#define T_COSE_OPT_MESSAGE_TYPE_SIGN1       18
#define T_COSE_OPT_MESSAGE_TYPE_ENCRYPT     96
#define T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0    16
#define T_COSE_OPT_MESSAGE_TYPE_MAC         97
#define T_COSE_OPT_MESSAGE_TYPE_MAC0        17

// TODO: get rid of this
#define T_COSE_OPT_IS_SIGN1(opts) \
   ((T_COSE_OPT_MESSAGE_TYPE_MASK & opts) == T_COSE_OPT_MESSAGE_TYPE_SIGN1)

/* Not expecting any more. */


/* Default size allowed for Enc_structure for COSE_Encrypt and COSE_Encrypt0.
 * If there are a lot or header parameters or AAD passed in is large,
 * this may not be big enough and error TODO will be returned. Call
 * TODO to give a bigger buffer.*/
#define T_COSE_ENCRYPT_STRUCT_DEFAULT_SIZE 64

/**
 * The error \ref T_COSE_ERR_NO_KID is returned if the kid parameter
 * is missing. Note that the kid parameter is primarily passed on to
 * the crypto layer so the crypto layer can look up the key. If the
 * verification key is determined by other than the kid, then it is
 * fine if there is no kid.
 */
#define T_COSE_OPT_REQUIRE_KID 0x00001000


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


/* Structure that holds all the inputs for signing that is
 * used in a few places (so it ends up in t_cose_common.h).
 * It is public because it is part of the signer/verify
 * call back interface. It is also used for MAC.
 *
 * These are the inputs to create a Sig_structure
 * from section 4.4 in RFC 9052.
 *
 * aad and sign_protected may be \ref NULL_Q_USEFUL_BUF_C.
 *
 * payload is a CBOR encoded byte string that may
 * contain CBOR or other.
 *
 * body_protected are the byte-string wrapped protected
 * header parameters from the COSE_Sign or COSE_Sign1.
 */
struct t_cose_sign_inputs {
    struct q_useful_buf_c  body_protected;
    struct q_useful_buf_c  aad;
    struct q_useful_buf_c  sign_protected;
    struct q_useful_buf_c  payload;
};




/* A COSE algorithm ID and the number of bits for the key. Typically,
 * the number of bits in the key is known from the alg ID, but not
 * always. This structure is typically used to give input for
 * the construction of COSE_KDF_Context.
 *
 * alg_bits should be size_t to be completely type-consistent,
 * but that would push the size of this structure over an
 * an alignment boundary and double its size.
 */
struct t_cose_alg_and_bits {
    int32_t   cose_alg_id;
    uint32_t  bits_in_key;
};




/* This is the base class for all implementations
 * of COSE_Signature and COSE_Recipient. It implments what
 * is common to them:
 *   - The ability to identify the type of one
 *   - The ability to make a linked list
 *
 * The linked list part saves object code because the same
 * function to add to the linked list is used for all types
 * of COSE_Recipient and COSE_Signature
 *
 * The identification part is to know the type of a concrete
 * instance to be able to call some special methods it
 * might implement, particularly for COSE_Signature verifiers
 * and COSE_Recipient decryptors as the COSE_Sign verifier
 * and COSE_Encrypt decryptor loops over a set of them.
 */
struct t_cose_rs_obj {
    struct t_cose_rs_obj *next;
    uint16_t              ident;
};


void
t_cose_link_rs(struct t_cose_rs_obj **list, struct t_cose_rs_obj *new_rs);


/* This is just to make a simple 16 bit unique id for each recipient-signer object */
#define TYPE_RS_SIGNER 's'
#define TYPE_RS_VERIFIER 'v'
#define TYPE_RS_RECIPIENT_CREATOR 'c'
#define TYPE_RS_RECIPIENT_DECODER 'd'
#define RS_IDENT(type, id1) (type + (id1 << 8))



#ifdef __cplusplus
}
#endif


#endif /* __T_COSE_COMMON_H__ */
