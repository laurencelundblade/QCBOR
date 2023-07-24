/*
 * t_cose_crypto.h
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2020-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef __T_COSE_CRYPTO_H__
#define __T_COSE_CRYPTO_H__

#include <stdint.h>
#include <stdbool.h>
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_key.h"


#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif



/**
 * \file t_cose_crypto.h
 *
 * \brief This defines the adaptation layer for cryptographic
 * functions needed by t_cose.
 *
 * This is  small wrapper around the cryptographic functions to:
 * - Map COSE algorithm IDs to cryptographic library IDs
 * - Map cryptographic library errors to \ref t_cose_err_t errors
 * - Have inputs and outputs be \c struct \c q_useful_buf_c and
 *   \c struct \c q_useful_buf
 * - Handle key selection
 *
 * An implementation must be made of these functions
 * for the various cryptographic libraries that are used on
 * various platforms and OSs. The functions are:
 *   - t_cose_t_crypto_sig_size()
 *   - t_cose_crypto_pub_key_sign()
 *   - t_cose_crypto_pub_key_verify()
 *   - t_cose_crypto_hash_start()
 *   - t_cose_crypto_hash_update()
 *   - t_cose_crypto_hash_finish()
 *
 * This runs entirely off of COSE-style algorithm identifiers.  They
 * are simple integers and thus work nice as function parameters. An
 * initial set is defined by [COSE (RFC 8152)]
 * (https://tools.ietf.org/html/rfc8152). New ones can be registered
 * in the [IANA COSE Registry]
 * (https://www.iana.org/assignments/cose/cose.xhtml). Local use new
 * ones can also be defined (\c \#define) if what is needed is not in
 * the IANA registry.
 *
 * \anchor useful_buf_use
 * Binary data is returned to the caller using a \c struct \c
 * q_useful_buf to pass the buffer to receive the data and its length in
 * and a \c q_useful_buf_c to return the pointer and length of the
 * returned data. The point of this is coding hygiene. The buffer
 * passed in is not const as it is to be modified.  The \c
 * q_useful_buf_c returned is const. The lengths of buffers are
 * handled in a clear, consistent and enforced manner.
 *
 * The pointer in the \c q_useful_buf_c will always point to the
 * buffer passed in via the \c q_useful_buf so the lifetime of the
 * data is under control of the caller.
 *
 * This is not intended as any sort of general cryptographic API. It
 * is just the functions needed by t_cose in the form that is most
 * useful for t_cose.
 *
 * No other file in t_cose should need modification for new algorithms,
 * new key types and sizes or the integration of cryptographic libraries
 * except on some occasions, this file as follows:
 *
 * - Support for a new T_COSE_ALGORITHM_XXX signature algorithm
 *    - See t_cose_algorithm_is_ecdsa()
 *    - If not ECDSA add another function like t_cose_algorithm_is_ecdsa()
 * - Support another hash implementation that is not a service
 *    - See struct \ref t_cose_crypto_hash
 *
 * To reduce stack usage and save a little code these can be defined.
 *    - T_COSE_DISABLE_ES384
 *    - T_COSE_DISABLE_ES512
 *
 * The actual code that implements these hashes in the crypto library may
 * or may not be saved with these defines depending on how the library
 * works, whether dead stripping of object code is on and such.
 */




/** Helper macro to convert bits to bytes */
#define T_COSE_BITS_TO_BYTES(bits) (((bits) + 7) / 8)

/** Constant for maximum ECC curve size in bits */
#define T_COSE_ECC_MAX_CURVE_BITS 521

/** Export of EC key in SEC1 uncompressed format */
#define T_COSE_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits)                         \
    (2 * T_COSE_BITS_TO_BYTES(key_bits) + 1)

/** Wrapper for T_COSE_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE() */
#define T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE                                       \
    (T_COSE_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(T_COSE_ECC_MAX_CURVE_BITS))

/** Helper macro to round up to a multiple */
#define T_COSE_ROUND_UP_TO_MULTIPLE(block_size, length) \
    (((length) + (block_size) - 1) / (block_size) * (block_size))

/** The maximum size of a block cipher. */
#define T_COSE_BLOCK_CIPHER_BLOCK_MAX_SIZE 16

/** The maximum IV size for all supported cipher algorithms, in bytes. */
#define T_COSE_CIPHER_IV_MAX_SIZE 16

/** Macro to compute the maximum output size of a cipher */
#define T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(input_length)                     \
    (T_COSE_ROUND_UP_TO_MULTIPLE(T_COSE_BLOCK_CIPHER_BLOCK_MAX_SIZE,            \
                              (input_length) + 1) +                             \
     T_COSE_CIPHER_IV_MAX_SIZE)

/** The maximum output size of the symmetric produced by a key agreement algorithm, in bytes.
 *  If we support an ECC curve with 521 bits, then the value below must be set to 66 bytes
 *  because ceil( 521 / 8 ) = 66 bytes.
 */
#define T_COSE_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE 66

#define T_COSE_EC_P256_SIG_SIZE 64  /* size for secp256r1 */
#define T_COSE_EC_P384_SIG_SIZE 96  /* size for secp384r1 */
#define T_COSE_EC_P512_SIG_SIZE 132 /* size for secp521r1 */


/**
 * There is a stack variable to hold the output of the signing
 * operation.  This sets the maximum signature size this code can
 * handle based on the COSE algorithms configured. The size of the
 * signature goes with the size of the key, not the algorithm, so a
 * key could be given for signing or verification that is larger than
 * this. However, it is not typical to do so. If the key or signature
 * is too large the failure will be graceful with an error.
 *
 * For ECDSA the signature format used is defined in RFC 8152 section
 * 8.1. It is the concatenation of r and s, each of which is the key
 * size in bits rounded up to the nearest byte.  That is twice the key
 * size in bytes.
 *
 * RSA signatures are typically much larger than this, but do not need
 * to be stored on the stack, since the COSE format is the same as the
 * one OpenSSL understands natively. The stack variable therefore does
 * not need to be made large enough to fit these signatures.
 */
#ifndef T_COSE_DISABLE_ES512
    #define T_COSE_MAX_ECDSA_SIG_SIZE T_COSE_EC_P512_SIG_SIZE
#else
    #ifndef T_COSE_DISABLE_ES384
        #define T_COSE_MAX_ECDSA_SIG_SIZE T_COSE_EC_P384_SIG_SIZE
    #else
        #define T_COSE_MAX_ECDSA_SIG_SIZE T_COSE_EC_P256_SIG_SIZE
    #endif
#endif



/*
 * Says where a particular algorithm is supported or not.
 * Most useful for test code that wants to know if a
 * test should be attempted or not.
 *
 * See t_cose_is_algorithm_supported()
 */
bool t_cose_crypto_is_algorithm_supported(int32_t cose_algorithm_id);

/**
 * \brief Returns the size of a signature given the key and algorithm.
 *
 * \param[in] cose_algorithm_id  The algorithm ID
 * \param[in] signing_key        Key to compute size of
 * \param[out] sig_size          The returned size in bytes.
 *
 * \return An error code or \ref T_COSE_SUCCESS.
 *
 * This is used the caller wishes to compute the size of a token in
 * order to allocate memory for it.
 *
 * The size of a signature depends primarily on the key size but it is
 * usually necessary to know the algorithm too.
 *
 * This always returns the exact size of the signature.
 */
enum t_cose_err_t
t_cose_crypto_sig_size(int32_t            cose_algorithm_id,
                       struct t_cose_key  signing_key,
                       size_t            *sig_size);


/**
 * \brief Perform public key signing. Part of the t_cose crypto
 * adaptation layer.
 *
 * \param[in] cose_algorithm_id The algorithm to sign with. The IDs are
 *                              defined in [COSE (RFC 8152)]
 *                              (https://tools.ietf.org/html/rfc8152) or
 *                              in the [IANA COSE Registry]
 *                              (https://www.iana.org/assignments/cose/cose.xhtml).
 *                              A proprietary ID can also be defined
 *                              locally (\c \#define) if the needed
 *                              one hasn't been registered.
 * \param[in] signing_key       Indicates or contains key to sign with.
 * \param[in] crypto_context       Pointer to adaptor-specific context. May be NULL.
 * \param[in] hash_to_sign      The bytes to sign. Typically, a hash of
 *                              a payload.
 * \param[in] signature_buffer  Pointer and length of buffer into which
 *                              the resulting signature is put.
 * \param[in] signature         Pointer and length of the signature
 *                              returned.
 *
 * \retval T_COSE_SUCCESS
 *         Successfully created the signature.
 * \retval T_COSE_ERR_SIG_BUFFER_SIZE
 *         The \c signature_buffer too small.
 * \retval T_COSE_ERR_UNSUPPORTED_SIGNING_ALG
 *         The requested signing algorithm, \c cose_algorithm_id, is not
 *         supported.
 * \retval T_COSE_ERR_UNKNOWN_KEY
 *         The key identified by \c key_select was not found.
 * \retval T_COSE_ERR_WRONG_TYPE_OF_KEY
 *         The key was found, but it was the wrong type.
 * \retval T_COSE_ERR_INVALID_ARGUMENT
 *         Some (unspecified) argument was not valid.
 * \retval T_COSE_ERR_INSUFFICIENT_MEMORY
 *         Insufficient heap memory.
 * \retval T_COSE_ERR_FAIL
 *         General unspecific failure.
 * \retval T_COSE_ERR_TAMPERING_DETECTED
 *         Equivalent to \c PSA_ERROR_CORRUPTION_DETECTED.
 *
 * This is called to do public key signing. The implementation will
 * vary from one platform / OS to another but should conform to the
 * description here.
 *
 * The contents of signing_key is usually the type that holds
 * a key for the cryptographic library.
 *
 * See the note in the Detailed Description (the \\file comment block)
 * for details on how \c q_useful_buf and \c q_useful_buf_c are used
 * to return the signature.
 *
 * The \c crypto_context is a pointer that's passed in from the public
 * t_cose interface all the way down to the crypto adaptor. It allows the
 * user of t_cose to manipulate the how the crypto is called in some cases.
 * Each crypto adapter that supports this must provide a definition of the
 * structure of what is pointed to by the crypto context and users of this
 * must be aware that what they are using is specific to one crypto
 * adatpor.
 */
enum t_cose_err_t
t_cose_crypto_sign(int32_t                cose_algorithm_id,
                   struct t_cose_key      signing_key,
                   void                  *crypto_context,
                   struct q_useful_buf_c  hash_to_sign,
                   struct q_useful_buf    signature_buffer,
                   struct q_useful_buf_c *signature);


/**
 * \brief Perform public key signing in a restartable manner. Part of the t_cose
 * crypto adaptation layer.
 *
 * \param[in] started           If false, then this is the first call of a
 *                              signing operation. If it is true, this is a
 *                              subsequent call.
 *
 * \retval T_COSE_ERR_SIG_IN_PROGRESS
 *         Signing is in progress, the function needs to be called again with
 *         the same parameters.
 *
 * For other parameters and possible return values and general description see
 * t_cose_crypto_sign.
 *
 * To complete a signing operation this function needs to be called multiple
 * times. For a signing operation the first call to this function must happen
 * with \c started == false, and all subsequent calls for this signing operation
 * must happen with \c started == true. When the return value is
 * \c T_COSE_ERR_SIG_IN_PROGRESS the data in the output parameters is undefined.
 * The function must be called again (and again...) until \c T_COSE_SUCCESS or
 * an error is returned.
 *
 * Note that this function is only implemented if the crypto adapter supports
 * restartable operation, and even in that case it might not be available for
 * all algorithms.
 */
enum t_cose_err_t
t_cose_crypto_sign_restart(bool                   started,
                           int32_t                cose_algorithm_id,
                           struct t_cose_key      signing_key,
                           void                  *crypto_context,
                           struct q_useful_buf_c  hash_to_sign,
                           struct q_useful_buf    signature_buffer,
                           struct q_useful_buf_c *signature);


/**
 * \brief Perform public key signature verification. Part of the
 * t_cose crypto adaptation layer.
 *
 * \param[in] cose_algorithm_id The algorithm to use for verification.
 *                              The IDs are defined in [COSE (RFC 8152)]
 *                              (https://tools.ietf.org/html/rfc8152)
 *                              or in the [IANA COSE Registry]
 *                       (https://www.iana.org/assignments/cose/cose.xhtml).
 *                              A proprietary ID can also be defined
 *                              locally (\c \#define) if the needed one
 *                              hasn't been registered.
 * \param[in] verification_key  The verification key to use.
 * \param[in] crypto_context       Pointer to adaptor-specific context. May be NULL.
 * \param[in] hash_to_verify    The hash of the data that is to be verified.
 * \param[in] signature         The COSE-format signature.
 *
 * This verifies that the \c signature passed in was over the \c
 * hash_to_verify passed in.
 *
 * The key selected must be, or include, a public key of the correct
 * type for \c cose_algorithm_id.
 *
 * See the discussion for the crypto_context in t_cose_crypto_sign(). It applies also
 * here.
 *
 * \retval T_COSE_SUCCESS
 *         The signature is valid
 * \retval T_COSE_ERR_SIG_VERIFY
 *         Signature verification failed. For example, the
 *         cryptographic operations completed successfully but hash
 *         wasn't as expected.
 * \retval T_COSE_ERR_WRONG_TYPE_OF_KEY
 *         The key was found, but it was the wrong type
 *         for the operation.
 * \retval T_COSE_ERR_UNSUPPORTED_SIGNING_ALG
 *         The requested signing algorithm is not supported.
 * \retval T_COSE_ERR_INVALID_ARGUMENT
 *         Some (unspecified) argument was not valid.
 * \retval T_COSE_ERR_INSUFFICIENT_MEMORY
 *         Out of heap memory.
 * \retval T_COSE_ERR_FAIL
 *         General unspecific failure.
 * \retval T_COSE_ERR_TAMPERING_DETECTED
 *         Equivalent to \c PSA_ERROR_CORRUPTION_DETECTED.
 */
enum t_cose_err_t
t_cose_crypto_verify(int32_t               cose_algorithm_id,
                     struct t_cose_key     verification_key,
                     void                  *crypto_context,
                     struct q_useful_buf_c hash_to_verify,
                     struct q_useful_buf_c signature);


/**
 * \brief Perform public key signing for EdDSA.
 *
 * The EdDSA signing algorithm (or more precisely its PureEdDSA
 * variant, used in COSE) requires two passes over the input data.
 * This requires the whole to-be-signed structure to be held in
 * memory and given as an argument to this function, rather than
 * an incrementally computed hash.
 *
 * \param[in] signing_key       Indicates or contains key to sign with.
 * \param[in] tbs               The bytes to sign.
 * \param[in] signature_buffer  Pointer and length of buffer into which
 *                              the resulting signature is put.
 * \param[in] signature         Pointer and length of the signature
 *                              returned.
 *
 * \retval T_COSE_SUCCESS
 *         Successfully created the signature.
 * \retval T_COSE_ERR_SIG_BUFFER_SIZE
 *         The \c signature_buffer too small.
 * \retval T_COSE_ERR_UNSUPPORTED_SIGNING_ALG
 *         EdDSA signatures are not supported.
 * \retval T_COSE_ERR_UNKNOWN_KEY
 *         The key identified by \c key_select was not found.
 * \retval T_COSE_ERR_WRONG_TYPE_OF_KEY
 *         The key was found, but it was the wrong type.
 * \retval T_COSE_ERR_INVALID_ARGUMENT
 *         Some (unspecified) argument was not valid.
 * \retval T_COSE_ERR_INSUFFICIENT_MEMORY
 *         Insufficient heap memory.
 * \retval T_COSE_ERR_FAIL
 *         General unspecific failure.
 * \retval T_COSE_ERR_TAMPERING_DETECTED
 *         Equivalent to \c PSA_ERROR_CORRUPTION_DETECTED.
 *
 * This is called to do public key signing. The implementation will
 * vary from one platform / OS to another but should conform to the
 * description here.
 *
 * The contents of signing_key is usually the type that holds
 * a key for the cryptographic library.
 *
 * See the note in the Detailed Description (the \\file comment block)
 * for details on how \c q_useful_buf and \c q_useful_buf_c are used
 * to return the signature.
 *
 */
enum t_cose_err_t
t_cose_crypto_sign_eddsa(struct t_cose_key      signing_key,
                         void                  *crypto_context,
                         struct q_useful_buf_c  tbs,
                         struct q_useful_buf    signature_buffer,
                         struct q_useful_buf_c *signature);

/**
 * \brief Perform public key signature verification for EdDSA.
 *
 * The EdDSA signing algorithm (or more precisely its PureEdDSA
 * variant, used in COSE) requires two passes over the input data.
 * This requires the whole to-be-signed structure to be held in
 * memory and given as an argument to this function, rather than
 * an incrementally computed hash.
 *
 * \param[in] verification_key  The verification key to use.
 * \param[in] tbs               The data to be verified.
 * \param[in] signature         The COSE-format signature.
 *
 * The key selected must be of the correct type for EdDSA
 * signatures.
 *
 * \retval T_COSE_SUCCESS
 *         The signature is valid
 * \retval T_COSE_ERR_SIG_VERIFY
 *         Signature verification failed. For example, the
 *         cryptographic operations completed successfully but hash
 *         wasn't as expected.
 * \retval T_COSE_ERR_WRONG_TYPE_OF_KEY
 *         The key was found, but it was the wrong type
 *         for the operation.
 * \retval T_COSE_ERR_UNSUPPORTED_SIGNING_ALG
 *         EdDSA signatures are not supported.
 * \retval T_COSE_ERR_INVALID_ARGUMENT
 *         Some (unspecified) argument was not valid.
 * \retval T_COSE_ERR_INSUFFICIENT_MEMORY
 *         Out of heap memory.
 * \retval T_COSE_ERR_FAIL
 *         General unspecific failure.
 * \retval T_COSE_ERR_TAMPERING_DETECTED
 *         Equivalent to \c PSA_ERROR_CORRUPTION_DETECTED.
 */
enum t_cose_err_t
t_cose_crypto_verify_eddsa(struct t_cose_key     verification_key,
                           void                  *crypto_context,
                           struct q_useful_buf_c tbs,
                           struct q_useful_buf_c signature);


#ifdef T_COSE_USE_PSA_CRYPTO
#include "psa/crypto.h"

#elif T_COSE_USE_OPENSSL_CRYPTO
#include "openssl/evp.h"

#elif T_COSE_USE_B_CON_SHA256
/* This is code for use with Brad Conte's crypto.  See
 * https://github.com/B-Con/crypto-algorithms and see the description
 * of t_cose_crypto_hash
 */
#include "sha256.h"
#endif


/**
 * The context for use with the hash adaptation layer here.
 *
 * Hash implementations for this porting layer are put into two
 * different categories.
 *
 * The first can be supported generically without any dependency on
 * the actual hash implementation in this header. These only need a
 * pointer or handle for the hash context.  Usually these are
 * implemented by a service, system API or crypto HW that runs in a
 * separate context or process. They probably allocate memory
 * internally. These can use context.ptr or context.handle to hold the
 * pointer or handle to the hash context.
 *
 * The second sort of hash implementations need more than just a
 * pointer or handle. Typically these are libraries that are linked
 * with this code and run in the same process / context / thread as
 * this code. These can be efficient requiring no context switches or
 * memory allocations. These type require this header be modified for
 * the #include which defines the hash context and so this struct
 * includes that context as a member. This context is allocated on the
 * stack, so any members added here should be small enough to go on
 * the stack. USE_B_CON_SHA256 is an example of this type.
 *
 * The actual implementation of the hash is in a separate .c file
 * that will be specific to the particular platform, library,
 * service or such used.
 */
struct t_cose_crypto_hash {

    #ifdef T_COSE_USE_PSA_CRYPTO
        /* --- The context for PSA Crypto (MBed Crypto) --- */

        /* psa_hash_operation_t actually varied by the implementation of
         * the crypto library. Sometimes the implementation is inline and
         * thus the context is a few hundred bytes, sometimes it is not.
         * This varies by what is in crypto_struct.h (which is not quite
         * a public interface).
         *
         * This can be made smaller for PSA implementations that work inline
         * by disabling the larger algorithms using PSA / MBed configuration.
         */
        psa_hash_operation_t ctx;
        psa_status_t         status;

    #elif T_COSE_USE_OPENSSL_CRYPTO
        /* --- The context for OpenSSL crypto --- */
        EVP_MD_CTX  *evp_ctx;
        int          update_error; /* Used to track error return by SHAXXX_Update() */

   #elif T_COSE_USE_B_CON_SHA256
        /* --- Specific context for Brad Conte's sha256.c --- */
        SHA256_CTX b_con_hash_context;

   #else
    /* --- Default: generic pointer / handle --- */

        union {
            void    *ptr;
            uint64_t handle;
        } context;
        int64_t status;
   #endif

};

/**
 * The context for use with the HMAC adaptation layer here.
 * Borrow the structure of t_cose_crypto_hash.
 */
struct t_cose_crypto_hmac {
    #ifdef T_COSE_USE_PSA_CRYPTO
        /* --- The context for PSA Crypto (MBed Crypto) --- */
        psa_mac_operation_t op_ctx;

    #elif T_COSE_USE_OPENSSL_CRYPTO
        /* --- The context for OpenSSL crypto --- */
        EVP_MD_CTX  *evp_ctx;
        EVP_PKEY    *evp_pkey;

    #else
        /* --- Default: generic pointer / handle --- */
        union {
            void    *ptr;
            uint64_t handle;
        } context;
        int64_t status;
    #endif
};

/**
 * Size of the signature (tag) output for the HMAC-SHA256.
 */
#define T_COSE_CRYPTO_HMAC256_TAG_SIZE   T_COSE_CRYPTO_SHA256_SIZE

/**
 * Size of the signature (tag) output for the HMAC-SHA384.
 */
#define T_COSE_CRYPTO_HMAC384_TAG_SIZE   T_COSE_CRYPTO_SHA384_SIZE

/**
 * Size of the signature (tag) output for the HMAC-SHA512.
 */
#define T_COSE_CRYPTO_HMAC512_TAG_SIZE   T_COSE_CRYPTO_SHA512_SIZE

/**
 * Max size of the tag output for the HMAC operations. This works up to SHA3-512.
 */
/* TODO: should this vary with T_COSE_CRYPTO_MAX_HASH_SIZE? */
#define T_COSE_CRYPTO_HMAC_TAG_MAX_SIZE  T_COSE_CRYPTO_SHA512_SIZE

/**
 * Maximum size of the hash output
 */
#define T_COSE_CRYPTO_MAX_HASH_SIZE T_COSE_CRYPTO_SHA512_SIZE

/**
 * Max size of an HMAC key. RFC 2160 which says the key should be the block size of the hash
 * function used and that a longer key is allowed, but doesn't increase security. The block size
 * of SHA-512 is 1024 bits and of SHA3-224 is 1152. This constant is for internal buffers
 * holding a key. It is set at 200, far above what is needed to be generous and because
 * 200 bytes isn't very much. */
#define T_COSE_CRYPTO_HMAC_MAX_KEY 200


/**
 * \brief Start cryptographic hash. Part of the t_cose crypto
 * adaptation layer.
 *
 * \param[in,out] hash_ctx      Pointer to the hash context that
 *                              will be initialized.
 * \param[in] cose_hash_alg_id  Algorithm ID that identifies the
 *                              hash to use. This is from the
 *                              [IANA COSE Registry]
 *                          (https://www.iana.org/assignments/cose/cose.xhtml)
 *
 * \retval T_COSE_ERR_UNSUPPORTED_HASH
 *         The requested algorithm is unknown or unsupported.
 *
 * \retval T_COSE_ERR_HASH_GENERAL_FAIL
 *         Some general failure of the hash function
 *
 * \retval T_COSE_SUCCESS
 *         Success.
 *
 * This initializes the hash context for the particular algorithm. It
 * must be called first. A \c hash_ctx can be reused if it is
 * reinitialized.
 *
 * \ref T_COSE_INVALID_ALGORITHM_ID may be passed to this function, in which
 * case \ref T_COSE_ERR_UNSUPPORTED_HASH must be returned.
 *
 * Other errors can be returned and will usually be propagated up, but hashes
 * generally don't fail so it is suggested not to bother (and to reduce
 * object code size for mapping errors).
 */
enum t_cose_err_t
t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                         int32_t                    cose_hash_alg_id);


/**
 * \brief Feed data into a cryptographic hash. Part of the t_cose
 * crypto adaptation layer.
 *
 * \param[in,out] hash_ctx  Pointer to the hash context in which
 *                          accumulate the hash.
 * \param[in]  data_to_hash Pointer and length of data to feed into
 *                          hash. The pointer may by \c NULL in which
 *                          case no hashing is performed.
 *
 * There is no return value. If an error occurs it is remembered in \c
 * hash_ctx and returned when t_cose_crypto_hash_finish() is called.
 * Once in the error state, this function may be called, but it will
 * not do anything.
 *
 * This function can be called with \c data_to_hash.ptr NULL and it
 * will pretend to hash. This allows the same code that is used to
 * produce the real hash to be used to return a length of the would-be
 * hash for encoded data structure size calculations.
 */
void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c      data_to_hash);


/**
 * \brief Finish a cryptographic hash. Part of the t_cose crypto
 * adaptation layer.
 *
 * \param[in,out] hash_ctx           Pointer to the hash context.
 * \param[in] buffer_to_hold_result  Pointer and length into which
 *                                   the resulting hash is put.
 * \param[out] hash_result           Pointer and length of the
 *                                   resulting hash.
 *
 * \retval T_COSE_ERR_HASH_GENERAL_FAIL
 *         Some general failure of the hash function.
 * \retval T_COSE_ERR_HASH_BUFFER_SIZE
 *         The size of the buffer to hold the hash result was
 *         too small.
 * \retval T_COSE_SUCCESS
 *         Success.
 *
 * Call this to complete the hashing operation. If the everything
 * completed correctly, the resulting hash is returned. Note that any
 * errors that occurred during t_cose_crypto_hash_update() are
 * returned here.
 *
 * See \ref useful_buf_use for details on how \c q_useful_buf and
 * \c q_useful_buf_c are used to return the hash.
 *
 * Other errors can be returned and will usually be propagated up, but
 * hashes generally don't fail so it is suggested not to bother (and
 * to reduce object code size for mapping errors).
 */
enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf        buffer_to_hold_result,
                          struct q_useful_buf_c     *hash_result);

/**
 * \brief Set up a multipart HMAC calculation operation.
 *
 * \param[in,out] hmac_ctx      Pointer to the HMAC context.
 * \param[in] signing_key       The key for the HMAC operation
 * \param[in] cose_alg_id       The algorithm used in HMAC.
 *
 * \retval T_COSE_SUCCESS
 *         Tag calculation succeeds.
 * \retval T_COSE_ERR_UNSUPPORTED_SIGNING_ALG
 *         The algorithm is unsupported.
 * \retval T_COSE_ERR_INVALID_ARGUMENT
 *         Invalid arguments.
 * \retval T_COSE_ERR_FAIL
 *         Some general failure of the HMAC function.
 */
enum t_cose_err_t
t_cose_crypto_hmac_compute_setup(struct t_cose_crypto_hmac *hmac_ctx,
                                 struct t_cose_key          signing_key,
                                 const int32_t              cose_alg_id);

/**
 * \brief Add a message fragment to a multipart HMAC operation.
 *
 * \param[in,out] hmac_ctx      Pointer to the HMAC context.
 * \param[in] payload           Pointer and length of payload
 *
 * \retval T_COSE_SUCCESS
 *         Tag calculation succeeds.
 * \retval T_COSE_ERR_SIG_BUFFER_SIZE
 *         The size of the buffer to hold the tag result was too small.
 * \retval T_COSE_ERR_INVALID_ARGUMENT
 *         Invalid arguments.
 * \retval T_COSE_ERR_FAIL
 *         Some general failure of the HMAC function.
 */
enum t_cose_err_t
t_cose_crypto_hmac_update(struct t_cose_crypto_hmac *hmac_ctx,
                          struct q_useful_buf_c      payload);

/**
 * \brief Finish the calculation of the HMAC of a message.
 *
 * \param[in,out] hmac_ctx      Pointer to the HMAC context.
 * \param[in] tag_buf           Pointer and length into which
 *                              the resulting tag is put.
 * \param[out] tag              Pointer and length of the
 *                              resulting tag.
 *
 * \retval T_COSE_SUCCESS
 *         Tag calculation succeeds.
 * \retval T_COSE_ERR_SIG_BUFFER_SIZE
 *         The size of the buffer to hold the tag result was too small.
 * \retval T_COSE_ERR_INVALID_ARGUMENT
 *         Invalid arguments.
 * \retval T_COSE_ERR_FAIL
 *         Some general failure of the HMAC function.
 */
enum t_cose_err_t
t_cose_crypto_hmac_compute_finish(struct t_cose_crypto_hmac *hmac_ctx,
                                  struct q_useful_buf        tag_buf,
                                  struct q_useful_buf_c     *tag);

/**
 * \brief Set up a multipart HMAC validation operation.
 *
 * \param[in,out] hmac_ctx      Pointer to the HMAC context.
 * \param[in] cose_alg_id       The algorithm used in HMAC.
 * \param[in] validation_key    Key for HMAC validation.
 *
 * \retval T_COSE_SUCCESS
 *         Operation succeeds.
 * \retval T_COSE_ERR_UNSUPPORTED_SIGNING_ALG
 *         The algorithm is unsupported.
 * \retval T_COSE_ERR_INVALID_ARGUMENT
 *         Invalid arguments.
 * \retval T_COSE_ERR_FAIL
 *         Some general failure of the HMAC function.
 */
enum t_cose_err_t
t_cose_crypto_hmac_validate_setup(struct t_cose_crypto_hmac *hmac_ctx,
                                  const  int32_t             cose_alg_id,
                                  struct t_cose_key          validation_key);

/**
 * \brief Finish the validation of the HMAC of a message.
 *
 * \param[in,out] hmac_ctx      Pointer to the HMAC context.
 * \param[in] tag               Pointer and length of the tag.
 *
 * \retval T_COSE_SUCCESS
 *         Tag calculation succeeds.
 * \retval T_COSE_ERR_INVALID_ARGUMENT
 *         Invalid arguments.
 * \retval T_COSE_ERR_FAIL
 *         Some general failure of the HMAC function.
 * \retval PSA_ERROR_INVALID_SIGNATURE
 *         HMAC validation failed.
 */
enum t_cose_err_t
t_cose_crypto_hmac_validate_finish(struct t_cose_crypto_hmac *hmac_ctx,
                                   struct q_useful_buf_c      tag);





// TODO: rename this to have hmac in its name
static inline size_t t_cose_tag_size(int32_t cose_alg_id)
{
    switch(cose_alg_id) {
        case T_COSE_ALGORITHM_HMAC256:
            return T_COSE_CRYPTO_HMAC256_TAG_SIZE;
        case T_COSE_ALGORITHM_HMAC384:
            return T_COSE_CRYPTO_HMAC384_TAG_SIZE;
        case T_COSE_ALGORITHM_HMAC512:
            return T_COSE_CRYPTO_HMAC512_TAG_SIZE;
        default:
            return INT32_MAX;
    }
}


/**
 * \brief Returns the requested number of random bytes.
 *
 * \param[in] buffer             Pointer and length of buffer into which
 *                               the resulting random bytes are put.
 * TBD:
 *
 * This function will either return the requested number of random bytes,
 * or produce an error.
 *
 * \retval T_COSE_SUCCESS
 *         Successfully returned the requested number of random bytes.
 * \retval T_COSE_ERR_RNG_FAILED
 *         The random number generator failed to return the requested
 *         number of bytes.
 */
//  TODO: just make it fill the buffer and get rid of number?
enum t_cose_err_t
t_cose_crypto_get_random(struct q_useful_buf    buffer,
                         size_t                 number,
                         struct q_useful_buf_c *random);


/**
 * \brief Requests generation of a public / private key pair.
 *
 * \param[in] cose_ec_curve_id   Curve identifier from COSE curve registry.
 * \param[out] key                t_cose_key structure to hold the key pair
 *
 * This function will either return a key in form of a t_cose_key
 * structure, or produce an error.
 *
 * \retval T_COSE_SUCCESS
 *         Successfully generated a public/private key pair
 *
 * \retval T_COSE_ERR_UNSUPPORTED_KEM_ALG
 *         Unknown algorithm
 *
 * \retval T_COSE_ERR_KEY_GENERATION_FAILED
 *         Key generation failed
 */
enum t_cose_err_t
t_cose_crypto_generate_ec_key(int32_t            cose_ec_curve_id,
                              struct t_cose_key *key);



/**
 * \brief Exports key
 *
 * \param[in] key               Handle to key
 * \param[in] key_buffer        Pointer and length of buffer into which
 *                              the resulting key is put.
 * \param[out] exported_key          Length of the returned key.
 *
 * \retval T_COSE_SUCCESS
 *         Successfully exported the key.
 * \retval T_COSE_ERR_KEY_EXPORT_FAILED
 *         The key export operation failed.
 *
 * The t_cose implementation tries to avoid use of this, preferring
 * to use keys in the form of a struct t_cose_key rather than
 * have the actual bytes of the key in memory. This allows
 * crypto adaptors to work with crypto implementations in
 * HSMs and such that can encrypt/decrypt without the
 * key being present outside the HSM.
 *
 * The one place this is used outside of the PSA crypto layer
 * is the option that lets the caller set the CEK and the
 * CEK needs to be given to a key distribtion method.
 */
// TODO: say how to know the length
enum t_cose_err_t
t_cose_crypto_export_symmetric_key(struct t_cose_key      key,
                                   struct q_useful_buf    key_buffer,
                                   struct q_useful_buf_c *exported_key);


/**
 * \brief Uses the AES key wrap algorithm defined in RFC 3394 to
 *        encrypt the CEK.
 *
 * \param[in] cose_algorithm_id   A COSE key wrap algorithm id.
 * \param[in] kek                 The key encryption key.
 * \param[in] plaintext           The plaintext to encrypt, e.g. the CEK.
 * \param[in] ciphertext_buffer   Buffer to hold ciphertext output.
 * \param[out] ciphertext_result  Resulting ciphertext with wrapped key.
 *
 * \retval T_COSE_SUCCESS
 *         Operation was successful.
 * \retval T_COSE_ERR_TOO_SMALL
 *         \c ciphertext_buffer was too smalll.
 * \retval T_COSE_ERR_UNSUPPORTED_CIPHER_ALG
 *         The wrapping algorithm is not supported (this error code is borrowed to mean
 *         wrapping algorithm)
 * \retval T_COSE_ERR_WRONG_TYPE_OF_KEY
 *         The key is the wrong length for the algorithm.
 * \retval T_COSE_ERR_KW_FAILED
 *         Key wrap failed for other than the above reasons.
 *
 * This uses RFC 3394 to wrap a key, typically the CEK (content
 * encryption key) using another key, the KEK (key encryption
 * key). This key wrap provides both confidentiality and integrity.
 *
 * OIther than AES is facilitated here, but in practice only AES is needed.
 *
 * Implementations of this must error out on incorrect algorithm IDs. They
 * can't just assume AES and go off the key size. This is so callers of this
 * can rely on this to check the algorithm ID and not have to check it.
 */
enum t_cose_err_t
t_cose_crypto_kw_wrap(int32_t                 cose_algorithm_id,
                      struct t_cose_key       kek,
                      struct q_useful_buf_c   plaintext,
                      struct q_useful_buf     ciphertext_buffer,
                      struct q_useful_buf_c  *ciphertext_result);


/**
 * \brief Uses the AES key wrap algorithm defined in RFC 3394 to
 *        decrypt the CEK.
 *
 * \param[in] cose_algorithm_id   A COSE key wrap algorithm id.
 * \param[in] kek                 The key encryption key.
 * \param[in] ciphertext           The wrapped key.
 * \param[in] plaintext_buffer   Buffer to hold plaintext output.
 * \param[out] plaintext_result  Resulting plaintext, usually the CEK.
 *
 * \retval T_COSE_SUCCESS
 *         Operation was successful.
 * \retval T_COSE_ERR_TOO_SMALL
 *         \c plaintext_buffer was too smalll.
 * \retval T_COSE_ERR_UNSUPPORTED_CIPHER_ALG
 *         The wrapping algorithm is not supported (this error code is borrowed to mean
 *         wrapping algorithm)
 * \retval T_COSE_ERR_WRONG_TYPE_OF_KEY
 *         The key is the wrong length for the algorithm.
 * \retval T_COSE_ERR_DATA_AUTH_FAILED
 *         The authentication of the wrapped key failed.
 * \retval T_COSE_ERR_KW_FAILED
 *         Key unwrap failed for other than the above reasons.
 *
 * This uses RFC 3394 to unwrap a key, typically the CEK (content
 * encryption key) using another key, the KEK (key encryption
 * key). This key wrap provides both confidentiality and integrity.
 *
 * OIther than AES is facilitated here, but in practice only AES is needed.
 *
 * Implementations of this must error out on incorrect algorithm IDs. They
 * can't just assume AES and go off the key size. This is so callers of this
 * can rely on this to check the algorithm ID and not have to check it.
 */
enum t_cose_err_t
t_cose_crypto_kw_unwrap(int32_t                 cose_algorithm_id,
                        struct t_cose_key       kek,
                        struct q_useful_buf_c   ciphertext,
                        struct q_useful_buf     plaintext_buffer,
                        struct q_useful_buf_c  *plaintext_result);


/**
 * \brief Returns the t_cose_key given an algorithm and a symmetric key.
 *
 * \param[in] cose_algorithm_id  COSE algorithm id
 * \param[in] symmetric_key                Symmetric key.
 * \param[out] key               Key in t_cose_key structure.
 *
 * \retval T_COSE_SUCCESS
 *         The key was successfully imported and is returned as a
 *         struct t_cose_key.
 * \retval T_COSE_ERR_UNSUPPORTED_CIPHER_ALG
 *         An unsupported COSE algorithm was provided.
 * \retval T_COSE_ERR_KEY_IMPORT_FAILED
 *         The provided symmetric key could not be imported.
 *
 * This is part of the crypto adaptor layer because there is an easy
 * universal representation of a symmetric key -- a byte string (not
 * true for public key algorithms, so there isn't similar for them
 * (yet)).
 *
 * If the crypto library enforces policy around keys (e.g., Mbed TLS),
 * this will confgure the key returned for the algorithm passed in and
 * an expected usage policy based on the algorithm. If the library
 * enforces no policy (e.g. OpenSSL) this will not configure the key
 * returned. Future adaptors for libraries where the policy is
 * optional may choose to do either.
 *
 * There's one odd-ball case the PSA implementation of this takes into
 * account -- the Mbed TLS key wrap API. The t_cose API takes the kek
 * as a t_cose_key because all input keys to t_cose are such. This
 * means a PSA key handle. However, the key wrap API takes bytes for
 * the key so the key must be exported from the handle and thus must
 * allow the key export key use.
 *
 * See also t_cose_crypto_free_symmetric_key().
 */
enum t_cose_err_t
t_cose_crypto_make_symmetric_key_handle(int32_t               cose_algorithm_id,
                                        struct q_useful_buf_c symmetric_key,
                                        struct t_cose_key     *key);


/**
 * \brief Decrypt a ciphertext using an AEAD cipher. Part of the
 * t_cose crypto adaptation layer.
 *
 * \param[in] cose_algorithm_id      The algorithm to use for decryption.
 *                                   The IDs are defined in [COSE (RFC 8152)]
 *                                   (https://tools.ietf.org/html/rfc8152)
 *                                    or in the [IANA COSE Registry]
 *                                   (https://www.iana.org/assignments/cose/cose.xhtml).
 * \param[in] key                    The decryption key to use.
 * \param[in] nonce                  The nonce used as input to the decryption operation.
 * \param[in] add_data               Additional data used for decryption.
 * \param[in] ciphertext             The ciphertext to decrypt.
 * \param[in] plaintext_buffer       Buffer where the plaintext will be put.
 * \param[out] plaintext  Place to return the plaintext
 *
 * The key provided must be a symmetric key of the correct type for
 * \c cose_algorithm_id.
 *
 * A key handle is used even though it could be a buffer with a key in
 * order to allow use of keys internal to the crypto library, crypto
 * HW and such. See t_cose_crypto_make_symmetric_key_handle().
 *
 * This does not need to support a size calculation mode as is
 * required of t_cose_crypto_aead_encrypt().
 *
 * One of the following errors should be returned. Other errors should
 * not be returned.
 *
 * \retval T_COSE_SUCCESS
 *         The decryption operation was successful.
 * \retval T_COSE_ERR_UNSUPPORTED_CIPHER_ALG
 *         An unsupported cipher algorithm was provided.
 * \retval T_COSE_ERR_TOO_SMALL
 *         The \c plaintext_buffer is too small.
 * \retval T_COSE_ERR_WRONG_TYPE_OF_KEY
 *         The key is not right for the algorithm or is not allowed for decryption.
 * \retval T_COSE_ERR_DATA_AUTH_FAILED
 *         The data integrity check failed.
 * \retval T_COSE_ERR_DECRYPT_FAIL
 *         Decryption failed for a reason other than above.
 */
enum t_cose_err_t
t_cose_crypto_aead_decrypt(int32_t                cose_algorithm_id,
                           struct t_cose_key      key,
                           struct q_useful_buf_c  nonce,
                           struct q_useful_buf_c  add_data,
                           struct q_useful_buf_c  ciphertext,
                           struct q_useful_buf    plaintext_buffer,
                           struct q_useful_buf_c *plaintext);

/**
 * \brief Encrypt plaintext using an AEAD cipher. Part of the
 * t_cose crypto adaptation layer.
 *
 * \param[in] cose_algorithm_id      The algorithm to use for encryption.
 *                                   The IDs are defined in [COSE (RFC 8152)]
 *                                   (https://tools.ietf.org/html/rfc8152)
 *                                    or in the [IANA COSE Registry]
 *                                   (https://www.iana.org/assignments/cose/cose.xhtml).
 * \param[in] key                    The encryption key to use.
 * \param[in] nonce                  The nonce used as input to the encryption operation.
 * \param[in] add_data               Additional data used for encryption.
 * \param[in] plaintext              The plaintext to encrypt.
 * \param[in] ciphertext_buffer      Buffer where the ciphertext will be put.
 * \param[out] ciphertext  Place to put pointer and length to ciphertext.
 *
 * The key provided must be a symmetric key of the correct type for
 * \c cose_algorithm_id.
 *
 * A key handle is used even though it could be a buffer with a key in
 * order to allow use of keys internal to the crypto library, crypto
 * HW and such. See t_cose_crypto_make_symmetric_key_handle().
 *
 * This must support a size calculation mode which is indicated by
 * ciphertext_buffer.ptr == NULL and which fills the size in
 * ciphertext->len.
 *
 * One of the following errors should be returned. Other errors should
 * not be returned.
 *
 * \retval T_COSE_SUCCESS
 *         The decryption operation was successful.
 * \retval T_COSE_ERR_UNSUPPORTED_CIPHER_ALG
 *         An unsupported cipher algorithm was provided.
 * \retval T_COSE_ERR_TOO_SMALL
 *         \c ciphertext_buffer is too small.
 * \retval T_COSE_ERR_WRONG_TYPE_OF_KEY
 *         The key is not right for the algorithm or is not allowed for encryption.
 * \retval T_COSE_ERR_ENCRYPT_FAIL
 *         Encryption failed for a reason other than above.
 */
enum t_cose_err_t
t_cose_crypto_aead_encrypt(int32_t                cose_algorithm_id,
                           struct t_cose_key      key,
                           struct q_useful_buf_c  nonce,
                           struct q_useful_buf_c  add_data,
                           struct q_useful_buf_c  plaintext,
                           struct q_useful_buf    ciphertext_buffer,
                           struct q_useful_buf_c *ciphertext);


/* Free a symmetric key. */
void
t_cose_crypto_free_symmetric_key(struct t_cose_key key);


/**
 * \brief Elliptic curve diffie-helman.
 *
 * \param[in] private_key     The private EC Key
 * \param[in] public_key      The public EC key
 * \param[in] shared_key_buf  Buffer to write the derived shared key in to
 * \param[out] shared_key     The derived shared key
 *
 *  This works works for NIST curves up to secp521r1.
 *  It must work for key sizes up to T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE.
 *
 *  This should work for Edwards curves too. TODO: test this.
 *
 *  (The choice is made to focus just on ECDH because no
 *  one really does finite field DH (aka classic DH) and
 *  there's no expectation that any will be registered in
 *  the COSE registry.  This also keeps the API simpler,
 *  saves a little code and makes it more clear what
 *  someone needs to implement in the adaptor and the
 *  expected output and key sizes.)
 */
enum t_cose_err_t
t_cose_crypto_ecdh(struct t_cose_key      private_key,
                   struct t_cose_key      public_key,
                   struct q_useful_buf    shared_key_buf,
                   struct q_useful_buf_c *shared_key);



/**
 * \brief RFC 5869 HKDF
 *
 * \param[in] cose_hash_algorithm_id  Hash algorithm the HKDF uses.
 * \param[in] salt     The salt bytes or \c NULL_Q_USEFUL_BUF_C.
 * \param[in] ikm   The input key material.
 * \param[in] info   The info bytes or \c NULL_Q_USEFUL_BUF_C.
 * \param[in,out] okm_buffer  The output key material.
 *
 * \retval T_COSE_ERR_UNSUPPORTED_HASH
 * \retval T_COSE_ERR_HKDF_FAIL
 *
 * With HKDF you can request the output be up to 255 times
 * the length of output of the hash function. In this interface that length
 * request is the length of the okm_buffer. On success
 * the whole \c okm_buffer will always be filled in.
 * The usual parameter pair of an empty \c q_useful_buf
 * passed in and filled-in \c q_useful_buf_c returned is not
 * used because it would be redundant and waste some
 * object code.
 *
 * The salt is usually a non-secret random value and is
 * optional.
 *
 * The input key material is a secret and is not optional.
 *
 * The info is an optional context and application-specific
 * information string.
 *
 * See RFC 5869 for a detailed description.
 */
enum t_cose_err_t
t_cose_crypto_hkdf(int32_t                     cose_hash_algorithm_id,
                   const struct q_useful_buf_c salt,
                   const struct q_useful_buf_c ikm,
                   const struct q_useful_buf_c info,
                   const struct q_useful_buf   okm_buffer);



/* Import a COSE_Key in EC2 format into a key handle.
 *
 * \param[in] curve        EC curve from COSE curve registry.
 * \param[in] x_coord      The X coordinate as a byte string.
 * \param[in] y_coord      The Y coordinate or NULL.
 * \param[in] y_bool       The Y sign bit when y_coord is NULL.
 * \param[out] key_handle  The key handle.
 *
 * This doesn't do the actual CBOR decoding, just the import
 * into a key handle for the crypto library.
 *
 * The coordinates are as specified in SECG 1.
 *
 * TODO: also support the private key.
 */
enum t_cose_err_t
t_cose_crypto_import_ec2_pubkey(int32_t               cose_ec_curve_id,
                                struct q_useful_buf_c x_coord,
                                struct q_useful_buf_c y_coord,
                                bool                  y_bool,
                                struct t_cose_key    *key_handle);


/* Export a key handle into COSE_Key in EC2 format.
 *
 * \param[in] key_handle   The key handle.
 * \param[out] curve        EC curve from COSE curve registry.
 * \param[out] x_coord_buf  Buffer in which to put X coordinate.
 * \param[out] x_coord      The X coordinate as a byte string.
 * \param[out] y_coord_buf  Buffer in which to put Y coordinate.
 * \param[out] y_coord      The Y coordinate or NULL.
 * \param[out] y_bool       The Y sign bit when y_coord is NULL.
 *
 * This doesn't do the actual CBOR decoding, just the export
 * from a key handle for the crypto library.
 *
 * The coordinates are as specified in SECG 1.
 *
 * TODO: also support the private key.
 * TODO: a way to turn point compression on / off?
 */
enum t_cose_err_t
t_cose_crypto_export_ec2_key(struct t_cose_key      key_handle,
                             int32_t               *cose_ec_curve_id,
                             struct q_useful_buf    x_coord_buf,
                             struct q_useful_buf_c *x_coord,
                             struct q_useful_buf    y_coord_buf,
                             struct q_useful_buf_c *y_coord,
                             bool                  *y_bool);

#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_CRYPTO_H__ */
