/*
 * t_cose_crypto.h
 *
 * Copyright 2019-2022, Laurence Lundblade
 * Copyright (c) 2020-2022, Arm Limited. All rights reserved.
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

#ifdef __cplusplus
extern "C" {
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
 * - Support for a new T_COSE_ALGORITHM_XXX signature algorithm is added
 *    - See \ref T_COSE_CRYPTO_MAX_HASH_SIZE for additional hashes
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



/* This sets the maximum key size for symmetric ciphers like AES and ChaCha20 (not supported yet).
* It is set to 32 to accommodate AES 256 and anything with a smaller
* key size. This is used to size stack buffers that hold keys.
* Attempts to use a symmetric key size larger than this will result in an error.
* Smaller keys sizes are no problem.
* This could be more dynamically sized based on which algorithms
* are turned on or off, but probably isn't necessary because
* it isn't very large and dynamic setting wouldn't save much stack.
*/
#define T_COSE_ENCRYPTION_MAX_KEY_LENGTH 32

/** Helper macro to convert bits to bytes */
#define T_COSE_BITS_TO_BYTES(bits) (((bits) + 7) / 8)

/** Constant for maximum ECC curve size in bits */
#define T_COSE_ECC_MAX_CURVE_BITS 521


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
 */
enum t_cose_err_t
t_cose_crypto_sign(int32_t                cose_algorithm_id,
                   struct t_cose_key      signing_key,
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
 * \param[in] kid               The COSE kid (key ID) or \c NULL_Q_USEFUL_BUF_C.
 * \param[in] hash_to_verify    The hash of the data that is to be verified.
 * \param[in] signature         The COSE-format signature.
 *
 * This verifies that the \c signature passed in was over the \c
 * hash_to_verify passed in.
 *
 * The public key used to verify the signature is selected by the \c
 * kid if it is not \c NULL_Q_USEFUL_BUF_C or the \c key_select if it
 * is.
 *
 * The key selected must be, or include, a public key of the correct
 * type for \c cose_algorithm_id.
 *
 * \retval T_COSE_SUCCESS
 *         The signature is valid
 * \retval T_COSE_ERR_SIG_VERIFY
 *         Signature verification failed. For example, the
 *         cryptographic operations completed successfully but hash
 *         wasn't as expected.
 * \retval T_COSE_ERR_UNKNOWN_KEY
 *         The key identified by \c key_select or a \c kid was
 *         not found.
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
                     struct q_useful_buf_c kid,
                     struct q_useful_buf_c hash_to_verify,
                     struct q_useful_buf_c signature);

#ifndef T_COSE_DISABLE_EDDSA

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
 * \param[in] kid               The COSE kid (key ID) or \c NULL_Q_USEFUL_BUF_C.
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
 * \retval T_COSE_ERR_UNKNOWN_KEY
 *         The key identified by \c key_select or a \c kid was
 *         not found.
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
                           struct q_useful_buf_c kid,
                           struct q_useful_buf_c tbs,
                           struct q_useful_buf_c signature);
#endif /* T_COSE_DISABLE_EDDSA */

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
        int32_t      cose_hash_alg_id; /* COSE integer ID for the hash alg */

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
 * Max size of the tag output for the HMAC operations.
 */
#define T_COSE_CRYPTO_HMAC_TAG_MAX_SIZE  T_COSE_CRYPTO_SHA512_SIZE

/**
 * The maximum needed to hold a hash. It is smaller and less stack is needed
 * if the larger hashes are disabled.
 */
#if !defined(T_COSE_DISABLE_ES512) || !defined(T_COSE_DISABLE_PS512)
    #define T_COSE_CRYPTO_MAX_HASH_SIZE T_COSE_CRYPTO_SHA512_SIZE
#else
    #if !defined(T_COSE_DISABLE_ES384) || !defined(T_COSE_DISABLE_PS384)
        #define T_COSE_CRYPTO_MAX_HASH_SIZE T_COSE_CRYPTO_SHA384_SIZE
    #else
        #define T_COSE_CRYPTO_MAX_HASH_SIZE T_COSE_CRYPTO_SHA256_SIZE
    #endif
#endif


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

/**
 * \brief Indicate whether a COSE algorithm is ECDSA or not.
 *
 * \param[in] cose_algorithm_id    The algorithm ID to check.
 *
 * \returns This returns \c true if the algorithm is ECDSA and \c false if not.
 *
 * This is a convenience function to check whether a given
 * integer COSE algorithm ID uses the ECDSA signing algorithm
 * or not.
 *
 */
static bool
t_cose_algorithm_is_ecdsa(int32_t cose_algorithm_id);

/**
 * \brief Indicate whether a COSE algorithm is RSASSA-PSS or not.
 *
 * \param[in] cose_algorithm_id    The algorithm ID to check.
 *
 * \returns This returns \c true if the algorithm is RSASSA-PSS
 * and \c false if not.
 *
 * This is a convenience function to check whether a given
 * integer COSE algorithm ID uses the RSASSA-PSS signing algorithm
 * or not.
 *
 */
static bool
t_cose_algorithm_is_rsassa_pss(int32_t cose_algorithm_id);




/*
 * Inline implementations. See documentation above.
 */

/**
 * \brief Look for an integer in a zero-terminated list of integers.
 *
 * \param[in] cose_algorithm_id    The algorithm ID to check.
 * \param[in] list                 zero-terminated list of algorithm IDs.
 *
 * \returns This returns \c true if an integer is in the list, \c false if not.
 *
 * Used to implement t_cose_algorithm_is_ecdsa() and in the future
 * _is_rsa() and such.
 *
 * Typically used once in the crypto adaptation layer, so defining it
 * inline rather than in a .c file is OK and saves creating a whole
 * new .c file just for this.
 */
static inline bool
t_cose_check_list(int32_t cose_algorithm_id, const int32_t *list)
{
    while(*list != T_COSE_ALGORITHM_NONE) {
        if(*list == cose_algorithm_id) {
            return true;
        }
        list++;
    }

    return false;
}

static inline bool
t_cose_algorithm_is_ecdsa(int32_t cose_algorithm_id)
{
    /* The simple list of COSE alg IDs that use ECDSA */
    static const int32_t ecdsa_list[] = {
        T_COSE_ALGORITHM_ES256,
#ifndef T_COSE_DISABLE_ES384
        T_COSE_ALGORITHM_ES384,
#endif
#ifndef T_COSE_DISABLE_ES512
        T_COSE_ALGORITHM_ES512,
#endif
        T_COSE_ALGORITHM_NONE};

    return t_cose_check_list(cose_algorithm_id, ecdsa_list);
}


static inline bool
t_cose_algorithm_is_rsassa_pss(int32_t cose_algorithm_id)
{
    /* The simple list of COSE alg IDs that use RSASSA-PSS */
    static const int32_t rsa_list[] = {
#ifndef T_COSE_DISABLE_PS256
        T_COSE_ALGORITHM_PS256,
#endif
#ifndef T_COSE_DISABLE_PS384
        T_COSE_ALGORITHM_PS384,
#endif
#ifndef T_COSE_DISABLE_PS512
        T_COSE_ALGORITHM_PS512,
#endif
        T_COSE_ALGORITHM_NONE};

    return t_cose_check_list(cose_algorithm_id, rsa_list);
}

static inline bool
t_cose_algorithm_is_short_circuit(int32_t cose_algorithm_id)
{
    /* The simple list of COSE alg IDs that use ECDSA */
    static const int32_t ecdsa_list[] = {
        T_COSE_ALGORITHM_SHORT_CIRCUIT_256,
        T_COSE_ALGORITHM_SHORT_CIRCUIT_384,
        T_COSE_ALGORITHM_SHORT_CIRCUIT_512,
        T_COSE_ALGORITHM_NONE};

    return t_cose_check_list(cose_algorithm_id, ecdsa_list);
}


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

#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
/*
 * Get the COSE Hash algorithm ID from the corresponding
 * COSE HMAC algorithm ID
 */
static inline int32_t t_cose_hmac_to_hash_alg_id(int32_t cose_hamc_alg_id)
{
    switch(cose_hamc_alg_id) {
        case T_COSE_ALGORITHM_HMAC256:
            return T_COSE_ALGORITHM_SHA_256;

        default:
            return INT32_MAX;
    }
}
#endif



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

/* TBD: Generate key */
enum t_cose_err_t
t_cose_crypto_generate_key(struct t_cose_key    *ephemeral_key,
                           int32_t               cose_algorithm_id);

/**
 * \brief Exports the public key
 *
 * \param[in] key               Handle to key
 * \param[in] pk_buffer         Pointer and length of buffer into which
 *                              the resulting public key is put.
 * \param[out] pk               Public Key
 *
 * \retval T_COSE_SUCCESS
 *         Successfully exported the public key.
 * \retval T_COSE_ERR_PUBLIC_KEY_EXPORT_FAILED
 *         The public key export operation failed.
 */
enum t_cose_err_t
t_cose_crypto_export_public_key(struct t_cose_key      key,
                                struct q_useful_buf    pk_buffer,
                                size_t                *pk_len);

/**
 * \brief Exports key
 *
 * \param[in] key               Handle to key
 * \param[in] key_buffer        Pointer and length of buffer into which
 *                              the resulting key is put.
 * \param[out] key_len          Length of the returned key.
 *
 * \retval T_COSE_SUCCESS
 *         Successfully exported the key.
 * \retval T_COSE_ERR_KEY_EXPORT_FAILED
 *         The key export operation failed.
 */
enum t_cose_err_t
t_cose_crypto_export_key(struct t_cose_key      key,
                         struct q_useful_buf    key_buffer,
                         size_t                *key_len);

/**
 * \brief Uses the AES key wrap algorithm defined in RFC 3394 to
 *        encrypt the CEK.
 *
 * \param[in] algorithm_id        Algorithm id
 * \param[in] kek                 Key Encryption Key
 * \param[in] plaintext           Plaintext
 * \param[in] ciphertext_buffer   Ciphertext buffer
 * \param[out] ciphertext_result  Resulting ciphertext
 *
 * \retval T_COSE_SUCCESS
 *         Operation was successful.
 * \retval T_COSE_ERR_AES_KW_FAILED
 *         AES key wrap operation failed.
 */
enum t_cose_err_t
t_cose_crypto_aes_kw(int32_t                 algorithm_id,
                     struct q_useful_buf_c   kek,
                     struct q_useful_buf_c   plaintext,
                     struct q_useful_buf     ciphertext_buffer,
                     struct q_useful_buf_c  *ciphertext_result);

/**
 * \brief HPKE Decrypt Wrapper
 *
 * \param[in] cose_algorithm_id   COSE algorithm id
 * \param[in] pkE                 pkE buffer
 * \param[in] pkR                 pkR key
 * \param[in] ciphertext          Ciphertext buffer
 * \param[in] plaintext           Plaintext buffer
 * \param[out] plaintext_len      Length of the returned plaintext
 *
 * \retval T_COSE_SUCCESS
 *         HPKE decrypt operation was successful.
 * \retval T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG
 *         An unsupported algorithm was supplied to the function call.
 * \retval T_COSE_ERR_HPKE_DECRYPT_FAIL
 *         Decrypt operation failed.
 */
enum t_cose_err_t
t_cose_crypto_hpke_decrypt(int32_t                            cose_algorithm_id,
                           struct q_useful_buf_c              pkE,
                           struct t_cose_key                  pkR,
                           struct q_useful_buf_c              ciphertext,
                           struct q_useful_buf                plaintext,
                           size_t                            *plaintext_len);

/**
 * \brief Returns the t_cose_key given an algorithm.and a symmetric key
 *
 * \param[in] cose_algorithm_id  COSE algorithm id
 * \param[in] cek                Symmetric key
 * \param[in] cek_len            Symmetric key length
 * \param[in] flags              Key usage flags
 * \param[out] key               Key in t_cose_key structure.
 *
 * \retval T_COSE_SUCCESS
 *         The key was successfully imported and is returned in the
 *         t_cose_key format.
 * \retval T_COSE_ERR_UNKNOWN_KEY
 *         The provided symmetric key could not be imported.
 * \retval T_COSE_ERR_UNSUPPORTED_CIPHER_ALG
 *         An unsupported COSE algorithm was provided.
 * \retval T_COSE_ERR_UNSUPPORTED_KEY_USAGE_FLAGS
 *         The provided key usage flags are unsupported.
 */
enum t_cose_err_t
t_cose_crypto_get_cose_key(int32_t              cose_algorithm_id,
                           uint8_t             *cek,
                           size_t               cek_len,
                           uint8_t              flags,
                           struct t_cose_key   *key);


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
 * \param[out] plaintext_output_len  The size of the plaintext.
 *
 * The key provided must be a symmetric key of the correct type for
 * \c cose_algorithm_id.
 *
 * \retval T_COSE_SUCCESS
 *         The decryption operation was successful.
 * \retval T_COSE_ERR_UNSUPPORTED_CIPHER_ALG
 *         An unsupported cipher algorithm was provided.
 * \retval T_COSE_ERR_DECRYPT_FAIL
 *         The decryption operation failed.
 */
enum t_cose_err_t
t_cose_crypto_decrypt(int32_t                cose_algorithm_id,
                      struct t_cose_key      key,
                      struct q_useful_buf_c  nonce,
                      struct q_useful_buf_c  add_data,
                      struct q_useful_buf_c  ciphertext,
                      struct q_useful_buf    plaintext_buffer,
                      size_t                *plaintext_output_len);

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
 * \param[out] ciphertext_output_len The size of the ciphertext.
 *
 * The key provided must be a symmetric key of the correct type for
 * \c cose_algorithm_id.
 *
 * \retval T_COSE_SUCCESS
 *         The decryption operation was successful.
 * \retval T_COSE_ERR_UNSUPPORTED_CIPHER_ALG
 *         An unsupported cipher algorithm was provided.
 * \retval T_COSE_ERR_KEY_IMPORT_FAILED
 *         The provided key could not be imported.
 * \retval T_COSE_ERR_ENCRYPT_FAIL
 *         The encryption operation failed.
 */
enum t_cose_err_t
t_cose_crypto_encrypt(int32_t                cose_algorithm_id,
                      struct q_useful_buf_c  key,
                      struct q_useful_buf_c  nonce,
                      struct q_useful_buf_c  add_data,
                      struct q_useful_buf_c  plaintext,
                      struct q_useful_buf    ciphertext_buffer,
                      size_t                *ciphertext_output_len);


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_CRYPTO_H__ */
