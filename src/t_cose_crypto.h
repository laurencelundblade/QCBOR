/*
 * t_cose_crypto.h
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef __T_COSE_CRYPTO_H__
#define __T_COSE_CRYPTO_H__

#include "t_cose_common.h"
#include "q_useful_buf.h"
#include <stdint.h>
#include "t_cose_standard_constants.h"

#ifdef __cplusplus
extern "C" {
#endif




/**
 * \file t_cose_crypto.h
 *
 * \brief This is the adaptation layer for cryptographic functions used by
 * t_cose.
 *
 * This is  small wrapper around the cryptographic functions to:
 * - Map COSE algorithm IDs to TF-M algorithm IDs
 * - Map crypto errors to \ref t_cose_err_t errors
 * - Have inputs and outputs be \c struct \c q_useful_buf_c and
 *   \c struct \c q_useful_buf
 * - Handle key selection
 *
 * The idea is that implementations can be made of these functions
 * that adapt to various cryptographic libraries that are used on
 * various platforms and OSs.
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
 * Binary data is returned to the caller using a \c struct \c
 * q_useful_buf to pass the buffer to receive the data and its length in
 * and a \c q_useful_buf_c to return the pointer and length of the
 * returned data. The point of this is coding hygiene. The buffer
 * passed in is not const as it is to be modified.  The \c
 * q_useful_buf_c returned is const.
 *
 * The pointer in the \c q_useful_buf_c will always point to the buffer
 * passed in via the \c q_useful_buf so the lifetime of the data is
 * under control of the caller.
 *
 * This is not intended as any sort of general cryptographic API. It
 * is just the functions needed by t_cose in the form that is most
 * useful for t_cose.
 */


/**
 * Size of the signature output for the various curves.
 * https://crypto.stackexchange.com/questions/12299/ecc-key-size-and-signature-size/12300
 */
#define T_COSE_EC_P256_SIG_SIZE 64

#define T_COSE_EC_P384_SIG_SIZE 96

#define T_COSE_EC_P512_SIG_SIZE 132


/**
 * Size of the largest signature of any of the algorithm types
 * supported.
 *
 * This will have to be adjusted if support for other algorithms
 * larger is added.
 *
 * This is a compile time constant so it can be used to define stack
 * variable sizes.
 */

#ifndef T_COSE_DISABLE_ES512
    #define T_COSE_MAX_EC_SIG_SIZE T_COSE_EC_P512_SIG_SIZE
#else
    #ifndef T_COSE_DISABLE_ES384
        #define T_COSE_MAX_EC_SIG_SIZE T_COSE_EC_P384_SIG_SIZE
    #else
        #define T_COSE_MAX_EC_SIG_SIZE T_COSE_EC_P256_SIG_SIZE
    #endif
#endif


/**
 * \brief Get the size in bytes of a particular signature type.
 *
 * \param[in] cose_sig_alg_id  The COSE algorithm ID.
 *
 * \return The size in bytes of the signature for a public-key signing
 * algorithm or zero for unknown algorithm IDs.
 */
static inline size_t t_cose_signature_size(int32_t cose_sig_alg_id);


/**
 * \brief Perform public key signing. Part of the t_cose crypto
 * adaptation layer.
 *
 * \param[in] cose_alg_id       The algorithm to sign with. The IDs are
 *                              defined in [COSE (RFC 8152)]
 *                              (https://tools.ietf.org/html/rfc8152) or
 *                              in the [IANA COSE Registry]
 *                          (https://www.iana.org/assignments/cose/cose.xhtml).
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
 *         The requested signing algorithm, \c cose_alg_id, is not
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
 *         Equivalent to \c PSA_ERROR_TAMPERING_DETECTED.
 *
 * This is called to do public key signing. The implementation will
 * vary from one platform / OS to another but should conform to the
 * description here.
 *
 * The key selection depends on the platform / OS.
 *
 * See the note in the Detailed Description (the \\file comment block)
 * for details on how \c q_useful_buf and \c q_useful_buf_c are used to
 * return the signature.
 *
 * To find out the size of the signature buffer needed, call this with
 * \c signature_buffer->ptr \c NULL and \c signature_buffer->len a
 * very large number like \c UINT32_MAX. The size will be returned in
 * \c signature->len.
 */
enum t_cose_err_t
t_cose_crypto_pub_key_sign(int32_t cose_alg_id,
                           struct t_cose_key signing_key,
                           struct q_useful_buf_c hash_to_sign,
                           struct q_useful_buf signature_buffer,
                           struct q_useful_buf_c *signature);


/**
 * \brief perform public key signature verification. Part of the
 * t_cose crypto adaptation layer.
 *
 * \param[in] cose_alg_id      The algorithm to use for verification.
 *                             The IDs are defined in [COSE (RFC 8152)]
 *                             (https://tools.ietf.org/html/rfc8152)
 *                             or in the [IANA COSE Registry]
 *                       (https://www.iana.org/assignments/cose/cose.xhtml).
 *                             A proprietary ID can also be defined
 *                             locally (\c \#define) if the needed one
 *                             hasn't been registered.
 * \param[in] verification_key The verification key to use.
 * \param[in] key_id           A key id or \c NULL_Q_USEFUL_BUF_C.
 * \param[in] hash_to_verify   The data or hash that is to be verified.
 * \param[in] signature        The signature.
 *
 * This verifies that the \c signature passed in was over the \c
 * hash_to_verify passed in.
 *
 * The public key used to verify the signature is selected by the \c
 * key_id if it is not \c NULL_Q_USEFUL_BUF_C or the \c key_select if it
 * is.
 *
 * The key selected must be, or include, a public key of the correct
 * type for \c cose_alg_id.
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
 *         Equivalent to \c PSA_ERROR_TAMPERING_DETECTED.
 */
enum t_cose_err_t
t_cose_crypto_pub_key_verify(int32_t cose_alg_id,
                             struct t_cose_key verification_key,
                             struct q_useful_buf_c key_id,
                             struct q_useful_buf_c hash_to_verify,
                             struct q_useful_buf_c signature);


/**
 * The size of X and Y coordinate in 2 parameter style EC public
 * key. Format is as defined in [COSE (RFC 8152)]
 * (https://tools.ietf.org/html/rfc8152) and [SEC 1: Elliptic Curve
 * Cryptography](http://www.secg.org/sec1-v2.pdf).
 *
 * This size is well-known and documented in public standards.
 */
#define T_COSE_CRYPTO_EC_P256_COORD_SIZE 32



/*
 * No function to get private key because there is no need for it.
 * The private signing key only needs to exist behind
 * t_cose_crypto_pub_key_sign().
 */


#define T_COSE_USE_OPENSSL_HASH
#undef T_COSE_USE_B_CON_SHA256

#ifdef T_COSE_USE_B_CON_SHA256
/* This is code for use with Brad Conte's crypto.  See
 * https://github.com/B-Con/crypto-algorithms and see the description
 * of t_cose_crypto_hash
 */
#include "sha256.h"
#endif

#ifdef T_COSE_USE_OPENSSL_HASH
#include "openssl/sha.h"
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

#ifdef T_COSE_USE_OPENSSL_HASH
    /* What is needed for a full proper integration of OpenSSL's hashes */
    /* The hash context goes on the stack. This is 224 bytes on 64-bit x86 */
    union {
        SHA256_CTX sha_256;
#if !defined T_COSE_DISABLE_ES512 || !defined T_COSE_DISABLE_ES384
        // SHA 384 uses the sha_512 context
        // This uses about 100 bytes above SHA-256
        SHA512_CTX sha_512;
#endif
    } ctx;

    int     update_error; /* Used to track error return by SHAXXX_Upate() */
    int32_t cose_hash_alg_id; /* COSE integer ID for the hash alg */

#else
#ifdef T_COSE_USE_B_CON_SHA256
    /* Specific context for Brad Conte's sha256.c */
    SHA256_CTX context;
#else
    /*
     *  Generic pointer / handle that can work for many
     *  hash implementations.
     */
    union {
        void    *ptr;
        uint64_t handle;
    } context;
    int64_t status;
#endif
#endif

};


/**
 * The size of the output of SHA-256, 384 & 512 in bytes.
 *
 * (It is safe to define these independently here as they are
 * well-known and fixed. There is no need to reference
 * platform-specific headers and incur messy dependence.)
 */
#define T_COSE_CRYPTO_SHA256_SIZE 32
#define T_COSE_CRYPTO_SHA384_SIZE 48
#define T_COSE_CRYPTO_SHA512_SIZE 64


/**
 * The maximum needed to hold a hash. It is smaller and less stack is used
 * if the larger hashes are disabled.
 */
#ifndef T_COSE_DISABLE_ES512
    #define T_COSE_CRYPTO_MAX_HASH_SIZE T_COSE_CRYPTO_SHA512_SIZE
#else
    #ifndef T_COSE_DISABLE_ES384
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
 *                          (https://www.iana.org/assignments/cose/cose.xhtml).
 *                              As of the creation of this interface
 *                              no identifiers of only a hash
 *                              functions have been registered.
 *                              Signature algorithms that include
 *                              specification of the hash have been
 *                              registered, but they are not to be
 *                              used here. Until hash functions only
 *                              have been officially registered, some
 *                              IDs are defined in the proprietary
 *                              space in t_cose_common.h.
 *
 * \retval T_COSE_ERR_UNSUPPORTED_HASH
 *         The requested algorithm is unknown or unsupported.
 *
 * \retval T_COSE_ERR_HASH_GENERAL_FAIL
 *         Some general failure of the hash function
 *
 * This initializes the hash context for the particular algorithm. It
 * must be called first. A \c hash_ctx can be reused if it is
 * reinitialized.
 */
enum t_cose_err_t
t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                         int32_t cose_hash_alg_id);


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
 * produce the real hash to be used to return a length of the would be
 * hash for encoded data structure size calculations.
 */
void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c data_to_hash);


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
 *
 * Call this to complete the hashing operation. If the everything
 * completed correctly, the resulting hash is returned. Note that any
 * errors that occurred during t_cose_crypto_hash_update() are
 * returned here.
 *
 * See the note in the Detailed Description (the \\file comment block)
 * for details on how \c q_useful_buf and \c q_useful_buf_c are used
 * to return the hash.
 */
enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf buffer_to_hold_result,
                          struct q_useful_buf_c *hash_result);



/*
 * Public inline function. See documentation above.
 */
static inline size_t t_cose_signature_size(int32_t cose_sig_alg_id)
{
    switch(cose_sig_alg_id) {
    case COSE_ALGORITHM_ES256:
        return T_COSE_EC_P256_SIG_SIZE;
#ifndef T_COSE_DISABLE_ES384
    case COSE_ALGORITHM_ES384:
        return T_COSE_EC_P384_SIG_SIZE;
#endif
#ifndef T_COSE_DISABLE_ES512
    case COSE_ALGORITHM_ES512:
        return T_COSE_EC_P512_SIG_SIZE;
#endif
    default:
        return 0;
    }
}


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_CRYPTO_H__ */
