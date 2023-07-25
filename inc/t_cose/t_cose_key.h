/*
 * t_cose_key.h
 *
 * Copyright 2019-2023, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Created by Laurence Lundblade on 2/6/23.
 *
 * See BSD-3-Clause license in README.md
 */


#ifndef t_cose_key_h
#define t_cose_key_h

#include <stdbool.h>
#include <stdint.h>
#include <t_cose/q_useful_buf.h>
#include "t_cose/t_cose_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file t_cose_key.h
 *
 * This file has several purposes:
 *
 * - The definition of struct t_cose_key, an abstraction of a
 *   cryptographic key.
 *
 * - APIs to initialize struct t_cose_key from common or
 *   standard key representations.
 *
 * -  Encoding and decoding of COSE_Key defined in RFC 9052.
 *
 * t_cose is designed to support multiple cryptographic
 * libraries. Cryptographic libraries have very different ways of
 * holding and handling keys. It is not possible to have a common
 * efficient representation of keys that is fully independent for all
 * the cryptographic libraries. Struct t_cose_key is an abstraction to
 * hold several representations (pointers, handles and buffers) so key
 * varying key representations can pass through t_cose to the library
 * to the underlying library. This is the one part of t_cose APIs that
 * is not independent of the cryptographic library.
 *
 * For example, OpenSSL’s representation of a symmetric key is a
 * pointer and a length. Mbed TLS’s representation is a key
 * handle. Struct t_cose_key is a union and can handle either of
 * these, but the user needs to know which and act accordingly.
 *
 * In typical use, the caller of t_cose will initialize a struct
 * t_cose_key with the right kind of key material for the
 * operation. For example, when creating a COSE_Sign, they might
 * initialize a t_cose_key with a private key for ECDSA
 * prime256v1. The steps to do this will be different for Mbed TLS
 * from OpenSSL because these two libraries have very different
 * representations for an EC key. Then the t_cose_key is passed to a
 * t_cose API which will pass it to the cryptographic libary for the
 * particular cryptographic operation.  t_cose itself does no
 * operation with the key.
 *
 * t_cose_key itself carries no type information. Any error checking
 * for the key type is in the cryptographic library. For example, if
 * you try to pass a symmetric key to a public key signing algorithm,
 * t_cose won’t notice, but the cryptographic library probably will
 * (such checking is left out of t_cose to keep code size and memory
 * use lower). Sometimes the error numbers for these errors may
 * be less than ideal because of the layers involved.
 *
 * For some cryptographic libraries, keys involve some allocation that
 * must be freed. This might be a memory pool (e.g., malloc) or a pool
 * of key handles. While some do not require this, it is better
 * practice to always free keys so that implementations are portable
 * to both libraries that require freeing and those that don’t
 * (libraries that don’t require freeing will provide a stub that does
 * nothing for freeing).
 *
 * Some libraries like Mbed TLS have mandatory key use policy and
 * other like OpenSSL have none. Both are accommodated.  COSE_Key also
 * is able to express some key use policy.
 *
 * When keys pass through t_cose completely, it is up to the caller to
 * set up the policy of the key for the anticipated use. For example,
 * when using Mbed TLS, a key that is passed to
 * t_cose_signature_sign_main_set_signing_key() for ECDSA signing
 * should be configured for use with the
 * PSA_ALG_ECDSA(PSA_ALG_SHA_256) algorithm and the
 * PSA_KEY_USAGE_SIGN_HASH usage.
 *
 * The abstraction provided by t_cose_key accommodates architectures
 * where the actual bytes for the key are behind a protection boundary
 * such as in an HSM. This support is an important design
 * characteristic of t_cose.
 *
 * When t_cose provides library-independent means to initialize a
 * t_cose_key such as t_cose_key_init_symmetric(), it will set up the
 * policy as best it can in a general way. It will take the COSE
 * algorithm ID and translate it to that for the library and set up
 * for expected key usage.
 *
 * Import/export for common/standard key serialization formats
 * supported here are intentionally limited to those that can be more
 * easily supported across all the cryptographic libraries to minimize
 * the work of porting to a new cryptographic library. For example,
 * symmetric keys are easy to support because they are always
 * representable as a byte string. Public key formats are messier
 * because there are multiple formats for representing them (e.g.,
 * PEM, DER, a point on a curve, …).  COSE_Key is the primary
 * serialization format that will be (is) supported here. This is a
 * COSE library not a general purpose crypto library.
 */




/**
 * This is the maximum key size for symmetric ciphers like AES and
 * ChaCha20 (not supported yet).  It also applies to key wrap.  It is
 * set to 32 to accommodate AES 256 and anything with a smaller key
 * size. This is used to size buffers that hold keys and buffers that
 * are related to key size.  Attempts to use a symmetric cipher key
 * size larger than this will result in an error.  Smaller keys sizes
 * are no problem.
 *
 * This primarily affects stack use, but is not a primary consumer of
 * stack. (Improvement: this could be made #ifdef conditional on which
 * algorithms are enabled, but it's not a high priority because it doesn't
 * use that much stack).
*/
#define T_COSE_MAX_SYMMETRIC_KEY_LENGTH 32


/**
 * This hold keys so they can pass through t_cose to the underlying
 * cryptographic library where they are used. It is used for all keys
 * for all algorithms in the t_cose API whether they are symmetric,
 * public or private.
 *
 * To fill this in, the particular use, key type and algorithm
 * expected must be know. Further, the cryptographic library and how
 * it uses this structure for a particular key and algorithm must be
 * known. Looking at the t_cose example code is probably most direct
 * path. Also see the general discussion for t_cose_key.h.
 *
 * Initializers are provided for some common or standard key
 * serialization formats.
 *
 * t_cose_key is initialized to 0 and/or NULL pointers if it is not
 * holding a key. Crypto adapters for libraries should honor this
 * if possible.
 */
struct t_cose_key {
    union {
        /** For libraries that use a pointer to the key or key handle. */
        void *ptr;

        /** For libraries that use an integer handle to the key. */
        uint64_t handle;

        /** For pointer and length of some memory the use of which is
         * up to the adapter layer. It could be just the bytes of the
         * key or it could be an elaborate structure. */
        struct q_useful_buf_c buffer;
    } key;
};

/*
 * (The crypto_lib member used in t_cose 1.x is dropped in 2.x because
 * it seems unnecessary and was not supported uniformly. It is
 * unneccessary because individual t_cose libraries are for a
 * particular crypto library and only one is supported at a time by
 * t_cose. Removal of the crypto_lib member also saves object code.)
 */




/**
 * \brief Initialize a  t_cose_key holding a symmetric key.
 *
 * \param[in] cose_algorithm_id   The algorithm with which the key is to be used.
 * \param[in] symmetric_key   Pointer and length of bytes in symmertic key.
 * \param[out] key   The t_cose_key to be initialize.
 *
 * This takes the bytes that make up a symmetric key and
 * makes a t_cose_key out of it in the form for use with the
 * current crypto library. This works for keys for AES (e.g.,   )
 * key wrap and HMAC  (e.g., ). For example, this can be used to
 * make a t_cose_key for t_cose_mac_set_computing_key(),
 * t_cose_encrypt_set_key(), t_cose_recipient_enc_keywrap_set_key()
 * and others APIs needing a symmetric
 * key.
 *
 * The lifetime of the bytes passed in for \c symmetric_key should
 * be longer than that of the key returned as it may reference the
 * bytes (It does for OpenSSL. Not sure for MbedTLS).
 *
 * For some crypto libraries, the key will only be usable for
 * the algorithm specfied. For other crypto libraries
 * there no is policy enforcement.
 *
 * The number of bits in \c symmetric_key should be the correct number
 * for the algorithm specified. An error will usually
 * be returned if it is not.
 *
 * See t_cose_key_free_symmetric().
 *
 * See \ref T_COSE_MAX_SYMMETRIC_KEY_LENGTH.
 */
enum t_cose_err_t
t_cose_key_init_symmetric(int32_t               cose_algorithm_id,
                          struct q_useful_buf_c symmetric_key,
                          struct t_cose_key     *key);


/**
 * \brief Free t_cose_key initialized by t_cose_key_init_symmetric()
 *
 * \param[in] key   The key to free.
 *
 * While not all crypto libraries require this call to be made, it
 * should be made by any code that is to be usable with multiple
 * crypto libraries.
 */
void
t_cose_key_free_symmetric(struct t_cose_key key);


#ifdef __cplusplus
}
#endif

#endif /* t_cose_key_h */
