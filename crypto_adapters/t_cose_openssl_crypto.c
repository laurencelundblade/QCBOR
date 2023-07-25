/*
 *  t_cose_openssl_crypto.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created 3/31/2019.
 */


#include "t_cose_crypto.h" /* The interface this code implements */

#include <openssl/ecdsa.h> /* Needed for signature format conversion */
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "t_cose_util.h"

/**
 * \file t_cose_openssl_crypto.c
 *
 * \brief Crypto Adaptation for t_cose to use OpenSSL ECDSA and hashes.
 *
 * This connects up the abstracted crypto services defined in
 * t_cose_crypto.h to the OpenSSL implementation of them.
 *
 * Having this adapter layer doesn't bloat the implementation as everything here
 * had to be done anyway -- the mapping of algorithm IDs, the data format
 * rearranging, the error code translation.
 *
 * This code should just work out of the box if compiled and linked
 * against OpenSSL and with the T_COSE_USE_OPENSSL_CRYPTO preprocessor
 * define set for the build.
 *
 * This works with OpenSSL 1.1.1 and 3.0. It uses the APIs common
 * to these two and that are not marked for future deprecation.
 *
 * A few complaints about OpenSSL in comparison to Mbed TLS:
 *
 * OpenSSL mallocs for various things where MBed TLS does not.
 * This makes the OpenSSL code more complex because checks for malloc
 * failures are necessary.
 *
 * There's a lot of APIs in OpenSSL, but there's a needle to thread to
 * get the APIS that are in 1.1.1, 3.0 and not slated for future
 * deprecation.
 *
 * The APIs that fit the above only work for DER-encoded signatures.
 * t_cose encodes signatures in a more simple way. This difference
 * requires the code here to do conversion which increases its size
 * and complexity and requires intermediate buffers and requires more
 * use of malloc.
 *
 * An older version of t_cose (anything from 2021) uses simpler
 * OpenSSL APIs. They still work but may be deprecated in the
 * future. They could be used in use cases where a particular version
 * of the OpenSSL library is selected and reduce code size
 * a llittle.
 */

/*
 * See documentation in t_cose_crypto.h
 *
 * This will typically not be referenced and thus not linked,
 * for deployed code. This is mainly used for test.
 */
bool t_cose_crypto_is_algorithm_supported(int32_t cose_algorithm_id)
{
    static const int32_t supported_algs[] = {
        T_COSE_ALGORITHM_SHA_256,
        T_COSE_ALGORITHM_SHA_384,
        T_COSE_ALGORITHM_SHA_512,
        T_COSE_ALGORITHM_ES256,
#ifndef T_COSE_DISABLE_ES384
        T_COSE_ALGORITHM_ES384,
#endif
#ifndef T_COSE_DISABLE_ES512
        T_COSE_ALGORITHM_ES512,
#endif
#ifndef T_COSE_DISABLE_PS256
        T_COSE_ALGORITHM_PS256,
#endif
#ifndef T_COSE_DISABLE_PS384
        T_COSE_ALGORITHM_PS384,
#endif
#ifndef T_COSE_DISABLE_PS512
        T_COSE_ALGORITHM_PS512,
#endif
        T_COSE_ALGORITHM_EDDSA,
        T_COSE_ALGORITHM_A128GCM,
        T_COSE_ALGORITHM_A192GCM,
        T_COSE_ALGORITHM_A256GCM,

#ifndef T_COSE_DISABLE_KEYWRAP
        T_COSE_ALGORITHM_A128KW,
        T_COSE_ALGORITHM_A192KW,
        T_COSE_ALGORITHM_A256KW,
#endif /* T_COSE_DISABLE_KEYWRAP */

        T_COSE_ALGORITHM_HMAC256,
        T_COSE_ALGORITHM_HMAC384,
        T_COSE_ALGORITHM_HMAC512,

        T_COSE_ALGORITHM_NONE /* List terminator */
    };

    return t_cose_check_list(cose_algorithm_id, supported_algs);
}


/* Map COSE hash algorithm ID to OpenSSL EVP_MD.
 * Returns NULL for unsupported algorithm.
 * This uses nid and  EVP_get_digestbynid() because
 * it is the least amount of object code and works for
 * OpenSSL 1.1.1 and 3.0. EVP_sha256() and friends work,
 * but will be more function calls. EVP_MD_fetch() is
 * the fancy new way, but doesn't work in OpenSSL 1.1.1.
 * EVP_MD_fetch() would allow use of different engines
 * rather than the basic default, but that doesn't seem
 * necessary. */
static const EVP_MD *
cose_hash_alg_to_ossl(int32_t cose_hash_alg_id)
{
    int nid;

    /*  switch() is less object code than t_cose_int16_map(). */
    switch(cose_hash_alg_id) {
        case T_COSE_ALGORITHM_SHA_256:
            nid = NID_sha256;
            break;

#if !defined(T_COSE_DISABLE_ES384) || !defined(T_COSE_DISABLE_PS384)
        case T_COSE_ALGORITHM_SHA_384:
            nid = NID_sha384;
            break;
#endif

#if !defined(T_COSE_DISABLE_ES512) || !defined(T_COSE_DISABLE_PS512)
        case T_COSE_ALGORITHM_SHA_512:
            nid = NID_sha512;
            break;
#endif

        default:
            return NULL;
    }

    return EVP_get_digestbynid(nid);
}

/* As cose_hash_alg_to_ossl(), but for HMAC algorithms. */
static const EVP_MD *
cose_hmac_alg_to_ossl(int32_t cose_hmac_alg_id)
{
    int nid;

    /*  switch() is less object code than t_cose_int16_map(). */
    switch(cose_hmac_alg_id) {
        case T_COSE_ALGORITHM_HMAC256:
            nid = NID_sha256;
            break;

        case T_COSE_ALGORITHM_HMAC384:
            nid = NID_sha384;
            break;

        case T_COSE_ALGORITHM_HMAC512:
            nid = NID_sha512;
            break;

        default:
            return NULL;
    }

    return EVP_get_digestbynid(nid);
}


/* OpenSSL archaically uses int for lengths in some APIs. t_cose
 * properly use size_t for lengths. While it is unlikely that this
 * will ever be an issue because lengths are unlikely to be near
 * SIZE_MAX or INT_MAX, this code is written for full correctness and
 * to fully pass static analyzers. This requires checks before casting
 * from int to size_t and vice versa.
 *
 * This function returns true if the value x can be safely cast to an
 * integer.
 *
 * It shouldn't generate much object code (and if you really want you
 * could just make it return true always and it would generate no
 * object code).  In particular compilers will know if SIZE_MAX >
 * INT_MAX at compile time so half of this function is excluded.
 *
 * Note that it is allowed for INT_MAX to be 32,767. It is not out of
 * the question that a ciphertext or plaintext is larger than
 * that. Even though such a small INT_MAX is rare, the full
 * correctness of this code requires the checks implemented here.
 *
 * See also is_int_to_size_t_cast_ok().
 *
 * It is really unfortunate that OpenSSL is like this (and has other
 * issues).  See the AEAD crypto adapters for MbedTLS/PSA. They are
 * less than half the code and complexity.
 *
 * https://stackoverflow.com/questions/1819189/what-range-of-values-can-integer-types-store-in-c
 * https://stackoverflow.com/questions/131803/unsigned-int-vs-size-t
 */
static inline bool
is_size_t_to_int_cast_ok(size_t x)
{
#if SIZE_MAX > INT_MAX
    /* The common case on a typical 64 or 32-bit CPU where SIZE_MAX is
     * 0xffffffffffffffff or 0xffffffff and INT_MAX is 0x7fffffff.
     */
    if(x > INT_MAX) {
        return false;
    } else {
        return true;
    }
#else
    /* It would be very weird for INT_MAX to be larger than SIZE_MAX,
     * but it is allowed by the C standard and this code aims for
     * correctness against the C standard. If this happens a size_t
     * always fits in an int.
     */
    return true;
#endif /* SIZE_MAX > INT_MAX */
}

#ifndef T_COSE_DISABLE_KEYWRAP
static inline bool
is_size_t_to_uint_cast_ok(size_t x)
{
#if SIZE_MAX > UNT_MAX
    /* The common case on a typical 64 or 32-bit CPU where SIZE_MAX is
     * 0xffffffffffffffff or 0xffffffff and INT_MAX is 0x7fffffff.
     */
    if(x > UINT_MAX) {
        return false;
    } else {
        return true;
    }
#else
    /* It would be very weird for INT_MAX to be larger than SIZE_MAX,
     * but it is allowed by the C standard and this code aims for
     * correctness against the C standard. If this happens a size_t
     * always fits in an int.
     */
    return true;
#endif /* SIZE_MAX > INT_MAX */
}
#endif /* T_COSE_DISABLE_KEYWRAP */


/* See is_size_t_to_int_cast_ok() */
static inline bool
is_int_to_size_t_cast_ok(int x)
{
#if SIZE_MAX > INT_MAX
    /* The common case on a typical 64 or 32-bit CPU where SIZE_MAX is
     * 0xffffffffffffffff or 0xffffffff and INT_MAX is 0x7fffffff.
     */
    if(x < 0) {
        return false;
    } else {
        return true;
    }
#else
    /* It would be very weird for INT_MAX to be larger than SIZE_MAX,
     * but it is allowed by the C standard and this code aims for
     * correctness against the C standard. */
    if(x < 0 || x > (int)SIZE_MAX) {
        return false;
    } else {
        return true;
    }
#endif /* SIZE_MAX > INT_MAX */
}


/**
 * \brief Get the rounded-up size of an ECDSA key in bytes.
 */
static unsigned ecdsa_key_size(EVP_PKEY *key_evp)
{
    int      key_len_bits;
    unsigned key_len_bytes;

    key_len_bits = EVP_PKEY_bits(key_evp);

    /* Calculation of size per RFC 8152 section 8.1 -- round up to
     * number of bytes. */
    key_len_bytes = (unsigned)key_len_bits / 8;
    if(key_len_bits % 8) {
        key_len_bytes++;
    }

    return key_len_bytes;
}


/**
 * \brief Convert DER-encoded ECDSA signature to COSE-serialized signature
 *
 * \param[in] key_evp             The key used to produce the DER signature.
 * \param[in] der_signature       DER-encoded signature.
 * \param[in] signature_buffer    The buffer for output.
 *
 * \return The pointer and length of serialized signature in \c signature_buffer
           or NULL_Q_USEFUL_BUF_C on error.
 *
 * The serialized format is defined by COSE in RFC 8152 section
 * 8.1. The signature which consist of two integers, r and s,
 * are simply zero padded to the nearest byte length and
 * concatenated.
 */
static inline struct q_useful_buf_c
ecdsa_signature_der_to_cose(EVP_PKEY              *key_evp,
                            struct q_useful_buf_c  der_signature,
                            struct q_useful_buf    signature_buffer)
{
    unsigned              key_len;
    size_t                r_len;
    size_t                s_len;
    const BIGNUM         *r_bn;
    const BIGNUM         *s_bn;
    struct q_useful_buf_c cose_signature;
    void                 *r_start_ptr;
    void                 *s_start_ptr;
    const unsigned char  *temp_der_sig_pointer;
    ECDSA_SIG            *es;

    key_len = ecdsa_key_size(key_evp);

    /* Put DER-encoded sig into an ECDSA_SIG so we can get the r and s out. */
    temp_der_sig_pointer = der_signature.ptr;
    es = d2i_ECDSA_SIG(NULL, &temp_der_sig_pointer, (long)der_signature.len);
    if(es == NULL) {
        cose_signature = NULL_Q_USEFUL_BUF_C;
        goto Done;
    }

    /* Zero the buffer so that bytes r and s are padded with zeros */
    q_useful_buf_set(signature_buffer, 0);

    /* Get the signature r and s as BIGNUMs */
    r_bn = NULL;
    s_bn = NULL;
    ECDSA_SIG_get0(es, &r_bn, &s_bn);
    /* ECDSA_SIG_get0 returns void */


    /* Internal consistency check that the r and s values will fit
     * into the expected size. Be sure the output buffer is not
     * overrun.
     */
    /* Cast is safe because BN_num_bytes() is documented to not return
     * negative numbers.
     */
    r_len = (size_t)BN_num_bytes(r_bn);
    s_len = (size_t)BN_num_bytes(s_bn);
    if(r_len + s_len > signature_buffer.len) {
        cose_signature = NULL_Q_USEFUL_BUF_C;
        goto Done2;
    }

    /* Copy r and s of signature to output buffer and set length */
    r_start_ptr = (uint8_t *)(signature_buffer.ptr) + key_len - r_len;
    BN_bn2bin(r_bn, r_start_ptr);

    s_start_ptr = (uint8_t *)signature_buffer.ptr + 2 * key_len - s_len;
    BN_bn2bin(s_bn, s_start_ptr);

    cose_signature = (UsefulBufC){signature_buffer.ptr, 2 * key_len};

Done2:
    ECDSA_SIG_free(es);

Done:
    return cose_signature;
}


/**
 * \brief Convert COSE-serialized ECDSA signature to DER-encoded signature.
 *
 * \param[in] key_evp         Key that will be used to verify the signature.
 * \param[in] cose_signature  The COSE-serialized signature.
 * \param[in] buffer          Place to write DER-format signature.
 * \param[out] der_signature  The returned DER-encoded signature
 *
 * \return one of the \ref t_cose_err_t error codes.
 *
 * The serialized format is defined by COSE in RFC 8152 section
 * 8.1. The signature which consist of two integers, r and s,
 * are simply zero padded to the nearest byte length and
 * concatenated.
 *
 * OpenSSL has a preference for DER-encoded signatures.
 *
 * This uses an ECDSA_SIG as an intermediary to convert
 * between the two.
 */
static enum t_cose_err_t
ecdsa_signature_cose_to_der(EVP_PKEY              *key_evp,
                            struct q_useful_buf_c  cose_signature,
                            struct q_useful_buf    buffer,
                            struct q_useful_buf_c *der_signature)
{
    unsigned          key_len;
    enum t_cose_err_t return_value;
    BIGNUM           *signature_r_bn = NULL;
    BIGNUM           *signature_s_bn = NULL;
    int               ossl_result;
    ECDSA_SIG        *signature;
    unsigned char    *der_signature_ptr;
    int               der_signature_len;

    key_len = ecdsa_key_size(key_evp);

    /* Check the signature length against expected */
    if(cose_signature.len != key_len * 2) {
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    }

    /* Put the r and the s from the signature into big numbers */
    signature_r_bn = BN_bin2bn(cose_signature.ptr, (int)key_len, NULL);
    if(signature_r_bn == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    signature_s_bn = BN_bin2bn(((const uint8_t *)cose_signature.ptr)+key_len,
                                    (int)key_len,
                                    NULL);
    if(signature_s_bn == NULL) {
        BN_free(signature_r_bn);
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Put the signature bytes into an ECDSA_SIG */
    signature = ECDSA_SIG_new();
    if(signature == NULL) {
        /* Don't leak memory in error condition */
        BN_free(signature_r_bn);
        BN_free(signature_s_bn);
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Put the r and s bignums into an ECDSA_SIG. Freeing
     * ossl_sig_to_verify will now free r and s.
     */
    ossl_result = ECDSA_SIG_set0(signature,
                                 signature_r_bn,
                                 signature_s_bn);
    if(ossl_result != 1) {
        BN_free(signature_r_bn);
        BN_free(signature_s_bn);
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Now output the ECDSA_SIG structure in DER format.
     *
     * Code safety is the priority here.  i2d_ECDSA_SIG() has two
     * output buffer modes, one where it just writes to the buffer
     * given and the other were it allocates memory.  It would be
     * better to avoid the allocation, but the copy mode is not safe
     * because you can't give it a buffer length. This is bad stuff
     * from last century.
     *
     * So the allocation mode is used on the presumption that it is
     * safe and correct even though there is more copying and memory
     * use.
     */
    der_signature_ptr = NULL;
    der_signature_len = i2d_ECDSA_SIG(signature, &der_signature_ptr);
    ECDSA_SIG_free(signature);
    if(der_signature_len < 0) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    *der_signature = q_useful_buf_copy_ptr(buffer,
                                           der_signature_ptr,
                                           (size_t)der_signature_len);
    if(q_useful_buf_c_is_null_or_empty(*der_signature)) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    OPENSSL_free(der_signature_ptr);

    return_value = T_COSE_SUCCESS;

Done:
    /* All the memory frees happen along the way in the code above. */
    return return_value;
}


/**
 * \brief Common checks and conversions for signing and verification key.
 *
 * \param[in] t_cose_key                 The key to check and convert.
 * \param[out] return_ossl_ec_key        The OpenSSL key in memory.
 *
 * \return Error or \ref T_COSE_SUCCESS.
 *
 * It pulls the OpenSSL key out of \c t_cose_key and checks it.
 */
static enum t_cose_err_t
key_convert(struct t_cose_key  t_cose_key, EVP_PKEY **return_ossl_ec_key)
{
    enum t_cose_err_t  return_value;

    /* Check the signing key and get it out of the union */
    if(t_cose_key.key.ptr == NULL) {
        return_value = T_COSE_ERR_EMPTY_KEY;
        goto Done;
    }
    *return_ossl_ec_key = (EVP_PKEY *)t_cose_key.key.ptr;

    return_value = T_COSE_SUCCESS;

Done:
    return return_value;
}


static bool
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


static bool
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

/*
 * Public Interface. See documentation in t_cose_crypto.h
 */
enum t_cose_err_t t_cose_crypto_sig_size(int32_t           cose_algorithm_id,
                                         struct t_cose_key signing_key,
                                         size_t           *sig_size)
{
    enum t_cose_err_t return_value;
    EVP_PKEY         *signing_key_evp;

    return_value = key_convert(signing_key, &signing_key_evp);
    if(return_value != T_COSE_SUCCESS) {
        return return_value;
    }

    // TODO: see if EVP works for all key sizes and/or if other means of
    // checking algorithm so t_cose_algorithm_is can be elimiated here (like it is for PSA)
    if(t_cose_algorithm_is_ecdsa(cose_algorithm_id)) {
        /* EVP_PKEY_size is not suitable because it returns the size
         * of the DER-encoded signature, which is larger than the COSE
         * signatures.
         *
         * We instead compute the size ourselves based on the COSE
         * encoding of two r and s values, each the same size as the key.
         */
        *sig_size = ecdsa_key_size(signing_key_evp) * 2;
        return_value = T_COSE_SUCCESS;
        goto Done;
    } else if (t_cose_algorithm_is_rsassa_pss(cose_algorithm_id)
            || cose_algorithm_id == T_COSE_ALGORITHM_EDDSA) {
        *sig_size = (size_t)EVP_PKEY_size(signing_key_evp);
        return_value = T_COSE_SUCCESS;
        goto Done;
    } else {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

Done:
    return return_value;
}


/* Return algorithm ID for hash used with a particular RSA algorithm ID */
static int32_t
rsa_alg_to_hash_alg(int32_t rsa_alg)
{
    int32_t cose_hash_alg_map[] = {T_COSE_ALGORITHM_SHA_512,
                                   T_COSE_ALGORITHM_SHA_384,
                                   T_COSE_ALGORITHM_SHA_256};

    int32_t x = rsa_alg - T_COSE_ALGORITHM_PS512;

    if(x < 0 || x > 3) {
        return T_COSE_ALGORITHM_NONE;
    }

    return cose_hash_alg_map[x];
}


/**
 * \brief Configure an EVP_PKEY_CTX for a given algorithm.
 *
 * \param[in] context            The OpenSSL context to configure.
 * \param[in] cose_algorithm_id  The algorithm ID.
 *
 * \return Error or \ref T_COSE_SUCCESS.
 */
static enum t_cose_err_t
configure_pkey_context(EVP_PKEY_CTX* context, int32_t cose_algorithm_id)
{
    enum t_cose_err_t return_value;
    const EVP_MD     *message_digest;
    int               ossl_result;


    if (t_cose_algorithm_is_ecdsa(cose_algorithm_id)) {
        /* ECDSA doesn't need any further configuration of its context.
         * The parameters are inferred from the key.
         */
        return_value = T_COSE_SUCCESS;
    } else if (t_cose_algorithm_is_rsassa_pss(cose_algorithm_id)) {
        /**
         * These parameters are specified in Section 2 of RFC8230.
         * In a nutshell:
         * - PSS padding
         * - MGF1 mask generation, using the same hash function used to digest
         *   the message.
         * - Salt length should match the size of the output of the hash
         *   function.
         */

        message_digest = cose_hash_alg_to_ossl(rsa_alg_to_hash_alg(cose_algorithm_id));
        if(message_digest == NULL) {
            return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
            goto Done;
        }

        ossl_result = EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PSS_PADDING);
        if(ossl_result != 1) {
            return_value = T_COSE_ERR_SIG_FAIL;
            goto Done;
        }

        /* EVP_PKEY_CTX_set_signature_md and EVP_PKEY_CTX_set_rsa_mgf1_md are
         * macro wrappers around the EVP_PKEY_CTX_ctrl function, and cast
         * the `const EVP_MD*` argument into a void*. This would cause a
         * cast-qual warning, if not for the pragmas. Clang supports GCC
         * pragmas, so it works on clang too.
         */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
        ossl_result = EVP_PKEY_CTX_set_signature_md(context, message_digest);
        if(ossl_result != 1) {
            return_value = T_COSE_ERR_SIG_FAIL;
            goto Done;
        }

        ossl_result = EVP_PKEY_CTX_set_rsa_mgf1_md(context, message_digest);
        if(ossl_result != 1) {
            return_value = T_COSE_ERR_SIG_FAIL;
            goto Done;
        }
#pragma GCC diagnostic pop

        ossl_result = EVP_PKEY_CTX_set_rsa_pss_saltlen(context, RSA_PSS_SALTLEN_DIGEST);
        if(ossl_result != 1) {
            return_value = T_COSE_ERR_SIG_FAIL;
            goto Done;
        }

        return_value = T_COSE_SUCCESS;
    } else {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }


Done:
    return return_value;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_sign(const int32_t                cose_algorithm_id,
                   const struct t_cose_key      signing_key,
                   void                        *crypto_context,
                   const struct q_useful_buf_c  hash_to_sign,
                   const struct q_useful_buf    signature_buffer,
                   struct q_useful_buf_c       *signature)
{
    /* This is the overhead for the DER encoding of an EC signature as
     * described by ECDSA-Sig-Value in RFC 3279.  It is at max 3 * (1
     * type byte and 2 length bytes) + 2 zero pad bytes = 11
     * bytes. We make it 16 to have a little extra. It is expected that
     * EVP_PKEY_sign() will not over write the buffer so there will
     * be no security problem if this is too short. */
    #define DER_SIG_ENCODE_OVER_HEAD 16

    enum t_cose_err_t      return_value;
    EVP_PKEY_CTX          *sign_context;
    EVP_PKEY              *signing_key_evp;
    int                    ossl_result;

    (void)crypto_context; /* This crypto adaptor doesn't use this */

    /* This buffer is passed to OpenSSL to write the ECDSA signature into, in
     * DER format, before it can be converted to the expected COSE format. When
     * RSA signing is selected, this buffer is unused since OpenSSL's output is
     * suitable for use in COSE directly.
     */
    MakeUsefulBufOnStack(  der_format_signature, T_COSE_MAX_ECDSA_SIG_SIZE + DER_SIG_ENCODE_OVER_HEAD);

    /* This implementation supports only ECDSA so far. The
     * interface allows it to support other, but none are implemented.
     *
     * This implementation works for different key lengths and
     * curves. That is, the curve and key length is associated with
     * the signing_key passed in, not the cose_algorithm_id This
     * check looks for ECDSA signing as indicated by COSE and rejects
     * what is not since it only supports ECDSA.
     */
    if(!t_cose_algorithm_is_ecdsa(cose_algorithm_id) &&
       !t_cose_algorithm_is_rsassa_pss(cose_algorithm_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done2;
    }

    /* Pull the pointer to the OpenSSL-format EVP_PKEY out of the
     * t_cose key structure. */
    return_value = key_convert(signing_key, &signing_key_evp);
    if(return_value != T_COSE_SUCCESS) {
        goto Done2;
    }

    /* Create and initialize the OpenSSL EVP_PKEY_CTX that is the
     * signing context. */
    sign_context = EVP_PKEY_CTX_new(signing_key_evp, NULL);
    if(sign_context == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }
    ossl_result = EVP_PKEY_sign_init(sign_context);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    return_value = configure_pkey_context(sign_context, cose_algorithm_id);
    if (return_value) {
        goto Done;
    }

    /* Actually do the signature operation.  */
    if (t_cose_algorithm_is_ecdsa(cose_algorithm_id)) {
        ossl_result = EVP_PKEY_sign(sign_context,
                                    der_format_signature.ptr,
                                    &der_format_signature.len,
                                    hash_to_sign.ptr,
                                    hash_to_sign.len);
        if(ossl_result != 1) {
            return_value = T_COSE_ERR_SIG_FAIL;
            goto Done;
        }

        /* The signature produced by OpenSSL is DER-encoded. That encoding
         * has to be removed and turned into the serialization format used
         * by COSE. It is unfortunate that the OpenSSL APIs that create
         * signatures that are not in DER-format are slated for
         * deprecation.
         */
        *signature = ecdsa_signature_der_to_cose(
                signing_key_evp,
                q_usefulbuf_const(der_format_signature),
                signature_buffer);

        if(q_useful_buf_c_is_null(*signature)) {
            return_value = T_COSE_ERR_SIG_FAIL;
            goto Done;
        }

        return_value = T_COSE_SUCCESS;
    } else if (t_cose_algorithm_is_rsassa_pss(cose_algorithm_id)) {
        /* signature->len gets adjusted to match just the signature size.
         */
        *signature = q_usefulbuf_const(signature_buffer);
        ossl_result = EVP_PKEY_sign(sign_context,
                                    signature_buffer.ptr,
                                    &signature->len,
                                    hash_to_sign.ptr,
                                    hash_to_sign.len);

        if(ossl_result != 1) {
          return_value = T_COSE_ERR_SIG_FAIL;
          goto Done;
        }

        return_value = T_COSE_SUCCESS;
    } else {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

Done:
    /* This checks for NULL before free, so it is not
     * necessary to check for NULL here.
     */
    EVP_PKEY_CTX_free(sign_context);

Done2:
    return return_value;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_verify(const int32_t                cose_algorithm_id,
                     const struct t_cose_key      verification_key,
                     void                        *crypto_context,
                     const struct q_useful_buf_c  hash_to_verify,
                     const struct q_useful_buf_c  cose_signature)
{
    int                    ossl_result;
    enum t_cose_err_t      return_value;
    EVP_PKEY_CTX          *verify_context = NULL;
    EVP_PKEY              *verification_key_evp;

    /* This buffer is used to convert COSE ECDSA signature to DER format,
     * before it can be consumed by OpenSSL. When RSA signatures are
     * selected the buffer is unused.
     */
    MakeUsefulBufOnStack(  der_format_buffer, T_COSE_MAX_ECDSA_SIG_SIZE + DER_SIG_ENCODE_OVER_HEAD);

    /* This is the signature that will be passed to OpenSSL. It will either
     * point to `cose_signature`, or into `der_format_buffer`, depending on
     * whether an RSA or ECDSA signature is used
     */
    struct q_useful_buf_c  openssl_signature;

    (void)crypto_context; /* This crypto adaptor doesn't use this */

    if(!t_cose_algorithm_is_ecdsa(cose_algorithm_id) &&
       !t_cose_algorithm_is_rsassa_pss(cose_algorithm_id)) {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    /* Get the verification key in an EVP_PKEY structure which is what
     * is needed for sig verification. */
    return_value = key_convert(verification_key, &verification_key_evp);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if (t_cose_algorithm_is_ecdsa(cose_algorithm_id)) {
        /* Unfortunately the officially supported OpenSSL API supports
         * only DER-encoded signatures so the COSE format ECDSA signatures must
         * be converted to DER for verification. This requires a temporary
         * buffer and a fair bit of work inside ecdsa_signature_cose_to_der().
         */
        return_value = ecdsa_signature_cose_to_der(verification_key_evp,
                                                   cose_signature,
                                                   der_format_buffer,
                                                   &openssl_signature);
        if(return_value) {
          goto Done;
        }
    } else if (t_cose_algorithm_is_rsassa_pss(cose_algorithm_id)) {
        /* COSE RSA signatures are already in the format OpenSSL
         * expects, they can be used without any re-encoding.
         */
        openssl_signature = cose_signature;
    } else {
        return_value = T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
        goto Done;
    }

    /* Create the verification context and set it up with the
     * necessary verification key.
     */
    verify_context = EVP_PKEY_CTX_new(verification_key_evp, NULL);
    if(verify_context == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    ossl_result = EVP_PKEY_verify_init(verify_context);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    return_value = configure_pkey_context(verify_context, cose_algorithm_id);
    if (return_value) {
        goto Done;
    }

    /* Actually do the signature verification */
    ossl_result =  EVP_PKEY_verify(verify_context,
                                   openssl_signature.ptr,
                                   openssl_signature.len,
                                   hash_to_verify.ptr,
                                   hash_to_verify.len);


    if(ossl_result == 0) {
        /* The operation succeeded, but the signature doesn't match */
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    } else if (ossl_result != 1) {
        /* Failed before even trying to verify the signature */
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Everything succeeded */
    return_value = T_COSE_SUCCESS;

Done:
    EVP_PKEY_CTX_free(verify_context);

    return return_value;
}





/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                         int32_t                    cose_hash_alg_id)
{
    int           ossl_result;
    const EVP_MD *message_digest;

    message_digest = cose_hash_alg_to_ossl(cose_hash_alg_id);
    if(message_digest == NULL){
        return T_COSE_ERR_UNSUPPORTED_HASH;
    }

    hash_ctx->evp_ctx = EVP_MD_CTX_new();
    if(hash_ctx->evp_ctx == NULL) {
        return T_COSE_ERR_INSUFFICIENT_MEMORY;
    }

    ossl_result = EVP_DigestInit_ex(hash_ctx->evp_ctx, message_digest, NULL);
    if(ossl_result == 0) {
        EVP_MD_CTX_free(hash_ctx->evp_ctx);
        return T_COSE_ERR_HASH_GENERAL_FAIL;
    }

    hash_ctx->update_error = 1; /* 1 is success in OpenSSL */

    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
void
t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf_c data_to_hash)
{
    if(hash_ctx->update_error) { /* 1 is no error, 0 means error for OpenSSL */
        if(data_to_hash.ptr) {
            hash_ctx->update_error = EVP_DigestUpdate(hash_ctx->evp_ctx,
                                                      data_to_hash.ptr,
                                                      data_to_hash.len);
        }
    }
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf        buffer_to_hold_result,
                          struct q_useful_buf_c     *hash_result)
{
    int          ossl_result;
    unsigned int hash_result_len;

    if(!hash_ctx->update_error) {
        EVP_MD_CTX_free(hash_ctx->evp_ctx);
        return T_COSE_ERR_HASH_GENERAL_FAIL;
    }

    // TODO: know what the correct hash size is and error out of buffer is too small
    hash_result_len = (unsigned int)buffer_to_hold_result.len;
    ossl_result = EVP_DigestFinal_ex(hash_ctx->evp_ctx,
                                     buffer_to_hold_result.ptr,
                                     &hash_result_len);

    *hash_result = (UsefulBufC){buffer_to_hold_result.ptr, hash_result_len};

    EVP_MD_CTX_free(hash_ctx->evp_ctx);

    /* OpenSSL returns 1 for success, not 0 */
    return ossl_result ? T_COSE_SUCCESS : T_COSE_ERR_HASH_GENERAL_FAIL;
}




/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hmac_compute_setup(struct t_cose_crypto_hmac *hmac_ctx,
                                 struct t_cose_key          signing_key,
                                 const int32_t              cose_alg_id)
{
    int                         ossl_result;
    const EVP_MD               *message_digest;
    Q_USEFUL_BUF_MAKE_STACK_UB( key_buf, T_COSE_CRYPTO_HMAC_MAX_KEY);
    struct q_useful_buf_c       key_bytes;
    enum t_cose_err_t           result;

    message_digest = cose_hmac_alg_to_ossl(cose_alg_id);
    if(message_digest == NULL) {
        return T_COSE_ERR_UNSUPPORTED_HMAC_ALG;
    }

    result = t_cose_crypto_export_symmetric_key(signing_key, /* in: key to export */
                                                key_buf,     /* in: buffer to write to */
                                               &key_bytes); /* out: exported key */
    if(result != T_COSE_SUCCESS) {
        /* This happens when the key is bigger than T_COSE_CRYPTO_HMAC_MAX_KEY */
        return T_COSE_ERR_UNSUPPORTED_KEY_LENGTH;
    }

    hmac_ctx->evp_ctx = EVP_MD_CTX_new();
    if(hmac_ctx->evp_ctx == NULL) {
        return T_COSE_ERR_INSUFFICIENT_MEMORY;
    }

    /* The cast from size_t to int is safe because t_cose_crypto_export_symmetric_key()
     * will never return a key larger than T_COSE_CRYPTO_HMAC_MAX_KEY because
     * that is the size of its input buffer as defined above/here. */
    hmac_ctx->evp_pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,       /* in: type */
                                              NULL,                /* in: engine */
                                              key_bytes.ptr,       /* in: key */
                                              (int)key_bytes.len); /* in: keylen */
    if(hmac_ctx->evp_pkey == NULL) {
        EVP_MD_CTX_free(hmac_ctx->evp_ctx);
        return T_COSE_ERR_INSUFFICIENT_MEMORY;
    }

    /* EVP_MAC is not used because it is not available in OpenSSL 1.1. */

    ossl_result = EVP_DigestSignInit(hmac_ctx->evp_ctx, /* in: ctx -- EVP Context to initialize */
                                     NULL,  /* in/out: pctx */
                                     message_digest, /* in: type Digest function/type/algorithm */
                                     NULL,  /* in: Engine -- not used */
                                     hmac_ctx->evp_pkey); /* in: pkey -- the HMAC key */
    if(ossl_result != 1) {
        EVP_MD_CTX_free(hmac_ctx->evp_ctx);
        return T_COSE_ERR_HMAC_GENERAL_FAIL;
    }

    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hmac_update(struct t_cose_crypto_hmac *hmac_ctx,
                          struct q_useful_buf_c      payload)
{
    int  ossl_result;

    ossl_result = EVP_DigestSignUpdate(hmac_ctx->evp_ctx, payload.ptr, payload.len);
    if(ossl_result != 1) {
        return T_COSE_ERR_HMAC_GENERAL_FAIL;
    }

    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hmac_compute_finish(struct t_cose_crypto_hmac *hmac_ctx,
                                  struct q_useful_buf        tag_buf,
                                  struct q_useful_buf_c     *tag)
{
    int    ossl_result;
    size_t in_out_len;

    in_out_len = tag_buf.len;
    ossl_result = EVP_DigestSignFinal(hmac_ctx->evp_ctx, tag_buf.ptr, &in_out_len);

    EVP_MD_CTX_free(hmac_ctx->evp_ctx);
    EVP_PKEY_free(hmac_ctx->evp_pkey);

    if(ossl_result != 1) {
        return T_COSE_ERR_HMAC_GENERAL_FAIL;
    }

    tag->ptr = tag_buf.ptr;
    tag->len = in_out_len;

    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
// TODO: argument order alignment with t_cose_crypto_hmac_compute_setup
enum t_cose_err_t
t_cose_crypto_hmac_validate_setup(struct t_cose_crypto_hmac *hmac_ctx,
                                  const  int32_t             cose_alg_id,
                                  struct t_cose_key          validation_key)
{
    return t_cose_crypto_hmac_compute_setup(hmac_ctx, validation_key, cose_alg_id);
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hmac_validate_finish(struct t_cose_crypto_hmac *hmac_ctx,
                                   struct q_useful_buf_c      input_tag)
{
    Q_USEFUL_BUF_MAKE_STACK_UB( tag_buf, T_COSE_CRYPTO_HMAC_TAG_MAX_SIZE);
    struct q_useful_buf_c       computed_tag;
    enum t_cose_err_t           result;

    result = t_cose_crypto_hmac_compute_finish(hmac_ctx, tag_buf, &computed_tag);
    if(result != T_COSE_SUCCESS) {
        return result;
    }

    if(q_useful_buf_compare(computed_tag, input_tag)) {
        return T_COSE_ERR_HMAC_VERIFY;
    }

    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_sign_eddsa(struct t_cose_key      signing_key,
                         void                  *crypto_context,
                         struct q_useful_buf_c  tbs,
                         struct q_useful_buf    signature_buffer,
                         struct q_useful_buf_c *signature)
{
    enum t_cose_err_t return_value;
    int               ossl_result;
    EVP_MD_CTX       *sign_context = NULL;
    EVP_PKEY         *signing_key_evp;

    (void)crypto_context; /* This crypto adaptor doesn't use this */

    return_value = key_convert(signing_key, &signing_key_evp);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    sign_context = EVP_MD_CTX_new();
    if(sign_context == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    ossl_result = EVP_DigestSignInit(sign_context,
                                     NULL,
                                     NULL,
                                     NULL,
                                     signing_key_evp);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    *signature = q_usefulbuf_const(signature_buffer);
    /** Must use EVP_DigestSign rather than EVP_PKEY_verify, since
     * the tbs data is not hashed yet. Because of how EdDSA works, we
     * cannot hash the data ourselves separately.
     */
    ossl_result = EVP_DigestSign(sign_context,
                                 signature_buffer.ptr,
                                 &signature->len,
                                 tbs.ptr,
                                 tbs.len);
    if (ossl_result != 1) {
        /* Failed before even trying to verify the signature */
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Everything succeeded */
    return_value = T_COSE_SUCCESS;

Done:
     EVP_MD_CTX_free(sign_context);

    return return_value;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_verify_eddsa(struct t_cose_key     verification_key,
                           void                 *crypto_context,
                           struct q_useful_buf_c tbs,
                           struct q_useful_buf_c signature)
{
    enum t_cose_err_t return_value;
    int               ossl_result;
    EVP_MD_CTX       *verify_context = NULL;
    EVP_PKEY         *verification_key_evp;

    (void)crypto_context; /* This crypto adaptor doesn't use this */

    return_value = key_convert(verification_key, &verification_key_evp);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    verify_context = EVP_MD_CTX_new();
    if(verify_context == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    ossl_result = EVP_DigestVerifyInit(verify_context,
                                       NULL,
                                       NULL,
                                       NULL,
                                       verification_key_evp);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /** Must use EVP_DigestVerify rather than EVP_PKEY_verify, since
     * the tbs data is not hashed yet. Because of how EdDSA works, we
     * cannot hash the data ourselves separately.
     */
    ossl_result = EVP_DigestVerify(verify_context,
                                   signature.ptr,
                                   signature.len,
                                   tbs.ptr,
                                   tbs.len);
    if(ossl_result == 0) {
        /* The operation succeeded, but the signature doesn't match */
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    } else if (ossl_result != 1) {
        /* Failed before even trying to verify the signature */
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Everything succeeded */
    return_value = T_COSE_SUCCESS;

Done:
     EVP_MD_CTX_free(verify_context);

    return return_value;
}



/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_get_random(struct q_useful_buf    buffer,
                         size_t                 number,
                         struct q_useful_buf_c *random)
{
    int ossl_result;

    if (number > buffer.len) {
        return T_COSE_ERR_TOO_SMALL;
    }

    if(!is_size_t_to_int_cast_ok(number)) {
        return T_COSE_ERR_FAIL;
    }
    ossl_result = RAND_bytes(buffer.ptr, (int)number);
    if(ossl_result != 1) {
        return T_COSE_ERR_RNG_FAILED;
    }

    random->ptr = buffer.ptr;
    random->len = number;

    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_make_symmetric_key_handle(int32_t               cose_algorithm_id,
                                        struct q_useful_buf_c symmetric_key,
                                        struct t_cose_key    *key_handle)
{
    const int32_t symmetric_algs[] = {
        T_COSE_ALGORITHM_A128GCM,
        T_COSE_ALGORITHM_A192GCM,
        T_COSE_ALGORITHM_A256GCM,
        T_COSE_ALGORITHM_A128KW,
        T_COSE_ALGORITHM_A192KW,
        T_COSE_ALGORITHM_A256KW,
        T_COSE_ALGORITHM_HMAC256,
        T_COSE_ALGORITHM_HMAC384,
        T_COSE_ALGORITHM_HMAC512};

    if(!t_cose_check_list(cose_algorithm_id, symmetric_algs)) {
        /* This check could be disabled when usage guards are disabled */
        return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }

    /* Unlike PSA/Mbed, there is no key use policy enforcement and not even
     * a key handle, so this is much much simpler. */
    key_handle->key.buffer = symmetric_key;

    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_export_symmetric_key(struct t_cose_key      key,
                                   struct q_useful_buf    key_buffer,
                                   struct q_useful_buf_c *exported_key)
{
    *exported_key = q_useful_buf_copy(key_buffer, key.key.buffer);
    if(q_useful_buf_c_is_null(*exported_key)) {
        return T_COSE_ERR_TOO_SMALL;
    }

    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
void
t_cose_crypto_free_symmetric_key(struct t_cose_key key)
{
    (void)key;
    /* Nothing to do for OpenSSL symmetric keys. */
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_generate_ec_key(const int32_t       cose_ec_curve_id,
                              struct t_cose_key  *key)
{
    EC_KEY   *ec_key;
    int       ossl_result;
    int       nid;
    EC_GROUP *ec_group;
    EVP_PKEY *evp_pkey;

    switch (cose_ec_curve_id) {
        case T_COSE_ELLIPTIC_CURVE_P_256:
             nid        = NID_X9_62_prime256v1;
             break;
        case T_COSE_ELLIPTIC_CURVE_P_384:
             nid        = NID_secp384r1;
             break;
        case T_COSE_ELLIPTIC_CURVE_P_521:
             nid        = NID_secp521r1;
             break;
        default:
             return T_COSE_ERR_UNSUPPORTED_ELLIPTIC_CURVE_ALG;
    }

    ec_key = EC_KEY_new();
    if(ec_key == NULL) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    ec_group = EC_GROUP_new_by_curve_name(nid);
    if(ec_group == NULL) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    ossl_result = EC_KEY_set_group(ec_key, ec_group);
    if(ossl_result != 1) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    ossl_result = EC_KEY_generate_key(ec_key);
    if(ossl_result != 1) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    evp_pkey = EVP_PKEY_new();
    if(evp_pkey == NULL) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    ossl_result = EVP_PKEY_set1_EC_KEY(evp_pkey, ec_key);
    if(ossl_result != 1) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    key->key.ptr = evp_pkey;

    return T_COSE_SUCCESS;
}


/* Compute size of ciphertext, given size of plaintext. Returns
 * SIZE_MAX if the algorithm is unknown. Also returns the tag
 * length. */
static size_t
aead_byte_count(const int32_t cose_algorithm_id,
                size_t        plain_text_len,
                size_t       *tag_length)
{
    /* So far this just works for GCM AEAD algorithms, but can be
     * augmented for others.
     *
     * For GCM as used by COSE and HPKE, the authentication tag is
     * appended to the end of the cipher text and is always 16 bytes.
     * Since GCM is a variant of counter mode, the ciphertext length
     * is the same as the plaintext length. (This is not true of other
     * ciphers).
     * https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode
     */

    /* The same tag length for all COSE and HPKE AEAD algorithms supported.*/
    const size_t common_gcm_tag_length = 16;

    *tag_length = common_gcm_tag_length;

    if(plain_text_len > (SIZE_MAX - common_gcm_tag_length)) {
        /* The extremely rare case where plain_text_len
         * is almost SIZE_MAX in length and the length
         * additions below will fail. This error is not
         * the right one, but the case is so rare that
         * it's not worth the trouble of making up some
         * other error. This check is here primarily
         * for static analyzers. */
        return SIZE_MAX;
    }

    switch(cose_algorithm_id) {
        case T_COSE_ALGORITHM_A128GCM:
            return plain_text_len + common_gcm_tag_length;
        case T_COSE_ALGORITHM_A192GCM:
            return plain_text_len + common_gcm_tag_length;
        case T_COSE_ALGORITHM_A256GCM:
            return plain_text_len + common_gcm_tag_length;
        default: return SIZE_MAX;;
    }
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_aead_encrypt(const int32_t          cose_algorithm_id,
                           struct t_cose_key      key,
                           struct q_useful_buf_c  nonce,
                           struct q_useful_buf_c  aad,
                           struct q_useful_buf_c  plaintext,
                           struct q_useful_buf    ciphertext_buffer,
                           struct q_useful_buf_c *ciphertext)
{
    EVP_CIPHER_CTX   *evp_context;
    int               ossl_result;
    const EVP_CIPHER *evp_cipher;
    int               expected_key_length;
    size_t            expected_iv_length;
    int               buffer_bytes_used;
    int               bytes_output;
    int               dummy_length;
    size_t            expected_output_length;
    size_t            tag_length;
    enum t_cose_err_t return_value;


    /* ------- Plaintext and ciphertext lengths -------*/
    /*
     * This is the critical length check that makes the rest of the
     * calls to OpenSSL that write to the output buffer safe because
     * OpenSSL by itself doesn't isn't safe. You cannot tell it the
     * length of the buffer it is writing to.
     *
     * Here's the text from the openssl documentation:
     *
     *    For most ciphers and modes, the amount of data written can
     *    be anything from zero bytes to (inl + cipher_block_size - 1)
     *    bytes. For wrap cipher modes, the amount of data written can
     *    be anything from zero bytes to (inl + cipher_block_size)
     *    bytes. For stream ciphers, the amount of data written can be
     *    anything from zero bytes to inl bytes.
     */

    /* output-length-check */
    /* This assumes that OpenSSL outputs exactly the number
     * of bytes this call calculates. */
    expected_output_length = aead_byte_count(cose_algorithm_id,
                                             plaintext.len,
                                            &tag_length);
    if(expected_output_length == SIZE_MAX) {
        return_value = T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
        goto Done3;
    }
    if(ciphertext_buffer.len < expected_output_length) {
        /* Output buffer is too small */
        return_value = T_COSE_ERR_TOO_SMALL;
        goto Done3;
    }
    /* Now it is established that the output buffer is big enough */
    if(ciphertext_buffer.ptr == NULL) {
        /* Called in length calculation mode. Return length & exit. */
        ciphertext->len = expected_output_length;
        return_value = T_COSE_SUCCESS;
        goto Done3;
    }

    /* ------- Algorithm and key and IV length checks -------*/
    switch(cose_algorithm_id) {
         case T_COSE_ALGORITHM_A128GCM: evp_cipher = EVP_aes_128_gcm();break;
         case T_COSE_ALGORITHM_A192GCM: evp_cipher = EVP_aes_192_gcm();break;
         case T_COSE_ALGORITHM_A256GCM: evp_cipher = EVP_aes_256_gcm();break;
        default: return_value = T_COSE_ERR_UNSUPPORTED_CIPHER_ALG; goto Done3;
     }
    /* This is a sanity check. OpenSSL doesn't provide this check when
     * using a key. It just assume you've provided the right key
     * length to EVP_EncryptInit(). A bit unhygenic if you ask me.
     * Assuming that EVP_CIPHER_key_length() will always return a
     * small positive integer so the cast to size_t is safe. */
    expected_key_length = EVP_CIPHER_key_length(evp_cipher);
    if(key.key.buffer.len != (size_t)expected_key_length) {
        return_value = T_COSE_ERR_WRONG_TYPE_OF_KEY;
        goto Done2;
    }
    /* Same hygene check for IV/nonce length as for key */
    /* Assume that EVP_CIPHER_iv_length() won't ever return something
     * dumb like -1. It would be a bug in OpenSSL or such if it did.
     * This make the cast to size_t mostly safe. */
    expected_iv_length = (size_t)EVP_CIPHER_iv_length(evp_cipher);
    if(nonce.len < expected_iv_length){
        return_value = T_COSE_ERR_ENCRYPT_FAIL;
        goto Done2;
    }

    /* -------- Context initialization with key and IV ---------- */
    evp_context = EVP_CIPHER_CTX_new();
    if (evp_context == NULL) {
        return_value = T_COSE_ERR_ENCRYPT_FAIL;
        goto Done2;
    }
    ossl_result = EVP_EncryptInit(evp_context,
                                  evp_cipher,
                                  NULL,
                                  NULL);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_ENCRYPT_FAIL;
        goto Done1;
    }
    // TODO: is this necessary? Can there be only one call to EVP_EncryptInit() that sets the key and iv?
    // TODO: cast of nonce
    ossl_result = EVP_CIPHER_CTX_ctrl(evp_context,
                                      EVP_CTRL_AEAD_SET_IVLEN,
                                      (int)nonce.len,
                                      NULL);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_ENCRYPT_FAIL;
        goto Done1;
    }
    ossl_result = EVP_EncryptInit(evp_context,
                                  evp_cipher,
                                  key.key.buffer.ptr,
                                  nonce.ptr);

    // TODO: I'm not sure this code is working right yet. The documentation
    // is inadequate and it is complicated. More work is needed to
    // examine documentation, examples and to especially test all the
    // various cases and error conditions.

    /* ---------- AAD ---------- */
    if (!q_useful_buf_c_is_null(aad)) {
        if(!is_size_t_to_int_cast_ok(aad.len)) {
            /* Cast to integer below would not be safe. */
            return_value = T_COSE_ERR_ENCRYPT_FAIL;
            goto Done1;
        }
        /* The NULL output pointer seems to tell it that this is AAD. TODO: confirm this */
        ossl_result = EVP_EncryptUpdate(evp_context,
                                        NULL,
                                        &dummy_length,
                                        aad.ptr, (int)aad.len);
        if(ossl_result != 1) {
            return_value = T_COSE_ERR_ENCRYPT_FAIL;
            goto Done1;
        }
    }

    /* ---------- Actual encryption of plaintext to cipher text ---------*/
    if(!is_size_t_to_int_cast_ok(expected_output_length)) {
        /* This tells us that it is not safe to track the output
         * of the encryption in the integer variables buffer_bytes_used
         * and bytes_output. */
        return_value = T_COSE_ERR_ENCRYPT_FAIL;
        goto Done1;
    }
    buffer_bytes_used = 0;
    /* This assumes a stream cipher and no need for handling blocks.
     * The section above on lengths makes sure the buffer being written
     * to is big enough and that the cast of plaintext.len is safe.
     */
    if(!is_size_t_to_int_cast_ok(plaintext.len)) {
        /* Cast to integer below would not be safe. */
        return_value = T_COSE_ERR_ENCRYPT_FAIL;
        goto Done1;
    }
    ossl_result = EVP_EncryptUpdate(evp_context,
                                    ciphertext_buffer.ptr,
                                    &bytes_output,
                                    plaintext.ptr, (int)plaintext.len);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_ENCRYPT_FAIL;
        goto Done1;
    }

    buffer_bytes_used += bytes_output; /* Safe becaue of output-length-check */

    // TODO: Final or Final_ex?
    ossl_result = EVP_EncryptFinal_ex(evp_context,
                                     (uint8_t *)ciphertext_buffer.ptr + buffer_bytes_used,
                                     &bytes_output);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_ENCRYPT_FAIL;
        goto Done1;
    }
    buffer_bytes_used += bytes_output; /* Safe becaue of output-length-check */

    /* ---------- AEAD authentication tag and finish ----------- */
    /* Get tag. */
    /* Cast of tag_length to int is safe because we know that
     * symmetric_cipher_byte_count will only return small positive values. */
    ossl_result = EVP_CIPHER_CTX_ctrl(evp_context,
                                      EVP_CTRL_AEAD_GET_TAG,
                                      (int)tag_length,
                                      (uint8_t *)ciphertext_buffer.ptr + buffer_bytes_used);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_ENCRYPT_FAIL;
        goto Done1;
    }
    buffer_bytes_used += (int)tag_length; /* Safe becaue of output-length-check */

    if(!is_int_to_size_t_cast_ok(buffer_bytes_used)) {
        return_value = T_COSE_ERR_ENCRYPT_FAIL;
        goto Done1;
    }
    ciphertext->len = (size_t)buffer_bytes_used;
    ciphertext->ptr = ciphertext_buffer.ptr;

    return_value = T_COSE_SUCCESS;

Done1:
    /* https://stackoverflow.com/questions/26345175/correct-way-to-free-allocate-the-context-in-the-openssl */
    EVP_CIPHER_CTX_free(evp_context);
Done2:
    /* It seems that EVP_aes_128_gcm(), ... returns a const, non-allocated
     * EVP_CIPHER and thus doesn't have to be freed. */
Done3:
    return return_value;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_aead_decrypt(const int32_t          cose_algorithm_id,
                           struct t_cose_key      key,
                           struct q_useful_buf_c  nonce,
                           struct q_useful_buf_c  aad,
                           struct q_useful_buf_c  ciphertext,
                           struct q_useful_buf    plaintext_buffer,
                           struct q_useful_buf_c *plaintext)
{
    EVP_CIPHER_CTX   *evp_context;
    int               ossl_result;
    const EVP_CIPHER *evp_cipher;
    int               expected_key_length;
    size_t            expected_iv_length;
    int               bytes_output;
    int               dummy_length;
    size_t            tag_length;
    enum t_cose_err_t return_value;

    /* ------- Identify the algorithm -------*/
    switch(cose_algorithm_id) {
        case T_COSE_ALGORITHM_A128GCM: evp_cipher = EVP_aes_128_gcm ();break;
        case T_COSE_ALGORITHM_A192GCM: evp_cipher = EVP_aes_192_gcm ();break;
        case T_COSE_ALGORITHM_A256GCM: evp_cipher = EVP_aes_256_gcm ();break;
        default: return_value = T_COSE_ERR_UNSUPPORTED_CIPHER_ALG; goto Done3;
    }
    tag_length = 16; /* The tag length for all the above ciphers is 16 */

    /* ------- Length checks (since OpenSSL doesn't) -------*/
    if(ciphertext.len < tag_length) { /* ciphertext-length-check */
        /* All algorithms supported so far are AEAD, have a tag and thus
         * have a minimum length of the tag_length. This check  makes the
         * length calculation below safe. */
        return_value = T_COSE_ERR_DECRYPT_FAIL;
        goto Done2;
    }
    if(plaintext_buffer.len < ciphertext.len - tag_length) { /* plaintext-buffer-check */
        /* The buffer to receive the plaintext is too small. This
         * check assumes AEAD. See aead_byte_count(). */
        return_value = T_COSE_ERR_TOO_SMALL;
        goto Done2;
    }
    if(!is_size_t_to_int_cast_ok(plaintext_buffer.len)){
        /* While plaintext_buffer.len is never cast to int,
         * the length of bytes that are put in it are
         * held by the integer bytes_output. This checks
         * affirms that it is OK to hold that counter in an int. */
        return_value = T_COSE_ERR_DECRYPT_FAIL;
        goto Done2;
    }

    /* ------- Algorithm and key and IV length checks -------*/
    /* This is a sanity check. OpenSSL doesn't provide this check
     * when using a key. It just assumes you've provided the right key
     * length to EVP_DecryptInit(). A bit unhygenic if you ask me. */
    expected_key_length = EVP_CIPHER_key_length(evp_cipher);
    if(key.key.buffer.len != (size_t)expected_key_length) {
        return_value = T_COSE_ERR_WRONG_TYPE_OF_KEY;
        goto Done2;
    }
    /* Same hygene check for IV/nonce length as for key */
    /* Assume that EVP_CIPHER_iv_length() won't ever return something
     * dumb like -1. It would be a bug in OpenSSL or such if it did.
     * This make the cast to size_t mostly safe. */
    expected_iv_length = (size_t)EVP_CIPHER_iv_length(evp_cipher);
    if(nonce.len < expected_iv_length){
        return_value = T_COSE_ERR_DECRYPT_FAIL;
        goto Done2;
    }

    /* -------- Context initialization with key and IV ---------- */
    evp_context = EVP_CIPHER_CTX_new();
    if (evp_context == NULL) {
        return_value = T_COSE_ERR_DECRYPT_FAIL;
        goto Done2;
    }
    ossl_result = EVP_DecryptInit(evp_context,
                                  evp_cipher,
                                  key.key.buffer.ptr,
                                  nonce.ptr);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_DECRYPT_FAIL;
        goto Done1;
    }

    // TODO: I'm not sure this code is working right yet. The documentation
    // is inadequate and it is complicated. More work is needed to
    // examine documentation, examples and to especially test all the
    // various cases and error conditions.

    // TODO: is this necessary? EVP_CIPHER_CTX_ctrl (evp_context, EVP_CTRL_GCM_SET_TAG, 16, ref_TAG);


    /* ---------- AAD ---------- */
    if (!q_useful_buf_c_is_null(aad)) {
        if(!is_size_t_to_int_cast_ok(aad.len)) {
            /* Cast to integer below would not be safe. */
            return_value = T_COSE_ERR_ENCRYPT_FAIL;
        }
        /* The NULL output pointer seems to tell it that this is AAD. TODO: confirm this */
        ossl_result = EVP_DecryptUpdate(evp_context,
                                        NULL,
                                        &dummy_length,
                                        aad.ptr, (int)aad.len);
        if(ossl_result != 1) {
            return_value = T_COSE_ERR_ENCRYPT_FAIL;
            goto Done1;
        }
    }

    /* ---------- Actual encryption of plaintext to cipher text ---------*/
    /* Length subtraction safe because of ciphertext-length-check */
    if(!is_size_t_to_int_cast_ok(ciphertext.len - tag_length)) {
        /* Cast to integer below would not be safe. */
        return_value = T_COSE_ERR_ENCRYPT_FAIL;
        goto Done1;
    }
    ossl_result = EVP_DecryptUpdate(evp_context,
                                    plaintext_buffer.ptr,
                                    &bytes_output,
                                    ciphertext.ptr,
                                    (int)(ciphertext.len - tag_length));
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_ENCRYPT_FAIL;
        goto Done1;
    }


    /* ---------- Process the authentication tag and finalize ---------*/
    /* No check for cast safety of tag_length OK because it is always
     * a smalll positive number. */
    /* The pointer math below is safe because it is calculating a
     * pointer that is in input ciphertext data. */
    /* This is to cast away const without any warnings because the arg
     * to EVP_CIPHER_CTX_ctrl is not const this is compiled with
     * -Wcast-qual. */
    void *tmp = (void *)(uintptr_t)((const uint8_t *)ciphertext.ptr +
                                    (ciphertext.len - tag_length));
    ossl_result = EVP_CIPHER_CTX_ctrl(evp_context,
                                      EVP_CTRL_AEAD_SET_TAG,
                                      (int)tag_length,
                                      tmp);
    if(ossl_result != 1) {
        return_value = 10; // TODO: proper error code
        goto Done1;
    }
    /* The pointer math is safe and this call won't write off the end
     * of the buffer because of plaintext-buffer-check. Because this
     * only implements AEAD this will not actually write anything. A
     * block-mode cipher probably requires a little different code
     * that doesn't assume this writes nothing (no dummy_length).
     */
    ossl_result = EVP_DecryptFinal_ex(evp_context,
                                      (uint8_t *)plaintext_buffer.ptr + bytes_output,
                                      &dummy_length);
    if(ossl_result != 1) {
        /* This is where an authentication failure is detected. */
        return_value = 10; // TODO: proper error code
        goto Done1;
    }

    /* ---------- Return pointer and length of plaintext ---------*/
    if(!is_int_to_size_t_cast_ok(bytes_output)) {
        return_value = T_COSE_ERR_ENCRYPT_FAIL;
        goto Done1;
    }
    plaintext->len = (size_t)bytes_output;
    plaintext->ptr = plaintext_buffer.ptr;

    return_value = T_COSE_SUCCESS;

Done1:
    /* https://stackoverflow.com/questions/26345175/correct-way-to-free-allocate-the-context-in-the-openssl */
    EVP_CIPHER_CTX_free(evp_context);
Done2:
    /* It seems that EVP_aes_128_gcm(), ... returns a const, non-allocated
     * EVP_CIPHER and thus doesn't have to be freed. */
Done3:
    return return_value;
}


#ifndef T_COSE_DISABLE_KEYWRAP

static int
bits_in_kw_key(int32_t cose_algorithm_id)
{
    switch(cose_algorithm_id) {
        case T_COSE_ALGORITHM_A128KW: return 128;
        case T_COSE_ALGORITHM_A192KW: return 192;
        case T_COSE_ALGORITHM_A256KW: return 256;
        default: return INT_MAX;
    }
}


/* This computes the length of the output of a key wrap algorithm
 * based on the plaintext size. It is only dependent on the
 * plaintext size, not on the key size.
 */
static size_t
key_wrap_length(size_t plaintext_size)
{
    if(plaintext_size % 8) {
        return 0;
    }

    if(plaintext_size > SIZE_MAX - 8) {
        return 0;
    }

    return plaintext_size + 8;
}


/* The IV for all key wraps sizes in RFC 3394 */
static const uint8_t rfc_3394_key_wrap_iv[] = {0xa6, 0xa6, 0xa6, 0xa6,
                                               0xa6, 0xa6, 0xa6, 0xa6};

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_kw_wrap(int32_t                 algorithm_id,
                      struct t_cose_key       kek,
                      struct q_useful_buf_c   plaintext,
                      struct q_useful_buf     ciphertext_buffer,
                      struct q_useful_buf_c  *ciphertext_result)
{
    enum t_cose_err_t  err;
    int      ossl_result;
    AES_KEY  kek_ossl;
    size_t   wrapped_size;
    int      key_size_in_bits;
    int      expected_kek_bits;
    struct q_useful_buf_c   kek_bytes;
    Q_USEFUL_BUF_MAKE_STACK_UB( kek_bytes_buf, T_COSE_MAX_SYMMETRIC_KEY_LENGTH);

    /* Export the actual key bytes from t_cose_key (which might be a handle) */
    err = t_cose_crypto_export_symmetric_key(kek,
                                             kek_bytes_buf,
                                            &kek_bytes);
    if(err != T_COSE_SUCCESS) {
        return err;
    }


    /* Check the algorithm ID and get expected bits in KEK. */
    expected_kek_bits = bits_in_kw_key(algorithm_id);
    if(expected_kek_bits == INT_MAX) {
        return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }

    /* Safely calculate bits in the KEK and check it */
    if(kek_bytes.len > INT_MAX / 8) {
        /* Cast to int isn't safe */
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;
    }
    key_size_in_bits = (int)kek_bytes.len * 8;
    if(key_size_in_bits != expected_kek_bits){
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;
    }

    /* Set up the kek as an OpenSSL AES_KEY */
    ossl_result = AES_set_encrypt_key(kek_bytes.ptr, key_size_in_bits, &kek_ossl);
    if(ossl_result != 0) {
        /* An OpenSSL API unlike others for which 0 is success. */
        return T_COSE_ERR_KW_FAILED;
    }

    /* Check for space in the output buffer */
    wrapped_size = key_wrap_length(plaintext.len);
    if(ciphertext_buffer.len <= wrapped_size) {
        return T_COSE_ERR_TOO_SMALL;
    }

    /* Do the wrap */
    if(!is_size_t_to_uint_cast_ok(plaintext.len)){
        return T_COSE_ERR_KW_FAILED;
    }
    // TODO: be sure OpenSSL won't run off the end of
    // any buffers in this call by reading docs, testing and thinking...
    ossl_result = AES_wrap_key(&kek_ossl,
                               rfc_3394_key_wrap_iv,
                               ciphertext_buffer.ptr,
                               plaintext.ptr,
                               (unsigned int)plaintext.len);
    if(ossl_result != (int)wrapped_size) {
        return T_COSE_ERR_KW_FAILED;
    }

    ciphertext_result->len = wrapped_size;
    ciphertext_result->ptr = ciphertext_buffer.ptr;

    return T_COSE_SUCCESS;
}



/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_kw_unwrap(int32_t                 algorithm_id,
                        struct t_cose_key       kek,
                        struct q_useful_buf_c   ciphertext,
                        struct q_useful_buf     plaintext_buffer,
                        struct q_useful_buf_c  *plaintext_result)
{
    int     unwrapped_size;
    enum t_cose_err_t err;
    AES_KEY kek_ossl;
    size_t  expected_unwrapped_size;
    int     kek_size_in_bits;
    int      expected_kek_bits;
    struct q_useful_buf_c   kek_bytes;
    Q_USEFUL_BUF_MAKE_STACK_UB( kek_bytes_buf, T_COSE_MAX_SYMMETRIC_KEY_LENGTH);

    /* Export the actual key bytes from t_cose_key (which might be a handle) */
    err = t_cose_crypto_export_symmetric_key(kek,
                                             kek_bytes_buf,
                                            &kek_bytes);
    if(err != T_COSE_SUCCESS) {
        return err;
    };


    /* Check the algorithm ID and get expected bits in KEK. */
    expected_kek_bits = bits_in_kw_key(algorithm_id);
    if(expected_kek_bits == INT_MAX) {
        return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }

    /* Safely calculate bits in the KEK and check it */
    if(kek_bytes.len > INT_MAX / 8) {
        /* Cast to int isn't safe */
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;
    }
    kek_size_in_bits = (int)kek_bytes.len * 8;
    if(kek_size_in_bits != expected_kek_bits){
        return T_COSE_ERR_WRONG_TYPE_OF_KEY;
    }

    /* Set up the kek as an OpenSSL AES_KEY */
    unwrapped_size = AES_set_decrypt_key(kek_bytes.ptr, kek_size_in_bits, &kek_ossl);
    if(unwrapped_size != 0) {
        /* An OpenSSL API unlike others for which 0 is success. */
        return T_COSE_ERR_KW_FAILED;
    }

    /* Check for space in the output buffer */
    expected_unwrapped_size = ciphertext.len - 8;
    if(plaintext_buffer.len < expected_unwrapped_size) {
        return T_COSE_ERR_TOO_SMALL;
    }

    /* Do the unwrap */
    if(!is_size_t_to_uint_cast_ok(ciphertext.len)) {
        return T_COSE_ERR_KW_FAILED;
    }
    // TODO: be sure OpenSSL won't run off the end of
    // any buffers in this call by reading docs, testing and thinking...
    unwrapped_size = AES_unwrap_key(&kek_ossl,
                                 rfc_3394_key_wrap_iv,
                                 plaintext_buffer.ptr,
                                 ciphertext.ptr,
                                 (unsigned int)ciphertext.len);
    if(!is_int_to_size_t_cast_ok(unwrapped_size)) {
        return T_COSE_ERR_KW_FAILED;
    }
    if((size_t)unwrapped_size != expected_unwrapped_size) {
        /* Doesn't seem to be any way to distinguish data auth failed
         * from other errors and this seems the more likely error.
         * TODO: go read ossl source to understand. */
        return T_COSE_ERR_DATA_AUTH_FAILED;
    }
    plaintext_result->len = expected_unwrapped_size;
    plaintext_result->ptr = plaintext_buffer.ptr;

    return T_COSE_SUCCESS;
}


#endif /* !T_COSE_DISABLE_KEYWRAP */




/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_ecdh(struct t_cose_key      private_key,
                   struct t_cose_key      public_key,
                   struct q_useful_buf    shared_key_buf,
                   struct q_useful_buf_c *shared_key)
{
    int           ossl_status;
    EVP_PKEY_CTX *ctx;
    size_t        shared_key_len;

    ctx = EVP_PKEY_CTX_new((EVP_PKEY *)private_key.key.ptr, /* in: pkey */
                           NULL);                           /* in: engine */
    if(ctx == NULL) {
        return T_COSE_ERR_FAIL; // TODO error code
    }

    /* Pretty sure EVP_PKEY_derive works with finite-field
     * DH in addition to ECDH, but that is not made
     * use of here. If finite-field DH is needed,
     * maybe this here implementation can be wrapped
     * by an inline function named t_cose_crypto_ffdh()
     */

    ossl_status = EVP_PKEY_derive_init(ctx);
    if(ossl_status != 1) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    ossl_status = EVP_PKEY_derive_set_peer(ctx,
                                           (EVP_PKEY *)public_key.key.ptr);
    if(ossl_status != 1) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }


    ossl_status = EVP_PKEY_derive(ctx, NULL, &shared_key_len);
    if(ossl_status != 1) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }
    if(shared_key_len > shared_key_buf.len) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }
    ossl_status = EVP_PKEY_derive(ctx, shared_key_buf.ptr, &shared_key_len);
    if(ossl_status != 1) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    shared_key->ptr = shared_key_buf.ptr;
    shared_key->len = shared_key_len;

    EVP_PKEY_CTX_free(ctx);

    return T_COSE_SUCCESS;
}




#include "openssl/kdf.h"



/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hkdf(const int32_t               cose_hash_algorithm_id,
                   const struct q_useful_buf_c salt,
                   const struct q_useful_buf_c ikm,
                   const struct q_useful_buf_c info,
                   const struct q_useful_buf   okm_buffer)
{
    int               ossl_result;
    EVP_PKEY_CTX     *ctx;
    size_t            x_len;
    const EVP_MD     *message_digest;
    enum t_cose_err_t return_value;

    /* This implentation works for OpenSSL 1.x and 3.x. There is a
     * better API than the one used here, but it is only available in
     * 3.x. */

    // TODO: test this more and find a way to be more sure
    // it is all using the OpenSSL APIs right. The documentation
    // doesn't really say how to use it.

    /* These checks make it safe to cast from size_t to int below. */
    if(!is_size_t_to_int_cast_ok(salt.len) ||
       !is_size_t_to_int_cast_ok(ikm.len) ||
       !is_size_t_to_int_cast_ok(info.len)) {
        return_value = T_COSE_ERR_INVALID_LENGTH;
        goto Done2;
    }

    x_len = okm_buffer.len;

    message_digest = cose_hash_alg_to_ossl(cose_hash_algorithm_id);
    if(message_digest == NULL) {
        return_value = T_COSE_ERR_UNSUPPORTED_HASH;
        goto Done2;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if(ctx == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done2;
    }

    ossl_result = EVP_PKEY_derive_init(ctx);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_HKDF_FAIL;
        goto Done1;
    }

    /* See comment above in configure_pkey_context(). The following
     * OpenSSL APIs should have the argments declared as const, but
     * they are not so this pragma is necessary t_cose can compile
     * with "-Wcast-qual". */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    ossl_result = EVP_PKEY_CTX_set_hkdf_md(ctx, message_digest);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_HKDF_FAIL;
        goto Done1;
    }

    /* Cast to int OK'd by check above */
    ossl_result = EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.ptr, (int)salt.len);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_HKDF_FAIL;
        goto Done1;
    }

    /* Cast to int OK'd by check above */
    ossl_result = EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm.ptr, (int)ikm.len);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_HKDF_FAIL;
        goto Done1;
    }

    /* Cast to int OK'd by check above */
    ossl_result = EVP_PKEY_CTX_add1_hkdf_info(ctx, info.ptr, (int)info.len);
    if(ossl_result != 1) {
        return_value = T_COSE_ERR_HKDF_FAIL;
        goto Done1;
    }
#pragma GCC diagnostic pop

    ossl_result = EVP_PKEY_derive(ctx,
                                  okm_buffer.ptr,
                                  &x_len);

    if(x_len != okm_buffer.len || ossl_result != 1) {
        return_value = T_COSE_ERR_HKDF_FAIL;
        goto Done1;
    }

    return_value = T_COSE_SUCCESS;

Done1:
    EVP_PKEY_CTX_free(ctx);
Done2:
    return return_value;
}




/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_import_ec2_pubkey(const int32_t               cose_ec_curve_id,
                                const struct q_useful_buf_c x_coord,
                                const struct q_useful_buf_c y_coord,
                                const bool                  y_bool,
                                struct t_cose_key          *key_handle)
{
    int                       ossl_result;
    int                       nid;
    EC_POINT                 *ec_point;
    EC_KEY                   *ec_key;
    EC_GROUP                 *ec_group;
    EVP_PKEY                 *evp_pkey;
    uint8_t                   first_byte;
    UsefulOutBuf_MakeOnStack( import_buf, T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE);
    struct q_useful_buf_c     import_octets;

    switch (cose_ec_curve_id) {
        case T_COSE_ELLIPTIC_CURVE_P_256:
             nid  = NID_X9_62_prime256v1;
             break;
        case T_COSE_ELLIPTIC_CURVE_P_384:
             nid  = NID_secp384r1;
             break;
        case T_COSE_ELLIPTIC_CURVE_P_521:
             nid  = NID_secp521r1;
             break;
        /* The only other registered for EC2 is secp256k1 */
        default:
             return T_COSE_ERR_UNSUPPORTED_ELLIPTIC_CURVE_ALG;
    }


    /* This converts to a serialized representation of an EC Point
     * described in
     * Certicom Research, "SEC 1: Elliptic Curve Cryptography", Standards for
     * Efficient Cryptography, May 2009, <https://www.secg.org/sec1-v2.pdf>.
     * The description is very mathematical and hard to read for us
     * coder types. It was much easier to understand reading Jim's
     * COSE-C implementation. See mbedtls_ecp_keypair() in COSE-C.
     *
     * This string is the format used by Mbed TLS to import an EC
     * public key.
     *
     * This does implement point compression. The patents for it have
     * run out so it's OK to implement. Point compression is commented
     * out in Jim's implementation, presumably because of the patent
     * issue.
     *
     * A simple English description of the format is this. The first
     * byte is 0x04 for no point compression and 0x02 or 0x03 if there
     * is point compression. 0x02 indicates a positive y and 0x03 a
     * negative y (or is the other way). Following the first byte
     * are the octets of x. If the first byte is 0x04 then following
     * x is the y value.
     *
     * UsefulOutBut is used to safely construct this string.
     */
    if(q_useful_buf_c_is_null(y_coord)) {
        /* This is point compression */
        first_byte = y_bool ? 0x02 : 0x03;
    } else {
        /* Uncompressed */
        first_byte = 0x04;
    }
    UsefulOutBuf_AppendByte(&import_buf, first_byte);
    UsefulOutBuf_AppendUsefulBuf(&import_buf, x_coord);
    if(first_byte == 0x04) {
        UsefulOutBuf_AppendUsefulBuf(&import_buf, y_coord);
    }
    import_octets = UsefulOutBuf_OutUBuf(&import_buf);


    ec_key = EC_KEY_new();
    if(ec_key == NULL) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    ec_group = EC_GROUP_new_by_curve_name(nid);
    if(ec_group == NULL) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    // TODO: this and related are to be depreacted, so they say...
    ossl_result = EC_KEY_set_group(ec_key, ec_group);
    if(ossl_result != 1) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    ec_point = EC_POINT_new(ec_group);
    if(ec_point == NULL) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    ossl_result = EC_POINT_oct2point(ec_group,
                                     ec_point,
                                     import_octets.ptr, import_octets.len,
                                     NULL);
    if(ossl_result != 1) {
         return T_COSE_ERR_FAIL; // TODO: error code
     }

    ossl_result = EC_KEY_set_public_key(ec_key, ec_point);
    if(ossl_result != 1) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    evp_pkey = EVP_PKEY_new();
    if(evp_pkey == NULL) {
         return T_COSE_ERR_FAIL; // TODO: error code
    }

    ossl_result = EVP_PKEY_set1_EC_KEY(evp_pkey, ec_key);
    if(ossl_result != 1) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    key_handle->key.ptr = evp_pkey;

    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_export_ec2_key(struct t_cose_key      key_handle,
                             int32_t               *cose_ec_curve_id,
                             struct q_useful_buf    x_coord_buf,
                             struct q_useful_buf_c *x_coord,
                             struct q_useful_buf    y_coord_buf,
                             struct q_useful_buf_c *y_coord,
                             bool                  *y_bool)
{
    EC_KEY               *ec_key;
    const EC_POINT       *ec_point;
    const EC_GROUP       *ec_group;
    uint8_t               export_buf[T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE];
    size_t                export_len;
    struct q_useful_buf_c export;
    uint8_t               first_byte;
    size_t                len;

    ec_key = EVP_PKEY_get1_EC_KEY((EVP_PKEY *)key_handle.key.ptr);
    if(ec_key == NULL) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    ec_point = EC_KEY_get0_public_key(ec_key);
    if(ec_point == NULL) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }

    ec_group = EC_KEY_get0_group(ec_key);
    if(ec_group == NULL) {
        return T_COSE_ERR_FAIL;
    }

    /* TODO: add support for compressed? */
    export_len = EC_POINT_point2oct(ec_group, /* in: group */
                                    ec_point, /* in: point */
                                    POINT_CONVERSION_UNCOMPRESSED, /* in: point conversion form */
                                    export_buf, /* in/out: buffer to output to */
                                    sizeof(export_buf), /* in: */
                                    NULL /* in: BN_CTX */
                                   );

    first_byte = export_buf[0];
    export = (struct q_useful_buf_c){export_buf+1, export_len-1};

    /* export_buf is one first byte, the x-coord and maybe the y-coord
     * per SEC1.
     */

    switch(EC_GROUP_get_curve_name(ec_group)) {
        case NID_X9_62_prime256v1:
            *cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_256;
            break;
        case NID_secp384r1:
            *cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_384;
            break;
        case NID_secp521r1:
            *cose_ec_curve_id = T_COSE_ELLIPTIC_CURVE_P_521;
            break;
        /* The only other registered for EC2 is secp256k1 */
        default:
            return T_COSE_ERR_FAIL;
    }

    switch(first_byte) {
        case 0x04:
            /* uncompressed */
            len      = (export_len - 1 ) / 2;
            *y_coord = UsefulBuf_Copy(y_coord_buf, UsefulBuf_Tail(export, len));
            if(q_useful_buf_c_is_null(*y_coord)) {
                return T_COSE_ERR_FAIL;
            }
            break;

        case 0x02:
            /* compressed */
            len      = export_len - 1;
            *y_coord = NULL_Q_USEFUL_BUF_C;
            *y_bool  = true;
            break;

        case 0x03:
            /* compressed */
            len      = export_len - 1;
            *y_coord = NULL_Q_USEFUL_BUF_C;
            *y_bool  = false;
            break;

        default:
            return T_COSE_ERR_FAIL;
    }
    *x_coord = UsefulBuf_Copy(x_coord_buf, UsefulBuf_Head(export, len));
    if(q_useful_buf_c_is_null(*x_coord)) {
        return T_COSE_ERR_FAIL;
    }

    return T_COSE_SUCCESS;
}
