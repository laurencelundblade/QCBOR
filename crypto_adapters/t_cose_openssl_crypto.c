/*
 *  t_cose_openssl_crypto.c
 *
 * Copyright 2019-2022, Laurence Lundblade
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
#ifndef T_COSE_DISABLE_EDDSA
        T_COSE_ALGORITHM_EDDSA,
#endif
        T_COSE_ALGORITHM_A128GCM,
        T_COSE_ALGORITHM_A192GCM, /* For 9053 key wrap and direct, not HPKE */
        T_COSE_ALGORITHM_A256GCM,
        T_COSE_ALGORITHM_NONE /* List terminator */
    };

    return t_cose_check_list(cose_algorithm_id, supported_algs);
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
 * \param[in] key_len             Size of the key in bytes -- governs sig size.
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

    /* Put DER-encode sig into an ECDSA_SIG so we can get the r and s out. */
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
 * \param[in] key_len         Size of the key in bytes -- governs sig size.
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
    if(t_cose_key.crypto_lib != T_COSE_CRYPTO_LIB_OPENSSL) {
        return_value = T_COSE_ERR_INCORRECT_KEY_FOR_LIB;
        goto Done;
    }
    if(t_cose_key.k.key_ptr == NULL) {
        return_value = T_COSE_ERR_EMPTY_KEY;
        goto Done;
    }
    *return_ossl_ec_key = (EVP_PKEY *)t_cose_key.k.key_ptr;

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
    const EVP_MD     *md;
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
        switch (cose_algorithm_id) {
            case T_COSE_ALGORITHM_PS256:
                md = EVP_sha256();
                break;

            case T_COSE_ALGORITHM_PS384:
                md = EVP_sha384();
                break;

            case T_COSE_ALGORITHM_PS512:
                md = EVP_sha512();
                break;

            default:
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
        ossl_result = EVP_PKEY_CTX_set_signature_md(context, md);
        if(ossl_result != 1) {
            return_value = T_COSE_ERR_SIG_FAIL;
            goto Done;
        }

        ossl_result = EVP_PKEY_CTX_set_rsa_mgf1_md(context, md);
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
                     const struct q_useful_buf_c  kid,
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

    /* This implementation doesn't use any key store with the ability
     * to look up a key based on kid. */
    (void)kid;

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
    int           nid;
    const EVP_MD *message_digest;

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
        return T_COSE_ERR_UNSUPPORTED_HASH;
    }

    message_digest = EVP_get_digestbynid(nid);
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

    hash_ctx->cose_hash_alg_id = cose_hash_alg_id;
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

enum t_cose_err_t
t_cose_crypto_hmac_compute_setup(struct t_cose_crypto_hmac *hmac_ctx,
                                 struct t_cose_key          signing_key,
                                 const int32_t              cose_alg_id)
{
    (void)hmac_ctx;
    (void)signing_key;
    (void)cose_alg_id;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

enum t_cose_err_t
t_cose_crypto_hmac_update(struct t_cose_crypto_hmac *hmac_ctx,
                          struct q_useful_buf_c      payload)
{
    (void)hmac_ctx;
    (void)payload;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

enum t_cose_err_t
t_cose_crypto_hmac_compute_finish(struct t_cose_crypto_hmac *hmac_ctx,
                                  struct q_useful_buf        tag_buf,
                                  struct q_useful_buf_c     *tag)
{
    (void)hmac_ctx;
    (void)tag_buf;
    (void)tag;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

enum t_cose_err_t
t_cose_crypto_hmac_validate_setup(struct t_cose_crypto_hmac *hmac_ctx,
                                  const  int32_t             cose_alg_id,
                                  struct t_cose_key          validation_key)
{
    (void)hmac_ctx;
    (void)cose_alg_id;
    (void)validation_key;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}

enum t_cose_err_t
t_cose_crypto_hmac_validate_finish(struct t_cose_crypto_hmac *hmac_ctx,
                                   struct q_useful_buf_c      tag)
{
    (void)hmac_ctx;
    (void)tag;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}


#ifndef T_COSE_DISABLE_EDDSA

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
                           struct q_useful_buf_c kid,
                           void                 *crypto_context,
                           struct q_useful_buf_c tbs,
                           struct q_useful_buf_c signature)
{
    enum t_cose_err_t return_value;
    int               ossl_result;
    EVP_MD_CTX       *verify_context = NULL;
    EVP_PKEY         *verification_key_evp;

    /* This implementation doesn't use any key store with the ability
     * to look up a key based on kid. */
    (void)kid;

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

#endif /* T_COSE_DISABLE_EDDSA */



/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_make_symmetric_key_handle(int32_t               cose_algorithm_id,
                                        struct q_useful_buf_c symmetric_key,
                                        struct t_cose_key    *key_handle)
{
    (void)cose_algorithm_id; // TODO: maybe check the algorithm is symmetric
    key_handle->crypto_lib   = T_COSE_CRYPTO_LIB_OPENSSL;
    key_handle->k.key_buffer = symmetric_key;

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
    if(key.crypto_lib != T_COSE_CRYPTO_LIB_OPENSSL) {
        return_value = T_COSE_ERR_INCORRECT_KEY_FOR_LIB;
    }
    /* This is a sanity check. OpenSSL doesn't provide this check when
     * using a key. It just assume you've provided the right key
     * length to EVP_EncryptInit(). A bit unhygenic if you ask me.
     * Assuming that EVP_CIPHER_key_length() will always return a
     * small positive integer so the cast to size_t is safe. */
    expected_key_length = EVP_CIPHER_key_length(evp_cipher);
    if(key.k.key_buffer.len != (size_t)expected_key_length) {
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
                                  key.k.key_buffer.ptr,
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
    if(key.crypto_lib != T_COSE_CRYPTO_LIB_OPENSSL) {
        return_value = T_COSE_ERR_INCORRECT_KEY_FOR_LIB;
        goto Done2;
    }
    /* This is a sanity check. OpenSSL doesn't provide this check
     * when using a key. It just assumes you've provided the right key
     * length to EVP_DecryptInit(). A bit unhygenic if you ask me. */
    expected_key_length = EVP_CIPHER_key_length(evp_cipher);
    if(key.k.key_buffer.len != (size_t)expected_key_length) {
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
                                  key.k.key_buffer.ptr,
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
