/*
 *  t_cose_test_crypto.c
 *
 * Copyright 2019-2023, Laurence Lundblade
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created 3/31/2019.
 */


#include "t_cose_crypto.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_test_crypto.h"
#include "t_cose_util.h"

#define SIGN_ITERATION_COUNT 5

/*
 * This file is stub crypto for initial bring up and test of t_cose.
 * It is NOT intended for commercial use. When this file is used as
 * the crypto adapter, no external crypto library is necessary. This is
 * convenient because sometimes it takes a while to sort out the crypto
 * porting layer for a new platform. With this most of t_cose can be tested
 * and demo signatures (short-circuit signatures) can be generated to
 * simulate out this would work.
 *
 * This file uses no signature algorithm. It uses the Brad Conte hash
 * implementation that is bundled with t_cose for the purpose of this
 * testing, not for commercial use.
 */


/*
 * See documentation in t_cose_crypto.h
 *
 * This will typically not be referenced and thus not linked,
 * for deployed code. This is mainly used for test.
 */
bool
t_cose_crypto_is_algorithm_supported(int32_t cose_algorithm_id)
{
    static const int32_t supported_algs[] = {
        T_COSE_ALGORITHM_SHA_256,
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
        T_COSE_ALGORITHM_SHORT_CIRCUIT_256,
        T_COSE_ALGORITHM_SHORT_CIRCUIT_384,
        T_COSE_ALGORITHM_SHORT_CIRCUIT_512,
#endif /* !T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */
        T_COSE_ALGORITHM_NONE /* List terminator */
    };

    for(const int32_t *i = supported_algs; *i != T_COSE_ALGORITHM_NONE; i++) {
        if(*i == cose_algorithm_id) {
            return true;
        }
    }
    return false;
}


static bool
t_cose_algorithm_is_short_circuit(int32_t cose_algorithm_id)
{
    /* The simple list of COSE alg IDs that use ECDSA */
    static const int32_t ecdsa_list[] = {
        T_COSE_ALGORITHM_SHORT_CIRCUIT_256,
        T_COSE_ALGORITHM_SHORT_CIRCUIT_384,
        T_COSE_ALGORITHM_SHORT_CIRCUIT_512,
        T_COSE_ALGORITHM_NONE
    };

    return t_cose_check_list(cose_algorithm_id, ecdsa_list);
}


/* The Brad Conte hash implementaiton bundled with t_cose */
#include "sha256.h"

/* Use of this file requires definition of T_COSE_USE_B_CON_SHA256 when
 * making t_cose_crypto.h.
 *
 * This only implements SHA-256 as that is all that is needed for the
 * non signing and verification tests using short-circuit signatures.
 */

#ifdef T_COSE_ENABLE_HASH_FAIL_TEST
/* Global variable just for this particular test. Not thread
 * safe or good for commercial use.
 */
int hash_test_mode = 0;
#endif


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_sig_size(int32_t           cose_algorithm_id,
                       struct t_cose_key signing_key,
                       size_t           *sig_size)
{
    (void)signing_key;

    /* sizes are 2x to simulate an ECDSA signature */
    *sig_size =
        cose_algorithm_id == T_COSE_ALGORITHM_SHORT_CIRCUIT_256 ? 2 * 256/8 :
        cose_algorithm_id == T_COSE_ALGORITHM_SHORT_CIRCUIT_384 ? 2 * 384/8 :
        cose_algorithm_id == T_COSE_ALGORITHM_SHORT_CIRCUIT_512 ? 2 * 512/8 :
        0;

    return *sig_size == 0 ? T_COSE_ERR_UNSUPPORTED_SIGNING_ALG : T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_sign(int32_t                cose_algorithm_id,
                   struct t_cose_key      signing_key,
                   void                  *crypto_context,
                   struct q_useful_buf_c  hash_to_sign,
                   struct q_useful_buf    signature_buffer,
                   struct q_useful_buf_c *signature)
{
    enum t_cose_err_t return_value;
    size_t            array_index;
    size_t            amount_to_copy;
    size_t            sig_size;
    struct t_cose_test_crypto_context *cc = (struct t_cose_test_crypto_context *)crypto_context;

    /* This is used for testing the crypto context */
    if(cc != NULL && cc->test_error != T_COSE_SUCCESS) {
        return cc->test_error;
    }

    /* This makes the short-circuit signature that is a concatenation
     * of copies of the hash. */
    return_value = t_cose_crypto_sig_size(cose_algorithm_id, signing_key, &sig_size);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* Check the signature length against buffer size */
    if(sig_size > signature_buffer.len) {
        /* Buffer too small for this signature type */
        return_value = T_COSE_ERR_SIG_BUFFER_SIZE;
        goto Done;
    }

    /* Loop concatening copies of the hash to fill out to signature size */
    for(array_index = 0; array_index < sig_size; array_index += hash_to_sign.len) {
        amount_to_copy = sig_size - array_index;
        if(amount_to_copy > hash_to_sign.len) {
            amount_to_copy = hash_to_sign.len;
        }
        memcpy((uint8_t *)signature_buffer.ptr + array_index,
               hash_to_sign.ptr,
               amount_to_copy);
    }
    signature->ptr = signature_buffer.ptr;
    signature->len = sig_size;
    return_value   = T_COSE_SUCCESS;

Done:
    return return_value;
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_sign_restart(bool                   started,
                           int32_t                cose_algorithm_id,
                           struct t_cose_key      signing_key,
                           void                  *crypto_context,
                           struct q_useful_buf_c  hash_to_sign,
                           struct q_useful_buf    signature_buffer,
                           struct q_useful_buf_c *signature)
{
    struct t_cose_test_crypto_context *cc = (struct t_cose_test_crypto_context *)crypto_context;

    /* If this is the first iteration */
    if(!started) {
        cc->sign_iterations_left = SIGN_ITERATION_COUNT;
    }
    if(cc->sign_iterations_left-- > 1) {
        return T_COSE_ERR_SIG_IN_PROGRESS;
    }

    return t_cose_crypto_sign(cose_algorithm_id,
                              signing_key,
                              crypto_context,
                              hash_to_sign,
                              signature_buffer,
                              signature);
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_verify(int32_t                cose_algorithm_id,
                     struct t_cose_key      verification_key,
                     void                  *crypto_context,
                     struct q_useful_buf_c  hash_to_verify,
                     struct q_useful_buf_c  signature)
{
    struct q_useful_buf_c hash_from_sig;
    enum t_cose_err_t     return_value;
    struct t_cose_test_crypto_context *cc = (struct t_cose_test_crypto_context *)crypto_context;

    (void)verification_key;

    /* This is used for testing the crypto context */
    if(cc != NULL && cc->test_error != T_COSE_SUCCESS) {
        return cc->test_error;
    }

    if(!t_cose_algorithm_is_short_circuit(cose_algorithm_id)) {
        return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
    }

    hash_from_sig = q_useful_buf_head(signature, hash_to_verify.len);
    if(q_useful_buf_c_is_null(hash_from_sig)) {
        return_value = T_COSE_ERR_SIG_VERIFY;
        goto Done;
    }

    if(q_useful_buf_compare(hash_from_sig, hash_to_verify)) {
        return_value = T_COSE_ERR_SIG_VERIFY;
    } else {
        return_value = T_COSE_SUCCESS;
    }

Done:
    return return_value;
}




/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hash_start(struct t_cose_crypto_hash *hash_ctx,
                         int32_t cose_hash_alg_id)
{
#ifdef T_COSE_ENABLE_HASH_FAIL_TEST
    if(hash_test_mode == 1) {
        return T_COSE_ERR_HASH_GENERAL_FAIL;
    }
#endif

    if(cose_hash_alg_id != T_COSE_ALGORITHM_SHA_256) {
        return T_COSE_ERR_UNSUPPORTED_HASH;
    }

    sha256_init(&(hash_ctx->b_con_hash_context));
    return 0;
}

/*
 * See documentation in t_cose_crypto.h
 */
void t_cose_crypto_hash_update(struct t_cose_crypto_hash *hash_ctx,
                               struct q_useful_buf_c data_to_hash)
{
    if(data_to_hash.ptr) {
        sha256_update(&(hash_ctx->b_con_hash_context),
                      data_to_hash.ptr,
                      data_to_hash.len);
    }
}

/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_hash_finish(struct t_cose_crypto_hash *hash_ctx,
                          struct q_useful_buf buffer_to_hold_result,
                          struct q_useful_buf_c *hash_result)
{
#ifdef T_COSE_ENABLE_HASH_FAIL_TEST
    if(hash_test_mode == 2) {
        return T_COSE_ERR_HASH_GENERAL_FAIL;
    }
#endif

    sha256_final(&(hash_ctx->b_con_hash_context), buffer_to_hold_result.ptr);
    *hash_result = (UsefulBufC){buffer_to_hold_result.ptr, 32};

    return 0;
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
    (void)signing_key;
    (void)crypto_context;
    (void)tbs;
    (void)signature_buffer;
    (void)signature;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
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
    (void)verification_key;
    (void)crypto_context;
    (void)tbs;
    (void)signature;
    return T_COSE_ERR_UNSUPPORTED_SIGNING_ALG;
}



/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_generate_ec_key(const int32_t       cose_ec_curve_id,
                              struct t_cose_key  *key)
{
    (void)key;
    (void)cose_ec_curve_id;
    return T_COSE_ERR_KEY_GENERATION_FAILED;
}



/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_get_random(struct q_useful_buf    buffer,
                         size_t                 number,
                         struct q_useful_buf_c *random)
{
    if (number > buffer.len) {
        return(T_COSE_ERR_TOO_SMALL);
    }

    /* In test mode this just fills a buffer with 'x' */
    memset(buffer.ptr, 'x', number);

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
    (void)cose_algorithm_id;

    key_handle->key.buffer = symmetric_key;

    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
void
t_cose_crypto_free_symmetric_key(struct t_cose_key key)
{
    (void)key;
}

/* Compute size of ciphertext, given size of plaintext. Returns
 * SIZE_MAX if the algorithm is unknown. Also returns the tag
 * length. */
static size_t
aead_byte_count(const int32_t cose_algorithm_id,
                size_t        plain_text_len)
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

#define FAKE_TAG "tagtagtagtagtagt"

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
    struct q_useful_buf_c tag = Q_USEFUL_BUF_FROM_SZ_LITERAL(FAKE_TAG);

    (void)nonce;
    (void)aad;
    (void)cose_algorithm_id;
    (void)key;


    if(ciphertext_buffer.ptr == NULL) {
        /* Called in length calculation mode. Return length & exit. */
        ciphertext->len = aead_byte_count(cose_algorithm_id,
                                          plaintext.len);;
        return T_COSE_SUCCESS;
    }

    /* Use useful output to copy the plaintext as pretend encryption
     * and add "tagtag.." as a pretend tag.*/
    UsefulOutBuf UOB;
    UsefulOutBuf_Init(&UOB, ciphertext_buffer);
    UsefulOutBuf_AppendUsefulBuf(&UOB, plaintext);
    UsefulOutBuf_AppendUsefulBuf(&UOB, tag);
    *ciphertext = UsefulOutBuf_OutUBuf(&UOB);

    if(q_useful_buf_c_is_null(*ciphertext)) {
        return T_COSE_ERR_TOO_SMALL;
    }

    return T_COSE_SUCCESS;
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
    struct q_useful_buf_c expected_tag = Q_USEFUL_BUF_FROM_SZ_LITERAL(FAKE_TAG);
    struct q_useful_buf_c received_tag;
    struct q_useful_buf_c received_plaintext;

    (void)nonce;
    (void)aad;
    (void)cose_algorithm_id;
    (void)key;

    UsefulInputBuf UIB;
    UsefulInputBuf_Init(&UIB, ciphertext);
    if(ciphertext.len < expected_tag.len) {
        return T_COSE_ERR_DECRYPT_FAIL;
    }
    received_plaintext = UsefulInputBuf_GetUsefulBuf(&UIB, ciphertext.len - expected_tag.len);
    received_tag = UsefulInputBuf_GetUsefulBuf(&UIB, expected_tag.len);

    if(q_useful_buf_compare(expected_tag, received_tag)) {
        return T_COSE_ERR_DATA_AUTH_FAILED;
    }

    *plaintext = q_useful_buf_copy(plaintext_buffer, received_plaintext);

    if(q_useful_buf_c_is_null(*plaintext)) {
        return T_COSE_ERR_TOO_SMALL;
    }

    return T_COSE_SUCCESS;
}


static const uint8_t rfc_3394_key_wrap_iv[] = {0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6};

enum t_cose_err_t
t_cose_crypto_kw_wrap(int32_t                 cose_algorithm_id,
                      struct t_cose_key   kek,
                      struct q_useful_buf_c   plaintext,
                      struct q_useful_buf     ciphertext_buffer,
                      struct q_useful_buf_c  *ciphertext_result)
{
    UsefulOutBuf UOB;

    (void)cose_algorithm_id;
    (void)kek;

    UsefulOutBuf_Init(&UOB, ciphertext_buffer);
    UsefulOutBuf_AppendUsefulBuf(&UOB, plaintext);
    UsefulOutBuf_AppendUsefulBuf(&UOB, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(rfc_3394_key_wrap_iv));
    *ciphertext_result = UsefulOutBuf_OutUBuf(&UOB);

    if(q_useful_buf_c_is_null(*ciphertext_result)){
        return T_COSE_ERR_TOO_SMALL;
    }

    return T_COSE_SUCCESS;
}


enum t_cose_err_t
t_cose_crypto_kw_unwrap(int32_t                 cose_algorithm_id,
                        struct t_cose_key   kek,
                        struct q_useful_buf_c   ciphertext,
                        struct q_useful_buf     plaintext_buffer,
                        struct q_useful_buf_c  *plaintext_result)
{
    UsefulBufC                  tag;
    struct q_useful_buf_c       plain_text;
    const struct q_useful_buf_c expected_tag = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(rfc_3394_key_wrap_iv);

    (void)cose_algorithm_id;
    (void)kek;

    UsefulInputBuf UIB;
    UsefulInputBuf_Init(&UIB, ciphertext);

    plain_text = UsefulInputBuf_GetUsefulBuf(&UIB, ciphertext.len - expected_tag.len);
    tag = UsefulInputBuf_GetUsefulBuf(&UIB, expected_tag.len);

    if(UsefulBuf_Compare(tag, expected_tag)) {
        return T_COSE_ERR_DATA_AUTH_FAILED;
    }

    *plaintext_result = UsefulBuf_Copy(plaintext_buffer, plain_text);
    if(q_useful_buf_c_is_null(*plaintext_result)) {
        return T_COSE_ERR_TOO_SMALL;
    }

    return T_COSE_SUCCESS;
}




enum t_cose_err_t
t_cose_crypto_hkdf(const int32_t               cose_hash_algorithm_id,
                   const struct q_useful_buf_c salt,
                   const struct q_useful_buf_c ikm,
                   const struct q_useful_buf_c info,
                   const struct q_useful_buf   okm_buffer)
{
    (void)cose_hash_algorithm_id;
    (void)salt;
    (void)ikm;
    (void)info;
    /* This makes a fixed fake output of all x's */
    (void)UsefulBuf_Set(okm_buffer, 'x');
    return T_COSE_SUCCESS;
}


/*
 * See documentation in t_cose_crypto.h
 */
enum t_cose_err_t
t_cose_crypto_import_ec2_pubkey(int32_t               cose_ec_curve_id,
                                struct q_useful_buf_c x_coord,
                                struct q_useful_buf_c y_coord,
                                bool                  y_bool,
                                struct t_cose_key    *pub_key)
{
    (void)cose_ec_curve_id;
    (void)x_coord;
    (void)y_coord;
    (void)y_bool;
    (void)pub_key;

    return T_COSE_ERR_FAIL;
}


enum t_cose_err_t
t_cose_crypto_export_ec2_key(struct t_cose_key     pub_key,
                             int32_t               *curve,
                             struct q_useful_buf    x_coord_buf,
                             struct q_useful_buf_c *x_coord,
                             struct q_useful_buf    y_coord_buf,
                             struct q_useful_buf_c *y_coord,
                             bool                  *y_bool)
{
    (void)curve;
    (void)x_coord;
    (void)x_coord_buf;
    (void)y_coord_buf;
    (void)y_coord;
    (void)y_bool;
    (void)pub_key;

    return T_COSE_ERR_FAIL;
}

enum t_cose_err_t
t_cose_crypto_ecdh(struct t_cose_key      private_key,
                   struct t_cose_key      public_key,
                   struct q_useful_buf    shared_key_buf,
                   struct q_useful_buf_c *shared_key)
{
    (void)private_key;
    (void)public_key;
    (void)shared_key_buf;
    (void)shared_key;

    return T_COSE_ERR_FAIL;

}
