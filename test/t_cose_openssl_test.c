/*
 *  t_cose_openssl_test.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose_openssl_test.h"
#include "t_cose_sign1_sign.h"
#include "t_cose_sign1_verify.h"
#include "q_useful_buf.h"

#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h" /* for NID for EC curve */
#include "openssl/err.h"


/*
 * Some hard coded keys for the test cases here.
 */
#define PUBLIC_KEY_prime256v1 \
    "0437ab65955fae0466673c3a2934a3" \
    "4f2f0ec2b3eec224198557998fc04b" \
    "f4b2b495d9798f2539c90d7d102b3b" \
    "bbda7fcbdb0e9b58d4e1ad2e61508d" \
    "a75f84a67b"

#define PRIVATE_KEY_prime256v1 \
    "f1b7142343402f3b5de7315ea894f9" \
    "da5cf503ff7938a37ca14eb0328698" \
    "8450"


#define PUBLIC_KEY_secp384r1 \
    "04bdd9c3f818c9cef3e11e2d40e775" \
    "beb37bc376698d71967f93337a4e03" \
    "2dffb11b505067dddb4214b56d9bce" \
    "c59177eccd8ab05f50975933b9a738" \
    "d90c0b07eb9519567ef9075807cf77" \
    "139fc1fe85608851361136806123ed" \
    "c735ce5a03e8e4"

#define PRIVATE_KEY_secp384r1 \
    "03df14f4b8a43fd8ab75a6046bd2b5" \
    "eaa6fd10b2b203fd8a78d7916de20a" \
    "a241eb37ec3d4c693d23ba2b4f6e5b" \
    "66f57f"


#define PUBLIC_KEY_secp521r1 \
    "0400e4d253175a14311fc2dd487687" \
    "70cb49b07bd15d327beb98aa33e60c" \
    "d0181b17fb8f1cbf07dbc8652ff5b7" \
    "b4452c082e0686c0fab8089071cbc5" \
    "37101d344b94c201e6424f3a18da4f" \
    "20ecabfbc84b8467c217cd67055fa5" \
    "dec7fb1ae87082302c1813caa4b7b1" \
    "cf28d94677e486fb4b317097e9307a" \
    "bdb9d50187779a3d1e682c123c"

#define PRIVATE_KEY_secp521r1 \
    "0045d2d1439435fab333b1c6c8b534" \
    "f0969396ad64d5f535d65f68f2a160" \
    "6590bb15fd5322fc97a416c395745e" \
    "72c7c85198c0921ab3b8e92dd901b5" \
    "a42159adac6d"



/*
 * The key object returned by this is malloced and has to be freed. This
 * heap use is a part of OpenSSL and not t_cose which does not use the heap
 */
static int make_ecdsa_key_pair(struct t_cose_key *ossl_key, int32_t cose_alg)
{
    EC_GROUP          *ossl_ec_group = NULL;
    enum t_cose_err_t  return_value;
    BIGNUM            *ossl_private_key_bn = NULL;
    EC_KEY            *ossl_ec_key = NULL;
    int                ossl_result;
    EC_POINT          *ossl_pub_key_point = NULL;
    int                nid;
    const char        *public_key;
    const char        *private_key;

    switch (cose_alg) {
        case T_COSE_ALGORITHM_ES256:
            nid = NID_X9_62_prime256v1;
            public_key = PUBLIC_KEY_prime256v1;
            private_key =  PRIVATE_KEY_prime256v1 ;
            break;

        case T_COSE_ALGORITHM_ES384:
            nid = NID_secp384r1;
            public_key = PUBLIC_KEY_secp384r1;
            private_key = PRIVATE_KEY_secp384r1;
            break;

        case T_COSE_ALGORITHM_ES512:
            nid = NID_secp521r1;
            public_key = PUBLIC_KEY_secp521r1;
            private_key = PRIVATE_KEY_secp521r1;
            break;

    default:
        return -1;
    }


    /* Make a group for the particular EC algorithm */
    ossl_ec_group = EC_GROUP_new_by_curve_name(nid);
    if(ossl_ec_group == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Make an empty EC key object */
    ossl_ec_key = EC_KEY_new();
    if(ossl_ec_key == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Associate group with key object */
    ossl_result = EC_KEY_set_group(ossl_ec_key, ossl_ec_group);
    if (!ossl_result) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Make an instance of a big number to store the private key */
    ossl_private_key_bn = BN_new();
    if(ossl_private_key_bn == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }
    BN_zero(ossl_private_key_bn);

    /* Stuff the specific private key into the big num */
    ossl_result = BN_hex2bn(&ossl_private_key_bn, private_key);
    if(ossl_private_key_bn == 0) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Now associate the big num with the key object so we finally
     * have a key set up and ready for signing */
    ossl_result = EC_KEY_set_private_key(ossl_ec_key, ossl_private_key_bn);
    if (!ossl_result) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }


    /* Make an empty EC point into which the public key gets loaded */
    ossl_pub_key_point = EC_POINT_new(ossl_ec_group);
    if(ossl_pub_key_point == NULL) {
        return_value = T_COSE_ERR_INSUFFICIENT_MEMORY;
        goto Done;
    }

    /* Turn the serialized public key into an EC point */
    ossl_pub_key_point = EC_POINT_hex2point(ossl_ec_group,
                                            public_key,
                                            ossl_pub_key_point,
                                            NULL);
    if(ossl_pub_key_point == NULL) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    /* Associate the EC point with key object */
    /* The key object has both the public and private keys in it */
    ossl_result = EC_KEY_set_public_key(ossl_ec_key, ossl_pub_key_point);
    if(ossl_result == 0) {
        return_value = T_COSE_ERR_SIG_FAIL;
        goto Done;
    }

    ossl_key->crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL;
    ossl_key->k.key_ptr  = ossl_ec_key;
    return_value         = T_COSE_SUCCESS;

Done:
    return return_value;
}


static void free_ecdsa_key_pair(struct t_cose_key ossl_key)
{
    EC_KEY_free(ossl_key.k.key_ptr);
}


int_fast32_t openssl_basic_test_alg(int32_t cose_alg)
{
    struct t_cose_sign1_sign_ctx   sign_ctx;
    enum t_cose_err_t              return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct t_cose_key              ossl_key;
    struct q_useful_buf_c          payload;
    struct t_cose_sign1_verify_ctx verify_ctx;

    /* -- Get started with context initialization, selecting the alg -- */
    t_cose_sign1_sign_init(&sign_ctx, 0, cose_alg);

    /* Make an ECDSA key pair that will be used for both signing and
     * verification.
     */
    return_value = make_ecdsa_key_pair(&ossl_key, cose_alg);
    if(return_value) {
        return 1000 + return_value;
    }
    t_cose_sign1_set_signing_key(&sign_ctx, ossl_key,  NULL_Q_USEFUL_BUF_C);

    t_cose_sign1_sign(&sign_ctx,
                      Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"),
                      signed_cose_buffer,
                      &signed_cose);
    if(return_value) {
        return 2000 + return_value;
    }

    /* Verification */
    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, ossl_key);

    return_value = t_cose_sign1_verify(&verify_ctx,
                                       signed_cose,         /* COSE to verify */
                                       &payload,  /* Payload from signed_cose */
                                       NULL);         /* Don't return headers */
    if(return_value) {
        return 5000 + return_value;
    }

    /* OpenSSL uses malloc to allocate buffers for keys, so they have to be freed */
    free_ecdsa_key_pair(ossl_key);

    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"))) {
        return 6000;
    }

    return 0;
}


int_fast32_t openssl_basic_test()
{
    int_fast32_t return_value;

    return_value  = openssl_basic_test_alg(T_COSE_ALGORITHM_ES256);
    if(return_value) {
        return 20000 + return_value;
    }

#ifndef T_COSE_DISABLE_ES384
    return_value  = openssl_basic_test_alg(T_COSE_ALGORITHM_ES384);
    if(return_value) {
        return 30000 + return_value;
    }
#endif

#ifndef T_COSE_DISABLE_ES512
    return_value  = openssl_basic_test_alg(T_COSE_ALGORITHM_ES512);
    if(return_value) {
        return 50000 + return_value;
    }
#endif

    return 0;

}


int_fast32_t openssl_sig_fail_test()
{
    struct t_cose_sign1_sign_ctx   sign_ctx;
    QCBOREncodeContext             cbor_encode;
    enum t_cose_err_t              return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct t_cose_key              ossl_key;
    struct q_useful_buf_c          payload;
    QCBORError                     cbor_error;
    struct t_cose_sign1_verify_ctx verify_ctx;


    /* Make an ECDSA key pair that will be used for both signing and
     * verification.
     */
    return_value = make_ecdsa_key_pair(&ossl_key, T_COSE_ALGORITHM_ES256);
    if(return_value) {
        return 1000 + return_value;
    }

    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);

    t_cose_sign1_sign_init(&sign_ctx,  0,  T_COSE_ALGORITHM_ES256);
    t_cose_sign1_set_signing_key(&sign_ctx, ossl_key,NULL_Q_USEFUL_BUF_C);

    return_value = t_cose_sign1_encode_headers(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + return_value;
    }

    QCBOREncode_AddSZString(&cbor_encode, "payload");


    return_value = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 3000 + return_value;
    }

    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 4000 + cbor_error;
    }

    /* tamper with the pay load to see that the signature verification fails */
    size_t xx = q_useful_buf_find_bytes(signed_cose,
                                        Q_USEFUL_BUF_FROM_SZ_LITERAL("payload"));
    if(xx == SIZE_MAX) {
        return 99;
    }
    ((char *)signed_cose.ptr)[xx] = 'h';


    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, ossl_key);

    return_value = t_cose_sign1_verify(&verify_ctx,
                                       signed_cose,         /* COSE to verify */
                                       &payload,  /* Payload from signed_cose */
                                       NULL);         /* Don't return headers */

    if(return_value != T_COSE_ERR_SIG_VERIFY) {
        return 5000 + return_value;
    }

    free_ecdsa_key_pair(ossl_key);

    return 0;
}


int_fast32_t openssl_make_cwt_test()
{
    struct t_cose_sign1_sign_ctx   sign_ctx;
    QCBOREncodeContext             cbor_encode;
    enum t_cose_err_t              return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(    signed_cose_buffer, 300);
    struct q_useful_buf_c          signed_cose;
    struct t_cose_key              ossl_key;
    struct q_useful_buf_c          payload;
    QCBORError                     cbor_error;
    struct t_cose_sign1_verify_ctx verify_ctx;


    
    /* -- initialize for signing --
     *  No special options selected
     */
    t_cose_sign1_sign_init(&sign_ctx,  0,  T_COSE_ALGORITHM_ES256);


    /* -- Key and kid --
     * The ECDSA key pair made is both for signing and verification.
     * The kid comes from RFC 8932
     */
    return_value = make_ecdsa_key_pair(&ossl_key, T_COSE_ALGORITHM_ES256);
    if(return_value) {
        return 1000 + return_value;
    }
    t_cose_sign1_set_signing_key(&sign_ctx,
                         ossl_key,
                         Q_USEFUL_BUF_FROM_SZ_LITERAL("AsymmetricECDSA256"));


    /* -- Encoding context and output of headers -- */
    QCBOREncode_Init(&cbor_encode, signed_cose_buffer);
    return_value = t_cose_sign1_encode_headers(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + return_value;
    }


    /* -- The payload as from RFC 8932 -- */
    QCBOREncode_OpenMap(&cbor_encode);
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 1, "coap://as.example.com");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 2, "erikw");
    QCBOREncode_AddSZStringToMapN(&cbor_encode, 3, "coap://light.example.com");
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 4, 1444064944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 5, 1443944944);
    QCBOREncode_AddInt64ToMapN(&cbor_encode, 6, 1443944944);
    const uint8_t xx[] = {0x0b, 0x71};
    QCBOREncode_AddBytesToMapN(&cbor_encode, 7, Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(xx));
    QCBOREncode_CloseMap(&cbor_encode);


    /* -- Finish up the COSE_Sign1. This is where the signing happens -- */
    return_value = t_cose_sign1_encode_signature(&sign_ctx, &cbor_encode);
    if(return_value) {
        return 2000 + return_value;
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    cbor_error = QCBOREncode_Finish(&cbor_encode, &signed_cose);
    if(cbor_error) {
        return 3000 + cbor_error;
    }
    /* --- Done making COSE Sign1 object  --- */


    /* Compare to expected from CWT RFC */
    /* The first part, the intro and protected headers must be the same */
    const uint8_t rfc8392_first_part_bytes[] = {
        0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa1, 0x04, 0x52, 0x41, 0x73, 0x79,
        0x6d, 0x6d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x45, 0x43, 0x44, 0x53, 0x41,
        0x32, 0x35, 0x36, 0x58, 0x50, 0xa7, 0x01, 0x75, 0x63, 0x6f, 0x61, 0x70,
        0x3a, 0x2f, 0x2f, 0x61, 0x73, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x02, 0x65, 0x65, 0x72, 0x69, 0x6b, 0x77,
        0x03, 0x78, 0x18, 0x63, 0x6f, 0x61, 0x70, 0x3a, 0x2f, 0x2f, 0x6c, 0x69,
        0x67, 0x68, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
        0x63, 0x6f, 0x6d, 0x04, 0x1a, 0x56, 0x12, 0xae, 0xb0, 0x05, 0x1a, 0x56,
        0x10, 0xd9, 0xf0, 0x06, 0x1a, 0x56, 0x10, 0xd9, 0xf0, 0x07, 0x42, 0x0b,
        0x71};
    struct q_useful_buf_c fp = Q_USEFUL_BUF_FROM_BYTE_ARRAY_LITERAL(rfc8392_first_part_bytes);
    struct q_useful_buf_c head = q_useful_buf_head(signed_cose, sizeof(rfc8392_first_part_bytes));
    if(q_useful_buf_compare(head, fp)) {
        return -1;
    }

    /* --- Start verifying the COSE Sign1 object  --- */
    /* Run the signature verification */
    t_cose_sign1_verify_init(&verify_ctx, 0);

    t_cose_sign1_set_verification_key(&verify_ctx, ossl_key);

    return_value =
        t_cose_sign1_verify(&verify_ctx,
                            signed_cose,                    /* COSE to verify */
                            &payload,             /* Payload from signed_cose */
                            NULL);         /* Don't return headers */

    if(return_value) {
        return 4000 + return_value;
    }

    /* Format the expected payload CBOR fragment */

    /* Skip the key id, because this has the short-circuit key id */
    const size_t kid_encoded_len =
      1 +
      1 +
      1 +
      strlen("AsymmetricECDSA256"); // length of short-circuit key id


    /* compare payload output to the one expected */
    if(q_useful_buf_compare(payload, q_useful_buf_tail(fp, kid_encoded_len + 8))) {
        return 5000;
    }
    /* --- Done verifying the COSE Sign1 object  --- */

    return 0;
}
