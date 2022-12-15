/*
 * t_cose_encrypt_dec.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */
#include "t_cose/t_cose_encrypt_dec.h"
#include "t_cose/t_cose_standard_constants.h"
#include "qcbor/qcbor.h"
#include <stdio.h>
#include <stdlib.h>
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose_crypto.h"

enum t_cose_err_t
t_cose_encrypt_dec(struct t_cose_encrypt_dec_ctx* me,
                   uint8_t *cose,
                   size_t cose_len,
                   uint8_t *detached_ciphertext,
                   size_t detached_ciphertext_len,
                   uint8_t *plaintext,
                   size_t plaintext_len,
                   size_t *plaintext_output_len)
{
#if !defined(T_COSE_DISABLE_HPKE) && !defined(T_COSE_DISABLE_AES_KW)

    QCBORItem              protected_hdr;
    UsefulBufC             nonce_cbor;
    UsefulBufC             kid_cbor;
    int64_t                algorithm_id = 0;
    QCBORDecodeContext     DC, DC2;
    QCBORItem              Item;
    QCBORItem              Cipher;
    QCBORError             result;
    enum t_cose_err_t      cose_result;
    size_t                 key_bitlen;
    int64_t                alg = 0;
    uint8_t               *ciphertext;
    size_t                 ciphertext_len;

    int64_t                kty;
    int64_t                crv;
    UsefulBufC             peer_key_x;
    UsefulBufC             peer_key_y;

    /* Temporary storge area */
    uint8_t                tmp[50];
    /* Temporary storge area for encrypted cek. */
    uint8_t                tmp2[50];
    UsefulBufC             ephemeral = {(uint8_t *) tmp, sizeof(tmp)};
    UsefulBufC             cek_encrypted = {(uint8_t *) tmp2, sizeof(tmp2)};
    size_t                 peer_key_buf_len = 0;
    /*  Temporary storge area for encrypted cek. */
    uint8_t                peer_key_buf[T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE] = {0x04};

    uint8_t                add_data[20];
    size_t                 add_data_len = sizeof(add_data);
    struct q_useful_buf    add_data_struct = {add_data, add_data_len};
    UsefulBufC             add_data_buf;
    QCBOREncodeContext     additional_data;
    bool                   detached_mode;
    uint8_t                cek[T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_ENCRYPTION_MAX_KEY_LENGTH)];
    size_t                 cek_len = T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_ENCRYPTION_MAX_KEY_LENGTH);
    struct t_cose_key      cek_key;


    /* Initialize decoder */
    QCBORDecode_Init(&DC,
                     (UsefulBufC){cose, cose_len},
                     QCBOR_DECODE_MODE_NORMAL);

   /* Make sure the first item is a tag */
    result = QCBORDecode_GetNext(&DC, &Item);

    /* Check whether tag is CBOR_TAG_COSE_ENCRYPT or CBOR_TAG_COSE_ENCRYPT0 */
    if (QCBORDecode_IsTagged(&DC, &Item, CBOR_TAG_COSE_ENCRYPT) == false &&
        QCBORDecode_IsTagged(&DC, &Item, CBOR_TAG_COSE_ENCRYPT0) == false) {
        return(T_COSE_ERR_INCORRECTLY_TAGGED);
    }

    /* protected header */
    result = QCBORDecode_GetNext(&DC, &protected_hdr);

    if (result != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_FORMATTING);
    }

    if (protected_hdr.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return(T_COSE_ERR_PARAMETER_CBOR);
    }

    /* Re-initialize to parse protected header */
    QCBORDecode_Init(&DC2,
                     (UsefulBufC)
                     {
                      protected_hdr.val.string.ptr,
                      protected_hdr.val.string.len
                     },
                     QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterMap(&DC2, NULL);

    QCBORDecode_GetInt64InMapN(&DC2, T_COSE_HEADER_PARAM_ALG, &algorithm_id);

    QCBORDecode_ExitMap(&DC2);

    result = QCBORDecode_Finish(&DC2);

    if (result != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_FORMATTING);
    }

    /* unprotected header */
    QCBORDecode_EnterMap(&DC, NULL);

    QCBORDecode_GetByteStringInMapN(&DC, T_COSE_HEADER_PARAM_IV, &nonce_cbor);

    if (QCBORDecode_GetError(&DC) !=0 ) {
         return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
    }

    if (me->key_distribution == T_COSE_KEY_DISTRIBUTION_DIRECT) {
        QCBORDecode_GetByteStringInMapN(&DC, T_COSE_HEADER_PARAM_KID, &kid_cbor);

        if (QCBORDecode_GetError(&DC) !=0 ) {
             return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
        }
    }

    QCBORDecode_ExitMap(&DC);

    /* Ciphertext */
    result = QCBORDecode_GetNext(&DC, &Cipher);

    if (result != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_FORMATTING);
    }

    if (Cipher.val.string.len != 0) {
        ciphertext = (uint8_t *) Cipher.val.string.ptr;
        ciphertext_len = Cipher.val.string.len;
        detached_mode = false;
    } else {
        ciphertext = detached_ciphertext;
        ciphertext_len = detached_ciphertext_len;
        detached_mode = true;
    }

    /* Two key distribution mechanisms are supported, namely
     *  - Direct key distribution (where no recipient info is included)
     *  - HPKE-based key distribution (which requires recipient info)
     */
    if (me->key_distribution == T_COSE_KEY_DISTRIBUTION_DIRECT) {
        if (kid_cbor.len == 0 ||
            strncmp(me->kid.ptr, kid_cbor.ptr, me->kid.len) != 0
           ) {
                return(T_COSE_ERR_UNKNOWN_KEY);
        }
    } else {
        /* Recipients */
        QCBORDecode_EnterArray(&DC, NULL);

        /* protected header */
        result = QCBORDecode_GetNext(&DC, &Item);

        if (result != QCBOR_SUCCESS) {
            return(T_COSE_ERR_CBOR_FORMATTING);
        }

        if (Item.uDataType != QCBOR_TYPE_BYTE_STRING) {
             return(T_COSE_ERR_PARAMETER_CBOR);
        }

        if (protected_hdr.uDataType != QCBOR_TYPE_BYTE_STRING) {
             return(T_COSE_ERR_PARAMETER_CBOR);
        }

        /* Re-initialize to parse protected header */
        QCBORDecode_Init(&DC2,
                         (UsefulBufC)
                         {
                          Item.val.string.ptr,
                          Item.val.string.len
                         },
                         QCBOR_DECODE_MODE_NORMAL);

        QCBORDecode_EnterMap(&DC2, NULL);

        /* Retrieve algorithm */
        QCBORDecode_GetInt64InMapN(&DC2, T_COSE_HEADER_PARAM_ALG, &alg);

        result = QCBORDecode_GetError(&DC2);

        if (result != QCBOR_SUCCESS) {
             return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
        }

        QCBORDecode_ExitMap(&DC2);

        result = QCBORDecode_Finish(&DC2);

        if (result != QCBOR_SUCCESS) {
            return(T_COSE_ERR_CBOR_FORMATTING);
        }

        /* Setting key distribution parameters. */
        switch(alg) {
        case T_COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM:
            key_bitlen = 128;
            break;

        case T_COSE_ALGORITHM_HPKE_P521_HKDF512_AES256_GCM:
            key_bitlen = 256;
           break;

        default:
            return(T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG);
        }

        /* unprotected header */
        QCBORDecode_EnterMap(&DC, NULL);

        /* get ephemeral */
        QCBORDecode_GetByteStringInMapN(&DC,
                                        T_COSE_HEADER_ALG_PARAM_EPHEMERAL_KEY,
                                        &ephemeral);

        result = QCBORDecode_GetError(&DC);

        if (result != QCBOR_SUCCESS) {
            return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
        }

        /* Decode ephemeral */
        QCBORDecode_Init(&DC2,
                         (UsefulBufC)
                         {
                          ephemeral.ptr,
                          ephemeral.len
                         },
                         QCBOR_DECODE_MODE_NORMAL);

        QCBORDecode_EnterMap(&DC2, NULL);

        /* -- get kty paramter */
        QCBORDecode_GetInt64InMapN(&DC2,
                                   T_COSE_KEY_COMMON_KTY,
                                   &kty);

        result = QCBORDecode_GetError(&DC2);

        if (result != QCBOR_SUCCESS) {
            return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
        }

        QCBORDecode_GetInt64InMapN(&DC2,
                                   T_COSE_KEY_PARAM_CRV,
                                   &crv);

        result = QCBORDecode_GetError(&DC2);

        if (result != QCBOR_SUCCESS) {
            return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
        }

        /* -- get x parameter */
        QCBORDecode_GetByteStringInMapN(&DC2,
                                        T_COSE_KEY_PARAM_X_COORDINATE,
                                        &peer_key_x);

        result = QCBORDecode_GetError(&DC2);

        if (result != QCBOR_SUCCESS) {
            return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
        }

        /* Check whether the key size is expected */
        if (peer_key_x.len != key_bitlen / 4) {
            return(T_COSE_ERR_EPHEMERAL_KEY_SIZE_INCORRECT);
        }

        /* Copy the x-part of the key into the peer key buffer */
        if (peer_key_x.len > T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE / 2) {
            return(T_COSE_ERR_EPHEMERAL_KEY_SIZE_INCORRECT);
        }

        memcpy(peer_key_buf+1, peer_key_x.ptr, peer_key_x.len);
        peer_key_buf_len = 1+peer_key_x.len;

        /* -- get y parameter */
        QCBORDecode_GetByteStringInMapN(&DC2,
                                        T_COSE_KEY_PARAM_Y_COORDINATE,
                                        &peer_key_y);

        result = QCBORDecode_GetError(&DC2);

        if (result != QCBOR_SUCCESS) {
            return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
        }

        /* Check whether the key size is expected */
        if (peer_key_y.len != key_bitlen / 4) {
            return(T_COSE_ERR_EPHEMERAL_KEY_SIZE_INCORRECT);
        }

        /* Copy the y-part of the key into the peer key buffer */
        if (peer_key_x.len > T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE / 2) {
            return(T_COSE_ERR_EPHEMERAL_KEY_SIZE_INCORRECT);
        }

        memcpy(peer_key_buf+1+peer_key_x.len, peer_key_y.ptr, peer_key_y.len);
        peer_key_buf_len += peer_key_y.len;

        QCBORDecode_ExitMap(&DC2);

        /* get kid */
        QCBORDecode_GetByteStringInMapN(&DC,
                                        T_COSE_HEADER_PARAM_KID,
                                        &kid_cbor);

        result = QCBORDecode_GetError(&DC);

        if (result != QCBOR_SUCCESS) {
            return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
        }

        if (kid_cbor.len == 0 ||
            strncmp(me->kid.ptr, kid_cbor.ptr, me->kid.len) != 0
           ) {
            return(T_COSE_ERR_UNKNOWN_KEY);
        }

        QCBORDecode_ExitMap(&DC);

        /* get CEK */
        QCBORDecode_GetByteString(&DC, &cek_encrypted);

        result = QCBORDecode_GetError(&DC);

        if (result != QCBOR_SUCCESS) {
            return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
        }

        /* Execute HPKE */
        cose_result = t_cose_crypto_hpke_decrypt((int32_t) alg,
                                                 (struct q_useful_buf_c)
                                                 {
                                                     .len = peer_key_buf_len,
                                                     .ptr = peer_key_buf
                                                 },
                                                 me->recipient_key,
                                                 cek_encrypted,
                                                 (struct q_useful_buf)
                                                 {
                                                     .len = cek_len,
                                                     .ptr = cek
                                                 },
                                                 &cek_len);

        if (cose_result != T_COSE_SUCCESS) {
            return(cose_result);
        }
    }

    /* Create Additional Data Structure
    *
    *  Enc_structure = [
    *    context : "Encrypt" or "Encrypt0",
    *    protected : empty_or_serialized_map,
    *    external_aad : bstr
    *  ]
    */

    /* Initialize additional data CBOR array */
    QCBOREncode_Init(&additional_data, add_data_struct);

    QCBOREncode_BstrWrap(&additional_data);

    /* Open array */
    QCBOREncode_OpenArray(&additional_data);

    /* 1. Add context string "Encrypt0" or "Encrypt" */
    if (me->key_distribution == T_COSE_KEY_DISTRIBUTION_DIRECT) {
        QCBOREncode_AddText(&additional_data,
                            ((UsefulBufC) {"Encrypt0", 8})
                           );
    } else {
        QCBOREncode_AddText(&additional_data,
                            ((UsefulBufC) {"Encrypt", 7})
                           );
    }

    /* 2. Add protected headers (as bstr) */
    QCBOREncode_BstrWrap(&additional_data);

    QCBOREncode_OpenMap(&additional_data);

    QCBOREncode_AddInt64ToMapN(&additional_data,
                               T_COSE_HEADER_PARAM_ALG,
                               algorithm_id);

    QCBOREncode_CloseMap(&additional_data);
    QCBOREncode_CloseBstrWrap2(&additional_data,
                               false,
                               &add_data_buf);

    /* 3. Add any externally provided additional data,
     *    which is empty in our case.
     */
    QCBOREncode_BstrWrap(&additional_data);
    QCBOREncode_CloseBstrWrap2(&additional_data,
                               false,
                               &add_data_buf);

    /* Close array */
    QCBOREncode_CloseArray(&additional_data);

    QCBOREncode_CloseBstrWrap2(&additional_data,
                               false,
                               &add_data_buf);

    /* Finish and check the results */
    result = QCBOREncode_Finish(&additional_data,
                                &add_data_buf);

    if (result != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_FORMATTING);
    }

    if (me->key_distribution == T_COSE_KEY_DISTRIBUTION_HPKE) {

        cose_result = t_cose_crypto_get_cose_key((int32_t) algorithm_id,
                                                 cek,
                                                 cek_len,
                                                 T_COSE_KEY_USAGE_FLAG_DECRYPT,
                                                 &cek_key);

        if (cose_result != T_COSE_SUCCESS) {
            return(cose_result);
        }
        cose_result = t_cose_crypto_decrypt((int32_t) algorithm_id,
                                            cek_key,
                                            nonce_cbor,
                                            add_data_buf,
            (struct q_useful_buf_c) {.ptr = ciphertext, .len = ciphertext_len},
            (struct q_useful_buf) {.ptr = plaintext, .len = plaintext_len},
                                            plaintext_output_len);

        // TODO: put this in crypto layer
        // TODO: find the other key memory leaks (pretty sure there are some...)
        psa_close_key((psa_key_handle_t)cek_key.k.key_handle);

    } else {
        cose_result = t_cose_crypto_decrypt((int32_t) algorithm_id,
                                            me->recipient_key,
                                            nonce_cbor,
                                            add_data_buf,
            (struct q_useful_buf_c) {.ptr = ciphertext, .len = ciphertext_len},
            (struct q_useful_buf) {.ptr = plaintext, .len = plaintext_len},
                                            plaintext_output_len);
    }

    if (cose_result != T_COSE_SUCCESS) {
        return(cose_result);
    }

    return(T_COSE_SUCCESS);
#else /* T_COSE_DISABLE_HPKE */
    (void)me;
    (void)cose;
    (void)cose_len;
    (void)detached_ciphertext;
    (void)detached_ciphertext_len;
    (void)plaintext;
    (void)plaintext_len;
    (void)plaintext_output_len;

    return T_COSE_ERR_FAIL;
#endif /* T_COSE_DISABLE_HPKE */
}
