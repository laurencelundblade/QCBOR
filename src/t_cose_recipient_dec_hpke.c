/*
 * t_cose_recipient_dec_hpke.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.

 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */


#ifndef T_COSE_DISABLE_HPKE

#include <stdint.h>
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_recipient_dec_hpke.h"  /* Interface implemented */
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_crypto.h"
#include "hpke.h"


/**
 * See definition in t_cose_recipient_dec_hpke.h
 */
enum t_cose_err_t
t_cose_crypto_hpke_decrypt(int32_t                cose_algorithm_id,
                           struct q_useful_buf_c  pkE,
                           struct t_cose_key      pkR,
                           struct q_useful_buf_c  ciphertext,
                           struct q_useful_buf    plaintext,
                           size_t                *plaintext_len)
{
    hpke_suite_t           suite;
    size_t                 key_bitlen;
    int                    ret;

    /* Setting key distribution parameters. */
    switch(cose_algorithm_id) {
    case T_COSE_ALGORITHM_HPKE_P256_HKDF256_AES128_GCM:
        key_bitlen = 128;
        suite.kem_id = HPKE_KEM_ID_P256;
        suite.kdf_id = HPKE_KDF_ID_HKDF_SHA256;
        suite.aead_id = HPKE_AEAD_ID_AES_GCM_128;
        break;

    case T_COSE_ALGORITHM_HPKE_P521_HKDF512_AES256_GCM:
        key_bitlen = 256;
        suite.kem_id = HPKE_KEM_ID_P521;
        suite.kdf_id = HPKE_KDF_ID_HKDF_SHA512;
        suite.aead_id = HPKE_AEAD_ID_AES_GCM_256;
        break;

    default:
        return(T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG);
    }

    (void)key_bitlen; // TODO: use this or get rid of it.

    /* Execute HPKE */
    *plaintext_len = plaintext.len;

    ret = mbedtls_hpke_decrypt(
            HPKE_MODE_BASE,                  // HPKE mode
            suite,                           // ciphersuite
            NULL, 0, NULL,                   // PSK for authentication
            0, NULL,                         // pkS
            (psa_key_handle_t)
            pkR.key.handle,                // skR handle
            pkE.len,                         // pkE_len
            pkE.ptr,                         // pkE
            ciphertext.len,                  // Ciphertext length
            ciphertext.ptr,                  // Ciphertext
            0, NULL,                         // Additional data
            0, NULL,                         // Info
            plaintext_len,                   // Plaintext length
            (uint8_t *) plaintext.ptr        // Plaintext
        );

    if (ret != 0) {
        return(T_COSE_ERR_HPKE_DECRYPT_FAIL);
    }

    return(T_COSE_SUCCESS);
}


/* This is an implementation of t_cose_recipient_dec_cb */
enum t_cose_err_t
t_cose_recipient_dec_hpke_cb_private(struct t_cose_recipient_dec *me_x,
                                     const struct t_cose_header_location loc,
                                     QCBORDecodeContext *cbor_decoder,
                                     struct q_useful_buf cek_buffer,
                                     struct t_cose_parameter_storage *p_storage,
                                     struct t_cose_parameter **params,
                                     struct q_useful_buf_c *cek)
{
    struct t_cose_recipient_dec_hpke *me;
    QCBORItem              Item;
    QCBORError             result;
    QCBORDecodeContext     DC2;
    int64_t                alg = 0;
    size_t                 key_bitlen;
    uint8_t                tmp2[50];
    uint8_t                tmp[50];

    UsefulBufC             hpke_sender_info = {(uint8_t *) tmp, sizeof(tmp)};

    uint64_t               kem_id;
    uint64_t               kdf_id;
    uint64_t               aead_id;
    UsefulBufC             enc;

    UsefulBufC             cek_encrypted = {(uint8_t *) tmp2, sizeof(tmp2)};
    size_t                 peer_key_buf_len = 0;
    /*  Temporary storge area for encrypted cek. */
    uint8_t                peer_key_buf[T_COSE_EXPORT_PUBLIC_KEY_MAX_SIZE] = {0x04};

    UsefulBufC             kid_cbor;

    enum t_cose_err_t      cose_result;

    me = (struct t_cose_recipient_dec_hpke *)me_x;

    (void)loc; // TODO: use this when decoding header params
    (void)p_storage; // TODO: return decoded header params
    (void)params; // TODO: return decoded header params

    /* One recipient */
    QCBORDecode_EnterArray(cbor_decoder, NULL);
    // TODO: Exit these arrays and Finish()

    /* protected header */
    result = QCBORDecode_GetNext(cbor_decoder, &Item);

    if (result != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_FORMATTING);
    }

    if (Item.uDataType != QCBOR_TYPE_BYTE_STRING) {
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

    if (alg != T_COSE_ALGORITHM_HPKE_v1_BASE)
        return(T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG);

    /* unprotected header */
    QCBORDecode_EnterMap(cbor_decoder, NULL);

    /* get HPKE_sender_info */
    QCBORDecode_GetByteStringInMapN(cbor_decoder,
                                    T_COSE_HEADER_ALG_PARAM_HPKE_SENDER_INFO,
                                    &hpke_sender_info);

    result = QCBORDecode_GetError(cbor_decoder);

    if (result != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
    }

    /* Decode HPKE_sender_info structure
     *
     *  HPKE_sender_info = [
     *     kem_id : uint,       ; kem identifier
     *     kdf_id : uint,       ; kdf identifier
     *     aead_id : uint,      ; aead identifier
     *     enc : bstr,          ; encapsulated key
     *  ]
     */
    QCBORDecode_Init(&DC2,
                     (UsefulBufC)
                     {
                      hpke_sender_info.ptr,
                      hpke_sender_info.len
                     },
                     QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&DC2, NULL);

    /* -- get kem_id  */
    QCBORDecode_GetUInt64(&DC2,
                          &kem_id);

    result = QCBORDecode_GetAndResetError(&DC2);

    if (result != QCBOR_ERR_NO_MORE_ITEMS) {
        return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
    }

    /* -- set key length */
    switch(kem_id) {

    case HPKE_KEM_ID_P256:
        key_bitlen = 128;
        break;

    default:
        /* TBD: need a better error code */
        return(T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG);
    }

    /* -- get kem_id  */
    QCBORDecode_GetUInt64(&DC2,
                          &kdf_id);

    result = QCBORDecode_GetAndResetError(&DC2);

    if (result != QCBOR_ERR_NO_MORE_ITEMS) {
        return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
    }

    /* -- get aead_id  */
    QCBORDecode_GetUInt64(&DC2,
                          &aead_id);

    result = QCBORDecode_GetAndResetError(&DC2);

    if (result != QCBOR_ERR_NO_MORE_ITEMS) {
        return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
    }

    /* -- get enc */
    QCBORDecode_GetByteString(&DC2,
                              &enc);

    result = QCBORDecode_GetAndResetError(&DC2);

    if (result != QCBOR_ERR_NO_MORE_ITEMS) {
        return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
    }


    QCBORDecode_ExitArray(&DC2);

    /* get kid */
    QCBORDecode_GetByteStringInMapN(cbor_decoder,
                                    T_COSE_HEADER_PARAM_KID,
                                    &kid_cbor);

    result = QCBORDecode_GetError(cbor_decoder);

    if (result != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
    }

    if (kid_cbor.len == 0 ||
        strncmp(me->kid.ptr, kid_cbor.ptr, me->kid.len) != 0
       ) {
        return(T_COSE_ERR_UNKNOWN_KEY);
    }

    QCBORDecode_ExitMap(cbor_decoder);

    /* get CEK */
    QCBORDecode_GetByteString(cbor_decoder, &cek_encrypted);

    result = QCBORDecode_GetError(cbor_decoder);

    if (result != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
    }

    /* Execute HPKE */
    cose_result = t_cose_crypto_hpke_decrypt((int32_t) alg,
                                             (struct q_useful_buf_c)
                                             {
                                                 .len = enc.len,
                                                 .ptr = enc.ptr
                                             },
                                             me->skr,
                                             cek_encrypted,
                                             cek_buffer,
                                             &cek->len);


    cek->ptr = cek_buffer.ptr;

    return(cose_result);
}

#else /* T_COSE_DISABLE_HPKE */

/* Place holder for compiler tools that don't like files with no functions */
void t_cose_recipient_dec_hpke_placeholder(void) {}

#endif /* T_COSE_DISABLE_HPKE */
