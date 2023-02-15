/*
 * t_cose_encrypt_dec.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */
#include <stdlib.h>
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_encrypt_dec.h"
#include "t_cose/t_cose_recipient_dec.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_crypto.h"



enum t_cose_err_t
t_cose_encrypt_dec(struct t_cose_encrypt_dec_ctx* me,
                   const uint8_t *cose,
                   size_t cose_len,
                   uint8_t *detached_ciphertext,
                   size_t detached_ciphertext_len,
                   uint8_t *plaintext,
                   size_t plaintext_len,
                   struct q_useful_buf_c *plain_text)
{
    QCBORItem              protected_hdr;
    UsefulBufC             nonce_cbor;
    UsefulBufC             kid_cbor;
    int64_t                algorithm_id = 0;
    QCBORDecodeContext     DC, DC2;
    QCBORItem              Item;
    QCBORItem              Cipher;
    QCBORError             result;
    enum t_cose_err_t      cose_result;

    struct q_useful_buf_c  cipher_text;

    uint8_t                add_data[20];
    size_t                 add_data_len = sizeof(add_data);
    struct q_useful_buf    add_data_struct = {add_data, add_data_len};
    UsefulBufC             add_data_buf;
    QCBOREncodeContext     additional_data;
    bool                   detached_mode;
    struct q_useful_buf_c  cek;
    struct t_cose_key      cek_key;
    struct t_cose_parameter *decoded_params;
    MakeUsefulBufOnStack(cek_buf, 64); // TODO: correct size
    uint32_t                 message_type;


    /* Initialize decoder */
    QCBORDecode_Init(&DC,
                     (UsefulBufC){cose, cose_len},
                     QCBOR_DECODE_MODE_NORMAL);

   /* Make sure the first item is a tag */
    result = QCBORDecode_GetNext(&DC, &Item);

    message_type = me->option_flags & T_COSE_OPT_MESSAGE_TYPE_MASK;

    /* Check whether tag is CBOR_TAG_COSE_ENCRYPT or CBOR_TAG_COSE_ENCRYPT0 */
    // TODO: allow tag determination of message_type
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
    kid_cbor = NULL_Q_USEFUL_BUF_C;
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

#if 0
    if (me->key_distribution == T_COSE_KEY_DISTRIBUTION_DIRECT) {
        // TODO: not sure that the kid is mandatory here.
        QCBORDecode_GetByteStringInMapN(&DC, T_COSE_HEADER_PARAM_KID, &kid_cbor);

        if (QCBORDecode_GetError(&DC) !=0 ) {
            // TODO: not sure this is the right error code
             return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
        }
    }
#else
    (void)kid_cbor;
#endif

    QCBORDecode_ExitMap(&DC);

    /* Ciphertext */
    result = QCBORDecode_GetNext(&DC, &Cipher);

    if (result != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_FORMATTING);
    }

    if (Cipher.val.string.len != 0) {
        cipher_text = Cipher.val.string;
        detached_mode = false;
    } else {
        cipher_text.ptr = detached_ciphertext;
        cipher_text.len = detached_ciphertext_len;
        detached_mode = true;
    }

    (void)detached_mode; // TODO: use this variable or get rid of it

    if (message_type == T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0) {
        // TODO: need a mechanism to detect whether cek was set. This may be a change to the defintion of t_cose_key
        if(me->recipient_list != NULL) {
            return T_COSE_ERR_FAIL; // TODO: need better error here
        }
        // TODO: create example / test of using custom headers to check the kid here.
        cek_key = me->cek;

    } else if (message_type == T_COSE_OPT_MESSAGE_TYPE_ENCRYPT) {
        enum t_cose_err_t err;
        QCBORDecode_EnterArray(&DC, NULL);
        // TODO: handle multiple recipient decoders in a loop
        const struct t_cose_header_location loc = {.nesting = 1,
                                                   .index = 0};
        err = me->recipient_list->decode_cb(me->recipient_list,
                                            loc,
                                           &DC,
                                            cek_buf,
                                            me->p_storage,
                                           &decoded_params,
                                           &cek);
        (void)err; // TODO: check the error code
        QCBORDecode_ExitArray(&DC);


        err = t_cose_crypto_make_symmetric_key_handle((int32_t)algorithm_id,
                                                      cek,
                                                      &cek_key);
    } else {
        // TODO: better error here.
        return T_COSE_ERR_FAIL;
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
    if (message_type == T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0) {
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

    cose_result = t_cose_crypto_aead_decrypt((int32_t) algorithm_id,
                                             cek_key,
                                             nonce_cbor,
                                             add_data_buf,
                                             cipher_text,
                                             (struct q_useful_buf) {.ptr = plaintext, .len = plaintext_len},
                                             plain_text);


    if (cose_result != T_COSE_SUCCESS) {
        return(cose_result);
    }

    return(T_COSE_SUCCESS);
}
