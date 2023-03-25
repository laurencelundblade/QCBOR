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
#include "t_cose_util.h"


// TODO: maybe rearrange this to align with what happens in crypto adaptor layer
struct hpke_sender_info {
    uint64_t               kem_id;
    uint64_t               kdf_id;
    uint64_t               aead_id;
    struct q_useful_buf_c  enc;
};

static enum t_cose_err_t
hpke_sender_info_decode_cb(void                    *cb_context,
                            QCBORDecodeContext      *cbor_decoder,
                            struct t_cose_parameter *parameter)
{
    // TODO: this will have to cascade to an external supplied special header decoder too
    struct hpke_sender_info  *sender_info = (struct hpke_sender_info  *)cb_context;

    QCBORDecode_EnterArray(cbor_decoder, NULL);
    QCBORDecode_GetUInt64(cbor_decoder, &(sender_info->kem_id));
    QCBORDecode_GetUInt64(cbor_decoder, &(sender_info->kdf_id));
    QCBORDecode_GetUInt64(cbor_decoder, &(sender_info->aead_id));
    QCBORDecode_GetByteString(cbor_decoder, &(sender_info->enc));
    QCBORDecode_ExitArray(cbor_decoder);
    if(QCBORDecode_GetError(cbor_decoder)) {
        sender_info->kem_id = UINT64_MAX; /* This indicates failure */
    }

    // TODO: more error handling
    return 0;
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
    QCBORError             result;
    int64_t                alg = 0;
    size_t                 key_bitlen;
    struct q_useful_buf_c  cek_encrypted;
    struct q_useful_buf_c  protected_params;
    enum t_cose_err_t      cose_result;
    struct hpke_sender_info  sender_info;
    int                    psa_ret;
    MakeUsefulBufOnStack(enc_struct_buf, 50); // TODO: allow this to be supplied externally
    struct q_useful_buf_c enc_struct;

    me = (struct t_cose_recipient_dec_hpke *)me_x;

    /* One recipient */
    QCBORDecode_EnterArray(cbor_decoder, NULL);

    cose_result = t_cose_headers_decode(cbor_decoder, /* in: decoder to read from */
                                loc,          /* in: location in COSE message */
                                hpke_sender_info_decode_cb, /* in: callback for specials */
                                &sender_info, /* in: context for callback */
                                p_storage,    /* in: parameter storage */
                                params,       /* out: list of decoded params */
                               &protected_params /* out: encoded prot params */
                                );
    if(cose_result != T_COSE_SUCCESS) {
        goto Done;
    }

    alg = t_cose_find_parameter_alg_id(*params, true);
    if (alg != T_COSE_ALGORITHM_HPKE_v1_BASE)
        return(T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG);

    // TODO: put kid processing back in


    /* -- set key length */
    switch(sender_info.kem_id) {

    case HPKE_KEM_ID_P256:
        key_bitlen = 128;
        break;

    default:
        /* TBD: need a better error code */
        return(T_COSE_ERR_UNSUPPORTED_KEY_EXCHANGE_ALG);
    }

    /* get CEK */
    QCBORDecode_GetByteString(cbor_decoder, &cek_encrypted);


    /* Close out decoding and error check */
    QCBORDecode_ExitArray(cbor_decoder);
    result = QCBORDecode_GetError(cbor_decoder);
    if (result != QCBOR_SUCCESS) {
        return(T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING);
    }

    /* --- Make the Enc_structure ---- */

    cose_result = create_enc_structure("Enc_Recipient", /* in: context string */
                         protected_params,
                         NULL_Q_USEFUL_BUF_C, /* in: Externally supplied AAD */
                         enc_struct_buf,
                         &enc_struct);
    if(cose_result != T_COSE_SUCCESS) {
        goto Done;
    }

    // TODO: There is a big rearrangement necessary when the crypto adaptation layer calls for HPKE are sorted out. Lots of work to complete that...
    hpke_suite_t     suite;
    size_t           cek_len_in_out;

    // TODO: check that the sender_info decode happened correctly before proceeding
    suite.aead_id = (uint16_t)sender_info.aead_id;
    suite.kdf_id = (uint16_t)sender_info.kdf_id;
    suite.kem_id = (uint16_t)sender_info.kem_id;

    cek_len_in_out = cek_buffer.len;

    psa_ret = mbedtls_hpke_decrypt(
             HPKE_MODE_BASE,                  // HPKE mode
             suite,                           // ciphersuite
             NULL, 0, NULL,                   // PSK for authentication
             0, NULL,                         // pkS
             (psa_key_handle_t)me->skr.key.handle, // skR handle
             sender_info.enc.len,                         // pkE_len
             sender_info.enc.ptr,                         // pkE
             cek_encrypted.len,                  // Ciphertext length
             cek_encrypted.ptr,                  // Ciphertext
                                   // TODO: fix the const-ness all the way down so the cast can be removed
             enc_struct.len, (uint8_t *)enc_struct.ptr,   // Additional data
             0, NULL,                         // Info
             &cek_len_in_out,                   // Plaintext length
             cek_buffer.ptr                   // Plaintext
         );

     if (psa_ret != 0) {
         return(T_COSE_ERR_HPKE_DECRYPT_FAIL);
     }

    cek->ptr = cek_buffer.ptr;
    cek->len = cek_len_in_out;

Done:
    return(cose_result);
}

#else /* T_COSE_DISABLE_HPKE */

/* Place holder for compiler tools that don't like files with no functions */
void t_cose_recipient_dec_hpke_placeholder(void) {}

#endif /* T_COSE_DISABLE_HPKE */
