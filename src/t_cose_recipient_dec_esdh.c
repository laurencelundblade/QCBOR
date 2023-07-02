/*
 * t_cose_recipient_dec_esdh.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.

 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 */

#ifndef T_COSE_DISABLE_ESDH

#include <stdint.h>
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_recipient_dec_esdh.h"  /* Interface implemented */
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_crypto.h"
#include "t_cose_util.h"


// TODO: maybe rearrange this to align with what happens in crypto adaptor layer
struct esdh_sender_info {
    uint64_t               kem_id;
    uint64_t               kdf_id;
    uint64_t               aead_id;
    struct q_useful_buf_c  enc;
};

static enum t_cose_err_t
esdh_sender_info_decode_cb(void                    *cb_context,
                            QCBORDecodeContext      *cbor_decoder,
                            struct t_cose_parameter *parameter)
{
    if(parameter->label != T_COSE_HEADER_ALG_PARAM_HPKE_SENDER_INFO) {
        return 0;
    }
    // TODO: this will have to cascade to an external supplied
    // special header decoder too
    struct esdh_sender_info  *sender_info = (struct esdh_sender_info  *)cb_context;

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
t_cose_recipient_dec_esdh_cb_private(struct t_cose_recipient_dec *me_x,
                                     const struct t_cose_header_location loc,
                                     const struct t_cose_alg_and_bits    ce_alg,
                                     QCBORDecodeContext *cbor_decoder,
                                     struct q_useful_buf cek_buffer,
                                     struct t_cose_parameter_storage *p_storage,
                                     struct t_cose_parameter **params,
                                     struct q_useful_buf_c *cek)
{
    struct t_cose_recipient_dec_esdh *me;
    QCBORError             result;
    int64_t                alg = 0;
    struct q_useful_buf_c  cek_encrypted;
    struct q_useful_buf_c  protected_params;
    enum t_cose_err_t      cose_result;
    struct esdh_sender_info  sender_info;
    //int                    psa_ret;
    MakeUsefulBufOnStack(enc_struct_buf, 50); // TODO: allow this to be
                                              // supplied externally
    struct q_useful_buf_c enc_struct;

    me = (struct t_cose_recipient_dec_esdh *)me_x;

    // TODO: some of these will have to get used
    (void)ce_alg;
    (void)cek_buffer;
    (void)cek;

    /* One recipient */
    QCBORDecode_EnterArray(cbor_decoder, NULL);

    cose_result = t_cose_headers_decode(cbor_decoder, /* in: decoder to read from */
                                loc,          /* in: location in COSE message*/
                                esdh_sender_info_decode_cb, /* in: callback for specials */
                                &sender_info, /* in: context for callback */
                                p_storage,    /* in: parameter storage */
                                params,       /* out: list of decoded params */
                               &protected_params /* out: encoded prot params */
                                );
    if(cose_result != T_COSE_SUCCESS) {
        goto Done;
    }

    /* Recipient array contains AES Key Wrap algorithm.
     * The KEK used to encrypt the CEK with AES-KW is then
     * found in an inner recipient array.
     */
    alg = t_cose_param_find_alg_id(*params, false);
    if (alg != T_COSE_ALGORITHM_A128KW &&
        alg != T_COSE_ALGORITHM_A192KW &&
        alg != T_COSE_ALGORITHM_A256KW)
        return T_COSE_ERR_UNSUPPORTED_CONTENT_KEY_DISTRIBUTION_ALG;

    // TODO: put kid processing back in

    /* get CEK */
    QCBORDecode_GetByteString(cbor_decoder, &cek_encrypted);


    /* TBD: Here we need to look at the inner recipient structure */

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

    /*
    // TODO: There is a big rearrangement necessary when the crypto adaptation
    // layer calls for ESDH are sorted out. Lots of work to complete that...
    esdh_suite_t     suite;
    size_t           cek_len_in_out;

    // TODO: check that the sender_info decode happened correctly
    // before proceeding
   suite.aead_id = (uint16_t)sender_info.aead_id;
    suite.kdf_id = (uint16_t)sender_info.kdf_id;
    suite.kem_id = (uint16_t)sender_info.kem_id;

    cek_len_in_out = cek_buffer.len;

    psa_ret = mbedtls_esdh_decrypt(
             ESDH_MODE_BASE,                  // ESDH mode
             suite,                           // ciphersuite
             NULL, 0, NULL,                   // PSK for authentication
             0, NULL,                         // pkS
             (psa_key_handle_t)me->skr.key.handle, // skR handle
             sender_info.enc.len,                         // pkE_len
             sender_info.enc.ptr,                         // pkE
             cek_encrypted.len,                  // Ciphertext length
             cek_encrypted.ptr,                  // Ciphertext
        // TODO: fix the const-ness all the way down so the cast can be removed
             enc_struct.len, (uint8_t *)(uintptr_t)enc_struct.ptr,   // AAD
             0, NULL,                         // Info
             &cek_len_in_out,                   // Plaintext length
             cek_buffer.ptr                   // Plaintext
         );

     if (psa_ret != 0) {
         return(T_COSE_ERR_ESDH_DECRYPT_FAIL);
     }

    cek->ptr = cek_buffer.ptr;
    cek->len = cek_len_in_out;
*/
Done:
    return(cose_result);
}

#else /* T_COSE_DISABLE_ESDH */

/* Place holder for compiler tools that don't like files with no functions */
void t_cose_recipient_dec_esdh_placeholder(void) {}

#endif /* T_COSE_DISABLE_ESDH */
