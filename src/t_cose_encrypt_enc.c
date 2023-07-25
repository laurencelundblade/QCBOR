/*
 * t_cose_encrypt_enc.c
 *
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2023, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include <stdlib.h>
#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_recipient_enc.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"
#include "t_cose_crypto.h"


/*
 * Pubilc Function. See t_cose_sign_sign.h
 */
enum t_cose_err_t
t_cose_encrypt_enc_detached(struct t_cose_encrypt_enc *me,
                            struct q_useful_buf_c      payload,
                            struct q_useful_buf_c      external_aad,
                            struct q_useful_buf        buffer_for_detached,
                            struct q_useful_buf        buffer_for_message,
                            struct q_useful_buf_c     *encrypted_detached,
                            struct q_useful_buf_c     *encrypted_cose_message)
{
    enum t_cose_err_t            return_value;
    QCBORError                   cbor_err;
    QCBOREncodeContext           cbor_encoder;
    unsigned                     message_type;
    struct q_useful_buf_c        nonce;
    struct t_cose_parameter      params[2]; /* 1 for Alg ID plus 1 for IV */
    struct q_useful_buf_c        body_prot_headers;
    struct q_useful_buf_c        enc_structure;
    struct t_cose_alg_and_bits   ce_alg;
    Q_USEFUL_BUF_MAKE_STACK_UB(  cek_buffer, T_COSE_MAX_SYMMETRIC_KEY_LENGTH);
    struct q_useful_buf_c        cek_bytes;
    struct t_cose_key            cek_handle;
    Q_USEFUL_BUF_MAKE_STACK_UB(  nonce_buffer, T_COSE_MAX_SYMMETRIC_KEY_LENGTH);
    Q_USEFUL_BUF_MAKE_STACK_UB(  enc_struct_buffer, T_COSE_ENCRYPT_STRUCT_DEFAULT_SIZE);
    const char                  *enc_struct_string;
    struct q_useful_buf          encrypt_buffer;
    struct q_useful_buf_c        encrypt_output;
    bool                         is_cose_encrypt0;
    struct t_cose_recipient_enc *recipient;


    /* ---- Figure out the COSE message type ---- */
    message_type = T_COSE_OPT_MESSAGE_TYPE_MASK & me->option_flags;
    is_cose_encrypt0 = true;
    switch(message_type) {
        case T_COSE_OPT_MESSAGE_TYPE_UNSPECIFIED:
            message_type = T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0;
            break;
        case T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0:
            break;
        case T_COSE_OPT_MESSAGE_TYPE_ENCRYPT:
            is_cose_encrypt0 = false;
            break;
        default:
            return T_COSE_ERR_BAD_OPT;
    }


    /* ---- Algorithm ID, IV and parameter list ---- */
    /* Determine algorithm parameters */
    ce_alg.cose_alg_id = me->payload_cose_algorithm_id;
    ce_alg.bits_in_key = bits_in_crypto_alg(ce_alg.cose_alg_id);
    if(ce_alg.bits_in_key == UINT32_MAX) {
        return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }
    params[0] = t_cose_param_make_alg_id(ce_alg.cose_alg_id);

    /* Generate random nonce (aka iv) */
    return_value = t_cose_crypto_get_random(nonce_buffer,
                                            ce_alg.bits_in_key / 8,
                                            &nonce);
    params[1] = t_cose_param_make_iv(nonce);

    params[0].next = &params[1];
    params[1].next = me->added_body_parameters;
    /* At this point all the header parameters to be encoded are in a
     * linked list the head of which is params[0]. */


    /* ---- Get started with the CBOR encoding ---- */
    QCBOREncode_Init(&cbor_encoder, buffer_for_message);
    if(!(me->option_flags & T_COSE_OPT_OMIT_CBOR_TAG)) {
        QCBOREncode_AddTag(&cbor_encoder, message_type);
    }
    QCBOREncode_OpenArray(&cbor_encoder);


    /* ---- The body header parameters ---- */
    return_value = t_cose_headers_encode(&cbor_encoder, /* in: cbor encoder */
                                         &params[0],    /* in: param linked list */
                                         &body_prot_headers); /* out: bytes for CBOR-encoded protected params */
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    /* ---- Make the Enc_structure ---- */
    /* Per RFC 9052 section 5.3 the structure that is authenticated
     * along with the payload by the AEAD.
     *
     *  Enc_structure = [
     *    context : "Encrypt",
     *    protected : empty_or_serialized_map,
     *    external_aad : bstr
     *  ]
     */
    if(!q_useful_buf_is_null(me->extern_enc_struct_buffer)) {
        /* Caller gave us a (bigger) buffer for Enc_structure */
        enc_struct_buffer = me->extern_enc_struct_buffer;
    }
    enc_struct_string = is_cose_encrypt0 ? "Encrypt0" : "Encrypt";
    return_value =
        create_enc_structure(enc_struct_string, /* in: message context string */
                             body_prot_headers, /* in: CBOR encoded prot hdrs */
                             external_aad,      /* in: external AAD */
                             enc_struct_buffer, /* in: output buffer */
                            &enc_structure);    /* out: encoded Enc_structure */
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    /* ---- Figure out the CEK ---- */
    if(is_cose_encrypt0) {
        /* For COSE_Encrypt0, the caller must have set the cek explicitly. */
        cek_handle = me->cek;
    } else {
        /* For COSE_Encrypt, a random key is generated (which will be
         * conveyed to the recipient by some key distribution method in
         * a COSE_Recipient). */
        return_value = t_cose_crypto_get_random(cek_buffer,
                                                ce_alg.bits_in_key / 8,
                                                &cek_bytes);
        if (return_value != T_COSE_SUCCESS) {
            goto Done;
        }
        return_value = t_cose_crypto_make_symmetric_key_handle(
                                    ce_alg.cose_alg_id, /* in: alg id */
                                    cek_bytes,          /* in: key bytes */
                                   &cek_handle);        /* out: key handle */
    }
    if (return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    /* At this point cek_handle has the encryption key for the AEAD */


    /* ---- Run AEAD to encrypt the payload, detached or not */
    if(q_useful_buf_is_null(buffer_for_detached)) {
        /* Set up so AEAD writes directly to the output buffer to save lots
         * of memory since no intermediate buffer is needed!
         */
        QCBOREncode_OpenBytes(&cbor_encoder, &encrypt_buffer);
    } else {
        /* For detached, write to the buffer supplied by the caller. */
        encrypt_buffer = buffer_for_detached;
    }

    return_value =
        t_cose_crypto_aead_encrypt(ce_alg.cose_alg_id, /* in: AEAD alg ID */
                                   cek_handle,     /* in: content encryption key handle */
                                   nonce,          /* in: nonce / IV */
                                   enc_structure,  /* in: AAD to authenticate */
                                   payload,        /* in: payload to encrypt */
                                   encrypt_buffer, /* in: buffer to write to */
                                  &encrypt_output  /* out: ciphertext */);

    if (return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(q_useful_buf_is_null(buffer_for_detached)) {
        QCBOREncode_CloseBytes(&cbor_encoder, encrypt_output.len);
    } else {
        QCBOREncode_AddNULL(&cbor_encoder);
        *encrypted_detached = encrypt_output;
    }

    /* ---- COSE_Recipients for COSE_Encrypt message ---- */
    if ( !is_cose_encrypt0 ) {
        for(recipient = me->recipients_list;
            recipient != NULL;
            recipient = recipient->next_in_list) {

            /* Array holding the COSE_Recipients */
            QCBOREncode_OpenArray(&cbor_encoder);

            /* Do the public key crypto and output a COSE_Recipient */
            /* cek_bytes is not uninitialized here despite what some
             * compilers think. It is a waste of code to put in an
             * unneccessary initialization for them. */
            return_value = recipient->creat_cb(recipient,
                                               cek_bytes,
                                               ce_alg,
                                              &cbor_encoder);
            if(return_value) {
                goto Done;
            }

            QCBOREncode_CloseArray(&cbor_encoder);
        }
        t_cose_crypto_free_symmetric_key(cek_handle);
    }

     /* ---- Close out the CBOR encoding ---- */
    QCBOREncode_CloseArray(&cbor_encoder);
    cbor_err = QCBOREncode_Finish(&cbor_encoder, encrypted_cose_message);
    if (cbor_err != QCBOR_SUCCESS) {
        return qcbor_encode_error_to_t_cose_error(&cbor_encoder);
    }

Done:
    return return_value;
}
