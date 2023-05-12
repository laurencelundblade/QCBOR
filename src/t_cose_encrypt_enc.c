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
    struct q_useful_buf_c        cek_bytes;
    struct t_cose_parameter      params[2]; /* 1 for Alg ID plus 1 for IV */
    struct q_useful_buf_c        body_prot_headers;
    struct q_useful_buf_c        enc_structure;
    size_t                       key_byte_len;
    Q_USEFUL_BUF_MAKE_STACK_UB(  cek_buffer, T_COSE_MAX_SYMMETRIC_KEY_LENGTH);
    Q_USEFUL_BUF_MAKE_STACK_UB(  nonce_buffer, T_COSE_MAX_SYMMETRIC_KEY_LENGTH);
    Q_USEFUL_BUF_MAKE_STACK_UB(  enc_struct_buffer, T_COSE_ENCRYPT_STRUCT_DEFAULT_SIZE);
    struct t_cose_key            cek_handle;
    const char                  *enc_struct_string;
    struct q_useful_buf          encrypt_buffer;
    struct q_useful_buf_c        encrypt_output;
    bool                         is_cose_encrypt0;
    struct t_cose_recipient_enc *recipient;


    /* ---- Figure out the COSE message type ---- */
    message_type = T_COSE_OPT_MESSAGE_TYPE_MASK & me->option_flags;
    is_cose_encrypt0 = true;
    switch(message_type) {
        case 0: message_type = T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0; break;
        case T_COSE_OPT_MESSAGE_TYPE_ENCRYPT0: break;
        case T_COSE_OPT_MESSAGE_TYPE_ENCRYPT: is_cose_encrypt0 = false; break;
        default: return T_COSE_ERR_FAIL; // TODO: better error code
    }

    /* ---- Algorithm ID, IV and parameter list ---- */
    /* Determine algorithm parameters */
    switch(me->payload_cose_algorithm_id) {
        case T_COSE_ALGORITHM_A128GCM:
            key_byte_len = 128 / 8;
            break;
        case T_COSE_ALGORITHM_A192GCM:
            key_byte_len = 192 / 8;
            break;
        case T_COSE_ALGORITHM_A256GCM:
            key_byte_len = 256 / 8;
            break;
        default:
            return T_COSE_ERR_UNSUPPORTED_CIPHER_ALG;
    }
    params[0] = t_cose_param_make_alg_id(me->payload_cose_algorithm_id);

    /* Generate random nonce (aka iv) */
    return_value = t_cose_crypto_get_random(nonce_buffer, key_byte_len, &nonce);
    params[1] = t_cose_param_make_iv(nonce);

    params[0].next = &params[1];
    params[1].next = me->added_body_parameters;
    /* At this point all the header parameters to be encoded are in
     * a linked list the head of which is params[0]. */


    /* ---- Get started with the CBOR encoding ---- */
    QCBOREncode_Init(&cbor_encoder, buffer_for_message);
    QCBOREncode_AddTag(&cbor_encoder, message_type);
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
        // TODO: allow cek to be set for COSE_Encrypt?
        /* For COSE_Encrypt, a random key is generated (which will be
         * conveyed to the recipient by some key distribution method in
         * a COSE_Recipient). */
        return_value = t_cose_crypto_get_random(cek_buffer,
                                                key_byte_len,
                                                &cek_bytes);
        if (return_value != T_COSE_SUCCESS) {
            goto Done;
        }
        return_value = t_cose_crypto_make_symmetric_key_handle(me->payload_cose_algorithm_id, /* in: alg id */
                                                               cek_bytes, /* in: key bytes */
                                                              &cek_handle); /* out: key handle */
    }
    if (return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    /* At this point cek_handle references the encryption key for the AEAD */

    // TODO: for non-recipient HPKE, there will have to be algorithm mapping
    // and other stuff here
    // TODO: probably some new callback scheme...

    /* ---- Run AEAD to actually encrypt the payload, detached or not */
    if(q_useful_buf_is_null(buffer_for_detached)) {
        /* This sets up so AEAD writes directly to the output buffer. This
         * saves a lot of memory since no intermediate buffer is needed!
         */
        QCBOREncode_OpenBytes(&cbor_encoder, &encrypt_buffer);
    } else {
        /* For detached, write to the buffer supplied by the caller. */
        encrypt_buffer = buffer_for_detached;
    }

    // TODO: support AE (in addition to AEAD) algorithms
    return_value =
        t_cose_crypto_aead_encrypt(me->payload_cose_algorithm_id, /* in: AEAD algorithm ID */
                                   cek_handle,     /* in: content encryption key handle */
                                   nonce,          /* in: nonce / IV */
                                   enc_structure,  /* in: additional data to authenticate */
                                   payload,        /* in: payload to encrypt */
                                   encrypt_buffer, /* in: buffer to write to */
                                  &encrypt_output  /* out: ciphertext */);
    if(!is_cose_encrypt0) {
        /* If not encrypt0, then we made the CEK here and must free it here. */
        t_cose_crypto_free_symmetric_key(cek_handle);
    }
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

            /* This does the public-key crypto and outputs a COSE_Recipient */
            return_value = recipient->creat_cb(recipient,
                                               cek_bytes,
                                              &cbor_encoder);
            if(return_value) {
                goto Done;
            }

            QCBOREncode_CloseArray(&cbor_encoder);
        }
    }

     /* ---- Close out the CBOR encoding ---- */
    QCBOREncode_CloseArray(&cbor_encoder);
    cbor_err = QCBOREncode_Finish(&cbor_encoder, encrypted_cose_message);

    if (cbor_err != QCBOR_SUCCESS) {
        return T_COSE_ERR_FAIL; // TODO: map error
    }

Done:
    return return_value;
}
