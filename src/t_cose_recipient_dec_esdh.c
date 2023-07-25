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


#include <stdint.h>
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose/t_cose_recipient_dec_esdh.h"  /* Interface implemented */
#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_standard_constants.h"
#include "t_cose_crypto.h"
#include "t_cose_util.h"


static enum t_cose_err_t
decode_ephemeral_key(void                    *cb_context,
                     QCBORDecodeContext      *cbor_decoder,
                     struct t_cose_parameter *parameter)
{
    struct q_useful_buf_c  x;
    struct q_useful_buf_c  y_string;
    bool                   y_bool;
    int64_t                kty;
    int64_t                curve;
    enum t_cose_err_t      result;
    QCBORItem              y;

    if(parameter->label != T_COSE_HEADER_ALG_PARAM_EPHEMERAL_KEY) {
        return 0;
    }
    // TODO: this will have to cascade to an external supplied header decoder
    (void) cb_context; /* Not used because key goes back into parameter */
    // TODO: this is pretty generic and can probably move to t_cose_key.c

    QCBORDecode_EnterMap(cbor_decoder, NULL);

    QCBORDecode_GetInt64InMapN(cbor_decoder, T_COSE_KEY_COMMON_KTY, &kty);
    QCBORDecode_GetInt64InMapN(cbor_decoder, T_COSE_KEY_PARAM_CRV, &curve);
    QCBORDecode_GetByteStringInMapN(cbor_decoder, T_COSE_KEY_PARAM_X_COORDINATE, &x);
    QCBORDecode_GetItemInMapN(cbor_decoder, T_COSE_KEY_PARAM_Y_COORDINATE, QCBOR_TYPE_ANY, &y);

    QCBORDecode_ExitMap(cbor_decoder);
    if(QCBORDecode_GetError(cbor_decoder)) {
        return T_COSE_ERR_FAIL; // TODO: is this right?
    }

    // TODO: check kty

    /* If y is a bool, then point compression is used and y is a boolean
     * indicating the sign. If not then it is a byte string with the y.
     * Anything else is an error. See RFC 9053 7.1.1.
     */
    switch(y.uDataType) {
        case QCBOR_TYPE_BYTE_STRING:
            y_string = y.val.string;
            y_bool = true; /* Unused. Only here to avoid compiler warning */
            break;

        case QCBOR_TYPE_TRUE:
            y_bool = true;
            y_string = NULL_Q_USEFUL_BUF_C;
            break;

        case QCBOR_TYPE_FALSE:
            y_bool = true;
            y_string = NULL_Q_USEFUL_BUF_C;
            break;

        default:
            return 77; // TODO: error code
    }

    /* Turn it into a t_cose_key that is imported into the library */

    if(curve > INT32_MAX || curve < INT32_MIN) {
        // Make sure cast is safe
        return T_COSE_ERR_FAIL; // TODO: error
    }
    result = t_cose_crypto_import_ec2_pubkey((int32_t)curve,
                                 x,
                                 y_string,
                                 y_bool,
                                 &parameter->value.special_decode.value.key);

    // TODO: set the parameter type?

    // TODO: more error handling
    return result;
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
    int64_t                alg;
    struct q_useful_buf_c  cek_encrypted;
    struct q_useful_buf_c  info_struct;
    struct q_useful_buf_c  kek;
    struct t_cose_key      kek_handle;
    struct q_useful_buf_c  party_u;
    struct q_useful_buf_c  party_v;
    struct q_useful_buf_c  derived_key;
    struct q_useful_buf_c  protected_params;
    enum t_cose_err_t      cose_result;
    int32_t                kdf_hash_alg;
    const struct t_cose_parameter *salt_param;
    const struct t_cose_parameter *ephem_param;
    struct q_useful_buf_c  salt;
    struct t_cose_key      ephemeral_key;
    MakeUsefulBufOnStack(  kek_buffer,
                             T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_MAX_SYMMETRIC_KEY_LENGTH));
    MakeUsefulBufOnStack(  info_struct_buf, T_COSE_DEC_COSE_KDF_CONTEXT);
    struct t_cose_alg_and_bits  keywrap_alg;
    // TODO: size this correctly
    MakeUsefulBufOnStack(  derived_secret_buf,
                           10+T_COSE_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(T_COSE_MAX_SYMMETRIC_KEY_LENGTH));

    me = (struct t_cose_recipient_dec_esdh *)me_x;


    /* One recipient */
    QCBORDecode_EnterArray(cbor_decoder, NULL);

    cose_result = t_cose_headers_decode(
                           cbor_decoder, /* in: decoder to read from */
                           loc,          /* in: location in COSE message*/
                           decode_ephemeral_key, /* in: callback for specials */
                           NULL,         /* in: context for callback */
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

    // TODO: put kid processing back in

    /* get CEK */
    QCBORDecode_GetByteString(cbor_decoder, &cek_encrypted);

    /* Close out decoding and error check */
    QCBORDecode_ExitArray(cbor_decoder);
    result = QCBORDecode_GetError(cbor_decoder);
    if (result != QCBOR_SUCCESS) {
        return T_COSE_ERR_CBOR_MANDATORY_FIELD_MISSING;
    }


    alg = t_cose_param_find_alg_id(*params, true);

    switch(alg) {
    case T_COSE_ALGORITHM_ECDH_ES_A128KW:
        kdf_hash_alg            = T_COSE_ALGORITHM_SHA_256;
        keywrap_alg.cose_alg_id = T_COSE_ALGORITHM_A128KW;
        keywrap_alg.bits_in_key = 128;
        break;

    case T_COSE_ALGORITHM_ECDH_ES_A192KW:
        kdf_hash_alg            = T_COSE_ALGORITHM_SHA_256;
        keywrap_alg.cose_alg_id = T_COSE_ALGORITHM_A192KW;
        keywrap_alg.bits_in_key = 192;
        break;

    case T_COSE_ALGORITHM_ECDH_ES_A256KW:
        kdf_hash_alg            = T_COSE_ALGORITHM_SHA_256;
        keywrap_alg.cose_alg_id = T_COSE_ALGORITHM_A256KW;
        keywrap_alg.bits_in_key = 256;
        break;

    default:
        return T_COSE_ERR_UNSUPPORTED_CONTENT_KEY_DISTRIBUTION_ALG;
    }
    (void)ce_alg; /* Not used because key wrap is not an AEAD */


    /* --- Run ECDH --- */
    /* Inputs: pub key, ephemeral key
     * Outputs: derived key */

    /* The ephemeral public key comes from the headers. It was
     * processed by the decode_ephemeral_key() callback. */
    ephem_param = t_cose_param_find(*params,
                                    T_COSE_HEADER_ALG_PARAM_EPHEMERAL_KEY);
    if(ephem_param == NULL) {
        return T_COSE_ERR_FAIL; // TODO: error code
    }
    ephemeral_key = ephem_param->value.special_decode.value.key;

    cose_result = t_cose_crypto_ecdh(me->private_key,    /* in: secret key */
                                     ephemeral_key,      /* in: public key */
                                     derived_secret_buf, /* in: output buf */
                                     &derived_key        /* out: derived key*/
                                     );
    if(cose_result != T_COSE_SUCCESS) {
         goto Done;
     }

    /* --- Make Info structure ---- */
    party_u = t_cose_param_find_bstr(*params,
                                     T_COSE_HEADER_ALG_PARAM_PARTYU_IDENT);
    party_v = t_cose_param_find_bstr(*params,
                                     T_COSE_HEADER_ALG_PARAM_PARTYV_IDENT);
    // TODO: allow info_struct_buf to be supplied externally
    cose_result = create_kdf_context_info(keywrap_alg,
                                          party_u,
                                          party_v,
                                          protected_params,
                                          me->supp_pub_other,
                                          me->supp_priv_info,
                                          info_struct_buf,
                                         &info_struct);
    if (cose_result != T_COSE_SUCCESS) {
        return cose_result;
    }


    /* --- Run the HKDF --- */
    salt_param = t_cose_param_find(*params, T_COSE_HEADER_ALG_PARAM_SALT);
    if(salt_param != NULL) {
        if(salt_param->value_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
            goto Done;
        }
        salt = salt_param->value.string;
    } else {
        salt = NULL_Q_USEFUL_BUF_C;
    }
    kek_buffer.len = keywrap_alg.bits_in_key/8;
    cose_result = t_cose_crypto_hkdf(kdf_hash_alg,
                                     salt,         /* in: salt */
                                     derived_key,  /* in: ikm */
                                     info_struct,  /* in: info */
                                     kek_buffer);  /* in/out: buffer and kek */
    if(cose_result != T_COSE_SUCCESS) {
        goto Done;
    }
    kek.ptr = kek_buffer.ptr;
    kek.len = kek_buffer.len;


    /* --- Perform key unrwap --- */
    cose_result = t_cose_crypto_make_symmetric_key_handle(keywrap_alg.cose_alg_id,
                                                          kek,
                                                          &kek_handle);
    if(cose_result != T_COSE_SUCCESS) {
        goto Done;
    }

    cose_result = t_cose_crypto_kw_unwrap(
                        keywrap_alg.cose_alg_id, /* in: key wrap algorithm */
                        kek_handle,              /* in: key encryption key */
                        cek_encrypted,           /* in: encrypted CEK */
                        cek_buffer,              /* in: buffer for CEK */
                        cek);                    /* out: the CEK*/

Done:
    return cose_result;
}
