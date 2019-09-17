/*
 *  t_cose_sign1_verify.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */


#include "t_cose_sign1_verify.h"
#include "qcbor.h"
#include "t_cose_crypto.h"
#include "q_useful_buf.h"
#include "t_cose_util.h"
#include "t_cose_headers.h"


/**
 * \file t_cose_sign1_verify.c
 *
 * \brief \c COSE_Sign1 verification implementation.
 */



#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
/**
 *  \brief Verify a short-circuit signature
 *
 * \param[in] hash_to_verify  Pointer and length of hash to verify.
 * \param[in] signature       Pointer and length of signature
 *
 * \return This returns one of the error codes defined by \ref
 *         t_cose_err_t.
 *
 * See t_cose_sign1_init() for description of the short-circuit
 * signature.
 */
static inline enum t_cose_err_t
t_cose_crypto_short_circuit_verify(struct q_useful_buf_c hash_to_verify,
                                   struct q_useful_buf_c signature)
{
    struct q_useful_buf_c hash_from_sig;
    enum t_cose_err_t     return_value;

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
#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */


/*
 * Public function. See t_cose_sign1_verify.h
 */
enum t_cose_err_t
t_cose_sign1_verify(int32_t                   option_flags,
                    struct t_cose_signing_key verification_key,
                    struct q_useful_buf_c     cose_sign1,
                    struct q_useful_buf_c     *payload)
{
    /* Stack use:
         144     108
          56      52
          16       8
           4       4
           8       4
          32      32
          16       8
          16       8
          32      32
          16       8
          72      36
         ---     ---
         396     300
     */
    QCBORDecodeContext            decode_context;
    QCBORItem                     item;
    struct q_useful_buf_c         protected_headers;
    enum t_cose_err_t             return_value;
    Q_USEFUL_BUF_MAKE_STACK_UB(   buffer_for_tbs_hash,
                                      T_COSE_CRYPTO_MAX_HASH_SIZE);
    struct q_useful_buf_c         tbs_hash;
    struct q_useful_buf_c         signature;
    struct t_cose_headers         unprotected_headers;
    struct t_cose_headers         parsed_protected_headers;
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
    struct q_useful_buf_c         short_circuit_kid;
#endif

    *payload = NULL_Q_USEFUL_BUF_C;

    QCBORDecode_Init(&decode_context, cose_sign1, QCBOR_DECODE_MODE_NORMAL);

    /* --  The array of four -- */
    QCBORDecode_GetNext(&decode_context, &item);
    if(item.uDataType != QCBOR_TYPE_ARRAY) {
        return_value = T_COSE_ERR_SIG_STRUCT;
        goto Done;
    }

    if(!QCBORDecode_IsTagged(&decode_context, &item, CBOR_TAG_COSE_SIGN1)) {
        return_value = T_COSE_ERR_SIGN1_FORMAT;
        goto Done;
    }


    /* --  Get the protected headers -- */
    QCBORDecode_GetNext(&decode_context, &item);
    if(item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return_value = T_COSE_ERR_SIGN1_FORMAT;
        goto Done;
    }

    protected_headers = item.val.string;

    return_value = parse_protected_headers(protected_headers, &parsed_protected_headers);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }


    /* --  Get the unprotected headers -- */
    return_value = parse_unprotected_headers(&decode_context, &unprotected_headers);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }
    if((option_flags & T_COSE_OPT_REQUIRE_KID) &&
        q_useful_buf_c_is_null(unprotected_headers.kid)) {
        return_value = T_COSE_ERR_NO_KID;
        goto Done;
    }


    /* -- Get the payload -- */
    QCBORDecode_GetNext(&decode_context, &item);
    if(item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return_value = T_COSE_ERR_SIGN1_FORMAT;
        goto Done;
    }
    *payload = item.val.string;


    /* -- Get the signature -- */
    QCBORDecode_GetNext(&decode_context, &item);
    if(item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return_value = T_COSE_ERR_SIGN1_FORMAT;
        goto Done;
    }
    signature = item.val.string;

    
    /* -- Finish up the CBOR decode -- */
    /* This check make sure the array only had the expected four
     items. Works for definite and indefinte length arrays. Also
     make sure there were no extra bytes. */
    if(QCBORDecode_Finish(&decode_context) != QCBOR_SUCCESS) {
        return_value = T_COSE_ERR_CBOR_NOT_WELL_FORMED;
        goto Done;
    }


    /* -- Skip signature verification if requested --*/
    if(option_flags & T_COSE_OPT_PARSE_ONLY) {
        return_value = T_COSE_SUCCESS;
        goto Done;
    }

    /* -- Compute the TBS bytes -- */
    return_value = create_tbs_hash(parsed_protected_headers.cose_alg_id,
                                   buffer_for_tbs_hash,
                                   &tbs_hash,
                                   protected_headers,
                                   T_COSE_TBS_BARE_PAYLOAD,
                                   *payload);
    if(return_value) {
        goto Done;
    }

    /* -- Check for short-circuit signature and verify if it exists -- */
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
    short_circuit_kid = get_short_circuit_kid();
    if(!return_value && !q_useful_buf_compare(unprotected_headers.kid, short_circuit_kid)) {
        if(!(option_flags & T_COSE_OPT_ALLOW_SHORT_CIRCUIT)) {
            return_value = T_COSE_ERR_SHORT_CIRCUIT_SIG;
            goto Done;
        }

        return_value = t_cose_crypto_short_circuit_verify(tbs_hash,
                                                          signature);
        goto Done;
    }
#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */


    /* -- Verify the signature (if it wasn't short-circuit) -- */
    return_value = t_cose_crypto_pub_key_verify(parsed_protected_headers.cose_alg_id,
                                                verification_key,
                                                unprotected_headers.kid,
                                                tbs_hash,
                                                signature);

Done:
    return return_value;
}
