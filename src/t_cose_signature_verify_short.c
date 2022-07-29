//
//  t_cose_signature_verify_short.c
//
//  Created by Laurence Lundblade on 7/27/22.
//  Copyright © 2022 Laurence Lundblade. All rights reserved.
//

#include "t_cose/t_cose_signature_verify_short.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose_util.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose_crypto.h"

//#define T_COSE_CRYPTO_MAX_HASH_SIZE 300 // TODO: fix this


// This is replicated in t_cose_signature_sign_short.c

static const uint8_t defined_short_circuit_kid[] = {
    0xef, 0x95, 0x4b, 0x4b, 0xd9, 0xbd, 0xf6, 0x70,
    0xd0, 0x33, 0x60, 0x82, 0xf5, 0xef, 0x15, 0x2a,
    0xf8, 0xf3, 0x5b, 0x6a, 0x6c, 0x00, 0xef, 0xa6,
    0xa9, 0xa7, 0x1f, 0x49, 0x51, 0x7e, 0x18, 0xc6};

static struct q_useful_buf_c short_circuit_kid;

/*
 * Public function. See t_cose_util.h
 */
struct q_useful_buf_c get_short_circuit_kid_x(void)
{
    short_circuit_kid.len = sizeof(defined_short_circuit_kid);
    short_circuit_kid.ptr = defined_short_circuit_kid;

    return short_circuit_kid;
}

/**
 * \brief Verify a short-circuit signature
 *
 * \param[in] hash_to_verify  Pointer and length of hash to verify.
 * \param[in] signature       Pointer and length of signature.
 *
 * \return This returns one of the error codes defined by \ref
 *         t_cose_err_t.
 *
 * See t_cose_sign1_sign_init() for description of the short-circuit
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

/* Warning: this is still early development. Documentation may be incorrect. */


static enum t_cose_err_t
t_cose_signature_verify1_short(struct t_cose_signature_verify *me_x,
                               const struct q_useful_buf_c       protected_body_headers,
                               const struct q_useful_buf_c       protected_signature_headers,
                               const struct q_useful_buf_c       payload,
                               const struct q_useful_buf_c       aad,
                               const struct t_cose_header_param *body_parameters,
                               const struct q_useful_buf_c       signature)
{
    int32_t                             alg_id;
    enum t_cose_err_t                   return_value;
    struct q_useful_buf_c               kid;
    //const struct t_cose_signature_verify_short *me = (const struct t_cose_signature_verify_short *)me_x;
    Q_USEFUL_BUF_MAKE_STACK_UB(         buffer_for_tbs_hash, T_COSE_CRYPTO_MAX_HASH_SIZE);
    struct q_useful_buf_c               tbs_hash;

    /* --- Get the parameters values needed here --- */
    alg_id = t_cose_find_parameter_alg_id(body_parameters);
    if(alg_id == T_COSE_ALGORITHM_NONE) {
        return_value = 88; // TODO: error code
        goto Done;
    }
    kid = t_cose_find_parameter_kid(body_parameters);

    if(q_useful_buf_compare(kid, get_short_circuit_kid_x())) {
        return_value = 88; // TODO: error code
        goto Done;
    }

    /* --- Compute the hash of the to-be-signed bytes -- */
    return_value = create_tbs_hash(alg_id,
                                   protected_body_headers,
                                   protected_signature_headers,
                                   aad,
                                   payload,
                                   buffer_for_tbs_hash,
                                   &tbs_hash);
    if(return_value) {
        goto Done;
    }

    /* -- Verify the signature -- */
    return_value = t_cose_crypto_short_circuit_verify(tbs_hash, signature);
Done:
    return return_value;
}



/*
 Returns: END_OF_HEADERS if no there are no more COSE_Signatures
          CBOR decoding error
          Error decoding the COSE_Signature (but not a COSE error)
          Signature validate
          Signature didn't validate
 */
static enum t_cose_err_t
t_cose_signature_verify_short(struct t_cose_signature_verify *me_x,
                              const bool                        run_crypto,
                              const struct header_location      loc,
                              const struct q_useful_buf_c       protected_body_headers,
                              const struct q_useful_buf_c       payload,
                              const struct q_useful_buf_c       aad,
                              const struct header_param_storage params,
                              QCBORDecodeContext               *qcbor_decoder)
{
    enum t_cose_err_t      return_value;
    struct q_useful_buf_c  protected_parameters;
    struct q_useful_buf_c  signature;
    const struct t_cose_signature_verify_short *me = (const struct t_cose_signature_verify_short *)me_x;

    /* --- Decode the COSE_Signature ---*/
    QCBORDecode_EnterArray(qcbor_decoder, NULL);

    return_value = t_cose_headers_decode(qcbor_decoder,
                                         loc,
                                         me->reader,
                                         me->reader_ctx,
                                         params,
                                        &protected_parameters);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    /* --- The signature --- */
    QCBORDecode_GetByteString(qcbor_decoder, &signature);

    QCBORDecode_ExitArray(qcbor_decoder);
    if(QCBORDecode_GetError(qcbor_decoder)) {
        return_value = 200; // TODO:
        goto Done;
    }
    /* --- Done decoding the COSE_Signature --- */


    if(!run_crypto) {
        goto Done;
    }

    return_value = t_cose_signature_verify1_short(me_x,
                                                  protected_body_headers,
                                                  protected_parameters,
                                                  payload,
                                                  aad,
                                                  params.storage,
                                                  signature);
Done:
    return return_value;
}


void
t_cose_signature_verify_short_init(struct t_cose_signature_verify_short *me)
{
    memset(me, 0, sizeof(*me));
    me->s.callback  = t_cose_signature_verify_short;
    me->s.callback1 = t_cose_signature_verify1_short;
}
