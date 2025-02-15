/*
 * t_cose_sign1_verify.c
 *
 * Copyright 2019-2025, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_sign_verify.h"
#include "t_cose/t_cose_standard_constants.h"

#include "t_cose_util.h"


/**
 * \file t_cose_sign1_verify.c
 *
 * \brief \c COSE_Sign1 verification compatibility layer over the t_cose_sign_verify which
 *        is now the main implementation of \c COSE_Sign1 and \c COSE_Sign.
 */



void
t_cose_sign1_verify_init(struct t_cose_sign1_verify_ctx *me,
                         uint32_t                        option_flags)
{
    t_cose_sign_verify_init(&(me->me2),
                            option_flags | T_COSE_OPT_MESSAGE_TYPE_SIGN1);
    me->option_flags = option_flags;

    t_cose_signature_verify_main_init(&(me->main_verifier));
    t_cose_sign_add_verifier(&(me->me2),
                       t_cose_signature_verify_from_main(&(me->main_verifier)));

    t_cose_signature_verify_eddsa_init(&(me->eddsa_verifier), option_flags);
    t_cose_sign_add_verifier(&(me->me2),
                    t_cose_signature_verify_from_eddsa(&(me->eddsa_verifier)));
}


void
t_cose_sign1_set_verification_key(struct t_cose_sign1_verify_ctx *me,
                                  struct t_cose_key           verification_key)
{
    /* Set the same key for both. We don't know which verifier will be used
     * until decoding the input. There is only one key in t_cose_sign1().
     * Also, t_cose_sign1 didn't do any kid matching, so it is NULL here.
     */
    t_cose_signature_verify_eddsa_set_key(&(me->eddsa_verifier),
                                          verification_key,
                                          // TODO: should this be NULL?
                                          NULL_Q_USEFUL_BUF_C);
    t_cose_signature_verify_main_set_key(&(me->main_verifier),
                                         verification_key,
                                         NULL_Q_USEFUL_BUF_C);
}


enum t_cose_err_t
t_cose_sign1_private_verify_main(struct t_cose_sign1_verify_ctx *me,
                                 struct q_useful_buf_c           cose_message,
                                 struct q_useful_buf_c           ext_sup_data,
                                 const bool                      payload_is_detached,
                                 struct q_useful_buf_c          *payload,
                                 struct t_cose_parameters       *parameters)
{
    enum t_cose_err_t        return_value;
    struct t_cose_parameter *decoded_params;
    QCBORDecodeContext       cbor_decoder;
    uint64_t                 tag_numbers[T_COSE_MAX_TAGS_TO_RETURN];

    struct t_cose_sign_verify_ctx *me2 = &(me->me2);

    QCBORDecode_Init(&cbor_decoder, cose_message, QCBOR_DECODE_MODE_NORMAL);

#if QCBOR_VERSION_MAJOR >= 2
    QCBORError               cbor_error;
    int                      tag_num_index;

    /* This implements t_cose v1 tag semantics with QCBOR v2 */

    /* Get all the tag numbers that preceed the COSE_Sign1 */
    cbor_error = t_cose_private_consume_tag_nums(&cbor_decoder, tag_numbers, &tag_num_index);
    if(cbor_error != QCBOR_SUCCESS) {
        return qcbor_decode_error_to_t_cose_error(cbor_error, T_COSE_ERR_SIGN1_FORMAT);
    }

    /* See if it is tagged as a COSE_Sign1 */
    bool is_tagged_cose_sign1 = false;
    if(tag_numbers[tag_num_index] == CBOR_TAG_COSE_SIGN1) {
        tag_numbers[tag_num_index] = CBOR_TAG_INVALID64;
        tag_num_index--;
        is_tagged_cose_sign1 = true;
    }

    /* What flags matter? T_COSE_OPT_TAG_REQUIRED, T_COSE_OPT_TAG_PROHIBITED, */
    if(me->option_flags & T_COSE_OPT_TAG_REQUIRED) {
        if(!is_tagged_cose_sign1) {
            /* Caller doesn't know if this is a COSESign1 or not. They
             * are relying on that, so if not tagged, it is an error. */
            return T_COSE_ERR_INCORRECTLY_TAGGED;
        }
    }

    if(me->option_flags & T_COSE_OPT_TAG_PROHIBITED) {
        if(is_tagged_cose_sign1) {
            /* Caller knows this is a COSE_Sign1 for sure and there should
             * be no tag indicating so. */
            return T_COSE_ERR_INCORRECTLY_TAGGED;
        }
    }

    /* Now reverse the order of the tag numbers from v2 to v1 */
    for(int iii = 0; iii < T_COSE_MAX_TAGS_TO_RETURN; iii++) {
        if(tag_num_index >= 0) {
            me->tag_numbers[iii] = tag_numbers[tag_num_index];
            tag_num_index--;
        } else {
            me->tag_numbers[iii] = CBOR_TAG_INVALID64;
        }
    }

    me2->option_flags |= CBOR_TAG_COSE_SIGN1;

#endif /* QCBOR_VERSION_MAJOR >= 2 */
    
    /* Possible tag error conditions processed and all OK. It's a COSE_Sign1 */
    me2->v1_compatible = true;

    return_value = t_cose_sign_verify_private(me2,
                                             &cbor_decoder,
                                              ext_sup_data,
                                              payload_is_detached,
                                              payload,
                                             &decoded_params,
                                              tag_numbers);

    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

#if QCBOR_VERSION_MAJOR == 1
    memcpy(me->tag_numbers, tag_numbers, sizeof(tag_numbers));
#endif /* QCBOR_VERSION_MAJOR == 1 */

    if(parameters != NULL) {
        return_value = t_cose_params_common(decoded_params, parameters);
    }

Done:
    return return_value;
}
