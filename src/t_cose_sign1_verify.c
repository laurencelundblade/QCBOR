/*
 *  t_cose_sign1_verify.c
 *
 * Copyright 2019-2022, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_parameters.h"
#include "t_cose/t_cose_sign_verify.h"

#include "t_cose_standard_constants.h"

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
    t_cose_sign_verify_init(&(me->me2), option_flags | T_COSE_OPT_MESSAGE_TYPE_SIGN1);
    me->option_flags = option_flags;

#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
    t_cose_signature_verify_short_init(&(me->verifier_sc));
    t_cose_sign_add_verifier(&(me->me2),
                             t_cose_signature_verify_from_short(&(me->verifier_sc)));
#endif
}


void
t_cose_sign1_set_verification_key(struct t_cose_sign1_verify_ctx *me,
                                  struct t_cose_key               verification_key)
{
    t_cose_signature_verify_ecdsa_init(&(me->verifier));
    t_cose_signature_verify_ecdsa_set_key(&(me->verifier), verification_key);
    t_cose_sign_add_verifier(&(me->me2),
                             t_cose_signature_verify_from_ecdsa(&(me->verifier)));
}


/**
 * \brief Clear a struct t_cose_parameters to empty
 *
 * \param[in,out] parameters   Parameter list to clear.
 */
static inline void clear_cose_parameters(struct t_cose_parameters *parameters)
{
#if COSE_ALGORITHM_RESERVED != 0
#error Invalid algorithm designator not 0. Parameter list initialization fails.
#endif

#if T_COSE_ALGORITHM_NONE != COSE_ALGORITHM_RESERVED
#error Constant for unset algorithm ID not aligned with COSE_ALGORITHM_RESERVED
#endif

    /* This clears all the useful_bufs to NULL_Q_USEFUL_BUF_C
     * and the cose_algorithm_id to COSE_ALGORITHM_RESERVED
     */
    memset(parameters, 0, sizeof(struct t_cose_parameters));

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    /* The only non-zero clear-state value. (0 is plain text in CoAP
     * content format) */
    parameters->content_type_uint =  T_COSE_EMPTY_UINT_CONTENT_TYPE;
#endif
}


enum t_cose_err_t
t_cose_translate_params_private(const struct t_cose_header_param *decoded_params,
                                struct t_cose_parameters   *returned_parameters)
{
    enum t_cose_err_t                 return_value = T_COSE_SUCCESS;
    const struct t_cose_header_param *p;

    clear_cose_parameters(returned_parameters);

    /* No duplicate detection is necessary because t_cose_headers_decode()
     * does it. */
    for(p = decoded_params; p->parameter_type != 0; p++) {
        if(p->label == COSE_HEADER_PARAM_KID) {
            if(p->parameter_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
                return_value = T_COSE_ERR_PARAMETER_CBOR;
                goto Done;
            }
            returned_parameters->kid = p->value.string;

        } else if(p->label == COSE_HEADER_PARAM_ALG) {
            if(p->parameter_type != T_COSE_PARAMETER_TYPE_INT64) {
                return_value = T_COSE_ERR_PARAMETER_CBOR;
                goto Done;
            }
            if(!p->prot) {
                return_value = T_COSE_ERR_PARAMETER_NOT_PROTECTED;
                goto Done;
            }
            if(p->value.i64 == COSE_ALGORITHM_RESERVED || p->value.i64 > INT32_MAX) {
                return_value = T_COSE_ERR_NON_INTEGER_ALG_ID;
                goto Done;
            }
            returned_parameters->cose_algorithm_id = (int32_t)p->value.i64;

        } else if(p->label == COSE_HEADER_PARAM_IV) {
            if(p->parameter_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
                return_value = T_COSE_ERR_PARAMETER_CBOR;
                goto Done;
            }
            returned_parameters->iv = p->value.string;

        } else if(p->label == COSE_HEADER_PARAM_PARTIAL_IV) {
            if(p->parameter_type != T_COSE_PARAMETER_TYPE_BYTE_STRING) {
                return_value = T_COSE_ERR_PARAMETER_CBOR;
                goto Done;
            }
            returned_parameters->partial_iv = p->value.string;

#ifndef T_COSE_DISABLE_CONTENT_TYPE
        } else if(p->label == COSE_HEADER_PARAM_CONTENT_TYPE) {
            if(p->parameter_type == T_COSE_PARAMETER_TYPE_TEXT_STRING) {
                returned_parameters->content_type_tstr = p->value.string;

            } else if(p->parameter_type == T_COSE_PARAMETER_TYPE_INT64) {
                if(p->value.i64 < 0 || p->value.i64 > UINT16_MAX) {
                      return_value = T_COSE_ERR_BAD_CONTENT_TYPE;
                      goto Done;
                }
                returned_parameters->content_type_uint = (uint32_t)p->value.i64;

            } else {
                return_value = T_COSE_ERR_BAD_CONTENT_TYPE;
            }
#endif /* T_COSE_DISABLE_CONTENT_TYPE */
        }
    }

    Done:
        return return_value;
}

