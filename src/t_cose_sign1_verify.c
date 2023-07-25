/*
 * t_cose_sign1_verify.c
 *
 * Copyright 2019-2023, Laurence Lundblade
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
t_cose_sign1_verify(struct t_cose_sign1_verify_ctx *me,
                    struct q_useful_buf_c           cose_sign1,
                    struct q_useful_buf_c          *payload,
                    struct t_cose_parameters       *parameters)
{
    enum t_cose_err_t        return_value;
    struct t_cose_parameter *decoded_params;

    return_value = t_cose_sign_verify(&(me->me2),
                                      cose_sign1,
                                      NULL_Q_USEFUL_BUF_C,
                                      payload,
                                      &decoded_params);
    if(return_value != T_COSE_SUCCESS) {
        goto Done;
    }

    if(parameters != NULL) {
        return_value = t_cose_params_common(decoded_params,
                                            parameters);
    }

Done:
    return return_value;
}
