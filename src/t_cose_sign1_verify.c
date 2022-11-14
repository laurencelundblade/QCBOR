/*
 * t_cose_sign1_verify.c
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

#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
    t_cose_signature_verify_short_init(&(me->verifier_sc));
    t_cose_sign_add_verifier(&(me->me2),
                       t_cose_signature_verify_from_short(&(me->verifier_sc)));
#endif
}


void
t_cose_sign1_set_verification_key(struct t_cose_sign1_verify_ctx *me,
                                  struct t_cose_key           verification_key)
{
    t_cose_signature_verify_ecdsa_init(&(me->verifier));
    t_cose_signature_verify_ecdsa_set_key(&(me->verifier), verification_key);
    t_cose_sign_add_verifier(&(me->me2),
                          t_cose_signature_verify_from_ecdsa(&(me->verifier)));
}



