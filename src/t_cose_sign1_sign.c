/*
 * t_cose_sign1_sign.c
 *
 * Copyright (c) 2018-2022, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "t_cose/t_cose_sign1_sign.h"
#include "qcbor/qcbor.h"
#include "t_cose_standard_constants.h"
#include "t_cose_crypto.h"
#include "t_cose_util.h"


/**
 * \file t_cose_sign1_sign.c
 *
 * \brief This implements t_cose signing.
 */




void
t_cose_sign1_set_signing_key(struct t_cose_sign1_sign_ctx *me,
                             struct t_cose_key             signing_key,
                             struct q_useful_buf_c         kid)
{
#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
    if(me->option_flags & T_COSE_OPT_SHORT_CIRCUIT_SIG) {

        me->kid = kid; // TODO: is this needed?
        // tell the short circuit signer to put this kid in.
        me->short_circuit_signer.kid = kid; // TODO: fix layering violation?

    } else
#endif
    {
        t_cose_signature_sign_ecdsa_init(&(me->signer), me->cose_algorithm_id);

        t_cose_signature_sign_ecdsa_set_signing_key(&(me->signer),
                                                    signing_key,
                                                    kid);
        t_cose_sign_add_signer(&(me->me2),
                               t_cose_signature_sign_from_ecdsa(&(me->signer)));
    }
}


#ifndef T_COSE_DISABLE_CONTENT_TYPE
void
t_cose_sign1_set_content_type_uint(struct t_cose_sign1_sign_ctx *me,
                                   uint16_t                     content_type)
{
    me->content_id_param[0] = T_COSE_CT_UINT_PARAM(content_type);
    me->content_id_param[1] = T_COSE_END_PARAM;

    t_cose_sign_add_body_header_params(&(me->me2), me->content_id_param);
}


void
t_cose_sign1_set_content_type_tstr(struct t_cose_sign1_sign_ctx *me,
                                   const char                   *content_type)
{
    me->content_id_param[0] = T_COSE_CT_TSTR_PARAM(q_useful_buf_from_sz(content_type));
    me->content_id_param[1] = T_COSE_END_PARAM;

    t_cose_sign_add_body_header_params(&(me->me2), me->content_id_param);
}
#endif




