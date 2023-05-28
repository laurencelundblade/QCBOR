/*
 * t_cose_sign1_sign.c
 *
 * Copyright (c) 2018-2022, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include "qcbor/qcbor.h"
#include "t_cose/t_cose_sign1_sign.h"
#include "t_cose/t_cose_standard_constants.h"


/**
 * \file t_cose_sign1_sign.c
 *
 * \brief This implements the t_cose v1 interface for COSE_Sign1.
 */


void
t_cose_sign1_sign_init(struct t_cose_sign1_sign_ctx *me,
                       uint32_t                      option_flags,
                       int32_t                       cose_algorithm_id)
{
    memset(me, 0, sizeof(*me));
#ifndef T_COSE_DISABLE_CONTENT_TYPE
    /* Only member for which 0 is not the empty state */
    me->content_type_uint = T_COSE_EMPTY_UINT_CONTENT_TYPE;
#endif

    me->cose_algorithm_id = cose_algorithm_id;
    me->option_flags = option_flags;  // Used by t_cose_make_test_messages.c

    // TODO: Translate any more options flags?
    t_cose_sign_sign_init(&(me->me2), option_flags | T_COSE_OPT_MESSAGE_TYPE_SIGN1);

    if(cose_algorithm_id == T_COSE_ALGORITHM_EDDSA) {
        t_cose_signature_sign_eddsa_init(&(me->signer.eddsa));
        t_cose_sign_add_signer(&(me->me2),
                       t_cose_signature_sign_from_eddsa(&(me->signer.eddsa)));
    } else
    {
        t_cose_signature_sign_main_init(&(me->signer.general),
                                        me->cose_algorithm_id);
        t_cose_sign_add_signer(&(me->me2),
                      t_cose_signature_sign_from_main(&(me->signer.general)));
    }
}


void
t_cose_sign1_set_signing_key(struct t_cose_sign1_sign_ctx *me,
                             struct t_cose_key             signing_key,
                             struct q_useful_buf_c         kid)
{
    me->signing_key = signing_key; /* Used by make test message */
    me->kid = kid; /* Used by make test message */
    if(me->cose_algorithm_id == T_COSE_ALGORITHM_EDDSA) {
        t_cose_signature_sign_eddsa_set_signing_key(&(me->signer.eddsa),
                                                     signing_key,
                                                     kid);
    } else {
        t_cose_signature_sign_main_set_signing_key(&(me->signer.general),
                                                    signing_key,
                                                    kid);
    }
}


#ifndef T_COSE_DISABLE_CONTENT_TYPE
void
t_cose_sign1_set_content_type_uint(struct t_cose_sign1_sign_ctx *me,
                                   uint16_t                     content_type)
{
    me->content_id_param = t_cose_param_make_ct_uint(content_type);

    t_cose_sign_add_body_header_params(&(me->me2), &me->content_id_param);
}


void
t_cose_sign1_set_content_type_tstr(struct t_cose_sign1_sign_ctx *me,
                                   const char                   *content_type)
{
    me->content_id_param = t_cose_param_make_ct_tstr(q_useful_buf_from_sz(content_type));

    t_cose_sign_add_body_header_params(&(me->me2), &me->content_id_param);
}
#endif


void
t_cose_sign1_sign_set_auxiliary_buffer(struct t_cose_sign1_sign_ctx *me,
                                       struct q_useful_buf           aux_buffer)
{
    if(me->cose_algorithm_id == T_COSE_ALGORITHM_EDDSA) {
        t_cose_signature_sign_eddsa_set_auxiliary_buffer(&(me->signer.eddsa),
                                                         aux_buffer);
    }
}


size_t
t_cose_sign1_sign_auxiliary_buffer_size(struct t_cose_sign1_sign_ctx *me)
{
    if(me->cose_algorithm_id == T_COSE_ALGORITHM_EDDSA) {
        return me->signer.eddsa.auxiliary_buffer_size;
    } else {
        return 0;
    }
}
