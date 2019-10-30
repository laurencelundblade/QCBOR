/*
 * t_cose_make_test_messages.h
 *
 * Copyright (c) 2019, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#ifndef __T_COSE_MAKE_TEST_MESSAGES__
#define __T_COSE_MAKE_TEST_MESSAGES__

#include <stdint.h>
#include <stdbool.h>
#include "qcbor.h"
#include "t_cose_common.h"
#include "t_cose_sign1_sign.h"


#ifdef __cplusplus
extern "C" {
#endif


/**
 * \file t_cose_make_test_messages.h
 *
 * \brief Create a test \c COSE_Sign1 message for testing the verifier.
 *
 */


/**
 * Various flags to pass to t_cose_test_message_sign1_sign() to
 * make different types of test messages for testing verification
 */
#define T_COSE_TEST_HEADER_LABEL 0x80000000

#define T_COSE_TEST_BAD_CRIT_HEADER   0x40000000

#define T_COSE_TEST_EXTRA_HEADER 0x20000000

#define T_COSE_TEST_NO_PROTECTED_HEADERS 0x10000000

#define T_COSE_TEST_NO_UNPROTECTED_HEADERS 0x08000000

#define T_COSE_TEST_NOT_WELL_FORMED_1 0x04000000

#define T_COSE_TEST_NOT_WELL_FORMED_2 0x02000000

#define T_COSE_TEST_UNKNOWN_CRIT_UINT_HEADER 0x01000000

#define T_COSE_TEST_CRIT_HEADER_EXIST 0x00800000

#define T_COSE_TEST_TOO_MANY_CRIT_HEADER_EXIST 0x00400000

#define T_COSE_TEST_BAD_CRIT_LABEL 0x00200000

#define T_COSE_TEST_CRIT_NOT_PROTECTED 0x00100000

#define T_COSE_TEST_TOO_MANY_UNKNOWN 0x00080000

#define T_COSE_TEST_UNKNOWN_CRIT_TSTR_HEADER 0x00040000

#define T_COSE_TEST_ALL_HEADERS 0x00020000

#define T_COSE_TEST_BAD_PROTECTED 0x00010000

#define T_COSE_TEST_UNPROTECTED_NOT_MAP 0x00008000

#define T_COSE_TEST_KID_IN_PROTECTED 0x00004000

#define T_COSE_TEST_TOO_LARGE_CONTENT_TYPE 0x00002000

#define T_COSE_TEST_UNCLOSED_PROTECTED 0x00001000

#define T_COSE_TEST_DUP_CONTENT_ID 0x00000800

#define T_COSE_TEST_EMPTY_PROTECTED_HEADER 0x00000400

#define T_COSE_TEST_EMPTY_CRIT_HEADERS_PARAM 0x00000200

#define T_COSE_TEST_TOO_MANY_TSTR_CRIT_LABLELS 0x00000100


/**
 * Replica of t_cose_sign1_sign() with modifications to
 * output various good and bad messages for testing verification.
 *
 * \c test_mess_options is one of \c T_COSE_TEST_XXX
 */
enum t_cose_err_t
t_cose_test_message_sign1_sign(struct t_cose_sign1_sign_ctx *me,
                               int32_t                       test_mess_options,
                               struct q_useful_buf_c         payload,
                               struct q_useful_buf           out_buf,
                               struct q_useful_buf_c        *result);


#ifdef __cplusplus
}
#endif

#endif /* __T_COSE_MAKE_TEST_MESSAGES__ */
