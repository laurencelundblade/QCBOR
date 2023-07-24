/* ==============================================================================
 * run_tests.c -- test aggregator and results reporting
 *
 * Copyright (c) 2018-2023, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created on 9/30/18
 =============================================================================*/

#include "run_tests.h"
#include "t_cose/q_useful_buf.h"
#include <stdbool.h>
#include <stddef.h>


typedef int32_t (test_fun_t)(void);


#define TEST_ENTRY(test_name)  {#test_name, test_name, true}
#define TEST_ENTRY_DISABLED(test_name)  {#test_name, test_name, false}

typedef struct {
    const char  *szTestName;
    test_fun_t  *test_fun;
    bool         bEnabled;
} test_entry;


/*
 * Test configuration
 */

#include "t_cose_test.h"
#include "t_cose_sign_verify_test.h"
#include "t_cose_compute_validate_mac_test.h"
#include "t_cose_param_test.h"
#include "t_cose_crypto_test.h"
#include "t_cose_encrypt_decrypt_test.h"
#include "t_cose/t_cose_common.h"


static test_entry s_tests[] = {
    TEST_ENTRY(aead_test),
#ifndef T_COSE_DISABLE_KEYWRAP
    TEST_ENTRY(kw_test),
#endif
    TEST_ENTRY(hkdf_test),

#ifndef T_COSE_USE_B_CON_SHA256 /* test crypto doesn't support ECDH */

    TEST_ENTRY(ecdh_test),
    TEST_ENTRY(ec_import_export_test),

    TEST_ENTRY(esdh_enc_dec_test),
    TEST_ENTRY(decrypt_known_good),
#endif /* T_COSE_USE_B_CON_SHA256 */

    TEST_ENTRY(sign1_structure_decode_test),

    TEST_ENTRY(crypto_context_test),

#ifndef T_COSE_DISABLE_SIGN_VERIFY_TESTS
    /* Many tests can be run without a crypto library integration and
     * provide good test coverage of everything but the signing and
     * verification. These tests can't be run with signing and
     * verification short circuited.  They must have a real crypto
     * library integrated. */
    TEST_ENTRY(sign_verify_basic_test),
    TEST_ENTRY(sign_verify_make_cwt_test),
    TEST_ENTRY(sign_verify_sig_fail_test),
    TEST_ENTRY(sign_verify_get_size_test),
    TEST_ENTRY(sign_verify_known_good_test),
    TEST_ENTRY(sign_verify_unsupported_test),
    TEST_ENTRY(sign_verify_bad_auxiliary_buffer),

#ifndef T_COSE_DISABLE_COSE_SIGN
    TEST_ENTRY(verify_multi_test),
    TEST_ENTRY(verify_multi_test),
    TEST_ENTRY(restart_test_2_step),
#endif /* T_COSE_DISABLE_SIGN1 */

    // TODO: should these really be conditional on T_COSE_DISABLE_SIGN_VERIFY_TESTS

#endif /* T_COSE_DISABLE_SIGN_VERIFY_TESTS */

    TEST_ENTRY(compute_validate_mac_basic_test),
    TEST_ENTRY(compute_validate_mac_fail_test),
    TEST_ENTRY(compute_validate_get_size_mac_test),
    TEST_ENTRY(compute_validate_detached_content_mac_fail_test),
    TEST_ENTRY(compute_validate_get_size_detached_content_mac_test),

#ifndef T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
    /* These tests can't run if short-circuit signatures are disabled.
     * The most critical ones are replicated in the group of tests
     * that require a real crypto library. Typically short-circuit
     * signing is only disabled for extreme code size savings so these
     * tests are typically always run.
     */
    TEST_ENTRY(bad_parameters_test),
    TEST_ENTRY(crit_parameters_test),

#ifndef T_COSE_DISABLE_CONTENT_TYPE
    TEST_ENTRY(content_type_test),
#endif /* !T_COSE_DISABLE_CONTENT_TYPE */
    TEST_ENTRY(all_header_parameters_test),
#ifdef FIXME /* Issue with key material for this test */
    TEST_ENTRY(cose_example_test),
#endif
    TEST_ENTRY(short_circuit_signing_error_conditions_test),
    TEST_ENTRY(short_circuit_self_test),
    TEST_ENTRY(short_circuit_self_detached_content_test),
    TEST_ENTRY(short_circuit_decode_only_test),
    TEST_ENTRY(short_circuit_make_cwt_test),
    TEST_ENTRY(short_circuit_verify_fail_test),
    TEST_ENTRY(tags_test),
    TEST_ENTRY(get_size_test),
    TEST_ENTRY(indef_array_and_map_test),

#ifdef T_COSE_ENABLE_HASH_FAIL_TEST
    TEST_ENTRY(short_circuit_hash_fail_test),
#endif /* T_COSE_DISABLE_HASH_FAIL_TEST */
#endif /* T_COSE_DISABLE_SHORT_CIRCUIT_SIGN */

    TEST_ENTRY(param_test),
    TEST_ENTRY(common_params_test),
    TEST_ENTRY(base_encrypt_decrypt_test)

};




/**
 * \brief Convert number to ASCII string, similar to sprint
 *
 * \param [in]  nNum       The 32-bit integer to convert.
 * \param [in]  StringMem  The buffer to output to.
 *
 * \return POinter to NULL-terminated string with result or "XXX" on failure.
 *
 * Convert a number up to 999999999 to a string. This is so sprintf doesn't
 * have to be linked in so as to minimized dependencies even in test code.
 *
 * StringMem should be 12 bytes long, 9 for digits, 1 for minus and
 * 1 for \0 termination.
 */
static const char *NumToString(int32_t nNum, UsefulBuf StringMem)
{
   const int32_t nMax = 1000000000;

   UsefulOutBuf OutBuf;
   UsefulOutBuf_Init(&OutBuf, StringMem);

   if(nNum < 0) {
      UsefulOutBuf_AppendByte(&OutBuf, '-');
      nNum = -nNum;
   }
   if(nNum > nMax-1) {
      return "XXX";
   }

   bool bDidSomeOutput = false;
   for(int32_t n = nMax; n > 0; n/=10) {
      int32_t nDigitValue = nNum/n;
      if(nDigitValue || bDidSomeOutput){
         bDidSomeOutput = true;
         UsefulOutBuf_AppendByte(&OutBuf, (uint8_t)('0' + nDigitValue));
         nNum -= nDigitValue * n;
      }
   }
   if(!bDidSomeOutput){
      UsefulOutBuf_AppendByte(&OutBuf, '0');
   }
   UsefulOutBuf_AppendByte(&OutBuf, '\0');

   return UsefulOutBuf_GetError(&OutBuf) ? "" : StringMem.ptr;
}


/*
 * Public function. See run_test.h.
 */
int RunTestsTCose(const char    *szTestNames[],
                  OutputStringCB pfOutput,
                  void          *poutCtx,
                  int           *pNumTestsRun)
{
    int                        nTestsFailed = 0;
    int                        nTestsRun = 0;
    Q_USEFUL_BUF_MAKE_STACK_UB(StringStorage, 12);
    test_entry                *t;

    const test_entry *s_tests_end = s_tests + sizeof(s_tests)/sizeof(test_entry);

    for(t = s_tests; t < s_tests_end; t++) {
        if(szTestNames[0]) {
            /* Some tests have been named */
            const char **szRequestedNames;
            for(szRequestedNames = szTestNames; *szRequestedNames;  szRequestedNames++) {
                if(!strcmp(t->szTestName, *szRequestedNames)) {
                    break; /* Name matched */
                }
            }
            if(*szRequestedNames == NULL) {
                /* Didn't match this test */
                continue;
            }
        } else {
            /* no tests named, but don't run "disabled" tests */
            if(!t->bEnabled) {
                /* Don't run disabled tests when all tests are being run
                 * as indicated by no specific test names being given
                 */
                continue;
            }
        }

        int32_t nTestResult = (int32_t)(t->test_fun)();

        if(nTestResult == INT32_MIN) {
            /* INT32_MIN means tests didn't do any testing. It is typically
             * returned when the algorithms needed for a test aren't
             * available when checked by t_cose_is_algorithm_supported(). */
            continue;
        }
        nTestsRun++;
        if(pfOutput) {
            (*pfOutput)(t->szTestName, poutCtx, 0);
        }

        if(nTestResult) {
            if(pfOutput) {
                (*pfOutput)(" FAILED (returned ", poutCtx, 0);
                (*pfOutput)(NumToString(nTestResult, StringStorage), poutCtx, 0);
                (*pfOutput)(")", poutCtx, 1);
            }
            nTestsFailed++;
        } else {
            if(pfOutput) {
                (*pfOutput)( " PASSED", poutCtx, 1);
            }
        }
        /* TODO using special error code to indicate if a test
         * did not actually run due to lack of algorithm support?
         */
    }

    if(pNumTestsRun) {
        *pNumTestsRun = nTestsRun;
    }

    if(pfOutput) {
        (*pfOutput)( "SUMMARY: ", poutCtx, 0);
        (*pfOutput)( NumToString(nTestsRun, StringStorage), poutCtx, 0);
        (*pfOutput)( " tests run; ", poutCtx, 0);
        (*pfOutput)( NumToString(nTestsFailed, StringStorage), poutCtx, 0);
        (*pfOutput)( " tests failed", poutCtx, 1);
    }

    return nTestsFailed;
}


/*
 * Public function. See run_test.h.
 */
static void PrintSize(const char    *szWhat,
                      uint32_t       uSize,
                      OutputStringCB pfOutput,
                      void          *pOutCtx)
{
    Q_USEFUL_BUF_MAKE_STACK_UB(buffer, 20);
    const char                *szNum;

   (*pfOutput)(szWhat, pOutCtx, 0);
    szNum = NumToString((int32_t)uSize, buffer);
    for(size_t i = strlen(szWhat); i < 49 - strlen(szNum); i++) {
       (*pfOutput)(" ", pOutCtx, 0);
    }
   (*pfOutput)(szNum, pOutCtx, 0);
   (*pfOutput)("", pOutCtx, 1);
}




/* Print out the sizes of the important data structures */

#include "t_cose/t_cose_sign_sign.h"
#include "t_cose/t_cose_sign_verify.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/t_cose_sign1_sign.h"

#include "t_cose/t_cose_signature_sign_main.h"
#include "t_cose/t_cose_signature_verify_main.h"

#include "t_cose/t_cose_signature_sign_eddsa.h"
#include "t_cose/t_cose_signature_verify_eddsa.h"

#include "t_cose_crypto.h"
#include "t_cose/t_cose_parameters.h"

#include "t_cose/t_cose_encrypt_enc.h"
#include "t_cose/t_cose_encrypt_dec.h"

#include "t_cose/t_cose_mac_compute.h"
#include "t_cose/t_cose_mac_validate.h"

#include "t_cose/t_cose_recipient_enc_keywrap.h"
#include "t_cose/t_cose_recipient_dec_keywrap.h"

#include "t_cose/t_cose_recipient_enc_esdh.h"
#include "t_cose/t_cose_recipient_dec_esdh.h"


/*
 * Public function. See run_test.h.
 */
void PrintSizesTCose(OutputStringCB pfOutput, void *pOutCtx)
{
   /* Type and size of return from sizeof() varies. These will never be large
    * so cast to uint32_t is safe.
    */
    PrintSize("sizeof(struct t_cose_parameter)",
              (uint32_t)sizeof(struct t_cose_parameter),
              pfOutput, pOutCtx);
    PrintSize("sizeof(struct t_cose_parameters)",
              (uint32_t)sizeof(struct t_cose_parameters),
              pfOutput, pOutCtx);
    PrintSize("sizeof(struct t_cose_key)",
              (uint32_t)sizeof(struct t_cose_key),
              pfOutput, pOutCtx);

    PrintSize("sizeof(struct t_cose_sign_ctx)",
              (uint32_t)sizeof(struct t_cose_sign_sign_ctx),
              pfOutput, pOutCtx);
    PrintSize("sizeof(struct t_cose_sign1_ctx)",
              (uint32_t)sizeof(struct t_cose_sign1_sign_ctx),
              pfOutput, pOutCtx);
    PrintSize("sizeof(struct t_cose_sign_verify_ctx)",
              (uint32_t)sizeof(struct t_cose_sign_verify_ctx),
              pfOutput, pOutCtx);
    PrintSize("sizeof(struct t_cose_sign1_verify_ctx)",
              (uint32_t)sizeof(struct t_cose_sign1_verify_ctx),
              pfOutput, pOutCtx);

    PrintSize("sizeof(struct t_cose_encrypt_enc)",
              (uint32_t)sizeof(struct t_cose_encrypt_enc),
              pfOutput, pOutCtx);
    PrintSize("sizeof(struct t_cose_encrypt_dec_ctx)",
              (uint32_t)sizeof(struct t_cose_encrypt_dec_ctx),
              pfOutput, pOutCtx);

    PrintSize("sizeof(struct t_cose_mac_calculate_ctx)",
              (uint32_t)sizeof(struct t_cose_mac_calculate_ctx),
              pfOutput, pOutCtx);

    PrintSize("sizeof(struct t_cose_mac_validate_ctx)",
              (uint32_t)sizeof(struct t_cose_mac_validate_ctx),
              pfOutput, pOutCtx);

    PrintSize("sizeof(struct t_cose_signature_sign_main)",
              (uint32_t)sizeof(struct t_cose_signature_sign_main),
              pfOutput, pOutCtx);
    PrintSize("sizeof(struct t_cose_signature_verify_main)",
              (uint32_t)sizeof(struct t_cose_signature_verify_main),
              pfOutput, pOutCtx);

    PrintSize("sizeof(struct t_cose_signature_sign_eddsa)",
               (uint32_t)sizeof(struct t_cose_signature_sign_eddsa),
               pfOutput, pOutCtx);
     PrintSize("sizeof(struct t_cose_signature_verify_eddsa)",
               (uint32_t)sizeof(struct t_cose_signature_verify_eddsa),
               pfOutput, pOutCtx);

    PrintSize("sizeof(struct t_cose_recipient_enc_keywrap)",
              (uint32_t)sizeof(struct t_cose_recipient_enc_keywrap),
              pfOutput, pOutCtx);
    PrintSize("sizeof(struct t_cose_recipient_dec_keywrap)",
              (uint32_t)sizeof(struct t_cose_recipient_dec_keywrap),
              pfOutput, pOutCtx);

    PrintSize("sizeof(struct t_cose_recipient_enc_esdh)",
              (uint32_t)sizeof(struct t_cose_recipient_enc_esdh),
              pfOutput, pOutCtx);
    PrintSize("sizeof(struct t_cose_recipient_dec_esdh)",
              (uint32_t)sizeof(struct t_cose_recipient_dec_esdh),
              pfOutput, pOutCtx);

    PrintSize("sizeof(struct t_cose_crypto_hash)",
              (uint32_t)sizeof(struct t_cose_crypto_hash),
              pfOutput, pOutCtx);

    (*pfOutput)("", pOutCtx, 1);
}
