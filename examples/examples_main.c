/*
 * examples_main.c
 *
 * Copyright 2023, Laurence Lundblade
 *
 * Created by Laurence Lundblade on 2/21/23.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 */

#include <stdbool.h>
#include <stdio.h>

#include "signing_examples.h"
#include "encryption_examples.h"


typedef int32_t (test_fun_t)(void);

#define TEST_ENTRY(test_name)  {#test_name, test_name, true}

typedef struct {
    const char  *szTestName;
    test_fun_t  *test_fun;
    bool         bEnabled;
} test_entry;

static test_entry s_tests[] = {

    TEST_ENTRY(one_step_sign_example),
    TEST_ENTRY(two_step_sign_example),
    TEST_ENTRY(one_step_multi_sign_detached_example),
    TEST_ENTRY(old_one_step_sign_example),
    TEST_ENTRY(old_two_step_sign_example),

    TEST_ENTRY(encrypt0_example),
#ifndef T_COSE_DISABLE_KEYWRAP
    TEST_ENTRY(key_wrap_example),
#endif /* !T_COSE_DISABLE_KEYWRAP */

    TEST_ENTRY(esdh_example),
    TEST_ENTRY(esdh_example_detached),
};



int main(int argc, const char * argv[])
{
    (void)argc; /* Avoid unused parameter error */
    (void)argv;
    int nTestsFailed = 0;
    int nTestsRun = 0;

    test_entry *t;
    const test_entry *s_tests_end = s_tests + sizeof(s_tests)/sizeof(test_entry);

    for(t = s_tests; t < s_tests_end; t++) {
        /* Could bring in command line arges from run_tests.c here */

        int32_t nTestResult = (int32_t)(t->test_fun)();
        nTestsRun++;

        if(nTestResult) {
            nTestsFailed++;
        }
    }

    printf("\n%d of %d EXAMPLES FAILED\n", nTestsFailed, nTestsRun);
}
