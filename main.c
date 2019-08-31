/*
 *  t_cose_openssl_signature.c
 *
 * Copyright 2019, Laurence Lundblade
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md.
 *
 * Created 4/21/2019.
 */

#include <stdio.h>
#include "run_tests.h"


/*
 This is an implementation of OutputStringCB built using stdio. If
 you don't have stdio, replaces this.
 */
static void fputs_wrapper(const char *szString, void *pOutCtx, int bNewLine)
{
    fputs(szString, (FILE *)pOutCtx);
    if(bNewLine) {
        fputs("\n", pOutCtx);
    }
}


int main(int argc, const char * argv[])
{
    (void)argc; // Avoid unused parameter error

    // This call prints out sizes of data structures to remind us
    // to keep them small.
    PrintSizes(&fputs_wrapper, stdout);

    // This runs all the tests
    return RunTests(argv+1, &fputs_wrapper, stdout, NULL);
}
