/*==============================================================================
  cmd_line_mainc.c -- Runs tests for QCBOR encoder / decoder

 Copyright (c) 2018-2019, Laurence Lundblade. All rights reserved.

 SPDX-License-Identifier: BSD-3-Clause

 See BSD-3-Clause license in README.md

 Created on 9/13/18
 ==============================================================================*/

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
