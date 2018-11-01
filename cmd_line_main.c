/*==============================================================================
 cmd_line_mainc.c -- basic tests for qcbor encoder / decoder
 
 Copyright (c) 2018, Laurence Lundblade.
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are
 met:
 * Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above
 copyright notice, this list of conditions and the following
 disclaimer in the documentation and/or other materials provided
 with the distribution.
 * Neither the name of The Linux Foundation nor the names of its
 contributors, nor the name "Laurence Lundblade" may be used to
 endorse or promote products derived from this software without
 specific prior written permission.
 
 THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ==============================================================================*/
//  Created by Laurence Lundblade on 9/13/18.

#include <stdio.h>
#include "run_tests.h"
#include "qcbor.h" // just to print sizes of the structures.


int fputs_wrapper(const char *szString, void *ctx)
{
    return fputs(szString, (FILE *)ctx);
}


int main(int argc, const char * argv[])
{
    (void)argc; // Suppress unused warning
    (void)argv; // Suppress unused warning

    // Type and size of return from sizeof() varies. These will never be large so cast is safe
    // TODO: use fputs_wrapper to output these
    printf("sizeof(QCBOREncodeContext) %d\n", (uint32_t)sizeof(QCBOREncodeContext));
    printf("sizeof(QCBORDecodeContext) %d\n", (uint32_t)sizeof(QCBORDecodeContext));
    printf("sizeof(QCBORDecodeNesting) %d\n", (uint32_t)sizeof(QCBORDecodeNesting));
    printf("sizeof(QCBORItem) %d\n", (uint32_t)sizeof(QCBORItem));
    printf("sizeof(QCBORStringAllocator) %d\n\n", (uint32_t)sizeof(QCBORStringAllocator));

    // TODO: command line arg to select test
    int nNumTestsFailed = run_tests(&fputs_wrapper, stdout, NULL);

    return nNumTestsFailed;
}
