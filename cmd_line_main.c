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


static void PrintSize(const char *szWhat, uint32_t uSize)
{
    UsefulBuf_MAKE_STACK_UB(foo, 20);

    fputs_wrapper(szWhat, stdout);
    fputs_wrapper(" ", stdout);
    fputs_wrapper(NumToString(uSize,foo), stdout);
    fputs_wrapper("\n", stdout);
}


int main(int argc, const char * argv[])
{
    // Type and size of return from sizeof() varies. These will never be large so cast is safe
    PrintSize("sizeof(QCBORTrackNesting)", (uint32_t)sizeof(QCBORTrackNesting));
    PrintSize("sizeof(QCBORTrackNesting)", (uint32_t)sizeof(QCBORTrackNesting));
    PrintSize("sizeof(QCBOREncodeContext)", (uint32_t)sizeof(QCBOREncodeContext));
    PrintSize("sizeof(QCBORDecodeContext)", (uint32_t)sizeof(QCBORDecodeContext));
    PrintSize("sizeof(QCBORDecodeNesting)", (uint32_t)sizeof(QCBORDecodeNesting));
    PrintSize("sizeof(QCBORItem)", (uint32_t)sizeof(QCBORItem));
    PrintSize("sizeof(QCBORStringAllocator)", (uint32_t)sizeof(QCBORStringAllocator));
    fputs_wrapper("\n", stdout);

    int nNumTestsFailed = 0;

    if(argc > 1) {
        nNumTestsFailed += run_tests(argv[1], &fputs_wrapper, stdout, NULL);
    } else {
        nNumTestsFailed += run_tests(NULL, &fputs_wrapper, stdout, NULL);
    }

    return nNumTestsFailed;
}
