/*==============================================================================
 Copyright 2018 Laurence Lundblade
 
 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the
 "Software"), to deal in the Software without restriction, including
 without limitation the rights to use, copy, modify, merge, publish,
 distribute, sublicense, and/or sell copies of the Software, and to
 permit persons to whom the Software is furnished to do so, subject to
 the following conditions:
 
 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 
 (This is the MIT license)
 ==============================================================================*/

//
//  main.c
//  QCBOR
//
//  Created by Laurence Lundblade on 9/13/18.
//  Copyright © 2018 Laurence Lundblade. All rights reserved.
//

#include <stdio.h>

#include "basic_test.h"
#include "half_precision_test.h"


int fputs_wrapper(const char *szString, void *ctx)
{
    return fputs(szString, (FILE *)ctx);
}


int main(int argc, const char * argv[]) {
    
    half_precision_decode_basic();
    
    half_precision_encode_basic();
    
    int nNumTestsFailed = run_tests(&fputs_wrapper, stdout, NULL);

    return nNumTestsFailed;
}
