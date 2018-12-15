
/*==============================================================================
 run_tests.c -- test aggregator and results reporting
 
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
    * The name "Laurence Lundblade" may not be used to
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
//  Created by Laurence Lundblade on 9/30/18.


#include "run_tests.h"
#include "UsefulBuf.h"
#include <stdbool.h>

#include "float_tests.h"
#include "qcbor_decode_tests.h"
#include "qcbor_encode_tests.h"
#include "UsefulBuf_Tests.h"
#include "qcbor_decode_malloc_tests.h"

// Used to test the test runner
int fail_test()
{
    return -44;
}


/*
 Convert a number up to 999999999 to a string. This is so sprintf doesn't
 have to be linked in so as to minimized dependencies even in test code.
  */
const char *NumToString(int32_t nNum, UsefulBuf StringMem)
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
    for(int n = nMax; n > 0; n/=10) {
        int x = nNum/n;
        if(x || bDidSomeOutput){
            bDidSomeOutput = true;
            UsefulOutBuf_AppendByte(&OutBuf, '0' + x);
            nNum -= x * n;
        }
    }
    if(!bDidSomeOutput){
        UsefulOutBuf_AppendByte(&OutBuf, '0');
    }
    UsefulOutBuf_AppendByte(&OutBuf, '\0');
    
    return UsefulOutBuf_GetError(&OutBuf) ? "" : StringMem.ptr;
}



typedef int (test_fun_t)(void);
typedef const char * (test_fun2_t)(void);


#define TEST_ENTRY(test_name)  {#test_name, test_name}
typedef struct {
    const char *szTestName;
    test_fun_t  *test_fun;
} test_entry;

typedef struct {
    const char *szTestName;
    test_fun2_t  *test_fun;
} test_entry2;

test_entry2 s_tests2[] = {
    TEST_ENTRY(UBUTest_CopyUtil),
    TEST_ENTRY(UOBTest_NonAdversarial),
    TEST_ENTRY(TestBasicSanity),
    TEST_ENTRY(UOBTest_BoundaryConditionsTest),
    TEST_ENTRY(UBMacroConversionsTest),
    TEST_ENTRY(UBUtilTests),
    TEST_ENTRY(UIBTest_IntegerFormat)
};


test_entry s_tests[] = {
    TEST_ENTRY(MallocAllStringsTest),
    TEST_ENTRY(AllocAllStringsTest),
    TEST_ENTRY(IndefiniteLengthNestTest),
    TEST_ENTRY(NestedMapTestIndefLen),
    TEST_ENTRY(ParseSimpleTest),
    TEST_ENTRY(EncodeRawTest),
    TEST_ENTRY(RTICResultsTest),
    TEST_ENTRY(MapEncodeTest),
    TEST_ENTRY(ArrayNestingTest1),
    TEST_ENTRY(ArrayNestingTest2),
    TEST_ENTRY(ArrayNestingTest3),
    TEST_ENTRY(EncodeDateTest),
    TEST_ENTRY(SimpleValuesTest1),
    TEST_ENTRY(IntegerValuesTest1),
    TEST_ENTRY(AllAddMethodsTest),
    TEST_ENTRY(ParseTooDeepArrayTest),
    TEST_ENTRY(ComprehensiveInputTest),
    TEST_ENTRY(ParseMapTest),
    TEST_ENTRY(IndefiniteLengthArrayMapTest),
    TEST_ENTRY(BasicEncodeTest),
    TEST_ENTRY(NestedMapTest),
    TEST_ENTRY(BignumParseTest),
    TEST_ENTRY(OptTagParseTest),
    TEST_ENTRY(DateParseTest),
    TEST_ENTRY(ShortBufferParseTest2),
    TEST_ENTRY(ShortBufferParseTest),
    TEST_ENTRY(ParseDeepArrayTest),
    TEST_ENTRY(SimpleArrayTest),
    TEST_ENTRY(IntegerValuesParseTest),
    TEST_ENTRY(MemPoolTest),
    TEST_ENTRY(IndefiniteLengthStringTest),
    TEST_ENTRY(HalfPrecisionDecodeBasicTests),
    TEST_ENTRY(DoubleAsSmallestTest),
    TEST_ENTRY(HalfPrecisionAgainstRFCCodeTest),
    TEST_ENTRY(BstrWrapTest),
    TEST_ENTRY(BstrWrapErrorTest),
    TEST_ENTRY(BstrWrapNestTest),
    TEST_ENTRY(CoseSign1TBSTest),
    TEST_ENTRY(EncodeErrorTests),
    //TEST_ENTRY(fail_test),
};


int run_tests(const char *szTestName, outputstring output, void *poutCtx, int *pNumTestsRun)
{
    int nTestsFailed = 0;
    int nTestsRun = 0;
    UsefulBuf_MAKE_STACK_UB(StringStorage, 5);

    test_entry2 *t2;
    const test_entry2 *s_tests2_end = s_tests2 + sizeof(s_tests2)/sizeof(test_entry2);
    
    for(t2 = s_tests2; t2 < s_tests2_end; t2++) {
        if(szTestName && strcmp(szTestName, t2->szTestName)) {
            continue;
        }
        const char * x = (t2->test_fun)();
        nTestsRun++;
        if(output) {
            (*output)(t2->szTestName, poutCtx);
        }
        
        if(x) {
            if(output) {
                (*output)(" FAILED (returned ", poutCtx);
                (*output)(x, poutCtx);
                (*output)(")\n", poutCtx);
            }
            nTestsFailed++;
        } else {
            if(output) {
                (*output)( " PASSED\n", poutCtx);
            }
        }
    }
    
    
    test_entry *t;
    const test_entry *s_tests_end = s_tests + sizeof(s_tests)/sizeof(test_entry);
    
    for(t = s_tests; t < s_tests_end; t++) {
        if(szTestName && strcmp(szTestName, t->szTestName)) {
            continue;
        }
        int x = (t->test_fun)();
        nTestsRun++;
        if(output) {
            (*output)(t->szTestName, poutCtx);
        }
        
        if(x) {
            if(output) {
                (*output)(" FAILED (returned ", poutCtx);
                (*output)(NumToString(x, StringStorage), poutCtx);
                (*output)(")\n", poutCtx);
            }
            nTestsFailed++;
        } else {
            if(output) {
                (*output)( " PASSED\n", poutCtx);
            }
        }
    }
    
    if(pNumTestsRun) {
        *pNumTestsRun = nTestsRun;
    }
    
    if(output) {
        (*output)( "SUMMARY: ", poutCtx);
        (*output)( NumToString(nTestsRun, StringStorage), poutCtx);
        (*output)( " tests run; ", poutCtx);
        (*output)( NumToString(nTestsFailed, StringStorage), poutCtx);
        (*output)( " tests failed\n", poutCtx);
    }
    
    return nTestsFailed;
}
