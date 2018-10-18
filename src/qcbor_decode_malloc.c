/*==============================================================================
 float_tests.c -- tests for float and conversion to/from half-precision
 
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

#include "qcbor.h"
#include <stdlib.h> // for realloc and free

static UsefulBuf MemMallocAlloc(void *ctx, void *pOldMem, size_t uNewSize)
{
    (void)ctx;
    void *pNewMem = realloc(pOldMem, uNewSize);
    return (UsefulBuf){pNewMem, uNewSize};
}

static void MemMallocFree(void *ctx, void *old)
{
    (void)ctx;
    free(old);
}

static void MemMallocDestructor(void *ctx)
{
    free(ctx);
}
/*
 Public function. See qcbor.h
 */
QCBORStringAllocator *QCBORDecode_MakeMallocStringAllocator()
{
    QCBORStringAllocator *pAllocaterContext = malloc(sizeof(QCBORStringAllocator));
    if(pAllocaterContext) {
        pAllocaterContext->fAllocate   = MemMallocAlloc;
        pAllocaterContext->fFree       = MemMallocFree;
        pAllocaterContext->fDestructor = MemMallocDestructor;
        pAllocaterContext->pAllocaterContext = pAllocaterContext; // So that destructor can work.
    }
    
    return pAllocaterContext;
}




