/*==============================================================================

 Copyright (c) 2018, Laurence Lundblade.
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
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
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. ==============================================================================*/

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




