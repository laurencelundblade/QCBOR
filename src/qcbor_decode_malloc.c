//
//  qcbor_decode_malloc.c
//  QCBOR
//
//  Created by Laurence Lundblade on 10/1/18.
//  Copyright © 2018 Laurence Lundblade. All rights reserved.
//

#include "qcbor.h"
#include <stdlib.h> // for realloc and free

static UsefulBuf MemMallocAlloc(void *ctx, void *pOldMem, size_t uNewSize)
{
    void *pNewMem = realloc(pOldMem, uNewSize);
    return (UsefulBuf){pNewMem, uNewSize};
}

static void MemMallocFree(void *ctx, void *old)
{
    free(old);
}

static void MemMallocDestructor(void *ctx)
{
    free(ctx);
}


QCBORStringAllocator *QCBORDecode_MakeMallocStringAllocator()
{
    QCBORStringAllocator *pAllocaterContext = malloc(sizeof(QCBORStringAllocator));
    if(pAllocaterContext) {
        pAllocaterContext->fAllocate   = MemMallocAlloc;
        pAllocaterContext->fFree       = MemMallocFree;
        pAllocaterContext->fDestructor = MemMallocDestructor;
    }
    
    return pAllocaterContext;
}


/*
void QCBORDecodeMalloc_Init(QCBORDecodeContext *me, UsefulBufC EncodedCBOR, int8_t nDecodeMode)
{
    QCBORDecode_Init(me, EncodedCBOR, nDecodeMode);
    
    QCBORStringAllocator *pAllocaterContext = malloc(sizeof(QCBORStringAllocator));
    
    pAllocaterContext->fAllocate = MemMalloc;
    pAllocaterContext->fFree = MemFree;
    
    QCBORDecode_SetUpAllocator(me, pAllocaterContext);
}


int QCBORDecodeMalloc_Finish(QCBORDecodeContext *me)
{
    const QCBORStringAllocator *pAllocator = QCBORDecode_GetAllocator(me);
    
    free((void *)pAllocator); // TODO: better way to cast away const here
    return QCBORDecode_Finish(me);
} */



