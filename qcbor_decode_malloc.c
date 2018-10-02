//
//  qcbor_decode_malloc.c
//  QCBOR
//
//  Created by Laurence Lundblade on 10/1/18.
//  Copyright © 2018 Laurence Lundblade. All rights reserved.
//

#include "qcbor.h"
#include <stdlib.h>


static void *MemMalloc(void *ctx, void *old, size_t y)
{
    return realloc(old, y);    
}

void QCBORDecodeMalloc_Init(QCBORDecodeContext *me, UsefulBufC EncodedCBOR, int8_t nDecodeMode)
{
    QCBORDecode_Init(me, EncodedCBOR, nDecodeMode);
    
    QCBORStringAllocator *pAllocator = malloc(sizeof(QCBORStringAllocator));
    
    pAllocator->AllocatorFunction = MemMalloc;
    
    QCBOR_Decode_SetUpAllocator(me, pAllocator);
}


int QCBORDecodeMalloc_Finish(QCBORDecodeContext *me)
{
    QCBORStringAllocator *pAllocator = QCBORDecode_GetAllocator(me);
    
    free(pAllocator);
    return QCBORDecode_Finish(me);
}




struct MemPoolType {
    size_t uSize;
    size_t uPos;
};

static void *MemPoolAlloc(void *ctx, void *old, size_t y)
{
    struct MemPoolType *p = (struct MemPoolType *)ctx;
    if(old) {
        // trying a realloc
        return NULL;
    } else {
        // New chunk
        if(p->uPos + y > p->uSize) {
            return NULL; // won't fit
        }
        void *pReturn =  ctx + sizeof( struct MemPoolType ) + p->uPos;
        p->uPos += y;
        return pReturn;
    }

}


int QCBORDecodeMemPool_Init(QCBORDecodeContext *me, UsefulBufC EncodedCBOR, int8_t nDecodeMode, UsefulBuf MemPool)
{
    QCBORDecode_Init(me, EncodedCBOR, nDecodeMode);
    
    if(MemPool.len < 20) {
        return -1;
    }
    
    QCBORStringAllocator *pAllocator = MemPool.ptr;
    pAllocator->AllocatorFunction = MemPoolAlloc;
    
    struct MemPoolType *p = MemPool.ptr + sizeof(QCBORStringAllocator);
    p->uSize = MemPool.len - sizeof(QCBORStringAllocator);
    p->uPos = 0;

    pAllocator->pAllocaterContext = p;\

    QCBOR_Decode_SetUpAllocator(me, pAllocator);
    
    return 0;
}
