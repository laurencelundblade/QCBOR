//
//  mempool_test.c
//  QCBOR
//
//  Created by Laurence Lundblade on 10/8/18.
//  Copyright © 2018 Laurence Lundblade. All rights reserved.
//

#include "mempool_test.h"
#include "qcbor.h"

int mempool_test(void)
{
    QCBORDecodeContext DC;
    
    const uint8_t pMinimalCBOR[] = {0xa0}; // One empty map
    
    QCBORDecode_Init(&DC, UsefulBuf_FromByteArrayLiteral(pMinimalCBOR),0);
    
    UsefulBuf_MakeStackUB(Pool, 100);
    
    QCBORDecode_SetMemPool(&DC, Pool, 0);
    
    // Cheat a little to get to the string allocator object
    // so we can call it directly to test it
    QCBORStringAllocator *pAlloc = (QCBORStringAllocator *)DC.pStringAllocator;
    
    // Ask for too much in one go
    // 90 < 100, but there is some overhead taken out of the 100
    UsefulBuf Allocated = (*pAlloc->fAllocate)(pAlloc->pAllocaterContext, NULL, 90);
    if(!UsefulBuf_IsNULL(Allocated)) {
        return -1;
    }
    
    
    
    QCBORDecode_SetMemPool(&DC, Pool, 0);
    
    // Cheat a little to get to the string allocator object
    // so we can call it directly to test it
    pAlloc = (QCBORStringAllocator *)DC.pStringAllocator;

    Allocated = (*pAlloc->fAllocate)(pAlloc->pAllocaterContext, NULL, 30);
    if(UsefulBuf_IsNULL(Allocated)) { // expected to succeed
        return -1;
    }
    UsefulBuf Allocated2 = (*pAlloc->fAllocate)(pAlloc->pAllocaterContext, NULL, 30);
    if(!UsefulBuf_IsNULL(Allocated2)) { // expected to fail
        return -1;
    }
    (*pAlloc->fFree)(pAlloc->pAllocaterContext, Allocated.ptr);
    Allocated = (*pAlloc->fAllocate)(pAlloc->pAllocaterContext, NULL, 30);
    if(UsefulBuf_IsNULL(Allocated)) { // succeed because of the free
        return -1;
    }
    
    
    QCBORDecode_SetMemPool(&DC, Pool, 0);
    
    // Cheat a little to get to the string allocator object
    // so we can call it directly to test it
    pAlloc = (QCBORStringAllocator *)DC.pStringAllocator;
    Allocated = (*pAlloc->fAllocate)(pAlloc->pAllocaterContext, NULL, 20);
    if(UsefulBuf_IsNULL(Allocated)) { // expected to succeed
        return -1;
    }
    Allocated2 = (*pAlloc->fAllocate)(pAlloc->pAllocaterContext, Allocated.ptr, 25);
    if(UsefulBuf_IsNULL(Allocated2)) { // expected to fail
        return -1;
    }
    if(Allocated2.ptr != Allocated.ptr || Allocated2.len != 25) {
        return -1;
    }
    
    
    
    
    return 0;
}
