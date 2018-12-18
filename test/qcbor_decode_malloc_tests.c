/*==============================================================================

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

#include "qcbor_decode_malloc_tests.h"
#include "qcbor.h"
#include <stdlib.h>


/*
 {"first integer": 42,
 "an array of two strings": ["string1", "string2"],
 "map in a map": {
 "bytes 1": h'78787878',
 "bytes 2": h'79797979',
 "another int": 98, "text 2":
 "lies, damn lies and statistics"}
 }
 */

static uint8_t pValidMapEncoded[] = {
    0xa3, 0x6d, 0x66, 0x69, 0x72, 0x73, 0x74, 0x20, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x65, 0x72, 0x18, 0x2a,
    0x77, 0x61, 0x6e, 0x20, 0x61, 0x72, 0x72, 0x61, 0x79, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x77, 0x6f, 0x20,
    0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x73, 0x82, 0x67, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x31, 0x67,
    0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x32, 0x6c, 0x6d, 0x61, 0x70, 0x20, 0x69, 0x6e, 0x20, 0x61, 0x20,
    0x6d, 0x61, 0x70, 0xa4, 0x67, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20, 0x31, 0x44, 0x78, 0x78, 0x78, 0x78,
    0x67, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20, 0x32, 0x44, 0x79, 0x79, 0x79, 0x79, 0x6b, 0x61, 0x6e, 0x6f,
    0x74, 0x68, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x74, 0x18, 0x62, 0x66, 0x74, 0x65, 0x78, 0x74, 0x20, 0x32,
    0x78, 0x1e, 0x6c, 0x69, 0x65, 0x73, 0x2c, 0x20, 0x64, 0x61, 0x6d, 0x6e, 0x20, 0x6c, 0x69, 0x65, 0x73,
    0x20, 0x61, 0x6e, 0x64, 0x20, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x73 } ;


#define UNCONST_POINTER(ptr)    ((void *)(ptr))


int MallocAllStringsTest()
{
    QCBORDecodeContext DC;

    // Next parse, save pointers to a few strings, destroy original and see all is OK.
    UsefulBuf_MAKE_STACK_UB(CopyOfStorage, 160);
    const UsefulBufC CopyOf = UsefulBuf_Copy(CopyOfStorage, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pValidMapEncoded));

    QCBORDecode_Init(&DC, CopyOf, QCBOR_DECODE_MODE_NORMAL);
    QCBORStringAllocator *pAlloc = QCBORDecode_MakeMallocStringAllocator();
    QCBORDecode_SetUpAllocator(&DC, pAlloc, true);


    int nCBORError;
    QCBORItem Item1, Item2, Item3, Item4;
    if((nCBORError = QCBORDecode_GetNext(&DC, &Item1)))
        return nCBORError;
    if(Item1.uDataType != QCBOR_TYPE_MAP ||
       Item1.val.uCount != 3)
        return -1;
    if((nCBORError = QCBORDecode_GetNext(&DC, &Item1)))
        return nCBORError;
    if((nCBORError = QCBORDecode_GetNext(&DC, &Item2)))
        return nCBORError;
    if((nCBORError = QCBORDecode_GetNext(&DC, &Item3)))
        return nCBORError;
    if((nCBORError = QCBORDecode_GetNext(&DC, &Item4)))
        return nCBORError;

    UsefulBuf_Set(CopyOfStorage, '_');

    if(Item1.uLabelType != QCBOR_TYPE_TEXT_STRING ||
       Item1.label.string.len != 13 ||
       Item1.uDataType != QCBOR_TYPE_INT64 ||
       Item1.val.int64 != 42 ||
       memcmp(Item1.label.string.ptr, "first integer", 13))
        return -1;

    if(Item2.uLabelType != QCBOR_TYPE_TEXT_STRING ||
       Item2.label.string.len != 23 ||
       memcmp(Item2.label.string.ptr, "an array of two strings", 23) ||
       Item2.uDataType != QCBOR_TYPE_ARRAY ||
       Item2.val.uCount != 2)
        return -1;

    if(Item3.uDataType != QCBOR_TYPE_TEXT_STRING ||
       Item3.val.string.len != 7 ||
       memcmp(Item3.val.string.ptr, "string1", 7))
        return -1;

    if(Item4.uDataType != QCBOR_TYPE_TEXT_STRING ||
       Item4.val.string.len != 7 ||
       memcmp(Item4.val.string.ptr, "string2", 7))
        return -1;

    (void)QCBORDecode_Finish(&DC);

    free(UNCONST_POINTER(Item1.label.string.ptr));
    free(UNCONST_POINTER(Item2.label.string.ptr));
    free(UNCONST_POINTER(Item3.val.string.ptr));
    free(UNCONST_POINTER(Item4.val.string.ptr));

    return 0;
}
