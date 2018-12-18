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
//  Created by Laurence Lundblade on 10/26/18.

#include <stdio.h>
#include "qcbor.h"



/*
 A small user of CBOR encoding and decoding
 that is good as an example and for
 checking code size with all the
 inlining and dead stripping on.

 */

int main(int argc, const char * argv[])
{
    (void)argc; // Suppress unused warning
    (void)argv; // Suppress unused warning

    uint8_t pBuf[300];
    // Very simple CBOR, a map with one boolean that is true in it
    QCBOREncodeContext EC;

    QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(pBuf));

    QCBOREncode_OpenMap(&EC);
    QCBOREncode_AddBoolToMapN(&EC, 66, true);
    QCBOREncode_CloseMap(&EC);

    UsefulBufC Encoded;
    if(QCBOREncode_Finish(&EC, &Encoded)) {
        return -1;
    }


    // Decode it and see that is right
    QCBORDecodeContext DC;
    QCBORItem Item;
    QCBORDecode_Init(&DC, Encoded, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_MAP) {
        return -2;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_TRUE) {
        return -3;
    }

    if(QCBORDecode_Finish(&DC)) {
        return -4;
    }


    // Make another encoded message with the CBOR from the previous put into this one
    UsefulBuf_MAKE_STACK_UB(MemoryForEncoded2, 20);
    QCBOREncode_Init(&EC, MemoryForEncoded2);
    QCBOREncode_OpenArray(&EC);
    QCBOREncode_AddUInt64(&EC, 451);
    QCBOREncode_AddEncoded(&EC, Encoded);
    QCBOREncode_OpenMap(&EC);
    QCBOREncode_AddEncodedToMapN(&EC, -70000, Encoded);
    QCBOREncode_CloseMap(&EC);
    QCBOREncode_CloseArray(&EC);

    UsefulBufC Encoded2;
    if(QCBOREncode_Finish(&EC, &Encoded2)) {
        return -5;
    }
    /*
     [                // 0    1:3
     451,          // 1    1:2
     {             // 1    1:2   2:1
     66: true    // 2    1:1
     },
     {             // 1    1:1   2:1
     -70000: {   // 2    1:1   2:1   3:1
     66: true  // 3    XXXXXX
     }
     }
     ]



     83                # array(3)
     19 01C3        # unsigned(451)
     A1             # map(1)
     18 42       # unsigned(66)
     F5          # primitive(21)
     A1             # map(1)
     3A 0001116F # negative(69999)
     A1          # map(1)
     18 42    # unsigned(66)
     F5       # primitive(21)
     */

    // Decode it and see if it is OK
    QCBORDecode_Init(&DC, Encoded2, QCBOR_DECODE_MODE_NORMAL);

    // 0    1:3
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_ARRAY || Item.val.uCount != 3) {
        return -6;
    }

    // 1    1:2
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_INT64 || Item.val.uint64 != 451) {
        return -7;
    }

    // 1    1:2   2:1
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 1) {
        return -8;
    }

    // 2    1:1
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_TRUE) {
        return -9;
    }

    // 1    1:1   2:1
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 1) {
        return -10;
    }

    // 2    1:1   2:1   3:1
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 1 || Item.uLabelType != QCBOR_TYPE_INT64 || Item.label.int64 != -70000) {
        return -11;
    }

    // 3    XXXXXX
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_TRUE || Item.uLabelType != QCBOR_TYPE_INT64 || Item.label.int64 != 66) {
        return -12;
    }

    if(QCBORDecode_Finish(&DC)) {
        return -13;
    }

    return 0;
}
