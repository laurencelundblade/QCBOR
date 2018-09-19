/*
  basic_test.c -- basic tests for qcbor encoder / decoder
 
  This is governed by the MIT license.
 
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
 */

#include "basic_test.h"
#include "qcbor.h"


/*
 Some very minimal tests until the full test suite is open sourced and available.
 Return codes here don't mean much (yet).
 */
int basic_test_one()
{
    // Very simple CBOR, a map with one boolean that is true in it
    UsefulBuf_MakeStackUB(MemoryForEncoded, 100);
    QCBOREncodeContext EC;
    
    QCBOREncode_Init(&EC, MemoryForEncoded);
    
    QCBOREncode_OpenMap(&EC);
    QCBOREncode_AddBoolToMapN(&EC, 66, true);
    QCBOREncode_CloseMap(&EC);
    
    UsefulBufC Encoded;
    if(QCBOREncode_Finish2(&EC, &Encoded)) {
        return -3;
    }
    
    
    // Decode it and see that is right
    QCBORDecodeContext DC;
    QCBORItem Item;
    QCBORDecode_Init(&DC, Encoded, QCBOR_DECODE_MODE_NORMAL);
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_MAP) {
        return -1;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_TRUE) {
        return -1;
    }
    
    if(QCBORDecode_Finish(&DC)) {
        return -2;
    }
    
    
    // Make another encoded message with the CBOR from the previous put into this one
    UsefulBuf_MakeStackUB(MemoryForEncoded2, 100);
    QCBOREncode_Init(&EC, MemoryForEncoded2);
    QCBOREncode_OpenArray(&EC);
    QCBOREncode_AddUInt64(&EC, 451);
    QCBOREncode_AddEncoded(&EC, Encoded);
    QCBOREncode_OpenMap(&EC);
    QCBOREncode_AddEncodedToMapN(&EC, -70000, Encoded);
    QCBOREncode_CloseMap(&EC);
    QCBOREncode_CloseArray(&EC);
    
    UsefulBufC Encoded2;
    if(QCBOREncode_Finish2(&EC, &Encoded2)) {
        return -3;
    }
    
    
    // Decode it and see if it is OK
    QCBORDecode_Init(&DC, Encoded2, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_ARRAY || Item.val.uCount != 3) {
        return -1;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_INT64 || Item.val.uint64 != 451) {
        return -1;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 1) {
        return -1;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_TRUE) {
        return -1;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 1) {
        return -1;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 1 || Item.uLabelType != QCBOR_TYPE_INT64 || Item.label.int64 != -70000) {
        return -1;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_TRUE || Item.uLabelType != QCBOR_TYPE_INT64 || Item.label.int64 != 66) {
        return -1;
    }
    
    if(QCBORDecode_Finish(&DC)) {
        return -2;
    }
    
    
    
    
    
    return 0;
}
