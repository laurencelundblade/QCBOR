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
//  half_precision_test.c
//  QCBOR
//
//  Created by Laurence Lundblade on 9/19/18.
//  Copyright © 2018 Laurence Lundblade. All rights reserved.
//

#include "half_precision_test.h"
#include "qcbor.h"

#include <math.h> // For INFINITY and NaN

static const uint8_t ExpectedHalf[] = {
    0xAD,
        0x64,
            0x7A, 0x65, 0x72, 0x6F,
        0xF9, 0x00, 0x00,   // 0.000
        0x6A,
            0x69, 0x6E, 0x66, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x74, 0x79,
        0xF9, 0x7C, 0x00,   // Infinity
        0x73,
            0x6E, 0x65, 0x67, 0x61, 0x74, 0x69, 0x76, 0x65, 0x20, 0x69, 0x6E, 0x66, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x74, 0x79,
        0xF9, 0xFC, 0x00,   // -Inifinity
        0x63,
            0x4E, 0x61, 0x4E,
        0xF9, 0x7E, 0x00,   // NaN
        0x63,
            0x6F, 0x6E, 0x65,
        0xF9, 0x3C, 0x00,   // 1.0
        0x69,
            0x6F, 0x6E, 0x65, 0x20, 0x74, 0x68, 0x69, 0x72, 0x64,
        0xF9, 0x35, 0x55,   // 0.333251953125
        0x76,
            0x6C, 0x61, 0x72, 0x67, 0x65, 0x73, 0x74, 0x20, 0x68, 0x61, 0x6C, 0x66, 0x2D, 0x70, 0x72, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6F, 0x6E,
        0xF9, 0x7B, 0xFF,   // 65504.0
        0x78, 0x18, 0x74, 0x6F, 0x6F, 0x2D, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x20, 0x68, 0x61, 0x6C, 0x66, 0x2D, 0x70, 0x72, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6F, 0x6E,
        0xF9, 0x7C, 0x00,   // Infinity
        0x72,
            0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20, 0x73, 0x75, 0x62, 0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C,
        0xF9, 0x00, 0x01,   // 0.000000059604
        0x6F,
            0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20, 0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C,
        0xF9, 0x03, 0xFF,   // 0.0000609755516
        0x71,
            0x62, 0x69, 0x67, 0x67, 0x65, 0x73, 0x74, 0x20, 0x73, 0x75, 0x62, 0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C,
        0xF9, 0x04, 0x00,   // 0.000061988
        0x70,
            0x73, 0x75, 0x62, 0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65,
        0xF9, 0x00, 0x00,
        0x03,
        0xF9, 0xC0, 0x00    // -2.0
};



int half_precision_encode_basic()
{
    UsefulBuf_MakeStackUB(EncodedHalfsMem, 220);

    QCBOREncodeContext EC;
    QCBOREncode_Init(&EC, EncodedHalfsMem);
    // These are mostly from https://en.wikipedia.org/wiki/Half-precision_floating-point_format
    QCBOREncode_OpenMap(&EC);
    QCBOREncode_AddFloatAsHalfToMap(&EC, "zero", 0.00F);
    QCBOREncode_AddFloatAsHalfToMap(&EC, "infinitity", INFINITY);
    QCBOREncode_AddFloatAsHalfToMap(&EC, "negative infinitity", -INFINITY);
    QCBOREncode_AddFloatAsHalfToMap(&EC, "NaN", NAN);
    QCBOREncode_AddFloatAsHalfToMap(&EC, "one", 1.0F);
    QCBOREncode_AddFloatAsHalfToMap(&EC, "one third", 0.333251953125F);
    QCBOREncode_AddFloatAsHalfToMap(&EC, "largest half-precision",65504.0F);
    // Float 65536.0F is 0x47800000 in hex. It has an exponent of 16, which is larger than 15, the largest half-precision exponent
    QCBOREncode_AddFloatAsHalfToMap(&EC, "too-large half-precision", 65536.0F);
    // Should convert to smallest possible half precision which is encodded as 0x00 0x01 or 5.960464477539063e-8
    QCBOREncode_AddFloatAsHalfToMap(&EC, "smallest subnormal", 0.0000000596046448);
    QCBOREncode_AddFloatAsHalfToMap(&EC, "smallest normal",    0.0000610351526F); // in hex single is 0x387fffff, exponent -15, significand 7fffff
    QCBOREncode_AddFloatAsHalfToMap(&EC, "biggest subnormal",  0.0000610351563F); // in hex single is 0x38800000, exponent -14, significand 0
    QCBOREncode_AddFloatAsHalfToMap(&EC, "subnormal single", 4e-40F); 
    QCBOREncode_AddFloatAsHalfToMapN(&EC, 3, -2.0F);
    QCBOREncode_CloseMap(&EC);
    
    EncodedCBOR EncodedHalfs;
    
    int nReturn = QCBOREncode_Finish2(&EC, &EncodedHalfs);
    
    if(nReturn) {
        return -1;
    }
    
    if(UsefulBuf_Compare(EncodedHalfs.Bytes, UsefulBuf_FromByteArrayLiteral(ExpectedHalf))) {
        return -3;
    }
    
    return 0;
}


int half_precision_decode_basic()
{
    UsefulBufC HalfPrecision = UsefulBuf_FromByteArrayLiteral(ExpectedHalf);
    
    QCBORDecodeContext DC;
    QCBORDecode_Init(&DC, HalfPrecision, 0);
    
    QCBORItem Item;

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_MAP) {
        return -1;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 0.0F) {
        return -1;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != INFINITY) {
        return -1;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != -INFINITY) {
        return -1;
    }

    QCBORDecode_GetNext(&DC, &Item); // TODO, is this really converting right? It is carrying payload, but this confuses things.
    if(Item.uDataType != QCBOR_TYPE_FLOAT || !isnan(Item.val.fnum)) {
        return -1;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 1.0F) {
        return -1;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 0.333251953125F) {
        return -1;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 65504.0F) {
        return -1;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != INFINITY) {
        return -1;
    }
    
    QCBORDecode_GetNext(&DC, &Item); // TODO: check this
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 0.0000000596046448F) {
        return -1;
    }

    QCBORDecode_GetNext(&DC, &Item); // TODO: check this
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 0.0000609755516F) {
        return -1;
    }

    QCBORDecode_GetNext(&DC, &Item); // TODO check this
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 0.0000610351563F) {
        return -1;
    }
    
    QCBORDecode_GetNext(&DC, &Item); 
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 0) {
        return -1;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != -2.0F) {
        return -1;
    }
    
    if(QCBORDecode_Finish(&DC)) {
        return -1;
    }
    
    return 0;
}
