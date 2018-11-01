/*==============================================================================
 float_tests.c -- tests for float and conversion to/from half-precision

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
//  Created by Laurence Lundblade on 9/19/18.


#include "float_tests.h"
#include "qcbor.h"
#include "half_to_double_from_rfc7049.h"
#include <math.h> // For INFINITY and NAN and isnan()


/*
 Output from http://cbor.me
 [0.0,
 1.0,
 1.100000023841858,
 1.5,
 65504.0,
 100000.0,
 3.4028234663852886e+38,
 Infinity,
 5.960464477539063e-8,
 0.00006103515625,
 -4.0,
 -4.099999904632568,
 NaN,
 Infinity,
 -Infinity,
 0.0,
 1.0,
 1.1,
 1.5,
 65504.0,
 100000.0,
 3.4028234663852886e+38,
 1.0e+300,
 5.960464477539063e-8,
 0.00006103515625,
 -4.0,
 -4.1,
 NaN,
 Infinity,
 -Infinity]
 */

static uint8_t spExpectedEncodedFloat[] = {
    0x98, 0x1e, 0xfa, 0x00, 0x00, 0x00, 0x00, 0xfa,
    0x3f, 0x80, 0x00, 0x00, 0xfa, 0x3f, 0x8c, 0xcc,
    0xcd, 0xfa, 0x3f, 0xc0, 0x00, 0x00, 0xfa, 0x47,
    0x7f, 0xe0, 0x00, 0xfa, 0x47, 0xc3, 0x50, 0x00,
    0xfa, 0x7f, 0x7f, 0xff, 0xff, 0xfa, 0x7f, 0x80,
    0x00, 0x00, 0xfa, 0x33, 0x80, 0x00, 0x00, 0xfa,
    0x38, 0x80, 0x00, 0x00, 0xfa, 0xc0, 0x80, 0x00,
    0x00, 0xfa, 0xc0, 0x83, 0x33, 0x33, 0xfa, 0x7f,
    0xc0, 0x00, 0x00, 0xfa, 0x7f, 0x80, 0x00, 0x00,
    0xfa, 0xff, 0x80, 0x00, 0x00, 0xfb, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, 0x3f,
    0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb,
    0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a,
    0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xfb, 0x40, 0xef, 0xfc, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xfb, 0x40, 0xf8, 0x6a, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xfb, 0x47, 0xef, 0xff, 0xff,
    0xe0, 0x00, 0x00, 0x00, 0xfb, 0x7e, 0x37, 0xe4,
    0x3c, 0x88, 0x00, 0x75, 0x9c, 0xfb, 0x3e, 0x70,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, 0x3f,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb,
    0xc0, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xfb, 0xc0, 0x10, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0xfb, 0x7f, 0xf8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xfb, 0x7f, 0xf0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xfb, 0xff, 0xf0, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};


int FloatValuesTest1()
{
    QCBOREncodeContext ECtx;
    int nReturn = 0;
    
    UsefulBuf_MAKE_STACK_UB(EncodedStorage, 220);
    
    QCBOREncode_Init(&ECtx, EncodedStorage);
    QCBOREncode_OpenArray(&ECtx);
    
    // These are all samples published
    // in RFC 7049.
    QCBOREncode_AddFloat(&ECtx, 0.0);
    QCBOREncode_AddFloat(&ECtx, 1.0);
    QCBOREncode_AddFloat(&ECtx, 1.1); // appx
    QCBOREncode_AddFloat(&ECtx, 1.5);
    QCBOREncode_AddFloat(&ECtx, 65504.0);
    QCBOREncode_AddFloat(&ECtx, 100000.0);
    QCBOREncode_AddFloat(&ECtx, 3.4028234663852886e+38);
    QCBOREncode_AddFloat(&ECtx, 1.0e+300); // Infinity?
    QCBOREncode_AddFloat(&ECtx, 5.960464477539063e-8);
    QCBOREncode_AddFloat(&ECtx, 0.00006103515625);
    QCBOREncode_AddFloat(&ECtx, -4.0);
    QCBOREncode_AddFloat(&ECtx, -4.1); // appx
    
    QCBOREncode_AddFloat(&ECtx, NAN);
    QCBOREncode_AddFloat(&ECtx, INFINITY);
    QCBOREncode_AddFloat(&ECtx, -INFINITY);
    
    
    QCBOREncode_AddDouble(&ECtx, 0.0);
    QCBOREncode_AddDouble(&ECtx, 1.0);
    QCBOREncode_AddDouble(&ECtx, 1.1); // appx
    QCBOREncode_AddDouble(&ECtx, 1.5);
    QCBOREncode_AddDouble(&ECtx, 65504.0);
    QCBOREncode_AddDouble(&ECtx, 100000.0);
    QCBOREncode_AddDouble(&ECtx, 3.4028234663852886e+38);
    QCBOREncode_AddDouble(&ECtx, 1.0e+300); // Infinity?
    QCBOREncode_AddDouble(&ECtx, 5.960464477539063e-8);
    QCBOREncode_AddDouble(&ECtx, 0.00006103515625);
    QCBOREncode_AddDouble(&ECtx, -4.0);
    QCBOREncode_AddDouble(&ECtx, -4.1); // appx
    
    QCBOREncode_AddDouble(&ECtx, NAN);
    QCBOREncode_AddDouble(&ECtx, INFINITY);
    QCBOREncode_AddDouble(&ECtx, -INFINITY);
    
    QCBOREncode_CloseArray(&ECtx);
    
    UsefulBufC Encoded;
    if(QCBOREncode_Finish2(&ECtx, &Encoded)) {
        nReturn = -1;
    }
    
    if(UsefulBuf_Compare(Encoded, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedEncodedFloat))) {
        nReturn = -2;
    }
    
    //printencoded(pEncoded, nEncodedLen);
    
    return(nReturn);
}




static const uint8_t spExpectedHalf[] = {
    0xB1,
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
        0xF9, 0xC0, 0x00,    // -2
        0x04,
        0xF9, 0x7E, 0x00,    // qNaN
        0x05,
        0xF9, 0x7C, 0x01,    // sNaN
        0x06,
        0xF9, 0x7E, 0x0F,    // qNaN with payload 0x0f
        0x07,
        0xF9, 0x7C, 0x0F,    // sNaN with payload 0x0f
    
};



int HalfPrecisionEncodeBasicTests()
{
    UsefulBuf_MAKE_STACK_UB(EncodedHalfsMem, 250);

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
    QCBOREncode_AddFloatAsHalfToMap(&EC, "smallest subnormal", 0.0000000596046448F);
    QCBOREncode_AddFloatAsHalfToMap(&EC, "smallest normal",    0.0000610351526F); // in hex single is 0x387fffff, exponent -15, significand 7fffff
    QCBOREncode_AddFloatAsHalfToMap(&EC, "biggest subnormal",  0.0000610351563F); // in hex single is 0x38800000, exponent -14, significand 0
    QCBOREncode_AddFloatAsHalfToMap(&EC, "subnormal single", 4e-40F); 
    QCBOREncode_AddFloatAsHalfToMapN(&EC, 3, -2.0F);
    QCBOREncode_AddFloatAsHalfToMapN(&EC, 4, UsefulBufUtil_CopyUint32ToFloat(0x7fc00000L)); // qNaN
    QCBOREncode_AddFloatAsHalfToMapN(&EC, 5, UsefulBufUtil_CopyUint32ToFloat(0x7f800001L)); // sNaN
    QCBOREncode_AddFloatAsHalfToMapN(&EC, 6, UsefulBufUtil_CopyUint32ToFloat(0x7fc0f00fL)); // qNaN with payload
    QCBOREncode_AddFloatAsHalfToMapN(&EC, 7, UsefulBufUtil_CopyUint32ToFloat(0x7f80f00fL)); // sNaN with payload
    QCBOREncode_CloseMap(&EC);
    
    UsefulBufC EncodedHalfs;
    int nReturn = QCBOREncode_Finish2(&EC, &EncodedHalfs);
    if(nReturn) {
        return -1;
    }
    
    if(UsefulBuf_Compare(EncodedHalfs, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedHalf))) {
        return -3;
    }
    
    return 0;
}


int HalfPrecisionDecodeBasicTests()
{
    UsefulBufC HalfPrecision = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedHalf);
    
    QCBORDecodeContext DC;
    QCBORDecode_Init(&DC, HalfPrecision, 0);
    
    QCBORItem Item;

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_MAP) {
        return -1;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 0.0F) {
        return -2;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != INFINITY) {
        return -3;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != -INFINITY) {
        return -4;
    }

    QCBORDecode_GetNext(&DC, &Item); // TODO, is this really converting right? It is carrying payload, but this confuses things.
    if(Item.uDataType != QCBOR_TYPE_FLOAT || !isnan(Item.val.fnum)) {
        return -5;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 1.0F) {
        return -6;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 0.333251953125F) {
        return -7;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 65504.0F) {
        return -8;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != INFINITY) {
        return -9;
    }
    
    QCBORDecode_GetNext(&DC, &Item); // TODO: check this
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 0.0000000596046448F) {
        return -10;
    }

    QCBORDecode_GetNext(&DC, &Item); // TODO: check this
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 0.0000609755516F) {
        return -11;
    }

    QCBORDecode_GetNext(&DC, &Item); // TODO check this
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 0.0000610351563F) {
        return -12;
    }
    
    QCBORDecode_GetNext(&DC, &Item); 
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != 0) {
        return -13;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || Item.val.fnum != -2.0F) {
        return -14;
    }

    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || UsefulBufUtil_CopyFloatToUint32(Item.val.fnum) != 0x7fc00000L) {
        return -15;
    }
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || UsefulBufUtil_CopyFloatToUint32(Item.val.fnum) != 0x7f800001) {
        return -16;
    }
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || UsefulBufUtil_CopyFloatToUint32(Item.val.fnum) != 0x7fc0000f) {
        return -17;
    }
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_FLOAT || UsefulBufUtil_CopyFloatToUint32(Item.val.fnum) != 0x7f80000f) {
        return -18;
    }
    
    if(QCBORDecode_Finish(&DC)) {
        return -19;
    }
    
    return 0;
}


int HalfPrecisionTransitiveTest()
{
    for(uint32_t uHalfP = 0; uHalfP < 0xffff; uHalfP += 1) {
        // Contruct the CBOR for the half-precision float by hand
        UsefulBuf_MAKE_STACK_UB(EncodedCBORMem, 3);
        UsefulOutBuf UOB;
        UsefulOutBuf_Init(&UOB, EncodedCBORMem);
        
        const uint8_t uHalfPrecInitialByte = HALF_PREC_FLOAT + (CBOR_MAJOR_TYPE_SIMPLE << 5); // 0xf9
        UsefulOutBuf_AppendByte(&UOB, uHalfPrecInitialByte); // The initial byte for a half-precision float
        UsefulOutBuf_AppendUint16(&UOB, (uint16_t)uHalfP);
        
        
        // Now parse the hand-constructed CBOR. This will invoke the conversion to a float
        QCBORDecodeContext DC;
        QCBORDecode_Init(&DC, UsefulOutBuf_OutUBuf(&UOB), 0);
        
        QCBORItem Item;
        QCBORDecode_GetNext(&DC, &Item);
        if(Item.uDataType != QCBOR_TYPE_FLOAT) {
            return -1;
        }
        
        //printf("%04x  QCBOR:%15.15f  \n", uHalfP,Item.val.fnum);

        
        // Now generate CBOR with the half-precision value. This will invoke the conversion from float to half
        UsefulBuf_MAKE_STACK_UB(OtherEncodedCBORMem, 5);
        QCBOREncodeContext EC;
        QCBOREncode_Init(&EC, OtherEncodedCBORMem);
        QCBOREncode_AddFloatAsHalf(&EC, Item.val.fnum);
        UsefulBufC EnCBOR;
        QCBOREncode_Finish2(&EC, &EnCBOR); // todo check return code
        
        
        // Finally parse the CBOR by hand to get at half-precision that was actually encoded.
        UsefulInputBuf UIB;
        UsefulInputBuf_Init(&UIB, EnCBOR);
        if(UsefulInputBuf_GetByte(&UIB) != uHalfPrecInitialByte) {
            return -2;
        }
        if(UsefulInputBuf_GetUint16(&UIB) != uHalfP) { // the moment of truth did we get back what we started with?
            return -3;
        }
    }
    
    return 0;
}


int HalfPrecisionAgainstRFCCodeTest()
{
    for(uint32_t uHalfP = 0; uHalfP < 0xffff; uHalfP += 60) {
        unsigned char x[2];
        x[1] = uHalfP & 0xff;
        x[0] = uHalfP >> 8;
        double d = decode_half(x);
        
        // Contruct the CBOR for the half-precision float by hand
        UsefulBuf_MAKE_STACK_UB(__xx, 3);
        UsefulOutBuf UOB;
        UsefulOutBuf_Init(&UOB, __xx);
        
        const uint8_t uHalfPrecInitialByte = HALF_PREC_FLOAT + (CBOR_MAJOR_TYPE_SIMPLE << 5); // 0xf9
        UsefulOutBuf_AppendByte(&UOB, uHalfPrecInitialByte); // The initial byte for a half-precision float
        UsefulOutBuf_AppendUint16(&UOB, (uint16_t)uHalfP);

        // Now parse the hand-constructed CBOR. This will invoke the conversion to a float
        QCBORDecodeContext DC;
        QCBORDecode_Init(&DC, UsefulOutBuf_OutUBuf(&UOB), 0);
        
        QCBORItem Item;
        
        QCBORDecode_GetNext(&DC, &Item);
        if(Item.uDataType != QCBOR_TYPE_FLOAT) {
            return -1;
        }
        
        //printf("%04x  QCBOR:%15.15f  RFC: %15.15f (%8x)\n", uHalfP,Item.val.fnum, d , UsefulBufUtil_CopyFloatToUint32(d));
        
        if(isnan(d)) {
            // The RFC code uses the native instructions which may or may not
            // handle sNaN, qNaN and NaN payloads correctly. This test just
            // makes sure it is a NaN and doesn't worry about the type of NaN
            if(!isnan(Item.val.fnum)) {
                return -3;
            }
        } else {
            if(Item.val.fnum != d) {
                return -2;
            }
        }
    }
    return 0;
}


/*
 {"zero": 0.0,
  "negative zero": -0.0,
  "infinitity": Infinity,
  "negative infinitity": -Infinity,
  "NaN": NaN,
  "one": 1.0,
  "one third": 0.333251953125,
  "largest half-precision": 65504.0,
  "largest half-precision point one": 65504.1,
  "too-large half-precision": 65536.0,
  "smallest subnormal": 5.96046448e-8,
  "smallest normal": 0.00006103515261202119,
  "biggest subnormal": 0.00006103515625,
  "subnormal single": 4.00000646641519e-40,
  3: -2.0,
  "large single exp": 2.5521177519070385e+38,
  "too-large single exp": 5.104235503814077e+38,
  "biggest single with prec": 16777216.0,
  "first single with prec loss": 16777217.0,
  1: "fin"}
 */
static const uint8_t spExpectedSmallest[] = {
    0xB4, 0x64, 0x7A, 0x65, 0x72, 0x6F, 0xF9, 0x00, 0x00, 0x6D,
    0x6E, 0x65, 0x67, 0x61, 0x74, 0x69, 0x76, 0x65, 0x20, 0x7A,
    0x65, 0x72, 0x6F, 0xF9, 0x80, 0x00, 0x6A, 0x69, 0x6E, 0x66,
    0x69, 0x6E, 0x69, 0x74, 0x69, 0x74, 0x79, 0xF9, 0x7C, 0x00,
    0x73, 0x6E, 0x65, 0x67, 0x61, 0x74, 0x69, 0x76, 0x65, 0x20,
    0x69, 0x6E, 0x66, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x74, 0x79,
    0xF9, 0xFC, 0x00, 0x63, 0x4E, 0x61, 0x4E, 0xF9, 0x7E, 0x00,
    0x63, 0x6F, 0x6E, 0x65, 0xF9, 0x3C, 0x00, 0x69, 0x6F, 0x6E,
    0x65, 0x20, 0x74, 0x68, 0x69, 0x72, 0x64, 0xF9, 0x35, 0x55,
    0x76, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x73, 0x74, 0x20, 0x68,
    0x61, 0x6C, 0x66, 0x2D, 0x70, 0x72, 0x65, 0x63, 0x69, 0x73,
    0x69, 0x6F, 0x6E, 0xF9, 0x7B, 0xFF, 0x78, 0x20, 0x6C, 0x61,
    0x72, 0x67, 0x65, 0x73, 0x74, 0x20, 0x68, 0x61, 0x6C, 0x66,
    0x2D, 0x70, 0x72, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6F, 0x6E,
    0x20, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x20, 0x6F, 0x6E, 0x65,
    0xFB, 0x40, 0xEF, 0xFC, 0x03, 0x33, 0x33, 0x33, 0x33, 0x78,
    0x18, 0x74, 0x6F, 0x6F, 0x2D, 0x6C, 0x61, 0x72, 0x67, 0x65,
    0x20, 0x68, 0x61, 0x6C, 0x66, 0x2D, 0x70, 0x72, 0x65, 0x63,
    0x69, 0x73, 0x69, 0x6F, 0x6E, 0xFA, 0x47, 0x80, 0x00, 0x00,
    0x72, 0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20,
    0x73, 0x75, 0x62, 0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C, 0xFB,
    0x3E, 0x70, 0x00, 0x00, 0x00, 0x1C, 0x5F, 0x68, 0x6F, 0x73,
    0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20, 0x6E, 0x6F,
    0x72, 0x6D, 0x61, 0x6C, 0xFA, 0x38, 0x7F, 0xFF, 0xFF, 0x71,
    0x62, 0x69, 0x67, 0x67, 0x65, 0x73, 0x74, 0x20, 0x73, 0x75,
    0x62, 0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C, 0xF9, 0x04, 0x00,
    0x70, 0x73, 0x75, 0x62, 0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C,
    0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0xFB, 0x37, 0xC1,
    0x6C, 0x28, 0x00, 0x00, 0x00, 0x00, 0x03, 0xF9, 0xC0, 0x00,
    0x70, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x20, 0x73, 0x69, 0x6E,
    0x67, 0x6C, 0x65, 0x20, 0x65, 0x78, 0x70, 0xFA, 0x7F, 0x40,
    0x00, 0x00, 0x74, 0x74, 0x6F, 0x6F, 0x2D, 0x6C, 0x61, 0x72,
    0x67, 0x65, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20,
    0x65, 0x78, 0x70, 0xFB, 0x47, 0xF8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x78, 0x18, 0x62, 0x69, 0x67, 0x67, 0x65, 0x73,
    0x74, 0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x77,
    0x69, 0x74, 0x68, 0x20, 0x70, 0x72, 0x65, 0x63, 0xFA, 0x4B,
    0x80, 0x00, 0x00, 0x78, 0x1B, 0x66, 0x69, 0x72, 0x73, 0x74,
    0x20, 0x73, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x77, 0x69,
    0x74, 0x68, 0x20, 0x70, 0x72, 0x65, 0x63, 0x20, 0x6C, 0x6F,
    0x73, 0x73, 0xFB, 0x41, 0x70, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x01, 0x63, 0x66, 0x69, 0x6E
};


int DoubleAsSmallestTest()
{
    UsefulBuf_MAKE_STACK_UB(EncodedHalfsMem, 420);
    
    QCBOREncodeContext EC;
    QCBOREncode_Init(&EC, EncodedHalfsMem);
    // These are mostly from https://en.wikipedia.org/wiki/Half-precision_floating-point_format
    QCBOREncode_OpenMap(&EC);
    // 64                                   # text(4)
    //    7A65726F                          # "zero"
    // F9 0000                              # primitive(0)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "zero", 0.00);

    // 64                                   # text(4)
    //    7A65726F                          # "negative zero"
    // F9 8000                              # primitive(0)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "negative zero", -0.00);
    
    // 6A                                   # text(10)
    //    696E66696E6974697479              # "infinitity"
    // F9 7C00                              # primitive(31744)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "infinitity", INFINITY);
    
    // 73                                   # text(19)
    //    6E6567617469766520696E66696E6974697479 # "negative infinitity"
    // F9 FC00                              # primitive(64512)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "negative infinitity", -INFINITY);
    
    // 63                                   # text(3)
    //    4E614E                            # "NaN"
    // F9 7E00                              # primitive(32256)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "NaN", NAN);
    
    // TODO: test a few NaN variants
    
    // 63                                   # text(3)
    //    6F6E65                            # "one"
    // F9 3C00                              # primitive(15360)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "one", 1.0);
    
    // 69                                   # text(9)
    //    6F6E65207468697264                # "one third"
    // F9 3555                              # primitive(13653)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "one third", 0.333251953125);
    
    // 76                                   # text(22)
    //    6C6172676573742068616C662D707265636973696F6E # "largest half-precision"
    // F9 7BFF                              # primitive(31743)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "largest half-precision",65504.0);

    // 76                                   # text(22)
    //    6C6172676573742068616C662D707265636973696F6E # "largest half-precision"
    // F9 7BFF                              # primitive(31743)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "largest half-precision point one",65504.1);
    
    // Float 65536.0F is 0x47800000 in hex. It has an exponent of 16, which is larger than 15, the largest half-precision exponent
    // 78 18                                # text(24)
    //    746F6F2D6C617267652068616C662D707265636973696F6E # "too-large half-precision"
    // FA 47800000                          # primitive(31743)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "too-large half-precision", 65536.0);
    
    // The smallest possible half-precision subnormal, but digitis are lost converting
    // to half, so this turns into a double
    // 72                                   # text(18)
    //    736D616C6C657374207375626E6F726D616C # "smallest subnormal"
    // FB 3E700000001C5F68                  # primitive(4499096027744984936)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "smallest subnormal", 0.0000000596046448);
    
    // The smallest possible half-precision snormal, but digitis are lost converting
    // to half, so this turns into a single TODO: confirm this is right
    // 6F                                   # text(15)
    //    736D616C6C657374206E6F726D616C    # "smallest normal"
    // FA 387FFFFF                          # primitive(947912703)
    // in hex single is 0x387fffff, exponent -15, significand 7fffff
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "smallest normal",    0.0000610351526F);
    
    // 71                                   # text(17)
    //    62696767657374207375626E6F726D616C # "biggest subnormal"
    // F9 0400                              # primitive(1024)
    // in hex single is 0x38800000, exponent -14, significand 0
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "biggest subnormal",  0.0000610351563F);
    
    // 70                                   # text(16)
    //    7375626E6F726D616C2073696E676C65  # "subnormal single"
    // FB 37C16C2800000000                  # primitive(4017611261645684736)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "subnormal single", 4e-40F);
    
    // 03                                   # unsigned(3)
    // F9 C000                              # primitive(49152)
    QCBOREncode_AddDoubleAsSmallestToMapN(&EC, 3, -2.0);
    
    // 70                                   # text(16)
    //    6C617267652073696E676C6520657870  # "large single exp"
    // FA 7F400000                          # primitive(2134900736)
    // (0x01LL << (DOUBLE_NUM_SIGNIFICAND_BITS-1)) | ((127LL + DOUBLE_EXPONENT_BIAS) << DOUBLE_EXPONENT_SHIFT);
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "large single exp", 2.5521177519070385E+38); // Exponent fits  single

    // 74                                   # text(20)
    //    746F6F2D6C617267652073696E676C6520657870 # "too-large single exp"
    // FB 47F8000000000000                  # primitive(5185894970917126144)
    // (0x01LL << (DOUBLE_NUM_SIGNIFICAND_BITS-1)) | ((128LL + DOUBLE_EXPONENT_BIAS) << DOUBLE_EXPONENT_SHIFT);
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "too-large single exp", 5.104235503814077E+38); // Exponent too large for single

    // 66                                   # text(6)
    //    646664666465                      # "dfdfde"
    // FA 4B800000                          # primitive(1266679808)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "biggest single with prec",16777216); // Single with no precision loss
    
    // 78 18                                # text(24)
    //    626967676573742073696E676C6520776974682070726563 # "biggest single with prec"
    // FA 4B800000                          # primitive(1266679808)
    QCBOREncode_AddDoubleAsSmallestToMap(&EC, "first single with prec loss",16777217); // Double becuase of precision loss
    
    // Just a convenient marker when cutting and pasting encoded CBOR
    QCBOREncode_AddSZStringToMapN(&EC, 1, "fin");

    QCBOREncode_CloseMap(&EC);
    
    UsefulBufC EncodedHalfs;
    int nReturn = QCBOREncode_Finish2(&EC, &EncodedHalfs);
    if(nReturn) {
        return -1;
    }
    
    if(UsefulBuf_Compare(EncodedHalfs, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedSmallest))) {
        return -3;
    }
    
    return 0;
}



#ifdef NAN_EXPERIMENT
/*
 Code for checking what the double to float cast does with
 NaNs.  Not run as part of tests. Keep it around to
 be able to check various platforms and CPUs.
 */

#define DOUBLE_NUM_SIGNIFICAND_BITS (52)
#define DOUBLE_NUM_EXPONENT_BITS    (11)
#define DOUBLE_NUM_SIGN_BITS        (1)

#define DOUBLE_SIGNIFICAND_SHIFT    (0)
#define DOUBLE_EXPONENT_SHIFT       (DOUBLE_NUM_SIGNIFICAND_BITS)
#define DOUBLE_SIGN_SHIFT           (DOUBLE_NUM_SIGNIFICAND_BITS + DOUBLE_NUM_EXPONENT_BITS)

#define DOUBLE_SIGNIFICAND_MASK     (0xfffffffffffffULL) // The lower 52 bits
#define DOUBLE_EXPONENT_MASK        (0x7ffULL << DOUBLE_EXPONENT_SHIFT) // 11 bits of exponent
#define DOUBLE_SIGN_MASK            (0x01ULL << DOUBLE_SIGN_SHIFT) // 1 bit of sign
#define DOUBLE_QUIET_NAN_BIT        (0x01ULL << (DOUBLE_NUM_SIGNIFICAND_BITS-1))


static int NaNExperiments() {
    double dqNaN = UsefulBufUtil_CopyUint64ToDouble(DOUBLE_EXPONENT_MASK | DOUBLE_QUIET_NAN_BIT);
    double dsNaN = UsefulBufUtil_CopyUint64ToDouble(DOUBLE_EXPONENT_MASK | 0x01);
    double dqNaNPayload = UsefulBufUtil_CopyUint64ToDouble(DOUBLE_EXPONENT_MASK | DOUBLE_QUIET_NAN_BIT | 0xf00f);
    
    float f1 = (float)dqNaN;
    float f2 = (float)dsNaN;
    float f3 = (float)dqNaNPayload;
    
    
    uint32_t uqNaN = UsefulBufUtil_CopyFloatToUint32((float)dqNaN);
    uint32_t usNaN = UsefulBufUtil_CopyFloatToUint32((float)dsNaN);
    uint32_t uqNaNPayload = UsefulBufUtil_CopyFloatToUint32((float)dqNaNPayload);
    
    // Result of this on x86 is that every NaN is a qNaN. The intel
    // CVTSD2SS instruction ignores the NaN payload and even converts
    // a sNaN to a qNaN.
    
    return 0;
}
#endif



