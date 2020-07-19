/*==============================================================================
 float_tests.c -- tests for float and conversion to/from half-precision

 Copyright (c) 2018-2020, Laurence Lundblade. All rights reserved.

 SPDX-License-Identifier: BSD-3-Clause

 See BSD-3-Clause license in README.md

 Created on 9/19/18
 =============================================================================*/


#include "float_tests.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include <math.h> // For INFINITY and NAN and isnan()

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT

#include "half_to_double_from_rfc7049.h"


// A series of half precision values to test half-precision decoding
/*
 As decoded by http://cbor.me
 {"zero": 0.0,
 "infinitity": Infinity,
 "negative infinitity": -Infinity,
 "NaN": NaN,
 "one": 1.0,
 "one third": 0.333251953125,
 "largest half-precision": 65504.0,
 "too-large half-precision": Infinity,
 "smallest subnormal": 5.960464477539063e-8,
 "smallest normal": 0.00006097555160522461,
 "biggest subnormal": 0.00006103515625,
 "subnormal single": 0.0,
 3: -2.0,
 4: NaN,
 5: NaN,
 6: NaN,
 7: NaN}
 */
static const uint8_t spExpectedHalf[] = {
    0xB1,
        0x64,
            0x7A, 0x65, 0x72, 0x6F,
        0xF9, 0x00, 0x00, // half-precision 0.000
        0x6A,
            0x69, 0x6E, 0x66, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x74, 0x79,
        0xF9, 0x7C, 0x00, // Infinity
        0x73,
            0x6E, 0x65, 0x67, 0x61, 0x74, 0x69, 0x76, 0x65, 0x20, 0x69, 0x6E,
            0x66, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x74, 0x79,
        0xF9, 0xFC, 0x00, // -Inifinity
        0x63,
            0x4E, 0x61, 0x4E,
        0xF9, 0x7E, 0x00, // NaN
        0x63,
            0x6F, 0x6E, 0x65,
        0xF9, 0x3C, 0x00, // 1.0
        0x69,
            0x6F, 0x6E, 0x65, 0x20, 0x74, 0x68, 0x69, 0x72, 0x64,
        0xF9, 0x35, 0x55, // half-precsion one third 0.333251953125
        0x76,
            0x6C, 0x61, 0x72, 0x67, 0x65, 0x73, 0x74, 0x20, 0x68, 0x61, 0x6C,
            0x66, 0x2D, 0x70, 0x72, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6F, 0x6E,
        0xF9, 0x7B, 0xFF, // largest half-precision 65504.0
        0x78, 0x18,
            0x74, 0x6F, 0x6F, 0x2D, 0x6C, 0x61, 0x72, 0x67, 0x65, 0x20, 0x68,
            0x61, 0x6C, 0x66, 0x2D, 0x70, 0x72, 0x65, 0x63, 0x69, 0x73, 0x69,
            0x6F, 0x6E,
        0xF9, 0x7C, 0x00, // Infinity
        0x72,
            0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20, 0x73, 0x75,
            0x62, 0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C,
        0xF9, 0x00, 0x01, // Smallest half-precision subnormal 0.000000059604645
        0x71,
            0x62, 0x69, 0x67, 0x67, 0x65, 0x73, 0x74, 0x20, 0x73, 0x75, 0x62,
            0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C,
        0xF9, 0x03, 0xFF, // Largest half-precision subnormal 0.0000609755516
        0x6F,
            0x73, 0x6D, 0x61, 0x6C, 0x6C, 0x65, 0x73, 0x74, 0x20, 0x6E, 0x6F,
            0x72, 0x6D, 0x61, 0x6C,
        0xF9, 0x04, 0x00,  // Smallest half-precision normal 0.000061988
        0x70,
            0x73, 0x75, 0x62, 0x6E, 0x6F, 0x72, 0x6D, 0x61, 0x6C, 0x20, 0x73,
            0x69, 0x6E, 0x67, 0x6C, 0x65,
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


int32_t HalfPrecisionDecodeBasicTests()
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
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 0.0) {
      return -2;
   }

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != INFINITY) {
      return -3;
   }

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != -INFINITY) {
      return -4;
   }

   // TODO: NAN-related is this really converting right? It is carrying payload, but
   // this confuses things.
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || !isnan(Item.val.dfnum)) {
      return -5;
   }

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 1.0) {
      return -6;
   }

   // Approximately 1/3
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 0.333251953125) {
      return -7;
   }

   // Largest half-precision
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 65504.0) {
      return -8;
   }

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != INFINITY) {
      return -9;
   }

   // Smallest half-precision subnormal
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 0.00000005960464477539063) {
      return -10;
   }

   // Largest half-precision subnormal
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 0.00006097555160522461) {
      return -11;
   }

   // Smallest half-precision normal
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 0.00006103515625) {
      return -12;
   }

   // half-precision zero
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != 0.0) {
      return -13;
   }

   // negative 2
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_DOUBLE || Item.val.dfnum != -2.0) {
      return -14;
   }

   // TODO: NAN-related double check these four tests
   QCBORDecode_GetNext(&DC, &Item); // qNaN
   if(Item.uDataType != QCBOR_TYPE_DOUBLE ||
      UsefulBufUtil_CopyDoubleToUint64(Item.val.dfnum) != 0x7ff8000000000000ULL) {
      return -15;
   }
   QCBORDecode_GetNext(&DC, &Item); // sNaN
   if(Item.uDataType != QCBOR_TYPE_DOUBLE ||
      UsefulBufUtil_CopyDoubleToUint64(Item.val.dfnum) != 0x7ff0000000000001ULL) {
      return -16;
   }
   QCBORDecode_GetNext(&DC, &Item); // qNaN with payload 0x0f
   if(Item.uDataType != QCBOR_TYPE_DOUBLE ||
      UsefulBufUtil_CopyDoubleToUint64(Item.val.dfnum) != 0x7ff800000000000fULL) {
      return -17;
   }
   QCBORDecode_GetNext(&DC, &Item); // sNaN with payload 0x0f
   if(Item.uDataType != QCBOR_TYPE_DOUBLE ||
      UsefulBufUtil_CopyDoubleToUint64(Item.val.dfnum) != 0x7ff000000000000fULL) {
      return -18;
   }

   if(QCBORDecode_Finish(&DC)) {
      return -19;
   }

   return 0;
}




int32_t HalfPrecisionAgainstRFCCodeTest()
{
    for(uint32_t uHalfP = 0; uHalfP < 0xffff; uHalfP += 60) {
        unsigned char x[2];
        x[1] = (uint8_t)(uHalfP & 0xff);
        x[0] = (uint8_t)(uHalfP >> 8); // uHalfP is always less than 0xffff
        double d = decode_half(x);

        // Contruct the CBOR for the half-precision float by hand
        UsefulBuf_MAKE_STACK_UB(__xx, 3);
        UsefulOutBuf UOB;
        UsefulOutBuf_Init(&UOB, __xx);

        const uint8_t uHalfPrecInitialByte = (uint8_t)(HALF_PREC_FLOAT + (CBOR_MAJOR_TYPE_SIMPLE << 5)); // 0xf9
        UsefulOutBuf_AppendByte(&UOB, uHalfPrecInitialByte); // The initial byte for a half-precision float
        UsefulOutBuf_AppendUint16(&UOB, (uint16_t)uHalfP);

        // Now parse the hand-constructed CBOR. This will invoke the
        // conversion to a float
        QCBORDecodeContext DC;
        QCBORDecode_Init(&DC, UsefulOutBuf_OutUBuf(&UOB), 0);

        QCBORItem Item;

        QCBORDecode_GetNext(&DC, &Item);
        if(Item.uDataType != QCBOR_TYPE_DOUBLE) {
            return -1;
        }

        //printf("%04x  QCBOR:%15.15f  RFC: %15.15f (%8x)\n",
        //       uHalfP, Item.val.fnum, d , UsefulBufUtil_CopyFloatToUint32(d));

        if(isnan(d)) {
            // The RFC code uses the native instructions which may or may not
            // handle sNaN, qNaN and NaN payloads correctly. This test just
            // makes sure it is a NaN and doesn't worry about the type of NaN
            if(!isnan(Item.val.dfnum)) {
                return -3;
            }
        } else {
            if(Item.val.dfnum != d) {
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


int32_t DoubleAsSmallestTest()
{
    UsefulBuf_MAKE_STACK_UB(EncodedHalfsMem, 420);

#define QCBOREncode_AddDoubleToMap QCBOREncode_AddDoubleToMap


    QCBOREncodeContext EC;
    QCBOREncode_Init(&EC, EncodedHalfsMem);
    // These are mostly from https://en.wikipedia.org/wiki/Half-precision_floating-point_format
    QCBOREncode_OpenMap(&EC);
    // 64                                   # text(4)
    //    7A65726F                          # "zero"
    // F9 0000                              # primitive(0)
    QCBOREncode_AddDoubleToMap(&EC, "zero", 0.00);

    // 64                                   # text(4)
    //    7A65726F                          # "negative zero"
    // F9 8000                              # primitive(0)
    QCBOREncode_AddDoubleToMap(&EC, "negative zero", -0.00);

    // 6A                                   # text(10)
    //    696E66696E6974697479              # "infinitity"
    // F9 7C00                              # primitive(31744)
    QCBOREncode_AddDoubleToMap(&EC, "infinitity", INFINITY);

    // 73                                   # text(19)
    //    6E6567617469766520696E66696E6974697479 # "negative infinitity"
    // F9 FC00                              # primitive(64512)
    QCBOREncode_AddDoubleToMap(&EC, "negative infinitity", -INFINITY);

    // 63                                   # text(3)
    //    4E614E                            # "NaN"
    // F9 7E00                              # primitive(32256)
    QCBOREncode_AddDoubleToMap(&EC, "NaN", NAN);

    // TODO: test a few NaN variants

    // 63                                   # text(3)
    //    6F6E65                            # "one"
    // F9 3C00                              # primitive(15360)
    QCBOREncode_AddDoubleToMap(&EC, "one", 1.0);

    // 69                                   # text(9)
    //    6F6E65207468697264                # "one third"
    // F9 3555                              # primitive(13653)
    QCBOREncode_AddDoubleToMap(&EC, "one third", 0.333251953125);

    // 76                                   # text(22)
    //   6C6172676573742068616C662D707265636973696F6E # "largest half-precision"
    // F9 7BFF                              # primitive(31743)
    QCBOREncode_AddDoubleToMap(&EC, "largest half-precision",65504.0);

    // 76                                   # text(22)
    //   6C6172676573742068616C662D707265636973696F6E # "largest half-precision"
    // F9 7BFF                              # primitive(31743)
    QCBOREncode_AddDoubleToMap(&EC, "largest half-precision point one",65504.1);

    // Float 65536.0F is 0x47800000 in hex. It has an exponent of 16, which
    // is larger than 15, the largest half-precision exponent
    // 78 18                                # text(24)
    //    746F6F2D6C617267652068616C662D707265636973696F6E # "too-large half-precision"
    // FA 47800000                          # primitive(31743)
    QCBOREncode_AddDoubleToMap(&EC, "too-large half-precision", 65536.0);

    // The smallest possible half-precision subnormal, but digitis are lost converting
    // to half, so this turns into a double
    // 72                                   # text(18)
    //    736D616C6C657374207375626E6F726D616C # "smallest subnormal"
    // FB 3E700000001C5F68                  # primitive(4499096027744984936)
    QCBOREncode_AddDoubleToMap(&EC, "smallest subnormal", 0.0000000596046448);

    // The smallest possible half-precision snormal, but digitis are lost converting
    // to half, so this turns into a single TODO: confirm this is right
    // 6F                                   # text(15)
    //    736D616C6C657374206E6F726D616C    # "smallest normal"
    // FA 387FFFFF                          # primitive(947912703)
    // in hex single is 0x387fffff, exponent -15, significand 7fffff
    QCBOREncode_AddDoubleToMap(&EC, "smallest normal",    0.0000610351526F);

    // 71                                   # text(17)
    //    62696767657374207375626E6F726D616C # "biggest subnormal"
    // F9 0400                              # primitive(1024)
    // in hex single is 0x38800000, exponent -14, significand 0
    QCBOREncode_AddDoubleToMap(&EC, "biggest subnormal",  0.0000610351563F);

    // 70                                   # text(16)
    //    7375626E6F726D616C2073696E676C65  # "subnormal single"
    // FB 37C16C2800000000                  # primitive(4017611261645684736)
    QCBOREncode_AddDoubleToMap(&EC, "subnormal single", 4e-40F);

    // 03                                   # unsigned(3)
    // F9 C000                              # primitive(49152)
    QCBOREncode_AddDoubleToMapN(&EC, 3, -2.0);

    // 70                                   # text(16)
    //    6C617267652073696E676C6520657870  # "large single exp"
    // FA 7F400000                          # primitive(2134900736)
    // (0x01LL << (DOUBLE_NUM_SIGNIFICAND_BITS-1)) | ((127LL + DOUBLE_EXPONENT_BIAS) << DOUBLE_EXPONENT_SHIFT);
    QCBOREncode_AddDoubleToMap(&EC, "large single exp", 2.5521177519070385E+38); // Exponent fits  single

    // 74                                   # text(20)
    //    746F6F2D6C617267652073696E676C6520657870 # "too-large single exp"
    // FB 47F8000000000000                  # primitive(5185894970917126144)
    // (0x01LL << (DOUBLE_NUM_SIGNIFICAND_BITS-1)) | ((128LL + DOUBLE_EXPONENT_BIAS) << DOUBLE_EXPONENT_SHIFT);
    // Exponent too large for single
    QCBOREncode_AddDoubleToMap(&EC, "too-large single exp", 5.104235503814077E+38);

    // 66                                   # text(6)
    //    646664666465                      # "dfdfde"
    // FA 4B800000                          # primitive(1266679808)
    // Single with no precision loss
    QCBOREncode_AddDoubleToMap(&EC, "biggest single with prec", 16777216);

    // 78 18                                # text(24)
    //    626967676573742073696E676C6520776974682070726563 # "biggest single with prec"
    // FA 4B800000                          # primitive(1266679808)
    // Double becuase of precision loss
    QCBOREncode_AddDoubleToMap(&EC, "first single with prec loss", 16777217);

    // Just a convenient marker when cutting and pasting encoded CBOR
    QCBOREncode_AddSZStringToMapN(&EC, 1, "fin");

    QCBOREncode_CloseMap(&EC);

    UsefulBufC EncodedHalfs;
    QCBORError uErr = QCBOREncode_Finish(&EC, &EncodedHalfs);
    if(uErr) {
        return -1;
    }

    if(UsefulBuf_Compare(EncodedHalfs, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedSmallest))) {
        return -3;
    }

    return 0;
}
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */


/*
[0.0, 3.14, 0.0, NaN, Infinity, 0.0, 3.140000104904175, 0.0, NaN, Infinity,
 {100: 0.0, 101: 3.1415926, "euler": 2.718281828459045, 105: 0.0,
  102: 0.0, 103: 3.141592502593994, "euler2": 2.7182817459106445, 106: 0.0}]
 */
static const uint8_t spExpectedFloats[] = {
   0x8B,
      0xF9, 0x00, 0x00,
      0xFB, 0x40, 0x09, 0x1E, 0xB8, 0x51, 0xEB, 0x85, 0x1F,
      0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x7F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xF9, 0x00, 0x00,
      0xFA, 0x40, 0x48, 0xF5, 0xC3,
      0xFA, 0x00, 0x00, 0x00, 0x00,
      0xFA, 0x7F, 0xC0, 0x00, 0x00,
      0xFA, 0x7F, 0x80, 0x00, 0x00,
      0xA8,
         0x18, 0x64,
          0xF9, 0x00, 0x00,
         0x18, 0x65,
          0xFB, 0x40, 0x09, 0x21, 0xFB, 0x4D, 0x12, 0xD8, 0x4A,
         0x65, 0x65, 0x75, 0x6C, 0x65, 0x72,
          0xFB, 0x40, 0x05, 0xBF, 0x0A, 0x8B, 0x14, 0x57, 0x69,
         0x18, 0x69,
          0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x18, 0x66,
          0xF9, 0x00, 0x00,
         0x18, 0x67,
          0xFA, 0x40, 0x49, 0x0F, 0xDA,
         0x66, 0x65, 0x75, 0x6C, 0x65, 0x72, 0x32,
          0xFA, 0x40, 0x2D, 0xF8, 0x54,
         0x18, 0x6A,
          0xFA, 0x00, 0x00, 0x00, 0x00};

static const uint8_t spExpectedFloatsNoHalf[] = {
   0x8B,
      0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x40, 0x09, 0x1E, 0xB8, 0x51, 0xEB, 0x85, 0x1F,
      0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x7F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFA, 0x00, 0x00, 0x00, 0x00,
      0xFA, 0x40, 0x48, 0xF5, 0xC3,
      0xFA, 0x00, 0x00, 0x00, 0x00,
      0xFA, 0x7F, 0xC0, 0x00, 0x00,
      0xFA, 0x7F, 0x80, 0x00, 0x00,
      0xA8,
         0x18, 0x64,
          0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x18, 0x65,
          0xFB, 0x40, 0x09, 0x21, 0xFB, 0x4D, 0x12, 0xD8, 0x4A,
         0x65, 0x65, 0x75, 0x6C, 0x65, 0x72,
          0xFB, 0x40, 0x05, 0xBF, 0x0A, 0x8B, 0x14, 0x57, 0x69,
         0x18, 0x69,
          0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x18, 0x66,
          0xFA, 0x00, 0x00, 0x00, 0x00,
         0x18, 0x67,
          0xFA, 0x40, 0x49, 0x0F, 0xDA,
         0x66, 0x65, 0x75, 0x6C, 0x65, 0x72, 0x32,
          0xFA, 0x40, 0x2D, 0xF8, 0x54,
         0x18, 0x6A,
          0xFA, 0x00, 0x00, 0x00, 0x00};

int32_t GeneralFloatEncodeTests()
{
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
   UsefulBuf_MAKE_STACK_UB(OutBuffer, sizeof(spExpectedFloats));
   UsefulBufC ExpectedFloats = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedFloats);
   (void)spExpectedFloatsNoHalf; // Avoid unused variable error
#else
   UsefulBuf_MAKE_STACK_UB(OutBuffer, sizeof(spExpectedFloatsNoHalf));
   UsefulBufC ExpectedFloats = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedFloatsNoHalf);
   (void)spExpectedFloats; // Avoid unused variable error
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */

   QCBOREncodeContext EC;
   QCBOREncode_Init(&EC, OutBuffer);
   QCBOREncode_OpenArray(&EC);

   QCBOREncode_AddDouble(&EC, 0.0);
   QCBOREncode_AddDouble(&EC, 3.14);
   QCBOREncode_AddDoubleNoPreferred(&EC, 0.0);
   QCBOREncode_AddDoubleNoPreferred(&EC, NAN);
   QCBOREncode_AddDoubleNoPreferred(&EC, INFINITY);

   QCBOREncode_AddFloat(&EC, 0.0);
   QCBOREncode_AddFloat(&EC, 3.14f);
   QCBOREncode_AddFloatNoPreferred(&EC, 0.0f);
   QCBOREncode_AddFloatNoPreferred(&EC, NAN);
   QCBOREncode_AddFloatNoPreferred(&EC, INFINITY);

   QCBOREncode_OpenMap(&EC);

   QCBOREncode_AddDoubleToMapN(&EC, 100, 0.0);
   QCBOREncode_AddDoubleToMapN(&EC, 101, 3.1415926);
   QCBOREncode_AddDoubleToMap(&EC, "euler", 2.71828182845904523536);
   QCBOREncode_AddDoubleNoPreferredToMapN(&EC, 105, 0.0);

   QCBOREncode_AddFloatToMapN(&EC, 102, 0.0f);
   QCBOREncode_AddFloatToMapN(&EC, 103, 3.1415926f);
   QCBOREncode_AddFloatToMap(&EC, "euler2", 2.71828182845904523536f);
   QCBOREncode_AddFloatNoPreferredToMapN(&EC, 106, 0.0f);

   QCBOREncode_CloseMap(&EC);
   QCBOREncode_CloseArray(&EC);

   UsefulBufC Encoded;
   QCBORError uErr = QCBOREncode_Finish(&EC, &Encoded);
   if(uErr) {
      return -1;
   }

   if(UsefulBuf_Compare(Encoded, ExpectedFloats)) {
      return -3;
   }

   return 0;
}


#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
/* returns 0 if equivalent, non-zero if not equivalent */
static int CHECK_EXPECTED_DOUBLE(double val, double expected)
{
   double diff = val - expected;

   diff = fabs(diff);

   if(diff > 0.000001) {
      return 1;
   } else {
      return 0;
   }
}
#endif


int32_t GeneralFloatDecodeTests()
{
   UsefulBufC TestData = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedFloats);

   QCBORDecodeContext DC;
   QCBORDecode_Init(&DC, TestData, 0);

   QCBORItem Item;
   QCBORError uErr;

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -1;
   }

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_DOUBLE ||
      Item.val.dfnum != 0.0) {
      return -2;
   }
#else
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_ERR_HALF_PRECISION_UNSUPPORTED) {
      return -3;
   }
#endif

   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_DOUBLE ||
      Item.val.dfnum != 3.14) {
      return -4;
   }

   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_DOUBLE ||
      Item.val.dfnum != 0.0) {
      return -5;
   }

   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_DOUBLE ||
      !isnan(Item.val.dfnum)) {
      return -6;
   }

   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_DOUBLE ||
      Item.val.dfnum != INFINITY) {
      return -7;
   }

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_DOUBLE ||
      Item.val.dfnum != 0.0) {
      return -8;
   }

   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_DOUBLE ||
      CHECK_EXPECTED_DOUBLE(3.14, Item.val.dfnum)) {
      return -9;
   }

   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_DOUBLE ||
      Item.val.dfnum != 0.0) {
      return -10;
   }

   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_DOUBLE ||
      !isnan(Item.val.dfnum)) {
      return -11;
   }

   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_DOUBLE ||
      Item.val.dfnum != INFINITY) {
      return -12;
   }

#else
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_ERR_HALF_PRECISION_UNSUPPORTED) {
      return -13;
   }

   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_FLOAT ||
      Item.val.fnum != 3.14f) {
      return -14;
   }

   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_FLOAT ||
      Item.val.fnum != 0.0f) {
      return -15;
   }

   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_FLOAT ||
      !isnan(Item.val.fnum)) {
      return -16;
   }

   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != QCBOR_SUCCESS ||
      Item.uDataType != QCBOR_TYPE_FLOAT ||
      Item.val.fnum != INFINITY) {
      return -17;
   }
#endif
   /* Sufficent test coverage. Don't need to decode the rest */

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



