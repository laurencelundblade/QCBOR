/*
 bstrwrap_tests.c -- tests for bstr wrapping in CBOR encoding
 
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
//  Created by Laurence Lundblade on 9/29/18.

#include "bstrwrap_tests.h"
#include "qcbor.h"


/*
 Very basic bstr wrapping test
 */
int bstrwraptest()
{
    UsefulBuf_MakeStackUB(MemoryForEncoded, 100);
    QCBOREncodeContext EC;
    
    QCBOREncode_Init(&EC, MemoryForEncoded);
    
    QCBOREncode_OpenArray(&EC);
    QCBOREncode_AddUInt64(&EC, 451);
    
    QCBOREncode_BstrWrap(&EC);
    QCBOREncode_AddUInt64(&EC, 466);
    
    UsefulBufC Wrapped;
    QCBOREncode_CloseBstrWrap(&EC, &Wrapped);
    
    QCBOREncode_CloseArray(&EC);
    
    UsefulBufC Encoded;
    if(QCBOREncode_Finish2(&EC, &Encoded)) {
        return -1;
    }
    
    const uint8_t pExpected[] = {0x82, 0x19, 0x01, 0xC3, 0x43, 0x19, 0x01, 0xD2};
    if(UsefulBuf_Compare(UsefulBuf_FromByteArrayLiteral(pExpected), Encoded)) {
        return -2;
    }
    
    return 0;
}



int bstr_wrap_error_test()
{
    // -------------- Test closing a bstrwrap when it is an array that is open -----------
    UsefulBuf_MakeStackUB(MemoryForEncoded, 100);
    QCBOREncodeContext EC;
    
    QCBOREncode_Init(&EC, MemoryForEncoded);
    
    QCBOREncode_OpenArray(&EC);
    QCBOREncode_AddUInt64(&EC, 451);
    
    QCBOREncode_BstrWrap(&EC);
    QCBOREncode_AddUInt64(&EC, 466);
    QCBOREncode_OpenArray(&EC);
    
    UsefulBufC Wrapped;
    QCBOREncode_CloseBstrWrap(&EC, &Wrapped);
    
    QCBOREncode_CloseArray(&EC);
    
    UsefulBufC Encoded2;
    if(QCBOREncode_Finish2(&EC, &Encoded2) != QCBOR_ERR_CLOSE_MISMATCH) {
        return -1;
    }
    
    // ----------- test closing a bstrwrap when nothing is open ---------------------
    QCBOREncode_Init(&EC, MemoryForEncoded);
    QCBOREncode_CloseBstrWrap(&EC, &Wrapped);
    if(QCBOREncode_Finish2(&EC, &Encoded2) != QCBOR_ERR_TOO_MANY_CLOSES) {
        return -2;
    }
    
    // --------------- test nesting too deep ----------------------------------
    QCBOREncode_Init(&EC, MemoryForEncoded);
    for(int i = 1; i < 18; i++) {
        QCBOREncode_BstrWrap(&EC);
    }
    QCBOREncode_AddBool(&EC, true);
    
    for(int i = 1; i < 18; i++) {
        QCBOREncode_CloseBstrWrap(&EC, &Wrapped);
    }
    
    if(QCBOREncode_Finish2(&EC, &Encoded2) != QCBOR_ERR_ARRAY_NESTING_TOO_DEEP) {
        return -3;
    }
    
    return 0;
}



// Part of bstr_wrap_nest_test
/*
 83 array with three
   53  byte string with 19 bytes
      01  #1
      50 byte string with 16 bytes
           02
           4D byte string with 13 bytes
               03
               4A byte string with 10 bytes
                    04
                    47 byte string with 7 bytes
                        05
                        44 byte string with 4 bytes
                            06
                            41 byte string with 1 byte
                                 07
                            01
                        02
                    03
               04
           05
       06
  07
    A2 map with two items
      18 20  label for byte string
      54 byte string of length 20
         82 Array with two items
            10  The integer value 10
            A2 map with two items
               18 21 label for byte string
               44 byte string with 4 bytes
                  81 array with 1 item
                     11 integer value 11
                  18 30 integer value 30
               18 40 integer label 40
               65 68 65 6C 6C 6F text string hello
         18 31 integer value 31
      18 41 integer label 41
      65 68 65 6C 6C 6F text string hello
 
 
 */
static const uint8_t sExpectedDeepBstr[] =
{
    0x83, 0x56, 0x00, 0x53, 0x01, 0x50, 0x02, 0x4D,
    0x03, 0x4A, 0x04, 0x47, 0x05, 0x44, 0x06, 0x41,
    0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0xA2, 0x18, 0x20, 0x54, 0x82, 0x10, 0xA2,
    0x18, 0x21, 0x44, 0x81, 0x11, 0x18, 0x30, 0x18,
    0x40, 0x65, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x18,
    0x31, 0x18, 0x41, 0x65, 0x68, 0x65, 0x6C, 0x6C,
    0x6F
};

// Part of bstr_wrap_nest_test
static int decode_next_nested(UsefulBufC Wrapped)
{
    int nReturn;
    QCBORDecodeContext DC;
    QCBORDecode_Init(&DC, Wrapped, QCBOR_DECODE_MODE_NORMAL);
    
    QCBORItem Item;
    nReturn = QCBORDecode_GetNext(&DC, &Item);
    if(nReturn) {
        return -11;
    }
    if(Item.uDataType != QCBOR_TYPE_INT64) {
        return -12;
    }
    
    nReturn = QCBORDecode_GetNext(&DC, &Item);
    if(nReturn == QCBOR_ERR_HIT_END) {
        return 0;
    }
    if(Item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return -13;
    }
    nReturn =  decode_next_nested(Item.val.string);
    if(nReturn) {
        return nReturn;
    }
    
    nReturn = QCBORDecode_GetNext(&DC, &Item);
    if(nReturn) {
        return -14;
    }
    if(Item.uDataType != QCBOR_TYPE_INT64) {
        return -15;
    }
    
    if(QCBORDecode_Finish(&DC)) {
        return -16;
    }
    
    return 0;
}

// Part of bstr_wrap_nest_test
static int decode_next_nested2(UsefulBufC Wrapped)
{
    int nReturn;
    QCBORDecodeContext DC;
    QCBORDecode_Init(&DC, Wrapped, QCBOR_DECODE_MODE_NORMAL);
    
    QCBORItem Item;
    nReturn = QCBORDecode_GetNext(&DC, &Item);
    if(nReturn) {
        return -11;
    }
    if(Item.uDataType != QCBOR_TYPE_ARRAY) {
        return -12;
    }
    
    nReturn = QCBORDecode_GetNext(&DC, &Item);
    if(nReturn) {
        return -11;
    }
    if(Item.uDataType != QCBOR_TYPE_INT64) {
        return -12;
    }
    
    nReturn = QCBORDecode_GetNext(&DC, &Item);
    if(nReturn) {
        return -11;
    }
    if(Item.uDataType != QCBOR_TYPE_MAP) {
        return 0;
    }
    
    nReturn = QCBORDecode_GetNext(&DC, &Item);
    if(nReturn) {
        return -11;
    }
    if(Item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return -13;
    }
    nReturn =  decode_next_nested2(Item.val.string);
    if(nReturn) {
        return nReturn;
    }
    
    nReturn = QCBORDecode_GetNext(&DC, &Item);
    if(nReturn) {
        return -11;
    }
    if(Item.uDataType != QCBOR_TYPE_TEXT_STRING) {
        return -12;
    }
    nReturn = QCBORDecode_GetNext(&DC, &Item);
    if(nReturn) {
        return -11;
    }
    if(Item.uDataType != QCBOR_TYPE_INT64) {
        return -12;
    }
    
    if(QCBORDecode_Finish(&DC)) {
        return -16;
    }
    
    return 0;
}


int bstr_wrap_nest_test()
{
    UsefulBuf_MakeStackUB(MemoryForEncoded, 300);
    QCBOREncodeContext EC;
    QCBOREncode_Init(&EC, MemoryForEncoded);
    
    // ---- Make a complicated nested CBOR structure ---
    QCBOREncode_OpenArray(&EC);
    
    for(int i = 0; i < QCBOR_MAX_ARRAY_NESTING-2; i++) {
        QCBOREncode_BstrWrap(&EC);
        QCBOREncode_AddUInt64(&EC, i);
    }
    
    for(int i = 0; i < QCBOR_MAX_ARRAY_NESTING-2; i++) {
        QCBOREncode_CloseBstrWrap(&EC, NULL);
        QCBOREncode_AddUInt64(&EC, i);
    }
    
    for(int i = 0; i < (QCBOR_MAX_ARRAY_NESTING-2)/3; i++) {
        QCBOREncode_OpenMap(&EC);
        QCBOREncode_BstrWrapMapN(&EC, i+0x20);
        QCBOREncode_OpenArray(&EC);
        QCBOREncode_AddUInt64(&EC, i+0x10);
    }
    
    for(int i = 0; i < (QCBOR_MAX_ARRAY_NESTING-2)/3; i++) {
        QCBOREncode_CloseArray(&EC);
        QCBOREncode_AddUInt64(&EC, i+0x30);
        QCBOREncode_CloseBstrWrap(&EC, NULL);
        QCBOREncode_AddSZStringToMapN(&EC, i+0x40, "hello");
        QCBOREncode_CloseMap(&EC);
    }
    QCBOREncode_CloseArray(&EC);
    
    UsefulBufC Encoded;
    if(QCBOREncode_Finish2(&EC, &Encoded)) {
        return -1;
    }
    
    // ---Compare it to expected. Expected was hand checked with use of CBOR playground ----
    if(UsefulBuf_Compare(UsefulBuf_FromByteArrayLiteral(sExpectedDeepBstr), Encoded)) {
        return -25;
    }
    
    
    // ---- Decode it and see if it is OK ------
    QCBORDecodeContext DC;
    QCBORDecode_Init(&DC, Encoded, QCBOR_DECODE_MODE_NORMAL);
    
    QCBORItem Item;
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_ARRAY || Item.val.uCount != 3) {
        return -2;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return -3;
    }
    
    int nReturn = decode_next_nested(Item.val.string);
    if(nReturn) {
        return nReturn;
    }
    
    nReturn = QCBORDecode_GetNext(&DC, &Item);
    if(nReturn) {
        return -11;
    }
    if(Item.uDataType != QCBOR_TYPE_INT64) {
        return -12;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_MAP || Item.val.uCount != 2) {
        return -2;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return -3;
    }
    nReturn = decode_next_nested2(Item.val.string);
    if(nReturn) {
        return nReturn;
    }
    
    nReturn = QCBORDecode_GetNext(&DC, &Item);
    if(nReturn) {
        return -11;
    }
    if(Item.uDataType != QCBOR_TYPE_TEXT_STRING) {
        return -12;
    }
    
    if(QCBORDecode_Finish(&DC)) {
        return -16;
    }
    
    return 0;
}


/*
 this corresponds exactly to the example in RFC 8152
 section C.2.1. This doesn't actually verify the signature
 though that would be nice as it would make the test
 really good. That would require bring in ECDSA crypto
 to this test.
 */
int cose_sign1_tbs_test()
{
    // All of this is from RFC 8152 C.2.1
    const char *szKid = "11";
    UsefulBufC Kid = UsefulBuf_FromSZ(szKid);
    const char *szPayload = "This is the content.";
    UsefulBufC Payload = UsefulBuf_FromSZ(szPayload);
    const uint8_t pProtectedHeaders[] = {0xa1, 0x01, 0x26};
    UsefulBufC ProtectedHeaders = UsefulBuf_FromByteArrayLiteral(pProtectedHeaders);
    const uint8_t sSignature[] = {
        0x8e, 0xb3, 0x3e, 0x4c, 0xa3, 0x1d, 0x1c, 0x46, 0x5a, 0xb0,
        0x5a, 0xac, 0x34, 0xcc, 0x6b, 0x23, 0xd5, 0x8f, 0xef, 0x5c,
        0x08, 0x31, 0x06, 0xc4, 0xd2, 0x5a, 0x91, 0xae, 0xf0, 0xb0,
        0x11, 0x7e, 0x2a, 0xf9, 0xa2, 0x91, 0xaa, 0x32, 0xe1, 0x4a,
        0xb8, 0x34, 0xdc, 0x56, 0xed, 0x2a, 0x22, 0x34, 0x44, 0x54,
        0x7e, 0x01, 0xf1, 0x1d, 0x3b, 0x09, 0x16, 0xe5, 0xa4, 0xc3,
        0x45, 0xca, 0xcb, 0x36};
    // It would be good to compare this to the output from
    // a COSE implementation like COSE-C. It has been checked
    // against the CBOR playground.
    UsefulBufC Signature = UsefulBuf_FromByteArrayLiteral(sSignature);
    const uint8_t sExpected[] = {
        0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA1, 0x04, 0x42, 0x31,
        0x31, 0x54, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6F, 0x6E, 0x74, 0x65, 0x6E,
        0x74, 0x2E, 0x58, 0x40, 0x8E, 0xB3, 0x3E, 0x4C, 0xA3, 0x1D,
        0x1C, 0x46, 0x5A, 0xB0, 0x5A, 0xAC, 0x34, 0xCC, 0x6B, 0x23,
        0xD5, 0x8F, 0xEF, 0x5C, 0x08, 0x31, 0x06, 0xC4, 0xD2, 0x5A,
        0x91, 0xAE, 0xF0, 0xB0, 0x11, 0x7E, 0x2A, 0xF9, 0xA2, 0x91,
        0xAA, 0x32, 0xE1, 0x4A, 0xB8, 0x34, 0xDC, 0x56, 0xED, 0x2A,
        0x22, 0x34, 0x44, 0x54, 0x7E, 0x01, 0xF1, 0x1D, 0x3B, 0x09,
        0x16, 0xE5, 0xA4, 0xC3, 0x45, 0xCA, 0xCB, 0x36};
    UsefulBufC Expected = UsefulBuf_FromByteArrayLiteral(sExpected);
    
    UsefulBuf_MakeStackUB(MemoryForEncoded, 98);
    QCBOREncodeContext EC;
    QCBOREncode_Init(&EC, MemoryForEncoded);
    
    // top level array for cose sign1, 18 is the tag for COSE sign
    QCBOREncode_OpenArray_3(&EC, NULL, QCBOR_NO_INT_LABEL, 18);
    
    // Add protected headers
    QCBOREncode_AddBytes(&EC, ProtectedHeaders);
    
    // Empty map with unprotected headers
    QCBOREncode_OpenMap(&EC);
    QCBOREncode_AddBytesToMapN(&EC, 4, Kid);
    QCBOREncode_CloseMap(&EC);
    
    // The payload
    UsefulBufC WrappedPayload;
    QCBOREncode_BstrWrap(&EC);
    QCBOREncode_AddEncoded(&EC, Payload); // Payload is not actually CBOR in example C.2.1
    QCBOREncode_CloseBstrWrap(&EC, &WrappedPayload);
    
    // Check we got back the actual payload expected
    if(UsefulBuf_Compare(WrappedPayload, Payload)) {
        return -1;
    }
    
    // The signature
    QCBOREncode_AddBytes(&EC, Signature);
    QCBOREncode_CloseArray(&EC);
    
    // Finish and check the results
    UsefulBufC COSE_Sign1;
    if(QCBOREncode_Finish2(&EC, &COSE_Sign1)) {
        return -2;
    }
    
    // 98 is the size from RFC 8152 C.2.1
    if(COSE_Sign1.len != 98) {
        return -3;
    }
    
    if(UsefulBuf_Compare(COSE_Sign1, Expected)) {
        return -4;
    }
    
    return 0;
}

