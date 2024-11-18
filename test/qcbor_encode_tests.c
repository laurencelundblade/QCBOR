/*==============================================================================
 Copyright (c) 2016-2018, The Linux Foundation.
 Copyright (c) 2018-2024, Laurence Lundblade.
 Copyright (c) 2022, Arm Limited. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of The Linux Foundation nor the names of its
      contributors, nor the name "Laurence Lundblade" may be used to
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
 =============================================================================*/

#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor_encode_tests.h"


/*
 This is the test set for CBOR encoding.

 This is largely complete for the implemented.

 A few more things to do include:
   - Add a test for counting the top level items and adding it back in with AddRaw()
   - Run on some different CPUs like 32-bit and maybe even 16-bit
   - Test the large array count limit
   - Add the CBOR diagnostic output for every expected

 */

#define PRINT_FUNCTIONS_FOR_DEBUGGING

#ifdef  PRINT_FUNCTIONS_FOR_DEBUGGING
#include <stdio.h>

#if 0
// ifdef these out to not have compiler warnings
static void printencoded(const uint8_t *pEncoded, size_t nLen)
{
   size_t i;
   for(i = 0; i < nLen; i++) {
      uint8_t Z = pEncoded[i];
      printf("%02x ", Z);
   }
   printf("\n");

   fflush(stdout);
}
#endif


// Do the comparison and print out where it fails
static int UsefulBuf_Compare_Print(UsefulBufC U1, UsefulBufC U2) {
   size_t i;
   for(i = 0; i < U1.len; i++) {
      if(((const uint8_t *)U1.ptr)[i] != ((const uint8_t *)U2.ptr)[i]) {
         printf("Position: %u  Actual: 0x%x   Expected: 0x%x\n",
                (uint32_t)i,
                ((const uint8_t *)U1.ptr)[i],
                ((const uint8_t *)U2.ptr)[i]);
         return 1;
      }
   }
   return 0;

}

#define CheckResults(Enc, Expected) \
   UsefulBuf_Compare_Print(Enc, (UsefulBufC){Expected, sizeof(Expected)})

#else

#define CheckResults(Enc, Expected) \
   UsefulBuf_Compare(Enc, (UsefulBufC){Expected, sizeof(Expected)})

#endif


/*
 Returns 0 if UsefulBufs are equal
 Returns 1000000 + offeset if they are not equal.
*/
struct UBCompareDiagnostic {
   uint8_t uActual;
   uint8_t uExpected;
   size_t  uOffset;
};

static int32_t
UsefulBuf_CompareWithDiagnostic(UsefulBufC Actual,
                                UsefulBufC Expected,
                                struct UBCompareDiagnostic *pDiag) {
   size_t i;
   for(i = 0; i < Actual.len; i++) {
      if(((const uint8_t *)Actual.ptr)[i] != ((const uint8_t *)Expected.ptr)[i]) {
         if(pDiag) {
            pDiag->uActual   = ((const uint8_t *)Actual.ptr)[i];
            pDiag->uExpected = ((const uint8_t *)Expected.ptr)[i];
            pDiag->uOffset   = i;
         }
         // Cast to int is OK as this is only a diagnostic and the sizes
         // here are never over a few KB.
         return (int32_t)i + 1000000;
      }
   }
   return 0;

}


static inline int32_t
MakeTestResultCode(uint32_t   uTestCase,
                   uint32_t   uTestNumber,
                   QCBORError uErrorCode)
{
   uint32_t uCode = (uTestCase * 1000000) +
                    (uTestNumber * 1000) +
                    (uint32_t)uErrorCode;
   return (int32_t)uCode;
}


// One big buffer that is used by all the tests to encode into
// Putting it in uninitialized data is better than using a lot
// of stack. The tests should run on small devices too.
static uint8_t spBigBuf[2200];



/*
 Some very minimal tests.
 */
int32_t BasicEncodeTest(void)
{
   // Very simple CBOR, a map with one boolean that is true in it
   QCBOREncodeContext EC;

   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));

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


   UsefulBuf Tmp = QCBOREncode_RetrieveOutputStorage(&EC);
   if(Tmp.ptr != spBigBuf && Tmp.len != sizeof(spBigBuf)) {
      return -111;
   }

   // Make another encoded message with the CBOR from the previous
   // put into this one
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
   if(Item.uDataType != QCBOR_TYPE_MAP ||
      Item.val.uCount != 1 ||
      Item.uLabelType != QCBOR_TYPE_INT64 ||
      Item.label.int64 != -70000) {
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


/* Don't change this, make a new test instead. Keep this
 * as it was in v1 for full regression. */
static const uint8_t spExpectedEncodedAll[] = {
 0x98, 0x23, 0x66, 0x55, 0x49, 0x4e, 0x54, 0x36, 0x32, 0xd8,
 0x64, 0x1a, 0x05, 0x5d, 0x23, 0x15, 0x65, 0x49, 0x4e, 0x54,
 0x36, 0x34, 0xd8, 0x4c, 0x1b, 0x00, 0x00, 0x00, 0x12, 0x16,
 0xaf, 0x2b, 0x15, 0x00, 0x38, 0x2b, 0xa4, 0x63, 0x4c, 0x42,
 0x4c, 0x18, 0x4d, 0x23, 0x18, 0x58, 0x78, 0x1a, 0x4e, 0x45,
 0x47, 0x4c, 0x42, 0x4c, 0x54, 0x48, 0x41, 0x54, 0x20, 0x49,
 0x53, 0x20, 0x4b, 0x49, 0x4e, 0x44, 0x20, 0x4f, 0x46, 0x20,
 0x4c, 0x4f, 0x4e, 0x47, 0x3b, 0x00, 0x00, 0x02, 0x2d, 0x9a,
 0xc6, 0x94, 0x55, 0x3a, 0x05, 0xf5, 0xe0, 0xff, 0x3a, 0x2f,
 0xaf, 0x07, 0xff, 0xc1, 0x1a, 0x8e, 0x15, 0x1c, 0x8a,
 0xa3, 0x74, 0x4c, 0x6f, 0x6e, 0x67, 0x4c, 0x69, 0x76, 0x65,
 0x44, 0x65, 0x6e, 0x69, 0x73, 0x52, 0x69, 0x74, 0x63, 0x68,
 0x69, 0x65, 0xc1, 0x1a, 0x53, 0x72, 0x4e, 0x00, 0x66, 0x74,
 0x69, 0x6d, 0x65, 0x28, 0x29, 0xc1, 0x1a, 0x58, 0x0d, 0x41,
 0x72, 0x39, 0x07, 0xb0, 0xc1, 0x1a, 0x58, 0x0d, 0x3f, 0x76,
 0x42, 0xff, 0x00, 0xa4, 0x66, 0x62, 0x69, 0x6e, 0x62, 0x69,
 0x6e, 0xda, 0x00, 0x01, 0x86, 0xa0, 0x41, 0x00,
 0x65, 0x65, 0x6D, 0x70, 0x74, 0x79, 0x40,
 0x66, 0x62,
 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x43, 0x01, 0x02, 0x03, 0x00,
 0x44, 0x04, 0x02, 0x03, 0xfe, 0x6f, 0x62, 0x61, 0x72, 0x20,
 0x62, 0x61, 0x72, 0x20, 0x66, 0x6f, 0x6f, 0x20, 0x62, 0x61,
 0x72, 0x64, 0x6f, 0x6f, 0x66, 0x0a, 0x60, 0xd8, 0x20, 0x78, 0x6b,
 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x73, 0x74, 0x61,
 0x63, 0x6b, 0x6f, 0x76, 0x65, 0x72, 0x66, 0x6c, 0x6f, 0x77,
 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x71, 0x75, 0x65, 0x73, 0x74,
 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x32, 0x38, 0x30, 0x35, 0x39,
 0x36, 0x39, 0x37, 0x2f, 0x68, 0x6f, 0x77, 0x2d, 0x64, 0x6f,
 0x2d, 0x69, 0x2d, 0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x2d,
 0x62, 0x65, 0x74, 0x77, 0x65, 0x65, 0x6e, 0x2d, 0x64, 0x65,
 0x62, 0x75, 0x67, 0x2d, 0x61, 0x6e, 0x64, 0x2d, 0x72, 0x65,
 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2d, 0x62, 0x75, 0x69, 0x6c,
 0x64, 0x73, 0x2d, 0x69, 0x6e, 0x2d, 0x78, 0x63, 0x6f, 0x64,
 0x65, 0x2d, 0x36, 0x2d, 0x37, 0x2d, 0x38, 0xd8, 0x22, 0x78,
 0x1c, 0x59, 0x57, 0x35, 0x35, 0x49, 0x47, 0x4e, 0x68, 0x63,
 0x6d, 0x35, 0x68, 0x62, 0x43, 0x42, 0x77, 0x62, 0x47, 0x56,
 0x68, 0x63, 0x33, 0x56, 0x79, 0x5a, 0x51, 0x3d, 0x3d, 0xd8,
 0x23, 0x67, 0x5b, 0x5e, 0x61, 0x62, 0x63, 0x5d, 0x2b, 0xd9,
 0x01, 0x01, 0x59, 0x01, 0x57, 0x4d, 0x49, 0x4d, 0x45, 0x2d, 0x56,
 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x31, 0x2e,
 0x30, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d,
 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x6d, 0x75, 0x6c, 0x74,
 0x69, 0x70, 0x61, 0x72, 0x74, 0x2f, 0x6d, 0x69, 0x78, 0x65,
 0x64, 0x3b, 0x0a, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72,
 0x79, 0x3d, 0x22, 0x58, 0x58, 0x58, 0x58, 0x62, 0x6f, 0x75,
 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x74, 0x65, 0x78, 0x74,
 0x22, 0x0a, 0x0a, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73,
 0x20, 0x61, 0x20, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x70, 0x61,
 0x72, 0x74, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
 0x20, 0x69, 0x6e, 0x20, 0x4d, 0x49, 0x4d, 0x45, 0x20, 0x66,
 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x2e, 0x0a, 0x0a, 0x2d, 0x2d,
 0x58, 0x58, 0x58, 0x58, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61,
 0x72, 0x79, 0x20, 0x74, 0x65, 0x78, 0x74, 0x0a, 0x43, 0x6f,
 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65,
 0x3a, 0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61,
 0x69, 0x6e, 0x0a, 0x0a, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69,
 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x6f, 0x64, 0x79,
 0x20, 0x74, 0x65, 0x78, 0x74, 0x0a, 0x0a, 0x2d, 0x2d, 0x58,
 0x58, 0x58, 0x58, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72,
 0x79, 0x20, 0x74, 0x65, 0x78, 0x74, 0x0a, 0x43, 0x6f, 0x6e,
 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a,
 0x20, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69,
 0x6e, 0x3b, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
 0x2d, 0x44, 0x69, 0x73, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x69,
 0x6f, 0x6e, 0x3a, 0x20, 0x61, 0x74, 0x74, 0x61, 0x63, 0x68,
 0x6d, 0x65, 0x6e, 0x74, 0x3b, 0x0a, 0x66, 0x69, 0x6c, 0x65,
 0x6e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x74, 0x65, 0x73, 0x74,
 0x2e, 0x74, 0x78, 0x74, 0x22, 0x0a, 0x0a, 0x74, 0x68, 0x69,
 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61,
 0x74, 0x74, 0x61, 0x63, 0x68, 0x6d, 0x65, 0x6e, 0x74, 0x20,
 0x74, 0x65, 0x78, 0x74, 0x0a, 0x0a, 0x2d, 0x2d, 0x58, 0x58,
 0x58, 0x58, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79,
 0x20, 0x74, 0x65, 0x78, 0x74, 0x2d, 0x2d, 0xae, 0x65, 0x23,
 0x23, 0x23, 0x23, 0x23, 0x6f, 0x66, 0x6f, 0x6f, 0x20, 0x62,
 0x61, 0x72, 0x20, 0x66, 0x6f, 0x6f, 0x20, 0x66, 0x6f, 0x6f,
 0x64, 0x5f, 0x5f, 0x5f, 0x5f, 0x67, 0x66, 0x6f, 0x6f, 0x20,
 0x62, 0x61, 0x72, 0x66, 0x28, 0x29, 0x28, 0x29, 0x28, 0x29,
 0xd9, 0x03, 0xe8, 0x6b, 0x72, 0x61, 0x62, 0x20, 0x72, 0x61,
 0x62, 0x20, 0x6f, 0x6f, 0x66, 0x16, 0x6f, 0x66, 0x6f, 0x6f,
 0x20, 0x66, 0x6f, 0x6f, 0x20, 0x66, 0x6f, 0x6f, 0x20, 0x66,
 0x6f, 0x6f, 0x62, 0x5e, 0x5e, 0x69, 0x6f, 0x6f, 0x6f, 0x6f,
 0x6f, 0x6f, 0x6f, 0x6f, 0x66, 0x18, 0x63, 0x6d, 0x66, 0x66,
 0x66, 0x66, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f,
 0x66, 0x63, 0x52, 0x46, 0x43, 0xd8, 0x20, 0x78, 0x31, 0x68,
 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x74, 0x6f, 0x6f,
 0x6c, 0x73, 0x2e, 0x69, 0x65, 0x74, 0x66, 0x2e, 0x6f, 0x72,
 0x67, 0x2f, 0x68, 0x74, 0x6d, 0x6c, 0x2f, 0x72, 0x66, 0x63,
 0x37, 0x30, 0x34, 0x39, 0x23, 0x73, 0x65, 0x63, 0x74, 0x69,
 0x6f, 0x6e, 0x2d, 0x32, 0x2e, 0x34, 0x2e, 0x35, 0x18, 0x89,
 0xd8, 0x20, 0x6f, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f,
 0x63, 0x62, 0x6f, 0x72, 0x2e, 0x6d, 0x65, 0x2f, 0x68, 0x77,
 0x68, 0x65, 0x6e, 0x69, 0x6d, 0x36, 0x34, 0xd8, 0x22, 0x6c,
 0x63, 0x47, 0x78, 0x6c, 0x59, 0x58, 0x4e, 0x31, 0x63, 0x6d,
 0x55, 0x75, 0x18, 0x40, 0xd8, 0x22, 0x68, 0x63, 0x33, 0x56,
 0x79, 0x5a, 0x53, 0x34, 0x3d, 0x64, 0x70, 0x6f, 0x70, 0x6f,
 0xd8, 0x23, 0x68, 0x31, 0x30, 0x30, 0x5c, 0x73, 0x2a, 0x6d,
 0x6b, 0x38, 0x32, 0xd8, 0x23, 0x66, 0x70, 0x65, 0x72, 0x6c,
 0x5c, 0x42, 0x63, 0x4e, 0x65, 0x64, 0xd9, 0x01, 0x01, 0x59, 0x01,
 0x57, 0x4d, 0x49, 0x4d, 0x45, 0x2d, 0x56, 0x65, 0x72, 0x73,
 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x31, 0x2e, 0x30, 0x0a, 0x43,
 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70,
 0x65, 0x3a, 0x20, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x70, 0x61,
 0x72, 0x74, 0x2f, 0x6d, 0x69, 0x78, 0x65, 0x64, 0x3b, 0x0a,
 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x3d, 0x22,
 0x58, 0x58, 0x58, 0x58, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61,
 0x72, 0x79, 0x20, 0x74, 0x65, 0x78, 0x74, 0x22, 0x0a, 0x0a,
 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20,
 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x70, 0x61, 0x72, 0x74, 0x20,
 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x69, 0x6e,
 0x20, 0x4d, 0x49, 0x4d, 0x45, 0x20, 0x66, 0x6f, 0x72, 0x6d,
 0x61, 0x74, 0x2e, 0x0a, 0x0a, 0x2d, 0x2d, 0x58, 0x58, 0x58,
 0x58, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20,
 0x74, 0x65, 0x78, 0x74, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65,
 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x74,
 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x0a,
 0x0a, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
 0x68, 0x65, 0x20, 0x62, 0x6f, 0x64, 0x79, 0x20, 0x74, 0x65,
 0x78, 0x74, 0x0a, 0x0a, 0x2d, 0x2d, 0x58, 0x58, 0x58, 0x58,
 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x74,
 0x65, 0x78, 0x74, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x74, 0x65,
 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x3b, 0x0a,
 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x44, 0x69,
 0x73, 0x70, 0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x3a,
 0x20, 0x61, 0x74, 0x74, 0x61, 0x63, 0x68, 0x6d, 0x65, 0x6e,
 0x74, 0x3b, 0x0a, 0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d,
 0x65, 0x3d, 0x22, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78,
 0x74, 0x22, 0x0a, 0x0a, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69,
 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x74, 0x74, 0x61,
 0x63, 0x68, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x74, 0x65, 0x78,
 0x74, 0x0a, 0x0a, 0x2d, 0x2d, 0x58, 0x58, 0x58, 0x58, 0x62,
 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x74, 0x65,
 0x78, 0x74, 0x2d, 0x2d, 0x0a, 0xd9, 0x01, 0x01, 0x59, 0x01, 0x57,
 0x4d, 0x49, 0x4d, 0x45, 0x2d, 0x56, 0x65, 0x72, 0x73, 0x69,
 0x6f, 0x6e, 0x3a, 0x20, 0x31, 0x2e, 0x30, 0x0a, 0x43, 0x6f,
 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65,
 0x3a, 0x20, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x70, 0x61, 0x72,
 0x74, 0x2f, 0x6d, 0x69, 0x78, 0x65, 0x64, 0x3b, 0x0a, 0x62,
 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x3d, 0x22, 0x58,
 0x58, 0x58, 0x58, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72,
 0x79, 0x20, 0x74, 0x65, 0x78, 0x74, 0x22, 0x0a, 0x0a, 0x54,
 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x6d,
 0x75, 0x6c, 0x74, 0x69, 0x70, 0x61, 0x72, 0x74, 0x20, 0x6d,
 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x69, 0x6e, 0x20,
 0x4d, 0x49, 0x4d, 0x45, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61,
 0x74, 0x2e, 0x0a, 0x0a, 0x2d, 0x2d, 0x58, 0x58, 0x58, 0x58,
 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x74,
 0x65, 0x78, 0x74, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x74, 0x65,
 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x0a, 0x0a,
 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
 0x65, 0x20, 0x62, 0x6f, 0x64, 0x79, 0x20, 0x74, 0x65, 0x78,
 0x74, 0x0a, 0x0a, 0x2d, 0x2d, 0x58, 0x58, 0x58, 0x58, 0x62,
 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x74, 0x65,
 0x78, 0x74, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x74, 0x65, 0x78,
 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x3b, 0x0a, 0x43,
 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x44, 0x69, 0x73,
 0x70, 0x6f, 0x73, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20,
 0x61, 0x74, 0x74, 0x61, 0x63, 0x68, 0x6d, 0x65, 0x6e, 0x74,
 0x3b, 0x0a, 0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65,
 0x3d, 0x22, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x74, 0x78, 0x74,
 0x22, 0x0a, 0x0a, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73,
 0x20, 0x74, 0x68, 0x65, 0x20, 0x61, 0x74, 0x74, 0x61, 0x63,
 0x68, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x74, 0x65, 0x78, 0x74,
 0x0a, 0x0a, 0x2d, 0x2d, 0x58, 0x58, 0x58, 0x58, 0x62, 0x6f,
 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x20, 0x74, 0x65, 0x78,
 0x74, 0x2d, 0x2d, 0xc0, 0x74, 0x32, 0x30, 0x30, 0x33, 0x2d,
 0x31, 0x32, 0x2d, 0x31, 0x33, 0x54, 0x31, 0x38, 0x3a, 0x33,
 0x30, 0x3a, 0x30, 0x32, 0x5a, 0xa2, 0x68, 0x42, 0x65, 0x64,
 0x20, 0x74, 0x69, 0x6d, 0x65, 0xc0, 0x78, 0x1c, 0x32, 0x30,
 0x30, 0x33, 0x2d, 0x31, 0x32, 0x2d, 0x31, 0x33, 0x54, 0x31,
 0x38, 0x3a, 0x33, 0x30, 0x3a, 0x30, 0x32, 0x2e, 0x32, 0x35,
 0x2b, 0x30, 0x31, 0x3a, 0x30, 0x30, 0x18, 0x58, 0xc0, 0x78,
 0x1c, 0x32, 0x30, 0x30, 0x33, 0x2d, 0x31, 0x32, 0x2d, 0x31,
 0x33, 0x54, 0x31, 0x38, 0x3a, 0x33, 0x30, 0x3a, 0x30, 0x32,
 0x2e, 0x32, 0x35, 0x2b, 0x30, 0x31, 0x3a, 0x30, 0x30, 0xf7,
 0xa3, 0x64, 0x64, 0x61, 0x72, 0x65, 0xd8, 0x42, 0xf5, 0x62,
 0x75, 0x75, 0xf4, 0x1a, 0x00, 0x0b, 0x41, 0x62, 0xf6, 0x80,
 0xa3, 0x78, 0x1c, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x20, 0x61,
 0x6e, 0x64, 0x20, 0x74, 0x61, 0x67, 0x67, 0x65, 0x64, 0x20,
 0x65, 0x6d, 0x70, 0x74, 0x79, 0x20, 0x61, 0x72, 0x72, 0x61,
 0x79, 0xd9, 0x04, 0x45, 0x80, 0x65, 0x61, 0x6c, 0x61, 0x62,
 0x6c, 0x80, 0x18, 0x2a, 0x80, 0xa1, 0x68, 0x69, 0x6e, 0x20,
 0x61, 0x20, 0x6d, 0x61, 0x70, 0xa1, 0x19, 0x15, 0xb4, 0xa1,
 0x6e, 0x69, 0x6e, 0x20, 0x61, 0x20, 0x69, 0x6e, 0x20, 0x61,
 0x20, 0x69, 0x6e, 0x20, 0x61, 0xd9, 0x23, 0x7f, 0xa0, 0xa5,
 0x62, 0x73, 0x31, 0xd8, 0x58, 0xf8, 0xff, 0x62, 0x73, 0x32,
 0xe0, 0x62, 0x73, 0x33, 0xd8, 0x58, 0xf8, 0x21, 0x1a, 0x05,
 0x44, 0x8c, 0x06, 0xd8, 0x58, 0xf8, 0xff, 0x18, 0x59, 0xd8,
 0x58, 0xf3, 0xd8, 0x25, 0x50, 0x53, 0x4d, 0x41, 0x52, 0x54,
 0x43, 0x53, 0x4c, 0x54, 0x54, 0x43, 0x46, 0x49, 0x43, 0x41,
 0x32, 0xa2, 0x64, 0x55, 0x55, 0x55, 0x55, 0xd8, 0x25, 0x50,
 0x53, 0x4d, 0x41, 0x52, 0x54, 0x43, 0x53, 0x4c, 0x54, 0x54,
 0x43, 0x46, 0x49, 0x43, 0x41, 0x32, 0x18, 0x63, 0xd8, 0x25,
 0x50, 0x53, 0x4d, 0x41, 0x52, 0x54, 0x43, 0x53, 0x4c, 0x54,
 0x54, 0x43, 0x46, 0x49, 0x43, 0x41, 0x32, 0xf5, 0xf4, 0xa2,
 0x71, 0x47, 0x65, 0x6f, 0x72, 0x67, 0x65, 0x20, 0x69, 0x73,
 0x20, 0x74, 0x68, 0x65, 0x20, 0x6d, 0x61, 0x6e, 0xf5, 0x19,
 0x10, 0x41, 0xf5, 0xC2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0xC3, 0x49, 0x01, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0xA4, 0x63, 0x42, 0x4E, 0x2B,
 0xC2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x18, 0x40, 0xC2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x63, 0x42, 0x4E, 0x2D, 0xC3, 0x49,
 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38,
 0x3F, 0xC3, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00
};

static const char *szMIME = "\
MIME-Version: 1.0\n\
Content-Type: multipart/mixed;\n\
boundary=\"XXXXboundary text\"\n\
\n\
This is a multipart message in MIME format.\n\
\n\
--XXXXboundary text\n\
Content-Type: text/plain\n\
\n\
this is the body text\n\
\n\
--XXXXboundary text\n\
Content-Type: text/plain;\n\
Content-Disposition: attachment;\n\
filename=\"test.txt\"\n\
\n\
this is the attachment text\n\
\n\
--XXXXboundary text--";


static void AddAll(QCBOREncodeContext *pECtx)
{
   /* This calls a mix of deprecated and non-deprecated to test both.
    * Sometimes only deprecated because the deprecated calls the
    * non-deprecated */
   QCBOREncode_OpenArray(pECtx);

   /* Some ints that are tagged and have strings preceeding them
    * (not labels becase it is not a map) */
   QCBOREncode_AddSZString(pECtx, "UINT62");
   QCBOREncode_AddTagNumber(pECtx, 100);
   QCBOREncode_AddUInt64(pECtx, 89989909);
   QCBOREncode_AddSZString(pECtx, "INT64");
   QCBOREncode_AddTagNumber(pECtx, 76);
   QCBOREncode_AddInt64(pECtx, 77689989909);
   QCBOREncode_AddUInt64(pECtx, 0);
   QCBOREncode_AddInt64(pECtx, -44);

   /* ints that go in maps */
   QCBOREncode_OpenMap(pECtx);
   QCBOREncode_AddUInt64ToMap(pECtx, "LBL", 77);
   QCBOREncode_AddUInt64ToMapN(pECtx, -4, 88);
   QCBOREncode_AddInt64ToMap(pECtx, "NEGLBLTHAT IS KIND OF LONG", -2394893489238);
   QCBOREncode_AddInt64ToMapN(pECtx, -100000000, -800000000);
   QCBOREncode_CloseMap(pECtx);

   /* Epoch Date */
   QCBOREncode_AddDateEpoch(pECtx, 2383748234);

   /* Epoch date with labels */
   QCBOREncode_OpenMap(pECtx);
   QCBOREncode_AddDateEpochToMap(pECtx, "LongLiveDenisRitchie", 1400000000);
   QCBOREncode_AddTDateEpochToMapSZ(pECtx, "time()", QCBOR_ENCODE_AS_TAG, 1477263730);
   QCBOREncode_AddDateEpochToMapN(pECtx, -1969, 1477263222);
   QCBOREncode_CloseMap(pECtx);

   /* Binary blobs */
   QCBOREncode_AddBytes(pECtx, ((UsefulBufC) {(uint8_t []){0xff, 0x00}, 2}));

   /* binary blobs in maps */
   QCBOREncode_OpenMap(pECtx);
   QCBOREncode_AddSZString(pECtx, "binbin");
   QCBOREncode_AddTagNumber(pECtx, 100000);
   QCBOREncode_AddBytes(pECtx, ((UsefulBufC) {(uint8_t []){0x00}, 1}));
   QCBOREncode_AddBytesToMap(pECtx, "empty", NULLUsefulBufC); // Empty string
   QCBOREncode_AddBytesToMapSZ(pECtx, "blabel", ((UsefulBufC) {(uint8_t []){0x01, 0x02, 0x03}, 3}));
   QCBOREncode_AddBytesToMapN(pECtx, 0, ((UsefulBufC){(uint8_t []){0x04, 0x02, 0x03, 0xfe}, 4}));
   QCBOREncode_CloseMap(pECtx);

   /* text blobs */
   QCBOREncode_AddText(pECtx, UsefulBuf_FROM_SZ_LITERAL("bar bar foo bar"));
   QCBOREncode_AddSZString(pECtx, "oof\n");
   QCBOREncode_AddText(pECtx, NULLUsefulBufC); // Empty string

   const char *szURL =
    "http://stackoverflow.com/questions/28059697/how-do-i-toggle-between-debug-and-release-builds-in-xcode-6-7-8";
   QCBOREncode_AddURI(pECtx, UsefulBuf_FromSZ(szURL));
   QCBOREncode_AddB64Text(pECtx, UsefulBuf_FROM_SZ_LITERAL("YW55IGNhcm5hbCBwbGVhc3VyZQ=="));
   QCBOREncode_AddRegex(pECtx, UsefulBuf_FROM_SZ_LITERAL("[^abc]+"));
   QCBOREncode_AddMIMEData(pECtx, UsefulBuf_FromSZ(szMIME));

   /* text blobs in maps */
   QCBOREncode_OpenMap(pECtx);
   QCBOREncode_AddTextToMap(pECtx, "#####", UsefulBuf_FROM_SZ_LITERAL("foo bar foo foo"));
   QCBOREncode_AddTextToMapSZ(pECtx, "____", UsefulBuf_FROM_SZ_LITERAL("foo bar"));
   QCBOREncode_AddSZString(pECtx, "()()()");
   QCBOREncode_AddTag(pECtx, 1000);
   QCBOREncode_AddSZString(pECtx, "rab rab oof");
   QCBOREncode_AddTextToMapN(pECtx,22, UsefulBuf_FROM_SZ_LITERAL("foo foo foo foo"));
   QCBOREncode_AddSZStringToMap(pECtx, "^^", "oooooooof");
   QCBOREncode_AddSZStringToMapN(pECtx, 99, "ffffoooooooof");
   QCBOREncode_AddURIToMap(pECtx,
                           "RFC",
                           UsefulBuf_FROM_SZ_LITERAL("https://tools.ietf.org/html/rfc7049#section-2.4.5"));
   QCBOREncode_AddURIToMapN(pECtx, 0x89, UsefulBuf_FROM_SZ_LITERAL("http://cbor.me/"));
   QCBOREncode_AddB64TextToMap(pECtx, "whenim64", UsefulBuf_FROM_SZ_LITERAL("cGxlYXN1cmUu"));
   QCBOREncode_AddB64TextToMapN(pECtx, 64, UsefulBuf_FROM_SZ_LITERAL("c3VyZS4="));
   QCBOREncode_AddRegexToMap(pECtx, "popo", UsefulBuf_FROM_SZ_LITERAL("100\\s*mk")); //   x code string literal bug
   QCBOREncode_AddRegexToMapN(pECtx, -51, UsefulBuf_FROM_SZ_LITERAL("perl\\B"));  //   x code string literal bug
   QCBOREncode_AddMIMEDataToMap(pECtx, "Ned", UsefulBuf_FromSZ(szMIME));
   QCBOREncode_AddMIMEDataToMapN(pECtx, 10, UsefulBuf_FromSZ(szMIME));
   QCBOREncode_CloseMap(pECtx);

   /* Date strings */
   QCBOREncode_AddDateString(pECtx, "2003-12-13T18:30:02Z");
   QCBOREncode_OpenMap(pECtx);
   QCBOREncode_AddDateStringToMap(pECtx, "Bed time", "2003-12-13T18:30:02.25+01:00");
   QCBOREncode_AddDateStringToMapN(pECtx, 88, "2003-12-13T18:30:02.25+01:00");
   QCBOREncode_CloseMap(pECtx);

   /* true / false ... */
   QCBOREncode_AddUndef(pECtx);
   QCBOREncode_OpenMap(pECtx);
   QCBOREncode_AddSZString(pECtx, "dare");
   QCBOREncode_AddTagNumber(pECtx, 66);
   QCBOREncode_AddBool(pECtx, true);
   QCBOREncode_AddBoolToMap(pECtx, "uu", false);
   QCBOREncode_AddNULLToMapN(pECtx, 737634);
   QCBOREncode_CloseMap(pECtx);

   /* opening an array */
   QCBOREncode_OpenArray(pECtx);
   QCBOREncode_CloseArray(pECtx);

   /* opening arrays in a map */
   QCBOREncode_OpenMap(pECtx);
   QCBOREncode_AddSZString(pECtx, "label and tagged empty array");
   QCBOREncode_AddTagNumber(pECtx, 1093);
   QCBOREncode_OpenArray(pECtx);
   QCBOREncode_CloseArray(pECtx);
   QCBOREncode_OpenArrayInMap(pECtx, "alabl");
   QCBOREncode_CloseArray(pECtx);
   QCBOREncode_OpenArrayInMapN(pECtx, 42);
   QCBOREncode_CloseArray(pECtx);
   QCBOREncode_CloseMap(pECtx);

   /* opening maps with labels and tagging */
   QCBOREncode_OpenMap(pECtx);
   QCBOREncode_OpenMapInMap(pECtx, "in a map");
   QCBOREncode_OpenMapInMapN(pECtx, 5556);
   QCBOREncode_AddSZString(pECtx, "in a in a in a");
   QCBOREncode_AddTagNumber(pECtx, 9087);
   QCBOREncode_OpenMap(pECtx);
   QCBOREncode_CloseMap(pECtx);
   QCBOREncode_CloseMap(pECtx);
   QCBOREncode_CloseMap(pECtx);
   QCBOREncode_CloseMap(pECtx);

   /* Extended simple values (these are not standard...) */
   QCBOREncode_OpenMap(pECtx);
   QCBOREncode_AddSZString(pECtx, "s1");
   QCBOREncode_AddTag(pECtx, 88);
   QCBOREncode_AddSimple(pECtx, 255);
   QCBOREncode_AddSimpleToMap(pECtx, "s2", 0);
   QCBOREncode_AddSZString(pECtx, "s3");
   QCBOREncode_AddTag(pECtx, 88);
   QCBOREncode_AddSimple(pECtx, 33);
   QCBOREncode_AddInt64(pECtx, 88378374); // label before tag
   QCBOREncode_AddTag(pECtx, 88);
   QCBOREncode_AddSimple(pECtx, 255);
   QCBOREncode_AddInt64(pECtx, 89); // label before tag
   QCBOREncode_AddTag(pECtx, 88);
   QCBOREncode_AddSimple(pECtx, 19);
   QCBOREncode_CloseMap(pECtx);

   /* UUIDs */
   static const uint8_t ppppUUID[] = {0x53, 0x4D, 0x41, 0x52, 0x54, 0x43,
                                      0x53, 0x4C, 0x54, 0x54, 0x43, 0x46,
                                      0x49, 0x43, 0x41, 0x32};
   const UsefulBufC XXUUID = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(ppppUUID);
   QCBOREncode_AddBinaryUUID(pECtx, XXUUID);
   QCBOREncode_OpenMap(pECtx);
   QCBOREncode_AddBinaryUUIDToMap(pECtx, "UUUU", XXUUID);
   QCBOREncode_AddBinaryUUIDToMapN(pECtx, 99, XXUUID);
   QCBOREncode_CloseMap(pECtx);

   /* Bool */
   QCBOREncode_AddBool(pECtx, true);
   QCBOREncode_AddBool(pECtx, false);
   QCBOREncode_OpenMap(pECtx);
   QCBOREncode_AddBoolToMapSZ(pECtx, "George is the man", true);
   QCBOREncode_AddBoolToMapN(pECtx, 010101, true);
   QCBOREncode_CloseMap(pECtx);


   /* Big numbers */
   static const uint8_t pBignum[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
   const UsefulBufC BIGNUM = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pBignum);
   QCBOREncode_AddPositiveBignum(pECtx, BIGNUM);
   QCBOREncode_AddNegativeBignum(pECtx, BIGNUM);
   QCBOREncode_OpenMap(pECtx);
   QCBOREncode_AddPositiveBignumToMap(pECtx, "BN+", BIGNUM);
   QCBOREncode_AddPositiveBignumToMapN(pECtx, 64, BIGNUM);
   QCBOREncode_AddNegativeBignumToMap(pECtx, "BN-", BIGNUM);
   QCBOREncode_AddNegativeBignumToMapN(pECtx, -64, BIGNUM);
   QCBOREncode_CloseMap(pECtx);

   QCBOREncode_CloseArray(pECtx);
}


int32_t AllAddMethodsTest(void)
{
   /* Improvement: this test should be broken down into several so it is more
    * managable. Tags and labels could be more sensible */
   QCBOREncodeContext ECtx;
   UsefulBufC         Enc;
   size_t             size;
   int                nReturn;
   QCBORError         uExpectedErr;

   nReturn = 0;

   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_Config(&ECtx, QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);

   AddAll(&ECtx);

   if(QCBOREncode_Finish(&ECtx, &Enc)) {
      nReturn = -1;
      goto Done;
   }

   if(CheckResults(Enc, spExpectedEncodedAll)) {
      nReturn = -2;
      goto Done;
   }


   /* Also test size calculation */
   QCBOREncode_Init(&ECtx, SizeCalculateUsefulBuf);
   QCBOREncode_Config(&ECtx, QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);

   AddAll(&ECtx);

   if(QCBOREncode_FinishGetSize(&ECtx, &size)) {
      nReturn = -10;
      goto Done;
   }

   if(size != sizeof(spExpectedEncodedAll)) {
      nReturn = -11;
      goto Done;
   }

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   uExpectedErr = QCBOR_ERR_NOT_ALLOWED;
#else
   uExpectedErr = QCBOR_SUCCESS;
#endif


#if !defined(QCBOR_DISABLE_ENCODE_USAGE_GUARDS) && !defined(QCBOR_DISABLE_PREFERRED_FLOAT)
   uExpectedErr = QCBOR_ERR_NOT_ALLOWED;
#else
   uExpectedErr = QCBOR_SUCCESS;
#endif

#ifndef USEFULBUF_DISABLE_ALL_FLOAT
   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   /* 0x7ff8000000000001ULL is a NaN with a payload. */
   QCBOREncode_AddDouble(&ECtx, UsefulBufUtil_CopyUint64ToDouble(0x7ff8000000000001ULL));
   if(QCBOREncode_Finish(&ECtx, &Enc) != uExpectedErr) {
      nReturn = -22;
      goto Done;
   }


   /* 0x7ffc000000000000ULL is a NaN with a payload. */
   QCBOREncode_AddDouble(&ECtx, UsefulBufUtil_CopyUint64ToDouble(0x7ff8000000000001ULL));
   if(QCBOREncode_Finish(&ECtx, &Enc) != uExpectedErr) {
      nReturn = -23;
      goto Done;
   }

   /* 0x7ff80001UL is a NaN with a payload. */
   QCBOREncode_AddFloat(&ECtx, UsefulBufUtil_CopyUint32ToFloat(0x7ff80001UL));
   if(QCBOREncode_Finish(&ECtx, &Enc) != uExpectedErr) {
      nReturn = -24;
      goto Done;
   }

   /* 0x7ffc0000UL is a NaN with a payload. */
   QCBOREncode_AddFloat(&ECtx, UsefulBufUtil_CopyUint32ToFloat(0x7ffc0000UL));
   if(QCBOREncode_Finish(&ECtx, &Enc) != uExpectedErr) {
      nReturn = -25;
      goto Done;
   }
#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT */

Done:
   return nReturn;
}


/*
 98 30                  # array(48)
   3B 7FFFFFFFFFFFFFFF # negative(9223372036854775807)
   3B 0000000100000000 # negative(4294967296)
   3A FFFFFFFF         # negative(4294967295)
   3A FFFFFFFE         # negative(4294967294)
   3A FFFFFFFD         # negative(4294967293)
   3A 7FFFFFFF         # negative(2147483647)
   3A 7FFFFFFE         # negative(2147483646)
   3A 00010001         # negative(65537)
   3A 00010000         # negative(65536)
   39 FFFF             # negative(65535)
   39 FFFE             # negative(65534)
   39 FFFD             # negative(65533)
   39 0100             # negative(256)
   38 FF               # negative(255)
   38 FE               # negative(254)
   38 FD               # negative(253)
   38 18               # negative(24)
   37                  # negative(23)
   36                  # negative(22)
   20                  # negative(0)
   00                  # unsigned(0)
   00                  # unsigned(0)
   01                  # unsigned(1)
   16                  # unsigned(22)
   17                  # unsigned(23)
   18 18               # unsigned(24)
   18 19               # unsigned(25)
   18 1A               # unsigned(26)
   18 1F               # unsigned(31)
   18 FE               # unsigned(254)
   18 FF               # unsigned(255)
   19 0100             # unsigned(256)
   19 0101             # unsigned(257)
   19 FFFE             # unsigned(65534)
   19 FFFF             # unsigned(65535)
   1A 00010000         # unsigned(65536)
   1A 00010001         # unsigned(65537)
   1A 00010002         # unsigned(65538)
   1A 7FFFFFFF         # unsigned(2147483647)
   1A 7FFFFFFF         # unsigned(2147483647)
   1A 80000000         # unsigned(2147483648)
   1A 80000001         # unsigned(2147483649)
   1A FFFFFFFE         # unsigned(4294967294)
   1A FFFFFFFF         # unsigned(4294967295)
   1B 0000000100000000 # unsigned(4294967296)
   1B 0000000100000001 # unsigned(4294967297)
   1B 7FFFFFFFFFFFFFFF # unsigned(9223372036854775807)
   1B FFFFFFFFFFFFFFFF # unsigned(18446744073709551615)
 */
static const uint8_t spExpectedEncodedInts[] = {
   0x98, 0x30, 0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff, 0xff, 0x3b, 0x00, 0x00, 0x00, 0x01,
   0x00, 0x00, 0x00, 0x00, 0x3a, 0xff, 0xff, 0xff,
   0xff, 0x3a, 0xff, 0xff, 0xff, 0xfe, 0x3a, 0xff,
   0xff, 0xff, 0xfd, 0x3a, 0x7f, 0xff, 0xff, 0xff,
   0x3a, 0x7f, 0xff, 0xff, 0xfe, 0x3a, 0x00, 0x01,
   0x00, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x39,
   0xff, 0xff, 0x39, 0xff, 0xfe, 0x39, 0xff, 0xfd,
   0x39, 0x01, 0x00, 0x38, 0xff, 0x38, 0xfe, 0x38,
   0xfd, 0x38, 0x18, 0x37, 0x36, 0x20, 0x00, 0x00,
   0x01, 0x16, 0x17, 0x18, 0x18, 0x18, 0x19, 0x18,
   0x1a, 0x18, 0x1f, 0x18, 0xfe, 0x18, 0xff, 0x19,
   0x01, 0x00, 0x19, 0x01, 0x01, 0x19, 0xff, 0xfe,
   0x19, 0xff, 0xff, 0x1a, 0x00, 0x01, 0x00, 0x00,
   0x1a, 0x00, 0x01, 0x00, 0x01, 0x1a, 0x00, 0x01,
   0x00, 0x02, 0x1a, 0x7f, 0xff, 0xff, 0xff, 0x1a,
   0x7f, 0xff, 0xff, 0xff, 0x1a, 0x80, 0x00, 0x00,
   0x00, 0x1a, 0x80, 0x00, 0x00, 0x01, 0x1a, 0xff,
   0xff, 0xff, 0xfe, 0x1a, 0xff, 0xff, 0xff, 0xff,
   0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
   0x00, 0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
   0x00, 0x01, 0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff, 0xff, 0x1b, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff, 0xff, 0xff};

/*

  Test the generation of integers. This also ends up testing
  encoding of all the different lengths. It encodes integers
  of many lengths and values, especially around the boundaries
  for different types of integers.  It compares the output
  to expected values generated from http://cbor.me.

 */
int32_t IntegerValuesTest1(void)
{
   QCBOREncodeContext ECtx;
   int nReturn = 0;

   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_OpenArray(&ECtx);

   QCBOREncode_AddInt64(&ECtx, -9223372036854775807LL - 1);
   QCBOREncode_AddInt64(&ECtx, -4294967297);
   QCBOREncode_AddInt64(&ECtx, -4294967296);
   QCBOREncode_AddInt64(&ECtx, -4294967295);
   QCBOREncode_AddInt64(&ECtx, -4294967294);
   QCBOREncode_AddInt64(&ECtx, -2147483648);
   QCBOREncode_AddInt64(&ECtx, -2147483647);
   QCBOREncode_AddInt64(&ECtx, -65538);
   QCBOREncode_AddInt64(&ECtx, -65537);
   QCBOREncode_AddInt64(&ECtx, -65536);
   QCBOREncode_AddInt64(&ECtx, -65535);
   QCBOREncode_AddInt64(&ECtx, -65534);
   QCBOREncode_AddInt64(&ECtx, -257);
   QCBOREncode_AddInt64(&ECtx, -256);
   QCBOREncode_AddInt64(&ECtx, -255);
   QCBOREncode_AddInt64(&ECtx, -254);
   QCBOREncode_AddInt64(&ECtx, -25);
   QCBOREncode_AddInt64(&ECtx, -24);
   QCBOREncode_AddInt64(&ECtx, -23);
   QCBOREncode_AddInt64(&ECtx, -1);
   QCBOREncode_AddInt64(&ECtx, 0);
   QCBOREncode_AddUInt64(&ECtx, 0ULL);
   QCBOREncode_AddInt64(&ECtx, 1);
   QCBOREncode_AddInt64(&ECtx, 22);
   QCBOREncode_AddInt64(&ECtx, 23);
   QCBOREncode_AddInt64(&ECtx, 24);
   QCBOREncode_AddInt64(&ECtx, 25);
   QCBOREncode_AddInt64(&ECtx, 26);
   QCBOREncode_AddInt64(&ECtx, 31);
   QCBOREncode_AddInt64(&ECtx, 254);
   QCBOREncode_AddInt64(&ECtx, 255);
   QCBOREncode_AddInt64(&ECtx, 256);
   QCBOREncode_AddInt64(&ECtx, 257);
   QCBOREncode_AddInt64(&ECtx, 65534);
   QCBOREncode_AddInt64(&ECtx, 65535);
   QCBOREncode_AddInt64(&ECtx, 65536);
   QCBOREncode_AddInt64(&ECtx, 65537);
   QCBOREncode_AddInt64(&ECtx, 65538);
   QCBOREncode_AddInt64(&ECtx, 2147483647);
   QCBOREncode_AddInt64(&ECtx, 2147483647);
   QCBOREncode_AddInt64(&ECtx, 2147483648);
   QCBOREncode_AddInt64(&ECtx, 2147483649);
   QCBOREncode_AddInt64(&ECtx, 4294967294);
   QCBOREncode_AddInt64(&ECtx, 4294967295);
   QCBOREncode_AddInt64(&ECtx, 4294967296);
   QCBOREncode_AddInt64(&ECtx, 4294967297);
   QCBOREncode_AddInt64(&ECtx, 9223372036854775807LL);
   QCBOREncode_AddUInt64(&ECtx, 18446744073709551615ULL);

   QCBOREncode_CloseArray(&ECtx);

   UsefulBufC Enc;
   if(QCBOREncode_Finish(&ECtx, &Enc)) {
      nReturn = -1;
   }

   if(CheckResults(Enc, spExpectedEncodedInts))
     return -2;

   return(nReturn);
}

struct BigNumEncodeTest {
   const char *szDescription;
   UsefulBufC  BigNum;
   /* Expect all to succeed; no special error codes needed */
   UsefulBufC  PositiveNoPreferred;
   UsefulBufC  PositivePreferred;
   UsefulBufC  NegativeNoPreferred;
   UsefulBufC  NegativePreferred;
};

struct BigNumEncodeTest BigNumEncodeTestCases[] = {
   {
      "2^96 -1 or 79228162514264337593543950335 pos and neg with leading zeros",
      {"\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 15},
      {"\xC2\x4C\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 14},
      {"\xC2\x4C\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 14},
      {"\xC3\x4C\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe", 14},
      {"\xC3\x4C\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe", 14},
   },

   {
      "2^64+1 or 18446744073709551617 pos and neg)",
      {"\x01\x00\x00\x00\x00\x00\x00\x00\x01", 9},
      {"\xC2\x49\x01\x00\x00\x00\x00\x00\x00\x00\x01", 11},
      {"\xC2\x49\x01\x00\x00\x00\x00\x00\x00\x00\x01", 11},
      {"\xC3\x49\x01\x00\x00\x00\x00\x00\x00\x00\x00", 11},
      {"\xC3\x49\x01\x00\x00\x00\x00\x00\x00\x00\x00", 11},
   },
   {
      "2^64 or 18446744073709551616 pos and neg)",
      {"\x01\x00\x00\x00\x0000\x00\x00\x00", 9},
      {"\xC2\x49\x01\x00\x00\x00\x00\x00\x00\x00\x00", 11},
      {"\xC2\x49\x01\x00\x00\x00\x00\x00\x00\x00\x00", 11},
      {"\xC3\x48\xff\xff\xff\xff\xff\xff\xff\xff", 10},
      {"\x3B\xff\xff\xff\xff\xff\xff\xff\xff", 9},
   },
   {
      "2^64 - 1 or 18446744073709551615 pos and neg",
      {"\xff\xff\xff\xff\xff\xff\xff\xff", 8},
      {"\xC2\x48\xff\xff\xff\xff\xff\xff\xff\xff", 10},
      {"\x1B\xff\xff\xff\xff\xff\xff\xff\xff", 9},
      {"\xC3\x48\xff\xff\xff\xff\xff\xff\xff\xfe", 10},
      {"\x3B\xff\xff\xff\xff\xff\xff\xff\xfe", 9},
   },
   {
      "1 and -1",
      {"\x01", 1},
      {"\xC2\x41\x01", 3},
      {"\x01", 1},
      {"\xC3\x41\x00", 3},
      {"\x20", 1},
   },
   {
      "0 and error for no negative 0",
      {"\x00", 1},
      {"\xC2\x41\x00", 3},
      {"\x00", 1},
      NULLUsefulBufC,
      NULLUsefulBufC,
   },
   {
      "leading zeros -- 0 and error for no negative 0",
      {"\x00\x00\x00\x00", 4},
      {"\xC2\x41\x00", 3},
      {"\x00", 1},
      NULLUsefulBufC,
      NULLUsefulBufC,
   }

};


int32_t BigNumEncodeTests(void)
{
   unsigned           uTestIndex;
   unsigned           uTestCount;
   QCBOREncodeContext Enc;
   UsefulBufC         EncodedBigNumber;

   uTestCount = (int)C_ARRAY_COUNT(BigNumEncodeTestCases, struct BigNumEncodeTest);

   for(uTestIndex = 0; uTestIndex < uTestCount; uTestIndex++) {
      const struct BigNumEncodeTest *pTest = &BigNumEncodeTestCases[uTestIndex];

      if(uTestIndex == 6) {
         EncodedBigNumber.len = 0; /* Line of code so a break point can be set. */
      }

      QCBOREncode_Init(&Enc, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
      QCBOREncode_AddTBigNumberNoPreferred(&Enc, QCBOR_ENCODE_AS_TAG, false, pTest->BigNum);
      QCBOREncode_Finish(&Enc, &EncodedBigNumber);
      if(UsefulBuf_Compare(EncodedBigNumber, pTest->PositiveNoPreferred)) {
         return MakeTestResultCode(uTestIndex, 1, QCBOR_SUCCESS);
      }

      QCBOREncode_Init(&Enc, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
      QCBOREncode_AddTBigNumber(&Enc, QCBOR_ENCODE_AS_TAG, false, pTest->BigNum);
      QCBOREncode_Finish(&Enc, &EncodedBigNumber);
      if(UsefulBuf_Compare(EncodedBigNumber, pTest->PositivePreferred)) {
         return MakeTestResultCode(uTestIndex, 2, QCBOR_SUCCESS);
      }

      if(!UsefulBuf_IsNULLC(pTest->NegativeNoPreferred)){
         QCBOREncode_Init(&Enc, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
         QCBOREncode_AddTBigNumberNoPreferred(&Enc, QCBOR_ENCODE_AS_TAG, true, pTest->BigNum);
         QCBOREncode_Finish(&Enc, &EncodedBigNumber);
         if(UsefulBuf_Compare(EncodedBigNumber, pTest->NegativeNoPreferred)) {
            return MakeTestResultCode(uTestIndex, 3, QCBOR_SUCCESS);
         }
      }

      if(!UsefulBuf_IsNULLC(pTest->NegativePreferred)){
         QCBOREncode_Init(&Enc, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
         QCBOREncode_AddTBigNumber(&Enc, QCBOR_ENCODE_AS_TAG, true, pTest->BigNum);
         QCBOREncode_Finish(&Enc, &EncodedBigNumber);
         if(UsefulBuf_Compare(EncodedBigNumber, pTest->NegativePreferred)) {
            return MakeTestResultCode(uTestIndex, 4, QCBOR_SUCCESS);
         }
      }
   }

   return 0;
}


/*
 85                  # array(5)
   F5               # primitive(21)
   F4               # primitive(20)
   F6               # primitive(22)
   F7               # primitive(23)
   A1               # map(1)
      65            # text(5)
         554E446566 # "UNDef"
      F7            # primitive(23)
 */
static const uint8_t spExpectedEncodedSimple[] = {
   0x85, 0xf5, 0xf4, 0xf6, 0xf7, 0xa1, 0x65, 0x55, 0x4e, 0x44, 0x65, 0x66, 0xf7};

int32_t SimpleValuesTest1(void)
{
   QCBOREncodeContext ECtx;
   int nReturn = 0;

   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_OpenArray(&ECtx);

   QCBOREncode_AddBool(&ECtx, true);
   QCBOREncode_AddBool(&ECtx, false);
   QCBOREncode_AddNULL(&ECtx);
   QCBOREncode_AddUndef(&ECtx);

   QCBOREncode_OpenMap(&ECtx);

   QCBOREncode_AddUndefToMapSZ(&ECtx, "UNDef");
   QCBOREncode_CloseMap(&ECtx);

   QCBOREncode_CloseArray(&ECtx);

   UsefulBufC ECBOR;
   if(QCBOREncode_Finish(&ECtx, &ECBOR)) {
      nReturn = -1;
   }

   if(CheckResults(ECBOR, spExpectedEncodedSimple))
      return -2;

   return(nReturn);
}

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
/*
 9F                  # array(5)
   F5               # primitive(21)
   F4               # primitive(20)
   F6               # primitive(22)
   F7               # primitive(23)
   BF               # map(1)
      65            # text(5)
         554E446566 # "UNDef"
      F7            # primitive(23)
      FF            # break
   FF               # break
 */
static const uint8_t spExpectedEncodedSimpleIndefiniteLength[] = {
   0x9f, 0xf5, 0xf4, 0xf6, 0xf7, 0xbf, 0x65, 0x55, 0x4e, 0x44, 0x65, 0x66, 0xf7, 0xff, 0xff};

int32_t IndefiniteLengthTest(void)
{
   QCBOREncodeContext ECtx;

   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_OpenArrayIndefiniteLength(&ECtx);

   QCBOREncode_AddBool(&ECtx, true);
   QCBOREncode_AddBool(&ECtx, false);
   QCBOREncode_AddNULL(&ECtx);
   QCBOREncode_AddUndef(&ECtx);

   QCBOREncode_OpenMapIndefiniteLength(&ECtx);

   QCBOREncode_AddUndefToMap(&ECtx, "UNDef");
   QCBOREncode_CloseMapIndefiniteLength(&ECtx);

   QCBOREncode_CloseArrayIndefiniteLength(&ECtx);

   UsefulBufC ECBOR;
   if(QCBOREncode_Finish(&ECtx, &ECBOR)) {
      return -1;
   }

   if(CheckResults(ECBOR, spExpectedEncodedSimpleIndefiniteLength)) {
      return -2;
   }


#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_OpenArrayIndefiniteLength(&ECtx);
   QCBOREncode_CloseArray(&ECtx);
   if(QCBOREncode_GetErrorState(&ECtx) != QCBOR_ERR_CLOSE_MISMATCH) {
      return -3;
   }

   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_OpenArray(&ECtx);
   QCBOREncode_CloseArrayIndefiniteLength(&ECtx);
   if(QCBOREncode_GetErrorState(&ECtx) != QCBOR_ERR_CLOSE_MISMATCH) {
      return -3;
   }

   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_OpenArrayIndefiniteLength(&ECtx);
   QCBOREncode_CloseMapIndefiniteLength(&ECtx);
   if(QCBOREncode_GetErrorState(&ECtx) != QCBOR_ERR_CLOSE_MISMATCH) {
      return -3;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   return 0;
}
#endif

/*
A5                                      # map(5)
   63                                   # text(3)
      617272                            # "arr"
   98 1F                                # array(31)
      00                                # unsigned(0)
      01                                # unsigned(1)
      02                                # unsigned(2)
      03                                # unsigned(3)
      04                                # unsigned(4)
      05                                # unsigned(5)
      06                                # unsigned(6)
      07                                # unsigned(7)
      08                                # unsigned(8)
      09                                # unsigned(9)
      0A                                # unsigned(10)
      0B                                # unsigned(11)
      0C                                # unsigned(12)
      0D                                # unsigned(13)
      0E                                # unsigned(14)
      0F                                # unsigned(15)
      10                                # unsigned(16)
      11                                # unsigned(17)
      12                                # unsigned(18)
      13                                # unsigned(19)
      14                                # unsigned(20)
      15                                # unsigned(21)
      16                                # unsigned(22)
      17                                # unsigned(23)
      18 18                             # unsigned(24)
      18 19                             # unsigned(25)
      18 1A                             # unsigned(26)
      18 1B                             # unsigned(27)
      18 1C                             # unsigned(28)
      18 1D                             # unsigned(29)
      18 1E                             # unsigned(30)
   63                                   # text(3)
      6D6170                            # "map"
   B8 1F                                # map(31)
      61                                # text(1)
         61                             # "a"
      00                                # unsigned(0)
      61                                # text(1)
         62                             # "b"
      01                                # unsigned(1)
      61                                # text(1)
         63                             # "c"
      02                                # unsigned(2)
      61                                # text(1)
         64                             # "d"
      03                                # unsigned(3)
      61                                # text(1)
         65                             # "e"
      04                                # unsigned(4)
      61                                # text(1)
         66                             # "f"
      05                                # unsigned(5)
      61                                # text(1)
         67                             # "g"
      06                                # unsigned(6)
      61                                # text(1)
         68                             # "h"
      07                                # unsigned(7)
      61                                # text(1)
         69                             # "i"
      08                                # unsigned(8)
      61                                # text(1)
         6A                             # "j"
      09                                # unsigned(9)
      61                                # text(1)
         6B                             # "k"
      0A                                # unsigned(10)
      61                                # text(1)
         6C                             # "l"
      0B                                # unsigned(11)
      61                                # text(1)
         6D                             # "m"
      0C                                # unsigned(12)
      61                                # text(1)
         6E                             # "n"
      0D                                # unsigned(13)
      61                                # text(1)
         6F                             # "o"
      0E                                # unsigned(14)
      61                                # text(1)
         70                             # "p"
      0F                                # unsigned(15)
      61                                # text(1)
         71                             # "q"
      10                                # unsigned(16)
      61                                # text(1)
         72                             # "r"
      11                                # unsigned(17)
      61                                # text(1)
         73                             # "s"
      12                                # unsigned(18)
      61                                # text(1)
         74                             # "t"
      13                                # unsigned(19)
      61                                # text(1)
         75                             # "u"
      14                                # unsigned(20)
      61                                # text(1)
         76                             # "v"
      15                                # unsigned(21)
      61                                # text(1)
         77                             # "w"
      16                                # unsigned(22)
      61                                # text(1)
         78                             # "x"
      17                                # unsigned(23)
      61                                # text(1)
         79                             # "y"
      18 18                             # unsigned(24)
      61                                # text(1)
         7A                             # "z"
      18 19                             # unsigned(25)
      61                                # text(1)
         41                             # "A"
      18 1A                             # unsigned(26)
      61                                # text(1)
         42                             # "B"
      18 1B                             # unsigned(27)
      61                                # text(1)
         43                             # "C"
      18 1C                             # unsigned(28)
      61                                # text(1)
         44                             # "D"
      18 1D                             # unsigned(29)
      61                                # text(1)
         45                             # "E"
      18 1E                             # unsigned(30)
   65                                   # text(5)
      6D696E3331                        # "min31"
   38 1E                                # negative(30)
   66                                   # text(6)
      706C75733331                      # "plus31"
   18 1F                                # unsigned(31)
   63                                   # text(3)
      737472                            # "str"
   78 1F                                # text(31)
      7465737474657374746573747465737474657374746573747163626F723131 # "testtesttesttesttesttestqcbor11"
 */
static const uint8_t EncodeLengthThirtyone[] = {
   0xa5, 0x63, 0x61, 0x72, 0x72, 0x98, 0x1f, 0x00, 0x01, 0x02, 0x03, 0x04,
   0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
   0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x18, 0x18, 0x19, 0x18,
   0x1a, 0x18, 0x1b, 0x18, 0x1c, 0x18, 0x1d, 0x18, 0x1e, 0x63, 0x6d, 0x61,
   0x70, 0xb8, 0x1f, 0x61, 0x61, 0x00, 0x61, 0x62, 0x01, 0x61, 0x63, 0x02,
   0x61, 0x64, 0x03, 0x61, 0x65, 0x04, 0x61, 0x66, 0x05, 0x61, 0x67, 0x06,
   0x61, 0x68, 0x07, 0x61, 0x69, 0x08, 0x61, 0x6a, 0x09, 0x61, 0x6b, 0x0a,
   0x61, 0x6c, 0x0b, 0x61, 0x6d, 0x0c, 0x61, 0x6e, 0x0d, 0x61, 0x6f, 0x0e,
   0x61, 0x70, 0x0f, 0x61, 0x71, 0x10, 0x61, 0x72, 0x11, 0x61, 0x73, 0x12,
   0x61, 0x74, 0x13, 0x61, 0x75, 0x14, 0x61, 0x76, 0x15, 0x61, 0x77, 0x16,
   0x61, 0x78, 0x17, 0x61, 0x79, 0x18, 0x18, 0x61, 0x7a, 0x18, 0x19, 0x61,
   0x41, 0x18, 0x1a, 0x61, 0x42, 0x18, 0x1b, 0x61, 0x43, 0x18, 0x1c, 0x61,
   0x44, 0x18, 0x1d, 0x61, 0x45, 0x18, 0x1e, 0x65, 0x6d, 0x69, 0x6e, 0x33,
   0x31, 0x38, 0x1e, 0x66, 0x70, 0x6c, 0x75, 0x73, 0x33, 0x31, 0x18, 0x1f,
   0x63, 0x73, 0x74, 0x72, 0x78, 0x1f, 0x74, 0x65, 0x73, 0x74, 0x74, 0x65,
   0x73, 0x74, 0x74, 0x65, 0x73, 0x74, 0x74, 0x65, 0x73, 0x74, 0x74, 0x65,
   0x73, 0x74, 0x74, 0x65, 0x73, 0x74, 0x71, 0x63, 0x62, 0x6f, 0x72, 0x31,
   0x31
};

int32_t EncodeLengthThirtyoneTest(void)
{
   QCBOREncodeContext ECtx;
   int nReturn = 0;

   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_OpenMap(&ECtx);

   // add array with 31 items
   QCBOREncode_OpenArrayInMapSZ(&ECtx, "arr");
   for (size_t ix = 0; ix < 31; ix++) {
      QCBOREncode_AddInt64(&ECtx, (int64_t)ix);
   }
   QCBOREncode_CloseArray(&ECtx);

   // add map with 31 items
   QCBOREncode_OpenMapInMapSZ(&ECtx, "map");
   for (int ix = 0; ix < 31; ix++) {
      // make sure we have unique keys in the map (a-z then follow by A-Z)
      int c = 'a';
      if (ix < 26) c = c + ix;
      else c = 'A' + (ix - 26);
      char buffer[2] = { (char)c, 0 };
      QCBOREncode_AddInt64ToMapSZ(&ECtx, buffer, ix);
   }
   QCBOREncode_CloseMap(&ECtx);

   // add -31 and +31
   QCBOREncode_AddInt64ToMapSZ(&ECtx, "min31", -31);
   QCBOREncode_AddInt64ToMapSZ(&ECtx, "plus31", 31);

   // add string with length 31
   const char *str = "testtesttesttesttesttestqcbor11";
   UsefulBufC str_b = { str, 31 };
   QCBOREncode_AddTextToMapSZ(&ECtx, "str", str_b);

   QCBOREncode_CloseMap(&ECtx);

   UsefulBufC ECBOR;
   if(QCBOREncode_Finish(&ECtx, &ECBOR)) {
      nReturn = -1;
   }

   if(CheckResults(ECBOR, EncodeLengthThirtyone))
      return -2;

   return(nReturn);
}


/*
 * [  "2013-03-21T20:04:00Z",
 *    0("2013-03-21T20:04:00Z"),
 *    1363896240,
 *    1(1363896240),
 *    100(-10676),
 *    3994,
 *    1004("1940-10-09"),
 *    "1980-12-08",
 *    {  "Sample Date from RFC 3339": 0("1985-04-12T23:20:50.52Z"),
 *       "SD": 1(999),
 *       "Sample Date from RFC 8943": "1985-04-12",
 *       42: 1004("1985-04-12T23:20:50.52Z"),
 *       "SY": 100(-10676),
 *        45: 3994
 *    }
 * ]
 */
static const uint8_t spExpectedEncodedDates[] = {
   0x89, 0x74, 0x32, 0x30, 0x31, 0x33, 0x2D, 0x30, 0x33, 0x2D,
   0x32, 0x31, 0x54, 0x32, 0x30, 0x3A, 0x30, 0x34, 0x3A, 0x30,
   0x30, 0x5A, 0xC0, 0x74, 0x32, 0x30, 0x31, 0x33, 0x2D, 0x30,
   0x33, 0x2D, 0x32, 0x31, 0x54, 0x32, 0x30, 0x3A, 0x30, 0x34,
   0x3A, 0x30, 0x30, 0x5A, 0x1A, 0x51, 0x4B, 0x67, 0xB0, 0xC1,
   0x1A, 0x51, 0x4B, 0x67, 0xB0, 0xD8, 0x64, 0x39, 0x29, 0xB3,
   0x19, 0x0F, 0x9A, 0xD9, 0x03, 0xEC, 0x6A, 0x31, 0x39, 0x34,
   0x30, 0x2D, 0x31, 0x30, 0x2D, 0x30, 0x39, 0x6A, 0x31, 0x39,
   0x38, 0x30, 0x2D, 0x31, 0x32, 0x2D, 0x30, 0x38, 0xA6, 0x78,
   0x19, 0x53, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x44, 0x61,
   0x74, 0x65, 0x20, 0x66, 0x72, 0x6F, 0x6D, 0x20, 0x52, 0x46,
   0x43, 0x20, 0x33, 0x33, 0x33, 0x39, 0xC0, 0x77, 0x31, 0x39,
   0x38, 0x35, 0x2D, 0x30, 0x34, 0x2D, 0x31, 0x32, 0x54, 0x32,
   0x33, 0x3A, 0x32, 0x30, 0x3A, 0x35, 0x30, 0x2E, 0x35, 0x32,
   0x5A, 0x62, 0x53, 0x44, 0xC1, 0x19, 0x03, 0xE7, 0x78, 0x19,
   0x53, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x20, 0x44, 0x61, 0x74,
   0x65, 0x20, 0x66, 0x72, 0x6F, 0x6D, 0x20, 0x52, 0x46, 0x43,
   0x20, 0x38, 0x39, 0x34, 0x33, 0x6A, 0x31, 0x39, 0x38, 0x35,
   0x2D, 0x30, 0x34, 0x2D, 0x31, 0x32, 0x18, 0x2A, 0xD9, 0x03,
   0xEC, 0x77, 0x31, 0x39, 0x38, 0x35, 0x2D, 0x30, 0x34, 0x2D,
   0x31, 0x32, 0x54, 0x32, 0x33, 0x3A, 0x32, 0x30, 0x3A, 0x35,
   0x30, 0x2E, 0x35, 0x32, 0x5A, 0x62, 0x53, 0x59, 0xD8, 0x64,
   0x39, 0x29, 0xB3, 0x18, 0x2D, 0x19, 0x0F, 0x9A};

int32_t EncodeDateTest(void)
{
   QCBOREncodeContext ECtx;

   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));

   QCBOREncode_OpenArray(&ECtx);

   /* The values are taken from the CBOR RFCs */
   QCBOREncode_AddTDateString(&ECtx, QCBOR_ENCODE_AS_BORROWED, "2013-03-21T20:04:00Z");
   QCBOREncode_AddDateString(&ECtx, "2013-03-21T20:04:00Z");
   QCBOREncode_AddTDateEpoch(&ECtx, QCBOR_ENCODE_AS_BORROWED, 1363896240);
   QCBOREncode_AddDateEpoch(&ECtx, 1363896240);
   QCBOREncode_AddTDaysEpoch(&ECtx, QCBOR_ENCODE_AS_TAG, -10676);
   QCBOREncode_AddTDaysEpoch(&ECtx, QCBOR_ENCODE_AS_BORROWED, 3994);
   QCBOREncode_AddTDaysString(&ECtx, QCBOR_ENCODE_AS_TAG, "1940-10-09");
   QCBOREncode_AddTDaysString(&ECtx, QCBOR_ENCODE_AS_BORROWED, "1980-12-08");

   QCBOREncode_OpenMap(&ECtx);

   QCBOREncode_AddTDateStringToMapSZ(&ECtx,
                                     "Sample Date from RFC 3339",
                                     QCBOR_ENCODE_AS_TAG,
                                     "1985-04-12T23:20:50.52Z");
   QCBOREncode_AddDateEpochToMap(&ECtx, "SD", 999);
   QCBOREncode_AddTDaysStringToMapSZ(&ECtx,
                                     "Sample Date from RFC 8943",
                                     QCBOR_ENCODE_AS_BORROWED,
                                     "1985-04-12");
   QCBOREncode_AddTDaysStringToMapN(&ECtx,
                                     42,
                                     QCBOR_ENCODE_AS_TAG,
                                     "1985-04-12T23:20:50.52Z");
   QCBOREncode_AddTDaysEpochToMapSZ(&ECtx,
                                    "SY",
                                    QCBOR_ENCODE_AS_TAG,
                                    -10676);
   QCBOREncode_AddTDaysEpochToMapN(&ECtx,
                                   45,
                                   QCBOR_ENCODE_AS_BORROWED,
                                   3994);

   QCBOREncode_CloseMap(&ECtx);

   QCBOREncode_CloseArray(&ECtx);

   UsefulBufC ECBOR;
   if(QCBOREncode_Finish(&ECtx, &ECBOR)) {
      return -1;
   }

   if(CheckResults(ECBOR, spExpectedEncodedDates))
      return -2;

   return 0;
}


int32_t ArrayNestingTest1(void)
{
   QCBOREncodeContext ECtx;
   int i;
   int nReturn = 0;

   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   for(i = QCBOR_MAX_ARRAY_NESTING; i; i--) {
      QCBOREncode_OpenArray(&ECtx);
   }
   for(i = QCBOR_MAX_ARRAY_NESTING; i; i--) {
      QCBOREncode_CloseArray(&ECtx);
   }
   UsefulBufC Encoded;
   if(QCBOREncode_Finish(&ECtx, &Encoded)) {
      nReturn = -1;
   }

   return(nReturn);
}



int32_t ArrayNestingTest2(void)
{
   QCBOREncodeContext ECtx;
   int i;
   int nReturn = 0;

   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   for(i = QCBOR_MAX_ARRAY_NESTING+1; i; i--) {
      QCBOREncode_OpenArray(&ECtx);
   }
   for(i = QCBOR_MAX_ARRAY_NESTING; i; i--) {
      QCBOREncode_CloseArray(&ECtx);
   }

   UsefulBufC Encoded;
   if(QCBOREncode_Finish(&ECtx, &Encoded) != QCBOR_ERR_ARRAY_NESTING_TOO_DEEP) {
      nReturn = -1;
   }

   return(nReturn);
}



int32_t ArrayNestingTest3(void)
{
   QCBOREncodeContext ECtx;
   int i;
   int nReturn = 0;

   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   for(i = QCBOR_MAX_ARRAY_NESTING; i; i--) {
      QCBOREncode_OpenArray(&ECtx);
   }
   for(i = QCBOR_MAX_ARRAY_NESTING+1 ; i; i--) {
      QCBOREncode_CloseArray(&ECtx);
   }
   UsefulBufC Encoded;
   if(QCBOREncode_Finish(&ECtx, &Encoded) != QCBOR_ERR_TOO_MANY_CLOSES) {
      nReturn = -1;
   }

   return(nReturn);
}


/*
 81             # array(1)
 81          # array(1)
 81       # array(1)
 81    # array(1)
 80 # array(0)
*/
static const uint8_t spFiveArrarys[] = {0x81, 0x81, 0x81, 0x81, 0x80};

// Validated at http://cbor.me and by manually examining its output
/*
 82                        # array(2)
 81                     # array(1)
 81                  # array(1)
 81               # array(1)
 81            # array(1)
 80         # array(0)
 98 30                  # array(48)
 3B 7FFFFFFFFFFFFFFF # negative(9223372036854775807)
 3B 0000000100000000 # negative(4294967296)
 3A FFFFFFFF         # negative(4294967295)
 3A FFFFFFFE         # negative(4294967294)
 3A FFFFFFFD         # negative(4294967293)
 3A 7FFFFFFF         # negative(2147483647)
 3A 7FFFFFFE         # negative(2147483646)
 3A 00010001         # negative(65537)
 3A 00010000         # negative(65536)
 39 FFFF             # negative(65535)
 39 FFFE             # negative(65534)
 39 FFFD             # negative(65533)
 39 0100             # negative(256)
 38 FF               # negative(255)
 38 FE               # negative(254)
 38 FD               # negative(253)
 38 18               # negative(24)
 37                  # negative(23)
 36                  # negative(22)
 20                  # negative(0)
 00                  # unsigned(0)
 00                  # unsigned(0)
 01                  # unsigned(1)
 16                  # unsigned(22)
 17                  # unsigned(23)
 18 18               # unsigned(24)
 18 19               # unsigned(25)
 18 1A               # unsigned(26)
 18 1F               # unsigned(31)
 18 FE               # unsigned(254)
 18 FF               # unsigned(255)
 19 0100             # unsigned(256)
 19 0101             # unsigned(257)
 19 FFFE             # unsigned(65534)
 19 FFFF             # unsigned(65535)
 1A 00010000         # unsigned(65536)
 1A 00010001         # unsigned(65537)
 1A 00010002         # unsigned(65538)
 1A 7FFFFFFF         # unsigned(2147483647)
 1A 7FFFFFFF         # unsigned(2147483647)
 1A 80000000         # unsigned(2147483648)
 1A 80000001         # unsigned(2147483649)
 1A FFFFFFFE         # unsigned(4294967294)
 1A FFFFFFFF         # unsigned(4294967295)
 1B 0000000100000000 # unsigned(4294967296)
 1B 0000000100000001 # unsigned(4294967297)
 1B 7FFFFFFFFFFFFFFF # unsigned(9223372036854775807)
 1B FFFFFFFFFFFFFFFF # unsigned(18446744073709551615)
 */
static const uint8_t spEncodeRawExpected[] = {
   0x82, 0x81, 0x81, 0x81, 0x81, 0x80, 0x98, 0x30,
   0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0xff, 0x3b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
   0x00, 0x00, 0x3a, 0xff, 0xff, 0xff, 0xff, 0x3a,
   0xff, 0xff, 0xff, 0xfe, 0x3a, 0xff, 0xff, 0xff,
   0xfd, 0x3a, 0x7f, 0xff, 0xff, 0xff, 0x3a, 0x7f,
   0xff, 0xff, 0xfe, 0x3a, 0x00, 0x01, 0x00, 0x01,
   0x3a, 0x00, 0x01, 0x00, 0x00, 0x39, 0xff, 0xff,
   0x39, 0xff, 0xfe, 0x39, 0xff, 0xfd, 0x39, 0x01,
   0x00, 0x38, 0xff, 0x38, 0xfe, 0x38, 0xfd, 0x38,
   0x18, 0x37, 0x36, 0x20, 0x00, 0x00, 0x01, 0x16,
   0x17, 0x18, 0x18, 0x18, 0x19, 0x18, 0x1a, 0x18,
   0x1f, 0x18, 0xfe, 0x18, 0xff, 0x19, 0x01, 0x00,
   0x19, 0x01, 0x01, 0x19, 0xff, 0xfe, 0x19, 0xff,
   0xff, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x1a, 0x00,
   0x01, 0x00, 0x01, 0x1a, 0x00, 0x01, 0x00, 0x02,
   0x1a, 0x7f, 0xff, 0xff, 0xff, 0x1a, 0x7f, 0xff,
   0xff, 0xff, 0x1a, 0x80, 0x00, 0x00, 0x00, 0x1a,
   0x80, 0x00, 0x00, 0x01, 0x1a, 0xff, 0xff, 0xff,
   0xfe, 0x1a, 0xff, 0xff, 0xff, 0xff, 0x1b, 0x00,
   0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x1b,
   0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
   0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0xff, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
   0xff, 0xff};


int32_t EncodeRawTest(void)
{
   QCBOREncodeContext ECtx;

   QCBOREncode_Init(&ECtx, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_OpenArray(&ECtx);
   QCBOREncode_AddEncoded(&ECtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spFiveArrarys));
   QCBOREncode_AddEncoded(&ECtx, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedEncodedInts));
   QCBOREncode_CloseArray(&ECtx);

   UsefulBufC EncodedRawTest;

   if(QCBOREncode_Finish(&ECtx, &EncodedRawTest)) {
      return -4;
   }

   if(CheckResults(EncodedRawTest, spEncodeRawExpected)) {
      return -5;
   }

   return 0;
}

/*
 This returns a pointer to spBigBuf
 */
static int32_t CreateMap(uint8_t **pEncoded, size_t *pEncodedLen)
{
   QCBOREncodeContext ECtx;
   int nReturn = -1;

   *pEncoded = NULL;
   *pEncodedLen = INT32_MAX;
   size_t uFirstSizeEstimate = 0;

   // loop runs CBOR encoding twice. First with no buffer to
   // calucate the length so buffer can be allocated correctly,
   // and last with the buffer to do the actual encoding
   do {
      QCBOREncode_Init(&ECtx, (UsefulBuf){*pEncoded, *pEncodedLen});
      QCBOREncode_OpenMap(&ECtx);
      QCBOREncode_AddInt64ToMapSZ(&ECtx, "first integer", 42);
      QCBOREncode_OpenArrayInMapSZ(&ECtx, "an array of two strings");
      QCBOREncode_AddText(&ECtx, ((UsefulBufC) {"string1", 7}));
      QCBOREncode_AddText(&ECtx, ((UsefulBufC) {"string2", 7}));
      QCBOREncode_CloseArray(&ECtx);
      QCBOREncode_OpenMapInMapSZ(&ECtx, "map in a map");
      QCBOREncode_AddBytesToMap(&ECtx,"bytes 1", ((UsefulBufC) { "xxxx", 4}));
      QCBOREncode_AddBytesToMapSZ(&ECtx, "bytes 2",((UsefulBufC) { "yyyy", 4}));
      QCBOREncode_AddInt64ToMapSZ(&ECtx, "another int", 98);
      QCBOREncode_AddTextToMapSZ(&ECtx, "text 2", ((UsefulBufC) {"lies, damn lies and statistics", 30}));
      QCBOREncode_CloseMap(&ECtx);
      QCBOREncode_CloseMap(&ECtx);

      if(QCBOREncode_FinishGetSize(&ECtx, pEncodedLen))
         goto Done;
      if(*pEncoded != NULL) {
         if(uFirstSizeEstimate != *pEncodedLen) {
            nReturn = 1;
         } else {
            nReturn = 0;
         }
         goto Done;
      }
      *pEncoded = spBigBuf;
      uFirstSizeEstimate = *pEncodedLen;

   } while(1);

 Done:
   return(nReturn);
}

/*
 A3                                      # map(3)
   6D                                   # text(13)
      666972737420696E7465676572        # "first integer"
   18 2A                                # unsigned(42)
   77                                   # text(23)
      616E206172726179206F662074776F20737472696E6773 # "an array of two strings"
   82                                   # array(2)
      67                                # text(7)
         737472696E6731                 # "string1"
      67                                # text(7)
         737472696E6732                 # "string2"
   6C                                   # text(12)
      6D617020696E2061206D6170          # "map in a map"
   A4                                   # map(4)
      67                                # text(7)
         62797465732031                 # "bytes 1"
      44                                # bytes(4)
         78787878                       # "xxxx"
      67                                # text(7)
         62797465732032                 # "bytes 2"
      44                                # bytes(4)
         79797979                       # "yyyy"
      6B                                # text(11)
         616E6F7468657220696E74         # "another int"
      18 62                             # unsigned(98)
      66                                # text(6)
         746578742032                   # "text 2"
      78 1E                             # text(30)
         6C6965732C2064616D6E206C69657320616E642073746174697374696373 # "lies, damn lies and statistics"
 */
static const uint8_t spValidMapEncoded[] = {
   0xa3, 0x6d, 0x66, 0x69, 0x72, 0x73, 0x74, 0x20, 0x69, 0x6e,
   0x74, 0x65, 0x67, 0x65, 0x72, 0x18, 0x2a, 0x77, 0x61, 0x6e,
   0x20, 0x61, 0x72, 0x72, 0x61, 0x79, 0x20, 0x6f, 0x66, 0x20,
   0x74, 0x77, 0x6f, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
   0x73, 0x82, 0x67, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x31,
   0x67, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x32, 0x6c, 0x6d,
   0x61, 0x70, 0x20, 0x69, 0x6e, 0x20, 0x61, 0x20, 0x6d, 0x61,
   0x70, 0xa4, 0x67, 0x62, 0x79, 0x74, 0x65, 0x73, 0x20, 0x31,
   0x44, 0x78, 0x78, 0x78, 0x78, 0x67, 0x62, 0x79, 0x74, 0x65,
   0x73, 0x20, 0x32, 0x44, 0x79, 0x79, 0x79, 0x79, 0x6b, 0x61,
   0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x69, 0x6e, 0x74,
   0x18, 0x62, 0x66, 0x74, 0x65, 0x78, 0x74, 0x20, 0x32, 0x78,
   0x1e, 0x6c, 0x69, 0x65, 0x73, 0x2c, 0x20, 0x64, 0x61, 0x6d,
   0x6e, 0x20, 0x6c, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64,
   0x20, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63,
   0x73 } ;


int32_t MapEncodeTest(void)
{
   uint8_t *pEncodedMaps;
   size_t nEncodedMapLen;

   if(CreateMap(&pEncodedMaps, &nEncodedMapLen)) {
      return -1;
   }

   int nReturn = 0;
   if(memcmp(spValidMapEncoded, pEncodedMaps, sizeof(spValidMapEncoded)))
      nReturn = 2;

   return(nReturn);
}


/*
 @brief  Encode the RTIC results

 @param[in]     nRResult        CBOR_SIMPLEV_TRUE, CBOR_SIMPLEV_FALSE or
                                CBOR_SIMPLEV_NULL
 @param[in]     time            Time stamp in UNIX epoch time or 0 for none
 @param[in]     szAlexString    Diagnostic code.
 @param[in[     pOut            Buffer to put the result in
 @param[in/out] pnLen           Size of pOut buffer when called; length of data
                                output in buffer on return

 @return
 One of the CBOR encoder errors. QCBOR_SUCCESS, which is has value 0, if no error.

 The size of pOut should be 30 bytes plus the length of pnLen.  If you make it too
 short an error will be returned. This function will never write off the end
 of the buffer passed to it.

 If the result is 0, then the correct encoded CBOR is in pOut and *pnLen is the
 length of the encoded CBOR.

 */

static UsefulBufC
FormatRTICResults(uint8_t uRResult,
                  int64_t time,
                  const char *szType,
                  const char *szAlexString,
                  UsefulBuf Storage)
{
   // Buffer that the result will be written in to
   // It is fixed size and small that a stack variable will be fine
   // QCBOREncode will never write off the end of this buffer. If it won't
   // fit QCBOREncode_Finish will return an error.

   // Context for the encoder
   QCBOREncodeContext ECtx;
   QCBOREncode_Init(&ECtx, Storage);

   // All the RTIC results are grouped in a CBOR Map which will get turned into a JSON Object
   // Contents are label / value pairs
   QCBOREncode_OpenMap(&ECtx);

   { // Brace / indention just to show CBOR encoding nesting

      // The result: 0 if scan happened and found nothing; 1 if it happened and
      // found something wrong; 2 if it didn't happen
      QCBOREncode_AddSimpleToMapSZ(&ECtx, "integrity", uRResult);

      // Add the diagnostic code
      QCBOREncode_AddSZStringToMapSZ(&ECtx, "type", szType);

      // Add a time stamp
      if(time) {
         QCBOREncode_AddDateEpochToMap(&ECtx, "time", time);
      }

      // Add the diagnostic code
      QCBOREncode_AddSZStringToMapSZ(&ECtx, "diag", szAlexString);

      // Open a subordinate map for telemtry data
      QCBOREncode_OpenMapInMapSZ(&ECtx, "telemetry");

      { // Brace / indention just to show CBOR encoding nesting

         // Add a few fake integers and buffers for now.
         QCBOREncode_AddInt64ToMapSZ(&ECtx, "Shoe Size", 12);

         // Add a few fake integers and buffers for now.
         QCBOREncode_AddInt64ToMapSZ(&ECtx, "IQ", 0xffffffff);

         // Add a few fake integers and buffers for now.
         static const uint8_t pPV[] = {0x66, 0x67, 0x00, 0x56, 0xaa, 0xbb, 0x01, 0x01};
         const UsefulBufC WSPV = {pPV, sizeof(pPV)};

         QCBOREncode_AddBytesToMapSZ(&ECtx, "WhaleSharkPatternVector", WSPV);
      }
   }

   // Close the telemetry map
   QCBOREncode_CloseMap(&ECtx);

   // Close the map
   QCBOREncode_CloseMap(&ECtx);

   UsefulBufC Result;

   QCBOREncode_Finish(&ECtx, &Result);

   return Result;
}


/*
 A5                                      # map(5)
   69                                   # text(9)
      696E74656772697479                # "integrity"
   F4                                   # primitive(20)
   64                                   # text(4)
      74797065                          # "type"
   66                                   # text(6)
      726563656E74                      # "recent"
   64                                   # text(4)
      74696D65                          # "time"
   C1                                   # tag(1)
      1A 580D4172                       # unsigned(1477263730)
   64                                   # text(4)
      64696167                          # "diag"
   6A                                   # text(10)
      30784131654335303031              # "0xA1eC5001"
   69                                   # text(9)
      74656C656D65747279                # "telemetry"
   A3                                   # map(3)
      69                                # text(9)
         53686F652053697A65             # "Shoe Size"
      0C                                # unsigned(12)
      62                                # text(2)
         4951                           # "IQ"
      1A FFFFFFFF                       # unsigned(4294967295)
      77                                # text(23)
         5768616C65536861726B5061747465726E566563746F72 # "WhaleSharkPatternVector"
      48                                # bytes(8)
         66670056AABB0101               # "fg\x00V\xAA\xBB\x01\x01"
 */
static const uint8_t spExpectedRTIC[] = {
   0xa5, 0x69, 0x69, 0x6e, 0x74, 0x65, 0x67, 0x72, 0x69, 0x74,
   0x79, 0xf4, 0x64, 0x74, 0x79, 0x70, 0x65, 0x66, 0x72, 0x65,
   0x63, 0x65, 0x6e, 0x74, 0x64, 0x74, 0x69, 0x6d, 0x65, 0xc1,
   0x1a, 0x58, 0x0d, 0x41, 0x72, 0x64, 0x64, 0x69, 0x61, 0x67,
   0x6a, 0x30, 0x78, 0x41, 0x31, 0x65, 0x43, 0x35, 0x30, 0x30,
   0x31, 0x69, 0x74, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x74, 0x72,
   0x79, 0xa3, 0x69, 0x53, 0x68, 0x6f, 0x65, 0x20, 0x53, 0x69,
   0x7a, 0x65, 0x0c, 0x62, 0x49, 0x51, 0x1a, 0xff, 0xff, 0xff,
   0xff, 0x77, 0x57, 0x68, 0x61, 0x6c, 0x65, 0x53, 0x68, 0x61,
   0x72, 0x6b, 0x50, 0x61, 0x74, 0x74, 0x65, 0x72, 0x6e, 0x56,
   0x65, 0x63, 0x74, 0x6f, 0x72, 0x48, 0x66, 0x67, 0x00, 0x56,
   0xaa, 0xbb, 0x01, 0x01};


int32_t RTICResultsTest(void)
{
   const UsefulBufC Encoded = FormatRTICResults(CBOR_SIMPLEV_FALSE, 1477263730,
                                          "recent", "0xA1eC5001",
                                          UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   if(UsefulBuf_IsNULLC(Encoded)) {
      return -1;
   }

   if(CheckResults(Encoded, spExpectedRTIC)) {
      return -2;
   }

   return 0;
}


/*
 The expected encoding for first test in BstrWrapTest()

 82           # array(2)
   19 01C3   # unsigned(451)
   43        # bytes(3)
      1901D2 # "\x19\x01\xD2"
*/
static const uint8_t spExpectedBstrWrap[] = {0x82, 0x19, 0x01, 0xC3, 0x43, 0x19, 0x01, 0xD2};

static const uint8_t spExpectedForBstrWrapCancel[] = {0x82, 0x19, 0x01, 0xC3, 0x18, 0x2A};

/*
 * bstr wrapping test
 */
int32_t BstrWrapTest(void)
{
   QCBOREncodeContext EC;

   // First test - make some wrapped CBOR and see that it is as expected
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));

   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddUInt64(&EC, 451);

   QCBOREncode_BstrWrap(&EC);
   QCBOREncode_AddUInt64(&EC, 466);

   UsefulBufC Wrapped;
   QCBOREncode_CloseBstrWrap(&EC, &Wrapped);

   QCBOREncode_CloseArray(&EC);

   UsefulBufC Encoded;
   if(QCBOREncode_Finish(&EC, &Encoded)) {
      return -1;
   }

   if(CheckResults(Encoded, spExpectedBstrWrap)) {
      return -2;
   }

   // Second test - see if the length of the wrapped
   // bstr is correct. Also tests bstr wrapping
   // in length calculation only mode.
   QCBOREncode_Init(&EC, (UsefulBuf){NULL, INT32_MAX});
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_BstrWrap(&EC);
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddNULL(&EC);
   QCBOREncode_CloseArray(&EC);
   UsefulBufC BStr;
   QCBOREncode_CloseBstrWrap(&EC, &BStr);
   // 3 is one byte for the wrapping bstr, 1 for an array of length 1,
   // and 1 byte for a NULL
   if(BStr.ptr != NULL || BStr.len != 3) {
      return -5;
   }


   // Fourth test, cancelling a byte string
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));

   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddUInt64(&EC, 451);

   QCBOREncode_BstrWrap(&EC);
   QCBOREncode_CancelBstrWrap(&EC);


   QCBOREncode_AddUInt64(&EC, 42);
   QCBOREncode_CloseArray(&EC);
   if(QCBOREncode_Finish(&EC, &Encoded)) {
      return -8;
   }
   if(CheckResults(Encoded, spExpectedForBstrWrapCancel)) {
      return -9;
   }

   QCBORError uErr;
   // Fifth test, failed cancelling
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));

   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddUInt64(&EC, 451);

   QCBOREncode_BstrWrap(&EC);
   QCBOREncode_AddUInt64(&EC, 99);
   QCBOREncode_CancelBstrWrap(&EC);

   QCBOREncode_AddUInt64(&EC, 42);
   QCBOREncode_CloseArray(&EC);
   uErr = QCBOREncode_Finish(&EC, &Encoded);
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(uErr != QCBOR_ERR_CANNOT_CANCEL) {
      return -10;
   }
#else
   if(uErr != QCBOR_SUCCESS) {
      return -110;
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   // Sixth test, another cancel, but the error is not caught
   // This use will produce unintended CBOR. The error
   // is not caught because it would require tracking state
   // for QCBOREncode_BstrWrapInMapN.
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));

   QCBOREncode_OpenMap(&EC);
   QCBOREncode_AddUInt64ToMapN(&EC, 451, 88);

   QCBOREncode_BstrWrapInMapN(&EC, 55);
   QCBOREncode_CancelBstrWrap(&EC);

   QCBOREncode_CloseMap(&EC);
   uErr = QCBOREncode_Finish(&EC, &Encoded);
   if(uErr != QCBOR_SUCCESS) {
      return -11;
   }

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   // Seventh test, erroneous cancel
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_CancelBstrWrap(&EC);
   uErr = QCBOREncode_GetErrorState(&EC);
   if(uErr != QCBOR_ERR_TOO_MANY_CLOSES) {
      return -12;
   }

   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_CancelBstrWrap(&EC);
   uErr = QCBOREncode_GetErrorState(&EC);
   if(uErr != QCBOR_ERR_CLOSE_MISMATCH) {
      return -13;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   return 0;
}



int32_t BstrWrapErrorTest(void)
{
   QCBOREncodeContext EC;
   UsefulBufC         Wrapped;
   UsefulBufC         Encoded2;
   QCBORError         uError;

   // ---- Test closing a bstrwrap when it is an array that is open ---------

   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));

   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddUInt64(&EC, 451);

   QCBOREncode_BstrWrap(&EC);
   QCBOREncode_AddUInt64(&EC, 466);
   QCBOREncode_OpenArray(&EC);

   QCBOREncode_CloseBstrWrap(&EC, &Wrapped);

   QCBOREncode_CloseArray(&EC);

   uError = QCBOREncode_Finish(&EC, &Encoded2);
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(uError != QCBOR_ERR_CLOSE_MISMATCH) {
      return (int32_t)(100 + uError);
   }
#else
   /* The above test is run both when QCBOR_DISABLE_ENCODE_USAGE_GUARDS
    * is set and not to be sure to excerice all the relavant code in
    * both conditions.  When the guards are disabled, there is no
    * error returned, but the code path is still covered.
    */
   if(uError != QCBOR_SUCCESS) {
      return (int32_t)(600 + uError);
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   // -------- test closing a bstrwrap when nothing is open ----------------
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_CloseBstrWrap(&EC, &Wrapped);
   uError = QCBOREncode_Finish(&EC, &Encoded2);
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(uError != QCBOR_ERR_TOO_MANY_CLOSES) {
      return (int32_t)(700 + uError);
   }
#else
   if(uError != QCBOR_SUCCESS) {
      return (int32_t)(800 + uError);
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   // --------------- test nesting too deep ----------------------------------
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   for(int i = 1; i < 18; i++) {
      QCBOREncode_BstrWrap(&EC);
   }
   QCBOREncode_AddBool(&EC, true);

   for(int i = 1; i < 18; i++) {
      QCBOREncode_CloseBstrWrap(&EC, &Wrapped);
   }

   uError = QCBOREncode_Finish(&EC, &Encoded2);
   if(uError != QCBOR_ERR_ARRAY_NESTING_TOO_DEEP) {
      return (int32_t)(300 + uError);
   }

   return 0;
}


/*
 This is bstr wrapped CBOR in 6 levels.

 [
   h'82004E82014B8202488203458204428105',
   {
     32:h'A3101018406568656C6C6F18215828A3111118416568656C6C6F18225819A312121
     8426568656C6C6F18234BA2131318436568656C6C6F'
   }
 ]

 Unwrapping the first byte string in the above gives
   [0, h'82014B8202488203458204428105']

 Unwrapping again, the byte string immediately above gives
   [1, h'8202488203458204428105']

 ...

 Unrapping the second byte string in the top-level CBOR above gives
   {16: 16,
    64: "hello",
    33: h'A3111118416568656C6C6F18225819A3121218426568656C6C6F18234BA2....
 }

 Unwrapping again, the byte string immediately above gives
   {17: 17,
    65: "hello",
    34: h'A3121218426568656C6C6F18234BA2131318436568656C6C6F'
 }

 ...

 */
static const uint8_t spExpectedDeepBstr[] =
{
   0x82, 0x51, 0x82, 0x00, 0x4E, 0x82, 0x01, 0x4B,
   0x82, 0x02, 0x48, 0x82, 0x03, 0x45, 0x82, 0x04,
   0x42, 0x81, 0x05, 0xA1, 0x18, 0x20, 0x58, 0x37,
   0xA3, 0x10, 0x10, 0x18, 0x40, 0x65, 0x68, 0x65,
   0x6C, 0x6C, 0x6F, 0x18, 0x21, 0x58, 0x28, 0xA3,
   0x11, 0x11, 0x18, 0x41, 0x65, 0x68, 0x65, 0x6C,
   0x6C, 0x6F, 0x18, 0x22, 0x58, 0x19, 0xA3, 0x12,
   0x12, 0x18, 0x42, 0x65, 0x68, 0x65, 0x6C, 0x6C,
   0x6F, 0x18, 0x23, 0x4B, 0xA2, 0x13, 0x13, 0x18,
   0x43, 0x65, 0x68, 0x65, 0x6C, 0x6C, 0x6F
};


/*
 Get an int64 out of the decoder or fail.
 */
static int32_t GetInt64(QCBORDecodeContext *pDC, int64_t *pInt)
{
   QCBORItem Item;
   int32_t nReturn;

   nReturn = (int32_t)QCBORDecode_GetNext(pDC, &Item);
   if(nReturn) {
      return nReturn;
   }
   if(Item.uDataType != QCBOR_TYPE_INT64) {
      return -1;
   }

   *pInt = Item.val.int64;
   return 0;
}

/*
 Get an array out of the decoder or fail.
 */
static int32_t GetArray(QCBORDecodeContext *pDC, uint16_t *pInt)
{
   QCBORItem Item;
   int32_t nReturn;

   nReturn = (int32_t)QCBORDecode_GetNext(pDC, &Item);
   if(nReturn) {
      return nReturn;
   }
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -1;
   }

   *pInt = Item.val.uCount;
   return 0;
}

/*
 Get a map out of the decoder or fail.
 */
static int32_t GetMap(QCBORDecodeContext *pDC, uint16_t *pInt)
{
   QCBORItem Item;
   int32_t nReturn;

   nReturn = (int32_t)QCBORDecode_GetNext(pDC, &Item);
   if(nReturn) {
      return nReturn;
   }
   if(Item.uDataType != QCBOR_TYPE_MAP) {
      return -1;
   }

   *pInt = Item.val.uCount;
   return 0;
}

/*
 Get a byte string out of the decoder or fail.
 */
static int32_t GetByteString(QCBORDecodeContext *pDC, UsefulBufC *pBstr)
{
   QCBORItem Item;
   int32_t nReturn;

   nReturn = (int32_t)QCBORDecode_GetNext(pDC, &Item);
   if(nReturn) {
      return nReturn;
   }
   if(Item.uDataType != QCBOR_TYPE_BYTE_STRING) {
      return QCBOR_ERR_UNEXPECTED_TYPE;
   }

   *pBstr = Item.val.string;
   return 0;
}

/*
 Get a byte string out of the decoder or fail.
 */
static int32_t GetTextString(QCBORDecodeContext *pDC, UsefulBufC *pTstr)
{
   QCBORItem Item;
   int nReturn;

   nReturn = (int32_t)QCBORDecode_GetNext(pDC, &Item);
   if(nReturn) {
      return nReturn;
   }
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING) {
      return -1;
   }

   *pTstr = Item.val.string;
   return 0;
}


/*
 Recursively decode array containing a little CBOR and a bstr wrapped array
 with a little CBOR and a bstr wrapped array...

 Part of bstr_wrap_nest_test.
 */static int32_t DecodeNextNested(UsefulBufC Wrapped)
{
   int64_t            nInt;
   UsefulBufC         Bstr;
   uint16_t           nArrayCount;
   QCBORDecodeContext DC;
   int32_t            nResult;

   QCBORDecode_Init(&DC, Wrapped, QCBOR_DECODE_MODE_NORMAL);

   if(GetArray(&DC, &nArrayCount) || nArrayCount < 1 || nArrayCount > 2) {
      return -10;
   }

   if(GetInt64(&DC, &nInt)) {
      return -11;
   }

   nResult = GetByteString(&DC, &Bstr);
   if(nResult == QCBOR_ERR_HIT_END || nResult == QCBOR_ERR_NO_MORE_ITEMS) {
      if(nArrayCount != 1) {
         return -12;
      } else {
         // successful exit
         return 0;
      }
   }
   if(nResult) {
      return -13;
   }

   // tail recursion; good compilers will reuse the stack frame
   return DecodeNextNested(Bstr);
}


/*
 Recursively decode map containing a little CBOR and a bstr wrapped map
 with a little CBOR and a bstr wrapped map...

 Part of bstr_wrap_nest_test.
 */
static int32_t DecodeNextNested2(UsefulBufC Wrapped)
{
   int32_t            nResult;
   uint16_t           nMapCount;
   int64_t            nInt;
   UsefulBufC         Bstr;
   QCBORDecodeContext DC;

   QCBORDecode_Init(&DC, Wrapped, QCBOR_DECODE_MODE_NORMAL);

   if(GetMap(&DC, &nMapCount) || nMapCount < 2 || nMapCount > 3) {
      return -20;
   }

   if(GetInt64(&DC, &nInt)) {
      return -21;
   }

   // The "hello"
   if(GetTextString(&DC, &Bstr)) {
      return -22;
   }

   nResult = GetByteString(&DC, &Bstr);
   if(nResult == QCBOR_ERR_HIT_END || nResult == QCBOR_ERR_NO_MORE_ITEMS) {
      if(nMapCount == 2) {
         // successful exit
         return 0;
      } else {
         return -23;
      }
   }

   if(nResult) {
      return -24;
   }

   // tail recursion; good compilers will reuse the stack frame
   return DecodeNextNested2(Bstr);
}


int32_t BstrWrapNestTest(void)
{
   QCBOREncodeContext EC;
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));

   // ---- Make a complicated nested CBOR structure ---
   #define BSTR_TEST_DEPTH 6

   QCBOREncode_OpenArray(&EC);

   for(int i = 0; i < BSTR_TEST_DEPTH; i++) {
      QCBOREncode_BstrWrap(&EC);
      QCBOREncode_OpenArray(&EC);
      QCBOREncode_AddInt64(&EC, i);
   }
   for(int i = 0; i < BSTR_TEST_DEPTH; i++) {
      QCBOREncode_CloseArray(&EC);
      QCBOREncode_CloseBstrWrap(&EC, NULL);
   }

   QCBOREncode_OpenMap(&EC);
   for(int i = 0; i < (BSTR_TEST_DEPTH-2); i++) {
      QCBOREncode_BstrWrapInMapN(&EC, i+0x20);
      QCBOREncode_OpenMap(&EC);
      QCBOREncode_AddInt64ToMapN(&EC, i+0x10, i+0x10);
      QCBOREncode_AddSZStringToMapN(&EC, i+0x40, "hello");
   }

   for(int i = 0; i < (BSTR_TEST_DEPTH-2); i++) {
      QCBOREncode_CloseMap(&EC);
      QCBOREncode_CloseBstrWrap(&EC, NULL);
   }
   QCBOREncode_CloseMap(&EC);

   QCBOREncode_CloseArray(&EC);

   UsefulBufC Encoded;
   if(QCBOREncode_Finish(&EC, &Encoded)) {
      return -1;
   }

   // ---Compare it to expected. Expected was hand checked with use of CBOR playground ----
   if(UsefulBuf_Compare(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedDeepBstr), Encoded)) {
      return -2;
   }

   // ---- Decode it and see if it is OK ------
   QCBORDecodeContext DC;
   QCBORDecode_Init(&DC, Encoded, QCBOR_DECODE_MODE_NORMAL);

   UsefulBufC Bstr;
   uint16_t nArrayCount;

   // Array surrounding the the whole thing
   if(GetArray(&DC, &nArrayCount) || nArrayCount != 2) {
      return -3;
   }

   // Get the byte string wrapping some array stuff
   if(GetByteString(&DC, &Bstr)) {
      return -4;
   }

   // Decode the wrapped nested structure
   int nReturn = DecodeNextNested(Bstr);
   if(nReturn) {
      return nReturn;
   }

   // A map enclosing some map-oriented bstr wraps
   if(GetMap(&DC, &nArrayCount)) {
      return -5;
   }

   // Get the byte string wrapping some array stuff
   if(GetByteString(&DC, &Bstr)) {
      return -6;
   }

   // Decode the wrapped nested structure
   nReturn = DecodeNextNested2(Bstr);
   if(nReturn) {
      return nReturn;
   }

   if(QCBORDecode_Finish(&DC)) {
      return -7;
   }

   return 0;
}


static const uint8_t spCoseSign1Signature[] = {
   0x8e, 0xb3, 0x3e, 0x4c, 0xa3, 0x1d, 0x1c, 0x46, 0x5a, 0xb0,
   0x5a, 0xac, 0x34, 0xcc, 0x6b, 0x23, 0xd5, 0x8f, 0xef, 0x5c,
   0x08, 0x31, 0x06, 0xc4, 0xd2, 0x5a, 0x91, 0xae, 0xf0, 0xb0,
   0x11, 0x7e, 0x2a, 0xf9, 0xa2, 0x91, 0xaa, 0x32, 0xe1, 0x4a,
   0xb8, 0x34, 0xdc, 0x56, 0xed, 0x2a, 0x22, 0x34, 0x44, 0x54,
   0x7e, 0x01, 0xf1, 0x1d, 0x3b, 0x09, 0x16, 0xe5, 0xa4, 0xc3,
   0x45, 0xca, 0xcb, 0x36};

/*
 D2                                      # tag(18)
   84                                   # array(4)
      43                                # bytes(3)
         A10126                         # "\xA1\x01&"
      A1                                # map(1)
         04                             # unsigned(4)
         42                             # bytes(2)
            3131                        # "11"
      54                                # bytes(20)
         546869732069732074686520636F6E74656E742E # "This is the content."
      58 40                             # bytes(64)
         8EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25
         A91AEF0B0117E2AF9A291AA32E14AB834DC56ED2A223444547E
         01F11D3B0916E5A4C345CACB36     # "\x8E\xB3>L\xA3\x1D\x1CFZ\xB0Z\xAC4
                                           \xCCk#\xD5\x8F\xEF\b1\x06\xC4\xD2Z
                                           \x91\xAE\xF0\xB0\x11~*\xF9\xA2\x91
                                           \xAA2\xE1J\xB84\xDCV\xED*\"4DT~\x01
                                           \xF1\x1D;\t\x16\xE5\xA4\xC3E\xCA
                                           \xCB6"
 */
static const uint8_t spCoseSign1TBSExpected[] = {
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

static const uint8_t pProtectedHeaders[] = {0xa1, 0x01, 0x26};


/*
 This corresponds exactly to the example in RFC 8152 section
 C.2.1. This doesn't actually verify the signature (however
 the t_cose implementation does).
 */
int32_t CoseSign1TBSTest(void)
{
   // All of this is from RFC 8152 C.2.1
   const char          *szKid     = "11";
   const UsefulBufC     Kid       = UsefulBuf_FromSZ(szKid);
   const char          *szPayload = "This is the content.";
   const UsefulBufC     Payload   = UsefulBuf_FromSZ(szPayload);
   const UsefulBufC     ProtectedHeaders = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(pProtectedHeaders);
   const UsefulBufC     Signature        = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spCoseSign1Signature);

   QCBOREncodeContext EC;

   // --------QCBOREncode_CloseBstrWrap2(&EC, **false** ----------------------
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));

   // top level array for cose sign1, 18 is the tag for COSE sign
   QCBOREncode_AddTag(&EC, CBOR_TAG_COSE_SIGN1);
   QCBOREncode_OpenArray(&EC);

   // Add protected headers
   QCBOREncode_AddBytes(&EC, ProtectedHeaders);

   // Empty map with unprotected headers
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_AddBytesToMapN(&EC, 4, Kid);
   QCBOREncode_CloseMap(&EC);

   // The payload
   UsefulBufC WrappedPayload;
   QCBOREncode_BstrWrap(&EC);
   // Payload is not actually CBOR in example C.2.1 like it would be
   // for a CWT or EAT. It is just a text string.
   QCBOREncode_AddEncoded(&EC, Payload);
   QCBOREncode_CloseBstrWrap2(&EC, false, &WrappedPayload);

   // Check we got back the actual payload expected
   // The extra "T" is 0x54, which is the initial byte a bstr of length 20.
   if(UsefulBuf_Compare(WrappedPayload,
                        UsefulBuf_FROM_SZ_LITERAL("This is the content."))) {
      return -1;
   }

/*   if(UsefulBuf_Compare(WrappedPayload,
                        UsefulBuf_FROM_SZ_LITERAL("TThis is the content."))) {
      return -1;
   } */

   // The signature
   QCBOREncode_AddBytes(&EC, Signature);
   QCBOREncode_CloseArray(&EC);

   // Finish and check the results
   UsefulBufC COSE_Sign1;
   if(QCBOREncode_Finish(&EC, &COSE_Sign1)) {
      return -2;
   }

   // 98 is the size from RFC 8152 C.2.1
   if(COSE_Sign1.len != 98) {
      return -3;
   }

   // It would be good to compare this to the output from a COSE
   // implementation like COSE-C. This has been checked against the
   // CBOR playground.
   if(CheckResults(COSE_Sign1, spCoseSign1TBSExpected)) {
      return -4;
   }


   // --------QCBOREncode_CloseBstrWrap2(&EC, **true** ------------------------
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));

   // top level array for cose sign1, 18 is the tag for COSE sign
   QCBOREncode_AddTag(&EC, CBOR_TAG_COSE_SIGN1);
   QCBOREncode_OpenArray(&EC);

   // Add protected headers
   QCBOREncode_AddBytes(&EC, ProtectedHeaders);

   // Empty map with unprotected headers
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_AddBytesToMapN(&EC, 4, Kid);
   QCBOREncode_CloseMap(&EC);

   // The payload
   QCBOREncode_BstrWrap(&EC);
   // Payload is not actually CBOR in example C.2.1 like it would be
   // for a CWT or EAT. It is just a text string.
   QCBOREncode_AddEncoded(&EC, Payload);
   QCBOREncode_CloseBstrWrap2(&EC, true, &WrappedPayload);

   // Check we got back the actual payload expected
   // The extra "T" is 0x54, which is the initial byte a bstr of length 20.
   if(UsefulBuf_Compare(WrappedPayload,
                        UsefulBuf_FROM_SZ_LITERAL("TThis is the content."))) {
      return -11;
   }

   // The signature
   QCBOREncode_AddBytes(&EC, Signature);
   QCBOREncode_CloseArray(&EC);

   // Finish and check the results
   if(QCBOREncode_Finish(&EC, &COSE_Sign1)) {
      return -12;
   }

   // 98 is the size from RFC 8152 C.2.1
   if(COSE_Sign1.len != 98) {
      return -13;
   }

   // It would be good to compare this to the output from a COSE
   // implementation like COSE-C. This has been checked against the
   // CBOR playground.
   if(CheckResults(COSE_Sign1, spCoseSign1TBSExpected)) {
      return -14;
   }

   return 0;
}


int32_t EncodeErrorTests(void)
{
   QCBOREncodeContext EC;
   QCBORError         uErr;
   UsefulBufC         EncodedResult;
   MakeUsefulBufOnStack(SmallBuffer, 4);


   // ------ Test for QCBOR_ERR_BUFFER_TOO_LARGE ------
   // Do all of these tests with NULL buffers so no actual
   // large allocations are neccesary
   const UsefulBuf Buffer = (UsefulBuf){NULL, UINT32_MAX};

   // First verify no error from a big buffer
   QCBOREncode_Init(&EC, Buffer);
   QCBOREncode_OpenArray(&EC);
   // 6 is the CBOR overhead for opening the array and encodng the length
   // This exactly fills the buffer.
   QCBOREncode_AddBytes(&EC, (UsefulBufC){NULL, UINT32_MAX-6});
   QCBOREncode_CloseArray(&EC);
   size_t xx;
   if(QCBOREncode_FinishGetSize(&EC, &xx) != QCBOR_SUCCESS) {
      return -1;
   }

   // Second verify error from an array in encoded output too large
   // Also test fetching the error code before finish
   QCBOREncode_Init(&EC, (UsefulBuf){NULL, UINT32_MAX});
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddBytes(&EC, (UsefulBufC){NULL, UINT32_MAX-10});
   QCBOREncode_OpenArray(&EC); // Where QCBOR internally encounters and records error
   if(QCBOREncode_GetErrorState(&EC) != QCBOR_ERR_BUFFER_TOO_LARGE) {
      // Error fetch failed.
      return -122;
   }
   QCBOREncode_CloseArray(&EC);
   if(QCBOREncode_FinishGetSize(&EC, &xx) != QCBOR_ERR_BUFFER_TOO_LARGE) {
      return -2;
   }

   // Third, fit an array in exactly at max position allowed
   QCBOREncode_Init(&EC, Buffer);
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddBytes(&EC, (UsefulBufC){NULL, QCBOR_MAX_ARRAY_OFFSET-6});
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_CloseArray(&EC);
   QCBOREncode_CloseArray(&EC);
   if(QCBOREncode_FinishGetSize(&EC, &xx) != QCBOR_SUCCESS) {
      return -10;
   }


   // ----- QCBOR_ERR_BUFFER_TOO_SMALL --------------
   // Work close to the 4GB size limit for a better test
   const uint32_t uLargeSize =  UINT32_MAX - 1024;
   const UsefulBuf Large = (UsefulBuf){NULL,uLargeSize};

   QCBOREncode_Init(&EC, Large);
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddBytes(&EC, (UsefulBufC){NULL, uLargeSize/2 + 1});
   QCBOREncode_CloseArray(&EC);
   if(QCBOREncode_FinishGetSize(&EC, &xx) != QCBOR_SUCCESS) {
      // Making sure it succeeds when it should first
      return -3;
   }

   QCBOREncode_Init(&EC, Large);
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddBytes(&EC, (UsefulBufC){NULL, uLargeSize/2 + 1});
   QCBOREncode_AddBytes(&EC, (UsefulBufC){NULL, uLargeSize/2});
   QCBOREncode_CloseArray(&EC);
   if(QCBOREncode_FinishGetSize(&EC, &xx) != QCBOR_ERR_BUFFER_TOO_SMALL) {
      // Now just 1 byte over, see that it fails
      return -4;
   }


   // ----- QCBOR_ERR_ARRAY_NESTING_TOO_DEEP -------
   QCBOREncode_Init(&EC, Large);
   for(int i = QCBOR_MAX_ARRAY_NESTING; i > 0; i--) {
      QCBOREncode_OpenArray(&EC);
   }
   for(int i = QCBOR_MAX_ARRAY_NESTING; i > 0; i--) {
      QCBOREncode_CloseArray(&EC);
   }
   if(QCBOREncode_FinishGetSize(&EC, &xx) != QCBOR_SUCCESS) {
      // Making sure it succeeds when it should first
      return -5;
   }

   QCBOREncode_Init(&EC, Large);
   for(int i = QCBOR_MAX_ARRAY_NESTING+1; i > 0; i--) {
      QCBOREncode_OpenArray(&EC);
   }
   /* +1 level to cause error */
   for(int i = QCBOR_MAX_ARRAY_NESTING+1; i > 0; i--) {
      QCBOREncode_CloseArray(&EC);
   }
   if(QCBOREncode_FinishGetSize(&EC, &xx) != QCBOR_ERR_ARRAY_NESTING_TOO_DEEP) {
      return -6;
   }


   /* ------ QCBOR_ERR_TOO_MANY_CLOSES -------- */
   QCBOREncode_Init(&EC, Large);
   for(int i = QCBOR_MAX_ARRAY_NESTING; i > 0; i--) {
      QCBOREncode_OpenArray(&EC);
   }
   /* +1 level to cause error */
   for(int i = QCBOR_MAX_ARRAY_NESTING+1; i > 0; i--) {
      QCBOREncode_CloseArray(&EC);
   }
   uErr = QCBOREncode_FinishGetSize(&EC, &xx);
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(uErr != QCBOR_ERR_TOO_MANY_CLOSES) {
      return -7;
   }
#else /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */
   if(uErr != QCBOR_SUCCESS) {
      return -107;
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */


   /* ------ QCBOR_ERR_CLOSE_MISMATCH -------- */
   QCBOREncode_Init(&EC, Large);
   QCBOREncode_OpenArray(&EC);
   UsefulBufC Wrap;
   QCBOREncode_CloseBstrWrap(&EC, &Wrap);
   uErr = QCBOREncode_FinishGetSize(&EC, &xx);
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(uErr != QCBOR_ERR_CLOSE_MISMATCH) {
      return -8;
   }
#else /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */
   if(uErr != QCBOR_SUCCESS) {
      return -108;
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   /* ------ QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN --------- */
   QCBOREncode_Init(&EC, Large);
   for(int i = QCBOR_MAX_ARRAY_NESTING; i > 0; i--) {
      QCBOREncode_OpenArray(&EC);
   }
   /* -1 level to cause error */
   for(int i = QCBOR_MAX_ARRAY_NESTING-1; i > 0; i--) {
      QCBOREncode_CloseArray(&EC);
   }

   uErr = QCBOREncode_FinishGetSize(&EC, &xx);
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(uErr != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
      return -9;
   }
#else /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */
   if(uErr != QCBOR_SUCCESS) {
      return -109;
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   /* QCBOR_ERR_ARRAY_TOO_LONG is not tested here as
    it would require a 64KB of RAM to test */


   /* ----- Test the check for NULL buffer ------ */
   QCBOREncode_Init(&EC, Buffer);
   if(QCBOREncode_IsBufferNULL(&EC) == 0) {
      return -11;
   }

   UsefulBuf Tmp;
   Tmp = QCBOREncode_RetrieveOutputStorage(&EC);
   if(Tmp.ptr != NULL && Tmp.len != UINT32_MAX) {
      return -111;
   }

   /* ------ QCBOR_ERR_UNSUPPORTED -------- */
   QCBOREncode_Init(&EC, Large);
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddSimple(&EC, 24); /* CBOR_SIMPLEV_RESERVED_START */
   uErr = QCBOREncode_FinishGetSize(&EC, &xx);
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(uErr != QCBOR_ERR_ENCODE_UNSUPPORTED) {
      return -12;
   }
#else /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */
   if(uErr != QCBOR_SUCCESS) {
      return -112;
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */


   QCBOREncode_Init(&EC, Large);
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddSimple(&EC, 31); /* CBOR_SIMPLEV_RESERVED_END */
   uErr = QCBOREncode_FinishGetSize(&EC, &xx);
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(uErr != QCBOR_ERR_ENCODE_UNSUPPORTED) {
      return -13;
   }
#else /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */
   if(uErr != QCBOR_SUCCESS) {
      return -113;
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   /* Test that still-open error sticks */
   QCBOREncode_Init(&EC, Large);
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_Finish(&EC, &EncodedResult);
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(QCBOREncode_GetErrorState(&EC) != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
      return -120;
   }
#else /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */
   if(QCBOREncode_GetErrorState(&EC) != QCBOR_SUCCESS) {
      return -122;
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   /* Test that too-small error is sticky */
   QCBOREncode_Init(&EC, SmallBuffer);
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddInt64(&EC, INT64_MAX);
   QCBOREncode_AddInt64(&EC, INT64_MAX);
   QCBOREncode_AddInt64(&EC, INT64_MAX);
   QCBOREncode_CloseArray(&EC);
   QCBOREncode_Finish(&EC, &EncodedResult);
   if(QCBOREncode_GetErrorState(&EC) != QCBOR_ERR_BUFFER_TOO_SMALL) {
      return -130;
   }


#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   /* ------ QCBOR_ERR_ARRAY_TOO_LONG -------- */
   QCBOREncode_Init(&EC, Large);
   QCBOREncode_OpenArray(&EC);
   int i;
   for(i = 0; i < QCBOR_MAX_ITEMS_IN_ARRAY; i++) {
      QCBOREncode_AddInt64(&EC, 0);
   }
   if(QCBOREncode_GetErrorState(&EC)) {
      return 250;
   }
   QCBOREncode_AddInt64(&EC, 0);
   if(QCBOREncode_GetErrorState(&EC) != QCBOR_ERR_ARRAY_TOO_LONG) {
      return 251;
   }

   QCBOREncode_Init(&EC, Large);
   QCBOREncode_OpenMap(&EC);
   for(i = 0; i < QCBOR_MAX_ITEMS_IN_MAP; i++) {
      QCBOREncode_AddInt64ToMapN(&EC, 0,0);
   }
   if(QCBOREncode_GetErrorState(&EC)) {
      return 250;
   }
   QCBOREncode_AddInt64ToMapN(&EC, 0,0);
   if(QCBOREncode_GetErrorState(&EC) != QCBOR_ERR_ARRAY_TOO_LONG) {
      return 251;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   return 0;
}


#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA

/*
   [
      4([-1, 3]),
      [-1, 4],
      4([-20, 4759477275222530853136]),
      [2, 4759477275222530853136],
      4([9223372036854775807, -4759477275222530853137]),
      5([300, 100]),
      [600, 200],
      5([-20, 4759477275222530853136]),
      [4, 4759477275222530853136],
      5([-9223372036854775808, -4759477275222530853137])]
   ]
 */
static const uint8_t spExpectedExponentAndMantissaArrayv1[] = {

   0x8A, 0xC4, 0x82, 0x20, 0x03, 0x82, 0x20, 0x04,
   0xC4, 0x82, 0x33, 0xC2, 0x4A, 0x01, 0x02, 0x03,
   0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x82,
   0x02, 0xC2, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05,
   0x06, 0x07, 0x08, 0x09, 0x10, 0xC4, 0x82, 0x1B,
   0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xC3, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
   0x07, 0x08, 0x09, 0x10, 0xC5, 0x82, 0x19, 0x01,

   0x2C, 0x18, 0x64, 0x82, 0x19, 0x02, 0x58, 0x18,
   0xC8, 0xC5, 0x82, 0x33, 0xC2, 0x4A, 0x01, 0x02,
   0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
   0x82, 0x04, 0xC2, 0x4A, 0x01, 0x02, 0x03, 0x04,
   0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0xC5, 0x82,
   0x3B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xC3, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05,
   0x06, 0x07, 0x08, 0x09, 0x10};

/*
  {
    "decimal fraction": 4([-1, 3]),
    300: 4([-1, 3]),
    "decimal fraction bignum postive": 4([-200, 4759477275222530853136]),
    400: 4([2147483647, 4759477275222530853136]),
    "decimal fraction bignum negative": 4([9223372036854775807, -4759477275222530853137]),
    500: 4([9223372036854775807, -4759477275222530853137]),
    "big float": 5([300, 100]),
    600: 5([300, 100]),
    "big float bignum positive": 5([-20, 4759477275222530853136]),
    700: 5([-20, 4759477275222530853136]),
    "big float bignum negative": 5([-9223372036854775808, -4759477275222530853137]),
    800: 5([-9223372036854775808, -4759477275222530853137])
  }
 */
static const uint8_t spExpectedExponentAndMantissaMapv1[] = {
   0xAC, 0x70, 0x64, 0x65, 0x63, 0x69, 0x6D, 0x61,
   0x6C, 0x20, 0x66, 0x72, 0x61, 0x63, 0x74, 0x69,
   0x6F, 0x6E, 0xC4, 0x82, 0x20, 0x03, 0x19, 0x01,
   0x2C, 0xC4, 0x82, 0x20, 0x03, 0x78, 0x1F, 0x64,
   0x65, 0x63, 0x69, 0x6D, 0x61, 0x6C, 0x20, 0x66,
   0x72, 0x61, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x20,
   0x62, 0x69, 0x67, 0x6E, 0x75, 0x6D, 0x20, 0x70,
   0x6F, 0x73, 0x74, 0x69, 0x76, 0x65, 0xC4, 0x82,
   0x38, 0xC7, 0xC2, 0x4A, 0x01, 0x02, 0x03, 0x04,
   0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x19, 0x01,
   0x90, 0xC4, 0x82, 0x1A, 0x7F, 0xFF, 0xFF, 0xFF,
   0xC2, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
   0x07, 0x08, 0x09, 0x10, 0x78, 0x20, 0x64, 0x65,
   0x63, 0x69, 0x6D, 0x61, 0x6C, 0x20, 0x66, 0x72,
   0x61, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x62,
   0x69, 0x67, 0x6E, 0x75, 0x6D, 0x20, 0x6E, 0x65,
   0x67, 0x61, 0x74, 0x69, 0x76, 0x65, 0xC4, 0x82,
   0x1B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xC3, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05,
   0x06, 0x07, 0x08, 0x09, 0x10, 0x19, 0x01, 0xF4,
   0xC4, 0x82, 0x1B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xC3, 0x4A, 0x01, 0x02, 0x03,
   0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x69,
   0x62, 0x69, 0x67, 0x20, 0x66, 0x6C, 0x6F, 0x61,
   0x74, 0xC5, 0x82, 0x19, 0x01, 0x2C, 0x18, 0x64,
   0x19, 0x02, 0x58, 0xC5, 0x82, 0x19, 0x01, 0x2C,
   0x18, 0x64, 0x78, 0x19, 0x62, 0x69, 0x67, 0x20,
   0x66, 0x6C, 0x6F, 0x61, 0x74, 0x20, 0x62, 0x69,
   0x67, 0x6E, 0x75, 0x6D, 0x20, 0x70, 0x6F, 0x73,
   0x69, 0x74, 0x69, 0x76, 0x65, 0xC5, 0x82, 0x33,
   0xC2, 0x4A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
   0x07, 0x08, 0x09, 0x10, 0x19, 0x02, 0xBC, 0xC5,
   0x82, 0x33, 0xC2, 0x4A, 0x01, 0x02, 0x03, 0x04,
   0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x78, 0x19,
   0x62, 0x69, 0x67, 0x20, 0x66, 0x6C, 0x6F, 0x61,
   0x74, 0x20, 0x62, 0x69, 0x67, 0x6E, 0x75, 0x6D,
   0x20, 0x6E, 0x65, 0x67, 0x61, 0x74, 0x69, 0x76,
   0x65, 0xC5, 0x82, 0x3B, 0x7F, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0x4A, 0x01, 0x02,
   0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
   0x19, 0x03, 0x20, 0xC5, 0x82, 0x3B, 0x7F, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3, 0x4A,
   0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
   0x09, 0x10
};


struct EAMEncodeTest {
   const char *szDescription;
   int64_t     nExponent;
   UsefulBufC  BigNumMantissa;
   int64_t     nMantissa;
   bool        bSign;
   enum {EAM_Any, EAM_Pref, EAM_CDE} eSerialization;
   // TODO: add tag requirement

   /* Only testing successes (right?) */
   UsefulBufC  BigFloat;
   UsefulBufC  DecFrac;
   UsefulBufC  BigFloatBig;
   UsefulBufC  DecFracBig;
};

struct EAMEncodeTest EET[] = {
   { "basic",
      -1,
      NULLUsefulBufC,
      3,
      false,
      EAM_Pref,

      {"\xC5\x82\x20\x03", 4},
      {"\xC4\x82\x20\x03", 4},
      NULLUsefulBufC,
      NULLUsefulBufC
   },

   { "bignum gets preferred",
      -1,
      {"\x00\x03",2},
      0,
      false,
      EAM_Pref,

      NULLUsefulBufC,
      NULLUsefulBufC,
      {"\xC5\x82\x20\x03", 4},
      {"\xC4\x82\x20\x03", 4},
   }

   // TODO: add more test cases, including converting some of the already-existing
};



static void
EAMTestSetup(const struct EAMEncodeTest *pTest, QCBOREncodeContext *pEnc)
{
   QCBOREncode_Init(pEnc, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));

   switch(pTest->eSerialization) {
      case EAM_Pref:
         QCBOREncode_Config(pEnc, QCBOR_ENCODE_CONFIG_PREFERRED );
         break;
      case EAM_CDE:
         QCBOREncode_Config(pEnc, QCBOR_ENCODE_CONFIG_CDE);
         break;

      default:
         break;
   }
}


/* Test QCBOR v1 compatible functions */
int32_t ExponentAndMantissaEncodeTestsv1(void)
{
   QCBOREncodeContext EC;
   UsefulBufC         EncodedExponentAndMantissa;

   // Constant for the big number used in all the tests.
   static const uint8_t spBigNum[] = {0x01, 0x02, 0x03, 0x04, 0x05,
                                      0x06, 0x07, 0x08, 0x09, 0x010};
   const UsefulBufC   BigNum = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBigNum);

   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddDecimalFraction(&EC, 3, -1); // 3 * (10 ^ -1)
   QCBOREncode_AddTDecimalFraction(&EC, QCBOR_ENCODE_AS_BORROWED, 4, -1); // 3 * (10 ^ -1)
   QCBOREncode_AddDecimalFractionBigNum(&EC, BigNum , false, -20);
   QCBOREncode_AddTDecimalFractionBigNum(&EC, QCBOR_ENCODE_AS_BORROWED, BigNum , false, 2);
   QCBOREncode_AddTDecimalFractionBigNum(&EC, QCBOR_ENCODE_AS_TAG, BigNum, true, INT64_MAX);
   QCBOREncode_AddBigFloat(&EC, 100, 300);
   QCBOREncode_AddTBigFloat(&EC, QCBOR_ENCODE_AS_BORROWED, 200, 600);
   QCBOREncode_AddBigFloatBigNum(&EC, BigNum, false, -20);
   QCBOREncode_AddTBigFloatBigNum(&EC, QCBOR_ENCODE_AS_BORROWED, BigNum, false, 4);
   QCBOREncode_AddTBigFloatBigNum(&EC, QCBOR_ENCODE_AS_TAG, BigNum, true, INT64_MIN);
   QCBOREncode_CloseArray(&EC);

   if(QCBOREncode_Finish(&EC, &EncodedExponentAndMantissa)) {
      return -2;
   }

   struct UBCompareDiagnostic Foo;

   int nReturn = UsefulBuf_CompareWithDiagnostic(EncodedExponentAndMantissa,
                                                 UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedExponentAndMantissaArrayv1),
                                                 &Foo);
   if(nReturn) {
      return nReturn;
   }

   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_OpenMap(&EC);

   QCBOREncode_AddDecimalFractionToMap(&EC, "decimal fraction", 3, -1);

   QCBOREncode_AddDecimalFractionToMapN(&EC, 300, 3, -1);

   QCBOREncode_AddDecimalFractionBigNumToMapSZ(&EC,
                                             "decimal fraction bignum postive",
                                             BigNum,
                                             false,
                                             -200);

   QCBOREncode_AddDecimalFractionBigNumToMapN(&EC,
                                              400,
                                              BigNum,
                                              false,
                                              INT32_MAX);

   QCBOREncode_AddTDecimalFractionBigNumToMapSZ(&EC,
                                                "decimal fraction bignum negative",
                                                QCBOR_ENCODE_AS_TAG,
                                                BigNum,
                                                true,
                                                INT64_MAX);

   QCBOREncode_AddTDecimalFractionBigNumToMapN(&EC,
                                               500,
                                               QCBOR_ENCODE_AS_TAG,
                                               BigNum,
                                               true,
                                               INT64_MAX);

   QCBOREncode_AddBigFloatToMap(&EC, "big float", 100, 300);

   QCBOREncode_AddBigFloatToMapN(&EC, 600, 100, 300);

   QCBOREncode_AddBigFloatBigNumToMap(&EC,
                                      "big float bignum positive",
                                      BigNum,
                                      false,
                                      -20);

   QCBOREncode_AddBigFloatBigNumToMapN(&EC,
                                       700,
                                       BigNum,
                                       false,
                                       -20);

   QCBOREncode_AddTBigFloatBigNumToMapSZ(&EC,
                                         "big float bignum negative",
                                         QCBOR_ENCODE_AS_TAG,
                                         BigNum,
                                         true,
                                         INT64_MIN);

   QCBOREncode_AddTBigFloatBigNumToMapN(&EC,
                                        800,
                                        QCBOR_ENCODE_AS_TAG,
                                        BigNum,
                                        true,
                                        INT64_MIN);

   QCBOREncode_CloseMap(&EC);

   if(QCBOREncode_Finish(&EC, &EncodedExponentAndMantissa)) {
      return -3;
   }


   struct UBCompareDiagnostic Diag;

   nReturn = UsefulBuf_CompareWithDiagnostic(EncodedExponentAndMantissa,
                                             UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedExponentAndMantissaMapv1),
                                             &Diag);
   if(nReturn) {
      return nReturn + 1000000; // +1000000 to distinguish from first test above
   }

   return 0;
}



int32_t
ExponentAndMantissaEncodeTests(void)
{
   QCBOREncodeContext EC;
   UsefulBufC         EncodedExponentAndMantissa;
   int                nIndex;
   QCBORError         uErr;

   int32_t uReturn = ExponentAndMantissaEncodeTestsv1();
   if(uReturn) {
      return uReturn;
   }

   const int nNumberOfTests = C_ARRAY_COUNT(EET, struct EAMEncodeTest);

   for(nIndex = 0; nIndex < nNumberOfTests; nIndex++) {
      struct EAMEncodeTest *pTest = &EET[nIndex];


      if(UsefulBuf_IsNULLC(pTest->BigNumMantissa)) {
         EAMTestSetup(pTest, &EC);

         QCBOREncode_AddDecimalFraction(&EC, pTest->nMantissa, pTest->nExponent);
         uErr = QCBOREncode_Finish(&EC, &EncodedExponentAndMantissa);
         if(uErr) {
            return MakeTestResultCode((uint32_t)nIndex, 1, uErr);
         }

         if(UsefulBuf_Compare(EncodedExponentAndMantissa, pTest->DecFrac)) {
            return MakeTestResultCode((uint32_t)nIndex, 2, 0);
         }

         EAMTestSetup(pTest, &EC);
         QCBOREncode_AddBigFloat(&EC, pTest->nMantissa, pTest->nExponent);
         uErr = QCBOREncode_Finish(&EC, &EncodedExponentAndMantissa);
         if(uErr) {
            return MakeTestResultCode((uint32_t)nIndex, 11, uErr);
         }

         if(UsefulBuf_Compare(EncodedExponentAndMantissa, pTest->BigFloat)) {
            return MakeTestResultCode((uint32_t)nIndex, 12, 0);
         }

      } else {
         EAMTestSetup(pTest, &EC);

         //QCBOREncode_AddDecimalFractionBigNum(&EC, pTest->BigNumMantissa, pTest->bSign, pTest->nExponent);
         QCBOREncode_AddTDecimalFractionBigMantissa(&EC, QCBOR_ENCODE_AS_TAG, pTest->BigNumMantissa, pTest->bSign, pTest->nExponent);
         uErr = QCBOREncode_Finish(&EC, &EncodedExponentAndMantissa);
         if(uErr) {
            return MakeTestResultCode((uint32_t)nIndex, 11, uErr);
         }

         if(UsefulBuf_Compare(EncodedExponentAndMantissa, pTest->DecFracBig)) {
            return MakeTestResultCode((uint32_t)nIndex, 12, 0);
         }

         EAMTestSetup(pTest, &EC);

         //QCBOREncode_AddBigFloatBigNum(&EC, pTest->BigNumMantissa, pTest->bSign, pTest->nExponent);
         QCBOREncode_AddTBigFloatBigMantissa(&EC, QCBOR_ENCODE_AS_TAG, pTest->BigNumMantissa, pTest->bSign, pTest->nExponent);
         uErr = QCBOREncode_Finish(&EC, &EncodedExponentAndMantissa);
         if(uErr) {
            return MakeTestResultCode((uint32_t)nIndex, 11, uErr);
         }

         if(UsefulBuf_Compare(EncodedExponentAndMantissa, pTest->BigFloatBig)) {
            return MakeTestResultCode((uint32_t)nIndex, 12, 0);
         }
      }
   }

   return 0;
}


#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */


int32_t QCBORHeadTest(void)
{
   /* This test doesn't have to be extensive, because just about every
    * other test exercises QCBOREncode_EncodeHead().
    */
   // ---- basic test to encode a zero ----
   UsefulBuf_MAKE_STACK_UB(RightSize, QCBOR_HEAD_BUFFER_SIZE);

   UsefulBufC encoded = QCBOREncode_EncodeHead(RightSize,
                                               CBOR_MAJOR_TYPE_POSITIVE_INT,
                                               0,
                                               0);

   static const uint8_t expectedZero[] = {0x00};

   if(UsefulBuf_Compare(encoded, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(expectedZero))) {
      return -1;
   }

   // ---- Encode a zero padded out to an 8 byte integer ----
   encoded = QCBOREncode_EncodeHead(RightSize,
                                    CBOR_MAJOR_TYPE_POSITIVE_INT,
                                    8, // uMinSize is 8 bytes
                                    0);

   static const uint8_t expected9bytes[] = {0x1b, 0x00, 0x00, 0x00, 0x00,
                                                  0x00, 0x00, 0x00, 0x00};

   if(UsefulBuf_Compare(encoded, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(expected9bytes))) {
      return -2;
   }


   // ---- Try to encode into too-small a buffer ----
   UsefulBuf_MAKE_STACK_UB(TooSmall, QCBOR_HEAD_BUFFER_SIZE-1);

   encoded = QCBOREncode_EncodeHead(TooSmall,
                                    CBOR_MAJOR_TYPE_POSITIVE_INT,
                                    0,
                                    0);

   if(!UsefulBuf_IsNULLC(encoded)) {
      return -3;
   }

   return 0;
}


static const uint8_t spExpectedForOpenBytes[] = {
   0x50, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78,
   0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78,
   0x78
};

static const uint8_t spExpectedForOpenBytes2[] = {
   0xA4, 0x0A, 0x16, 0x14, 0x42, 0x78, 0x78, 0x66,
   0x74, 0x68, 0x69, 0x72, 0x74, 0x79, 0x43, 0x79,
   0x79, 0x79, 0x18, 0x28, 0x81, 0x40
};

int32_t
OpenCloseBytesTest(void)
{
   UsefulBuf_MAKE_STACK_UB(   TestBuf,  20);
   UsefulBuf_MAKE_STACK_UB(   TestBuf2, 30);
   QCBOREncodeContext         EC;
   UsefulBuf                  Place;
   UsefulBufC                 Encoded;
   QCBORError                 uErr;

   /* Normal use case -- add a byte string that fits */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenBytes(&EC, &Place);
   if(Place.ptr != TestBuf.ptr ||
      Place.len != TestBuf.len) {
      return 1;
   }
   Place.len -= 4;
   UsefulBuf_Set(Place, 'x');
   QCBOREncode_CloseBytes(&EC, Place.len);
   QCBOREncode_Finish(&EC, &Encoded);
   if(UsefulBuf_Compare(Encoded,
                        UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedForOpenBytes))) {
      return 2;
   }

   /* Run the same test but with a NULL buffer */
   QCBOREncode_Init(&EC, (UsefulBuf){NULL, 20});
   QCBOREncode_OpenBytes(&EC, &Place);
   if(!UsefulBuf_IsNULL(Place)) {
      return 3;
   }
   Place.len -= 4;
   /* We don't actually write anything since the pointer is NULL, but advance nevertheless. */
   QCBOREncode_CloseBytes(&EC, Place.len);
   uErr = QCBOREncode_Finish(&EC, &Encoded);
   if(uErr != QCBOR_SUCCESS ||
      Encoded.len != sizeof(spExpectedForOpenBytes)) {
      return 4;
   }

   /* Open a byte string with no room left */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_AddSZString(&EC, "0123456789012345678");
   QCBOREncode_OpenBytes(&EC, &Place);
   if(Place.ptr != NULL ||
      Place.len != 0) {
      return 5;
   }

   /* Try to extend byte string past end of encoding output buffer */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_AddSZString(&EC, "012345678901234567");
   QCBOREncode_OpenBytes(&EC, &Place);
   /* Don't bother to write any bytes*/
   QCBOREncode_CloseBytes(&EC, Place.len+1);
   uErr = QCBOREncode_GetErrorState(&EC);
   if(uErr != QCBOR_ERR_BUFFER_TOO_SMALL) {
      return 6;
   }

   /* Close a byte string without opening one. */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_AddSZString(&EC, "012345678");
   QCBOREncode_CloseBytes(&EC, 1);
   uErr = QCBOREncode_GetErrorState(&EC);
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(uErr != QCBOR_ERR_TOO_MANY_CLOSES) {
      return 7;
   }
#else
   if(uErr != QCBOR_SUCCESS) {
      return 107;
   }
#endif  /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   /* Forget to close a byte string */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_AddSZString(&EC, "012345678");
   QCBOREncode_OpenBytes(&EC, &Place);
   uErr = QCBOREncode_Finish(&EC, &Encoded);
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(uErr != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
      return 8;
   }
#else
   if(uErr != QCBOR_SUCCESS) {
      return 108;
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   /* Try to open a byte string in a byte string */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_AddSZString(&EC, "012345678");
   QCBOREncode_OpenBytes(&EC, &Place);
   QCBOREncode_OpenBytes(&EC, &Place);
   uErr = QCBOREncode_GetErrorState(&EC);
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(uErr != QCBOR_ERR_OPEN_BYTE_STRING) {
      return 9;
   }
#else
   if(uErr != QCBOR_SUCCESS) {
      return 109;
   }
#endif  /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   /* A successful case with a little complexity */
   QCBOREncode_Init(&EC, TestBuf2);
   QCBOREncode_OpenMap(&EC);
      QCBOREncode_AddInt64ToMapN(&EC, 10, 22);
      QCBOREncode_OpenBytesInMapN(&EC, 20, &Place);
         Place.len = 2;
         UsefulBuf_Set(Place, 'x');
      QCBOREncode_CloseBytes(&EC, 2);
      QCBOREncode_OpenBytesInMapSZ(&EC, "thirty", &Place);
         Place.len = 3;
         UsefulBuf_Set(Place, 'y');
      QCBOREncode_CloseBytes(&EC, 3);
      QCBOREncode_OpenArrayInMapN(&EC, 40);
         QCBOREncode_OpenBytes(&EC, &Place);
         QCBOREncode_CloseBytes(&EC, 0);
      QCBOREncode_CloseArray(&EC);
   QCBOREncode_CloseMap(&EC);
   uErr = QCBOREncode_Finish(&EC, &Encoded);
   if(uErr != QCBOR_SUCCESS) {
      return 10;
   }
   if(UsefulBuf_Compare(Encoded,
                        UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedForOpenBytes2))) {
      return 11;
   }

   return 0;
}



int32_t
SortMapTest(void)
{
   UsefulBuf_MAKE_STACK_UB(   TestBuf,  200);
   QCBOREncodeContext         EC;
   UsefulBufC                 EncodedAndSorted;
   QCBORError                 uErr;
   struct UBCompareDiagnostic CompareDiagnostics;


   /* --- Basic sort test case --- */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_AddInt64ToMapN(&EC, 3, 3);
   QCBOREncode_AddInt64ToMapN(&EC, 1, 1);
   QCBOREncode_AddInt64ToMapN(&EC, 4, 4);
   QCBOREncode_AddInt64ToMapN(&EC, 2, 2);
   QCBOREncode_CloseAndSortMap(&EC);
   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr) {
      return 11;
   }

   static const uint8_t spBasic[] = {
      0xA4, 0x01, 0x01, 0x02, 0x02, 0x03, 0x03, 0x04, 0x04};

   if(UsefulBuf_Compare(EncodedAndSorted, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spBasic))) {
      return 12;
   }

   /* --- Empty map sort test case --- */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_CloseAndSortMap(&EC);
   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr) {
      return 21;
   }

   static const uint8_t spEmpty[] = {0xA0};
   if(UsefulBuf_CompareWithDiagnostic(EncodedAndSorted,
                                      UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spEmpty),
                                      &CompareDiagnostics)) {
      return 22;
   }

   /* --- Several levels of nested sorted maps ---  */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMap(&EC);
     QCBOREncode_AddInt64ToMap(&EC, "three", 3);
     QCBOREncode_OpenMapInMapN(&EC, 428);
       QCBOREncode_AddNULLToMap(&EC, "null");
       QCBOREncode_OpenArrayInMap(&EC, "array");
         QCBOREncode_AddSZString(&EC, "hi");
         QCBOREncode_AddSZString(&EC, "there");
         QCBOREncode_CloseArray(&EC);
       QCBOREncode_OpenMapInMap(&EC, "empty2");
         QCBOREncode_CloseAndSortMap(&EC);
       QCBOREncode_OpenMapInMap(&EC, "empty1");
         QCBOREncode_CloseAndSortMap(&EC);
       QCBOREncode_CloseAndSortMap(&EC);
     QCBOREncode_AddDateEpochToMapN(&EC, 88, 888888);
     QCBOREncode_AddBoolToMap(&EC, "boo", true);
     QCBOREncode_CloseAndSortMap(&EC);
   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr) {
      return 31;
   }

   /* Correctly sorted.
    * {
    *   88: 1(888888),
    *   428: {
    *     "null": null,
    *     "array": [
    *       "hi",
    *       "there"
    *     ],
    *     "empty1": {},
    *     "empty2": {}
    *   },
    *   "boo": true,
    *   "three": 3
    *  }
    */
   static const uint8_t spSorted[] = {
      0xA4, 0x18, 0x58, 0xC1, 0x1A, 0x00, 0x0D, 0x90,
      0x38, 0x19, 0x01, 0xAC, 0xA4, 0x64, 0x6E, 0x75,
      0x6C, 0x6C, 0xF6, 0x65, 0x61, 0x72, 0x72, 0x61,
      0x79, 0x82, 0x62, 0x68, 0x69, 0x65, 0x74, 0x68,
      0x65, 0x72, 0x65, 0x66, 0x65, 0x6D, 0x70, 0x74,
      0x79, 0x31, 0xA0, 0x66, 0x65, 0x6D, 0x70, 0x74,
      0x79, 0x32, 0xA0, 0x63, 0x62, 0x6F, 0x6F, 0xF5,
      0x65, 0x74, 0x68, 0x72, 0x65, 0x65, 0x03};

   if(UsefulBuf_CompareWithDiagnostic(EncodedAndSorted,
                                      UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spSorted),
                                      &CompareDiagnostics)) {
      return 32;
   }


   /* Same data items, but added in a different order */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMap(&EC);
     QCBOREncode_AddInt64ToMap(&EC, "three", 3);
     QCBOREncode_OpenMapInMapN(&EC, 428);
       QCBOREncode_OpenMapInMap(&EC, "empty1");
         QCBOREncode_CloseAndSortMap(&EC);
       QCBOREncode_OpenArrayInMap(&EC, "array");
         QCBOREncode_AddSZString(&EC, "hi");
         QCBOREncode_AddSZString(&EC, "there");
         QCBOREncode_CloseArray(&EC);
       QCBOREncode_OpenMapInMap(&EC, "empty2");
         QCBOREncode_CloseAndSortMap(&EC);
       QCBOREncode_AddNULLToMap(&EC, "null");
       QCBOREncode_CloseAndSortMap(&EC);
     QCBOREncode_AddDateEpochToMapN(&EC, 88, 888888);
     QCBOREncode_AddBoolToMap(&EC, "boo", true);
     QCBOREncode_CloseAndSortMap(&EC);
   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr) {
      return 31;
   }

   if(UsefulBuf_CompareWithDiagnostic(EncodedAndSorted,
                                      UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spSorted),
                                      &CompareDiagnostics)) {
      return 32;
   }

   /* Same data items, but added in a different order */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMap(&EC);
     QCBOREncode_AddBoolToMap(&EC, "boo", true);
     QCBOREncode_OpenMapInMapN(&EC, 428);
       QCBOREncode_OpenMapInMap(&EC, "empty1");
         QCBOREncode_CloseAndSortMap(&EC);
       QCBOREncode_OpenArrayInMap(&EC, "array");
         QCBOREncode_AddSZString(&EC, "hi");
         QCBOREncode_AddSZString(&EC, "there");
         QCBOREncode_CloseArray(&EC);
       QCBOREncode_OpenMapInMap(&EC, "empty2");
         QCBOREncode_CloseAndSortMap(&EC);
       QCBOREncode_AddNULLToMap(&EC, "null");
       QCBOREncode_CloseAndSortMap(&EC);
     QCBOREncode_AddDateEpochToMapN(&EC, 88, 888888);
     QCBOREncode_AddInt64ToMap(&EC, "three", 3);
     QCBOREncode_CloseAndSortMap(&EC);
   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr) {
      return 31;
   }

   if(UsefulBuf_CompareWithDiagnostic(EncodedAndSorted,
                                      UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spSorted),
                                      &CompareDiagnostics)) {
      return 32;
   }



   /* --- Degenerate case of everything in order --- */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_AddInt64ToMapN(&EC, 0, 0);
   QCBOREncode_AddInt64ToMapN(&EC, 1, 1);
   QCBOREncode_AddInt64ToMapN(&EC, 2, 2);
   QCBOREncode_AddInt64ToMap(&EC, "a", 3);
   QCBOREncode_AddInt64ToMap(&EC, "b", 4);
   QCBOREncode_AddInt64ToMap(&EC, "aa", 5);
   QCBOREncode_AddInt64ToMap(&EC, "aaa", 6);
   QCBOREncode_CloseAndSortMap(&EC);
   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr) {
      return 41;
   }

   static const uint8_t sp6Items[] = {
      0xA7, 0x00, 0x00, 0x01, 0x01, 0x02, 0x02, 0x61,
      0x61, 0x03, 0x61, 0x62, 0x04, 0x62, 0x61, 0x61,
      0x05, 0x63, 0x61, 0x61, 0x61, 0x06};
   if(UsefulBuf_CompareWithDiagnostic(EncodedAndSorted,
                                      UsefulBuf_FROM_BYTE_ARRAY_LITERAL(sp6Items),
                                      &CompareDiagnostics)) {
      return 42;
   }

   /* --- Degenerate case -- reverse order --- */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_AddInt64ToMap(&EC, "aaa", 6);
   QCBOREncode_AddInt64ToMap(&EC, "aa", 5);
   QCBOREncode_AddInt64ToMap(&EC, "b", 4);
   QCBOREncode_AddInt64ToMap(&EC, "a", 3);
   QCBOREncode_AddInt64ToMapN(&EC, 2, 2);
   QCBOREncode_AddInt64ToMapN(&EC, 0, 0);
   QCBOREncode_AddInt64ToMapN(&EC, 1, 1);
   QCBOREncode_CloseAndSortMap(&EC);
   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr) {
      return 51;
   }

   if(UsefulBuf_CompareWithDiagnostic(EncodedAndSorted,
                                      UsefulBuf_FROM_BYTE_ARRAY_LITERAL(sp6Items),
                                      &CompareDiagnostics)) {
      return 52;
   }

   /* --- Same items, randomly out of order --- */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_AddInt64ToMap(&EC, "aa", 5);
   QCBOREncode_AddInt64ToMapN(&EC, 2, 2);
   QCBOREncode_AddInt64ToMapN(&EC, 0, 0);
   QCBOREncode_AddInt64ToMap(&EC, "b", 4);
   QCBOREncode_AddInt64ToMap(&EC, "aaa", 6);
   QCBOREncode_AddInt64ToMap(&EC, "a", 3);
   QCBOREncode_AddInt64ToMapN(&EC, 1, 1);
   QCBOREncode_CloseAndSortMap(&EC);
   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr) {
      return 61;
   }

   if(UsefulBuf_CompareWithDiagnostic(EncodedAndSorted,
                                      UsefulBuf_FROM_BYTE_ARRAY_LITERAL(sp6Items),
                                      &CompareDiagnostics)) {
      return 62;
   }

   /* --- Stuff in front of and after array to sort --- */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenArray(&EC);
   QCBOREncode_AddInt64(&EC, 111);
   QCBOREncode_AddInt64(&EC, 222);
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_AddInt64ToMapN(&EC, 0, 0);
   QCBOREncode_AddInt64ToMapN(&EC, 1, 1);
   QCBOREncode_AddInt64ToMapN(&EC, 2, 2);
   QCBOREncode_CloseAndSortMap(&EC);
   QCBOREncode_AddInt64(&EC, 888);
   QCBOREncode_AddInt64(&EC, 999);
   QCBOREncode_CloseArray(&EC);
   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr) {
      return 71;
   }

   static const uint8_t spPreItems[] = {
      0x85, 0x18, 0x6F, 0x18, 0xDE, 0xA3, 0x00, 0x00,
      0x01, 0x01, 0x02, 0x02, 0x19, 0x03, 0x78, 0x19,
      0x03, 0xE7};
   if(UsefulBuf_CompareWithDiagnostic(EncodedAndSorted,
                                      UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spPreItems),
                                      &CompareDiagnostics)) {
      return 72;
   }

   /* --- map with labels of all CBOR major types and in reverse order --- */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMap(&EC);

   /* Adding labels directly rather than AddToMap functions */

#ifndef USEFULBUF_DISABLE_ALL_FLOAT
   QCBOREncode_AddDouble(&EC, 8.77);
   QCBOREncode_AddInt64(&EC, 7);
#endif /* QCBOR_DISABLE_ALL_FLOAT */

   QCBOREncode_AddBool(&EC, true);
   QCBOREncode_AddInt64(&EC, 6);

   QCBOREncode_AddDateEpoch(&EC, 88);
   QCBOREncode_AddInt64(&EC, 5);

   QCBOREncode_AddEncoded(&EC, UsefulBuf_FromSZ("\xa0"));
   QCBOREncode_AddInt64(&EC, 4);

   QCBOREncode_AddEncoded(&EC, UsefulBuf_FromSZ("\x80"));
   QCBOREncode_AddInt64(&EC, 7);

   QCBOREncode_AddInt64ToMap(&EC, "text", 3);

   QCBOREncode_AddBytes(&EC, UsefulBuf_FromSZ("xx"));
   QCBOREncode_AddInt64(&EC, 2);

   QCBOREncode_AddInt64ToMapN(&EC, 1, 1); /* Integer */
   QCBOREncode_CloseAndSortMap(&EC);

   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr) {
      return 81;
   }

#ifndef USEFULBUF_DISABLE_ALL_FLOAT
   static const uint8_t spLabelTypes[] = {
      0xA8, 0x01, 0x01, 0x42, 0x78, 0x78, 0x02, 0x64,
      0x74, 0x65, 0x78, 0x74, 0x03, 0x80, 0x07, 0xA0,
      0x04, 0xC1, 0x18, 0x58, 0x05, 0xF5, 0x06, 0xFB,
      0x40, 0x21, 0x8A, 0x3D, 0x70, 0xA3, 0xD7, 0x0A,
      0x07};
#else
   static const uint8_t spLabelTypes[] = {
      0xA7, 0x01, 0x01, 0x42, 0x78, 0x78, 0x02, 0x64,
      0x74, 0x65, 0x78, 0x74, 0x03, 0x80, 0x07, 0xA0,
      0x04, 0xC1, 0x18, 0x58, 0x05, 0xF5, 0x06};
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */

   if(UsefulBuf_CompareWithDiagnostic(EncodedAndSorted,
                                      UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spLabelTypes),
                                      &CompareDiagnostics)) {
      return 82;
   }

   /* --- labels are indefinitely encoded ---  */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMap(&EC);

   QCBOREncode_AddInt64ToMap(&EC, "aaaa", 1);

   QCBOREncode_AddInt64ToMap(&EC, "bb", 2);

   QCBOREncode_AddEncoded(&EC, UsefulBuf_FromSZ("\x7f\x61" "a" "\x61" "a" "\xff"));
   QCBOREncode_AddInt64(&EC, 3);

   QCBOREncode_AddEncoded(&EC, UsefulBuf_FromSZ("\x7f" "\x61" "c" "\xff"));
   QCBOREncode_AddInt64(&EC, 4);

   QCBOREncode_CloseAndSortMap(&EC);

   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr) {
      return 91;
   }
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   static const uint8_t spIndefItems[] = {
      0xA4, 0x62, 0x62, 0x62, 0x02, 0x64, 0x61, 0x61,
      0x61, 0x61, 0x01, 0x7F, 0x61, 0x61, 0x61, 0x61,
      0xFF, 0x03, 0x7F, 0x61, 0x63, 0xFF, 0x04};
   if(UsefulBuf_CompareWithDiagnostic(EncodedAndSorted,
                                       UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spIndefItems),
                                       &CompareDiagnostics)) {
       return 92;
   }

   /* --- Indefinitely encoded maps --- */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMapIndefiniteLength(&EC);

   QCBOREncode_OpenMapIndefiniteLengthInMap(&EC, "aa");
   QCBOREncode_CloseMapIndefiniteLength(&EC);

   QCBOREncode_OpenArrayIndefiniteLengthInMap(&EC, "ff");
   QCBOREncode_CloseArrayIndefiniteLength(&EC);

   QCBOREncode_OpenMapIndefiniteLengthInMap(&EC, "zz");
   QCBOREncode_CloseMapIndefiniteLength(&EC);

   QCBOREncode_OpenMapIndefiniteLengthInMap(&EC, "bb");
   QCBOREncode_CloseMapIndefiniteLength(&EC);

   QCBOREncode_CloseAndSortMapIndef(&EC);
   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr) {
      return 101;
   }

   static const uint8_t spIndeMaps[] = {
      0xBF, 0x62, 0x61, 0x61, 0xBF, 0xFF, 0x62, 0x62,
      0x62, 0xBF, 0xFF, 0x62, 0x66, 0x66, 0x9F, 0xFF,
      0x62, 0x7A, 0x7A, 0xBF, 0xFF, 0xFF, 0x06, 0xFB};
   if(UsefulBuf_CompareWithDiagnostic(EncodedAndSorted,
                                      UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spIndeMaps),
                                      &CompareDiagnostics)) {
      return 102;
   }
#endif

   /* --- Duplicate label test  --- */
   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_AddInt64ToMapN(&EC, 3, 3);
   QCBOREncode_AddInt64ToMapN(&EC, 1, 1);
   QCBOREncode_AddInt64ToMapN(&EC, 1, 1);
   QCBOREncode_AddInt64ToMapN(&EC, 2, 2);
   QCBOREncode_CloseAndSortMap(&EC);
   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr != QCBOR_ERR_DUPLICATE_LABEL) {
      return 114;
   }

   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_AddInt64ToMapN(&EC, 3, 3);
   QCBOREncode_AddInt64ToMapN(&EC, 1, 1);
   QCBOREncode_AddInt64ToMapN(&EC, 1, 2);
   QCBOREncode_AddInt64ToMapN(&EC, 2, 2);
   QCBOREncode_CloseAndSortMap(&EC);
   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr != QCBOR_ERR_DUPLICATE_LABEL) {
      return 115;
   }

   QCBOREncode_Init(&EC, TestBuf);
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_AddInt64ToMap(&EC, "abc", 3);
   QCBOREncode_AddInt64ToMap(&EC, "def", 1);
   QCBOREncode_AddInt64ToMap(&EC, "def", 1);
   QCBOREncode_AddInt64ToMap(&EC, "def", 2);
   QCBOREncode_CloseAndSortMap(&EC);
   uErr = QCBOREncode_Finish(&EC, &EncodedAndSorted);
   if(uErr != QCBOR_ERR_DUPLICATE_LABEL) {
      return 116;
   }

   return 0;
}


#if !defined(USEFULBUF_DISABLE_ALL_FLOAT) && !defined(QCBOR_DISABLE_PREFERRED_FLOAT)

#include <math.h> /* For INFINITY and NAN and isnan() */


/* Public function. See qcbor_encode_tests.h */
int32_t CDETest(void)
{
   QCBOREncodeContext EC;
   UsefulBufC         Encoded;
   QCBORError         uExpectedErr;

   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));

   QCBOREncode_Config(&EC, QCBOR_ENCODE_CONFIG_CDE);


   /* Items added to test sorting and preferred encoding of numbers and floats */
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_AddFloatToMap(&EC, "k", 1.0f);
   QCBOREncode_AddInt64ToMap(&EC, "a", 1);
   QCBOREncode_AddDoubleToMap(&EC, "x", 2.0);
   QCBOREncode_AddDoubleToMap(&EC, "r", 3.4028234663852886E+38);
   QCBOREncode_AddDoubleToMap(&EC, "b", NAN);
   QCBOREncode_AddUndefToMap(&EC, "t"); /* Test because dCBOR disallows */

   QCBOREncode_CloseMap(&EC);

   uExpectedErr = QCBOREncode_Finish(&EC, &Encoded);
   if(uExpectedErr != QCBOR_SUCCESS) {
      return 2;
   }

   static const uint8_t spExpectedCDE[] = {
      0xA6, 0x61, 0x61, 0x01, 0x61, 0x62, 0xF9, 0x7E,
      0x00, 0x61, 0x6B, 0xF9, 0x3C, 0x00, 0x61, 0x72,
      0xFA, 0x7F, 0x7F, 0xFF, 0xFF, 0x61, 0x74, 0xF7,
      0x61, 0x78, 0xF9, 0x40, 0x00};

   if(UsefulBuf_Compare(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedCDE),
                        Encoded)) {
      return 1;
   }


#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   uExpectedErr = QCBOR_ERR_NOT_PREFERRED;
#else
   uExpectedErr = QCBOR_SUCCESS;
#endif

#ifndef  QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   /* Next, make sure methods that encode non-CDE error out */
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_Config(&EC, QCBOR_ENCODE_CONFIG_CDE);
   QCBOREncode_OpenMapIndefiniteLength(&EC);
   QCBOREncode_CloseMap(&EC);
   if(QCBOREncode_GetErrorState(&EC) != uExpectedErr) {
      return 100;
   }
#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

   return 0;
}

/* Public function. See qcbor_encode_tests.h */
int32_t DCBORTest(void)
{
   QCBOREncodeContext EC;
   UsefulBufC         Encoded;
   QCBORError         uExpectedErr;

   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_Config(&EC, QCBOR_ENCODE_CONFIG_DCBOR);


   /* Items added to test sorting and preferred encoding of numbers and floats */
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_AddFloatToMap(&EC, "k", 1.0f);
   QCBOREncode_AddInt64ToMap(&EC, "a", 1);
   QCBOREncode_AddDoubleToMap(&EC, "x", 2.0);
   QCBOREncode_AddDoubleToMap(&EC, "r", 3.4028234663852886E+38);
   QCBOREncode_AddDoubleToMap(&EC, "d1", -18446744073709549568.0);
   QCBOREncode_AddDoubleToMap(&EC, "d2", -18446744073709551616.0);
   QCBOREncode_AddDoubleToMap(&EC, "d3", -18446744073709555712.0);
   QCBOREncode_AddDoubleToMap(&EC, "b", NAN);

   QCBOREncode_CloseMap(&EC);

   QCBOREncode_Finish(&EC, &Encoded);

   static const uint8_t spExpecteddCBOR[] = {
      0xA8, 0x61, 0x61, 0x01, 0x61, 0x62, 0xF9, 0x7E, 0x00, 0x61, 0x6B, 0x01, 0x61, 0x72, 0xFA, 0x7F, 0x7F, 0xFF, 0xFF, 0x61, 0x78, 0x02, 0x62, 0x64, 0x31, 0x3B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xF7, 0xFF, 0x62, 0x64, 0x32, 0x3B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x62, 0x64, 0x33, 0xFB, 0xC3, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

   if(UsefulBuf_Compare(UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpecteddCBOR),
                        Encoded)) {
      return 1;
   }


#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   uExpectedErr = QCBOR_ERR_NOT_PREFERRED;
#else
   uExpectedErr = QCBOR_SUCCESS;
#endif

   /* Next, make sure methods that encode of non-CDE error out */

#ifndef  QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   /* Indefinite-length map */
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_Config(&EC, QCBOR_ENCODE_CONFIG_DCBOR);
   QCBOREncode_OpenMapIndefiniteLength(&EC);
   QCBOREncode_CloseMap(&EC);
   if(QCBOREncode_GetErrorState(&EC) != uExpectedErr) {
      return 100;
   }

   /* Indefinite-length array */
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_Config(&EC, QCBOR_ENCODE_CONFIG_DCBOR);
   QCBOREncode_OpenArrayIndefiniteLength(&EC);
   QCBOREncode_CloseMap(&EC);
   if(QCBOREncode_GetErrorState(&EC) != uExpectedErr) {
      return 101;
   }
#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

   /* The "undef" special value */
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_Config(&EC, QCBOR_ENCODE_CONFIG_DCBOR);
   QCBOREncode_AddUndef(&EC);
   QCBOREncode_CloseMap(&EC);
   if(QCBOREncode_GetErrorState(&EC) != uExpectedErr) {
      return 102;
   }


   /* Improvement: when indefinite length string encoding is supported
    * test it here too. */

   return 0;

}
#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT && ! QCBOR_DISABLE_PREFERRED_FLOAT */

int32_t SubStringTest(void)
{
   QCBOREncodeContext EC;
   size_t             uStart;
   size_t             uCurrent;
   UsefulBufC         SS;
   UsefulBufC         Encoded;
   QCBORError         uErr;

   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_OpenArray(&EC);
   uStart = QCBOREncode_Tell(&EC);
   QCBOREncode_AddInt64(&EC, 0);
   SS = QCBOREncode_SubString(&EC, uStart);
   if(UsefulBuf_Compare(SS, (UsefulBufC){"\x00", 1})) {
      return 1;
   }

   QCBOREncode_OpenArray(&EC);

   QCBOREncode_CloseArray(&EC);
   SS = QCBOREncode_SubString(&EC, uStart);
   if(UsefulBuf_Compare(SS, (UsefulBufC){"\x00\x80", 2})) {
      return 3;
   }


   /* Try it on a sequence */
   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   uStart = QCBOREncode_Tell(&EC);
   QCBOREncode_AddInt64(&EC, 1);
   QCBOREncode_AddInt64(&EC, 1);
   QCBOREncode_AddInt64(&EC, 1);
   QCBOREncode_AddInt64(&EC, 1);
   SS = QCBOREncode_SubString(&EC, uStart);
   if(UsefulBuf_Compare(SS, (UsefulBufC){"\x01\x01\x01\x01", 4})) {
      return 10;
   }

   uCurrent = QCBOREncode_Tell(&EC);
   if(!UsefulBuf_IsNULLC(QCBOREncode_SubString(&EC, uCurrent+1))) {
      return 11;
   }

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   /* Now cause an error */
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_CloseArray(&EC);
   if(!UsefulBuf_IsNULLC(QCBOREncode_SubString(&EC, uStart))) {
      return 15;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */


   QCBOREncode_Init(&EC, UsefulBuf_FROM_BYTE_ARRAY(spBigBuf));
   QCBOREncode_AddInt64(&EC, 1);
   QCBOREncode_AddInt64(&EC, 1);
   uStart = QCBOREncode_Tell(&EC);
   QCBOREncode_OpenMap(&EC);
   QCBOREncode_OpenMapInMapN(&EC, 3);
   QCBOREncode_OpenArrayInMapN(&EC, 4);
   QCBOREncode_AddInt64(&EC, 0);
   QCBOREncode_CloseArray(&EC);
   QCBOREncode_CloseMap(&EC);
   QCBOREncode_CloseMap(&EC);
   SS = QCBOREncode_SubString(&EC, uStart);
   if(UsefulBuf_Compare(SS, (UsefulBufC){"\xA1\x03\xA1\x04\x81\x00", 6})) {
      return 20;
   }

   uErr = QCBOREncode_Finish(&EC, &Encoded);
   if(uErr) {
      return 21;
   }
   if(UsefulBuf_Compare(Encoded, (UsefulBufC){"\x01\x01\xA1\x03\xA1\x04\x81\x00", 8})) {
      return 22;
   }

   return 0;
}
