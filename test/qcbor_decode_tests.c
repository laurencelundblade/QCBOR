/*==============================================================================
Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.

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
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

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

/*==============================================================================
 Modifications beyond the version released on CAF are under the MIT license:
 
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
 ==============================================================================*/

#include "qcbor.h"
#include "qcbor_decode_tests.h"
#include <stdio.h>
#include <strings.h>
#include <math.h> // for fabs()
#include <stdlib.h>


// TODO: test other than the normal decoder mode

static void printencoded(const char *szLabel, const uint8_t *pEncoded, size_t nLen)
{
   if(szLabel) {
      printf("%s ", szLabel);
   }
   
   size_t i;
   for(i = 0; i < nLen; i++) {
      uint8_t Z = pEncoded[i];
      printf("%02x ", Z);
   }
   printf("\n");

   fflush(stdout);
}


// TODO: -- add a test for counting the top level items and adding it back in with AddRaw()


static const uint8_t pExpectedEncodedInts[] = {
   0x98, 0x2f, 0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff,
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
   0x1a, 0x18, 0xfe, 0x18, 0xff, 0x19, 0x01, 0x00,
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









// return CBOR error or -1 if type of value doesn't match

static int IntegerValuesParseTestInternal(QCBORDecodeContext *pDCtx)
{
   QCBORItem          Item;
   int nCBORError;
   
   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_ARRAY)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 || // Todo; fix this for 32-bit machines
      Item.val.int64 != -9223372036854775807LL - 1)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -4294967297)
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -4294967296)
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -4294967295)
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -4294967294)
      return -1;
   
   
   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -2147483648)
      return -1;
  
   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -2147483647)
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -65538)
      return  -1;
   
   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -65537)
      return  -1;
   
   if((nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -65536)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -65535)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -65534)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -257)
      return  -1;
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -256)
      return  -1;
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -255)
      return  -1;
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -254)
      return  -1;
   
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -25)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -24)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -23)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != -1)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 0)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 0)
      return  -1;
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 1)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 22)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 23)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 24)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 25)
      return  -1;

   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 26)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 254)
      return  -1;
   
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 255)
      return  -1;
   
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 256)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 257)
      return  -1;
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 65534)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 65535)
      return  -1;

   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 65536)
      return  -1;
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 65537)
      return  -1;
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 65538)
      return  -1;
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 2147483647)
      return  -1;
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 2147483647)
      return  -1;
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 2147483648)
      return  -1;
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 2147483649)
      return  -1;
  
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 4294967294)
      return  -1;
   
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 4294967295)
      return  -1;
   
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 4294967296)
      return  -1;
   
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 4294967297)
      return  -1;

   
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 9223372036854775807LL)
      return  -1;
   
   
   if((   nCBORError = QCBORDecode_GetNext(pDCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_UINT64 ||
      Item.val.uint64 != 18446744073709551615ULL)
      return  -1;
   
   
   if(QCBORDecode_Finish(pDCtx) != QCBOR_SUCCESS) {
      return -1;
   }
   
   return 0;
}


/* 
   Tests the decoding of lots of different integers sizes 
   and values.
 */

int IntegerValuesParseTest()
{
   int n;
   QCBORDecodeContext DCtx;
   
   QCBORDecode_Init(&DCtx, (UsefulBufC){pExpectedEncodedInts, sizeof(pExpectedEncodedInts)}, QCBOR_DECODE_MODE_NORMAL);
   
   n = IntegerValuesParseTestInternal(&DCtx);
   
   return(n);
}


/*
   Creates a simple CBOR array and returns it in *pEncoded. The array is malloced
   and needs to be freed. This is used by several tests. 
 
   Two of the inputs can be set. Two other items in the array are fixed.
 
 */

static int CreateSimpleArray(int nInt1, int nInt2, uint8_t **pEncoded, size_t *pEncodedLen)
{
   QCBOREncodeContext ECtx;
   int nReturn = -1;
   
   *pEncoded = NULL;
   *pEncodedLen = INT32_MAX;
   
   // loop runs CBOR encoding twice. First with no buffer to
   // calucate the length so buffer can be allocated correctly,
   // and last with the buffer to do the actual encoding
   do {
       QCBOREncode_Init(&ECtx, (UsefulBuf){*pEncoded, *pEncodedLen});
      QCBOREncode_OpenArray(&ECtx);
      QCBOREncode_AddInt64(&ECtx, nInt1);
      QCBOREncode_AddInt64(&ECtx, nInt2);
      QCBOREncode_AddBytes(&ECtx, ((UsefulBufC) {"galactic", 8}));
      QCBOREncode_AddBytes(&ECtx, ((UsefulBufC) {"haven token", 11}));
      QCBOREncode_CloseArray(&ECtx);
      
      if(QCBOREncode_Finish(&ECtx, pEncodedLen))
         goto Done;

      if(*pEncoded != NULL) {
         nReturn = 0;
         goto Done;
      }
      *pEncoded = malloc(*pEncodedLen);
      if(*pEncoded == NULL) {
         nReturn = -1;
         goto Done;
      }
      
   } while(1);
Done:
   return (nReturn);
   
}


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







static int ParseOrderedArray(const uint8_t *pEncoded, size_t nLen, int64_t *pInt1, int64_t *pInt2,  const uint8_t **pBuf3, size_t *pBuf3Len,  const uint8_t **pBuf4, size_t *pBuf4Len)
{
   QCBORDecodeContext DCtx;
   QCBORItem          Item;
   int                nReturn = -1; // assume error until success
   
   QCBORDecode_Init(&DCtx, (UsefulBufC){pEncoded, nLen}, QCBOR_DECODE_MODE_NORMAL);
   
   // Make sure the first thing is a map
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 || Item.uDataType != QCBOR_TYPE_ARRAY)
      goto Done;
   
   // First integer
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 | Item.uDataType != QCBOR_TYPE_INT64)
      goto Done;
   *pInt1 = Item.val.int64;
   
   // Second integer
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 || Item.uDataType != QCBOR_TYPE_INT64)
      goto Done;
   *pInt2 = Item.val.int64;
   
   // First string
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 || Item.uDataType != QCBOR_TYPE_BYTE_STRING)
      goto Done;
   *pBuf3 = Item.val.string.ptr;
   *pBuf3Len = Item.val.string.len;
   
   // Second string
   if(QCBORDecode_GetNext(&DCtx, &Item) != 0 || Item.uDataType != QCBOR_TYPE_BYTE_STRING)
      goto Done;
   *pBuf4 = Item.val.string.ptr;
   *pBuf4Len = Item.val.string.len;
   
   nReturn = 0;
   
Done:
   return(nReturn);
}




int SimpleArrayTest()
{
   uint8_t *pEncoded;
   size_t  nEncodedLen;
   
   int64_t i1, i2;
   size_t i3, i4;
   const uint8_t *s3, *s4;
   
   
   if(CreateSimpleArray(23, 6000, &pEncoded, &nEncodedLen) < 0) {
      return(-1);
   }
   
   ParseOrderedArray(pEncoded, nEncodedLen, &i1, &i2, &s3, &i3, &s4, &i4);
   
   if(i1 != 23 ||
      i2 != 6000 ||
      i3 != 8 ||
      i4 != 11 ||
      bcmp("galactic", s3, 8) !=0 ||
      bcmp("haven token", s4, 11) !=0) {
      printf("SimpleArraryTest Failed\n");
      return(-1);
   }
   
   return(0);
}



static uint8_t s_pDeepArrays[] = {0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x80};

int ParseDeepArrayTest()
{
   QCBORDecodeContext DCtx;
   int nReturn = 0;
   int i;
   
   QCBORDecode_Init(&DCtx, (UsefulBufC){s_pDeepArrays, sizeof(s_pDeepArrays)}, QCBOR_DECODE_MODE_NORMAL);
   
   for(i = 0; i < 10; i++) {
      QCBORItem Item;
      
      if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
         Item.uDataType != QCBOR_TYPE_ARRAY ||
         Item.uNestingLevel != i) {
         nReturn = -1;
         break;
      }
   }
   
   return(nReturn);
}


static uint8_t s_pTooDeepArrays[] = {0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x80};

int ParseTooDeepArrayTest()
{
   QCBORDecodeContext DCtx;
   int nReturn = 0;
   int i;
   QCBORItem Item;
   
   
   QCBORDecode_Init(&DCtx, (UsefulBufC){s_pTooDeepArrays, sizeof(s_pTooDeepArrays)}, QCBOR_DECODE_MODE_NORMAL);
   
   for(i = 0; i < 10; i++) {
      
      if(QCBORDecode_GetNext(&DCtx, &Item) != 0 ||
         Item.uDataType != QCBOR_TYPE_ARRAY ||
         Item.uNestingLevel != i) {
         nReturn = -1;
         break;
      }
   }
   
   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_ARRAY_NESTING_TOO_DEEP)
      nReturn = -1;
   
   return(nReturn);
}






int ShortBufferParseTest()
{
   int nResult  = 0;
   QCBORDecodeContext DCtx;
   int num;
   
   for(num = sizeof(pExpectedEncodedInts)-1; num; num--) {
      int n;
      
      QCBORDecode_Init(&DCtx, (UsefulBufC){pExpectedEncodedInts, num}, QCBOR_DECODE_MODE_NORMAL);
      
      n = IntegerValuesParseTestInternal(&DCtx);
      
      //printf("Len %d, result: %d\n", num, n);
      
      if(n != QCBOR_ERR_HIT_END) {
         nResult = -1;
         goto Done;
      }
   }
Done:
   return nResult;
}



int ShortBufferParseTest2()
{
   uint8_t *pEncoded;
   int      nReturn;
   size_t   nEncodedLen;
   
   int64_t i1, i2;
   size_t i3, i4;
   const uint8_t *s3, *s4;
   
   nReturn = 0;
   
   if(CreateSimpleArray(23, 6000, &pEncoded, &nEncodedLen) < 0) {
      return(-1);
   }
   
   //printencoded(pEncoded,  nEncodedLen);
   
   for(nEncodedLen--; nEncodedLen; nEncodedLen--) {
      int nResult = ParseOrderedArray(pEncoded, (uint32_t)nEncodedLen, &i1, &i2, &s3, &i3, &s4, &i4);
      if(nResult == 0) {
         nReturn = -1;
      }
   }
   
   return(nReturn);
}


static int ParseMapTest1()
{
   QCBORDecodeContext DCtx;
   QCBORItem Item;
   int nCBORError;
   
   
   QCBORDecode_Init(&DCtx, (UsefulBufC){pValidMapEncoded, sizeof(pValidMapEncoded)}, QCBOR_DECODE_MODE_NORMAL);
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_MAP ||
      Item.val.uCount != 3)
      return -1;
   
   
 
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 13 ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 42 ||
      memcmp(Item.label.string.ptr, "first integer", 13))
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 23 ||
      memcmp(Item.label.string.ptr, "an array of two strings", 23) ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.val.uCount != 2)
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.val.string.len != 7 ||
      memcmp(Item.val.string.ptr, "string1", 7))
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.val.string.len != 7 ||
      memcmp(Item.val.string.ptr, "string2", 7))
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 12 ||
      memcmp(Item.label.string.ptr, "map in a map", 12) ||
      Item.uDataType != QCBOR_TYPE_MAP ||
      Item.val.uCount != 4)
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 7 ||
      memcmp(Item.label.string.ptr, "bytes 1", 7)||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      Item.val.string.len != 4 ||
      memcmp(Item.val.string.ptr, "xxxx", 4))
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 7 ||
      memcmp(Item.label.string.ptr, "bytes 2", 7) ||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      Item.val.string.len != 4 ||
      memcmp(Item.val.string.ptr, "yyyy", 4))
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 11 ||
      memcmp(Item.label.string.ptr, "another int", 11) ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 98)
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 6 ||
      memcmp(Item.label.string.ptr, "text 2", 6)||
      Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.val.string.len != 30 ||
      memcmp(Item.val.string.ptr, "lies, damn lies and statistics", 30))
      return -1;
   
   return 0;
}



/*
 This test parses pValidMapEncoded and checks for extra bytes along the way
 */
static int ExtraBytesTest(int nLevel)
{
   QCBORDecodeContext DCtx;
   QCBORItem Item;
   int nCBORError;
   
   QCBORDecode_Init(&DCtx, (UsefulBufC){pValidMapEncoded, sizeof(pValidMapEncoded)}, QCBOR_DECODE_MODE_NORMAL);
   
   if(nLevel < 1) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_EXTRA_BYTES) {
         return -1;
      } else {
         return 0;
      }
   }
   
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_MAP ||
      Item.val.uCount != 3)
      return -1;

   if(nLevel < 2) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
         return -1;
      } else {
         return 0;
      }
   }
   
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 13 ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.uCount != 42 ||
      memcmp(Item.label.string.ptr, "first integer", 13))
      return -1;
   
   if(nLevel < 3) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
         return -1;
      } else {
         return 0;
      }
   }
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 23 ||
      memcmp(Item.label.string.ptr, "an array of two strings", 23) ||
      Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.val.uCount != 2)
      return -1;
   
   
   if(nLevel < 4) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
         return -1;
      } else {
         return 0;
      }
   }
   
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.val.string.len != 7 ||
      memcmp(Item.val.string.ptr, "string1", 7))
      return -1;
   
   if(nLevel < 5) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
         return -1;
      } else {
         return 0;
      }
   }
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.val.string.len != 7 ||
      memcmp(Item.val.string.ptr, "string2", 7))
      return -1;
 
   if(nLevel < 6) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
         return -1;
      } else {
         return 0;
      }
   }
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 12 ||
      memcmp(Item.label.string.ptr, "map in a map", 12) ||
      Item.uDataType != QCBOR_TYPE_MAP ||
      Item.val.uCount != 4)
      return -1;
   
   if(nLevel < 7) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
         return -1;
      } else {
         return 0;
      }
   }
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 7 ||
      memcmp(Item.label.string.ptr, "bytes 1", 7)||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      Item.val.string.len != 4 ||
      memcmp(Item.val.string.ptr, "xxxx", 4))
      return -1;
   
   if(nLevel < 8) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
         return -1;
      } else {
         return 0;
      }
   }
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 7 ||
      memcmp(Item.label.string.ptr, "bytes 2", 7) ||
      Item.uDataType != QCBOR_TYPE_BYTE_STRING ||
      Item.val.string.len != 4 ||
      memcmp(Item.val.string.ptr, "yyyy", 4))
      return -1;
   
   if(nLevel < 9) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
         return -1;
      } else {
         return 0;
      }
   }
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 11 ||
      memcmp(Item.label.string.ptr, "another int", 11) ||
      Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.val.int64 != 98)
      return -1;
   
   if(nLevel < 10) {
      if(QCBORDecode_Finish(&DCtx) != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
         return -1;
      } else {
         return 0;
      }
   }
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      Item.label.string.len != 6 ||
      memcmp(Item.label.string.ptr, "text 2", 6)||
      Item.uDataType != QCBOR_TYPE_TEXT_STRING ||
      Item.val.string.len != 30 ||
      memcmp(Item.val.string.ptr, "lies, damn lies and statistics", 30))
      return -1;
   
   if(QCBORDecode_Finish(&DCtx) == QCBOR_ERR_EXTRA_BYTES) {
      return -1;
   }
   
   return 0;
}




int ParseMapTest()
{
   int n = ParseMapTest1();  // TODO: review this test carefully
   
   if(!n) {
      for(int i = 0; i < 10; i++) {
         n = ExtraBytesTest(i);
         if(n) {
            break;
         }
      }
   }
   
   return(n);
}


static uint8_t s_pSimpleValues[] = {0x8a, 0xf4, 0xf5, 0xf6, 0xf7, 0xff, 0xe0, 0xf3, 0xf8, 0x00, 0xf8, 0x13, 0xf8, 0x1f, 0xf8, 0x20, 0xf8, 0xff};

int ParseSimpleTest()
{
   QCBORDecodeContext DCtx;
   QCBORItem Item;
   int nCBORError;
   
   
   QCBORDecode_Init(&DCtx, UsefulBuf_FromByteArrayLiteral(s_pSimpleValues), QCBOR_DECODE_MODE_NORMAL);
   
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.val.uCount != 10)
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_FALSE)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_TRUE)
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_NULL)
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_UNDEF)
      return -1;

   // A break
   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_BAD_BREAK)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_UKNOWN_SIMPLE || Item.val.uSimple != 0)
      return -1;

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_UKNOWN_SIMPLE || Item.val.uSimple != 19)
      return -1;

   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_INVALID_CBOR)
      return -1;
   
   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_INVALID_CBOR)
      return -1;

   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_INVALID_CBOR)
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_UKNOWN_SIMPLE || Item.val.uSimple != 32)
      return -1;
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return nCBORError;
   if(Item.uDataType != QCBOR_TYPE_UKNOWN_SIMPLE || Item.val.uSimple != 255)
      return -1;
   
   return 0;
   
}


struct FailInput {
   UsefulBufC Input;
   int nError;
};


struct FailInput  Failures[] = {
   { {(uint8_t[]){0x18}, 1}, QCBOR_ERR_HIT_END },     // 1 byte integer missing the byte
   { {(uint8_t[]){0x1c}, 1}, QCBOR_ERR_UNSUPPORTED }, // Reserved additional info = 28
   { {(uint8_t[]){0x1d}, 1}, QCBOR_ERR_UNSUPPORTED }, // Reserved additional info = 29
   { {(uint8_t[]){0x1e}, 1}, QCBOR_ERR_UNSUPPORTED }, // Reserved additional info = 30
   { {(uint8_t[]){0x1f}, 1}, QCBOR_ERR_UNSUPPORTED }, // Indefinite length integer
   { {(uint8_t[]){0x3c}, 1}, QCBOR_ERR_UNSUPPORTED }, // 1 byte integer missing the byte
   { {(uint8_t[]){0x3d}, 1}, QCBOR_ERR_UNSUPPORTED }, // 1 byte integer missing the byte
   { {(uint8_t[]){0x3e}, 1}, QCBOR_ERR_UNSUPPORTED }, // 1 byte integer missing the byte
   { {(uint8_t[]){0x3f}, 1}, QCBOR_ERR_UNSUPPORTED }, // Indefinite length negative integer
   { {(uint8_t[]){0x41}, 1}, QCBOR_ERR_HIT_END },     // Short byte string
   { {(uint8_t[]){0x5c}, 1}, QCBOR_ERR_UNSUPPORTED }, // Reserved additional info = 28
   { {(uint8_t[]){0x5f}, 1}, QCBOR_ERR_UNSUPPORTED }, // Indefinite length byte string
   { {(uint8_t[]){0x61}, 1}, QCBOR_ERR_HIT_END },     // Short UTF-8 string
   { {(uint8_t[]){0x7c}, 1}, QCBOR_ERR_UNSUPPORTED }, // Reserved additional info = 28
   { {(uint8_t[]){0x7f}, 1}, QCBOR_ERR_UNSUPPORTED }, // Indefinite length UTF-8 string
   { {(uint8_t[]){0xff}, 1}, QCBOR_ERR_UNSUPPORTED } , // break
   { {(uint8_t[]){0xf8, 0x00}, 2}, QCBOR_ERR_INVALID_CBOR }, // An invalid encoding of a simple type
   { {(uint8_t[]){0xf8, 0x1f}, 2}, QCBOR_ERR_INVALID_CBOR },  // An invalid encoding of a simple type
   { {(uint8_t[]){0xc0, 0x00}, 2}, QCBOR_ERR_BAD_OPT_TAG },  // Text-based date, with an integer
   { {(uint8_t[]){0xc1, 0x41, 0x33}, 3}, QCBOR_ERR_BAD_OPT_TAG },   // Epoch date, with an byte string
   { {(uint8_t[]){0xc1, 0xc0, 0x00}, 3}, QCBOR_ERR_BAD_OPT_TAG },   // tagged as both epoch and string dates
   { {(uint8_t[]){0xc2, 0x00}, 2}, QCBOR_ERR_BAD_OPT_TAG }  // big num tagged an int, not a byte string

};


void Dump(UsefulBufC Input, int x)
{
   char label[10];
   
   sprintf(label, "%d", x);
   
   printencoded(label, Input.ptr, Input.len);
}


int FailureTests()
{
   int nResult = 0;
   
   struct FailInput *pFEnd = &Failures[0] + sizeof(Failures)/sizeof(struct FailInput);
   
   for(struct FailInput *pF = &Failures[0]; pF < pFEnd ;pF++) {
      QCBORDecodeContext DCtx;
      QCBORItem Item;
      int nCBORError;
      
      QCBORDecode_Init(&DCtx, pF->Input, QCBOR_DECODE_MODE_NORMAL);
      
      while(1) {
         nCBORError = QCBORDecode_GetNext(&DCtx, &Item);
         if(QCBOR_ERR_HIT_END == nCBORError) {
            break;
         }
         if(nCBORError != pF->nError) {
            nResult = 1;
            // Dump(pF->Input, nCBORError);
            break;
         }
      }
   }
   
   {
      QCBORDecodeContext DCtx;
      QCBORItem Item;
      int nCBORError;
      
      QCBORDecode_Init(&DCtx, UsefulBuf_FromByteArrayLiteral(s_pSimpleValues), QCBOR_DECODE_MODE_NORMAL);

      if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
         return nCBORError;
      if(Item.uDataType != QCBOR_TYPE_ARRAY ||
         Item.val.uCount != 10)
         return -1;
      
      DCtx.InBuf.magic = 0; // Corrupt the UsefulInputBuf
      
      nCBORError = QCBORDecode_GetNext(&DCtx, &Item);
      if(nCBORError != QCBOR_ERR_HIT_END)
         return -1;
   }
   
   
   return nResult;
}




static void Recurser(uint8_t *pBuf, int nLen, int nLenMax)
{
   
   if(nLen >= nLenMax) {
      return;
   }

   //printf("__%d__%d__\n", nLen, nLenMax);
   
   for(int i = 0; i < 256; i++) {
      pBuf[nLen] = i;
      
      QCBORDecodeContext DCtx;
      QCBORItem Item;
      int nCBORError;
      
      UsefulBufC Input = {pBuf, nLen+1};
      
      QCBORDecode_Init(&DCtx, Input, QCBOR_DECODE_MODE_NORMAL);
      
      while(1) {
         nCBORError =  QCBORDecode_GetNext(&DCtx, &Item);
         if(QCBOR_ERR_HIT_END == nCBORError) {
            break;
         }
         if(nCBORError != QCBOR_SUCCESS) {
            if(nCBORError != QCBOR_ERR_UNSUPPORTED && nCBORError != QCBOR_ERR_HIT_END && nCBORError != QCBOR_ERR_INVALID_CBOR) {
               //Dump(Input, nCBORError);
            }
            break;
         }
      }
      //Dump(Input, -1);

   
      Recurser(pBuf, nLen+1, nLenMax);
   }
}


/*
 Runs all possible input strings of a given length. This is set to 3 to make the test 
 run in reasonable time.
 Main point of this test is to not crash.
 */

int ComprehensiveInputTest()
{
   uint8_t pBuf[3]; // 3 keeps it running in reasonable time. 4 takes tens of minutes.
   
   Recurser(pBuf, 0, sizeof(pBuf));
   
   return 0;
}

static uint8_t s_DateTestInput[] = {
   0xc0, // tag for string date
   0x6a, '1','9','8','5','-','0','4','-','1','2', // Date string
   
   0xc1, // tag for epoch date
   0x1a, 0x53, 0x72, 0x4E, 0x00, // Epoch date 1400000000; Tue, 13 May 2014 16:53:20 GMT

   0xc1, 0xcf, 0xd8, 0xee, // Epoch date with extra tags
   0x1a, 0x53, 0x72, 0x4E, 0x01,

   0xc1, // tag for epoch date
   0x1b, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, // Too large integer
   
   0xc1, // tag for epoch date
   0xfa, 0x3f, 0x8c, 0xcc, 0xcd, // double with value 1.1
   
   0xc1, // tag for epoch date
   0xfa, 0x7f, 0x7f, 0xff, 0xff // 3.4028234663852886e+38 too large

};


// have to check float expected only to within an epsilon
int CHECK_EXPECTED_DOUBLE(double val, double expected) {
   
   double diff = val - expected;
   
   diff = fabs(diff);
   
   return diff > 0.0000001;
}


int DateParseTest()
{
   QCBORDecodeContext DCtx;
   QCBORItem Item;
   int nCBORError;
   
   QCBORDecode_Init(&DCtx, UsefulBuf_FromByteArrayLiteral(s_DateTestInput), QCBOR_DECODE_MODE_NORMAL);
   
   // String date
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_DATE_STRING ||
      UsefulBuf_Compare(Item.val.dateString, UsefulBuf_FromSZ("1985-04-12"))){
      return -1;
   }

   // Epoch date
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_DATE_EPOCH ||
      Item.val.epochDate.nSeconds != 1400000000 ||
      Item.val.epochDate.fSecondsFraction != 0 ) {
      return -1;
   }
   
   // Epoch date with extra tags
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_DATE_EPOCH ||
      Item.val.epochDate.nSeconds != 1400000001 ||
      Item.val.epochDate.fSecondsFraction != 0 ||
      Item.uTagBits != (0x02 | (0x01 << 0x0f)) ||
      Item.uTag != 0xee) {
      return -1;
   }
   
   // Epoch date that is too large for our representation
   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_DATE_OVERFLOW) {
      return -1;
   }
   
   // Epoch date in float format with fractional seconds
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_DATE_EPOCH ||
      Item.val.epochDate.nSeconds != 1 ||
      CHECK_EXPECTED_DOUBLE(Item.val.epochDate.fSecondsFraction, 0.1 )) {
      return -1;
   }
   
   // Epoch date float that is too large for our representation
   if(QCBORDecode_GetNext(&DCtx, &Item) != QCBOR_ERR_DATE_OVERFLOW) {
      return -1;
   }
   
   // TODO: could use a few more tests with float, double, and half precsion and negative (but coverage is still pretty good)

   return 0;
}

static uint8_t s_OptTestInput[] = {
   0xd9, 0xd9, 0xf7, // CBOR magic number
   0x81,
   0xd8, 62, // 62 is decimal intentionally
   0x00};

int OptTagParseTest()
{
   QCBORDecodeContext DCtx;
   QCBORItem Item;
   int nCBORError;
   
   
   QCBORDecode_Init(&DCtx, UsefulBuf_FromByteArrayLiteral(s_OptTestInput), QCBOR_DECODE_MODE_NORMAL);
   
   //
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_ARRAY ||
      Item.uTagBits != QCBOR_TAGFLAG_CBOR_MAGIC) {
      return -1;
   }
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_INT64 ||
      Item.uTagBits != (0x01LL << 62) ||
      Item.val.int64 != 0)
      return -1;
   
   return 0;
}



   
static uint8_t s_BigNumInput[] = {
 0x83,
   0xC2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0xC3, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0xA4,
     0x63, 0x42, 0x4E, 0x2B,
       0xC2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x18, 0x40,
       0xC2, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x63, 0x42, 0x4E, 0x2D,
       0xC3, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x38, 0x3F,
       0xC3, 0x49, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


static uint8_t sBigNum[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


int BignumParseTest()
{
   QCBORDecodeContext DCtx;
   QCBORItem Item;
   int nCBORError;
   
   QCBORDecode_Init(&DCtx, UsefulBuf_FromByteArrayLiteral(s_BigNumInput), QCBOR_DECODE_MODE_NORMAL);
   
   
   //
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -1;
   }
   
   // 
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_POSBIGNUM ||
      UsefulBuf_Compare(Item.val.bigNum, UsefulBuf_FromByteArrayLiteral(sBigNum))){
      return -1;
   }

   //
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_NEGBIGNUM ||
      UsefulBuf_Compare(Item.val.bigNum, UsefulBuf_FromByteArrayLiteral(sBigNum))){
      return -1;
   }
   
   //
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_MAP) {
      return -1;
   }
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_POSBIGNUM ||
      Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBuf_Compare(Item.val.bigNum, UsefulBuf_FromByteArrayLiteral(sBigNum))){
      return -1;
   }

   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_POSBIGNUM ||
      Item.uLabelType != QCBOR_TYPE_INT64 ||
      Item.label.int64 != 64 ||
      UsefulBuf_Compare(Item.val.bigNum, UsefulBuf_FromByteArrayLiteral(sBigNum))){
      return -1;
   }
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_NEGBIGNUM ||
      Item.uLabelType != QCBOR_TYPE_TEXT_STRING ||
      UsefulBuf_Compare(Item.val.bigNum, UsefulBuf_FromByteArrayLiteral(sBigNum))){
      return -1;
   }
   
   if((nCBORError = QCBORDecode_GetNext(&DCtx, &Item)))
      return -1;
   if(Item.uDataType != QCBOR_TYPE_NEGBIGNUM ||
      Item.uLabelType != QCBOR_TYPE_INT64 ||
      Item.label.int64 != -64 ||
      UsefulBuf_Compare(Item.val.bigNum, UsefulBuf_FromByteArrayLiteral(sBigNum))){
      return -1;
   }
   
   return 0;
}



static int CheckItemWithIntLabel(QCBORDecodeContext *pCtx, uint8_t uDataType, uint8_t uNestingLevel, int64_t nLabel, QCBORItem *pItem)
{
   QCBORItem Item;
   int nCBORError;
   
   if((nCBORError = QCBORDecode_GetNext(pCtx, &Item))) return -1;
   if(Item.uDataType != uDataType) return -1;
   if(uNestingLevel > 0) {
      if(Item.uLabelType != QCBOR_TYPE_INT64 &&  Item.uLabelType != QCBOR_TYPE_UINT64) return -1;
      if(Item.uLabelType == QCBOR_TYPE_INT64) {
         if(Item.label.int64 != nLabel) return -1;
      } else  {
         if(Item.label.uint64 != (uint64_t)nLabel) return -1;
      }
   }
   if(Item.uNestingLevel != uNestingLevel) return -1;
   
   if(pItem) {
      *pItem = Item;
   }
   return 0;
}


// Same code checks definite and indefinite length versions of the map
static int CheckCSRMaps(QCBORDecodeContext *pDC)
{
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_MAP, 0, 0, NULL)) return -1;
   
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_MAP, 1, -23, NULL)) return -1;
   
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_MAP, 2, -20, NULL)) return -1;
   
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_TEXT_STRING, 3, -18, NULL)) return -1;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_TEXT_STRING, 3, -17, NULL)) return -1;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_TEXT_STRING, 3, -15, NULL)) return -1;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_TEXT_STRING, 3, -16, NULL)) return -1;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_TEXT_STRING, 3, -14, NULL)) return -1;
   
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_MAP, 2, -19, NULL)) return -1;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_MAP, 3, -11, NULL)) return -1;
   
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_INT64, 4, -9, NULL)) return -1;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_BYTE_STRING, 3, -10, NULL)) return -1;
   
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_MAP, 1, -22, NULL)) return -1;
   if(CheckItemWithIntLabel(pDC, QCBOR_TYPE_INT64, 2, -5, NULL)) return -1;
   
   if(QCBORDecode_Finish(pDC)) return -2;
   
   return 0;
}


/*
// cbor.me decoded output
{
    -23: {
        -20: {
            -18: "Organization",
            -17: "SSG",
            -15: "Confusion",
            -16: "San Diego",
            -14: "US"
        },
        -19: {
            -11: {
                -9: -7
            },
            -10: '\u0001\u0002\u0003\u0004\u0005\u0006\a\b\t\n'
        }
    },
    -22: {
        -5: -3
    }
}
 */


static uint8_t s_CSRInput[] = {
   0xa2, 0x36, 0xa2, 0x33, 0xa5, 0x31, 0x6c, 0x4f,
   0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74,
   0x69, 0x6f, 0x6e, 0x30, 0x63, 0x53, 0x53, 0x47,
   0x2e, 0x69, 0x43, 0x6f, 0x6e, 0x66, 0x75, 0x73,
   0x69, 0x6f, 0x6e, 0x2f, 0x69, 0x53, 0x61, 0x6e,
   0x20, 0x44, 0x69, 0x65, 0x67, 0x6f, 0x2d, 0x62,
   0x55, 0x53, 0x32, 0xa2, 0x2a, 0xa1, 0x28, 0x26,
   0x29, 0x4a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
   0x07, 0x08, 0x09, 0x0a, 0x35, 0xa1, 0x24, 0x22};

int NestedMapTest()
{
   QCBORDecodeContext DCtx;
   
   QCBORDecode_Init(&DCtx, UsefulBuf_FromByteArrayLiteral(s_CSRInput), QCBOR_DECODE_MODE_NORMAL);
   
   return CheckCSRMaps(&DCtx);
}

// Same map as above, but using indefinite lengths
static uint8_t s_CSRInputIndefLen[] = {
   0xbf, 0x36, 0xbf, 0x33, 0xbf, 0x31, 0x6c, 0x4f,
   0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61, 0x74,
   0x69, 0x6f, 0x6e, 0x30, 0x63, 0x53, 0x53, 0x47,
   0x2e, 0x69, 0x43, 0x6f, 0x6e, 0x66, 0x75, 0x73,
   0x69, 0x6f, 0x6e, 0x2f, 0x69, 0x53, 0x61, 0x6e,
   0x20, 0x44, 0x69, 0x65, 0x67, 0x6f, 0x2d, 0x62,
   0x55, 0x53,  0xff, 0x32, 0xbf, 0x2a, 0xbf, 0x28,  0x26, 0xff,
   0x29, 0x4a, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
   0x07, 0x08, 0x09, 0x0a, 0xff, 0xff, 0x35, 0xbf, 0x24, 0x22, 0xff, 0xff};

int NestedMapTestIndefLen()
{
   QCBORDecodeContext DCtx;
   
   QCBORDecode_Init(&DCtx, UsefulBuf_FromByteArrayLiteral(s_CSRInputIndefLen), QCBOR_DECODE_MODE_NORMAL);
   
   return CheckCSRMaps(&DCtx);
}



static UsefulBufC make_nested_indefinite_arrays(int n, UsefulBuf Storage)
{
   UsefulOutBuf UOB;
   UsefulOutBuf_Init(&UOB, Storage);
   
   int i;
   for(i = 0; i < n; i++) {
      UsefulOutBuf_AppendByte(&UOB, 0x9f);
   }

   for(i = 0; i < n; i++) {
      UsefulOutBuf_AppendByte(&UOB, 0xff);
   }
   return UsefulOutBuf_OutUBuf(&UOB);
}


static int parse_indeflen_nested(UsefulBufC Nested, int nNestLevel)
{
   QCBORDecodeContext DC;
   QCBORDecode_Init(&DC, Nested, 0);
   
   int j;
   for(j = 0; j < nNestLevel; j++) {
      QCBORItem Item;
      int nReturn = QCBORDecode_GetNext(&DC, &Item);
      if(j >= QCBOR_MAX_ARRAY_NESTING) {
         // Should be in error
         if(nReturn != QCBOR_ERR_ARRAY_NESTING_TOO_DEEP) {
            return -4;
         } else {
            return 0; // Decoding doesn't recover after an error
         }
      } else {
         // Should be no error
         if(nReturn) {
            return -9; // Should not have got an error
         }
      }
      if(Item.uDataType != QCBOR_TYPE_ARRAY) {
         return -7;
      }
   }
   int nReturn = QCBORDecode_Finish(&DC);
   if(nReturn) {
      return -3;
   }
   return 0;
}


int indeflen_nest_test()
{
   UsefulBuf_MakeStackUB(Storage, 50);
   int i;
   for(i=1; i < QCBOR_MAX_ARRAY_NESTING+4; i++) { 
      UsefulBufC Nested = make_nested_indefinite_arrays(i, Storage);
      int nReturn = parse_indeflen_nested(Nested, i);
      if(nReturn) {
         return nReturn;
      }
   }
   return 0;
}



static const uint8_t pIndefiniteArray[] = {0x9f, 0x01, 0x82, 0x02, 0x03, 0xff}; // [1, [2, 3]]
static const uint8_t pIndefiniteArrayBad1[] = {0x9f}; // No closing break
static const uint8_t pIndefiniteArrayBad2[] = {0x9f, 0x9f, 0x02, 0xff}; // Not enough closing breaks
static const uint8_t pIndefiniteArrayBad3[] = {0x9f, 0x02, 0xff, 0xff}; // Too many closing breaks
static const uint8_t pIndefiniteArrayBad4[] = {0x81, 0x9f}; // Unclosed indeflen inside def len
static const uint8_t pIndefiniteArrayBad5[] = {0x9f, 0xc7, 0xff}; // confused tag

int indefinite_length_decode_test()
{
   int nResult;
   // --- first test -----
    UsefulBufC IndefLen = UsefulBuf_FromByteArrayLiteral(pIndefiniteArray);
   
    // Decode it and see if it is OK
    UsefulBuf_MakeStackUB(MemPool, 150);
    QCBORDecodeContext DC;
    QCBORItem Item;
    QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);
    
    QCBORDecode_SetMemPool(&DC, MemPool, false);
        
    QCBORDecode_GetNext(&DC, &Item);

    if(Item.uDataType != QCBOR_TYPE_ARRAY ||
       Item.uNestingLevel != 0 ||
       Item.uNextNestLevel != 1) {
       return -111;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_INT64 ||
       Item.uNestingLevel != 1 ||
       Item.uNextNestLevel != 1) {
        return -2;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_ARRAY ||
       Item.uNestingLevel != 1 ||
       Item.uNextNestLevel != 2) {
        return -3;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_INT64 |
       Item.uNestingLevel != 2 ||
       Item.uNextNestLevel != 2) {
        return -4;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_INT64 |
       Item.uNestingLevel != 2 ||
       Item.uNextNestLevel != 0) {
        return -5;
    }
    
    if(QCBORDecode_Finish(&DC)) {
        return -6;
    }
   
   // --- next test -----
   IndefLen = UsefulBuf_FromByteArrayLiteral(pIndefiniteArrayBad1);
   
   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);
   
   QCBORDecode_SetMemPool(&DC, MemPool, false);
   
   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -7;
   }
   
   nResult = QCBORDecode_Finish(&DC);
   if(nResult != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
      return -8;
   }

   
   // --- next test -----
   IndefLen = UsefulBuf_FromByteArrayLiteral(pIndefiniteArrayBad2);
   
   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);
   
   QCBORDecode_SetMemPool(&DC, MemPool, false);
   
   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -9;
   }

   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -10;
   }
   
   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_INT64) {
      return -11;
   }
   
   nResult = QCBORDecode_Finish(&DC);
   if(nResult != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
      return -12;
   }
   
   
   // --- next test -----
   IndefLen = UsefulBuf_FromByteArrayLiteral(pIndefiniteArrayBad3);
   
   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);
   
   QCBORDecode_SetMemPool(&DC, MemPool, false);
   
   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -13;
   }
   
   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult != QCBOR_ERR_BAD_BREAK) {
      return -14;
   }

   
   // --- next test -----
   IndefLen = UsefulBuf_FromByteArrayLiteral(pIndefiniteArrayBad4);
   
   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);
   
   QCBORDecode_SetMemPool(&DC, MemPool, false);
   
   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -15;
   }
   
   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -16;
   }
   
   nResult = QCBORDecode_Finish(&DC);
   if(nResult != QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN) {
      return -17;
   }
   
   // --- next test -----
   IndefLen = UsefulBuf_FromByteArrayLiteral(pIndefiniteArrayBad5);
   
   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);
   
   QCBORDecode_SetMemPool(&DC, MemPool, false);
   
   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult || Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -18;
   }
   
   nResult = QCBORDecode_GetNext(&DC, &Item);
   if(nResult != QCBOR_ERR_BAD_BREAK) {
      return -19;
   }
   
    return 0;
}


static const uint8_t pIndefiniteLenString[] = {
   0x81, // Array of length one
   0x7f, // text string marked with indefinite length
   0x65, 0x73, 0x74, 0x72, 0x65, 0x61, // first segment
   0x64, 0x6d, 0x69, 0x6e, 0x67, // second segment
   0xff // ending break
};

int indefinite_length_decode_string_test()
{
    UsefulBufC IndefLen = UsefulBuf_FromByteArrayLiteral(pIndefiniteLenString);
    
    
    // Decode it and see if it is OK
    QCBORDecodeContext DC;
    QCBORItem Item;
    UsefulBuf_MakeStackUB(MemPool, 200);
    
    QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);
    
   if(QCBORDecode_SetMemPool(&DC,  MemPool, false)) {
      return -4;
   }
    
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_ARRAY) {
        return -1;
    }
    
    QCBORDecode_GetNext(&DC, &Item);
    if(Item.uDataType != QCBOR_TYPE_TEXT_STRING) {
        return -1;
    }

   // ------ Don't set a string allocator and see an error
   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);
   
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -1;
   }
   
   if(QCBORDecode_GetNext(&DC, &Item) != QCBOR_ERR_NO_STRING_ALLOCATOR) {
      return -1;
   }
   
   // ----- Mempool is way too small -----
   UsefulBuf_MakeStackUB(MemPoolTooSmall, 20); // 20 is too small no matter what

   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);
   if(!QCBORDecode_SetMemPool(&DC,  MemPoolTooSmall, false)) {
      return -8;
   }


   
   // ----- Mempool is way too small -----
   UsefulBuf_MakeStackUB(MemPoolSmall, 60); // TODO: this tests needs some big strings to be CPU indepedent
   
   QCBORDecode_Init(&DC, IndefLen, QCBOR_DECODE_MODE_NORMAL);
   if(QCBORDecode_SetMemPool(&DC,  MemPoolSmall, false)) {
      return -8;
   }
   
   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return -1;
   }
   if(QCBORDecode_GetNext(&DC, &Item) != QCBOR_ERR_STRING_ALLOC) {
      return -1;
   }
      
    return 0;
}



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




   

