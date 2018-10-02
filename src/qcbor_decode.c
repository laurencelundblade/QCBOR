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

/*===================================================================================
 FILE:  qcbor_decode.c
 
 DESCRIPTION:  This file contains the implementation of QCBOR.
 
 EDIT HISTORY FOR FILE:
 
 This section contains comments describing changes made to the module.
 Notice that changes are listed in reverse chronological order.
 
 when               who             what, where, why
 --------           ----            ---------------------------------------------------
 02/04/17           llundbla        Work on CPUs that don's require pointer alignment
                                    by making use of changes in UsefulBuf
 03/01/17           llundbla        More data types; decoding improvements and fixes
 11/13/16           llundbla        Integrate most TZ changes back into github version.
 09/30/16           gkanike         Porting to TZ.
 03/15/16           llundbla        Initial Version.
 
 =====================================================================================*/

#include "qcbor.h"



/*
 Collection of functions to track the map and array nesting for decoding
 */

inline static int IsMapOrArray(uint8_t uDataType)
{
   return uDataType == QCBOR_TYPE_MAP || uDataType == QCBOR_TYPE_ARRAY;
}

inline static int DecodeNesting_IsNested(const QCBORDecodeNesting *pNesting)
{
   return pNesting->pCurrent != &(pNesting->pMapsAndArrays[0]);
}

inline static int IsIndefiniteLength(const QCBORDecodeNesting *pNesting)
{
   if(!DecodeNesting_IsNested(pNesting)) {
      return 0;
   }
   
   return pNesting->pCurrent->uCount == UINT16_MAX;
}

inline static int DecodeNesting_TypeIsMap(const QCBORDecodeNesting *pNesting)
{
   if(!DecodeNesting_IsNested(pNesting)) {
      return 0;
   }
   
   return CBOR_MAJOR_TYPE_MAP == pNesting->pCurrent->uMajorType;
}

inline static void DecodeNesting_Decrement(QCBORDecodeNesting *pNesting)
{
   if(!DecodeNesting_IsNested(pNesting)) {
      return;  // at top level where there is no tracking
   }
   
   if(IsIndefiniteLength(pNesting)) {
      // Decrement only gets called once. Only at the end of the array/map
      // when the break is encountered. There is no tracking of the number
      // of items in the array/map.
      pNesting->pCurrent--;

   } else {
      // Decrement
      pNesting->pCurrent->uCount--;
   
      // Pop up nesting levels if the counts at the levels is zero
      while(0 == pNesting->pCurrent->uCount && DecodeNesting_IsNested(pNesting)) {
         pNesting->pCurrent--;
      }
   }
}

inline static int DecodeNesting_Descend(QCBORDecodeNesting *pNesting, uint8_t uMajorType, int uCount)
{
   int nReturn = QCBOR_SUCCESS;
   
   if(uCount > QCBOR_MAX_ITEMS_IN_ARRAY) {
      nReturn = QCBOR_ERR_ARRAY_TOO_LONG;
      goto Done;
   }
   
   if(pNesting->pCurrent >= &(pNesting->pMapsAndArrays[QCBOR_MAX_ARRAY_NESTING])) {
      nReturn = QCBOR_ERR_ARRAY_NESTING_TOO_DEEP;
      goto Done;
   }
   
   pNesting->pCurrent++;
   
   pNesting->pCurrent->uMajorType = uMajorType;
   pNesting->pCurrent->uCount     = uCount;
   
Done:
   return nReturn;;
}

inline static uint8_t DecodeNesting_GetLevel(QCBORDecodeNesting *pNesting)
{
   return pNesting->pCurrent - &(pNesting->pMapsAndArrays[0]);
}

inline static void DecodeNesting_Init(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent = &(pNesting->pMapsAndArrays[0]);
}




/*
 Public function, see header file
 */
void QCBORDecode_Init(QCBORDecodeContext *me, UsefulBufC EncodedCBOR, int8_t nDecodeMode)
{
   memset(me, 0, sizeof(QCBORDecodeContext));
   UsefulInputBuf_Init(&(me->InBuf), EncodedCBOR);
   // Don't bother with error check on decode mode. If a bad value is passed it will just act as
   // if the default normal mode of 0 was set.
   me->uDecodeMode = nDecodeMode;
   DecodeNesting_Init(&(me->nesting));
}


/*
 Public function, see header file
 */
void QCBOR_Decode_SetUpAllocator(QCBORDecodeContext *pCtx, const QCBORStringAllocator *pAllocator)
{
    pCtx->pStringAllocator = (void *)pAllocator;
}

const QCBORStringAllocator *QCBORDecode_GetAllocator(QCBORDecodeContext *pCtx)
{
   return pCtx->pStringAllocator;
}



/*
 This decodes the fundamental part of a CBOR data item, the type and number
 
 This is the Counterpart to InsertEncodedTypeAndNumber().
 
 This does the network->host byte order conversion. The conversion here
 also results in the conversion for floats in addition to that for
 lengths, tags and integer values.
 
 */
inline static int DecodeTypeAndNumber(UsefulInputBuf *pUInBuf, int *pnMajorType, uint64_t *puNumber, uint8_t *puAdditionalInfo)
{
   int nReturn;
   
   // Get the initial byte that every CBOR data item has
   const uint8_t InitialByte = UsefulInputBuf_GetByte(pUInBuf);
   
   // Break down the initial byte
   const uint8_t uTmpMajorType   = InitialByte >> 5;
   const uint8_t uAdditionalInfo = InitialByte & 0x1f;
   
   // Get the integer that follows the major type. Do not know if this is a length, value, float or tag at this point
   // Also convert from network byte order. Call ntohxx on simple variables in case they are macros that
   // reference their argument multiple times.
   uint64_t uTmpValue;
   switch(uAdditionalInfo) {
         
      case LEN_IS_ONE_BYTE:
         uTmpValue = UsefulInputBuf_GetByte(pUInBuf);
         break;
         
      case LEN_IS_TWO_BYTES:
         uTmpValue = UsefulInputBuf_GetUint16(pUInBuf);
         break;
         
      case LEN_IS_FOUR_BYTES:
         uTmpValue = UsefulInputBuf_GetUint32(pUInBuf);
         break;
         
      case LEN_IS_EIGHT_BYTES:
         uTmpValue = UsefulInputBuf_GetUint64(pUInBuf);
         break;
         
      case ADDINFO_RESERVED1: // reserved by CBOR spec
      case ADDINFO_RESERVED2: // reserved by CBOR spec
      case ADDINFO_RESERVED3: // reserved by CBOR spec
         nReturn = QCBOR_ERR_UNSUPPORTED;
         goto Done;

       case LEN_IS_INDEFINITE:
           // Fall through OK to see what happens: TODO: check this.
      default:
         uTmpValue = uAdditionalInfo;
         break;
   }
   
   // If any of the UsefulInputBuf_Get calls fail we will get here with uTmpValue as 0.
   // There is no harm in this. This following check takes care of catching all of
   // these errors. 
   
   if(UsefulInputBuf_GetError(pUInBuf)) {
      nReturn = QCBOR_ERR_HIT_END;
      goto Done;
   }
   
   // All successful if we got here.
   nReturn           = QCBOR_SUCCESS;
   *pnMajorType      = uTmpMajorType;
   *puNumber         = uTmpValue;
   *puAdditionalInfo = uAdditionalInfo;
   
Done:
   return nReturn;
}


/*
 CBOR doesn't explicitly specify two's compliment for integers but all CPUs
 use it these days and the test vectors in the RFC are so. All integers in the CBOR
 structure are positive and the major type indicates positive or negative.
 CBOR can express positive integers up to 2^x - 1 where x is the number of bits
 and negative integers down to 2^x.  Note that negative numbers can be one
 more away from zero than positive.
 Stdint, as far as I can tell, uses two's compliment to represent
 negative integers.
 
 See http://www.unix.org/whitepapers/64bit.html for reasons int isn't
 used here in any way including in the interface
 */
inline static int DecodeInteger(int nMajorType, uint64_t uNumber, QCBORItem *pDecodedItem)
{
   int nReturn = QCBOR_SUCCESS;
   
   if(nMajorType == CBOR_MAJOR_TYPE_POSITIVE_INT) {
      if (uNumber <= INT64_MAX) {
         pDecodedItem->val.int64 = (int64_t)uNumber;
         pDecodedItem->uDataType = QCBOR_TYPE_INT64;
         
      } else {
         pDecodedItem->val.uint64 = uNumber;
         pDecodedItem->uDataType  = QCBOR_TYPE_UINT64;
         
      }
   } else {
      if(uNumber <= INT64_MAX) {
         pDecodedItem->val.int64 = -uNumber-1;
         pDecodedItem->uDataType = QCBOR_TYPE_INT64;
         
      } else {
         // C can't represent a negative integer in this range
         // so it is an error.  todo -- test this condition
         nReturn = QCBOR_ERR_INT_OVERFLOW;
      }
   }
   
   return nReturn;
}

// Make sure #define value line up as DecodeSimple counts on this.
#if QCBOR_TYPE_FALSE != CBOR_SIMPLEV_FALSE
#error QCBOR_TYPE_FALSE macro value wrong
#endif

#if QCBOR_TYPE_TRUE != CBOR_SIMPLEV_TRUE
#error QCBOR_TYPE_TRUE macro value wrong
#endif

#if QCBOR_TYPE_NULL != CBOR_SIMPLEV_NULL
#error QCBOR_TYPE_NULL macro value wrong
#endif

#if QCBOR_TYPE_UNDEF != CBOR_SIMPLEV_UNDEF
#error QCBOR_TYPE_UNDEF macro value wrong
#endif

#if QCBOR_TYPE_BREAK != CBOR_SIMPLE_BREAK
#error QCBOR_TYPE_BREAK macro value wrong
#endif

#if QCBOR_TYPE_DOUBLE != DOUBLE_PREC_FLOAT
#error QCBOR_TYPE_DOUBLE macro value wrong
#endif

#if QCBOR_TYPE_FLOAT != SINGLE_PREC_FLOAT
#error QCBOR_TYPE_FLOAT macro value wrong
#endif

/*
 Decode true, false, floats, break...
 */

inline static int DecodeSimple(uint8_t uAdditionalInfo, uint64_t uNumber, QCBORItem *pDecodedItem)
{
   int nReturn = QCBOR_SUCCESS;
   
   // uAdditionalInfo is 5 bits from the initial byte
   // compile time checks above make sure uAdditionalInfo values line up with uDataType values
   pDecodedItem->uDataType = uAdditionalInfo;
   
   switch(uAdditionalInfo) {
      case ADDINFO_RESERVED1:  // 28
      case ADDINFO_RESERVED2:  // 29
      case ADDINFO_RESERVED3:  // 30
         nReturn = QCBOR_ERR_UNSUPPORTED;
         break;
         
      case CBOR_SIMPLEV_FALSE: // 20
      case CBOR_SIMPLEV_TRUE:  // 21
      case CBOR_SIMPLEV_NULL:  // 22
      case CBOR_SIMPLEV_UNDEF: // 23
      case CBOR_SIMPLE_BREAK:  // 31
         break; // nothing to do
         
      case CBOR_SIMPLEV_ONEBYTE: // 24
         if(uNumber <= CBOR_SIMPLE_BREAK) {
            // This takes out f8 00 ... f8 1f which should be encoded as e0 … f7
            nReturn = QCBOR_ERR_INVALID_CBOR;
            goto Done;
         }
         // fall through intentionally
         
      default: // 0-19
         pDecodedItem->uDataType   = QCBOR_TYPE_UKNOWN_SIMPLE;
         // DecodeTypeAndNumber will make uNumber equal to uAdditionalInfo when uAdditionalInfo is < 24
         // This cast is safe because the 2, 4 and 8 byte lengths of uNumber are in the double/float cases above
         pDecodedItem->val.uSimple = (uint8_t)uNumber;
         break;
   }
   
Done:
   return nReturn;
}



/*
 Decode text and byte strings
 */
inline static int DecodeBytes(int nMajorType, uint64_t uNumber, UsefulInputBuf *pUInBuf, QCBORItem *pDecodedItem)
{
   const void *pBytes = UsefulInputBuf_GetBytes(pUInBuf, uNumber);
   
   int nReturn = QCBOR_ERR_HIT_END; 
   
   if(pBytes != NULL) {
      pDecodedItem->val.string = (UsefulBufC){pBytes, uNumber};
      pDecodedItem->uDataType  = (nMajorType == CBOR_MAJOR_TYPE_BYTE_STRING) ? QCBOR_TYPE_BYTE_STRING : QCBOR_TYPE_TEXT_STRING;
      nReturn = QCBOR_SUCCESS;
   }
   
   return nReturn;
}


/*
 Mostly just assign the right data type for the date string.
 */
inline static int DecodeDateString(QCBORItem Item, QCBORItem *pDecodedItem)
{
   if(Item.uDataType != QCBOR_TYPE_TEXT_STRING) {
      return QCBOR_ERR_BAD_OPT_TAG;
   }
   pDecodedItem->val.dateString = Item.val.string;
   pDecodedItem->uDataType = QCBOR_TYPE_DATE_STRING;
   pDecodedItem->uTagBits = Item.uTagBits;
   pDecodedItem->uTag = Item.uTag;
   return QCBOR_SUCCESS;
}


/*
 Mostly just assign the right data type for the bignum.
 */
inline static int DecodeBigNum(QCBORItem Item, QCBORItem *pDecodedItem, uint64_t uTagFlags)
{
   if(Item.uDataType != QCBOR_TYPE_BYTE_STRING) {
      return QCBOR_ERR_BAD_OPT_TAG;
   }
   pDecodedItem->val.bigNum     = Item.val.string;
   pDecodedItem->uDataType      = uTagFlags & QCBOR_TAGFLAG_POS_BIGNUM ? QCBOR_TYPE_POSBIGNUM : QCBOR_TYPE_NEGBIGNUM;
   pDecodedItem->uTagBits       = Item.uTagBits;
   pDecodedItem->uTag           = Item.uTag;
   return QCBOR_SUCCESS;
}


/*
 The epoch formatted date. Turns lots of different forms of encoding date into uniform one
 */
static int DecodeDateEpoch(QCBORItem Item, QCBORItem *pDecodedItem)
{
   int nReturn = QCBOR_SUCCESS;
   
   pDecodedItem->uTagBits                       = Item.uTagBits;
   pDecodedItem->uTag                           = Item.uTag;
   pDecodedItem->uDataType                      = QCBOR_TYPE_DATE_EPOCH;
   pDecodedItem->val.epochDate.fSecondsFraction = 0;
   
   switch (Item.uDataType) {
         
      case QCBOR_TYPE_INT64:
         pDecodedItem->val.epochDate.nSeconds = Item.val.int64;
         break;
         
      case QCBOR_TYPE_UINT64:
         if(Item.val.uint64 > INT64_MAX) {
            nReturn = QCBOR_ERR_DATE_OVERFLOW; 
            goto Done;
         }
         pDecodedItem->val.epochDate.nSeconds = Item.val.uint64;
         break;
         
      default:
         nReturn = QCBOR_ERR_BAD_OPT_TAG;
   }
   
Done:
   return nReturn;
}


/*
 Decode the optional tagging that preceeds the real data value. There could be lots of them.
 */
static int GetAnItem(UsefulInputBuf *pUInBuf, QCBORItem *pDecodedItem, int bCalledFromDecodeOptional);

/*
 Returns an error if there was something wrong with the optional item or it couldn't
 be handled.
 */
static int DecodeOptional(UsefulInputBuf *pUInBuf, uint64_t uInputTag, QCBORItem *pDecodedItem)
{
   int      nReturn = QCBOR_SUCCESS;
   
   uint64_t uTagFlags = 0; // accumulate the tags in the form of flags
   uint64_t uTagToProcess = uInputTag; // First process tag passed in
   
   QCBORItem Item;
   
   do {
      if(uTagToProcess < 63) { // 63 is the number of bits in a uint64 - 1
         uTagFlags |= 0x01LL << uTagToProcess;
      } else if(uTagToProcess == CBOR_TAG_CBOR_MAGIC) {
         uTagFlags |= QCBOR_TAGFLAG_CBOR_MAGIC;
      }
      /* This code ignores the all but the first tag of value
         greater than 63. Ignoring tags that are not understoof
         is allowed by the standard. Multiple tags are 
         presumably rare. */
      
      nReturn = GetAnItem(pUInBuf, &Item, 1);
      if(nReturn) {
         // Bail out of the whole item fetch on any sort of error here
         goto Done;
      }
      
      if(Item.uDataType != QCBOR_TYPE_OPTTAG) {
         break;
      }
      
      uTagToProcess = Item.uTag;
   } while (1);

   
   /*
     CBOR allows multiple tags on a data item. It also defines
     a number of standard tag values, most of which are 
     less than 64.  This code can deal with multiple tag
     values that are less than 64 and the last tag of multiple
     if the value is more than 64. Or said another way
     if there is one tag with a value >64 this code works. 
    
     The assumption is that multiple tag values > 64 are rare.
    
     At this point in this code. uTagFlags has all the flags
     < 64 and uTagToProcess has the last tag.
    
     Does this deal with multiple tags on an item we process?
    */
   
   Item.uTagBits = uTagFlags;
   Item.uTag = uTagToProcess;
   
   switch(uTagFlags & (QCBOR_TAGFLAG_DATE_STRING | QCBOR_TAGFLAG_DATE_EPOCH | QCBOR_TAGFLAG_POS_BIGNUM |QCBOR_TAGFLAG_NEG_BIGNUM)) {
      case 0:
         // No tags we know about. Pass them up
         *pDecodedItem = Item;
         break;
         
      case QCBOR_TAGFLAG_DATE_STRING:
         nReturn = DecodeDateString(Item, pDecodedItem);
         break;
         
      case QCBOR_TAGFLAG_DATE_EPOCH:
         nReturn = DecodeDateEpoch(Item, pDecodedItem);
         break;
         
      case QCBOR_TAGFLAG_POS_BIGNUM:
      case QCBOR_TAGFLAG_NEG_BIGNUM:
         nReturn = DecodeBigNum(Item, pDecodedItem, uTagFlags);
         break;
         
      default:
         // Encountering some mixed up CBOR like something that
         // is tagged as both a string and integer date.
         nReturn = QCBOR_ERR_BAD_OPT_TAG ;
      }

Done:
   return nReturn;
}



// Make sure the constants align as this is assumed by the GetAnItem() implementation
#if QCBOR_TYPE_ARRAY != CBOR_MAJOR_TYPE_ARRAY
#error QCBOR_TYPE_ARRAY value not lined up with major type
#endif
#if QCBOR_TYPE_MAP != CBOR_MAJOR_TYPE_MAP
#error QCBOR_TYPE_MAP value not lined up with major type
#endif

/*
 This gets a single data item and decodes it including preceding optional tagging. This does not
 deal with arrays and maps and nesting except to decode the data item introducing them. Arrays and
 maps are handled at the next level up in GetNext().
 
 Errors detected here include: an array that is too long to decode, hit end of buffer unexpectedly,
    a few forms of invalid encoded CBOR
 */

static int GetAnItem(UsefulInputBuf *pUInBuf, QCBORItem *pDecodedItem, int bCalledFromDecodeOptional)
{
   int nReturn;
   
   // Get the major type and the number. Number could be length of more bytes or the value depending on the major type
   // nAdditionalInfo is an encoding of the length of the uNumber and is needed to decode floats and doubles
   int      uMajorType;
   uint64_t uNumber;
   uint8_t  uAdditionalInfo;
   
   nReturn = DecodeTypeAndNumber(pUInBuf, &uMajorType, &uNumber, &uAdditionalInfo);
   
   // Error out here if we got into trouble on the type and number.
   // The code after this will not work if the type and number is not good.
   if(nReturn)
      goto Done;
   
   pDecodedItem->uTagBits = 0;
   pDecodedItem->uTag     = 0;
   
   // At this point the major type and the value are valid. We've got the type and the number that
   // starts every CBOR data item.
   switch (uMajorType) {
      case CBOR_MAJOR_TYPE_POSITIVE_INT: // Major type 0
      case CBOR_MAJOR_TYPE_NEGATIVE_INT: // Major type 1
         if(uAdditionalInfo == 31) {// TODO: right constant
            pDecodedItem->uDataType  = (uMajorType == CBOR_MAJOR_TYPE_BYTE_STRING) ? QCBOR_TYPE_BYTE_STRING : QCBOR_TYPE_TEXT_STRING;
            pDecodedItem->val.string = (UsefulBufC){NULL, 0xffff};
         } else {
            nReturn = DecodeInteger(uMajorType, uNumber, pDecodedItem);
         }
         break;
         
      case CBOR_MAJOR_TYPE_BYTE_STRING: // Major type 2
      case CBOR_MAJOR_TYPE_TEXT_STRING: // Major type 3
         nReturn = DecodeBytes(uMajorType, uNumber, pUInBuf, pDecodedItem);
         break;
         
      case CBOR_MAJOR_TYPE_ARRAY: // Major type 4
      case CBOR_MAJOR_TYPE_MAP:   // Major type 5
         // Record the number of items in the array or map
         if(uNumber > QCBOR_MAX_ITEMS_IN_ARRAY) {
            nReturn = QCBOR_ERR_ARRAY_TOO_LONG;
            goto Done;
         }
         if(uAdditionalInfo == LEN_IS_INDEFINITE) {
            pDecodedItem->val.uCount = UINT16_MAX;
         } else {
            pDecodedItem->val.uCount = (uint16_t)uNumber; // type conversion OK because of check above
         }
         pDecodedItem->uDataType  = uMajorType; // C preproc #if above makes sure constants align
         break;
         
      case CBOR_MAJOR_TYPE_OPTIONAL: // Major type 6, optional prepended tags
         pDecodedItem->uTag      = uNumber;
         pDecodedItem->uDataType = QCBOR_TYPE_OPTTAG;
         if(!bCalledFromDecodeOptional) {
            // There can be a more than one optional tag in front of an actual data item
            // they are all handled by looping in DecodeOptional which calls back here
            // this test avoids infinite recursion.
            nReturn = DecodeOptional(pUInBuf, uNumber, pDecodedItem);
         }
         break;
         
      case CBOR_MAJOR_TYPE_SIMPLE: // Major type 7, float, double, true, false, null...
         nReturn = DecodeSimple(uAdditionalInfo, uNumber, pDecodedItem);
         break;
         
      default: // Should never happen because DecodeTypeAndNumber() should never return > 7
         nReturn = QCBOR_ERR_UNSUPPORTED;
         break;
   }
   
Done:
   return nReturn;
}


/*
 Layer to process indefinite lengths
 
 */

UsefulBuf XX(QCBORStringAllocator *pAlloc, UsefulBufC yy, size_t add)
{
   // TODO: pointer arithmatic
   uint8_t *x = (*pAlloc->AllocatorFunction) (pAlloc->pAllocaterContext, yy.ptr, yy.len + add );
   return (UsefulBuf) {x, yy.len + add};
}
 
int GetFullItem(QCBORStringAllocator *pAlloc, UsefulInputBuf *pUInBuf, QCBORItem *pDecodedItem, int bCalledFromDecodeOptional)
{
   int nReturn = GetAnItem(pUInBuf, pDecodedItem, bCalledFromDecodeOptional);
   
   if(pDecodedItem->uDataType != CBOR_MAJOR_TYPE_BYTE_STRING && pDecodedItem->uDataType != CBOR_MAJOR_TYPE_TEXT_STRING) {
      return nReturn;
   }
   
   if(pDecodedItem->val.uCount != 0xffff) {
      return nReturn;
   }
   
   if(pAlloc == NULL) {
      return -99; // TODO: error
   }
   
   QCBORItem Item = *pDecodedItem;
   UsefulOutBuf UOB;
   UsefulOutBuf_Init(&UOB, XX(pAlloc, (UsefulBufC){NULL,0}, 0)); // Dummy storage allocation to start
   
   // loop getting segments of indefinite string

   do {
      UsefulOutBuf_Realloc(&UOB, XX(pAlloc, UsefulOutBuf_OutUBuf(&UOB), Item.val.string.len));
      UsefulOutBuf_AppendUsefulBuf(&UOB, Item.val.string);
      
      int xx = GetAnItem(pUInBuf, &Item, bCalledFromDecodeOptional);
      // Lots of error conditions here
      
   } while(Item.uDataType != QCBOR_TYPE_BREAK);
   
   pDecodedItem->val.string = UsefulOutBuf_OutUBuf(&UOB);
   
   return 0;
   
}


/*
 Public function, see header qcbor.h file
 */
int QCBORDecode_GetNext(QCBORDecodeContext *me, QCBORItem *pDecodedItem)
{
   int nReturn;
   
   if(!UsefulInputBuf_BytesUnconsumed(&(me->InBuf))) {
      nReturn = QCBOR_ERR_HIT_END;
      goto Done;
   }
   
   nReturn = GetAnItem(&(me->InBuf), pDecodedItem, 0);
   if(nReturn)
      goto Done;
   
   // If in a map and the right decoding mode, get the label
   if(DecodeNesting_TypeIsMap(&(me->nesting)) && me->uDecodeMode != QCBOR_DECODE_MODE_MAP_AS_ARRAY) {
      // In a map and caller wants maps decoded, not treated as arrays
      
      // Get the next item which will be the real data; Item will be the label
      QCBORItem LabelItem = *pDecodedItem;
      nReturn = GetAnItem(&(me->InBuf), pDecodedItem, 0);
      if(nReturn)
         goto Done;
      
      if(LabelItem.uDataType == QCBOR_TYPE_TEXT_STRING) {
         // strings are always good labels
         pDecodedItem->label.string = LabelItem.val.string;
         pDecodedItem->uLabelType = QCBOR_TYPE_TEXT_STRING;
      } else if (QCBOR_DECODE_MODE_MAP_STRINGS_ONLY == me->uDecodeMode) {
         // It's not a string and we only want strings, probably for easy translation to JSON
         nReturn = QCBOR_ERR_MAP_LABEL_TYPE;
         goto Done;
     } else if(LabelItem.uDataType == QCBOR_TYPE_INT64) {
         pDecodedItem->label.int64 = LabelItem.val.int64;
         pDecodedItem->uLabelType = QCBOR_TYPE_INT64;
      } else if(LabelItem.uDataType == QCBOR_TYPE_UINT64) {
         pDecodedItem->label.uint64 = LabelItem.val.uint64;
         pDecodedItem->uLabelType = QCBOR_TYPE_UINT64;
      } else if(LabelItem.uDataType == QCBOR_TYPE_BYTE_STRING) {
         pDecodedItem->label.string = LabelItem.val.string;
         pDecodedItem->uLabelType = QCBOR_TYPE_BYTE_STRING;
      } else {
         // label is not an int or a string. It is an arrray
         // or a float or such and this implementation doesn't handle that.
         nReturn = QCBOR_ERR_MAP_LABEL_TYPE ;
         goto Done;
      }
   }
   
   // Record the nesting level for this data item
   pDecodedItem->uNestingLevel = DecodeNesting_GetLevel(&(me->nesting));
   
   // If the new item is a non-empty array or map, the nesting level descends
   if(IsMapOrArray(pDecodedItem->uDataType) && pDecodedItem->val.uCount) {
      nReturn = DecodeNesting_Descend(&(me->nesting), pDecodedItem->uDataType, pDecodedItem->val.uCount);
   } else {
      if(!IsIndefiniteLength(&(me->nesting))) {
         // Is a definite length array or map
         // Track number of items in maps and arrays and ascend nesting if all are consumed
         // Note that an empty array or map is like a integer or string in effect here
         DecodeNesting_Decrement(&(me->nesting));
      } else {
         // Is an indefinite length array or map
         if(pDecodedItem->uDataType == QCBOR_TYPE_BREAK) {
            // Only decrement when the end is encountered.
            DecodeNesting_Decrement(&(me->nesting));
            // TODO: get another item here....
         }
      }
   }
   
Done:
   return nReturn;
}


/*
 Public function, see header qcbor.h file
 */
int QCBORDecode_Finish(QCBORDecodeContext *me)
{
   return UsefulInputBuf_BytesUnconsumed(&(me->InBuf)) ? QCBOR_ERR_EXTRA_BYTES : QCBOR_SUCCESS;
}



/*
 
 Use the 64-bit map. 48 8-bit tags built in, 1 16 bit tag, 15 64-bit tags can be assigned as of interest
 
 There is a tag map.
 
 TODO: how does tinyCBOR do it?
 
 
 
 
 
 */


/* 
 
Decoder errors handled in this file
 
 - Hit end of input before it was expected while decoding type and number QCBOR_ERR_HIT_END
 
 - indefinite length, currently not supported QCBOR_ERR_UNSUPPORTED
 
 - negative integer that is too large for C QCBOR_ERR_INT_OVERFLOW
 
 - Hit end of input while decoding a text or byte string QCBOR_ERR_HIT_END
 
 - Encountered conflicting tags -- e.g., an item is tagged both a date string and an epoch date QCBOR_ERR_UNSUPPORTED
 
 - Encountered a break, not supported because indefinite lengths are not supported QCBOR_ERR_UNSUPPORTED
 
 - Encontered an array or mapp that has too many items QCBOR_ERR_ARRAY_TOO_LONG
 
 - Encountered array/map nesting that is too deep QCBOR_ERR_ARRAY_NESTING_TOO_DEEP
 
 - An epoch date > INT64_MAX or < INT64_MIN was encountered QCBOR_ERR_DATE_OVERFLOW
 
 - The type of a map label is not a string or int QCBOR_ERR_MAP_LABEL_TYPE
 
 - Hit end with arrays or maps still open -- QCBOR_ERR_EXTRA_BYTES
 
 */

