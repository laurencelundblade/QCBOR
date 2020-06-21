/*==============================================================================
 Copyright (c) 2016-2018, The Linux Foundation.
 Copyright (c) 2018-2020, Laurence Lundblade.
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


#include "qcbor/qcbor_decode.h"
#include "ieee754.h"


/*
 This casts away the const-ness of a pointer, usually so it can be
 freed or realloced.
 */
#define UNCONST_POINTER(ptr)    ((void *)(ptr))



/*===========================================================================
 DecodeNesting -- Functions for tracking array/map nesting when decoding

 See qcbor/qcbor_decode.h for definition of the object
  used here: QCBORDecodeNesting
  ===========================================================================*/



/*
The main mode of decoding is a pre-order travesal of the tree of leaves (numbers, strings...)
formed by intermediate nodes (arrays and maps).  The cursor for the traversal
 is the byte offset in the encoded input and a leaf counter for definite
 length maps and arrays. Indefinite length maps and arrays are handled
 by look ahead for the break.

 The view presented to the caller has tags, labels and the chunks of
 indefinite length strings aggregated into one decorated data item.

The caller understands the nesting level in pre-order traversal by
 the fact that a data item that is a map or array is presented to
 the caller when it is first encountered in the pre-order traversal and that all data items are presented with its nesting level
 and the nesting level of the next item.

 The caller traverse maps and arrays in a special mode that often more convenient
 that tracking by nesting level. When an array or map is expected or encountered
 the EnterMap or EnteryArray can be called.

 When entering a map or array like this, the cursor points to the first
 item in the map or array. When exiting, it points to the item after
 the map or array, regardless of whether the items in the map or array were
 all traversed.

 When in a map or array, the cursor functions as normal, but traversal
 cannot go past the end of the map or array that was entered. If this
 is attempted the QCBOR_ERR_NO_MORE_ITEMS error is returned. To
 go past the end of the map or array ExitMap() or ExitArray() must
 be called. It can be called any time regardless of the position
 of the cursor.

 When a map is entered, a special function allows fetching data items
 by label. This call will traversal the whole map looking for the
 labeled item. The whole map is traversed so as to detect duplicates.
 This type of fetching items does not affect the normal traversal
 cursor.

 








When a data item is presented to the caller, the nesting level of the data
 item is presented along with the nesting level of the item that would be
 next consumed.









 */

inline static bool
// TODO: test  Map as array better?
IsMapOrArray(uint8_t uDataType)
{
   return uDataType == QCBOR_TYPE_MAP ||
          uDataType == QCBOR_TYPE_ARRAY ||
          uDataType == QCBOR_TYPE_MAP_AS_ARRAY;
}


inline static uint8_t
DecodeNesting_GetLevel(const QCBORDecodeNesting *pNesting)
{
   const ptrdiff_t nLevel = pNesting->pCurrent - &(pNesting->pMapsAndArrays[0]);
   // Check in DecodeNesting_Descend and never having
   // QCBOR_MAX_ARRAY_NESTING > 255 gaurantees cast is safe
   return (uint8_t)nLevel;
}


inline static bool DecodeNesting_InBoundedMode(const QCBORDecodeNesting *pNesting)
{
   return pNesting->pCurrent->bBoundedMode;
   //return pNesting->pCurrent->uType & QCBOR_NEST_TYPE_IS_BOUNDED;
}

/*inline static bool IsArray(const QCBORDecodeNesting *pNesting)
{
   const unsigned uIndex = DecodeNesting_GetLevel(pNesting);

   return (0x01ULL << ((uIndex * 3) + 1)) & pNesting->uTypeBitMap;
}

inline static bool IsBstr(const QCBORDecodeNesting *pNesting)
{
   const unsigned uIndex = DecodeNesting_GetLevel(pNesting);

   return (0x01ULL << ((uIndex * 3) + 2)) & pNesting->uTypeBitMap;
}*/


inline static bool
DecodeNesting_IsAtTop(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent == &(pNesting->pMapsAndArrays[0])) {
      return true;
   } else {
      return false;
   }
}

// Determine if at the end of a map or array while in map mode
inline static bool
DecodeNesting_AtEnd(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrentBounded && DecodeNesting_InBoundedMode(pNesting)) {
      if(pNesting->pCurrentBounded->uCount == 0) {
         // In map mode and consumed all items, so it is the end
         return true;
      } else {
         // In map mode, all items not consumed, so it is NOT the end
         return false;
      }
   } else {
      // Not in map mode. The end is determined in other ways.
      return false;
   }
}


inline static int
DecodeNesting_IsIndefiniteLength(const QCBORDecodeNesting *pNesting)
{
   return pNesting->pCurrent->uCount == UINT16_MAX;
   //return pNesting->pCurrent->uType & QCBOR_NEST_TYPE_IS_INDEFINITE;
}


inline static uint8_t
DecodeNesting_GetBoundedModeLevel(QCBORDecodeNesting *pNesting)
{
   // Check in DecodeNesting_Descend and never having
   // QCBOR_MAX_ARRAY_NESTING > 255 gaurantees cast is safe
   return (uint8_t)(pNesting->pCurrentBounded - &(pNesting->pMapsAndArrays[0]));
}

inline static int
DecodeNesting_TypeIsMap(const QCBORDecodeNesting *pNesting)
{
   if(DecodeNesting_IsAtTop(pNesting)) {
      return 0;
   }

   return CBOR_MAJOR_TYPE_MAP == pNesting->pCurrent->uMajorType;
}

inline static bool
DecodeNesting_BoundedIsType(const QCBORDecodeNesting *pNesting, uint8_t uType)
{
   if(pNesting->pCurrentBounded->uMajorType == uType) {
      return true;
   } else {
      return false;
   }
}


// return 1 if closed out an array or map
inline static void
DecodeNesting_DecrementX(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent->uCount--;
}

inline static bool
DecodeNesting_IsEndOfDefiniteLengthMapOrArray(QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->uCount == 0) {
      return true;
   } else {
      return false;
   }
}

inline static void
DecodeNesting_Ascend(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent--;
}




inline static void
DecodeNesting_EnterBoundedMode(QCBORDecodeNesting *pNesting, size_t uOffset)
{
   /* Have descended into this before this is called. The job here is just to mark it in bounded mode */
   pNesting->pCurrentBounded = pNesting->pCurrent;
   pNesting->pCurrent->bBoundedMode = true;
   //pNesting->pCurrentBounded->uType |= QCBOR_NEST_TYPE_IS_BOUNDED;
   // Cast to uint32_t is safe because QCBOR restricts encoded input to < UINT32_MAX
   pNesting->pCurrentBounded->uOffset  = (uint32_t)uOffset;
}




inline static QCBORError
DecodeNesting_Descend(QCBORDecodeNesting *pNesting, uint8_t uQCBORType, uint64_t uCount, uint32_t uEndOffset, uint32_t uEndOfBstr)
{
   QCBORError nReturn = QCBOR_SUCCESS;

   if(uCount == 0) {
      // Nothing to do for empty definite lenth arrays. They are just are
      // effectively the same as an item that is not a map or array
      goto Done;
      // Empty indefinite length maps and arrays are handled elsewhere
   }

   // Error out if arrays is too long to handle
   if(uCount != UINT16_MAX && uCount > QCBOR_MAX_ITEMS_IN_ARRAY) {
      nReturn = QCBOR_ERR_ARRAY_TOO_LONG;
      goto Done;
   }

   // Error out if nesting is too deep
   if(pNesting->pCurrent >= &(pNesting->pMapsAndArrays[QCBOR_MAX_ARRAY_NESTING])) {
      nReturn = QCBOR_ERR_ARRAY_NESTING_TOO_DEEP;
      goto Done;
   }

   // The actual descend
   pNesting->pCurrent++;

   // Fill in the new level fully
   pNesting->pCurrent->uMajorType = uQCBORType;
   pNesting->pCurrent->uCount     = (uint16_t)uCount;
   pNesting->pCurrent->uSaveCount = (uint16_t)uCount;
   pNesting->pCurrent->uPreviousEndOffset = uEndOffset;
   pNesting->pCurrent->uEndOfBstr = uEndOfBstr;
   pNesting->pCurrent->bBoundedMode   = false;

Done:
   return nReturn;;
}



inline static void
DecodeNesting_Init(QCBORDecodeNesting *pNesting, size_t uEndOffset)
{
   pNesting->pMapsAndArrays[0].uMajorType = QCBOR_TYPE_BYTE_STRING;
   // TODO: is cast in the right place?
   pNesting->pMapsAndArrays[0].uPreviousEndOffset = (uint32_t)uEndOffset;
   pNesting->pCurrent = &(pNesting->pMapsAndArrays[0]);
}


static void DecodeNesting_PrepareForMapSearch(QCBORDecodeNesting *pNesting, QCBORDecodeNesting *pSave)
{
   *pSave = *pNesting;
   pNesting->pCurrent = pNesting->pCurrentBounded;

   if(!DecodeNesting_IsIndefiniteLength(pNesting)) {
      pNesting->pCurrent->uCount = pNesting->pCurrent->uSaveCount;
   }
}

static inline void DecodeNesting_RestoreFromMapSearch(QCBORDecodeNesting *pNesting, QCBORDecodeNesting *pSave)
{
   *pNesting = *pSave;
}

QCBORError DecodeNesting_EnterBstr(QCBORDecodeNesting *pNesting, uint32_t uEndOffset)
{
   QCBORError uReturn ;

   // Error out if nesting is too deep
   if(pNesting->pCurrent >= &(pNesting->pMapsAndArrays[QCBOR_MAX_ARRAY_NESTING])) {
      uReturn = QCBOR_ERR_ARRAY_NESTING_TOO_DEEP;
      goto Done;
   }

   // The actual descend
   pNesting->pCurrent++;

   // Record a few details for this nesting level
   pNesting->pCurrent->uMajorType = 1; // TODO the right value for a bstr
   pNesting->pCurrent->uCount     = 0xffff;
   pNesting->pCurrent->uSaveCount = 0xffff;
   pNesting->pCurrent->uType      = 0;

   uReturn = QCBOR_SUCCESS;

Done:
   return uReturn;
}




/*===========================================================================
   QCBORStringAllocate -- STRING ALLOCATOR INVOCATION

   The following four functions are pretty wrappers for invocation of
   the string allocator supplied by the caller.

  ===========================================================================*/

static inline void
StringAllocator_Free(const QCORInternalAllocator *pMe, void *pMem)
{
   (pMe->pfAllocator)(pMe->pAllocateCxt, pMem, 0);
}

// StringAllocator_Reallocate called with pMem NULL is
// equal to StringAllocator_Allocate()
static inline UsefulBuf
StringAllocator_Reallocate(const QCORInternalAllocator *pMe,
                           void *pMem,
                           size_t uSize)
{
   return (pMe->pfAllocator)(pMe->pAllocateCxt, pMem, uSize);
}

static inline UsefulBuf
StringAllocator_Allocate(const QCORInternalAllocator *pMe, size_t uSize)
{
   return (pMe->pfAllocator)(pMe->pAllocateCxt, NULL, uSize);
}

static inline void
StringAllocator_Destruct(const QCORInternalAllocator *pMe)
{
   if(pMe->pfAllocator) {
      (pMe->pfAllocator)(pMe->pAllocateCxt, NULL, 0);
   }
}



/*===========================================================================
 QCBORDecode -- The main implementation of CBOR decoding

 See qcbor/qcbor_decode.h for definition of the object
 used here: QCBORDecodeContext
  ===========================================================================*/
/*
 Public function, see header file
 */
void QCBORDecode_Init(QCBORDecodeContext *me,
                      UsefulBufC EncodedCBOR,
                      QCBORDecodeMode nDecodeMode)
{
   memset(me, 0, sizeof(QCBORDecodeContext));
   UsefulInputBuf_Init(&(me->InBuf), EncodedCBOR);
   // Don't bother with error check on decode mode. If a bad value is
   // passed it will just act as if the default normal mode of 0 was set.
   me->uDecodeMode = (uint8_t)nDecodeMode;
   DecodeNesting_Init(&(me->nesting), EncodedCBOR.len);
   for(int i = 0; i < QCBOR_NUM_MAPPED_TAGS; i++) {
      me->auMappedTags[i] = CBOR_TAG_INVALID16;
   }
}


/*
 Public function, see header file
 */
void QCBORDecode_SetUpAllocator(QCBORDecodeContext *pMe,
                                QCBORStringAllocate pfAllocateFunction,
                                void *pAllocateContext,
                                bool bAllStrings)
{
   pMe->StringAllocator.pfAllocator   = pfAllocateFunction;
   pMe->StringAllocator.pAllocateCxt  = pAllocateContext;
   pMe->bStringAllocateAll            = bAllStrings;
}


/*
 Public function, see header file
 */
void QCBORDecode_SetCallerConfiguredTagList(QCBORDecodeContext *me,
                                            const QCBORTagListIn *pTagList)
{
   // This does nothing now. It is retained for backwards compatibility
}


/*
 This decodes the fundamental part of a CBOR data item, the type and
 number

 This is the Counterpart to InsertEncodedTypeAndNumber().

 This does the network->host byte order conversion. The conversion
 here also results in the conversion for floats in addition to that
 for lengths, tags and integer values.

 This returns:
   pnMajorType -- the major type for the item

   puArgument -- the "number" which is used a the value for integers,
               tags and floats and length for strings and arrays

   pnAdditionalInfo -- Pass this along to know what kind of float or
                       if length is indefinite

 The int type is preferred to uint8_t for some variables as this
 avoids integer promotions, can reduce code size and makes
 static analyzers happier.
 */
inline static QCBORError DecodeTypeAndNumber(UsefulInputBuf *pUInBuf,
                                              int *pnMajorType,
                                              uint64_t *puArgument,
                                              int *pnAdditionalInfo)
{
   QCBORError nReturn;

   // Get the initial byte that every CBOR data item has
   const int nInitialByte = (int)UsefulInputBuf_GetByte(pUInBuf);

   // Break down the initial byte
   const int nTmpMajorType   = nInitialByte >> 5;
   const int nAdditionalInfo = nInitialByte & 0x1f;

   // Where the number or argument accumulates
   uint64_t uArgument;

   if(nAdditionalInfo >= LEN_IS_ONE_BYTE && nAdditionalInfo <= LEN_IS_EIGHT_BYTES) {
      // Need to get 1,2,4 or 8 additional argument bytes. Map
      // LEN_IS_ONE_BYTE..LEN_IS_EIGHT_BYTES to actual length
      static const uint8_t aIterate[] = {1,2,4,8};

      // Loop getting all the bytes in the argument
      uArgument = 0;
      for(int i = aIterate[nAdditionalInfo - LEN_IS_ONE_BYTE]; i; i--) {
         // This shift and add gives the endian conversion
         uArgument = (uArgument << 8) + UsefulInputBuf_GetByte(pUInBuf);
      }
   } else if(nAdditionalInfo >= ADDINFO_RESERVED1 && nAdditionalInfo <= ADDINFO_RESERVED3) {
      // The reserved and thus-far unused additional info values
      nReturn = QCBOR_ERR_UNSUPPORTED;
      goto Done;
   } else {
      // Less than 24, additional info is argument or 31, an indefinite length
      // No more bytes to get
      uArgument = (uint64_t)nAdditionalInfo;
   }

   if(UsefulInputBuf_GetError(pUInBuf)) {
      nReturn = QCBOR_ERR_HIT_END;
      goto Done;
   }

   // All successful if we got here.
   nReturn           = QCBOR_SUCCESS;
   *pnMajorType      = nTmpMajorType;
   *puArgument       = uArgument;
   *pnAdditionalInfo = nAdditionalInfo;

Done:
   return nReturn;
}


/*
 CBOR doesn't explicitly specify two's compliment for integers but all
 CPUs use it these days and the test vectors in the RFC are so. All
 integers in the CBOR structure are positive and the major type
 indicates positive or negative.  CBOR can express positive integers
 up to 2^x - 1 where x is the number of bits and negative integers
 down to 2^x.  Note that negative numbers can be one more away from
 zero than positive.  Stdint, as far as I can tell, uses two's
 compliment to represent negative integers.

 See http://www.unix.org/whitepapers/64bit.html for reasons int isn't
 used carefully here, and in particular why it isn't used in the interface.
 Also see
 https://stackoverflow.com/questions/17489857/why-is-int-typically-32-bit-on-64-bit-compilers

 Int is used for values that need less than 16-bits and would be subject
 to integer promotion and complaining by static analyzers.
 */
inline static QCBORError
DecodeInteger(int nMajorType, uint64_t uNumber, QCBORItem *pDecodedItem)
{
   QCBORError nReturn = QCBOR_SUCCESS;

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
         // CBOR's representation of negative numbers lines up with the
         // two-compliment representation. A negative integer has one
         // more in range than a positive integer. INT64_MIN is
         // equal to (-INT64_MAX) - 1.
         pDecodedItem->val.int64 = (-(int64_t)uNumber) - 1;
         pDecodedItem->uDataType = QCBOR_TYPE_INT64;

      } else {
         // C can't represent a negative integer in this range
         // so it is an error.
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
inline static QCBORError
DecodeSimple(int nAdditionalInfo, uint64_t uNumber, QCBORItem *pDecodedItem)
{
   QCBORError nReturn = QCBOR_SUCCESS;

   // uAdditionalInfo is 5 bits from the initial byte compile time checks
   // above make sure uAdditionalInfo values line up with uDataType values.
   // DecodeTypeAndNumber never returns a major type > 1f so cast is safe
   pDecodedItem->uDataType = (uint8_t)nAdditionalInfo;

   switch(nAdditionalInfo) {
      // No check for ADDINFO_RESERVED1 - ADDINFO_RESERVED3 as they are
      // caught before this is called.

      case HALF_PREC_FLOAT:
         pDecodedItem->val.dfnum = IEEE754_HalfToDouble((uint16_t)uNumber);
         pDecodedItem->uDataType = QCBOR_TYPE_DOUBLE;
         break;
      case SINGLE_PREC_FLOAT:
         pDecodedItem->val.dfnum = (double)UsefulBufUtil_CopyUint32ToFloat((uint32_t)uNumber);
         pDecodedItem->uDataType = QCBOR_TYPE_DOUBLE;
         break;
      case DOUBLE_PREC_FLOAT:
         pDecodedItem->val.dfnum = UsefulBufUtil_CopyUint64ToDouble(uNumber);
         pDecodedItem->uDataType = QCBOR_TYPE_DOUBLE;
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
            nReturn = QCBOR_ERR_BAD_TYPE_7;
            goto Done;
         }
         /* FALLTHROUGH */
         // fall through intentionally

      default: // 0-19
         pDecodedItem->uDataType   = QCBOR_TYPE_UKNOWN_SIMPLE;
         /*
          DecodeTypeAndNumber will make uNumber equal to
          uAdditionalInfo when uAdditionalInfo is < 24 This cast is
          safe because the 2, 4 and 8 byte lengths of uNumber are in
          the double/float cases above
          */
         pDecodedItem->val.uSimple = (uint8_t)uNumber;
         break;
   }

Done:
   return nReturn;
}


/*
 Decode text and byte strings. Call the string allocator if asked to.
 */
inline static QCBORError DecodeBytes(const QCORInternalAllocator *pAllocator,
                                     int nMajorType,
                                     uint64_t uStrLen,
                                     UsefulInputBuf *pUInBuf,
                                     QCBORItem *pDecodedItem)
{
   QCBORError nReturn = QCBOR_SUCCESS;

   // CBOR lengths can be 64 bits, but size_t is not 64 bits on all CPUs.
   // This check makes the casts to size_t below safe.

   // 4 bytes less than the largest sizeof() so this can be tested by
   // putting a SIZE_MAX length in the CBOR test input (no one will
   // care the limit on strings is 4 bytes shorter).
   if(uStrLen > SIZE_MAX-4) {
      nReturn = QCBOR_ERR_STRING_TOO_LONG;
      goto Done;
   }

   const UsefulBufC Bytes = UsefulInputBuf_GetUsefulBuf(pUInBuf, (size_t)uStrLen);
   if(UsefulBuf_IsNULLC(Bytes)) {
      // Failed to get the bytes for this string item
      nReturn = QCBOR_ERR_HIT_END;
      goto Done;
   }

   if(pAllocator) {
      // We are asked to use string allocator to make a copy
      UsefulBuf NewMem = StringAllocator_Allocate(pAllocator, (size_t)uStrLen);
      if(UsefulBuf_IsNULL(NewMem)) {
         nReturn = QCBOR_ERR_STRING_ALLOCATE;
         goto Done;
      }
      pDecodedItem->val.string = UsefulBuf_Copy(NewMem, Bytes);
      pDecodedItem->uDataAlloc = 1;
   } else {
      // Normal case with no string allocator
      pDecodedItem->val.string = Bytes;
   }
   const bool bIsBstr = (nMajorType == CBOR_MAJOR_TYPE_BYTE_STRING);
   // Cast because ternary operator causes promotion to integer
   pDecodedItem->uDataType = (uint8_t)(bIsBstr ? QCBOR_TYPE_BYTE_STRING
                                               : QCBOR_TYPE_TEXT_STRING);

Done:
   return nReturn;
}







// Make sure the constants align as this is assumed by
// the GetAnItem() implementation
#if QCBOR_TYPE_ARRAY != CBOR_MAJOR_TYPE_ARRAY
#error QCBOR_TYPE_ARRAY value not lined up with major type
#endif
#if QCBOR_TYPE_MAP != CBOR_MAJOR_TYPE_MAP
#error QCBOR_TYPE_MAP value not lined up with major type
#endif

/*
 This gets a single data item and decodes it including preceding
 optional tagging. This does not deal with arrays and maps and nesting
 except to decode the data item introducing them. Arrays and maps are
 handled at the next level up in GetNext().

 Errors detected here include: an array that is too long to decode,
 hit end of buffer unexpectedly, a few forms of invalid encoded CBOR
 */
static QCBORError GetNext_Item(UsefulInputBuf *pUInBuf,
                               QCBORItem *pDecodedItem,
                               const QCORInternalAllocator *pAllocator)
{
   QCBORError nReturn;

   /*
    Get the major type and the number. Number could be length of more
    bytes or the value depending on the major type nAdditionalInfo is
    an encoding of the length of the uNumber and is needed to decode
    floats and doubles
   */
   int      nMajorType;
   uint64_t uNumber;
   int      nAdditionalInfo;

   memset(pDecodedItem, 0, sizeof(QCBORItem));

   nReturn = DecodeTypeAndNumber(pUInBuf, &nMajorType, &uNumber, &nAdditionalInfo);

   // Error out here if we got into trouble on the type and number.  The
   // code after this will not work if the type and number is not good.
   if(nReturn) {
      goto Done;
   }

   // At this point the major type and the value are valid. We've got
   // the type and the number that starts every CBOR data item.
   switch (nMajorType) {
      case CBOR_MAJOR_TYPE_POSITIVE_INT: // Major type 0
      case CBOR_MAJOR_TYPE_NEGATIVE_INT: // Major type 1
         if(nAdditionalInfo == LEN_IS_INDEFINITE) {
            nReturn = QCBOR_ERR_BAD_INT;
         } else {
            nReturn = DecodeInteger(nMajorType, uNumber, pDecodedItem);
         }
         break;

      case CBOR_MAJOR_TYPE_BYTE_STRING: // Major type 2
      case CBOR_MAJOR_TYPE_TEXT_STRING: // Major type 3
         if(nAdditionalInfo == LEN_IS_INDEFINITE) {
            const bool bIsBstr = (nMajorType == CBOR_MAJOR_TYPE_BYTE_STRING);
            pDecodedItem->uDataType = (uint8_t)(bIsBstr ? QCBOR_TYPE_BYTE_STRING
                                                        : QCBOR_TYPE_TEXT_STRING);
            pDecodedItem->val.string = (UsefulBufC){NULL, SIZE_MAX};
         } else {
            nReturn = DecodeBytes(pAllocator, nMajorType, uNumber, pUInBuf, pDecodedItem);
         }
         break;

      case CBOR_MAJOR_TYPE_ARRAY: // Major type 4
      case CBOR_MAJOR_TYPE_MAP:   // Major type 5
         // Record the number of items in the array or map
         if(uNumber > QCBOR_MAX_ITEMS_IN_ARRAY) {
            nReturn = QCBOR_ERR_ARRAY_TOO_LONG;
            goto Done;
         }
         if(nAdditionalInfo == LEN_IS_INDEFINITE) {
            pDecodedItem->val.uCount = UINT16_MAX; // Indicate indefinite length
         } else {
            // type conversion OK because of check above
            pDecodedItem->val.uCount = (uint16_t)uNumber;
         }
         // C preproc #if above makes sure constants for major types align
         // DecodeTypeAndNumber never returns a major type > 7 so cast is safe
         pDecodedItem->uDataType  = (uint8_t)nMajorType;
         break;

      case CBOR_MAJOR_TYPE_OPTIONAL: // Major type 6, optional prepended tags
         if(nAdditionalInfo == LEN_IS_INDEFINITE) {
            nReturn = QCBOR_ERR_BAD_INT;
         } else {
            pDecodedItem->val.uTagV = uNumber;
            pDecodedItem->uDataType = QCBOR_TYPE_OPTTAG;
         }
         break;

      case CBOR_MAJOR_TYPE_SIMPLE:
         // Major type 7, float, double, true, false, null...
         nReturn = DecodeSimple(nAdditionalInfo, uNumber, pDecodedItem);
         break;

      default:
         // Never happens because DecodeTypeAndNumber() should never return > 7
         nReturn = QCBOR_ERR_UNSUPPORTED;
         break;
   }

Done:
   return nReturn;
}



/*
 This layer deals with indefinite length strings. It pulls all the
 individual chunk items together into one QCBORItem using the string
 allocator.

 Code Reviewers: THIS FUNCTION DOES A LITTLE POINTER MATH
 */
static inline QCBORError
GetNext_FullItem(QCBORDecodeContext *me, QCBORItem *pDecodedItem)
{
   // Stack usage; int/ptr 2 UsefulBuf 2 QCBORItem  -- 96

   // Get pointer to string allocator. First use is to pass it to
   // GetNext_Item() when option is set to allocate for *every* string.
   // Second use here is to allocate space to coallese indefinite
   // length string items into one.
   const QCORInternalAllocator *pAllocator = me->StringAllocator.pfAllocator ?
                                                      &(me->StringAllocator) :
                                                      NULL;

   QCBORError nReturn;
   nReturn = GetNext_Item(&(me->InBuf),
                          pDecodedItem,
                          me->bStringAllocateAll ? pAllocator: NULL);
   if(nReturn) {
      goto Done;
   }

   // To reduce code size by removing support for indefinite length strings, the
   // code in this function from here down can be eliminated. Run tests, except
   // indefinite length string tests, to be sure all is OK if this is removed.

   // Only do indefinite length processing on strings
   const uint8_t uStringType = pDecodedItem->uDataType;
   if(uStringType!= QCBOR_TYPE_BYTE_STRING && uStringType != QCBOR_TYPE_TEXT_STRING) {
      goto Done; // no need to do any work here on non-string types
   }

   // Is this a string with an indefinite length?
   if(pDecodedItem->val.string.len != SIZE_MAX) {
      goto Done; // length is not indefinite, so no work to do here
   }

   // Can't do indefinite length strings without a string allocator
   if(pAllocator == NULL) {
      nReturn = QCBOR_ERR_NO_STRING_ALLOCATOR;
      goto Done;
   }

   // Loop getting chunk of indefinite string
   UsefulBufC FullString = NULLUsefulBufC;

   for(;;) {
      // Get item for next chunk
      QCBORItem StringChunkItem;
      // NULL string allocator passed here. Do not need to allocate
      // chunks even if bStringAllocateAll is set.
      nReturn = GetNext_Item(&(me->InBuf), &StringChunkItem, NULL);
      if(nReturn) {
         break;  // Error getting the next chunk
      }

      // See if it is a marker at end of indefinite length string
      if(StringChunkItem.uDataType == QCBOR_TYPE_BREAK) {
         // String is complete
         pDecodedItem->val.string = FullString;
         pDecodedItem->uDataAlloc = 1;
         break;
      }

      // Match data type of chunk to type at beginning.
      // Also catches error of other non-string types that don't belong.
      // Also catches indefinite length strings inside indefinite length strings
      if(StringChunkItem.uDataType != uStringType ||
         StringChunkItem.val.string.len == SIZE_MAX) {
         nReturn = QCBOR_ERR_INDEFINITE_STRING_CHUNK;
         break;
      }

      // Alloc new buffer or expand previously allocated buffer so it can fit
      // The first time throurgh FullString.ptr is NULL and this is
      // equivalent to StringAllocator_Allocate()
      UsefulBuf NewMem = StringAllocator_Reallocate(pAllocator,
                                                    UNCONST_POINTER(FullString.ptr),
                                                    FullString.len + StringChunkItem.val.string.len);

      if(UsefulBuf_IsNULL(NewMem)) {
         // Allocation of memory for the string failed
         nReturn = QCBOR_ERR_STRING_ALLOCATE;
         break;
      }

      // Copy new string chunk at the end of string so far.
      FullString = UsefulBuf_CopyOffset(NewMem, FullString.len, StringChunkItem.val.string);
   }

   if(nReturn != QCBOR_SUCCESS && !UsefulBuf_IsNULLC(FullString)) {
      // Getting the item failed, clean up the allocated memory
      StringAllocator_Free(pAllocator, UNCONST_POINTER(FullString.ptr));
   }

Done:
   return nReturn;
}


uint64_t ConvertTag(QCBORDecodeContext *me, uint16_t uTagVal) {
   if(uTagVal < 0xfff0) {
      return uTagVal;
   } else {
      // TODO constant and error check
      int x = uTagVal - 0xfff0;
      return me->auMappedTags[x];
   }
}

/*
 Gets all optional tag data items preceding a data item that is not an
 optional tag and records them as bits in the tag map.
 */
static QCBORError
GetNext_TaggedItem(QCBORDecodeContext *me, QCBORItem *pDecodedItem)
{
   // Stack usage: int/ptr: 3 -- 24
   QCBORError nReturn;

   uint16_t auTags[QCBOR_MAX_TAGS_PER_ITEM] = {CBOR_TAG_INVALID16,
                                               CBOR_TAG_INVALID16,
                                               CBOR_TAG_INVALID16,
                                               CBOR_TAG_INVALID16};

   // Loop fetching items until the item fetched is not a tag
   for(;;) {
      nReturn = GetNext_FullItem(me, pDecodedItem);
      if(nReturn) {
         goto Done; // Error out of the loop
      }

      if(pDecodedItem->uDataType != QCBOR_TYPE_OPTTAG) {
         // Successful exit from loop; maybe got some tags, maybe not
         memcpy(pDecodedItem->uTags, auTags, sizeof(auTags));
         break;
      }

      // Is there room for the tag in the tags list?
      size_t uTagIndex;
      for(uTagIndex = 0; uTagIndex < QCBOR_MAX_TAGS_PER_ITEM; uTagIndex++) {
         if(auTags[uTagIndex] == CBOR_TAG_INVALID16) {
            break;
         }
      }
      if(uTagIndex >= QCBOR_MAX_TAGS_PER_ITEM) {
         return QCBOR_ERR_TOO_MANY_TAGS;
      }

      // Is the tag > 16 bits?
      if(pDecodedItem->val.uTagV > CBOR_TAG_INVALID16) {
         size_t uTagMapIndex;
         // Is there room in the tag map?
         for(uTagMapIndex = 0; uTagMapIndex < QCBOR_NUM_MAPPED_TAGS; uTagMapIndex++) {
            if(me->auMappedTags[uTagMapIndex] == CBOR_TAG_INVALID16) {
               break;
            }
            if(me->auMappedTags[uTagMapIndex] == pDecodedItem->val.uTagV) {
               break;
            }
         }
         if(uTagMapIndex >= QCBOR_NUM_MAPPED_TAGS) {
            // No room for the tag
            return 97; // TODO error code
         }

         // Cover the case where tag is new and were it is already in the map
         me->auMappedTags[uTagMapIndex] = pDecodedItem->val.uTagV;
         auTags[uTagIndex] = (uint16_t)(uTagMapIndex + 0xfff0); // TODO proper constant and cast

      } else {
         auTags[uTagIndex] = (uint16_t)pDecodedItem->val.uTagV;
      }
   }

Done:
   return nReturn;
}


/*
 This layer takes care of map entries. It combines the label and data
 items into one QCBORItem.
 */
static inline QCBORError
GetNext_MapEntry(QCBORDecodeContext *me, QCBORItem *pDecodedItem)
{
   // Stack use: int/ptr 1, QCBORItem  -- 56
   QCBORError nReturn = GetNext_TaggedItem(me, pDecodedItem);
   if(nReturn)
      goto Done;

   if(pDecodedItem->uDataType == QCBOR_TYPE_BREAK) {
      // Break can't be a map entry
      goto Done;
   }

   if(me->uDecodeMode != QCBOR_DECODE_MODE_MAP_AS_ARRAY) {
      // In a map and caller wants maps decoded, not treated as arrays

      if(DecodeNesting_TypeIsMap(&(me->nesting))) {
         // If in a map and the right decoding mode, get the label

         // Save label in pDecodedItem and get the next which will
         // be the real data
         QCBORItem LabelItem = *pDecodedItem;
         nReturn = GetNext_TaggedItem(me, pDecodedItem);
         if(nReturn)
            goto Done;

         pDecodedItem->uLabelAlloc = LabelItem.uDataAlloc;

         if(LabelItem.uDataType == QCBOR_TYPE_TEXT_STRING) {
            // strings are always good labels
            pDecodedItem->label.string = LabelItem.val.string;
            pDecodedItem->uLabelType = QCBOR_TYPE_TEXT_STRING;
         } else if (QCBOR_DECODE_MODE_MAP_STRINGS_ONLY == me->uDecodeMode) {
            // It's not a string and we only want strings
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
            pDecodedItem->uLabelAlloc = LabelItem.uDataAlloc;
            pDecodedItem->uLabelType = QCBOR_TYPE_BYTE_STRING;
         } else {
            // label is not an int or a string. It is an arrray
            // or a float or such and this implementation doesn't handle that.
            // Also, tags on labels are ignored.
            nReturn = QCBOR_ERR_MAP_LABEL_TYPE;
            goto Done;
         }
      }
   } else {
      if(pDecodedItem->uDataType == QCBOR_TYPE_MAP) {
         if(pDecodedItem->val.uCount > QCBOR_MAX_ITEMS_IN_ARRAY/2) {
            nReturn = QCBOR_ERR_ARRAY_TOO_LONG;
            goto Done;
         }
         // Decoding a map as an array
         pDecodedItem->uDataType = QCBOR_TYPE_MAP_AS_ARRAY;
         // Cast is safe because of check against QCBOR_MAX_ITEMS_IN_ARRAY/2
         // Cast is needed because of integer promotion
         pDecodedItem->val.uCount = (uint16_t)(pDecodedItem->val.uCount * 2);
      }
   }

Done:
   return nReturn;
}


static QCBORError
NextIsBreak(UsefulInputBuf *pUIB, bool *pbNextIsBreak)
{
   *pbNextIsBreak = false;
   if(UsefulInputBuf_BytesUnconsumed(pUIB) != 0) {
      // TODO: use the Peek method?
      QCBORItem Peek;
      size_t uPeek = UsefulInputBuf_Tell(pUIB);
      QCBORError uReturn = GetNext_Item(pUIB, &Peek, NULL);
      if(uReturn != QCBOR_SUCCESS) {
         return uReturn;
      }
      if(Peek.uDataType != QCBOR_TYPE_BREAK) {
        // It is not a break, rewind so it can be processed normally.
        UsefulInputBuf_Seek(pUIB, uPeek);
      } else {
         *pbNextIsBreak = true;
      }
   }
   
   return QCBOR_SUCCESS;
}


/*
 An item was just consumed, now figure out if it was the
 end of an array or map that can be closed out. That
 may in turn close out another map or array.
 */
static QCBORError Ascender(QCBORDecodeContext *pMe)
{
   QCBORError uReturn;
   
   /* This loops ascending nesting levels as long as there is ascending to do */
   while(1) {
      if(!DecodeNesting_IsAtTop(&(pMe->nesting)) && !DecodeNesting_IsIndefiniteLength(&(pMe->nesting))) {
         /* 1st Case: in a definite length array (not a CBOR sequence). Simply
          decrement the item count. If it doesn't go to zero, then all is done.
          If it does go to zero, the bottom of the loop ascends one nesting level
          and the loop continues.
          */
         DecodeNesting_DecrementX(&(pMe->nesting));
         if(!DecodeNesting_IsEndOfDefiniteLengthMapOrArray(&(pMe->nesting))) {
            /* Didn't close out map or array; all work here is done */
            break;
         }
         
      } else {
         /* 2nd, 3rd, 4th and 5th  cases where a check for a following CBOR break must be checked for */
         bool bIsBreak = false;
         uReturn = NextIsBreak(&(pMe->InBuf), &bIsBreak);
         if(uReturn != QCBOR_SUCCESS) {
            goto Done;
         }
         
         if(bIsBreak) {
            if(DecodeNesting_IsAtTop(&(pMe->nesting))) {
               /* 2nd case where a break occurs at the top level and thus
                in a CBOR sequence. Always an error because break is
                not inside an indefinite length map or array. */
               uReturn = QCBOR_ERR_BAD_BREAK;
               goto Done;
            } else {
               /* 3rd case, the normal end of an indefinite length map
                  or array. The bottom of the loop ascends one nesting
                level and the loop continues. */
            }
         } else {
            /* 4th case where an indefinite length array is not closed out
             and 5th case which is just an item in a CBOR sequence. In either
             there is no close out so all work here is done.
             */
            break;
         }
      }
      
      /* All items in the level have been consumed. */
      
      /* But ascent in bounded mode is only by explicit call to QCBORDecode_ExitBoundedMode() */
      if(DecodeNesting_InBoundedMode(&(pMe->nesting))) {
         /* Set the count to zero for indefinite length arrays to indicate cursor is at end of bounded map / array */
         pMe->nesting.pCurrent->uCount = 0;
         break;
      }

      /* Finally, actually ascend one level. */
      DecodeNesting_Ascend(&(pMe->nesting));
   }
   
   uReturn = QCBOR_SUCCESS;

Done:
   return uReturn;
}


/*
 Public function, see header qcbor/qcbor_decode.h file
 TODO: correct this comment
 */
static QCBORError
QCBORDecode_GetNextMapOrArray(QCBORDecodeContext *me, QCBORItem *pDecodedItem)
{
   QCBORError uReturn;
   /* === First figure out if at the end of traversal === */

   /* Case 1. Out of bytes to consume.

      This is either the end of the top-level CBOR that was give
    to QCBORDecode_Init() or the end of a tag 24 bstr wrapped CBOR.
    It is detected by all bytes being consumed from the UsefulInputBuf.

    To go back out of the tag 24 bstr wrapped item, the caller must
    explicitly call Exit() which will reset the UsefulInputBuf
    to the next highest bstr wrapped or the top level.

    This is always the end condition that QCBORDecode_Finish()
    considers complete.

    TODO: can the DecodeNesting_IsAtTop be removed? QCBORDecode_Finish()
    will perform this check.

    */
   /* For a pre-order traversal a non-error end occurs when there
    are no more bytes to consume and the nesting level is at the top.
    If it's not at the top, then the CBOR is not well formed. This error
    is caught elsewhere.

    This handles the end of CBOR sequences as well as non-sequences. */
   if(UsefulInputBuf_BytesUnconsumed(&(me->InBuf)) == 0 && DecodeNesting_IsAtTop(&(me->nesting))) {
      uReturn = QCBOR_ERR_NO_MORE_ITEMS;
      goto Done;
   }


   /* Case 2. End of map or array in bounded mode

    The caller is attempting traveral of a bounded map or array and
    has got to the end of it.

    The caller must explicitly exit the bounded mode map or array
    to get past this condition.

    To complete a decode of the full input CBOR, the caller must
    exit all maps and arrays in bounded mode and this is never
    the successful end of decoding.

    */
   /* It is also an end of the input when in map mode and the cursor
    is at the end of the map */


   // This is to handle bounded mode
   if(DecodeNesting_AtEnd(&(me->nesting))) {
      uReturn = QCBOR_ERR_NO_MORE_ITEMS;
      goto Done;
   }

   /* === Not at the end; get another item === */
   uReturn = GetNext_MapEntry(me, pDecodedItem);
   if(uReturn) {
      goto Done;
   }

   // Breaks ending arrays/maps are always processed at the end of this function.
   // They should never show up here.
   if(pDecodedItem->uDataType == QCBOR_TYPE_BREAK) {
      uReturn = QCBOR_ERR_BAD_BREAK;
      goto Done;
   }

   // Record the nesting level for this data item before processing any of
   // decrementing and descending.
   pDecodedItem->uNestingLevel = DecodeNesting_GetLevel(&(me->nesting));

   // Process the item just received for descent or decrement, and
   // ascend if decrements are enough to close out a definite length array/map
   if(IsMapOrArray(pDecodedItem->uDataType) && pDecodedItem->val.uCount != 0) {
      // If the new item is array or map, the nesting level descends
      uReturn = DecodeNesting_Descend(&(me->nesting), pDecodedItem->uDataType, pDecodedItem->val.uCount, 0L, 0L);
      // Maps and arrays do count in as items in the map/array that encloses
      // them so a decrement needs to be done for them too, but that is done
      // only when all the items in them have been processed, not when they
      // are opened with the exception of an empty map or array.
      if(uReturn != QCBOR_SUCCESS) {
         goto Done;
      }
   }

   if(!IsMapOrArray(pDecodedItem->uDataType) ||
      pDecodedItem->val.uCount == 0 || pDecodedItem->val.uCount == UINT16_MAX) {
      /* The following cases are handled here:
         - A non-aggregate like an integer or string
         - An empty definite length map or array
         - An indefinite length map or array that might be empty or might not.
       */
      


      /* === Figure out if item got closed out maps or arrays === */

      /*
       This needs to decrement, check for end and ascend
       the tree until an an ascend is not possible or the bounded
       limit is reached or the end of the encoded CBOR input
       is reached. For
       definite length maps and arrays the end is by count. For
       indefinite it is by a break.

       Also state needs to be set that can tell the code at the
       beginning of this function that the end was reached.

       This is complicated...


       This will handle an indefinite length array
       inside a definte length array inside an indefinite
       length array...

       */

      // Decrement the count of items in the enclosing map/array
      // If the count in the enclosing map/array goes to zero, that
      // triggers a decrement in the map/array above that and
      // an ascend in nesting level.
      /* If the just consumed item is at the end of a map or
       array ascend in the nesting tracking. That may
       in turn may be the end of the above nesting level
       and so on up to the end of the whole encoded CBOR.
       
       Each level could be a definite or indefinte length
       map or array. These are handled very differently.
       
      */
      uReturn = Ascender(me);
      if(uReturn) {
         goto Done;
      }
   }



   /* === Tell the caller the nest level of the next item === */

   // Tell the caller what level is next. This tells them what maps/arrays
   // were closed out and makes it possible for them to reconstruct
   // the tree with just the information returned by GetNext
   // TODO: pull this into DecodeNesting_GetLevel
   if(DecodeNesting_InBoundedMode(&(me->nesting)) && me->nesting.pCurrent->uCount == 0) {
      // At end of a map / array in map mode, so next nest is 0 to
      // indicate this end.
      pDecodedItem->uNextNestLevel = 0;
   } else {
      pDecodedItem->uNextNestLevel = DecodeNesting_GetLevel(&(me->nesting));
   }

Done:
   if(uReturn != QCBOR_SUCCESS) {
      // Make sure uDataType and uLabelType are QCBOR_TYPE_NONE
      memset(pDecodedItem, 0, sizeof(QCBORItem));
   }
   return uReturn;
}


/*
 Mostly just assign the right data type for the date string.
 */
inline static QCBORError DecodeDateString(QCBORItem *pDecodedItem)
{
   // Stack Use: UsefulBuf 1 16
   if(pDecodedItem->uDataType != QCBOR_TYPE_TEXT_STRING) {
      return QCBOR_ERR_BAD_OPT_TAG;
   }

   const UsefulBufC Temp        = pDecodedItem->val.string;
   pDecodedItem->val.dateString = Temp;
   pDecodedItem->uDataType      = QCBOR_TYPE_DATE_STRING;
   return QCBOR_SUCCESS;
}


/*
 The epoch formatted date. Turns lots of different forms of encoding
 date into uniform one
 */
static QCBORError DecodeDateEpoch(QCBORItem *pDecodedItem)
{
   // Stack usage: 1
   QCBORError nReturn = QCBOR_SUCCESS;

   pDecodedItem->val.epochDate.fSecondsFraction = 0;

   switch (pDecodedItem->uDataType) {

      case QCBOR_TYPE_INT64:
         pDecodedItem->val.epochDate.nSeconds = pDecodedItem->val.int64;
         break;

      case QCBOR_TYPE_UINT64:
         if(pDecodedItem->val.uint64 > INT64_MAX) {
            nReturn = QCBOR_ERR_DATE_OVERFLOW;
            goto Done;
         }
         pDecodedItem->val.epochDate.nSeconds = (int64_t)pDecodedItem->val.uint64;
         break;

      case QCBOR_TYPE_DOUBLE:
      {
         // This comparison needs to be done as a float before
         // conversion to an int64_t to be able to detect doubles
         // that are too large to fit into an int64_t.  A double
         // has 52 bits of preceision. An int64_t has 63. Casting
         // INT64_MAX to a double actually causes a round up which
         // is bad and wrong for the comparison because it will
         // allow conversion of doubles that can't fit into a
         // uint64_t.  To remedy this INT64_MAX - 0x7ff is used as
         // the cutoff point as if that rounds up in conversion to
         // double it will still be less than INT64_MAX. 0x7ff is
         // picked because it has 11 bits set.
         //
         // INT64_MAX seconds is on the order of 10 billion years,
         // and the earth is less than 5 billion years old, so for
         // most uses this conversion error won't occur even though
         // doubles can go much larger.
         //
         // Without the 0x7ff there is a ~30 minute range of time
         // values 10 billion years in the past and in the future
         // where this this code would go wrong.
         const double d = pDecodedItem->val.dfnum;
         if(d > (double)(INT64_MAX - 0x7ff)) {
            nReturn = QCBOR_ERR_DATE_OVERFLOW;
            goto Done;
         }
         pDecodedItem->val.epochDate.nSeconds = (int64_t)d;
         pDecodedItem->val.epochDate.fSecondsFraction = d - (double)pDecodedItem->val.epochDate.nSeconds;
      }
         break;

      default:
         nReturn = QCBOR_ERR_BAD_OPT_TAG;
         goto Done;
   }
   pDecodedItem->uDataType = QCBOR_TYPE_DATE_EPOCH;

Done:
   return nReturn;
}


/*
 Mostly just assign the right data type for the bignum.
 */
inline static QCBORError DecodeBigNum(QCBORItem *pDecodedItem)
{
   // Stack Use: UsefulBuf 1  -- 16
   if(pDecodedItem->uDataType != QCBOR_TYPE_BYTE_STRING) {
      return QCBOR_ERR_BAD_OPT_TAG;
   }
   const UsefulBufC Temp    = pDecodedItem->val.string;
   pDecodedItem->val.bigNum = Temp;
   const bool bIsPosBigNum = (bool)(pDecodedItem->uTags[0] == CBOR_TAG_POS_BIGNUM);
   pDecodedItem->uDataType  = (uint8_t)(bIsPosBigNum ? QCBOR_TYPE_POSBIGNUM
                                                     : QCBOR_TYPE_NEGBIGNUM);
   return QCBOR_SUCCESS;
}


#ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
/*
 Decode decimal fractions and big floats.

 When called pDecodedItem must be the array that is tagged as a big
 float or decimal fraction, the array that has the two members, the
 exponent and mantissa.

 This will fetch and decode the exponent and mantissa and put the
 result back into pDecodedItem.
 */
inline static QCBORError
QCBORDecode_MantissaAndExponent(QCBORDecodeContext *me, QCBORItem *pDecodedItem)
{
   QCBORError nReturn;

   // --- Make sure it is an array; track nesting level of members ---
   if(pDecodedItem->uDataType != QCBOR_TYPE_ARRAY) {
      nReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }

   // A check for pDecodedItem->val.uCount == 2 would work for
   // definite length arrays, but not for indefnite.  Instead remember
   // the nesting level the two integers must be at, which is one
   // deeper than that of the array.
   const int nNestLevel = pDecodedItem->uNestingLevel + 1;

   // --- Is it a decimal fraction or a bigfloat? ---
   const bool bIsTaggedDecimalFraction = QCBORDecode_IsTagged(me, pDecodedItem, CBOR_TAG_DECIMAL_FRACTION);
   pDecodedItem->uDataType = bIsTaggedDecimalFraction ? QCBOR_TYPE_DECIMAL_FRACTION : QCBOR_TYPE_BIGFLOAT;

   // --- Get the exponent ---
   QCBORItem exponentItem;
   nReturn = QCBORDecode_GetNextMapOrArray(me, &exponentItem);
   if(nReturn != QCBOR_SUCCESS) {
      goto Done;
   }
   if(exponentItem.uNestingLevel != nNestLevel) {
      // Array is empty or a map/array encountered when expecting an int
      nReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }
   if(exponentItem.uDataType == QCBOR_TYPE_INT64) {
     // Data arriving as an unsigned int < INT64_MAX has been converted
     // to QCBOR_TYPE_INT64 and thus handled here. This is also means
     // that the only data arriving here of type QCBOR_TYPE_UINT64 data
     // will be too large for this to handle and thus an error that will
     // get handled in the next else.
     pDecodedItem->val.expAndMantissa.nExponent = exponentItem.val.int64;
   } else {
      // Wrong type of exponent or a QCBOR_TYPE_UINT64 > INT64_MAX
      nReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }

   // --- Get the mantissa ---
   QCBORItem mantissaItem;
   nReturn = QCBORDecode_GetNextWithTags(me, &mantissaItem, NULL);
   if(nReturn != QCBOR_SUCCESS) {
      goto Done;
   }
   if(mantissaItem.uNestingLevel != nNestLevel) {
      // Mantissa missing or map/array encountered when expecting number
      nReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }
   if(mantissaItem.uDataType == QCBOR_TYPE_INT64) {
      // Data arriving as an unsigned int < INT64_MAX has been converted
      // to QCBOR_TYPE_INT64 and thus handled here. This is also means
      // that the only data arriving here of type QCBOR_TYPE_UINT64 data
      // will be too large for this to handle and thus an error that
      // will get handled in an else below.
      pDecodedItem->val.expAndMantissa.Mantissa.nInt = mantissaItem.val.int64;
   }  else if(mantissaItem.uDataType == QCBOR_TYPE_POSBIGNUM || mantissaItem.uDataType == QCBOR_TYPE_NEGBIGNUM) {
      // Got a good big num mantissa
      pDecodedItem->val.expAndMantissa.Mantissa.bigNum = mantissaItem.val.bigNum;
      // Depends on numbering of QCBOR_TYPE_XXX
      pDecodedItem->uDataType = (uint8_t)(pDecodedItem->uDataType +
                                          mantissaItem.uDataType - QCBOR_TYPE_POSBIGNUM +
                                          1);
   } else {
      // Wrong type of mantissa or a QCBOR_TYPE_UINT64 > INT64_MAX
      nReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }

   // --- Check that array only has the two numbers ---
   if(mantissaItem.uNextNestLevel == nNestLevel) {
      // Extra items in the decimal fraction / big num
      nReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }

Done:

  return nReturn;
}
#endif /* QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA */



/*
 */
inline static QCBORError DecodeURI(QCBORItem *pDecodedItem)
{
   if(pDecodedItem->uDataType != QCBOR_TYPE_TEXT_STRING) {
      return QCBOR_ERR_BAD_OPT_TAG;
   }
   pDecodedItem->uDataType = QCBOR_TYPE_URI;
   return QCBOR_SUCCESS;
}


inline static QCBORError DecodeB64URL(QCBORItem *pDecodedItem)
{
   if(pDecodedItem->uDataType != QCBOR_TYPE_TEXT_STRING) {
      return QCBOR_ERR_BAD_OPT_TAG;
   }
   pDecodedItem->uDataType = QCBOR_TYPE_BASE64URL;
   return QCBOR_SUCCESS;
}


inline static QCBORError DecodeB64(QCBORItem *pDecodedItem)
{
   if(pDecodedItem->uDataType != QCBOR_TYPE_TEXT_STRING) {
      return QCBOR_ERR_BAD_OPT_TAG;
   }
   pDecodedItem->uDataType = QCBOR_TYPE_BASE64;
   return QCBOR_SUCCESS;
}


inline static QCBORError DecodeRegex(QCBORItem *pDecodedItem)
{
   if(pDecodedItem->uDataType != QCBOR_TYPE_TEXT_STRING) {
      return QCBOR_ERR_BAD_OPT_TAG;
   }
   pDecodedItem->uDataType = QCBOR_TYPE_REGEX;
   return QCBOR_SUCCESS;
}

inline static QCBORError DecodeWrappedCBOR(QCBORItem *pDecodedItem)
{
   if(pDecodedItem->uDataType != QCBOR_TYPE_BYTE_STRING) {
      return QCBOR_ERR_BAD_OPT_TAG;
   }
   pDecodedItem->uDataType = QBCOR_TYPE_WRAPPED_CBOR;
   return QCBOR_SUCCESS;
}

inline static QCBORError DecodeMIME(QCBORItem *pDecodedItem)
{
   if(pDecodedItem->uDataType == QCBOR_TYPE_TEXT_STRING) {
      pDecodedItem->uDataType = QCBOR_TYPE_MIME;
   } else if(pDecodedItem->uDataType != QCBOR_TYPE_BYTE_STRING) {
      pDecodedItem->uDataType = QCBOR_TYPE_BINARY_MIME;
   } else {
      return QCBOR_ERR_BAD_OPT_TAG;
   }
   return QCBOR_SUCCESS;
}


/*
 */
inline static QCBORError DecodeUUID(QCBORItem *pDecodedItem)
{
   if(pDecodedItem->uDataType != QCBOR_TYPE_BYTE_STRING) {
      return QCBOR_ERR_BAD_OPT_TAG;
   }
   pDecodedItem->uDataType = QCBOR_TYPE_UUID;
   return QCBOR_SUCCESS;
}


/*
 Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_GetNext(QCBORDecodeContext *me, QCBORItem *pDecodedItem)
{
   QCBORError nReturn;

   nReturn = QCBORDecode_GetNextMapOrArray(me, pDecodedItem);
   if(nReturn != QCBOR_SUCCESS) {
      goto Done;
   }

   for(int i = 0; i < QCBOR_MAX_TAGS_PER_ITEM; i++) {
      switch(pDecodedItem->uTags[i] ) {

         case CBOR_TAG_DATE_STRING:
         nReturn = DecodeDateString(pDecodedItem);
         break;

         case CBOR_TAG_DATE_EPOCH:
         nReturn = DecodeDateEpoch(pDecodedItem);
         break;

         case CBOR_TAG_POS_BIGNUM:
         case CBOR_TAG_NEG_BIGNUM:
         nReturn = DecodeBigNum(pDecodedItem);
         break;

   #ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
         case CBOR_TAG_DECIMAL_FRACTION:
         case CBOR_TAG_BIGFLOAT:
         // For aggregate tagged types, what goes into pTags is only collected
         // from the surrounding data item, not the contents, so pTags is not
         // passed on here.

         nReturn = QCBORDecode_MantissaAndExponent(me, pDecodedItem);
         break;
   #endif /* QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA */

         case CBOR_TAG_CBOR:
         nReturn = DecodeWrappedCBOR(pDecodedItem);
         break;

         case CBOR_TAG_URI:
         nReturn = DecodeURI(pDecodedItem);
         break;

         case CBOR_TAG_B64URL:
         nReturn = DecodeB64URL(pDecodedItem);
         break;
            
         case CBOR_TAG_B64:
         nReturn = DecodeB64(pDecodedItem);
         break;

         case CBOR_TAG_MIME:
         case CBOR_TAG_BINARY_MIME:
         nReturn = DecodeMIME(pDecodedItem);
         break;

         case CBOR_TAG_REGEX:
         nReturn = DecodeRegex(pDecodedItem);
         break;

         case CBOR_TAG_BIN_UUID:
         nReturn = DecodeUUID(pDecodedItem);
         break;
            
         case CBOR_TAG_INVALID16:
         // The end of the tag list or no tags
         // Successful exit from the loop.
         goto Done;
            
         default:
         // A tag that is not understood
         // A successful exit from the loop
         goto Done;

      }
      if(nReturn != QCBOR_SUCCESS) {
         goto Done;
      }
   }

Done:
   if(nReturn != QCBOR_SUCCESS) {
      pDecodedItem->uDataType  = QCBOR_TYPE_NONE;
      pDecodedItem->uLabelType = QCBOR_TYPE_NONE;
   }
   return nReturn;
}


QCBORError QCBORDecode_PeekNext(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   const size_t uOffset = UsefulInputBuf_Tell(&(pMe->InBuf));

   QCBORError uErr = QCBORDecode_GetNext(pMe, pDecodedItem);

   UsefulInputBuf_Seek(&(pMe->InBuf), uOffset);

   return uErr;
}


/*
 Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_GetNextWithTags(QCBORDecodeContext *me,
                            QCBORItem *pDecodedItem,
                            QCBORTagListOut *pTags)
{
   QCBORError nReturn;

   nReturn = QCBORDecode_GetNext(me, pDecodedItem);
   if(nReturn != QCBOR_SUCCESS) {
      return nReturn;
   }

   if(pTags != NULL) {
      pTags->uNumUsed = 0;
      for(int i = 0; i < QCBOR_MAX_TAGS_PER_ITEM; i++) {
         if(pDecodedItem->uTags[i] == CBOR_TAG_INVALID16) {
            break;
         }
         if(pTags->uNumUsed >= pTags->uNumAllocated) {
            return QCBOR_ERR_TOO_MANY_TAGS;
         }
         pTags->puTags[pTags->uNumUsed] = ConvertTag(me, pDecodedItem->uTags[i]);
         pTags->uNumUsed++;
      }
   }

   return QCBOR_SUCCESS;
}


/*
 Decoding items is done in 5 layered functions, one calling the
 next one down. If a layer has no work to do for a particular item
 it returns quickly.

 - QCBORDecode_GetNext, GetNextWithTags -- The top layer processes
 tagged data items, turning them into the local C representation.
 For the most simple it is just associating a QCBOR_TYPE with the data. For
 the complex ones that an aggregate of data items, there is some further
 decoding and a little bit of recursion.

 - QCBORDecode_GetNextMapOrArray - This manages the beginnings and
 ends of maps and arrays. It tracks descending into and ascending
 out of maps/arrays. It processes all breaks that terminate
 indefinite length maps and arrays.

 - GetNext_MapEntry -- This handles the combining of two
 items, the label and the data, that make up a map entry.
 It only does work on maps. It combines the label and data
 items into one labeled item.

 - GetNext_TaggedItem -- This decodes type 6 tagging. It turns the
 tags into bit flags associated with the data item. No actual decoding
 of the contents of the tagged item is performed here.

 - GetNext_FullItem -- This assembles the sub-items that make up
 an indefinte length string into one string item. It uses the
 string allocater to create contiguous space for the item. It
 processes all breaks that are part of indefinite length strings.

 - GetNext_Item -- This decodes the atomic data items in CBOR. Each
 atomic data item has a "major type", an integer "argument" and optionally
 some content. For text and byte strings, the content is the bytes
 that make up the string. These are the smallest data items that are
 considered to be well-formed.  The content may also be other data items in
 the case of aggregate types. They are not handled in this layer.

 Roughly this takes 300 bytes of stack for vars. Need to
 evaluate this more carefully and correctly.

 */


/*
 Public function, see header qcbor/qcbor_decode.h file
 */
int QCBORDecode_IsTagged(QCBORDecodeContext *me,
                         const QCBORItem   *pItem,
                         uint64_t           uTag)
{
   for(int i = 0; i < QCBOR_MAX_TAGS_PER_ITEM; i++ ) {
      if(pItem->uTags[i] == CBOR_TAG_INVALID16) {
         break;
      }
      if(ConvertTag(me, pItem->uTags[i]) == uTag) {
         return 1;
      }
   }

   return 0;
}


/*
 Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError QCBORDecode_Finish(QCBORDecodeContext *me)
{
   QCBORError nReturn = QCBOR_SUCCESS;

   // Error out if all the maps/arrays are not closed out
   if(!DecodeNesting_IsAtTop(&(me->nesting))) {
      nReturn = QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN;
      goto Done;
   }

   // Error out if not all the bytes are consumed
   if(UsefulInputBuf_BytesUnconsumed(&(me->InBuf))) {
      nReturn = QCBOR_ERR_EXTRA_BYTES;
   }

Done:
   // Call the destructor for the string allocator if there is one.
   // Always called, even if there are errors; always have to clean up
   StringAllocator_Destruct(&(me->StringAllocator));

   return nReturn;
}


/*
Public function, see header qcbor/qcbor_decode.h file
*/
uint64_t QCBORDecode_GetNthTag(QCBORDecodeContext *pMe,
                               const QCBORItem    *pItem,
                               unsigned int        uIndex)
{
   if(uIndex > QCBOR_MAX_TAGS_PER_ITEM) {
      return CBOR_TAG_INVALID16;
   } else if(pItem->uTags[uIndex] <= QCBOR_LAST_UNMAPPED_TAG) {
      return pItem->uTags[uIndex];
   } else if(pItem->uTags[uIndex] < QCBOR_NUM_MAPPED_TAGS + QCBOR_LAST_UNMAPPED_TAG) {
      return pMe->auMappedTags[pItem->uTags[uIndex] - QCBOR_LAST_UNMAPPED_TAG];
   } else {
      return CBOR_TAG_INVALID16;
   }
}


/*

Decoder errors handled in this file

 - Hit end of input before it was expected while decoding type and
   number QCBOR_ERR_HIT_END

 - negative integer that is too large for C QCBOR_ERR_INT_OVERFLOW

 - Hit end of input while decoding a text or byte string
   QCBOR_ERR_HIT_END

 - Encountered conflicting tags -- e.g., an item is tagged both a date
   string and an epoch date QCBOR_ERR_UNSUPPORTED

 - Encontered an array or mapp that has too many items
   QCBOR_ERR_ARRAY_TOO_LONG

 - Encountered array/map nesting that is too deep
   QCBOR_ERR_ARRAY_NESTING_TOO_DEEP

 - An epoch date > INT64_MAX or < INT64_MIN was encountered
   QCBOR_ERR_DATE_OVERFLOW

 - The type of a map label is not a string or int
   QCBOR_ERR_MAP_LABEL_TYPE

 - Hit end with arrays or maps still open -- QCBOR_ERR_EXTRA_BYTES

 */




/* ===========================================================================
   MemPool -- BUILT-IN SIMPLE STRING ALLOCATOR

   This implements a simple sting allocator for indefinite length
   strings that can be enabled by calling QCBORDecode_SetMemPool(). It
   implements the function type QCBORStringAllocate and allows easy
   use of it.

   This particular allocator is built-in for convenience. The caller
   can implement their own.  All of this following code will get
   dead-stripped if QCBORDecode_SetMemPool() is not called.

   This is a very primitive memory allocator. It does not track
   individual allocations, only a high-water mark. A free or
   reallocation must be of the last chunk allocated.

   The size of the pool and offset to free memory are packed into the
   first 8 bytes of the memory pool so we don't have to keep them in
   the decode context. Since the address of the pool may not be
   aligned, they have to be packed and unpacked as if they were
   serialized data of the wire or such.

   The sizes packed in are uint32_t to be the same on all CPU types
   and simplify the code.
   ========================================================================== */


static inline int
MemPool_Unpack(const void *pMem, uint32_t *puPoolSize, uint32_t *puFreeOffset)
{
   // Use of UsefulInputBuf is overkill, but it is convenient.
   UsefulInputBuf UIB;

   // Just assume the size here. It was checked during SetUp so
   // the assumption is safe.
   UsefulInputBuf_Init(&UIB, (UsefulBufC){pMem, QCBOR_DECODE_MIN_MEM_POOL_SIZE});
   *puPoolSize     = UsefulInputBuf_GetUint32(&UIB);
   *puFreeOffset   = UsefulInputBuf_GetUint32(&UIB);
   return UsefulInputBuf_GetError(&UIB);
}


static inline int
MemPool_Pack(UsefulBuf Pool, uint32_t uFreeOffset)
{
   // Use of UsefulOutBuf is overkill, but convenient. The
   // length check performed here is useful.
   UsefulOutBuf UOB;

   UsefulOutBuf_Init(&UOB, Pool);
   UsefulOutBuf_AppendUint32(&UOB, (uint32_t)Pool.len); // size of pool
   UsefulOutBuf_AppendUint32(&UOB, uFreeOffset); // first free position
   return UsefulOutBuf_GetError(&UOB);
}


/*
 Internal function for an allocation, reallocation free and destuct.

 Having only one function rather than one each per mode saves space in
 QCBORDecodeContext.

 Code Reviewers: THIS FUNCTION DOES POINTER MATH
 */
static UsefulBuf
MemPool_Function(void *pPool, void *pMem, size_t uNewSize)
{
   UsefulBuf ReturnValue = NULLUsefulBuf;

   uint32_t uPoolSize;
   uint32_t uFreeOffset;

   if(uNewSize > UINT32_MAX) {
      // This allocator is only good up to 4GB.  This check should
      // optimize out if sizeof(size_t) == sizeof(uint32_t)
      goto Done;
   }
   const uint32_t uNewSize32 = (uint32_t)uNewSize;

   if(MemPool_Unpack(pPool, &uPoolSize, &uFreeOffset)) {
      goto Done;
   }

   if(uNewSize) {
      if(pMem) {
         // REALLOCATION MODE
         // Calculate pointer to the end of the memory pool.  It is
         // assumed that pPool + uPoolSize won't wrap around by
         // assuming the caller won't pass a pool buffer in that is
         // not in legitimate memory space.
         const void *pPoolEnd = (uint8_t *)pPool + uPoolSize;

         // Check that the pointer for reallocation is in the range of the
         // pool. This also makes sure that pointer math further down
         // doesn't wrap under or over.
         if(pMem >= pPool && pMem < pPoolEnd) {
            // Offset to start of chunk for reallocation. This won't
            // wrap under because of check that pMem >= pPool.  Cast
            // is safe because the pool is always less than UINT32_MAX
            // because of check in QCBORDecode_SetMemPool().
            const uint32_t uMemOffset = (uint32_t)((uint8_t *)pMem - (uint8_t *)pPool);

            // Check to see if the allocation will fit. uPoolSize -
            // uMemOffset will not wrap under because of check that
            // pMem is in the range of the uPoolSize by check above.
            if(uNewSize <= uPoolSize - uMemOffset) {
               ReturnValue.ptr = pMem;
               ReturnValue.len = uNewSize;

               // Addition won't wrap around over because uNewSize was
               // checked to be sure it is less than the pool size.
               uFreeOffset = uMemOffset + uNewSize32;
            }
         }
      } else {
         // ALLOCATION MODE
         // uPoolSize - uFreeOffset will not underflow because this
         // pool implementation makes sure uFreeOffset is always
         // smaller than uPoolSize through this check here and
         // reallocation case.
         if(uNewSize <= uPoolSize - uFreeOffset) {
            ReturnValue.len = uNewSize;
            ReturnValue.ptr = (uint8_t *)pPool + uFreeOffset;
            uFreeOffset    += (uint32_t)uNewSize;
         }
      }
   } else {
      if(pMem) {
         // FREE MODE
         // Cast is safe because of limit on pool size in
         // QCBORDecode_SetMemPool()
         uFreeOffset = (uint32_t)((uint8_t *)pMem - (uint8_t *)pPool);
      } else {
         // DESTRUCT MODE
         // Nothing to do for this allocator
      }
   }

   UsefulBuf Pool = {pPool, uPoolSize};
   MemPool_Pack(Pool, uFreeOffset);

Done:
   return ReturnValue;
}


/*
 Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError QCBORDecode_SetMemPool(QCBORDecodeContext *pMe,
                                  UsefulBuf Pool,
                                  bool bAllStrings)
{
   // The pool size and free mem offset are packed into the beginning
   // of the pool memory. This compile time check make sure the
   // constant in the header is correct.  This check should optimize
   // down to nothing.
   if(QCBOR_DECODE_MIN_MEM_POOL_SIZE < 2 * sizeof(uint32_t)) {
      return QCBOR_ERR_BUFFER_TOO_SMALL;
   }

   // The pool size and free offset packed in to the beginning of pool
   // memory are only 32-bits. This check will optimize out on 32-bit
   // machines.
   if(Pool.len > UINT32_MAX) {
      return QCBOR_ERR_BUFFER_TOO_LARGE;
   }

   // This checks that the pool buffer given is big enough.
   if(MemPool_Pack(Pool, QCBOR_DECODE_MIN_MEM_POOL_SIZE)) {
      return QCBOR_ERR_BUFFER_TOO_SMALL;
   }

   pMe->StringAllocator.pfAllocator    = MemPool_Function;
   pMe->StringAllocator.pAllocateCxt  = Pool.ptr;
   pMe->bStringAllocateAll             = bAllStrings;

   return QCBOR_SUCCESS;
}



#include <stdio.h>
void printdecode(QCBORDecodeContext *pMe, const char *szName)
{
   printf("---%s--%d--%d--\narrow is current bounded level\nLevel   Count   Type S-Offset  SaveCount  Bounded E-Offset\n",
          szName,
          (uint32_t)pMe->InBuf.cursor,
          (uint32_t)pMe->InBuf.UB.len);
   for(int i = 0; i < QCBOR_MAX_ARRAY_NESTING; i++) {
      if(&(pMe->nesting.pMapsAndArrays[i]) > pMe->nesting.pCurrent) {
         break;
      }
      printf("%2s %2d   %5d  %s   %6u      %5d        %d    %5d\n",
             pMe->nesting.pCurrentBounded == &(pMe->nesting.pMapsAndArrays[i]) ? "->": "  ",
             i,
             pMe->nesting.pMapsAndArrays[i].uCount,
             pMe->nesting.pMapsAndArrays[i].uMajorType == QCBOR_TYPE_MAP ? "map  " :
               (pMe->nesting.pMapsAndArrays[i].uMajorType == QCBOR_TYPE_ARRAY ? "array" :
                 (pMe->nesting.pMapsAndArrays[i].uMajorType == QCBOR_TYPE_BYTE_STRING ? "bstr " :
                   (pMe->nesting.pMapsAndArrays[i].uMajorType == QCBOR_TYPE_NONE ? "none " : "?????"))),
             pMe->nesting.pMapsAndArrays[i].uOffset,
             pMe->nesting.pMapsAndArrays[i].uSaveCount,
             pMe->nesting.pMapsAndArrays[i].bBoundedMode,
             pMe->nesting.pMapsAndArrays[i].uPreviousEndOffset
             );

   }
   printf("\n");
}


/*
 Consume an entire map or array (and do next to
 nothing for non-aggregate types).
 */
static inline QCBORError
ConsumeItem(QCBORDecodeContext *pMe,
            const QCBORItem    *pItemToConsume,
            uint_fast8_t       *puNextNestLevel)
{
   QCBORError uReturn;
   QCBORItem  Item;
   
   printdecode(pMe, "ConsumeItem");

   if(IsMapOrArray(pItemToConsume->uDataType)) {
      /* There is only real work to do for maps and arrays */

      /* This works for definite and indefinite length
       * maps and arrays by using the nesting level
       */
      do {
         uReturn = QCBORDecode_GetNext(pMe, &Item);
         if(uReturn != QCBOR_SUCCESS) {
            goto Done;
         }
      } while(Item.uNextNestLevel >= pItemToConsume->uNextNestLevel);

      if(puNextNestLevel != NULL) {
         *puNextNestLevel = Item.uNextNestLevel;
      }
      uReturn = QCBOR_SUCCESS;

   } else {
      /* item_to_consume is not a map or array */
      if(puNextNestLevel != NULL) {
         /* Just pass the nesting level through */
         *puNextNestLevel = pItemToConsume->uNextNestLevel;
      }
      uReturn = QCBOR_SUCCESS;
   }

Done:
    return uReturn;
}


/* Return true if the labels in Item1 and Item2 are the same.
   Works only for integer and string labels. Returns false
   for any other type. */
static inline bool
MatchLabel(QCBORItem Item1, QCBORItem Item2)
{
   if(Item1.uLabelType == QCBOR_TYPE_INT64) {
      if(Item2.uLabelType == QCBOR_TYPE_INT64 && Item1.label.int64 == Item2.label.int64) {
         return true;
      }
   } else if(Item1.uLabelType == QCBOR_TYPE_TEXT_STRING) {
      if(Item2.uLabelType == QCBOR_TYPE_TEXT_STRING && !UsefulBuf_Compare(Item1.label.string, Item2.label.string)) {
         return true;
      }
   } else if(Item1.uLabelType == QCBOR_TYPE_BYTE_STRING) {
      if(Item2.uLabelType == QCBOR_TYPE_BYTE_STRING && !UsefulBuf_Compare(Item1.label.string, Item2.label.string)) {
         return true;
      }
   } else if(Item1.uLabelType == QCBOR_TYPE_UINT64) {
      if(Item2.uLabelType == QCBOR_TYPE_UINT64 && Item1.label.uint64 == Item2.label.uint64) {
         return true;
      }
   }
   
   /* Other label types are never matched */
   return false;
}


/*
 Returns true if Item1 and Item2 are the same type
 or if either are of QCBOR_TYPE_ANY.
 */
static inline bool
MatchType(QCBORItem Item1, QCBORItem Item2)
{
   if(Item1.uDataType == Item2.uDataType) {
      return true;
   } else if(Item1.uDataType == QCBOR_TYPE_ANY) {
      return true;
   } else if(Item2.uDataType == QCBOR_TYPE_ANY) {
      return true;
   }
   return false;
}


/**
 \brief Search a map for a set of items.

 @param[in]  pMe   The decode context to search.
 @param[in,out] pItemArray  The items to search for and the items found.
 @param[in] pCBContext  Context for the not-found item call back
 @param[in] pfCallback  Function to call on items not matched in pItemArray

 @retval QCBOR_ERR_NOT_ENTERED Trying to search without having entered a map

 @retval QCBOR_ERR_DUPLICATE_LABEL Duplicate items (items with the same label) were found for one of the labels being search for. This duplicate detection is only performed for items in pItemArray, not every item in the map.

 @retval QCBOR_ERR_UNEXPECTED_TYPE The label was matched, but not the type.

 @retval Also errors returned by QCBORDecode_GetNext().

 On input pItemArray contains a list of labels and data types
 of items to be found.
 
 On output the fully retrieved items are filled in with
 values and such. The label was matched, so it never changes.
 
 If an item was not found, its data type is set to none.
 
 */
static QCBORError
MapSearch(QCBORDecodeContext *pMe,
          QCBORItem          *pItemArray,
          size_t             *puOffset,
          void               *pCBContext,
          QCBORItemCallback   pfCallback)
{
   QCBORError  uReturn;

   QCBORDecodeNesting SaveNesting;
   DecodeNesting_PrepareForMapSearch(&(pMe->nesting), &SaveNesting);

   // Reposition to search from the start of the map / array
   UsefulInputBuf_Seek(&(pMe->InBuf), pMe->nesting.pCurrentBounded->uOffset);

   /* Loop over all the items in the map. They could be
   * deeply nested and this should handle both definite
   * and indefinite length maps and arrays, so this
   * adds some complexity. */
   const uint8_t uMapNestLevel = DecodeNesting_GetBoundedModeLevel(&(pMe->nesting));

   uint_fast8_t uNextNestLevel;
   
   uint64_t uFoundItemBitMap = 0;

   /* Iterate over items in the map / array */
   do {
      /* Remember offset of the item because sometimes it has to be returned */
      const size_t uOffset = UsefulInputBuf_Tell(&(pMe->InBuf));

      /* Get the item */
      QCBORItem Item;
      uReturn = QCBORDecode_GetNext(pMe, &Item);
      if(uReturn != QCBOR_SUCCESS) {
         /* Got non-well-formed CBOR */
         goto Done;
      }
       
      /* See if item has one of the labels that are of interest */
      int         nIndex;
      QCBORItem  *pIterator;
      for(pIterator = pItemArray, nIndex = 0; pIterator->uLabelType != 0; pIterator++, nIndex++) {
         if(MatchLabel(Item, *pIterator)) {
            // A label match has been found
            if(uFoundItemBitMap & (0x01ULL << nIndex)) {
               uReturn = QCBOR_ERR_DUPLICATE_LABEL;
               goto Done;
            }
            /* Also try to match its type */
            if(!MatchType(Item, *pIterator)) {
               uReturn = QCBOR_ERR_UNEXPECTED_TYPE;
               goto Done;
            }
            
            /* Successful match. Return the item. */
            *pIterator = Item;
            uFoundItemBitMap |= 0x01ULL << nIndex;
            if(puOffset) {
               *puOffset = uOffset;
            }
         } else {
            /* Call the callback on unmatched labels */
            /* It is tempting to do duplicate detection here, but that would
               require dynamic memory allocation because the number of labels
               that might be encountered is unbounded.
             */
            if(pfCallback) {
               uReturn = (*pfCallback)(pCBContext, &Item);
               if(uReturn != QCBOR_SUCCESS) {
                  goto Done;
               }
            }
         }
      }
         
      /* Consume the item whether matched or not. This
         does the work of traversing maps and array and
         everything in them. In this loop only the
         items at the current nesting level are examined
         to match the labels. */
      uReturn = ConsumeItem(pMe, &Item, &uNextNestLevel);
      if(uReturn) {
         goto Done;
      }
      
   } while (uNextNestLevel >= uMapNestLevel);

   
   uReturn = QCBOR_SUCCESS;

   const size_t uEndOffset = UsefulInputBuf_Tell(&(pMe->InBuf));
   // Cast OK because encoded CBOR is limited to UINT32_MAX
   pMe->uMapEndOffset = (uint32_t)uEndOffset;
   
   /* For all items not found, set the data type to QCBOR_TYPE_NONE */
   int        i;
   QCBORItem *pIterator;
   for(pIterator = pItemArray, i = 0; pIterator->uLabelType != 0; pIterator++, i++) {
      if(!(uFoundItemBitMap & (0x01ULL << i))) {
         pIterator->uDataType = QCBOR_TYPE_NONE;
      }
   }

Done:
   DecodeNesting_RestoreFromMapSearch(&(pMe->nesting), &SaveNesting);
    
   return uReturn;
}


/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetItemInMapN(QCBORDecodeContext *pMe,
                               int64_t             nLabel,
                               uint8_t             uQcborType,
                               QCBORItem          *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = uQcborType;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORError nReturn = MapSearch(pMe, OneItemSeach, NULL, NULL, NULL);
   if(nReturn) {
      pMe->uLastError = (uint8_t)nReturn;
   }

   if(OneItemSeach[0].uDataType == QCBOR_TYPE_NONE) {
      pMe->uLastError = QCBOR_ERR_NOT_FOUND;
   }

   *pItem = OneItemSeach[0];
}


/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetItemInMapSZ(QCBORDecodeContext *pMe,
                                const char         *szLabel,
                                uint8_t            uQcborType,
                                QCBORItem         *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = uQcborType;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORError nReturn = MapSearch(pMe, OneItemSeach, NULL, NULL, NULL);
   if(nReturn) {
      pMe->uLastError = (uint8_t)nReturn;
   }

   if(OneItemSeach[0].uDataType == QCBOR_TYPE_NONE) {
      pMe->uLastError = QCBOR_ERR_NOT_FOUND;
   }

   *pItem = OneItemSeach[0];
}


/**
 @param[in] TagSpec  Specification for matching tags.
 @param[in] uDataType  A QCBOR data type
 
 @retval QCBOR_SUCCESS   \c uDataType is allowed by @c TagSpec
 @retval QCBOR_ERR_UNEXPECTED_TYPE \c uDataType is not allowed by @c TagSpec
 
 The data type must be one of the QCBOR_TYPEs, not the IETF CBOR Registered tag value.
 */
static QCBORError CheckTagRequirement(const TagSpecification TagSpec, uint8_t uDataType)
{
   if(TagSpec.uTagRequirement == QCBOR_TAGSPEC_MATCH_TAG) {
      /* Must match the tag */
      if(uDataType == TagSpec.uTaggedType) {
         return QCBOR_SUCCESS;
      }
   } else {
      /* QCBOR_TAGSPEC_MATCH_TAG_CONTENT_TYPE or QCBOR_TAGSPEC_MATCH_EITHER */
      /* Must check all the possible types for the tag content */
      for(size_t i = 0; i < sizeof(TagSpec.uAllowedContentTypes); i++) {
         if(uDataType == TagSpec.uAllowedContentTypes[i]) {
            return QCBOR_SUCCESS;
         }
      }
      /* Didn't match any of the tag content types */
      /* Check the tag for the either case */
      if(TagSpec.uTagRequirement == QCBOR_TAGSPEC_MATCH_EITHER) {
         if(uDataType == TagSpec.uTaggedType) {
            return QCBOR_SUCCESS;
         }
      }
   }

   return QCBOR_ERR_UNEXPECTED_TYPE;
}


// Semi-private
// TODO: inline or collapse with QCBORDecode_GetTaggedStringInMapN?
void QCBORDecode_GetTaggedItemInMapN(QCBORDecodeContext *pMe,
                                     int64_t             nLabel,
                                     TagSpecification    TagSpec,
                                     QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)CheckTagRequirement(TagSpec, pItem->uDataType);
}

// Semi-private
void QCBORDecode_GetTaggedItemInMapSZ(QCBORDecodeContext *pMe,
                                     const char          *szLabel,
                                     TagSpecification    TagSpec,
                                     QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)CheckTagRequirement(TagSpec, pItem->uDataType);
}

// Semi-private
void QCBORDecode_GetTaggedStringInMapN(QCBORDecodeContext *pMe,
                                       int64_t             nLabel,
                                       TagSpecification    TagSpec,
                                       UsefulBufC          *pString)
{
   QCBORItem Item;
   QCBORDecode_GetTaggedItemInMapN(pMe, nLabel, TagSpec, &Item);
   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pString = Item.val.string;
   }
}

// Semi-private
void QCBORDecode_GetTaggedStringInMapSZ(QCBORDecodeContext *pMe,
                                        const char *        szLabel,
                                        TagSpecification    TagSpec,
                                        UsefulBufC          *pString)
{
   QCBORItem Item;
   QCBORDecode_GetTaggedItemInMapSZ(pMe, szLabel, TagSpec, &Item);
   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pString = Item.val.string;
   }
}

/*
Public function, see header qcbor/qcbor_decode.h file
*/
QCBORError QCBORDecode_GetItemsInMap(QCBORDecodeContext *pCtx, QCBORItem *pItemList)
{
   return MapSearch(pCtx, pItemList, NULL, NULL, NULL);
}

/*
Public function, see header qcbor/qcbor_decode.h file
*/
QCBORError QCBORDecode_GetItemsInMapWithCallback(QCBORDecodeContext *pCtx,
                                                 QCBORItem          *pItemList,
                                                 void               *pCallbackCtx,
                                                 QCBORItemCallback   pfCB)
{
   return MapSearch(pCtx, pItemList, NULL, pCallbackCtx, pfCB);
}


static void SearchAndEnter(QCBORDecodeContext *pMe, QCBORItem pSearch[])
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state; do nothing.
      return;
   }

   size_t uOffset;
   pMe->uLastError = (uint8_t)MapSearch(pMe, pSearch, &uOffset, NULL, NULL);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   /* Need to get the current pre-order nesting level and cursor to be
      at the first item in the map/array just entered.

    Also need to current map nesting level and start cursor to
    be at the right place.

    The UsefulInBuf offset could be anywhere, so no assumption is
    made about it.

    No assumption is made about the pre-order nesting level either.

    However the map mode nesting level is assumed to be one above
    the map level that is being entered.
    */
   /* Seek to the data item that is the map or array */
   UsefulInputBuf_Seek(&(pMe->InBuf), uOffset);
   pMe->nesting.pCurrent = pMe->nesting.pCurrentBounded; // TODO: part of DecodeNesting

   // TODO: check error?
   QCBORDecode_EnterBoundedMode(pMe, pSearch->uDataType);

   printdecode(pMe, "FinishEnter");
}


/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_EnterMapInMapN(QCBORDecodeContext *pMe, int64_t nLabel)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = QCBOR_TYPE_MAP;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE;

   /* The map to enter was found, now finish of entering it. */
   SearchAndEnter(pMe, OneItemSeach);
}


/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_EnterMapFromMapSZ(QCBORDecodeContext *pMe, const char  *szLabel)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = QCBOR_TYPE_MAP;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE;
   
   SearchAndEnter(pMe, OneItemSeach);
}

/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_EnterArrayFromMapN(QCBORDecodeContext *pMe, int64_t nLabel)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = QCBOR_TYPE_ARRAY;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE;

   SearchAndEnter(pMe, OneItemSeach);
}

/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_EnterArrayFromMapSZ(QCBORDecodeContext *pMe, const char  *szLabel)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = QCBOR_TYPE_ARRAY;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE;

   SearchAndEnter(pMe, OneItemSeach);
}



/* Next item must be map or this generates an error */
void QCBORDecode_EnterBoundedMode(QCBORDecodeContext *pMe, uint8_t uType)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state; do nothing.
      return;
   }

   /* Get the data item that is the map that is being searched */
   QCBORItem  Item;
   pMe->uLastError = (uint8_t)QCBORDecode_GetNext(pMe, &Item);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }
   if(Item.uDataType != uType) {
      pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
      return;
   }

   DecodeNesting_EnterBoundedMode(&(pMe->nesting), UsefulInputBuf_Tell(&(pMe->InBuf)));

   // TODO: restrict input to less than this or some other invalidation strategy.
   pMe->uMapEndOffset = 0xffffffff; // Invalidate the cached map end.

   printdecode(pMe, "EnterMapModeDone");
}


// Semi-private function
void QCBORDecode_ExitBoundedMode(QCBORDecodeContext *pMe, uint8_t uType)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state; do nothing.
      return;
   }

   printdecode(pMe, "start exit");

   QCBORError uErr = QCBOR_SUCCESS;

   if(!DecodeNesting_BoundedIsType(&(pMe->nesting), uType)){
      uErr = QCBOR_ERR_CLOSE_MISMATCH;
      goto Done;
   }

   /* Have to set the offset to the end of the map/array
    that is being exited. If there is no cached value,
    from previous map search, then do a dummy search. */
   if(pMe->uMapEndOffset == 0xffffffff) {
      QCBORItem Dummy;
      Dummy.uLabelType = QCBOR_TYPE_NONE;
      uErr = MapSearch(pMe, &Dummy, NULL, NULL, NULL);
      if(uErr != QCBOR_SUCCESS) {
         goto Done;
      }
   }
   UsefulInputBuf_Seek(&(pMe->InBuf), pMe->uMapEndOffset);
   pMe->uMapEndOffset = 0xffffffff; // Invalidate the cached map end.

   /* Before acending, mark this level as no longer in bound mode. */
   pMe->nesting.pCurrentBounded->bBoundedMode = false;

   // Always go up one level
   // Need error check to know level is bounded mode and not at top level
   pMe->nesting.pCurrent = pMe->nesting.pCurrentBounded - 1; // TODO error check
   
   uErr = Ascender(pMe);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }
   
   /* Also ascend to the next higest bounded mode level if
    there is one. */
   while(1) {
       pMe->nesting.pCurrentBounded--;
      if(DecodeNesting_InBoundedMode(&(pMe->nesting))) {
         break;
      }
      if(pMe->nesting.pCurrentBounded == &(pMe->nesting.pMapsAndArrays[0])) {
         pMe->nesting.pCurrentBounded = NULL;
         break;
      }
   }

Done:
   printdecode(pMe, "end exit");
   pMe->uLastError = (uint8_t)uErr;
}


void QCBORDecode_RewindMap(QCBORDecodeContext *pMe)
{
   // TODO: check for map mode; test this
   pMe->nesting.pCurrent->uCount = pMe->nesting.pCurrent->uSaveCount;
   UsefulInputBuf_Seek(&(pMe->InBuf), pMe->nesting.pCurrent->uOffset);
}



static QCBORError FarfWrappedBstr(QCBORDecodeContext *pMe, const QCBORItem *pItem, uint8_t uTagRequirement, UsefulBufC *pBstr)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state; do nothing.
      return pMe->uLastError;
   }

   QCBORError uError = QCBOR_SUCCESS;

   if(pItem->uDataType != QCBOR_TYPE_BYTE_STRING) {
      uError = QCBOR_ERR_UNEXPECTED_TYPE;
      goto Done;;
   }

   // TODO: check for the other wrapped CBOR tag
   const TagSpecification TagSpec = {uTagRequirement, QBCOR_TYPE_WRAPPED_CBOR, {QCBOR_TYPE_BYTE_STRING, 0,0,0,0,0}};

   uError = CheckTagRequirement(TagSpec, pItem->uDataType);
   if(uError != QCBOR_SUCCESS) {
      goto Done;
   }

   //if(pMe->nesting.pCurrent)
   pMe->nesting.pCurrent->uCount++; // Don't count the bstr yet

   if(pBstr) {
      *pBstr = pItem->val.string;
   }

   const size_t uPreviousLength = UsefulInputBuf_GetLength(&(pMe->InBuf));

   // Need to move UIB input cursor to the right place

   // Really this is a subtraction and an assignment; not much code
   // There is a range check in the seek.
   // The bstr was just consumed so the cursor is at the next item after it

   const size_t uEndOfBstr = UsefulInputBuf_Tell(&(pMe->InBuf));


   UsefulInputBuf_Seek(&(pMe->InBuf), uEndOfBstr - pItem->val.string.len);

   UsefulInputBuf_SetBufferLen(&(pMe->InBuf), uEndOfBstr);

   // TODO: comment on cast
   uError = DecodeNesting_Descend(&(pMe->nesting), QCBOR_TYPE_BYTE_STRING, UINT16_MAX, (uint32_t)uPreviousLength, (uint32_t)uEndOfBstr);
   pMe->nesting.pCurrent->bBoundedMode = true;
   pMe->nesting.pCurrentBounded = pMe->nesting.pCurrent;

Done:
   printdecode(pMe, "Entered Bstr");

   return uError;

}


void QCBORDecode_EnterBstrWrapped(QCBORDecodeContext *pMe, uint8_t uTagRequirement, UsefulBufC *pBstr)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state; do nothing.
      return;
   }

   /* Get the data item that is the map that is being searched */
   QCBORItem Item;
   pMe->uLastError = (uint8_t)QCBORDecode_GetNext(pMe, &Item);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)FarfWrappedBstr(pMe, &Item, uTagRequirement, pBstr);
}


void QCBORDecode_EnterBstrWrappedFromMapN(QCBORDecodeContext *pMe, uint8_t uTagRequirement, int64_t nLabel,  UsefulBufC *pBstr)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)FarfWrappedBstr(pMe, &Item, uTagRequirement, pBstr);
}


void QCBORDecode_EnterBstrWrappedFromMapSZ(QCBORDecodeContext *pMe, uint8_t uTagRequirement, const char *szLabel, UsefulBufC *pBstr)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)FarfWrappedBstr(pMe, &Item, uTagRequirement, pBstr);
}

void QCBORDecode_ExitBstrWrapped(QCBORDecodeContext *pMe)
{
   /* Reset the length of the Useful\InputBuf to what it was before
    the bstr wrapped CBOR was entered
    */
   UsefulInputBuf_SetBufferLen(&(pMe->InBuf), pMe->nesting.pCurrentBounded->uPreviousEndOffset);

   // Put the pre-order traversal cursor in the right place
   UsefulInputBuf_Seek(&(pMe->InBuf), pMe->nesting.pCurrentBounded->uEndOfBstr);

   // Invalidate the cached bounded mode end.
   pMe->uMapEndOffset = UINT32_MAX;


   // Always go up one level
   // Need error check to know level is bounded mode and not at top level
   pMe->nesting.pCurrent = pMe->nesting.pCurrentBounded - 1; // TODO error check

   QCBORError uErr = Ascender(pMe);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   /* Also ascend to the next highest bounded mode level if
    there is one. */
   while(1) {
       pMe->nesting.pCurrentBounded--;
      if(DecodeNesting_InBoundedMode(&(pMe->nesting))) {
         break;
      }
      if(pMe->nesting.pCurrentBounded == &(pMe->nesting.pMapsAndArrays[0])) {
         //pMe->nesting.pCurrentBounded = NULL;
         break;
      }
   }

   pMe->nesting.pCurrent = pMe->nesting.pCurrentBounded;

Done:
   // TODO: set last error here
   printdecode(pMe, "Exited Bstr");
}








static QCBORError InterpretBool(const QCBORItem *pItem, bool *pBool)
{
   switch(pItem->uDataType) {
      case QCBOR_TYPE_TRUE:
         *pBool = true;
         return QCBOR_SUCCESS;
         break;

      case QCBOR_TYPE_FALSE:
         *pBool = false;
         return QCBOR_SUCCESS;
         break;

      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
         break;
   }
}

/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetBool(QCBORDecodeContext *pMe, bool *pValue)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state, do nothing
      return;
   }

   QCBORError nError;
   QCBORItem  Item;

   nError = QCBORDecode_GetNext(pMe, &Item);
   if(nError != QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)nError;
      return;
   }
   pMe->uLastError = (uint8_t)InterpretBool(&Item, pValue);
}

/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetBoolInMapN(QCBORDecodeContext *pMe, int64_t nLabel, bool *pValue)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)InterpretBool(&Item, pValue);
}

/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetBoolInMapSZ(QCBORDecodeContext *pMe, const char *szLabel, bool *pValue)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)InterpretBool(&Item, pValue);
}



void QCBORDecode_GetTaggedStringInternal(QCBORDecodeContext *pMe, TagSpecification TagSpec, UsefulBufC *pBstr)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state, do nothing
      return;
   }

   QCBORError nError;
   QCBORItem  Item;

   nError = QCBORDecode_GetNext(pMe, &Item);
   if(nError != QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)nError;
      return;
   }

   pMe->uLastError = (uint8_t)CheckTagRequirement(TagSpec, Item.uDataType);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pBstr = Item.val.string;
   }
}




static QCBORError ConvertBigNum(uint8_t uTagRequirement, const QCBORItem *pItem, UsefulBufC *pValue, bool *pbIsNegative)
{
   *pbIsNegative = false;

   bool bMustBeTagged = true; // TODO: fix this --- they have to tell us if they are expecting positive or negative

   switch(pItem->uDataType) {
      case QCBOR_TYPE_BYTE_STRING:
         // TODO: check that there is no tag here?
         if(bMustBeTagged) {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         } else {
            *pValue = pItem->val.string;
            return QCBOR_SUCCESS;
         }
         break;

      case QCBOR_TYPE_POSBIGNUM:
         *pValue = pItem->val.string;
         return QCBOR_SUCCESS;
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         *pbIsNegative = true;
         *pValue = pItem->val.string;
         return QCBOR_SUCCESS;
         break;

      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
         break;
   }
}


/*
 @param[in] bMustBeTagged  If \c true, then the data item must be tagged as either
 a positive or negative bignum. If \c false, then it only must be a byte string and bIsNegative
 will always be false on the asumption that it is positive, but it can be interpretted as
 negative if the the sign is know from other context.
 @param[out] pValue   The bytes that make up the big num
 @param[out] pbIsNegative  \c true if tagged as a negative big num. \c false otherwise.

 if bMustBeTagged is false, then this will succeed if the data item is a plain byte string,
 a positive big num or a negative big num.

 */
void QCBORDecode_GetBignum(QCBORDecodeContext *pMe, uint8_t uTagRequirement, UsefulBufC *pValue, bool *pbIsNegative)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state, do nothing
      return;
   }

   QCBORItem  Item;
   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError != QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   pMe->uLastError = (uint8_t)ConvertBigNum(uTagRequirement, &Item, pValue, pbIsNegative);
}

/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetBignumInMapN(QCBORDecodeContext *pMe, int64_t nLabel, uint8_t uTagRequirement, UsefulBufC *pValue, bool *pbIsNegative)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)ConvertBigNum(uTagRequirement, &Item, pValue, pbIsNegative);
}

/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetBignumInMapSZ(QCBORDecodeContext *pMe, const char *szLabel, uint8_t uTagRequirement, UsefulBufC *pValue, bool *pbIsNegative)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)ConvertBigNum(uTagRequirement, &Item, pValue, pbIsNegative);
}



// Semi private
QCBORError FarfMIME(uint8_t uTagRequirement, const QCBORItem *pItem, UsefulBufC *pMessage, bool *pbIsNot7Bit)
{
   const TagSpecification TagSpecText = {uTagRequirement, QCBOR_TYPE_MIME, {QCBOR_TYPE_TEXT_STRING, 0,0,0,0,0}};
   const TagSpecification TagSpecBinary = {uTagRequirement, QCBOR_TYPE_BINARY_MIME, {QCBOR_TYPE_BYTE_STRING, 0,0,0,0,0}};
   
   QCBORError uReturn;
   
   if(CheckTagRequirement(TagSpecText, pItem->uDataType)) {
      *pMessage = pItem->val.string;
      if(pbIsNot7Bit != NULL) {
         *pbIsNot7Bit = false;
      }
      uReturn = QCBOR_SUCCESS;
   } else if(CheckTagRequirement(TagSpecBinary, pItem->uDataType)) {
      *pMessage = pItem->val.string;
      if(pbIsNot7Bit != NULL) {
         *pbIsNot7Bit = true;
      }
      uReturn = QCBOR_SUCCESS;

   } else {
      uReturn = QCBOR_ERR_UNEXPECTED_TYPE;
   }
   
   return uReturn;
}









typedef QCBORError (*fExponentiator)(uint64_t uMantissa, int64_t nExponent, uint64_t *puResult);


// The main exponentiator that works on only positive numbers
static QCBORError Exponentitate10(uint64_t uMantissa, int64_t nExponent, uint64_t *puResult)
{
   uint64_t uResult = uMantissa;

   if(uResult != 0) {
      /* This loop will run a maximum of 19 times because
       * UINT64_MAX < 10 ^^ 19. More than that will cause
       * exit with the overflow error
       */
      for(; nExponent > 0; nExponent--) {
         if(uResult > UINT64_MAX / 10) {
            return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW; // Error overflow
         }
         uResult = uResult * 10;
      }

      for(; nExponent < 0; nExponent++) {
         uResult = uResult / 10;
         if(uResult == 0) {
            return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW; // Underflow error
         }
      }
   }
   /* else, mantissa is zero so this returns zero */

   *puResult = uResult;

   return QCBOR_SUCCESS;
}


/* Convert a decimal fraction to an int64_t without using
 floating point or math libraries.  Most decimal fractions
 will not fit in an int64_t and this will error out with
 under or overflow
 */
static QCBORError Exponentitate2(uint64_t uMantissa, int64_t nExponent, uint64_t *puResult)
{
   uint64_t uResult;

   uResult = uMantissa;

   /* This loop will run a maximum of 64 times because
    * INT64_MAX < 2^31. More than that will cause
    * exist with the overflow error
    */
   while(nExponent > 0) {
      if(uResult > UINT64_MAX >> 1) {
         return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW; // Error overflow
      }
      uResult = uResult << 1;
      nExponent--;
   }

   while(nExponent < 0 ) {
      if(uResult == 0) {
         return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW; // Underflow error
      }
      uResult = uResult >> 1;
      nExponent++;
   }

   *puResult = uResult;

   return QCBOR_SUCCESS;
}

/*
 Compute value with signed mantissa and signed result. Works with exponent of 2 or 10 based on exponentiator.
 */
static inline QCBORError ExponentiateNN(int64_t nMantissa, int64_t nExponent, int64_t *pnResult, fExponentiator pfExp)
{
   uint64_t uResult;

   // Take the absolute value of the mantissa and convert to unsigned.
   // TODO: this should be possible in one intruction
   uint64_t uMantissa = nMantissa > 0 ? (uint64_t)nMantissa : (uint64_t)-nMantissa;

   // Do the exponentiation of the positive mantissa
   QCBORError uReturn = (*pfExp)(uMantissa, nExponent, &uResult);
   if(uReturn) {
      return uReturn;
   }


   /* (uint64_t)INT64_MAX+1 is used to represent the absolute value
    of INT64_MIN. This assumes two's compliment representation where
    INT64_MIN is one increment farther from 0 than INT64_MAX.
    Trying to write -INT64_MIN doesn't work to get this because the
    compiler tries to work with an int64_t which can't represent
    -INT64_MIN.
    */
   uint64_t uMax = nMantissa > 0 ? INT64_MAX : (uint64_t)INT64_MAX+1;

   // Error out if too large
   if(uResult > uMax) {
      return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
   }

   // Casts are safe because of checks above
   *pnResult = nMantissa > 0 ? (int64_t)uResult : -(int64_t)uResult;

   return QCBOR_SUCCESS;
}

/*
 Compute value with signed mantissa and unsigned result. Works with exponent of 2 or 10 based on exponentiator.
 */
static inline QCBORError ExponentitateNU(int64_t nMantissa, int64_t nExponent, uint64_t *puResult, fExponentiator pfExp)
{
   if(nMantissa < 0) {
      return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
   }

   // Cast to unsigned is OK because of check for negative
   // Cast to unsigned is OK because UINT64_MAX > INT64_MAX
   // Exponentiation is straight forward
   return (*pfExp)((uint64_t)nMantissa, nExponent, puResult);
}


#include <math.h>


static QCBORError ConvertBigNumToUnsigned(const UsefulBufC BigNum, uint64_t uMax, uint64_t *pResult)
{
   uint64_t uResult;

   uResult = 0;
   const uint8_t *pByte = BigNum.ptr;
   size_t uLen = BigNum.len;
   while(uLen--) {
      if(uResult > (uMax >> 8)) {
         return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
      }
      uResult = (uResult << 8) + *pByte++;
   }

   *pResult = uResult;
   return QCBOR_SUCCESS;
}

static inline QCBORError ConvertPositiveBigNumToUnsigned(const UsefulBufC BigNum, uint64_t *pResult)
{
   return ConvertBigNumToUnsigned(BigNum, UINT64_MAX, pResult);
}

static inline QCBORError ConvertPositiveBigNumToSigned(const UsefulBufC BigNum, int64_t *pResult)
{
   uint64_t uResult;
   QCBORError uError =  ConvertBigNumToUnsigned(BigNum, INT64_MAX, &uResult);
   if(uError) {
      return uError;
   }
   /* Cast is safe because ConvertBigNum is told to limit to INT64_MAX */
   *pResult = (int64_t)uResult;
   return QCBOR_SUCCESS;
}


static inline QCBORError ConvertNegativeBigNumToSigned(const UsefulBufC BigNum, int64_t *pResult)
{
   uint64_t uResult;
   /* negaative int furthest from zero is INT64_MIN
      which is expressed as -INT64_MAX-1. The value of
    a negative bignum is -n-1, one further from zero
    than the positive bignum */

   /* say INT64_MIN is -2; then INT64_MAX is 1.
    Then -n-1 <= INT64_MIN.
    Then -n -1 <= -INT64_MAX - 1
    THen n <= INT64_MAX. */
   QCBORError uError = ConvertBigNumToUnsigned(BigNum, INT64_MAX, &uResult);
   if(uError) {
      return uError;
   }
   /* Cast is safe because ConvertBigNum is told to limit to INT64_MAX */
   // TODO: this code is incorrect. See RFC 7049
   uResult++; // this is the -1 in -n-1
   *pResult = -(int64_t)uResult;
   return QCBOR_SUCCESS;
}

#include "fenv.h"


/*
Convert a integers and floats to an int64_t.

\param[in] uOptions  Bit mask list of conversion options.

\retval QCBOR_ERR_CONVERSION_NOT_REQUESTED  Conversion, possible, but not requested in uOptions.

\retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted

\retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW Conversion result is too large or too small.

*/
static QCBORError ConvertInt64(const QCBORItem *pItem, uint32_t uOptions, int64_t *pnValue)
{
   switch(pItem->uDataType) {
      // TODO: float when ifdefs are set
      case QCBOR_TYPE_DOUBLE:
         if(uOptions & QCBOR_CONVERT_TYPE_FLOAT) {
            // TODO: what about under/overflow here?
            // Invokes the floating-point HW and/or compiler-added libraries
            feclearexcept(FE_ALL_EXCEPT);
            *pnValue = llround(pItem->val.dfnum);
            if(fetestexcept(FE_INVALID)) {
               // TODO: better error code
               return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
            }
         } else {
            return  QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_INT64:
         if(uOptions & QCBOR_CONVERT_TYPE_INT64) {
            *pnValue = pItem->val.int64;
         } else {
            return  QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_UINT64:
         if(uOptions & QCBOR_CONVERT_TYPE_UINT64) {
            if(pItem->val.uint64 < INT64_MAX) {
               *pnValue = pItem->val.int64;
            } else {
               return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
            }
         } else {
            return  QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      default:
         return  QCBOR_ERR_UNEXPECTED_TYPE;
   }
   return QCBOR_SUCCESS;
}


void QCBORDecode_GetInt64ConvertInternal(QCBORDecodeContext *pMe,
                                         uint32_t            uOptions,
                                         int64_t            *pnValue,
                                         QCBORItem          *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   if(pItem) {
      *pItem = Item;
   }

   pMe->uLastError = (uint8_t)ConvertInt64(&Item, uOptions, pnValue);
}


void QCBORDecode_GetInt64ConvertInternalInMapN(QCBORDecodeContext *pMe,
                                               int64_t             nLabel,
                                               uint32_t            uOptions,
                                               int64_t            *pnValue,
                                               QCBORItem          *pItem)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)ConvertInt64(&Item, uOptions, pnValue);
}


void QCBORDecode_GetInt64ConvertInternalInMapSZ(QCBORDecodeContext *pMe,
                                               const char *         szLabel,
                                               uint32_t             uOptions,
                                               int64_t             *pnValue,
                                               QCBORItem           *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)ConvertInt64(&Item, uOptions, pnValue);
}



/*
 Convert a large variety of integer types to an int64_t.

 \param[in] uOptions  Bit mask list of conversion options.

 \retval QCBOR_ERR_CONVERSION_NOT_REQUESTED  Conversion, possible, but not requested in uOptions.

 \retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted

 \retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW Conversion result is too large or too small.

 */
static QCBORError Int64ConvertAll(const QCBORItem *pItem, uint32_t uOptions, int64_t *pnValue)
{
   QCBORError uErr;

   switch(pItem->uDataType) {

      case QCBOR_TYPE_POSBIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return ConvertPositiveBigNumToSigned(pItem->val.bigNum, pnValue);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

         case QCBOR_TYPE_NEGBIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return ConvertNegativeBigNumToSigned(pItem->val.bigNum, pnValue);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

#ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return ExponentiateNN(pItem->val.expAndMantissa.Mantissa.nInt,
                                                      pItem->val.expAndMantissa.nExponent,
                                                      pnValue,
                                                      &Exponentitate10);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

         case QCBOR_TYPE_BIGFLOAT:
         if(uOptions & QCBOR_CONVERT_TYPE_BIGFLOAT) {
            return ExponentiateNN(pItem->val.expAndMantissa.Mantissa.nInt,
                                                      pItem->val.expAndMantissa.nExponent,
                                                      pnValue,
                                                      Exponentitate2);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t nMantissa;
            uErr = ConvertPositiveBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  Exponentitate10);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t nMantissa;
            uErr = ConvertNegativeBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  Exponentitate10);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t nMantissa;
            uErr = ConvertPositiveBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  Exponentitate2);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t nMantissa;
            uErr = ConvertNegativeBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  Exponentitate2);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
#endif
   }
}


/*
 Public function, see header qcbor/qcbor_decode.h file
 */
void QCBORDecode_GetInt64ConvertAll(QCBORDecodeContext *pMe, uint32_t uOptions, int64_t *pnValue)
{
   QCBORItem Item;

   QCBORDecode_GetInt64ConvertInternal(pMe, uOptions, pnValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)Int64ConvertAll(&Item, uOptions, pnValue);
}


/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetInt64ConvertAllInMapN(QCBORDecodeContext *pMe, int64_t nLabel, uint32_t uOptions, int64_t *pnValue)
{
   QCBORItem Item;

   QCBORDecode_GetInt64ConvertInternalInMapN(pMe, nLabel, uOptions, pnValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)Int64ConvertAll(&Item, uOptions, pnValue);
}


/*
Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetInt64ConvertAllInMapSZ(QCBORDecodeContext *pMe, const char *szLabel, uint32_t uOptions, int64_t *pnValue)
{
   QCBORItem Item;
   QCBORDecode_GetInt64ConvertInternalInMapSZ(pMe, szLabel, uOptions, pnValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)Int64ConvertAll(&Item, uOptions, pnValue);
}


static QCBORError ConvertUint64(const QCBORItem *pItem, uint32_t uOptions, uint64_t *puValue)
{
   switch(pItem->uDataType) {
           // TODO: type flaot
        case QCBOR_TYPE_DOUBLE:
           if(uOptions & QCBOR_CONVERT_TYPE_FLOAT) {
              feclearexcept(FE_ALL_EXCEPT);
              double dRounded = round(pItem->val.dfnum);
              // TODO: over/underflow
              if(fetestexcept(FE_INVALID)) {
                 // TODO: better error code
                 return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
              } else if(isnan(dRounded)) {
                 // TODO: better error code
                 return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
              } else if(dRounded >= 0) {
                 *puValue = (uint64_t)dRounded;
              } else {
                 return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
              }
           } else {
              return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
           }
           break;

        case QCBOR_TYPE_INT64:
           if(uOptions & QCBOR_CONVERT_TYPE_INT64) {
              if(pItem->val.int64 >= 0) {
                 *puValue = (uint64_t)pItem->val.int64;
              } else {
                 return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
              }
           } else {
              return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
           }
           break;

        case QCBOR_TYPE_UINT64:
           if(uOptions & QCBOR_CONVERT_TYPE_UINT64) {
              *puValue =  pItem->val.uint64;
           } else {
              return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
           }
           break;

        default:
           return QCBOR_ERR_UNEXPECTED_TYPE;
     }
   return QCBOR_SUCCESS;
}


void QCBORDecode_GetUInt64ConvertInternal(QCBORDecodeContext *pMe,
                                          uint32_t uOptions,
                                          uint64_t *puValue,
                                          QCBORItem *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;

   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   if(pItem) {
      *pItem = Item;
   }

   pMe->uLastError = (uint8_t)ConvertUint64(&Item, uOptions, puValue);
}


void QCBORDecode_GetInt8ConvertInternal(QCBORDecodeContext *pMe, uint32_t uOptions, int8_t *pnValue, QCBORItem *pItem)
{
   int64_t uValue;
   QCBORDecode_GetInt64ConvertInternal(pMe, uOptions, &uValue, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   if(QCBOR_Int64ToInt8(uValue, pnValue)) {
      pMe->uLastError = QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
   }
}

void QCBORDecode_GetInt8ConvertInternalInMapN(QCBORDecodeContext *pMe, int64_t nLabel, uint32_t uOptions, int8_t *pnValue, QCBORItem *pItem)
{
   int64_t uValue;
   QCBORDecode_GetInt64ConvertInternalInMapN(pMe, nLabel, uOptions, &uValue, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   if(QCBOR_Int64ToInt8(uValue, pnValue)) {
      pMe->uLastError = QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
   }
}

void QCBORDecode_GetInt8ConvertInternalInMapSZ(QCBORDecodeContext *pMe, const char *szLabel, uint32_t uOptions, int8_t *pnValue, QCBORItem *pItem)
{
   int64_t uValue;
   QCBORDecode_GetInt64ConvertInternalInMapSZ(pMe, szLabel, uOptions, &uValue, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   if(QCBOR_Int64ToInt8(uValue, pnValue)) {
      pMe->uLastError = QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
   }
}




void QCBORDecode_GetUint64ConvertInternalInMapN(QCBORDecodeContext *pMe,
                                               int64_t             nLabel,
                                               uint32_t            uOptions,
                                               uint64_t            *puValue,
                                               QCBORItem          *pItem)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)ConvertUint64(&Item, uOptions, puValue);
}


void QCBORDecode_GetUint64ConvertInternalInMapSZ(QCBORDecodeContext *pMe,
                                               const char *         szLabel,
                                               uint32_t             uOptions,
                                               uint64_t             *puValue,
                                               QCBORItem           *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)ConvertUint64(&Item, uOptions, puValue);
}

/*
 Public function, see header qcbor/qcbor_decode.h file
*/
static QCBORError Uint64ConvertAll(const QCBORItem *pItem, uint32_t uOptions, uint64_t *puValue)
{
   QCBORError uErr;

   switch(pItem->uDataType) {

      case QCBOR_TYPE_POSBIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return ConvertPositiveBigNumToUnsigned(pItem->val.bigNum, puValue);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

#ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA

      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return ExponentitateNU(pItem->val.expAndMantissa.Mantissa.nInt,
                                                       pItem->val.expAndMantissa.nExponent,
                                                       puValue,
                                                       Exponentitate10);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT:
         if(uOptions & QCBOR_CONVERT_TYPE_BIGFLOAT) {
            return ExponentitateNU(pItem->val.expAndMantissa.Mantissa.nInt,
                                   pItem->val.expAndMantissa.nExponent,
                                   puValue,
                                   Exponentitate2);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            // TODO: Would be better to convert to unsigned
            int64_t nMantissa;
            uErr = ConvertPositiveBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr != QCBOR_SUCCESS) {
               return uErr;
            }
            return ExponentitateNU(nMantissa,
                                   pItem->val.expAndMantissa.nExponent,
                                   puValue,
                                   Exponentitate10);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            // TODO: Would be better to convert to unsigned
            int64_t nMantissa;
            uErr =  ConvertPositiveBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr != QCBOR_SUCCESS) {
               return uErr;
            }
            return ExponentitateNU(nMantissa,
                                   pItem->val.expAndMantissa.nExponent,
                                   puValue,
                                   Exponentitate2);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;
#endif
      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }
}

/*
  Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetUInt64ConvertAll(QCBORDecodeContext *pMe, uint32_t uOptions, uint64_t *puValue)
{
   QCBORItem Item;

   QCBORDecode_GetUInt64ConvertInternal(pMe, uOptions, puValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)Uint64ConvertAll(&Item, uOptions, puValue);
}


/*
  Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetUint64ConvertAllInMapN(QCBORDecodeContext *pMe, int64_t nLabel, uint32_t uOptions, uint64_t *puValue)
{
   QCBORItem Item;

   QCBORDecode_GetUint64ConvertInternalInMapN(pMe, nLabel, uOptions, puValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)Uint64ConvertAll(&Item, uOptions, puValue);
}


/*
  Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetUint64ConvertAllInMapSZ(QCBORDecodeContext *pMe, const char *szLabel, uint32_t uOptions, uint64_t *puValue)
{
   QCBORItem Item;
   QCBORDecode_GetUint64ConvertInternalInMapSZ(pMe, szLabel, uOptions, puValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)Uint64ConvertAll(&Item, uOptions, puValue);
}


static QCBORError ConvertDouble(const QCBORItem *pItem, uint32_t uOptions, double *pdValue)
{
   switch(pItem->uDataType) {
      // TODO: float when ifdefs are set
      case QCBOR_TYPE_DOUBLE:
         if(uOptions & QCBOR_CONVERT_TYPE_FLOAT) {
            if(uOptions & QCBOR_CONVERT_TYPE_FLOAT) {
               *pdValue = pItem->val.dfnum;
            } else {
               return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
            }
         }
         break;

      case QCBOR_TYPE_INT64:
         if(uOptions & QCBOR_CONVERT_TYPE_INT64) {
            // TODO: how does this work?
            *pdValue = (double)pItem->val.int64;

         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_UINT64:
         if(uOptions & QCBOR_CONVERT_TYPE_UINT64) {
             *pdValue = (double)pItem->val.uint64;
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }

   return QCBOR_SUCCESS;
}



void QCBORDecode_GetDoubleConvertInternal(QCBORDecodeContext *pMe,
                                          uint32_t            uOptions,
                                          double             *pdValue,
                                          QCBORItem          *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;

   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   if(pItem) {
      *pItem = Item;
   }

   pMe->uLastError = (uint8_t)ConvertDouble(&Item, uOptions, pdValue);
}


void QCBORDecode_GetDoubleConvertInternalInMapN(QCBORDecodeContext *pMe,
                                               int64_t             nLabel,
                                               uint32_t            uOptions,
                                               double             *pdValue,
                                               QCBORItem          *pItem)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)ConvertDouble(&Item, uOptions, pdValue);
}

void QCBORDecode_GetDoubleConvertInternalInMapSZ(QCBORDecodeContext *pMe,
                                               const char *          szLabel,
                                               uint32_t              uOptions,
                                               double               *pdValue,
                                               QCBORItem            *pItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)ConvertDouble(&Item, uOptions, pdValue);
}



static double ConvertBigNumToDouble(const UsefulBufC BigNum)
{
   double dResult;

   dResult = 0.0;
   const uint8_t *pByte = BigNum.ptr;
   size_t uLen = BigNum.len;
   /* This will overflow and become the float value INFINITY if the number
    is too large to fit. No error will be logged.
    TODO: should an error be logged? */
   while(uLen--) {
      dResult = (dResult * 256.0) + (double)*pByte++;
   }

   return dResult;
}

static QCBORError DoubleConvertAll(const QCBORItem *pItem, uint32_t uOptions, double *pdValue)
{
   /*
   https://docs.oracle.com/cd/E19957-01/806-3568/ncg_goldberg.html

   */
   switch(pItem->uDataType) {
         // TODO: type float
      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            // TODO: rounding and overflow errors
            *pdValue = (double)pItem->val.expAndMantissa.Mantissa.nInt *
                        pow(10.0, (double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT:
         if(uOptions & QCBOR_CONVERT_TYPE_BIGFLOAT ) {
           *pdValue = (double)pItem->val.expAndMantissa.Mantissa.nInt *
                                exp2((double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_POSBIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_BIG_NUM) {
            *pdValue = ConvertBigNumToDouble(pItem->val.bigNum);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_BIG_NUM) {
            *pdValue = -1-ConvertBigNumToDouble(pItem->val.bigNum);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            double dMantissa = ConvertBigNumToDouble(pItem->val.expAndMantissa.Mantissa.bigNum);
            *pdValue = dMantissa * pow(10, (double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
        if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
         double dMantissa = -ConvertBigNumToDouble(pItem->val.expAndMantissa.Mantissa.bigNum);
         *pdValue = dMantissa * pow(10, (double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
        if(uOptions & QCBOR_CONVERT_TYPE_BIGFLOAT) {
         double dMantissa = ConvertBigNumToDouble(pItem->val.expAndMantissa.Mantissa.bigNum);
         *pdValue = dMantissa * exp2((double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
        if(uOptions & QCBOR_CONVERT_TYPE_BIGFLOAT) {
         double dMantissa = -1-ConvertBigNumToDouble(pItem->val.expAndMantissa.Mantissa.bigNum);
         *pdValue = dMantissa * exp2((double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }

   return QCBOR_SUCCESS;
}


/*
   Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetDoubleConvertAll(QCBORDecodeContext *pMe, uint32_t uOptions, double *pdValue)
{

   QCBORItem Item;

   QCBORDecode_GetDoubleConvertInternal(pMe, uOptions, pdValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)DoubleConvertAll(&Item, uOptions, pdValue);
}


/*
   Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetDoubleConvertAllInMapN(QCBORDecodeContext *pMe, int64_t nLabel, uint32_t uOptions, double *pdValue)
{
   QCBORItem Item;

   QCBORDecode_GetDoubleConvertInternalInMapN(pMe, nLabel, uOptions, pdValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)DoubleConvertAll(&Item, uOptions, pdValue);
}


/*
   Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetDoubleConvertAllInMapSZ(QCBORDecodeContext *pMe, const char *szLabel, uint32_t uOptions, double *pdValue)
{
   QCBORItem Item;
   QCBORDecode_GetDoubleConvertInternalInMapSZ(pMe, szLabel, uOptions, pdValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)DoubleConvertAll(&Item, uOptions, pdValue);
}


void FarfDecimalFraction(QCBORDecodeContext *pMe,
                         uint8_t             uTagRequirement,
                         QCBORItem          *pItem,
                         int64_t             *pnMantissa,
                         int64_t             *pnExponent)
{
   QCBORError uErr;
   
   if(pItem->uDataType == QCBOR_TYPE_ARRAY) {
      if(uTagRequirement == QCBOR_TAGSPEC_MATCH_TAG_CONTENT_TYPE) {
         pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
         return;
      }
      uErr = QCBORDecode_MantissaAndExponent(pMe, pItem);
       if(uErr != QCBOR_SUCCESS) {
          pMe->uLastError = (uint8_t)uErr;
          return;
       }
    }
   
   if(uTagRequirement == QCBOR_TAGSPEC_MATCH_TAG_CONTENT_TYPE) {
      pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
      return;
   }
    
    switch (pItem->uDataType) {
          
       case QCBOR_TYPE_DECIMAL_FRACTION:
          *pnMantissa = pItem->val.expAndMantissa.Mantissa.nInt;
          *pnExponent = pItem->val.expAndMantissa.nExponent;
          break;
          
       case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
          *pnExponent = pItem->val.expAndMantissa.nExponent;
          
          uErr = ConvertPositiveBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, pnMantissa);
          if(uErr != QCBOR_SUCCESS) {
             pMe->uLastError = (uint8_t)uErr;
          }
          break;

       case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
          *pnExponent = pItem->val.expAndMantissa.nExponent;
          
          uErr = ConvertNegativeBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, pnMantissa);
          if(uErr != QCBOR_SUCCESS) {
             pMe->uLastError = (uint8_t)uErr;
          }
          break;
          
       default:
          pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
    }
}

void QCBORDecode_GetDecimalFractionN(QCBORDecodeContext *pMe,
                                     uint8_t             uTagRequirement,
                                     int64_t             nLabel,
                                     int64_t             *pnMantissa,
                                     int64_t             *pnExponent)
{
   QCBORItem Item;
   
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);
   FarfDecimalFraction(pMe, uTagRequirement, &Item, pnMantissa, pnExponent);
}



void QCBORDecode_GetDecimalFractionSZ(QCBORDecodeContext *pMe,
                                     uint8_t             uTagRequirement,
                                     const char         *szLabel,
                                     int64_t             *pnMantissa,
                                     int64_t             *pnExponent)
{
   QCBORItem Item;
   
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);
   
   FarfDecimalFraction(pMe, uTagRequirement, &Item, pnMantissa, pnExponent);
}


UsefulBufC ConvertIntToBigNum(uint64_t uInt, UsefulBuf Buffer)
{
   while(uInt & 0xff0000000000UL) {
      uInt = uInt << 8;
   };
   
   UsefulOutBuf UOB;
   
   UsefulOutBuf_Init(&UOB, Buffer);
   
   while(uInt) {
      UsefulOutBuf_AppendByte(&UOB, (uint8_t)((uInt & 0xff0000000000UL) >> 56));
      uInt = uInt << 8;
   }
   
   return UsefulOutBuf_OutUBuf(&UOB);
}


void QCBORDecode_GetDecimalFractionBigN(QCBORDecodeContext *pMe,
                                        uint8_t             uTagRequirement,
                                        int64_t             nLabel,
                                        UsefulBuf           pBufferForMantissa,
                                        UsefulBufC         *pMantissa,
                                        bool               *pbIsNegative,
                                        int64_t            *pnExponent)
{
   QCBORItem Item;
   QCBORError uErr;
   
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);
   
   if(Item.uDataType == QCBOR_TYPE_ARRAY) {
      uErr = QCBORDecode_MantissaAndExponent(pMe, &Item);
      if(uErr != QCBOR_SUCCESS) {
         pMe->uLastError = (uint8_t)uErr;
         return;
      }
   }
   
   uint64_t uMantissa;
   
   switch (Item.uDataType) {
         
      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(Item.val.expAndMantissa.Mantissa.nInt >= 0) {
            uMantissa = (uint64_t)Item.val.expAndMantissa.Mantissa.nInt;
            *pbIsNegative = false;
         } else {
            uMantissa = (uint64_t)-Item.val.expAndMantissa.Mantissa.nInt;
            *pbIsNegative = true;
         }
         *pMantissa = ConvertIntToBigNum(uMantissa, pBufferForMantissa);
         *pnExponent = Item.val.expAndMantissa.nExponent;
         break;
         
      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         *pnExponent = Item.val.expAndMantissa.nExponent;
         *pMantissa = Item.val.expAndMantissa.Mantissa.bigNum;
         *pbIsNegative = false;
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
         *pnExponent = Item.val.expAndMantissa.nExponent;
         *pMantissa = Item.val.expAndMantissa.Mantissa.bigNum;
         *pbIsNegative = true;
         break;
         
      default:
         pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
   }
}
