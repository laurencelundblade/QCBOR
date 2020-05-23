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
   if(pNesting->pCurrentMap && pNesting->pCurrentMap->uMapMode) {
      if(pNesting->pCurrentMap->uCount == 0) {
         // TODO: won't work for indefinite length
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
}

inline static int
DecodeNesting_InMapMode(const QCBORDecodeNesting *pNesting)
{
   return (bool)pNesting->pCurrentMap->uMapMode;
}

inline static uint8_t
DecodeNesting_GetLevel(QCBORDecodeNesting *pNesting)
{
   // Check in DecodeNesting_Descend and never having
   // QCBOR_MAX_ARRAY_NESTING > 255 gaurantees cast is safe
   return (uint8_t)(pNesting->pCurrent - &(pNesting->pMapsAndArrays[0]));
}

inline static uint8_t
DecodeNesting_GetMapModeLevel(QCBORDecodeNesting *pNesting)
{
   // Check in DecodeNesting_Descend and never having
   // QCBOR_MAX_ARRAY_NESTING > 255 gaurantees cast is safe
   return (uint8_t)(pNesting->pCurrentMap - &(pNesting->pMapsAndArrays[0]));
}

inline static int
DecodeNesting_TypeIsMap(const QCBORDecodeNesting *pNesting)
{
   if(DecodeNesting_IsAtTop(pNesting)) {
      return 0;
   }

   return CBOR_MAJOR_TYPE_MAP == pNesting->pCurrent->uMajorType;
}

// Process a break. This will either ascend the nesting or error out
inline static QCBORError
DecodeNesting_BreakAscend(QCBORDecodeNesting *pNesting)
{
   // breaks must always occur when there is nesting
   if(DecodeNesting_IsAtTop(pNesting)) {
      return QCBOR_ERR_BAD_BREAK;
   }

   // breaks can only occur when the map/array is indefinite length
   if(!DecodeNesting_IsIndefiniteLength(pNesting)) {
      return QCBOR_ERR_BAD_BREAK;
   }

   // if all OK, the break reduces the level of nesting
   pNesting->pCurrent--;

   return QCBOR_SUCCESS;
}

// Called on every single item except breaks including decode of a map/array
/* Decrements the map/array counter if possible. If decrement
 closed out a map or array, then level up in nesting and decrement
 again, until, the top is reached or the end of a map mode is reached
 */
inline static void
DecodeNesting_DecrementCount(QCBORDecodeNesting *pNesting)
{
   while(!DecodeNesting_IsAtTop(pNesting)) {
      // Not at the top level, so there is decrementing to be done.

      if(!DecodeNesting_IsIndefiniteLength(pNesting)) {
         // Decrement the current nesting level if it is not indefinite.
         pNesting->pCurrent->uCount--;
      }

      if(pNesting->pCurrent->uCount != 0) {
         // Did not close out an array or map, so nothing further
         break;
      }
      
      if(pNesting->pCurrent->uMapMode) {
         // In map mode the level-up must be done explicitly
         break;
      }

      // Closed out an array or map so level up
      pNesting->pCurrent--;
      /*if(pNesting->pCurrent->uMapMode) {
         // Bring the current map level along if new level is a map
         // TODO: must search up until a mapmode level is found.
         pNesting->pCurrentMap = pNesting->pCurrent;
      } */

      // Continue with loop to see if closing out this doesn't close out more
   }
}

inline static void
DecodeNesting_EnterMapMode(QCBORDecodeNesting *pNesting, size_t uOffset)
{
   pNesting->pCurrentMap = pNesting->pCurrent;
   pNesting->pCurrentMap->uMapMode = 1;
   // Cast to uint32_t is safe because QCBOR onl works on data < UINT32_MAX
   pNesting->pCurrentMap->uOffset  = (uint32_t)uOffset;
}

inline static void
DecodeNesting_Exit(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrentMap->uMapMode = 0;
   pNesting->pCurrent = pNesting->pCurrentMap - 1; // TODO error check
   
   DecodeNesting_DecrementCount(pNesting);

   while(1) {
      pNesting->pCurrentMap--;
      if(pNesting->pCurrentMap->uMapMode) {
         break;
      }
      if(pNesting->pCurrentMap == &(pNesting->pMapsAndArrays[0])) {
         break;
      }
   }
}

// Called on every map/array
inline static QCBORError
DecodeNesting_Descend(QCBORDecodeNesting *pNesting, QCBORItem *pItem)
{
   QCBORError nReturn = QCBOR_SUCCESS;

   if(pItem->val.uCount == 0) {
      // Nothing to do for empty definite lenth arrays. They are just are
      // effectively the same as an item that is not a map or array
      goto Done;
      // Empty indefinite length maps and arrays are handled elsewhere
   }

   // Error out if arrays is too long to handle
   if(pItem->val.uCount != UINT16_MAX && pItem->val.uCount > QCBOR_MAX_ITEMS_IN_ARRAY) {
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

   // Record a few details for this nesting level
   pNesting->pCurrent->uMajorType = pItem->uDataType;
   pNesting->pCurrent->uCount     = pItem->val.uCount;
   pNesting->pCurrent->uSaveCount = pItem->val.uCount;
   pNesting->pCurrent->uMapMode   = 0;

Done:
   return nReturn;;
}

inline static void
DecodeNesting_Init(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent = &(pNesting->pMapsAndArrays[0]);
}


static void DecodeNesting_PrepareForMapSearch(QCBORDecodeNesting *pNesting, QCBORDecodeNesting *pSave)
{
   *pSave = *pNesting;
   pNesting->pCurrent = pNesting->pCurrentMap;

   if(pNesting->pCurrent->uCount != UINT16_MAX) {
      pNesting->pCurrent->uCount = pNesting->pCurrent->uSaveCount;
   }
}

static void DecodeNesting_RestoreFromMapSearch(QCBORDecodeNesting *pNesting, QCBORDecodeNesting *pSave)
{
   *pNesting = *pSave;
}



/*
 This list of built-in tags. Only add tags here that are
 clearly established and useful. Once a tag is added here
 it can't be taken out as that would break backwards compatibility.
 There are only 48 slots available forever.
 */
static const uint16_t spBuiltInTagMap[] = {
   CBOR_TAG_DATE_STRING, // See TAG_MAPPER_FIRST_SIX
   CBOR_TAG_DATE_EPOCH, // See TAG_MAPPER_FIRST_SIX
   CBOR_TAG_POS_BIGNUM, // See TAG_MAPPER_FIRST_SIX
   CBOR_TAG_NEG_BIGNUM, // See TAG_MAPPER_FIRST_SIX
   CBOR_TAG_DECIMAL_FRACTION, // See TAG_MAPPER_FIRST_SIX
   CBOR_TAG_BIGFLOAT, // See TAG_MAPPER_FIRST_SIX
   CBOR_TAG_COSE_ENCRYPTO,
   CBOR_TAG_COSE_MAC0,
   CBOR_TAG_COSE_SIGN1,
   CBOR_TAG_ENC_AS_B64URL,
   CBOR_TAG_ENC_AS_B64,
   CBOR_TAG_ENC_AS_B16,
   CBOR_TAG_CBOR,
   CBOR_TAG_URI,
   CBOR_TAG_B64URL,
   CBOR_TAG_B64,
   CBOR_TAG_REGEX,
   CBOR_TAG_MIME,
   CBOR_TAG_BIN_UUID,
   CBOR_TAG_CWT,
   CBOR_TAG_ENCRYPT,
   CBOR_TAG_MAC,
   CBOR_TAG_SIGN,
   CBOR_TAG_GEO_COORD,
   CBOR_TAG_CBOR_MAGIC
};

// This is used in a bit of cleverness in GetNext_TaggedItem() to
// keep code size down and switch for the internal processing of
// these types. This will break if the first six items in
// spBuiltInTagMap don't have values 0,1,2,3,4,5. That is the
// mapping is 0 to 0, 1 to 1, 2 to 2 and 3 to 3....
#define QCBOR_TAGFLAG_DATE_STRING      (0x01LL << CBOR_TAG_DATE_STRING)
#define QCBOR_TAGFLAG_DATE_EPOCH       (0x01LL << CBOR_TAG_DATE_EPOCH)
#define QCBOR_TAGFLAG_POS_BIGNUM       (0x01LL << CBOR_TAG_POS_BIGNUM)
#define QCBOR_TAGFLAG_NEG_BIGNUM       (0x01LL << CBOR_TAG_NEG_BIGNUM)
#define QCBOR_TAGFLAG_DECIMAL_FRACTION (0x01LL << CBOR_TAG_DECIMAL_FRACTION)
#define QCBOR_TAGFLAG_BIGFLOAT         (0x01LL << CBOR_TAG_BIGFLOAT)

#define TAG_MAPPER_FIRST_SIX (QCBOR_TAGFLAG_DATE_STRING       |\
                               QCBOR_TAGFLAG_DATE_EPOCH       |\
                               QCBOR_TAGFLAG_POS_BIGNUM       |\
                               QCBOR_TAGFLAG_NEG_BIGNUM       |\
                               QCBOR_TAGFLAG_DECIMAL_FRACTION |\
                               QCBOR_TAGFLAG_BIGFLOAT)

#define TAG_MAPPER_FIRST_FOUR (QCBOR_TAGFLAG_DATE_STRING      |\
                               QCBOR_TAGFLAG_DATE_EPOCH       |\
                               QCBOR_TAGFLAG_POS_BIGNUM       |\
                               QCBOR_TAGFLAG_NEG_BIGNUM)

#define TAG_MAPPER_TOTAL_TAG_BITS 64 // Number of bits in a uint64_t
#define TAG_MAPPER_CUSTOM_TAGS_BASE_INDEX (TAG_MAPPER_TOTAL_TAG_BITS - QCBOR_MAX_CUSTOM_TAGS) // 48
#define TAG_MAPPER_MAX_SIZE_BUILT_IN_TAGS (TAG_MAPPER_TOTAL_TAG_BITS - QCBOR_MAX_CUSTOM_TAGS ) // 48

static inline int TagMapper_LookupBuiltIn(uint64_t uTag)
{
   if(sizeof(spBuiltInTagMap)/sizeof(uint16_t) > TAG_MAPPER_MAX_SIZE_BUILT_IN_TAGS) {
      /*
       This is a cross-check to make sure the above array doesn't
       accidentally get made too big.  In normal conditions the above
       test should optimize out as all the values are known at compile
       time.
       */
      return -1;
   }

   if(uTag > UINT16_MAX) {
      // This tag map works only on 16-bit tags
      return -1;
   }

   for(int nTagBitIndex = 0; nTagBitIndex < (int)(sizeof(spBuiltInTagMap)/sizeof(uint16_t)); nTagBitIndex++) {
      if(spBuiltInTagMap[nTagBitIndex] == uTag) {
         return nTagBitIndex;
      }
   }
   return -1; // Indicates no match
}

static inline int TagMapper_LookupCallerConfigured(const QCBORTagListIn *pCallerConfiguredTagMap, uint64_t uTag)
{
   for(int nTagBitIndex = 0; nTagBitIndex < pCallerConfiguredTagMap->uNumTags; nTagBitIndex++) {
      if(pCallerConfiguredTagMap->puTags[nTagBitIndex] == uTag) {
         return nTagBitIndex + TAG_MAPPER_CUSTOM_TAGS_BASE_INDEX;
      }
   }

   return -1; // Indicates no match
}

/*
  Find the tag bit index for a given tag value, or error out

 This and the above functions could probably be optimized and made
 clearer and neater.
 */
static QCBORError
TagMapper_Lookup(const QCBORTagListIn *pCallerConfiguredTagMap,
                 uint64_t uTag,
                 uint8_t *puTagBitIndex)
{
   int nTagBitIndex = TagMapper_LookupBuiltIn(uTag);
   if(nTagBitIndex >= 0) {
      // Cast is safe because TagMapper_LookupBuiltIn never returns > 47
      *puTagBitIndex = (uint8_t)nTagBitIndex;
      return QCBOR_SUCCESS;
   }

   if(pCallerConfiguredTagMap) {
      if(pCallerConfiguredTagMap->uNumTags > QCBOR_MAX_CUSTOM_TAGS) {
         return QCBOR_ERR_TOO_MANY_TAGS;
      }
      nTagBitIndex = TagMapper_LookupCallerConfigured(pCallerConfiguredTagMap, uTag);
      if(nTagBitIndex >= 0) {
         // Cast is safe because TagMapper_LookupBuiltIn never returns > 63

         *puTagBitIndex = (uint8_t)nTagBitIndex;
         return QCBOR_SUCCESS;
      }
   }

   return QCBOR_ERR_BAD_OPT_TAG;
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
   DecodeNesting_Init(&(me->nesting));
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
   me->pCallerConfiguredTagList = pTagList;
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
      // Need to get 1,2,4 or 8 additional argument bytes Map
      // LEN_IS_ONE_BYTE.. LEN_IS_EIGHT_BYTES to actual length
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


/*
 Gets all optional tag data items preceding a data item that is not an
 optional tag and records them as bits in the tag map.
 */
static QCBORError
GetNext_TaggedItem(QCBORDecodeContext *me,
                   QCBORItem *pDecodedItem,
                   QCBORTagListOut *pTags)
{
   // Stack usage: int/ptr: 3 -- 24
   QCBORError nReturn;
   uint64_t  uTagBits = 0;
   if(pTags) {
      pTags->uNumUsed = 0;
   }

   // Loop fetching items until the item fetched is not a tag
   for(;;) {
      nReturn = GetNext_FullItem(me, pDecodedItem);
      if(nReturn) {
         goto Done; // Error out of the loop
      }

      if(pDecodedItem->uDataType != QCBOR_TYPE_OPTTAG) {
         // Successful exit from loop; maybe got some tags, maybe not
         pDecodedItem->uTagBits = uTagBits;
         break;
      }

      uint8_t uTagBitIndex;
      // Tag was mapped, tag was not mapped, error with tag list
      switch(TagMapper_Lookup(me->pCallerConfiguredTagList, pDecodedItem->val.uTagV, &uTagBitIndex)) {

         case QCBOR_SUCCESS:
            // Successfully mapped the tag
            uTagBits |= 0x01ULL << uTagBitIndex;
            break;

         case QCBOR_ERR_BAD_OPT_TAG:
            // Tag is not recognized. Do nothing
            break;

         default:
            // Error Condition
            goto Done;
      }

      if(pTags) {
         // Caller wants all tags recorded in the provided buffer
         if(pTags->uNumUsed >= pTags->uNumAllocated) {
            nReturn = QCBOR_ERR_TOO_MANY_TAGS;
            goto Done;
         }
         pTags->puTags[pTags->uNumUsed] = pDecodedItem->val.uTagV;
         pTags->uNumUsed++;
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
GetNext_MapEntry(QCBORDecodeContext *me,
                 QCBORItem *pDecodedItem,
                 QCBORTagListOut *pTags)
{
   // Stack use: int/ptr 1, QCBORItem  -- 56
   QCBORError nReturn = GetNext_TaggedItem(me, pDecodedItem, pTags);
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
         nReturn = GetNext_TaggedItem(me, pDecodedItem, pTags);
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


/*
 Public function, see header qcbor/qcbor_decode.h file
 TODO: correct this comment
 */
QCBORError QCBORDecode_GetNextMapOrArray(QCBORDecodeContext *me,
                                         QCBORItem *pDecodedItem,
                                         QCBORTagListOut *pTags)
{
   // Stack ptr/int: 2, QCBORItem : 64

   QCBORError nReturn;

   /* For a pre-order traversal a non-error end occurs when there
    are no more bytes to consume and the nesting level is at the top.
    If it's not at the top, then the CBOR is not well formed. This error
    is caught elsewhere.

    This handles the end of CBOR sequences as well as non-sequences. */
   if(UsefulInputBuf_BytesUnconsumed(&(me->InBuf)) == 0 && DecodeNesting_IsAtTop(&(me->nesting))) {
      nReturn = QCBOR_ERR_NO_MORE_ITEMS;
      goto Done;
   }

   /* It is also an end of the input when in map mode and the cursor
    is at the end of the map */


   // This is to handle map and array mode
   if(DecodeNesting_AtEnd(&(me->nesting))) {
//   if(UsefulInputBuf_Tell(&(me->InBuf)) != 0 && DecodeNesting_AtEnd(&(me->nesting))) {
      nReturn = QCBOR_ERR_NO_MORE_ITEMS;
      goto Done;
   }

   nReturn = GetNext_MapEntry(me, pDecodedItem, pTags);
   if(nReturn) {
      goto Done;
   }

   // Breaks ending arrays/maps are always processed at the end of this function.
   // They should never show up here.
   if(pDecodedItem->uDataType == QCBOR_TYPE_BREAK) {
      nReturn = QCBOR_ERR_BAD_BREAK;
      goto Done;
   }

   // Record the nesting level for this data item before processing any of
   // decrementing and descending.
   pDecodedItem->uNestingLevel = DecodeNesting_GetLevel(&(me->nesting));

   // Process the item just received for descent or decrement, and
   // ascend if decrements are enough to close out a definite length array/map
   if(IsMapOrArray(pDecodedItem->uDataType)) {
      // If the new item is array or map, the nesting level descends
      nReturn = DecodeNesting_Descend(&(me->nesting), pDecodedItem);
      // Maps and arrays do count in as items in the map/array that encloses
      // them so a decrement needs to be done for them too, but that is done
      // only when all the items in them have been processed, not when they
      // are opened with the exception of an empty map or array.
       if(pDecodedItem->val.uCount == 0) {
           DecodeNesting_DecrementCount(&(me->nesting));
       }
   } else {
      // Decrement the count of items in the enclosing map/array
      // If the count in the enclosing map/array goes to zero, that
      // triggers a decrement in the map/array above that and
      // an ascend in nesting level.
      DecodeNesting_DecrementCount(&(me->nesting));
   }
   if(nReturn) {
      goto Done;
   }

   // For indefinite length maps/arrays, looking at any and
   // all breaks that might terminate them. The equivalent
   // for definite length maps/arrays happens in
   // DecodeNesting_DecrementCount().
   if(!DecodeNesting_IsAtTop(&(me->nesting)) && DecodeNesting_IsIndefiniteLength(&(me->nesting))) {
      while(UsefulInputBuf_BytesUnconsumed(&(me->InBuf))) {
         // Peek forward one item to see if it is a break.
         QCBORItem Peek;
         size_t uPeek = UsefulInputBuf_Tell(&(me->InBuf));
         nReturn = GetNext_Item(&(me->InBuf), &Peek, NULL);
         if(nReturn) {
            goto Done;
         }
         if(Peek.uDataType != QCBOR_TYPE_BREAK) {
            // It is not a break, rewind so it can be processed normally.
            UsefulInputBuf_Seek(&(me->InBuf), uPeek);
            break;
         }
         // It is a break. Ascend one nesting level.
         // The break is consumed.
         nReturn = DecodeNesting_BreakAscend(&(me->nesting));
         if(nReturn) {
            // break occured outside of an indefinite length array/map
            goto Done;
         }
      }
   }

   // Tell the caller what level is next. This tells them what maps/arrays
   // were closed out and makes it possible for them to reconstruct
   // the tree with just the information returned by GetNext
   // TODO: pull this into DecodeNesting_GetLevel
   if(me->nesting.pCurrent->uMapMode && me->nesting.pCurrent->uCount == 0) {
      // At end of a map / array in map mode, so next nest is 0 to
      // indicate this end.
      pDecodedItem->uNextNestLevel = 0;
   } else {
      pDecodedItem->uNextNestLevel = DecodeNesting_GetLevel(&(me->nesting));
   }

Done:
   if(nReturn != QCBOR_SUCCESS) {
      // Make sure uDataType and uLabelType are QCBOR_TYPE_NONE
      memset(pDecodedItem, 0, sizeof(QCBORItem));
   }
   return nReturn;
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
   const bool bIsPosBigNum = (bool)(pDecodedItem->uTagBits & QCBOR_TAGFLAG_POS_BIGNUM);
   pDecodedItem->uDataType  = (uint8_t)(bIsPosBigNum ? QCBOR_TYPE_POSBIGNUM
                                                     : QCBOR_TYPE_NEGBIGNUM);
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
   nReturn = QCBORDecode_GetNextMapOrArray(me, &exponentItem, NULL);
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
 Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_GetNextWithTags(QCBORDecodeContext *me,
                            QCBORItem *pDecodedItem,
                            QCBORTagListOut *pTags)
{
   QCBORError nReturn;

   nReturn = QCBORDecode_GetNextMapOrArray(me, pDecodedItem, pTags);
   if(nReturn != QCBOR_SUCCESS) {
      goto Done;
   }

#ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
#define TAG_MAPPER_FIRST_XXX TAG_MAPPER_FIRST_SIX
#else
#define TAG_MAPPER_FIRST_XXX TAG_MAPPER_FIRST_FOUR
#endif

   // Only pay attention to tags this code knows how to decode.
   switch(pDecodedItem->uTagBits & TAG_MAPPER_FIRST_XXX) {
      case 0:
         // No tags at all or none we know about. Nothing to do.
         // This is the pass-through path of this function
         // that will mostly be taken when decoding any item.
         break;

      case QCBOR_TAGFLAG_DATE_STRING:
         nReturn = DecodeDateString(pDecodedItem);
         break;

      case QCBOR_TAGFLAG_DATE_EPOCH:
         nReturn = DecodeDateEpoch(pDecodedItem);
         break;

      case QCBOR_TAGFLAG_POS_BIGNUM:
      case QCBOR_TAGFLAG_NEG_BIGNUM:
         nReturn = DecodeBigNum(pDecodedItem);
         break;

#ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
      case QCBOR_TAGFLAG_DECIMAL_FRACTION:
      case QCBOR_TAGFLAG_BIGFLOAT:
         // For aggregate tagged types, what goes into pTags is only collected
         // from the surrounding data item, not the contents, so pTags is not
         // passed on here.

         nReturn = QCBORDecode_MantissaAndExponent(me, pDecodedItem);
         break;
#endif /* QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA */

      default:
         // Encountering some mixed-up CBOR like something that
         // is tagged as both a string and integer date.
         nReturn = QCBOR_ERR_BAD_OPT_TAG;
   }

Done:
   if(nReturn != QCBOR_SUCCESS) {
      pDecodedItem->uDataType  = QCBOR_TYPE_NONE;
      pDecodedItem->uLabelType = QCBOR_TYPE_NONE;
   }
   return nReturn;
}


/*
 Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError QCBORDecode_GetNext(QCBORDecodeContext *me, QCBORItem *pDecodedItem)
{
   return QCBORDecode_GetNextWithTags(me, pDecodedItem, NULL);
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
                         const QCBORItem *pItem,
                         uint64_t uTag)
{
   const QCBORTagListIn *pCallerConfiguredTagMap = me->pCallerConfiguredTagList;

   uint8_t uTagBitIndex;
   // Do not care about errors in pCallerConfiguredTagMap here. They are
   // caught during GetNext() before this is called.
   if(TagMapper_Lookup(pCallerConfiguredTagMap, uTag, &uTagBitIndex)) {
      return 0;
   }

   const uint64_t uTagBit = 0x01ULL << uTagBitIndex;
   return (uTagBit & pItem->uTagBits) != 0;
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
   printf("---%s--%d--%d--\nLevel   Count   Type   Offset  SaveCount  MapMode\n",
          szName,
          (uint32_t)pMe->InBuf.cursor,
          (uint32_t)pMe->InBuf.UB.len);
   for(int i = 0; i < QCBOR_MAX_ARRAY_NESTING; i++) {
      if(&(pMe->nesting.pMapsAndArrays[i]) > pMe->nesting.pCurrent) {
         break;
      }
      printf("%2s %2d   %5d %s   %6u         %2d      %d\n",
             pMe->nesting.pCurrentMap == &(pMe->nesting.pMapsAndArrays[i]) ? "->": "  ",
             i,
             pMe->nesting.pMapsAndArrays[i].uCount,
             pMe->nesting.pMapsAndArrays[i].uMajorType == QCBOR_TYPE_MAP ? "  map" :
               (pMe->nesting.pMapsAndArrays[i].uMajorType == QCBOR_TYPE_ARRAY ? "array" :
                 (pMe->nesting.pMapsAndArrays[i].uMajorType == QCBOR_TYPE_NONE ? " none" : "?????")),
             pMe->nesting.pMapsAndArrays[i].uOffset,
             pMe->nesting.pMapsAndArrays[i].uSaveCount,
             pMe->nesting.pMapsAndArrays[i].uMapMode
             );

   }
   printf("\n");
}


/*
 *
 */
static inline QCBORError
ConsumeItem(QCBORDecodeContext *pMe,
            const QCBORItem    *pItemToConsume,
            uint_fast8_t       *puNextNestLevel)
{
   QCBORError nReturn;
   QCBORItem  Item;
   
   printdecode(pMe, "ConsumeItem");

   if(IsMapOrArray(pItemToConsume->uDataType)) {
      /* There is only real work to do for maps and arrays */

      /* This works for definite and indefinite length
       * maps and arrays by using the nesting level
       */
      do {
         nReturn = QCBORDecode_GetNext(pMe, &Item);
         if(nReturn != QCBOR_SUCCESS) {
            goto Done;
         }
      } while(Item.uNextNestLevel >= pItemToConsume->uNextNestLevel);

      if(puNextNestLevel != NULL) {
         *puNextNestLevel = Item.uNextNestLevel;
      }
      nReturn = QCBOR_SUCCESS;

   } else {
      /* item_to_consume is not a map or array */
      if(puNextNestLevel != NULL) {
         /* Just pass the nesting level through */
         *puNextNestLevel = pItemToConsume->uNextNestLevel;
      }
      nReturn = QCBOR_SUCCESS;
   }

Done:
    return nReturn;
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


/*
 On input pItemArray contains a list of labels and data types
 of items to be found.
 
 On output the fully retrieved items are filled in with
 values and such. The label was matched, so it never changes.
 
 If an item was not found, its data type is set to none.
 
 */
static QCBORError
MapSearch(QCBORDecodeContext *pMe, QCBORItem *pItemArray, size_t *puOffset, size_t *puEndOffset)
{
   QCBORError  nReturn;

   // TODO: what if pre-order cursor is not at the same level as map? This should be OK.
   if(!DecodeNesting_InMapMode(&(pMe->nesting))) {
      return QCBOR_ERR_NOT_ENTERED;
   }

   QCBORDecodeNesting SaveNesting;
   DecodeNesting_PrepareForMapSearch(&(pMe->nesting), &SaveNesting);

   UsefulInputBuf_Seek(&(pMe->InBuf), pMe->nesting.pCurrent->uOffset);

   /* Loop over all the items in the map. They could be
   * deeply nested and this should handle both definite
   * and indefinite length maps and arrays, so this
   * adds some complexity. */
   const uint8_t uMapNestLevel = DecodeNesting_GetMapModeLevel(&(pMe->nesting));

   uint_fast8_t uNextNestLevel;
   
   uint64_t uFound = 0;

   do {
      /* Remember offset because sometims we have to return it */
      const size_t uOffset = UsefulInputBuf_Tell(&(pMe->InBuf));

      /* Get the item */
      QCBORItem Item;
      nReturn = QCBORDecode_GetNext(pMe, &Item);
      if(nReturn != QCBOR_SUCCESS) {
         /* Got non-well-formed CBOR */
         goto Done;
      }
       
      /* See if item has one of the labels that are of interest */
      int         i;
      QCBORItem  *pIterator;
      for(pIterator = pItemArray, i = 0; pIterator->uLabelType != 0; pIterator++, i++) {
         if(MatchLabel(Item, *pIterator)) {
            // A label match has been found
            if(uFound & (0x01ULL << i)) {
               nReturn = QCBOR_ERR_DUPLICATE_LABEL;
               goto Done;
            }
            if(!MatchType(Item, *pIterator)) {
               nReturn = QCBOR_ERR_UNEXPECTED_TYPE;
               goto Done;
            }
            
            /* Successful match. Return the item. */
            *pIterator = Item;
            uFound |= 0x01ULL << i;
            if(puOffset) {
               *puOffset = uOffset;
            }
         }
      }
         
      /* Consume the item whether matched or not. This
         does th work of traversing maps and array and
         everything in them. In this loop only the
         items at the current nesting level are examined
         to match the labels. */
      nReturn = ConsumeItem(pMe, &Item, &uNextNestLevel);
      if(nReturn) {
         goto Done;
      }
      
   } while (uNextNestLevel >= uMapNestLevel);

   
   nReturn = QCBOR_SUCCESS;

   const size_t uEndOffset = UsefulInputBuf_Tell(&(pMe->InBuf));
   // Cast OK because encoded CBOR is limited to UINT32_MAX
   pMe->uMapEndOffset = (uint32_t)uEndOffset;
   // TODO: is zero *puOffset OK?
   if(puEndOffset) {
      *puEndOffset = uEndOffset;
   }
   
   /* For all items not found, set the data type to QCBOR_TYPE_NONE */
   int        i;
   QCBORItem *pIterator;
   for(pIterator = pItemArray, i = 0; pIterator->uLabelType != 0; pIterator++, i++) {
      if(!(uFound & (0x01ULL << i))) {
         pIterator->uDataType = QCBOR_TYPE_NONE;
      }
   }

Done:
   DecodeNesting_RestoreFromMapSearch(&(pMe->nesting), &SaveNesting);
    
   return nReturn;
}


void QCBORDecode_ExitMapMode(QCBORDecodeContext *pMe, uint8_t uType)
{
   size_t uEndOffset;

   (void)uType; // TODO: error check

/*
   if(pMe->uMapEndOffset) {
      uEndOffset = pMe->uMapEndOffset;
      // It is only valid once.
      pMe->uMapEndOffset = 0;
   } else { */
      QCBORItem Dummy;

      Dummy.uLabelType = QCBOR_TYPE_NONE;

      QCBORError nReturn = MapSearch(pMe, &Dummy, NULL, &uEndOffset);

      (void)nReturn; // TODO:
//   }
   
   printdecode(pMe, "start exit");
   UsefulInputBuf_Seek(&(pMe->InBuf), uEndOffset);

   DecodeNesting_Exit(&(pMe->nesting));
   printdecode(pMe, "end exit");

}


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

   QCBORError nReturn = MapSearch(pMe, OneItemSeach, NULL, NULL);
   if(nReturn) {
      pMe->uLastError = (uint8_t)nReturn;
   }

   if(OneItemSeach[0].uDataType == QCBOR_TYPE_NONE) {
      pMe->uLastError = QCBOR_ERR_NOT_FOUND;
   }

   *pItem = OneItemSeach[0];
}


QCBORError QCBORDecode_GetItemInMapSZ(QCBORDecodeContext *pMe,
                                      const char         *szLabel,
                                      uint8_t            uQcborType,
                                      QCBORItem         *pItem)
{
   QCBORItem One[2];

   One[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   One[0].label.string = UsefulBuf_FromSZ(szLabel);
   One[0].uDataType    = uQcborType;
   One[1].uLabelType   = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORError nReturn = MapSearch(pMe, One, NULL, NULL);
   if(nReturn) {
     return nReturn;
   }

   if(One[0].uDataType == QCBOR_TYPE_NONE) {
      return QCBOR_ERR_NOT_FOUND;
   }

   *pItem = One[0];

   return QCBOR_SUCCESS;
}


static QCBORError CheckTagRequirement(TagSpecification TagSpec, uint8_t uDataType)
{
   // This gets called a lot, so it needs to be fast, especially for simple cases.
   // TODO: this isn't working right yet
   if((TagSpec.uTagRequirement == 1 || TagSpec.uTagRequirement == 2) && uDataType == TagSpec.uTaggedType) {
      return QCBOR_SUCCESS;
   } else {
      for(int i = 0; i < 6; i++) {
         if(uDataType == TagSpec.uAllowedContentTypes[i]) {
            return QCBOR_SUCCESS;
         }
      }
   }

   return QCBOR_ERR_UNEXPECTED_TYPE;

}

void QCBORDecode_GetTaggedItemInMapN(QCBORDecodeContext *pMe,
                                     int64_t             nLabel,
                                     TagSpecification    TagSpec,
                                     QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = CheckTagRequirement(TagSpec, pItem->uDataType);
}

void QCBORDecode_GetTaggedItemInMapSZ(QCBORDecodeContext *pMe,
                                     const char          *szLabel,
                                     TagSpecification    TagSpec,
                                     QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = CheckTagRequirement(TagSpec, pItem->uDataType);
}

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


static void SearchAndEnter(QCBORDecodeContext *pMe, QCBORItem pSearch[])
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state; do nothing.
      return;
   }

   size_t uOffset;
   pMe->uLastError = MapSearch(pMe, pSearch, &uOffset, NULL);
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
   pMe->nesting.pCurrent = pMe->nesting.pCurrentMap; // TODO: part of DecodeNesting

   // TODO: check error?
   QCBORDecode_EnterMapMode(pMe, pSearch->uDataType);

   printdecode(pMe, "FinishEnter");
}


void QCBORDecode_EnterMapInMapN(QCBORDecodeContext *pMe, int64_t nLabel)
{
   QCBORItem One[2];
   One[0].uLabelType  = QCBOR_TYPE_INT64;
   One[0].label.int64 = nLabel;
   One[0].uDataType   = QCBOR_TYPE_MAP;
   One[1].uLabelType  = QCBOR_TYPE_NONE;

   /* The map to enter was found, now finish of entering it. */
   SearchAndEnter(pMe, One);
}


void QCBORDecode_EnterMapFromMapSZ(QCBORDecodeContext *pMe, const char  *szLabel)
{
   QCBORItem One[2];
   One[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   One[0].label.string = UsefulBuf_FromSZ(szLabel);
   One[0].uDataType    = QCBOR_TYPE_MAP;
   One[1].uLabelType   = QCBOR_TYPE_NONE;
   
   SearchAndEnter(pMe, One);
}


void QCBORDecode_EnterArrayFromMapN(QCBORDecodeContext *pMe, int64_t nLabel)
{
   QCBORItem One[2];
   One[0].uLabelType  = QCBOR_TYPE_INT64;
   One[0].label.int64 = nLabel;
   One[0].uDataType   = QCBOR_TYPE_ARRAY;
   One[1].uLabelType  = QCBOR_TYPE_NONE;

   SearchAndEnter(pMe, One);
}


void QCBORDecode_EnterArrayFromMapSZ(QCBORDecodeContext *pMe, const char  *szLabel)
{
   QCBORItem One[2];
   One[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   One[0].label.string = UsefulBuf_FromSZ(szLabel);
   One[0].uDataType    = QCBOR_TYPE_ARRAY;
   One[1].uLabelType   = QCBOR_TYPE_NONE;

   SearchAndEnter(pMe, One);
}





/* Next item must be map or this generates an error */
void QCBORDecode_EnterMapMode(QCBORDecodeContext *pMe, uint8_t uType)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state; do nothing.
      return;
   }

   /* Get the data item that is the map that is being searched */
   QCBORItem  Item;
   pMe->uLastError = QCBORDecode_GetNext(pMe, &Item);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }
   if(Item.uDataType != uType) {
      pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
      return;
   }

   DecodeNesting_EnterMapMode(&(pMe->nesting), UsefulInputBuf_Tell(&(pMe->InBuf)));

   printdecode(pMe, "EnterMapModeDone");
}



QCBORError QCBORDecode_GetItemsInMap(QCBORDecodeContext *pCtx, QCBORItem *pItemList)
{
   return MapSearch(pCtx, pItemList, NULL, NULL);
}





void QCBORDecode_RewindMap(QCBORDecodeContext *pMe)
{
   // TODO: check for map mode
   pMe->nesting.pCurrent->uCount = pMe->nesting.pCurrent->uSaveCount;
   UsefulInputBuf_Seek(&(pMe->InBuf), pMe->nesting.pCurrent->uOffset);
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

void QCBORDecode_GetBoolInMapN(QCBORDecodeContext *pMe, int64_t nLabel, bool *pValue)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = (uint8_t)InterpretBool(&Item, pValue);
}


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




static QCBORError ConvertBigNum(const QCBORItem *pItem, UsefulBufC *pValue, bool *pbIsNegative)
{
   *pbIsNegative = false;

   bool bMustBeTagged = true; // TODO: fix this

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


/**
 @param[in] bMustBeTagged  If \c true, then the data item must be tagged as either
 a positive or negative bignum. If \c false, then it only must be a byte string and bIsNegative
 will always be false on the asumption that it is positive, but it can be interpretted as
 negative if the the sign is know from other context.
 @param[out] pValue   The bytes that make up the big num
 @param[out] pbIsNegative  \c true if tagged as a negative big num. \c false otherwise.

 if bMustBeTagged is false, then this will succeed if the data item is a plain byte string,
 a positive big num or a negative big num.

 */
void QCBORDecode_GetBignum(QCBORDecodeContext *pMe, bool bMustBeTagged, UsefulBufC *pValue, bool *pbIsNegative)
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

   pMe->uLastError = (uint8_t)ConvertBigNum(&Item, pValue, pbIsNegative);
}

void QCBORDecode_GetBignumInMapN(QCBORDecodeContext *pMe, int64_t nLabel, bool bMustBeTagged, UsefulBufC *pValue, bool *pbIsNegative)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = ConvertBigNum(&Item, pValue, pbIsNegative);
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
   QCBORError uError = ConvertBigNumToUnsigned(BigNum, INT64_MAX-1, &uResult);
   if(uError) {
      return uError;
   }
   /* Cast is safe because ConvertBigNum is told to limit to INT64_MAX */
   // TODO: this code is incorrect. See RFC 7049
   *pResult = -(int64_t)uResult;
   return QCBOR_SUCCESS;
}

#include "fenv.h"


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

   pMe->uLastError = ConvertInt64(&Item, uOptions, pnValue);
}

void QCBORDecode_GetInt64ConvertInternalInMapN(QCBORDecodeContext *pMe,
                                               int64_t             nLabel,
                                               uint32_t            uOptions,
                                               int64_t            *pnValue,
                                               QCBORItem          *pItem)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   pMe->uLastError = ConvertInt64(&Item, uOptions, pnValue);
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

   pMe->uLastError = ConvertInt64(&Item, uOptions, pnValue);
}




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





void QCBORDecode_GetUInt64ConvertInternal(QCBORDecodeContext *pMe,
                                          uint32_t uOptions,
                                          uint64_t *pValue,
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

   switch(Item.uDataType) {
         // TODO: type flaot
      case QCBOR_TYPE_DOUBLE:
         if(uOptions & QCBOR_CONVERT_TYPE_FLOAT) {
            feclearexcept(FE_ALL_EXCEPT);
            double dRounded = round(Item.val.dfnum);
            // TODO: over/underflow
            if(fetestexcept(FE_INVALID)) {
               // TODO: better error code
               pMe->uLastError = QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
            } else if(isnan(dRounded)) {
               // TODO: better error code
               pMe->uLastError = QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
            } else if(dRounded >= 0) {
               *pValue = (uint64_t)dRounded;
            } else {
               pMe->uLastError = QCBOR_ERR_NUMBER_SIGN_CONVERSION;
            }
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_INT64:
         if(uOptions & QCBOR_CONVERT_TYPE_INT64) {
            if(Item.val.int64 >= 0) {
               *pValue = (uint64_t)Item.val.int64;
            } else {
               pMe->uLastError = QCBOR_ERR_NUMBER_SIGN_CONVERSION;
            }
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_UINT64:
         if(uOptions & QCBOR_CONVERT_TYPE_UINT64) {
            *pValue = Item.val.uint64;
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      default:
         pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
   }
}


/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetUInt64ConvertAll(QCBORDecodeContext *pMe, uint32_t uOptions, uint64_t *pValue)
{
   QCBORItem Item;

   QCBORDecode_GetUInt64ConvertInternal(pMe, uOptions, pValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   switch(Item.uDataType) {

      case QCBOR_TYPE_POSBIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_BIG_NUM) {
            pMe->uLastError = (uint8_t)ConvertPositiveBigNumToUnsigned(Item.val.bigNum, pValue);
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_BIG_NUM) {
            pMe->uLastError = QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

#ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA

      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            pMe->uLastError = (uint8_t)ExponentitateNU(Item.val.expAndMantissa.Mantissa.nInt,
                                                       Item.val.expAndMantissa.nExponent,
                                                       pValue,
                                                       Exponentitate10);
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT:
         if(uOptions & QCBOR_CONVERT_TYPE_BIGFLOAT) {
            pMe->uLastError = (uint8_t)ExponentitateNU(Item.val.expAndMantissa.Mantissa.nInt,
                                                       Item.val.expAndMantissa.nExponent,
                                                       pValue,
                                                       Exponentitate2);
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;



      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            // TODO: Would be better to convert to unsigned
            int64_t nMantissa;
            pMe->uLastError = (uint8_t)ConvertPositiveBigNumToSigned(Item.val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(!pMe->uLastError) {
               pMe->uLastError = (uint8_t)ExponentitateNU(nMantissa,
                                                          Item.val.expAndMantissa.nExponent,
                                                          pValue,
                                                          Exponentitate10);

            }
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            pMe->uLastError = QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            // TODO: Would be better to convert to unsigned
            int64_t nMantissa;
            pMe->uLastError = (uint8_t)ConvertPositiveBigNumToSigned(Item.val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(!pMe->uLastError) {
               pMe->uLastError = (uint8_t)ExponentitateNU(nMantissa,
                                                          Item.val.expAndMantissa.nExponent,
                                                          pValue,
                                                          Exponentitate2);
            }
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            pMe->uLastError = QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;
#endif
      default:
         pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
   }
}


void QCBORDecode_GetDoubleConvertInternal(QCBORDecodeContext *pMe,
                                          uint32_t            uOptions,
                                          double             *pValue,
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

   switch(Item.uDataType) {
      // TODO: float when ifdefs are set
      case QCBOR_TYPE_DOUBLE:
         if(uOptions & QCBOR_CONVERT_TYPE_FLOAT) {
            if(uOptions & QCBOR_CONVERT_TYPE_FLOAT) {
               *pValue = Item.val.dfnum;
            } else {
               pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
            }
         }
         break;

      case QCBOR_TYPE_INT64:
         if(uOptions & QCBOR_CONVERT_TYPE_INT64) {
            // TODO: how does this work?
            *pValue = (double)Item.val.int64;

         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_UINT64:
         if(uOptions & QCBOR_CONVERT_TYPE_UINT64) {
             *pValue = (double)Item.val.uint64;
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;
      default:
         pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
   }
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

/*
 Public function, see header qcbor/qcbor_decode.h file
*/
void QCBORDecode_GetDoubleConvertAll(QCBORDecodeContext *pMe, uint32_t uOptions, double *pValue)
{
   /*


   https://docs.oracle.com/cd/E19957-01/806-3568/ncg_goldberg.html

   */
   QCBORItem Item;

   QCBORDecode_GetDoubleConvertInternal(pMe, uOptions, pValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = QCBOR_SUCCESS;

   switch(Item.uDataType) {
         // TODO: type float
      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            // TODO: rounding and overflow errors
            *pValue = (double)Item.val.expAndMantissa.Mantissa.nInt *
                        pow(10.0, (double)Item.val.expAndMantissa.nExponent);
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT:
         if(uOptions & QCBOR_CONVERT_TYPE_BIGFLOAT ) {
           *pValue = (double)Item.val.expAndMantissa.Mantissa.nInt *
                                exp2((double)Item.val.expAndMantissa.nExponent);
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_POSBIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_BIG_NUM) {
            *pValue = ConvertBigNumToDouble(Item.val.bigNum);
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_BIG_NUM) {
            *pValue = -ConvertBigNumToDouble(Item.val.bigNum);
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            double dMantissa = ConvertBigNumToDouble(Item.val.expAndMantissa.Mantissa.bigNum);
            *pValue = dMantissa * pow(10, (double)Item.val.expAndMantissa.nExponent);
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
        if(uOptions & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
         double dMantissa = -ConvertBigNumToDouble(Item.val.expAndMantissa.Mantissa.bigNum);
         *pValue = dMantissa * pow(10, (double)Item.val.expAndMantissa.nExponent);
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
        if(uOptions & QCBOR_CONVERT_TYPE_BIGFLOAT) {
         double dMantissa = ConvertBigNumToDouble(Item.val.expAndMantissa.Mantissa.bigNum);
         *pValue = dMantissa * exp2((double)Item.val.expAndMantissa.nExponent);
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
        if(uOptions & QCBOR_CONVERT_TYPE_BIGFLOAT) {
         double dMantissa = -ConvertBigNumToDouble(Item.val.expAndMantissa.Mantissa.bigNum);
         *pValue = dMantissa * exp2((double)Item.val.expAndMantissa.nExponent);
         } else {
            pMe->uLastError = QCBOR_ERR_CONVERSION_NOT_REQUESTED;
         }
         break;

      default:
         pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
   }
}

