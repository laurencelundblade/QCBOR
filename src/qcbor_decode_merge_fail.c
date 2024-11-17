/*==============================================================================
 Copyright (c) 2016-2018, The Linux Foundation.
 Copyright (c) 2018-2024, Laurence Lundblade.
 Copyright (c) 2021, Arm Limited.
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
#include "qcbor/qcbor_spiffy_decode.h"
#include "qcbor/qcbor_tag_decode.h"
#include "ieee754.h" /* Does not use math.h */

#ifndef QCBOR_DISABLE_FLOAT_HW_USE

#include <math.h> /* For isnan(), llround(), llroudf(), round(), roundf(),
                   * pow(), exp2()
                   */
#include <fenv.h> /* feclearexcept(), fetestexcept() */

#endif /* QCBOR_DISABLE_FLOAT_HW_USE */


#if (defined(__GNUC__) && !defined(__clang__))
/*
 * This is how the -Wmaybe-uninitialized compiler warning is
 * handled. It can’t be ignored because some version of gcc enable it
 * with -Wall which is a common and useful gcc warning option. It also
 * can’t be ignored because it is the goal of QCBOR to compile clean
 * out of the box in all environments.
 *
 * The big problem with -Wmaybe-uninitialized is that it generates
 * false positives. It complains things are uninitialized when they
 * are not. This is because it is not a thorough static analyzer. This
 * is why “maybe” is in its name. The problem is it is just not
 * thorough enough to understand all the code (and someone saw fit to
 * put it in gcc and worse to enable it with -Wall).
 *
 * One solution would be to change the code so -Wmaybe-uninitialized
 * doesn’t get confused, for example adding an unnecessary extra
 * initialization to zero. (If variables were truly uninitialized, the
 * correct path is to understand the code thoroughly and set them to
 * the correct value at the correct time; in essence this is already
 * done; -Wmaybe-uninitialized just can’t tell). This path is not
 * taken because it makes the code bigger and is kind of the tail
 * wagging the dog.
 *
 * The solution here is to just use a pragma to disable it for the
 * whole file. Disabling it for each line makes the code fairly ugly
 * requiring #pragma to push, pop and ignore. Another reason is the
 * warnings issues vary by version of gcc and which optimization
 * optimizations are selected. Another reason is that compilers other
 * than gcc don’t have -Wmaybe-uninitialized.
 *
 * One may ask how to be sure these warnings are false positives and
 * not real issues. 1) The code has been read carefully to check. 2)
 * Testing is pretty thorough. 3) This code has been run through
 * thorough high-quality static analyzers.
 *
 * In particularly, most of the warnings are about
 * Item.Item->uDataType being uninitialized. QCBORDecode_GetNext()
 * *always* sets this value and test case confirm
 * this. -Wmaybe-uninitialized just can't tell.
 *
 * https://stackoverflow.com/questions/5080848/disable-gcc-may-be-used-uninitialized-on-a-particular-variable
 */
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif


static bool
QCBORItem_IsMapOrArray(const QCBORItem Item)
{
   const uint8_t uDataType = Item.uDataType;
   return uDataType == QCBOR_TYPE_MAP ||
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
          uDataType == QCBOR_TYPE_MAP_AS_ARRAY ||
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
          uDataType == QCBOR_TYPE_ARRAY;
}

static bool
QCBORItem_IsEmptyDefiniteLengthMapOrArray(const QCBORItem Item)
{
   if(!QCBORItem_IsMapOrArray(Item)){
      return false;
   }

   if(Item.val.uCount != 0) {
      return false;
   }
   return true;
}

static bool
QCBORItem_IsIndefiniteLengthMapOrArray(const QCBORItem Item)
{
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   if(!QCBORItem_IsMapOrArray(Item)){
      return false;
   }

   if(Item.val.uCount != QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH) {
      return false;
   }
   return true;
#else /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
   (void)Item;
   return false;
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
}

/* Return true if the labels in Item1 and Item2 are the same.
   Works only for integer and string labels. Returns false
   for any other type. */
static bool
QCBORItem_MatchLabel(const QCBORItem Item1, const QCBORItem Item2)
{
   if(Item1.uLabelType == QCBOR_TYPE_INT64) {
      if(Item2.uLabelType == QCBOR_TYPE_INT64 && Item1.label.int64 == Item2.label.int64) {
         return true;
      }
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
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
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
   }

   /* Other label types are never matched */
   return false;
}


/*
 Returns true if Item1 and Item2 are the same type
 or if either are of QCBOR_TYPE_ANY.
 */
static bool
QCBORItem_MatchType(const QCBORItem Item1, const QCBORItem Item2)
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


/*===========================================================================
   DecodeNesting -- Tracking array/map/sequence/bstr-wrapped nesting
  ===========================================================================*/

/*
 * See comments about and typedef of QCBORDecodeNesting in qcbor_private.h,
 * the data structure all these functions work on.
 */


static uint8_t
DecodeNesting_GetCurrentLevel(const QCBORDecodeNesting *pNesting)
{
   const ptrdiff_t nLevel = pNesting->pCurrent - &(pNesting->pLevels[0]);
   /* Limit in DecodeNesting_Descend against more than
    * QCBOR_MAX_ARRAY_NESTING gaurantees cast is safe
    */
   return (uint8_t)nLevel;
}


static uint8_t
DecodeNesting_GetBoundedModeLevel(const QCBORDecodeNesting *pNesting)
{
   const ptrdiff_t nLevel = pNesting->pCurrentBounded - &(pNesting->pLevels[0]);
   /* Limit in DecodeNesting_Descend against more than
    * QCBOR_MAX_ARRAY_NESTING gaurantees cast is safe
    */
   return (uint8_t)nLevel;
}


static uint32_t
DecodeNesting_GetMapOrArrayStart(const QCBORDecodeNesting *pNesting)
{
   return pNesting->pCurrentBounded->u.ma.uStartOffset;
}


static bool
DecodeNesting_IsBoundedEmpty(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrentBounded->u.ma.uCountCursor == QCBOR_COUNT_INDICATES_ZERO_LENGTH) {
      return true;
   } else {
      return false;
   }
}


static bool
DecodeNesting_IsCurrentAtTop(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent == &(pNesting->pLevels[0])) {
      return true;
   } else {
      return false;
   }
}


static bool
DecodeNesting_IsCurrentDefiniteLength(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->uLevelType == QCBOR_TYPE_BYTE_STRING) {
      /* Not a map or array */
      return false;
   }

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   if(pNesting->pCurrent->u.ma.uCountTotal == QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH) {
      /* Is indefinite */
      return false;
   }

#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

   /* All checks passed; is a definte length map or array */
   return true;
}

static bool
DecodeNesting_IsCurrentBstrWrapped(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->uLevelType == QCBOR_TYPE_BYTE_STRING) {
      /* is a byte string */
      return true;
   }
   return false;
}


static bool
DecodeNesting_IsCurrentBounded(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->uLevelType == QCBOR_TYPE_BYTE_STRING) {
      return true;
   }
   if(pNesting->pCurrent->u.ma.uStartOffset != QCBOR_NON_BOUNDED_OFFSET) {
      return true;
   }
   return false;
}


static void
DecodeNesting_SetMapOrArrayBoundedMode(QCBORDecodeNesting *pNesting, bool bIsEmpty, size_t uStart)
{
   /* Should be only called on maps and arrays */
   /*
    * DecodeNesting_EnterBoundedMode() checks to be sure uStart is not
    * larger than DecodeNesting_EnterBoundedMode which keeps it less than
    * uin32_t so the cast is safe.
    */
   pNesting->pCurrent->u.ma.uStartOffset = (uint32_t)uStart;

   if(bIsEmpty) {
      pNesting->pCurrent->u.ma.uCountCursor = QCBOR_COUNT_INDICATES_ZERO_LENGTH;
   }
}


static void
DecodeNesting_ClearBoundedMode(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent->u.ma.uStartOffset = QCBOR_NON_BOUNDED_OFFSET;
}


static bool
DecodeNesting_IsAtEndOfBoundedLevel(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrentBounded == NULL) {
      /* No bounded map or array set up */
      return false;
   }
   if(pNesting->pCurrent->uLevelType == QCBOR_TYPE_BYTE_STRING) {
      /* Not a map or array; end of those is by byte count */
      return false;
   }
   if(!DecodeNesting_IsCurrentBounded(pNesting)) {
      /* In a traveral at a level deeper than the bounded level */
      return false;
   }
   /* Works for both definite- and indefinitelength maps/arrays */
   if(pNesting->pCurrentBounded->u.ma.uCountCursor != 0 &&
      pNesting->pCurrentBounded->u.ma.uCountCursor != QCBOR_COUNT_INDICATES_ZERO_LENGTH) {
      /* Count is not zero, still unconsumed item */
      return false;
   }
   /* All checks passed, got to the end of an array or map*/
   return true;
}


static bool
DecodeNesting_IsEndOfDefiniteLengthMapOrArray(const QCBORDecodeNesting *pNesting)
{
   /* Must only be called on map / array */
   if(pNesting->pCurrent->u.ma.uCountCursor == 0) {
      return true;
   } else {
      return false;
   }
}


static bool
DecodeNesting_IsCurrentTypeMap(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->uLevelType == CBOR_MAJOR_TYPE_MAP) {
      return true;
   } else {
      return false;
   }
}


static bool
DecodeNesting_IsBoundedType(const QCBORDecodeNesting *pNesting, uint8_t uType)
{
   if(pNesting->pCurrentBounded == NULL) {
      return false;
   }

   uint8_t uItemDataType = pNesting->pCurrentBounded->uLevelType;
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   if(uItemDataType == QCBOR_TYPE_MAP_AS_ARRAY) {
      uItemDataType = QCBOR_TYPE_ARRAY;
   }
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */

   if(uItemDataType != uType) {
      return false;
   }

   return true;
}


static void
DecodeNesting_DecrementDefiniteLengthMapOrArrayCount(QCBORDecodeNesting *pNesting)
{
   /* Only call on a definite-length array / map */
   pNesting->pCurrent->u.ma.uCountCursor--;
}


static void
DecodeNesting_ReverseDecrement(QCBORDecodeNesting *pNesting)
{
   /* Only call on a definite-length array / map */
   pNesting->pCurrent->u.ma.uCountCursor++;
}


static void
DecodeNesting_Ascend(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent--;
}


static QCBORError
DecodeNesting_Descend(QCBORDecodeNesting *pNesting, uint8_t uType)
{
   /* Error out if nesting is too deep */
   if(pNesting->pCurrent >= &(pNesting->pLevels[QCBOR_MAX_ARRAY_NESTING])) {
      return QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP;
   }

   /* The actual descend */
   pNesting->pCurrent++;

   pNesting->pCurrent->uLevelType = uType;

   return QCBOR_SUCCESS;
}


static QCBORError
DecodeNesting_EnterBoundedMapOrArray(QCBORDecodeNesting *pNesting,
                                     bool                bIsEmpty,
                                     size_t              uOffset)
{
   /*
    * Should only be called on map/array.
    *
    * Have descended into this before this is called. The job here is
    * just to mark it in bounded mode.
    *
    * Check against QCBOR_MAX_DECODE_INPUT_SIZE make sure that
    * uOffset doesn't collide with QCBOR_NON_BOUNDED_OFFSET.
    *
    * Cast of uOffset to uint32_t for cases where SIZE_MAX < UINT32_MAX.
    */
   if((uint32_t)uOffset >= QCBOR_MAX_DECODE_INPUT_SIZE) {
      return QCBOR_ERR_INPUT_TOO_LARGE;
   }

   pNesting->pCurrentBounded = pNesting->pCurrent;

   DecodeNesting_SetMapOrArrayBoundedMode(pNesting, bIsEmpty, uOffset);

   return QCBOR_SUCCESS;
}


static QCBORError
DecodeNesting_DescendMapOrArray(QCBORDecodeNesting *pNesting,
                                const uint8_t       uQCBORType,
                                const uint16_t      uCount)
{
   QCBORError uError = QCBOR_SUCCESS;

   if(uCount == 0) {
      /* Nothing to do for empty definite-length arrays. They are just are
       * effectively the same as an item that is not a map or array.
       */
      goto Done;
      /* Empty indefinite-length maps and arrays are handled elsewhere */
   }

   /* Rely on check in QCBOR_Private_DecodeArrayOrMap() for definite-length
    * arrays and maps that are too long */

   uError = DecodeNesting_Descend(pNesting, uQCBORType);
   if(uError != QCBOR_SUCCESS) {
      goto Done;
   }

   pNesting->pCurrent->u.ma.uCountCursor = uCount;
   pNesting->pCurrent->u.ma.uCountTotal  = uCount;

   DecodeNesting_ClearBoundedMode(pNesting);

Done:
   return uError;;
}


static void
DecodeNesting_LevelUpCurrent(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent = pNesting->pCurrentBounded - 1;
}


static void
DecodeNesting_LevelUpBounded(QCBORDecodeNesting *pNesting)
{
   while(pNesting->pCurrentBounded != &(pNesting->pLevels[0])) {
      pNesting->pCurrentBounded--;
      if(DecodeNesting_IsCurrentBounded(pNesting)) {
         break;
      }
   }
}


static void
DecodeNesting_SetCurrentToBoundedLevel(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent = pNesting->pCurrentBounded;
}


static QCBORError
DecodeNesting_DescendIntoBstrWrapped(QCBORDecodeNesting *pNesting,
                                     uint32_t            uEndOffset,
                                     uint32_t            uStartOffset)
{
   QCBORError uError;

   uError = DecodeNesting_Descend(pNesting, QCBOR_TYPE_BYTE_STRING);
   if(uError != QCBOR_SUCCESS) {
      goto Done;
   }

   /* Fill in the new byte string level */
   pNesting->pCurrent->u.bs.uSavedEndOffset  = uEndOffset;
   pNesting->pCurrent->u.bs.uBstrStartOffset = uStartOffset;

   /* Bstr wrapped levels are always bounded */
   pNesting->pCurrentBounded = pNesting->pCurrent;

Done:
   return uError;;
}


static void
DecodeNesting_ZeroMapOrArrayCount(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent->u.ma.uCountCursor = 0;
}


static void
DecodeNesting_ResetMapOrArrayCount(QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->u.ma.uCountCursor != QCBOR_COUNT_INDICATES_ZERO_LENGTH) {
      pNesting->pCurrentBounded->u.ma.uCountCursor = pNesting->pCurrentBounded->u.ma.uCountTotal;
   }
}


static void
DecodeNesting_Init(QCBORDecodeNesting *pNesting)
{
   /* Assumes that *pNesting has been zero'd before this call. */
   pNesting->pLevels[0].uLevelType = QCBOR_TYPE_BYTE_STRING;
   pNesting->pCurrent = &(pNesting->pLevels[0]);
}


static void
DecodeNesting_PrepareForMapSearch(QCBORDecodeNesting *pNesting,
                                  QCBORDecodeNesting *pSave)
{
   *pSave = *pNesting;
}


static void
DecodeNesting_RestoreFromMapSearch(QCBORDecodeNesting *pNesting,
                                   const QCBORDecodeNesting *pSave)
{
   *pNesting = *pSave;
}


static uint32_t
DecodeNesting_GetPreviousBoundedEnd(const QCBORDecodeNesting *pMe)
{
   return pMe->pCurrentBounded->u.bs.uSavedEndOffset;
}




#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
/*===========================================================================
   QCBORStringAllocate -- STRING ALLOCATOR INVOCATION

   The following four functions are pretty wrappers for invocation of
   the string allocator supplied by the caller.

  ===========================================================================*/

static void
StringAllocator_Free(const QCBORInternalAllocator *pMe, const void *pMem)
{
   /* This cast to uintptr_t suppresses the "-Wcast-qual" warnings.
    * This is the one place where the const needs to be cast away so const can
    * be use in the rest of the code.
    */
   (pMe->pfAllocator)(pMe->pAllocateCxt, (void *)(uintptr_t)pMem, 0);
}

// StringAllocator_Reallocate called with pMem NULL is
// equal to StringAllocator_Allocate()
static UsefulBuf
StringAllocator_Reallocate(const QCBORInternalAllocator *pMe,
                           const void *pMem,
                           size_t uSize)
{
   /* See comment in StringAllocator_Free() */
   return (pMe->pfAllocator)(pMe->pAllocateCxt, (void *)(uintptr_t)pMem, uSize);
}

static UsefulBuf
StringAllocator_Allocate(const QCBORInternalAllocator *pMe, size_t uSize)
{
   return (pMe->pfAllocator)(pMe->pAllocateCxt, NULL, uSize);
}

static void
StringAllocator_Destruct(const QCBORInternalAllocator *pMe)
{
   /* See comment in StringAllocator_Free() */
   if(pMe->pfAllocator) {
      (pMe->pfAllocator)(pMe->pAllocateCxt, NULL, 0);
   }
}
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */




/*===========================================================================
 QCBORDecode -- The main implementation of CBOR decoding

 See qcbor/qcbor_decode.h for definition of the object
 used here: QCBORDecodeContext
  ===========================================================================*/
/*
 * Public function, see header file
 */
void
QCBORDecode_Init(QCBORDecodeContext *pMe,
                 UsefulBufC          EncodedCBOR,
                 QCBORDecodeMode     nDecodeMode)
{
   memset(pMe, 0, sizeof(QCBORDecodeContext));
   UsefulInputBuf_Init(&(pMe->InBuf), EncodedCBOR);
   /* Don't bother with error check on decode mode. If a bad value is
    * passed it will just act as if the default normal mode of 0 was set.
    */
   pMe->uDecodeMode = (uint8_t)nDecodeMode;
   DecodeNesting_Init(&(pMe->nesting));

   /* Inialize me->auMappedTags to CBOR_TAG_INVALID16. See
    * GetNext_TaggedItem() and MapTagNumber(). */
   memset(pMe->auMappedTags, 0xff, sizeof(pMe->auMappedTags));

   pMe->uTagNumberCheckOffset = SIZE_MAX;
}


/*
 * Public function, see header file
 */
void
QCBORDecode_CompatibilityV1(QCBORDecodeContext *pMe)
{
   pMe->uDecodeMode |= QCBOR_DECODE_UNPROCESSED_TAG_NUMBERS;
#ifndef QCBOR_DISABLE_TAGS
   QCBORDecode_InstallTagDecoders(pMe, QCBORDecode_TagDecoderTablev1, NULL);
#endif /* ! QCBOR_DISABLE_TAGS */
}




#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS

/*
 * Public function, see header file
 */
void
QCBORDecode_SetUpAllocator(QCBORDecodeContext *pMe,
                           QCBORStringAllocate pfAllocateFunction,
                           void               *pAllocateContext,
                           bool                bAllStrings)
{
   pMe->StringAllocator.pfAllocator   = pfAllocateFunction;
   pMe->StringAllocator.pAllocateCxt  = pAllocateContext;
   pMe->bStringAllocateAll            = bAllStrings;
}
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */






/*
 * Decoding items is done in six layers, one calling the next one
 * down. If a layer has no work to do for a particular item, it
 * returns quickly.
 *
 * 1. QCBORDecode_Private_GetNextTagContent - The top layer processes
 * tagged data items, turning them into the local C representation.
 * For the most simple it is just associating a QCBOR_TYPE with the
 * data. For the complex ones that an aggregate of data items, there
 * is some further decoding and some limited recursion.
 *
 * 2. QCBORDecode_Private_GetNextMapOrArray - This manages the
 * beginnings and ends of maps and arrays. It tracks descending into
 * and ascending out of maps/arrays. It processes breaks that
 * terminate indefinite-length maps and arrays.
 *
 * 3. QCBORDecode_Private_GetNextMapEntry - This handles the combining
 * of two items, the label and the data, that make up a map entry.  It
 * only does work on maps. It combines the label and data items into
 * one labeled item.
 *
 * 4. QCBORDecode_Private_GetNextTagNumber - This decodes type 6 tag
 * numbers. It turns the tag numbers into bit flags associated with
 * the data item. No actual decoding of the contents of the tag is
 * performed here.
 *
 * 5. QCBORDecode_Private_GetNextFullString - This assembles the
 * sub-items that make up an indefinite-length string into one string
 * item. It uses the string allocator to create contiguous space for
 * the item. It processes all breaks that are part of
 * indefinite-length strings.
 *
 * 6. QCBOR_Private_DecodeAtomicDataItem - This decodes the atomic
 * data items in CBOR. Each atomic data item has a "major type", an
 * integer "argument" and optionally some content. For text and byte
 * strings, the content is the bytes that make up the string. These
 * are the smallest data items that are considered to be well-formed.
 * The content may also be other data items in the case of aggregate
 * types. They are not handled in this layer.
 *
 * This uses about 350 bytes of stack. This number comes from
 * instrumenting (printf address of stack variables) the code on x86
 * compiled for size optimization.
 */


/*
 * Note about use of int and unsigned variables.
 *
 * See http://www.unix.org/whitepapers/64bit.html for reasons int is
 * used carefully here, and in particular why it isn't used in the
 * public interface.  Also see
 * https://stackoverflow.com/questions/17489857/why-is-int-typically-32-bit-on-64-bit-compilers
 *
 * Int is used for values that need less than 16-bits and would be
 * subject to integer promotion and result in complaining from static
 * analyzers.
 */


/**
 * @brief Decode the CBOR head, the type and argument.
 *
 * @param[in] pUInBuf            The input buffer to read from.
 * @param[in] bRequirePreferred  Require preferred serialization for argument.
 * @param[out] pnMajorType       The decoded major type.
 * @param[out] puArgument        The decoded argument.
 * @param[out] pnAdditionalInfo  The decoded Lower 5 bits of initial byte.
 *
 * @retval QCBOR_ERR_UNSUPPORTED Encountered unsupported/reserved features
 * @retval QCBOR_ERR_HIT_END Unexpected end of input
 *
 * This decodes the CBOR "head" that every CBOR data item has. See
 * longer description in QCBOREncode_EncodeHead().
 *
 * This does the network to host byte order conversion. The conversion
 * here also provides the conversion for floats in addition to that
 * for lengths, tags and integer values.
 *
 * The int type is preferred to uint8_t for some variables as this
 * avoids integer promotions, can reduce code size and makes static
 * analyzers happier.
 */
static QCBORError
QCBOR_Private_DecodeHead(UsefulInputBuf *pUInBuf,
#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
                         bool            bRequirePreferred,
#endif
                         int            *pnMajorType,
                         uint64_t       *puArgument,
                         int            *pnAdditionalInfo)
{
   QCBORError uReturn;
   uint64_t   uArgument;

   /* Get and break down initial byte that every CBOR data item has */
   const int nInitialByte    = (int)UsefulInputBuf_GetByte(pUInBuf);
   const int nTmpMajorType   = nInitialByte >> 5;
   const int nAdditionalInfo = nInitialByte & 0x1f;

   if(nAdditionalInfo >= LEN_IS_ONE_BYTE && nAdditionalInfo <= LEN_IS_EIGHT_BYTES) {
      /* Need to get 1,2,4 or 8 additional argument bytes. Map
       * LEN_IS_ONE_BYTE..LEN_IS_EIGHT_BYTES to actual length.
       */
      static const uint8_t aIterate[] = {1,2,4,8};

      /* Loop getting all the bytes in the argument */
      uArgument = 0;
      for(int i = aIterate[nAdditionalInfo - LEN_IS_ONE_BYTE]; i; i--) {
         /* This shift-and-add gives the endian conversion. */
         uArgument = (uArgument << 8) + UsefulInputBuf_GetByte(pUInBuf);
      }

#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
      /* If requested, check that argument is in preferred form */
      if(bRequirePreferred) {
         uint64_t uMinArgument;

         if(nAdditionalInfo == LEN_IS_ONE_BYTE) {
            if(uArgument < 24) {
               uReturn = QCBOR_ERR_PREFERRED_CONFORMANCE;
               goto Done;
            }
         } else {
            if(nTmpMajorType != CBOR_MAJOR_TYPE_SIMPLE) {
               /* Check only if not a floating-point number */
               int nArgLen = aIterate[nAdditionalInfo - LEN_IS_ONE_BYTE - 1];
               uMinArgument = UINT64_MAX >> ((int)sizeof(uint64_t) - nArgLen) * 8;
               if(uArgument <= uMinArgument) {
                  uReturn = QCBOR_ERR_PREFERRED_CONFORMANCE;
                  goto Done;
               }
            }
         }
      }
#endif /* ! QCBOR_DISABLE_DECODE_CONFORMANCE */

   } else if(nAdditionalInfo >= ADDINFO_RESERVED1 && nAdditionalInfo <= ADDINFO_RESERVED3) {
      /* The reserved and thus-far unused additional info values */
      uReturn = QCBOR_ERR_UNSUPPORTED;
      goto Done;
   } else {
#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
      if(bRequirePreferred && nAdditionalInfo == LEN_IS_INDEFINITE) {
         uReturn = QCBOR_ERR_PREFERRED_CONFORMANCE;
         goto Done;
      }
#endif /* ! QCBOR_DISABLE_DECODE_CONFORMANCE */

      /* Less than 24, additional info is argument or 31, an
       * indefinite-length.  No more bytes to get.
       */
      uArgument = (uint64_t)nAdditionalInfo;
   }

   if(UsefulInputBuf_GetError(pUInBuf)) {
      uReturn = QCBOR_ERR_HIT_END;
      goto Done;
   }

   /* All successful if arrived here. */
   uReturn           = QCBOR_SUCCESS;
   *pnMajorType      = nTmpMajorType;
   *puArgument       = uArgument;
   *pnAdditionalInfo = nAdditionalInfo;

Done:
   return uReturn;
}


/**
 * @brief Decode integer types, major types 0 and 1.
 *
 * @param[in] nMajorType       The CBOR major type (0 or 1).
 * @param[in] uArgument        The argument from the head.
 * @param[in] nAdditionalInfo  So it can be error-checked.
 * @param[out] pDecodedItem    The filled in decoded item.
 *
 * @retval QCBOR_ERR_INT_OVERFLOW  Too-large negative encountered.
 * @retval QCBOR_ERR_BAD_INT       nAdditionalInfo indicated indefinte.
 *
 * Must only be called when major type is 0 or 1.
 *
 * CBOR doesn't explicitly specify two's compliment for integers but
 * all CPUs use it these days and the test vectors in the RFC are
 * so. All integers in encoded CBOR are unsigned and the CBOR major
 * type indicates positive or negative.  CBOR can express positive
 * integers up to 2^64 - 1 negative integers down to -2^64.  Note that
 * negative numbers can be one more
 * away from zero than positive because there is no negative zero.
 *
 * The "65-bit negs" are values CBOR can encode that can't fit
 * into an int64_t or uint64_t. They decoded as a special type
 * QCBOR_TYPE_65BIT_NEG_INT. Not that this type does NOT
 * take into account the offset of one for CBOR negative integers.
 * It must be applied to get the correct value. Applying this offset
 * would overflow a uint64_t.
 */
static QCBORError
QCBOR_Private_DecodeInteger(const int      nMajorType,
                            const uint64_t uArgument,
                            const int      nAdditionalInfo,
                            QCBORItem     *pDecodedItem)
{
   QCBORError uReturn = QCBOR_SUCCESS;

   if(nAdditionalInfo == LEN_IS_INDEFINITE) {
      uReturn = QCBOR_ERR_BAD_INT;
      goto Done;
   }

   if(nMajorType == CBOR_MAJOR_TYPE_POSITIVE_INT) {
      if (uArgument <= INT64_MAX) {
         pDecodedItem->val.int64 = (int64_t)uArgument;
         pDecodedItem->uDataType = QCBOR_TYPE_INT64;

      } else {
         pDecodedItem->val.uint64 = uArgument;
         pDecodedItem->uDataType  = QCBOR_TYPE_UINT64;
      }

   } else {
      if(uArgument <= INT64_MAX) {
         /* INT64_MIN is one further away from 0 than INT64_MAX
          * so the -1 here doesn't overflow. */
         pDecodedItem->val.int64 = (-(int64_t)uArgument) - 1;
         pDecodedItem->uDataType = QCBOR_TYPE_INT64;

      } else {
         pDecodedItem->val.uint64 = uArgument;
         pDecodedItem->uDataType  = QCBOR_TYPE_65BIT_NEG_INT;
      }
   }

Done:
   return uReturn;
}


/**
 * @brief Decode text and byte strings
 *
 * @param[in] pMe              Decoder context.
 * @param[in] bAllocate        Whether to allocate and copy string.
 * @param[in] nMajorType       Whether it is a byte or text string.
 * @param[in] uStrLen          The length of the string.
 * @param[in] nAdditionalInfo  Whether it is an indefinite-length string.
 * @param[out] pDecodedItem    The filled-in decoded item.
 *
 * @retval QCBOR_ERR_HIT_END          Unexpected end of input.
 * @retval QCBOR_ERR_STRING_ALLOCATE  Out of memory.
 * @retval QCBOR_ERR_STRING_TOO_LONG  String longer than SIZE_MAX - 4.
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR  Allocation requested, but no allocator
 *
 * This reads @c uStrlen bytes from the input and fills in @c
 * pDecodedItem. If @c bAllocate is true, then memory for the string
 * is allocated.
 */
static QCBORError
QCBOR_Private_DecodeString(QCBORDecodeContext  *pMe,
                           const bool           bAllocate,
                           const int            nMajorType,
                           const uint64_t       uStrLen,
                           const int            nAdditionalInfo,
                           QCBORItem           *pDecodedItem)
{
   QCBORError uReturn = QCBOR_SUCCESS;

   /* ---- Figure out the major type ---- */
   #if CBOR_MAJOR_TYPE_BYTE_STRING + 4 != QCBOR_TYPE_BYTE_STRING
   #error QCBOR_TYPE_BYTE_STRING not lined up with major type
   #endif

   #if CBOR_MAJOR_TYPE_TEXT_STRING + 4 != QCBOR_TYPE_TEXT_STRING
   #error QCBOR_TYPE_TEXT_STRING not lined up with major type
   #endif
   pDecodedItem->uDataType = (uint8_t)(nMajorType + 4);

   if(nAdditionalInfo == LEN_IS_INDEFINITE) {
      /* --- Just the head of an indefinite-length string --- */
      pDecodedItem->val.string = (UsefulBufC){NULL, QCBOR_STRING_LENGTH_INDEFINITE};

   } else {
      /* --- A definite-length string --- */
      /* --- (which might be a chunk of an indefinte-length string) --- */

      /* CBOR lengths can be 64 bits, but size_t is not 64 bits on all
       * CPUs.  This check makes the casts to size_t below safe.
       *
       * The max is 4 bytes less than the largest sizeof() so this can be
       * tested by putting a SIZE_MAX length in the CBOR test input (no
       * one will care the limit on strings is 4 bytes shorter).
       */
      if(uStrLen > SIZE_MAX-4) {
         uReturn = QCBOR_ERR_STRING_TOO_LONG;
         goto Done;
      }

      const UsefulBufC Bytes = UsefulInputBuf_GetUsefulBuf(&(pMe->InBuf), (size_t)uStrLen);
      if(UsefulBuf_IsNULLC(Bytes)) {
         /* Failed to get the bytes for this string item */
         uReturn = QCBOR_ERR_HIT_END;
         goto Done;
      }

      if(bAllocate) {
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
         /* --- Put string in allocated memory --- */

         /* Note that this is not where allocation to coalesce
          * indefinite-length strings is done. This is for when the
          * caller has requested all strings be allocated. Disabling
          * indefinite length strings also disables this allocate-all
          * option.
          */

         if(pMe->StringAllocator.pfAllocator == NULL) {
            uReturn = QCBOR_ERR_NO_STRING_ALLOCATOR;
            goto Done;
         }
         UsefulBuf NewMem = StringAllocator_Allocate(&(pMe->StringAllocator), (size_t)uStrLen);
         if(UsefulBuf_IsNULL(NewMem)) {
            uReturn = QCBOR_ERR_STRING_ALLOCATE;
            goto Done;
         }
         pDecodedItem->val.string = UsefulBuf_Copy(NewMem, Bytes);
         pDecodedItem->uDataAlloc = 1;
#else
         uReturn = QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED;
#endif /*  ! QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
      } else {
         /* --- Normal case with no string allocator --- */
         pDecodedItem->val.string = Bytes;
      }
   }

Done:
   return uReturn;
}


/**
 * @brief Decode array or map.
 *
 * @param[in] uDecodeMode3Bit            Decoder mode.
 * @param[in] nMajorType       Whether it is a byte or text string.
 * @param[in] uItemCount       The length of the string.
 * @param[in] nAdditionalInfo  Whether it is an indefinite-length.
 * @param[out] pDecodedItem    The filled-in decoded item.
 *
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED Indefinites disabled.
 * @retval QCBOR_ERR_ARRAY_DECODE_TOO_LONG     Too many items in array/map.
 *
 * Not much to do for arrays and maps. Just the type item count (but a
 * little messy because of ifdefs for indefinite-lengths and
 * map-as-array decoding).
 *
 * This also does the bulk of the work for @ref
 * QCBOR_DECODE_MODE_MAP_AS_ARRAY, a special mode to handle
 * arbitrarily complex map labels. This ifdefs out with
 * QCBOR_DISABLE_NON_INTEGER_LABELS.
 */
static QCBORError
QCBOR_Private_DecodeArrayOrMap(const uint8_t  uDecodeMode3Bit,
                               const int      nMajorType,
                               uint64_t       uItemCount,
                               const int      nAdditionalInfo,
                               QCBORItem     *pDecodedItem)
{
   QCBORError uReturn;

   /* ------ Sort out the data type ------ */
   #if QCBOR_TYPE_ARRAY != CBOR_MAJOR_TYPE_ARRAY
   #error QCBOR_TYPE_ARRAY value not lined up with major type
   #endif

   #if QCBOR_TYPE_MAP != CBOR_MAJOR_TYPE_MAP
   #error QCBOR_TYPE_MAP value not lined up with major type
   #endif
   pDecodedItem->uDataType = (uint8_t)nMajorType;
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   if(uDecodeMode3Bit == QCBOR_DECODE_MODE_MAP_AS_ARRAY && nMajorType == QCBOR_TYPE_MAP) {
      pDecodedItem->uDataType = QCBOR_TYPE_MAP_AS_ARRAY;
   }
#else
   (void)uDecodeMode3Bit;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */

   uReturn = QCBOR_SUCCESS;

   if(nAdditionalInfo == LEN_IS_INDEFINITE) {
      /* ------ Indefinite-length array/map ----- */
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
      pDecodedItem->val.uCount = QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH;
#else /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
      uReturn = QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED;
#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
   } else {
      /* ----- Definite-length array/map ----- */
      if(uItemCount > (nMajorType == QCBOR_TYPE_MAP ? QCBOR_MAX_ITEMS_IN_MAP : QCBOR_MAX_ITEMS_IN_ARRAY)) {
         uReturn = QCBOR_ERR_ARRAY_DECODE_TOO_LONG;

      } else {
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
         if(uDecodeMode3Bit == QCBOR_DECODE_MODE_MAP_AS_ARRAY && nMajorType == QCBOR_TYPE_MAP) {
            /* ------ Map as array ------ */
            uItemCount *= 2;
         }
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */

         /* cast OK because of check above */
         pDecodedItem->val.uCount = (uint16_t)uItemCount;
      }
   }

   return uReturn;
}


/**
 * @brief Decode a tag number.
 *
 * @param[in] uTagNumber       The length of the string.
 * @param[in] nAdditionalInfo  So this can be error-checked.
 * @param[out] pDecodedItem    The filled-in decoded item.
 *
 * @retval QCBOR_ERR_BAD_INT        nAdditionalInfo is LEN_IS_INDEFINITE.
 * @retval QCBOR_ERR_TAGS_DISABLED  QCBOR_DISABLE_TAGS is defined.
 *
 * Not much to do for tags, but fill in pDecodedItem and check for
 * error in nAdditionalInfo.
 */
static QCBORError
QCBOR_Private_DecodeTagNumber(const uint64_t uTagNumber,
                              const int      nAdditionalInfo,
                              QCBORItem     *pDecodedItem)
{
#ifndef QCBOR_DISABLE_TAGS
   if(nAdditionalInfo == LEN_IS_INDEFINITE) {
      return QCBOR_ERR_BAD_INT;
   } else {
      pDecodedItem->val.uTagNumber = uTagNumber;
      pDecodedItem->uDataType = QCBOR_TYPE_TAG_NUMBER;
      return QCBOR_SUCCESS;
   }
#else /* QCBOR_DISABLE_TAGS */
   (void)nAdditionalInfo;
   (void)uTagNumber;
   (void)pDecodedItem;
   return QCBOR_ERR_TAGS_DISABLED;
#endif /* QCBOR_DISABLE_TAGS */
}


#ifndef USEFULBUF_DISABLE_ALL_FLOAT

#if !defined(QCBOR_DISABLE_DECODE_CONFORMANCE) && !defined(QCBOR_DISABLE_PREFERRED_FLOAT)

static QCBORError
QCBORDecode_Private_HalfConformance(const double d, const uint8_t uDecodeMode3Bit)
{
   struct IEEE754_ToInt ToInt;

   /* Only need to check for conversion to integer because
    * half-precision is always preferred serialization. Don't
    * need special checker for half-precision because whole
    * numbers always convert perfectly from half to double.
    *
    * This catches half-precision with NaN payload too.
    *
    * The only thing allowed here is a double/half-precision that
    * can't be converted to anything but a double.
    */
   if(uDecodeMode3Bit >= QCBOR_DECODE_MODE_DCBOR) {
      ToInt = IEEE754_DoubleToInt(d);
      if(ToInt.type != QCBOR_TYPE_DOUBLE) {
         return QCBOR_ERR_DCBOR_CONFORMANCE;
      }
   }

   return QCBOR_SUCCESS;
}


static QCBORError
QCBORDecode_Private_SingleConformance(const float f, const uint8_t uDecodeMode3Bit)
{
   struct IEEE754_ToInt ToInt;
   IEEE754_union        ToSmaller;

   if(uDecodeMode3Bit >= QCBOR_DECODE_MODE_DCBOR) {
      /* See if it could have been encoded as an integer */
      ToInt = IEEE754_SingleToInt(f);
      if(ToInt.type == IEEE754_ToInt_IS_INT || ToInt.type == IEEE754_ToInt_IS_UINT) {
         return QCBOR_ERR_DCBOR_CONFORMANCE;
      }

      /* Make sure there is no NaN payload */
      if(IEEE754_SingleHasNaNPayload(f)) {
         return QCBOR_ERR_DCBOR_CONFORMANCE;
      }
   }

   /* See if it could have been encoded shorter */
   if(uDecodeMode3Bit >= QCBOR_DECODE_MODE_PREFERRED) {
      ToSmaller = IEEE754_SingleToHalf(f, true);
      if(ToSmaller.uSize != sizeof(float)) {
         return QCBOR_ERR_PREFERRED_CONFORMANCE;
      }
   }

   return QCBOR_SUCCESS;
}


static QCBORError
QCBORDecode_Private_DoubleConformance(const double d, uint8_t uDecodeMode3Bit)
{
   struct IEEE754_ToInt ToInt;
   IEEE754_union        ToSmaller;

   if(uDecodeMode3Bit >= QCBOR_DECODE_MODE_DCBOR) {
      /* See if it could have been encoded as an integer */
      ToInt = IEEE754_DoubleToInt(d);
      if(ToInt.type == IEEE754_ToInt_IS_INT || ToInt.type == IEEE754_ToInt_IS_UINT) {
         return QCBOR_ERR_DCBOR_CONFORMANCE;
      }
      /* Make sure there is no NaN payload */
      if(IEEE754_DoubleHasNaNPayload(d)) {
         return QCBOR_ERR_DCBOR_CONFORMANCE;
      }
   }

   /* See if it could have been encoded shorter */
   if(uDecodeMode3Bit >= QCBOR_DECODE_MODE_PREFERRED) {
      ToSmaller = IEEE754_DoubleToSmaller(d, true, true);
      if(ToSmaller.uSize != sizeof(double)) {
         return QCBOR_ERR_PREFERRED_CONFORMANCE;
      }
   }

   return QCBOR_SUCCESS;
}
#else /* ! QCBOR_DISABLE_DECODE_CONFORMANCE && ! QCBOR_DISABLE_PREFERRED_FLOAT */

static QCBORError
QCBORDecode_Private_SingleConformance(const float f, uint8_t uDecodeMode3Bit)
{
   (void)f;
   if(uDecodeMode3Bit>= QCBOR_DECODE_MODE_PREFERRED) {
      return QCBOR_ERR_CANT_CHECK_FLOAT_CONFORMANCE;
   } else {
      return QCBOR_SUCCESS;
   }
}

static QCBORError
QCBORDecode_Private_DoubleConformance(const double d, uint8_t uDecodeMode3Bit)
{
   (void)d;
   if(uDecodeMode3Bit>= QCBOR_DECODE_MODE_PREFERRED) {
      return QCBOR_ERR_CANT_CHECK_FLOAT_CONFORMANCE;
   } else {
      return QCBOR_SUCCESS;
   }
}
#endif /* ! QCBOR_DISABLE_DECODE_CONFORMANCE && ! QCBOR_DISABLE_PREFERRED_FLOAT */


/*
 * Decode a float
 */
static QCBORError
QCBOR_Private_DecodeFloat(const uint8_t  uDecodeMode3Bit,
                          const int      nAdditionalInfo,
                          const uint64_t uArgument,
                          QCBORItem     *pDecodedItem)
{
   QCBORError uReturn = QCBOR_SUCCESS;
   float      single;

   (void)single; /* Avoid unused error from various #ifndefs */

   switch(nAdditionalInfo) {
      case HALF_PREC_FLOAT: /* 25 */
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         /* Half-precision is returned as a double. The cast to
          * uint16_t is safe because the encoded value was 16 bits. It
          * was widened to 64 bits to be passed in here.
          */
         pDecodedItem->val.dfnum = IEEE754_HalfToDouble((uint16_t)uArgument);
         pDecodedItem->uDataType = QCBOR_TYPE_DOUBLE;

         uReturn = QCBORDecode_Private_HalfConformance(pDecodedItem->val.dfnum, uDecodeMode3Bit);
         if(uReturn != QCBOR_SUCCESS) {
            break;
         }
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         uReturn = FLOAT_ERR_CODE_NO_HALF_PREC(QCBOR_SUCCESS);
         break;

      case SINGLE_PREC_FLOAT: /* 26 */
         /* Single precision is normally returned as a double since
          * double is widely supported, there is no loss of precision,
          * it makes it easy for the caller in most cases and it can
          * be converted back to single with no loss of precision
          *
          * The cast to uint32_t is safe because the encoded value was
          * 32 bits. It was widened to 64 bits to be passed in here.
          */
         single = UsefulBufUtil_CopyUint32ToFloat((uint32_t)uArgument);
         uReturn = QCBORDecode_Private_SingleConformance(single, uDecodeMode3Bit);
         if(uReturn != QCBOR_SUCCESS) {
            break;
         }

#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         /* In the normal case, use HW to convert float to
          * double. */
         pDecodedItem->val.dfnum = (double)single;
         pDecodedItem->uDataType = QCBOR_TYPE_DOUBLE;
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
         /* Use of float HW is disabled, return as a float. */
         pDecodedItem->val.fnum  = single;
         pDecodedItem->uDataType = QCBOR_TYPE_FLOAT;

         /* IEEE754_FloatToDouble() could be used here to return as
          * a double, but it adds object code and most likely
          * anyone disabling FLOAT HW use doesn't care about floats
          * and wants to save object code.
          */
#endif /* ! QCBOR_DISABLE_FLOAT_HW_USE */
         uReturn = FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS);
         break;

      case DOUBLE_PREC_FLOAT: /* 27 */
         pDecodedItem->val.dfnum = UsefulBufUtil_CopyUint64ToDouble(uArgument);
         pDecodedItem->uDataType = QCBOR_TYPE_DOUBLE;

         uReturn = QCBORDecode_Private_DoubleConformance(pDecodedItem->val.dfnum, uDecodeMode3Bit);
         if(uReturn != QCBOR_SUCCESS) {
            break;
         }
         uReturn = FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS);
         break;
   }

   return uReturn;
}
#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT */



/* Make sure #define value line up as DecodeSimple counts on this. */
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

/**
 * @brief Decode major type 7 -- true, false, floating-point, break...
 *
 * @param[in] nAdditionalInfo   The lower five bits from the initial byte.
 * @param[in] uArgument         The argument from the head.
 * @param[out] pDecodedItem     The filled in decoded item.
 *
 * @retval QCBOR_ERR_HALF_PRECISION_DISABLED Half-precision in input, but decode
 *                                           of half-precision disabled
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED      Float-point in input, but all float
 *                                           decode is disabled.
 * @retval QCBOR_ERR_BAD_TYPE_7              Not-allowed representation of simple
 *                                           type in input.
 */
static QCBORError
QCBOR_Private_DecodeType7(const uint8_t  uDecodeMode3Bit,
                          const int      nAdditionalInfo,
                          const uint64_t uArgument,
                          QCBORItem     *pDecodedItem)
{
   QCBORError uReturn = QCBOR_SUCCESS;

   /* uAdditionalInfo is 5 bits from the initial byte. Compile time
    * checks above make sure uAdditionalInfo values line up with
    * uDataType values.  DecodeHead() never returns an AdditionalInfo
    * > 0x1f so cast is safe.
    */
   pDecodedItem->uDataType = (uint8_t)nAdditionalInfo;

   switch(nAdditionalInfo) {
      /* No check for ADDINFO_RESERVED1 - ADDINFO_RESERVED3 as they
       * are caught before this is called.
       */

      case HALF_PREC_FLOAT: /* 25 */
      case SINGLE_PREC_FLOAT: /* 26 */
      case DOUBLE_PREC_FLOAT: /* 27 */
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
         uReturn = QCBOR_Private_DecodeFloat(uDecodeMode3Bit, nAdditionalInfo, uArgument, pDecodedItem);
#else
         uReturn = QCBOR_ERR_ALL_FLOAT_DISABLED;
#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT */
         break;

      case CBOR_SIMPLEV_FALSE: /* 20 */
      case CBOR_SIMPLEV_TRUE:  /* 21 */
      case CBOR_SIMPLEV_NULL:  /* 22 */
      case CBOR_SIMPLEV_UNDEF: /* 23 */
      case CBOR_SIMPLE_BREAK:  /* 31 */
#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
         if(uDecodeMode3Bit >= QCBOR_ENCODE_MODE_DCBOR &&
            nAdditionalInfo == CBOR_SIMPLEV_UNDEF) {
            uReturn = QCBOR_ERR_DCBOR_CONFORMANCE;
            goto Done;
         }
#endif /* ! QCBOR_DISABLE_DECODE_CONFORMANCE */
         break; /* nothing to do */

      case CBOR_SIMPLEV_ONEBYTE: /* 24 */
         if(uArgument <= CBOR_SIMPLE_BREAK) {
            /* This takes out f8 00 ... f8 1f which should be encoded
             * as e0 … f7 -- preferred serialization check for simple values.
             */
            uReturn = QCBOR_ERR_BAD_TYPE_7;
            goto Done;
         }
         /* FALLTHROUGH */

      default: /* 0-19 */
#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
         if(uDecodeMode3Bit >= QCBOR_ENCODE_MODE_DCBOR &&
            (uArgument < CBOR_SIMPLEV_FALSE || uArgument > CBOR_SIMPLEV_NULL)) {
            uReturn = QCBOR_ERR_DCBOR_CONFORMANCE;
            goto Done;
         }
#endif /* !QCBOR_DISABLE_DECODE_CONFORMANCE */

         pDecodedItem->uDataType = QCBOR_TYPE_UKNOWN_SIMPLE;
         /* QCBOR_Private_DecodeHead() will make uArgument equal to
          * nAdditionalInfo when nAdditionalInfo is < 24. This cast is
          * safe because the 2, 4 and 8 byte lengths of uNumber are in
          * the double/float cases above
          */
         pDecodedItem->val.uSimple = (uint8_t)uArgument;
         break;
   }

Done:
   return uReturn;
}


/**
 * @brief Decode a single primitive data item (decode layer 6).
 *
 * @param[in] pMe                Decoder context.
 * @param[in] bAllocateStrings   If true, use allocator for strings.
 * @param[out] pDecodedItem      The filled-in decoded item.
 *
 * @retval QCBOR_ERR_UNSUPPORTED             Encountered unsupported/reserved
 *                                           features
 * @retval QCBOR_ERR_HIT_END                 Unexpected end of input
 * @retval QCBOR_ERR_INT_OVERFLOW            Too-large negative encountered
 * @retval QCBOR_ERR_STRING_ALLOCATE         Out of memory.
 * @retval QCBOR_ERR_STRING_TOO_LONG         String longer than SIZE_MAX - 4.
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR     Allocation requested, but no allocator
 * @retval QCBOR_ERR_HALF_PRECISION_DISABLED Half-precision in input, but decode
 *                                           of half-precision disabled
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED      Float-point in input, but all
 *                                           float decode is disabled.
 * @retval QCBOR_ERR_BAD_TYPE_7              Not-allowed representation of
 *                                           simple type in input.
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED  Indefinite length map/array
 *                                              in input, but indefinite
 *                                              lengths disabled.
 * @retval QCBOR_ERR_BAD_INT                 nAdditionalInfo indicated indefinte.
 * @retval QCBOR_ERR_ARRAY_DECODE_TOO_LONG   Too many items in array/map.
 * @retval QCBOR_ERR_TAGS_DISABLED           QCBOR_DISABLE_TAGS is defined.
 *
 * This decodes the most primitive/atomic data item. It does no
 * combining of data items.
 */
static QCBORError
QCBOR_Private_DecodeAtomicDataItem(QCBORDecodeContext  *pMe,
                                   const bool           bAllocateStrings,
                                   QCBORItem           *pDecodedItem)
{
   QCBORError uReturn;
   int       nMajorType = 0;
   uint64_t  uArgument = 0;
   int       nAdditionalInfo = 0;
   uint8_t   uDecodeMode3Bit = pMe->uDecodeMode & QCBOR_DECODE_MODE_MASK;

   memset(pDecodedItem, 0, sizeof(QCBORItem));

   /* Decode the "head" that every CBOR item has into the major type,
    * argument and the additional info.
    */
   uReturn = QCBOR_Private_DecodeHead(&(pMe->InBuf),
#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
                                      // TODO: make this prettier; will optimizer take out stuff without ifdef?
                                      uDecodeMode3Bit >= QCBOR_DECODE_MODE_PREFERRED,
#endif /* !QCBOR_DISABLE_DECODE_CONFORMANCE */
                                      &nMajorType,
                                      &uArgument,
                                      &nAdditionalInfo);

   if(uReturn != QCBOR_SUCCESS) {
      return uReturn;
   }

   /* All the functions below get inlined by the optimizer. This code
    * is easier to read with them all being similar functions, even if
    * some functions don't do much.
    */
   switch (nMajorType) {
      case CBOR_MAJOR_TYPE_POSITIVE_INT: /* Major type 0 */
      case CBOR_MAJOR_TYPE_NEGATIVE_INT: /* Major type 1 */
         return QCBOR_Private_DecodeInteger(nMajorType, uArgument, nAdditionalInfo, pDecodedItem);
         break;

      case CBOR_MAJOR_TYPE_BYTE_STRING: /* Major type 2 */
      case CBOR_MAJOR_TYPE_TEXT_STRING: /* Major type 3 */
         return QCBOR_Private_DecodeString(pMe, bAllocateStrings, nMajorType, uArgument, nAdditionalInfo, pDecodedItem);
         break;

      case CBOR_MAJOR_TYPE_ARRAY: /* Major type 4 */
      case CBOR_MAJOR_TYPE_MAP:   /* Major type 5 */
         return QCBOR_Private_DecodeArrayOrMap(uDecodeMode3Bit, nMajorType, uArgument, nAdditionalInfo, pDecodedItem);
         break;

      case CBOR_MAJOR_TYPE_TAG: /* Major type 6, tag numbers */
         return QCBOR_Private_DecodeTagNumber(uArgument, nAdditionalInfo, pDecodedItem);
         break;

      case CBOR_MAJOR_TYPE_SIMPLE:
         /* Major type 7: float, double, true, false, null... */
         return QCBOR_Private_DecodeType7(uDecodeMode3Bit, nAdditionalInfo, uArgument, pDecodedItem);
         break;

      default:
         /* Never happens because DecodeHead() should never return > 7 */
         return QCBOR_ERR_UNSUPPORTED;
         break;
   }
}


/**
 * @brief Process indefinite-length strings (decode layer 5).
 *
 * @param[in] pMe   Decoder context
 * @param[out] pDecodedItem  The decoded item that work is done on.
 *
 * @retval QCBOR_ERR_UNSUPPORTED             Encountered unsupported/reserved
 *                                           features
 * @retval QCBOR_ERR_HIT_END                 Unexpected end of input
 * @retval QCBOR_ERR_INT_OVERFLOW            Too-large negative encountered
 * @retval QCBOR_ERR_STRING_ALLOCATE         Out of memory.
 * @retval QCBOR_ERR_STRING_TOO_LONG         String longer than SIZE_MAX - 4.
 * @retval QCBOR_ERR_HALF_PRECISION_DISABLED Half-precision in input, but decode
 *                                           of half-precision disabled
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED      Float-point in input, but all
 *                                           float decode is disabled.
 * @retval QCBOR_ERR_BAD_TYPE_7              Not-allowed representation of
 *                                           simple type in input.
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED  Indefinite length map/array
 *                                              in input, but indefinite
 *                                              lengths disabled.
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR     Indefinite-length string in input,
 *                                           but no string allocator.
 * @retval QCBOR_ERR_INDEFINITE_STRING_CHUNK  Error in indefinite-length string.
 * @retval QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED  Indefinite-length string in
 *                                               input, but indefinite-length
 *                                               strings are disabled.
 *
 * If @c pDecodedItem is not an indefinite-length string, this does nothing.
 *
 * If it is, this loops getting the subsequent chunk data items that
 * make up the string.  The string allocator is used to make a
 * contiguous buffer for the chunks.  When this completes @c
 * pDecodedItem contains the put-together string.
 *
 * Code Reviewers: THIS FUNCTION DOES A LITTLE POINTER MATH
 */
static QCBORError
QCBORDecode_Private_GetNextFullString(QCBORDecodeContext *pMe,
                                      QCBORItem          *pDecodedItem)
{
   /* Aproximate stack usage
    *                                             64-bit      32-bit
    *   local vars                                    32          16
    *   2 UsefulBufs                                  32          16
    *   QCBORItem                                     56          52
    *   TOTAL                                        120          74
    */
   QCBORError uReturn;

   /* A note about string allocation -- Memory for strings is
    * allocated either because 1) indefinte-length string chunks are
    * being coalecsed or 2) caller has requested all strings be
    * allocated.  The first case is handed below here. The second case
    * is handled in DecodeString if the bAllocate is true. That
    * boolean originates here with pMe->bStringAllocateAll immediately
    * below. That is, QCBOR_Private_DecodeAtomicDataItem() is called
    * in two different contexts here 1) main-line processing which is
    * where definite-length strings need to be allocated if
    * bStringAllocateAll is true and 2) processing chunks of
    * indefinite-lengths strings in in which case there must be no
    * allocation.
    */


   uReturn = QCBOR_Private_DecodeAtomicDataItem(pMe, pMe->bStringAllocateAll, pDecodedItem);
   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }

   /* This is where out-of-place break is detected for the whole
    * decoding stack. Break is an error for everything that calls
    * QCBORDecode_Private_GetNextFullString(), so the check is
    * centralized here.
    */
   if(pDecodedItem->uDataType == QCBOR_TYPE_BREAK) {
      uReturn = QCBOR_ERR_BAD_BREAK;
      goto Done;
   }


   /* Skip out if not an indefinite-length string */
   const uint8_t uStringType = pDecodedItem->uDataType;
   if(uStringType != QCBOR_TYPE_BYTE_STRING &&
      uStringType != QCBOR_TYPE_TEXT_STRING) {
      goto Done;
   }
   if(pDecodedItem->val.string.len != QCBOR_STRING_LENGTH_INDEFINITE) {
      goto Done;
   }

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
   /* Can't decode indefinite-length strings without a string allocator */
   if(!pMe->StringAllocator.pfAllocator) {
      uReturn = QCBOR_ERR_NO_STRING_ALLOCATOR;
      goto Done;
   }

   /* Loop getting chunks of the indefinite-length string */
   UsefulBufC FullString = NULLUsefulBufC;

   for(;;) {
      /* Get QCBORItem for next chunk */
      QCBORItem StringChunkItem;
      /* Pass false to DecodeAtomicDataItem() because the individual
       * string chunks in an indefinite-length must not be
       * allocated. They are always copied into the allocated
       * contiguous buffer allocated here.
       */
      uReturn = QCBOR_Private_DecodeAtomicDataItem(pMe, false, &StringChunkItem);
      if(uReturn) {
         break;
      }

      /* Is item is the marker for end of the indefinite-length string? */
      if(StringChunkItem.uDataType == QCBOR_TYPE_BREAK) {
         /* String is complete */
         pDecodedItem->val.string = FullString;
         pDecodedItem->uDataAlloc = 1;
         break;
      }

      /* All chunks must be of the same type, the type of the item
       * that introduces the indefinite-length string. This also
       * catches errors where the chunk is not a string at all and an
       * indefinite-length string inside an indefinite-length string.
       */
      if(StringChunkItem.uDataType != uStringType ||
         StringChunkItem.val.string.len == QCBOR_STRING_LENGTH_INDEFINITE) {
         uReturn = QCBOR_ERR_INDEFINITE_STRING_CHUNK;
         break;
      }

      if (StringChunkItem.val.string.len > 0) {
         /* The first time throurgh FullString.ptr is NULL and this is
          * equivalent to StringAllocator_Allocate(). Subsequently it is
          * not NULL and a reallocation happens.
          */
         UsefulBuf NewMem = StringAllocator_Reallocate(&(pMe->StringAllocator),
                                                       FullString.ptr,
                                                       FullString.len + StringChunkItem.val.string.len);
         if(UsefulBuf_IsNULL(NewMem)) {
            uReturn = QCBOR_ERR_STRING_ALLOCATE;
            break;
         }

         /* Copy new string chunk to the end of accumulated string */
         FullString = UsefulBuf_CopyOffset(NewMem, FullString.len, StringChunkItem.val.string);
      }
   }

   if(uReturn != QCBOR_SUCCESS && !UsefulBuf_IsNULLC(FullString)) {
      /* Getting the item failed, clean up the allocated memory */
      StringAllocator_Free(&(pMe->StringAllocator), FullString.ptr);
   }
#else /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
   uReturn = QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED;
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */

Done:
   return uReturn;
}


#ifndef QCBOR_DISABLE_TAGS
/**
 * @brief This converts a tag number to a shorter mapped value for storage.
 *
 * @param[in] pMe                 The decode context.
 * @param[in] uUnMappedTag        The tag number to map
 * @param[out] puMappedTagNumber  The stored tag number.
 *
 * @return error code.
 *
 * The main point of mapping tag numbers is make QCBORItem
 * smaller. With this mapping storage of 4 tags takes up 8
 * bytes. Without, it would take up 32 bytes.
 *
 * This maps tag numbers greater than QCBOR_LAST_UNMAPPED_TAG.
 * QCBOR_LAST_UNMAPPED_TAG is a little smaller than MAX_UINT16.
 *
 * See also UnMapTagNumber() and @ref QCBORItem.
 */
static QCBORError
QCBORDecode_Private_MapTagNumber(QCBORDecodeContext *pMe,
                                 const uint64_t      uUnMappedTag,
                                 uint16_t           *puMappedTagNumber)
{
   if(uUnMappedTag > QCBOR_LAST_UNMAPPED_TAG) {
      unsigned uTagMapIndex;
      /* Is there room in the tag map, or is it in it already? */
      for(uTagMapIndex = 0; uTagMapIndex < QCBOR_NUM_MAPPED_TAGS; uTagMapIndex++) {
         if(pMe->auMappedTags[uTagMapIndex] == CBOR_TAG_INVALID64) {
            break;
         }
         if(pMe->auMappedTags[uTagMapIndex] == uUnMappedTag) {
            break;
         }
      }
      if(uTagMapIndex >= QCBOR_NUM_MAPPED_TAGS) {
         return QCBOR_ERR_TOO_MANY_TAGS;
      }

      /* Covers the cases where tag is new and were it is already in the map */
      pMe->auMappedTags[uTagMapIndex] = uUnMappedTag;
      *puMappedTagNumber = (uint16_t)(uTagMapIndex + QCBOR_LAST_UNMAPPED_TAG + 1);

   } else {
      *puMappedTagNumber = (uint16_t)uUnMappedTag;
   }

   return QCBOR_SUCCESS;
}


/**
 * @brief This converts a mapped tag number to the actual tag number.
 *
 * @param[in] pMe               The decode context.
 * @param[in] uMappedTagNumber  The stored tag number.
 *
 * @return The actual tag number is returned or
 *         @ref CBOR_TAG_INVALID64 on error.
 *
 * This is the reverse of MapTagNumber()
 */
static uint64_t
QCBORDecode_Private_UnMapTagNumber(const QCBORDecodeContext *pMe,
                                   const uint16_t            uMappedTagNumber)
{
   if(uMappedTagNumber <= QCBOR_LAST_UNMAPPED_TAG) {
      return uMappedTagNumber;
   } else if(uMappedTagNumber == CBOR_TAG_INVALID16) {
      return CBOR_TAG_INVALID64;
   } else {
      /* This won't be negative because of code below in
       * MapTagNumber()
       */
      const unsigned uIndex = uMappedTagNumber - (QCBOR_LAST_UNMAPPED_TAG + 1);
      return pMe->auMappedTags[uIndex];
   }
}


static const struct QCBORTagDecoderEntry *
QCBORDecode_Private_LookUpTagDecoder(const struct QCBORTagDecoderEntry *pTagContentTable,
                                     const uint64_t                     uTagNumber)
{
   const struct QCBORTagDecoderEntry *pTE;

   if(pTagContentTable == NULL) {
      return NULL;
   }

   for(pTE = pTagContentTable; pTE->uTagNumber != CBOR_TAG_INVALID64; pTE++) {
      if(pTE->uTagNumber == uTagNumber || pTE->uTagNumber == CBOR_TAG_ANY) {
         break;
      }
   }

   if(pTE->uTagNumber == CBOR_TAG_INVALID64) {
      return NULL;
   }

   return pTE;
}
#endif /* ! QCBOR_DISABLE_TAGS */


/**
 * @brief Aggregate all tags wrapping a data item (decode layer 4).
 *
 * @param[in] pMe            Decoder context
 * @param[out] pDecodedItem  The decoded item that work is done on.
 *
 * @retval QCBOR_ERR_UNSUPPORTED             Encountered unsupported/reserved
 *                                           features
 * @retval QCBOR_ERR_HIT_END                 Unexpected end of input
 * @retval QCBOR_ERR_INT_OVERFLOW            Too-large negative encountered
 * @retval QCBOR_ERR_STRING_ALLOCATE         Out of memory.
 * @retval QCBOR_ERR_STRING_TOO_LONG         String longer than SIZE_MAX - 4.
 * @retval QCBOR_ERR_HALF_PRECISION_DISABLED Half-precision in input, but decode
 *                                           of half-precision disabled
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED      Float-point in input, but all
 *                                           float decode is disabled.
 * @retval QCBOR_ERR_BAD_TYPE_7              Not-allowed representation of
 *                                           simple type in input.
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED  Indefinite length map/array
 *                                              in input, but indefinite
 *                                              lengths disabled.
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR     Indefinite-length string in input,
 *                                           but no string allocator.
 * @retval QCBOR_ERR_INDEFINITE_STRING_CHUNK  Error in indefinite-length string.
 * @retval QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED  Indefinite-length string in
 *                                               input, but indefinite-length
 *                                               strings are disabled.
 * @retval QCBOR_ERR_TOO_MANY_TAGS           Too many tag numbers on item.
 *
 * This loops getting atomic data items until one is not a tag
 * number.  Usually this is largely pass-through because most
 * item are not tag numbers.
 */
static QCBORError
QCBORDecode_Private_GetNextTagNumber(QCBORDecodeContext *pMe,
                                     QCBORItem          *pDecodedItem)
{
#ifndef QCBOR_DISABLE_TAGS
   int         nIndex;
   QCBORError  uErr;
   uint16_t    uMappedTagNumber;
   QCBORError  uReturn;

   /* Accummulate the tag numbers from multiple items here and then
    * copy them into the last item, the non-tag-number item.
    */
   QCBORMappedTagNumbers  auTagNumbers;;

   /* Initialize to CBOR_TAG_INVALID16 */
   #if CBOR_TAG_INVALID16 != 0xffff
   /* Be sure the memset is initializing to CBOR_TAG_INVALID16 */
   #err CBOR_TAG_INVALID16 tag not defined as expected
   #endif
   memset(auTagNumbers, 0xff, sizeof(auTagNumbers));

   /* Loop fetching data items until the item fetched is not a tag number */
   uReturn = QCBOR_SUCCESS;
   for(nIndex = 0; ; nIndex++) {
      uErr = QCBORDecode_Private_GetNextFullString(pMe, pDecodedItem);
      if(uErr != QCBOR_SUCCESS) {
         uReturn = uErr;
         break;
      }

      if(pDecodedItem->uDataType != QCBOR_TYPE_TAG_NUMBER) {
         /* Successful exit from loop; maybe got some tags, maybe not */
         memcpy(pDecodedItem->auTagNumbers, auTagNumbers, sizeof(auTagNumbers));
         break;
      }

      if(nIndex >= QCBOR_MAX_TAGS_PER_ITEM) {
         /* No room in the item's tag number array */
         uReturn = QCBOR_ERR_TOO_MANY_TAGS;
         /* Continue on to get all tag numbers wrapping this item even
          * though it is erroring out in the end. This allows decoding
          * to continue. This is a QCBOR resource limit error, not a
          * problem with being well-formed CBOR.
          */
         continue;
      }

      /* Map the tag number */
      uMappedTagNumber = 0;
      uReturn = QCBORDecode_Private_MapTagNumber(pMe, pDecodedItem->val.uTagNumber, &uMappedTagNumber);
      /* Continue even on error so as to consume all tag numbers
       * wrapping this data item so decoding can go on. If
       * QCBORDecode_Private_MapTagNumber() errors once it will
       * continue to error.
       */

      auTagNumbers[nIndex] = uMappedTagNumber;
   }

   return uReturn;

#else /* ! QCBOR_DISABLE_TAGS */

   return QCBORDecode_Private_GetNextFullString(pMe, pDecodedItem);

#endif /* ! QCBOR_DISABLE_TAGS */
}


/**
 * @brief Combine a map entry label and value into one item (decode layer 3).
 *
 * @param[in] pMe            Decoder context
 * @param[out] pDecodedItem  The decoded item that work is done on.
 *
 * @retval QCBOR_ERR_UNSUPPORTED             Encountered unsupported/reserved
 *                                           features
 * @retval QCBOR_ERR_HIT_END                 Unexpected end of input
 * @retval QCBOR_ERR_INT_OVERFLOW            Too-large negative encountered
 * @retval QCBOR_ERR_STRING_ALLOCATE         Out of memory.
 * @retval QCBOR_ERR_STRING_TOO_LONG         String longer than SIZE_MAX - 4.
 * @retval QCBOR_ERR_HALF_PRECISION_DISABLED Half-precision in input, but decode
 *                                           of half-precision disabled
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED      Float-point in input, but all
 *                                           float decode is disabled.
 * @retval QCBOR_ERR_BAD_TYPE_7              Not-allowed representation of
 *                                           simple type in input.
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED  Indefinite length map/array
 *                                              in input, but indefinite
 *                                              lengths disabled.
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR     Indefinite-length string in input,
 *                                           but no string allocator.
 * @retval QCBOR_ERR_INDEFINITE_STRING_CHUNK  Error in indefinite-length string.
 * @retval QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED  Indefinite-length string in
 *                                               input, but indefinite-length
 *                                               strings are disabled.
 * @retval QCBOR_ERR_TOO_MANY_TAGS           Too many tag numbers on item.
 * @retval QCBOR_ERR_ARRAY_DECODE_TOO_LONG   Too many items in array.
 * @retval QCBOR_ERR_MAP_LABEL_TYPE          Map label not string or integer.
 *
 * If the current nesting level is a map, then this combines pairs of
 * items into one data item with a label and value.
 *
 * This is passthrough if the current nesting level is not a map.
 *
 * This also implements maps-as-array mode where a map is treated like
 * an array to allow caller to do their own label processing.
 */
static QCBORError
QCBORDecode_Private_GetNextMapEntry(QCBORDecodeContext *pMe,
                                    QCBORItem          *pDecodedItem,
                                    uint32_t           *puLabelEndOffset)
{
   QCBORItem  LabelItem;
   QCBORError uErr, uErr2;

   uErr = QCBORDecode_Private_GetNextTagNumber(pMe, pDecodedItem);
   if(QCBORDecode_IsUnrecoverableError(uErr)) {
      goto Done;
   }

   if(!DecodeNesting_IsCurrentTypeMap(&(pMe->nesting))) {
      /* Not decoding a map. Nothing to do. */
      /* When decoding maps-as-arrays, the type will be
       * QCBOR_TYPE_MAP_AS_ARRAY and this function will exit
       * here. This is now map processing for maps-as-arrays is not
       * done. */
      goto Done;
   }

   /* Decoding a map entry, so the item decoded above was the label */
   LabelItem = *pDecodedItem;

   if(puLabelEndOffset != NULL) {
       /* Cast is OK because lengths are all 32-bit in QCBOR */
       *puLabelEndOffset = (uint32_t)UsefulInputBuf_Tell(&(pMe->InBuf));
    }

   /* Get the value of the map item */
   uErr2 = QCBORDecode_Private_GetNextTagNumber(pMe, pDecodedItem);
   if(QCBORDecode_IsUnrecoverableError(uErr2)) {
      uErr = uErr2;
      goto Done;
   }
   if(uErr2 != QCBOR_SUCCESS) {
      /* The recoverable error for the value overrides the recoverable
       * error for the label, if there was an error for the label */
      uErr = uErr2;
   }

   /* Combine the label item and value item into one */
   pDecodedItem->uLabelAlloc = LabelItem.uDataAlloc;
   pDecodedItem->uLabelType  = LabelItem.uDataType;

#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   /* TODO: QCBOR_DECODE_MODE_MAP_STRINGS_ONLY might have been a bad idea. Maybe
    * get rid of it in QCBOR 2.0
    */
   if((pMe->uDecodeMode & QCBOR_DECODE_MODE_MASK) == QCBOR_DECODE_MODE_MAP_STRINGS_ONLY &&
      LabelItem.uDataType != QCBOR_TYPE_TEXT_STRING) {
      uErr = QCBOR_ERR_MAP_LABEL_TYPE;
      goto Done;
   }
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */

   switch(LabelItem.uDataType) {
      case QCBOR_TYPE_INT64:
         pDecodedItem->label.int64 = LabelItem.val.int64;
         break;

#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
      case QCBOR_TYPE_UINT64:
         pDecodedItem->label.uint64 = LabelItem.val.uint64;
         break;

      case QCBOR_TYPE_TEXT_STRING:
      case QCBOR_TYPE_BYTE_STRING:
         pDecodedItem->label.string = LabelItem.val.string;
         break;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */

      default:
         /* It is possible to skip over labels that are non-aggregate
          * types like floats, but not to skip over labels that are
          * arrays or maps. We might eventually handle more label
          * types like floats as they are not too hard and we now
          * have QCBOR_DISABLE_NON_INTEGER_LABELS */
         if(!pMe->bAllowAllLabels || QCBORItem_IsMapOrArray(LabelItem)) {
            uErr = QCBOR_ERR_MAP_LABEL_TYPE;
            goto Done;
         }
   }

Done:
   return uErr;
}


#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
/**
 * @brief Peek and see if next data item is a break;
 *
 * param[in]  pUIB            UsefulInputBuf to read from.
 * @param[out] pbNextIsBreak   Indicate if next was a break or not.
 *
 * @return  Any decoding error.
 *
 * See if next item is a CBOR break. If it is, it is consumed,
 * if not it is not consumed.
*/
static QCBORError
QCBOR_Private_NextIsBreak(QCBORDecodeContext *pMe, bool *pbNextIsBreak)
{
   *pbNextIsBreak = false;
   if(UsefulInputBuf_BytesUnconsumed(&(pMe->InBuf)) != 0) {
      QCBORItem Peek;
      size_t uPeek = UsefulInputBuf_Tell(&(pMe->InBuf));
      QCBORError uReturn = QCBOR_Private_DecodeAtomicDataItem(pMe, false, &Peek);
      if(uReturn != QCBOR_SUCCESS) {
         return uReturn;
      }
      if(Peek.uDataType != QCBOR_TYPE_BREAK) {
         /* It is not a break, rewind so it can be processed normally. */
         UsefulInputBuf_Seek(&(pMe->InBuf), uPeek);
      } else {
         *pbNextIsBreak = true;
      }
   }

   return QCBOR_SUCCESS;
}
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */


/**
 * @brief Ascend up nesting levels if all items in them have been consumed.
 *
 * @param[in] pMe       The decode context.
 * @param[in] bMarkEnd  If true mark end of maps/arrays with count of zero.
 * @param[out] pbBreak  Set to true if extra break was consumed.
 *
 * An item was just consumed, now figure out if it was the
 * end of an array/map map that can be closed out. That
 * may in turn close out the above array/map...
 *
 * When ascending indefinite-length arrays and maps, this will correctly
 * consume the break for the level above. This is a problem for the
 * implementation of QCBORDecode_GetArray() that must not return
 * that break. @c pbBreak is set to true to indicate that one
 * byte should be removed.
 *
 * Improvement: this could reduced further if indef is disabled
 */
static QCBORError
QCBORDecode_Private_NestLevelAscender(QCBORDecodeContext *pMe, bool bMarkEnd, bool *pbBreak)
{
   QCBORError uReturn;

   /* Loop ascending nesting levels as long as there is ascending to do */
   while(!DecodeNesting_IsCurrentAtTop(&(pMe->nesting))) {
      if(pbBreak) {
         *pbBreak = false;
      }

      if(DecodeNesting_IsCurrentBstrWrapped(&(pMe->nesting))) {
         /* Nesting level is bstr-wrapped CBOR */

         /* Ascent for bstr-wrapped CBOR is always by explicit call
          * so no further ascending can happen.
          */
         break;

      } else if(DecodeNesting_IsCurrentDefiniteLength(&(pMe->nesting))) {
         /* Level is a definite-length array/map */

         /* Decrement the item count the definite-length array/map */
         DecodeNesting_DecrementDefiniteLengthMapOrArrayCount(&(pMe->nesting));
         if(!DecodeNesting_IsEndOfDefiniteLengthMapOrArray(&(pMe->nesting))) {
             /* Didn't close out array/map, so all work here is done */
             break;
          }
          /* All items in a definite-length array were consumed so it
           * is time to ascend one level. This happens below.
           */

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
      } else {
         /* Level is an indefinite-length array/map. */

         /* Check for a break which is what ends indefinite-length arrays/maps */
         bool bIsBreak = false;
         uReturn = QCBOR_Private_NextIsBreak(pMe, &bIsBreak);
         if(uReturn != QCBOR_SUCCESS) {
            goto Done;
         }

         if(!bIsBreak) {
            /* Not a break so array/map does not close out. All work is done */
            break;
         }

         /* It was a break in an indefinitelength map / array so
          * it is time to ascend one level.
          */
         if(pbBreak) {
            *pbBreak = true;
         }

#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
      }


      /* All items in the array/map have been consumed. */

      /* But ascent in bounded mode is only by explicit call to
       * QCBORDecode_ExitBoundedMode().
       */
      if(DecodeNesting_IsCurrentBounded(&(pMe->nesting))) {
         /* Set the count to zero for definite-length arrays to indicate
         * cursor is at end of bounded array/map */
         if(bMarkEnd) {
            /* Used for definite and indefinite to signal end */
            DecodeNesting_ZeroMapOrArrayCount(&(pMe->nesting));

         }
         break;
      }

      /* Finally, actually ascend one level. */
      DecodeNesting_Ascend(&(pMe->nesting));
   }

   uReturn = QCBOR_SUCCESS;

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
Done:
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

   return uReturn;
}


/**
 * @brief Ascending & Descending out of nesting levels (decode layer 2).
 *
 * @param[in] pMe            Decoder context
 * @param[out] pbBreak       Set to true if extra break was consumed.
 * @param[out] pDecodedItem  The decoded item that work is done on.

 * @retval QCBOR_ERR_UNSUPPORTED             Encountered unsupported/reserved
 *                                           features
 * @retval QCBOR_ERR_HIT_END                 Unexpected end of input
 * @retval QCBOR_ERR_INT_OVERFLOW            Too-large negative encountered
 * @retval QCBOR_ERR_STRING_ALLOCATE         Out of memory.
 * @retval QCBOR_ERR_STRING_TOO_LONG         String longer than SIZE_MAX - 4.
 * @retval QCBOR_ERR_HALF_PRECISION_DISABLED Half-precision in input, but decode
 *                                           of half-precision disabled
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED      Float-point in input, but all
 *                                           float decode is disabled.
 * @retval QCBOR_ERR_BAD_TYPE_7              Not-allowed representation of
 *                                           simple type in input.
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED  Indefinite length map/array
 *                                              in input, but indefinite
 *                                              lengths disabled.
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR     Indefinite-length string in input,
 *                                           but no string allocator.
 * @retval QCBOR_ERR_INDEFINITE_STRING_CHUNK  Error in indefinite-length string.
 * @retval QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED  Indefinite-length string in
 *                                               input, but indefinite-length
 *                                               strings are disabled.
 * @retval QCBOR_ERR_TOO_MANY_TAGS           Too many tag numbers on item.
 * @retval QCBOR_ERR_ARRAY_DECODE_TOO_LONG   Too many items in array.
 * @retval QCBOR_ERR_MAP_LABEL_TYPE          Map label not string or integer.
 * @retval QCBOR_ERR_NO_MORE_ITEMS           Need more items for map or array.
 * @retval QCBOR_ERR_BAD_BREAK               Indefinite-length break in wrong
 *                                           place.
 * @retval QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP  Nesting deeper than QCBOR
 *                                                  can handle.
 *
 * This handles the traversal descending into and asecnding out of
 * maps, arrays and bstr-wrapped CBOR. It figures out the ends of
 * definite- and indefinte-length maps and arrays by looking at the
 * item count or finding CBOR breaks.  It detects the ends of the
 * top-level sequence and of bstr-wrapped CBOR by byte count.
 */
static QCBORError
QCBORDecode_Private_GetNextMapOrArray(QCBORDecodeContext *pMe,
                                      bool               *pbBreak,
                                      QCBORItem          *pDecodedItem,
                                      uint32_t           *puLabelEndOffset)
{
   QCBORError uReturn;
   /* ==== First: figure out if at the end of a traversal ==== */

   /* If out of bytes to consume, it is either the end of the
    * top-level sequence of some bstr-wrapped CBOR that was entered.
    *
    * In the case of bstr-wrapped CBOR, the length of the
    * UsefulInputBuf was set to that of the bstr-wrapped CBOR. When
    * the bstr-wrapped CBOR is exited, the length is set back to the
    * top-level's length or to the next highest bstr-wrapped CBOR.
   */
   if(UsefulInputBuf_BytesUnconsumed(&(pMe->InBuf)) == 0) {
      uReturn = QCBOR_ERR_NO_MORE_ITEMS;
      goto Done;
   }

   /* Check to see if at the end of a bounded definite-length map or
    * array. The check for a break ending indefinite-length array is
    * later in QCBORDecode_NestLevelAscender().
    */
   if(DecodeNesting_IsAtEndOfBoundedLevel(&(pMe->nesting))) {
      uReturn = QCBOR_ERR_NO_MORE_ITEMS;
      goto Done;
   }

   /* ==== Next: not at the end, so get another item ==== */
   uReturn = QCBORDecode_Private_GetNextMapEntry(pMe, pDecodedItem, puLabelEndOffset);
   if(QCBORDecode_IsUnrecoverableError(uReturn)) {
      /* Error is so bad that traversal is not possible. */
      goto Done;
   }

   /* Record the nesting level for this data item before processing
    * any of decrementing and descending.
    */
   pDecodedItem->uNestingLevel = DecodeNesting_GetCurrentLevel(&(pMe->nesting));


   /* ==== Next: Process the item for descent, ascent, decrement... ==== */
   if(QCBORItem_IsMapOrArray(*pDecodedItem)) {
      /* If the new item is a map or array, descend.
       *
       * Empty indefinite-length maps and arrays are descended into,
       * but then ascended out of in the next chunk of code.
       *
       * Maps and arrays do count as items in the map/array that
       * encloses them so a decrement needs to be done for them too,
       * but that is done only when all the items in them have been
       * processed, not when they are opened with the exception of an
       * empty map or array.
       */
      QCBORError uDescendErr;
      uDescendErr = DecodeNesting_DescendMapOrArray(&(pMe->nesting),
                                                    pDecodedItem->uDataType,
                                                    pDecodedItem->val.uCount);
      if(uDescendErr != QCBOR_SUCCESS) {
         /* This error is probably a traversal error and it overrides
          * the non-traversal error.
          */
         uReturn = uDescendErr;
         goto Done;
      }
   }

   if(!QCBORItem_IsMapOrArray(*pDecodedItem) ||
       QCBORItem_IsEmptyDefiniteLengthMapOrArray(*pDecodedItem) ||
       QCBORItem_IsIndefiniteLengthMapOrArray(*pDecodedItem)) {
      /* The following cases are handled here:
       *  - A non-aggregate item like an integer or string
       *  - An empty definite-length map or array
       *  - An indefinite-length map or array that might be empty or might not.
       *
       * QCBORDecode_NestLevelAscender() does the work of decrementing the count
       * for an definite-length map/array and break detection for an
       * indefinite-0length map/array. If the end of the map/array was
       * reached, then it ascends nesting levels, possibly all the way
       * to the top level.
       */
      QCBORError uAscendErr;
      uAscendErr = QCBORDecode_Private_NestLevelAscender(pMe, true, pbBreak);
      if(uAscendErr != QCBOR_SUCCESS) {
         /* This error is probably a traversal error and it overrides
          * the non-traversal error.
          */
         uReturn = uAscendErr;
         goto Done;
      }
   }

   /* ==== Last: tell the caller the nest level of the next item ==== */
   /* Tell the caller what level is next. This tells them what
    * maps/arrays were closed out and makes it possible for them to
    * reconstruct the tree with just the information returned in a
    * QCBORItem.
   */
   if(DecodeNesting_IsAtEndOfBoundedLevel(&(pMe->nesting))) {
      /* At end of a bounded map/array; uNextNestLevel 0 to indicate this */
      pDecodedItem->uNextNestLevel = 0;
   } else {
      pDecodedItem->uNextNestLevel = DecodeNesting_GetCurrentLevel(&(pMe->nesting));
   }

Done:
   return uReturn;
}


/**
 * @brief Decode tag content for select tags (decoding layer 1).
 *
 * @param[in] pMe            The decode context.
 * @param[out] pDecodedItem  The decoded item.
 *
 * @return Decoding error code.
 *
 * CBOR tag numbers for the item were decoded in GetNext_TaggedItem(),
 * but the whole tag was not decoded. Here, the whole tags (tag number
 * and tag content) are decoded. This is a
 * quick pass through for items that are not tags.
 */
static QCBORError
QCBORDecode_Private_GetNextTagContent(QCBORDecodeContext *pMe,
                                      QCBORItem          *pDecodedItem)
{
   QCBORError uErr;

   uErr = QCBORDecode_Private_GetNextMapOrArray(pMe, NULL, pDecodedItem, NULL);

#ifndef QCBOR_DISABLE_TAGS
   uint64_t   uTagNumber;
   int        nTagIndex;
   const struct QCBORTagDecoderEntry *pTagDecoder;

   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   /* Loop over tag numbers in reverse, those closest to content first */
   for(nTagIndex = QCBOR_MAX_TAGS_PER_ITEM-1; nTagIndex >= 0; nTagIndex--) {

      if(pDecodedItem->auTagNumbers[nTagIndex] == CBOR_TAG_INVALID16) {
         continue; /* Empty slot, skip to next */
      }

      /* See if there's a content decoder for it */
      uTagNumber  = QCBORDecode_Private_UnMapTagNumber(pMe, pDecodedItem->auTagNumbers[nTagIndex]);
      pTagDecoder = QCBORDecode_Private_LookUpTagDecoder(pMe->pTagDecoderTable, uTagNumber);
      if(pTagDecoder == NULL) {
         break; /* Successful exist -- a tag that we can't decode */
      }

      /* Call the content decoder */
      uErr = pTagDecoder->pfContentDecoder(pMe, pMe->pTagDecodersContext, pTagDecoder->uTagNumber, pDecodedItem);
      if(uErr != QCBOR_SUCCESS) {
         break; /* Error exit from the loop */
      }

      /* Remove tag number from list since its content was decoded */
      pDecodedItem->auTagNumbers[nTagIndex] = CBOR_TAG_INVALID16;
   }

Done:
#endif /* ! QCBOR_DISABLE_TAGS */

   return uErr;
}


/**
 * @brief Consume an entire map or array including its contents.
 *
 * @param[in]  pMe              The decoder context.
 * @param[in]  pItemToConsume   The array/map whose contents are to be
 *                              consumed.
 * @param[out] puNextNestLevel  The next nesting level after the item was
 *                              fully consumed.
 *
 * This may be called when @c pItemToConsume is not an array or
 * map. In that case, this is just a pass through for @c puNextNestLevel
 * since there is nothing to do.
 */
static QCBORError
QCBORDecode_Private_ConsumeItem(QCBORDecodeContext *pMe,
                                const QCBORItem    *pItemToConsume,
                                bool               *pbBreak,
                                uint8_t            *puNextNestLevel)
{
   QCBORError uReturn;
   QCBORItem  Item;

   /* If it is a map or array, this will tell if it is empty. */
   const bool bIsEmpty = (pItemToConsume->uNextNestLevel <= pItemToConsume->uNestingLevel);

   if(QCBORItem_IsMapOrArray(*pItemToConsume) && !bIsEmpty) {
      /* There is only real work to do for non-empty maps and arrays */

      /* This works for definite- and indefinite-length maps and
       * arrays by using the nesting level
       */
      do {
         uReturn = QCBORDecode_Private_GetNextMapOrArray(pMe, pbBreak, &Item, NULL);
         if(QCBORDecode_IsUnrecoverableError(uReturn) ||
            uReturn == QCBOR_ERR_NO_MORE_ITEMS) {
            goto Done;
         }
      } while(Item.uNextNestLevel >= pItemToConsume->uNextNestLevel);

      *puNextNestLevel = Item.uNextNestLevel;

      uReturn = QCBOR_SUCCESS;

   } else {
      /* pItemToConsume is not a map or array. Just pass the nesting
       * level through. */
      *puNextNestLevel = pItemToConsume->uNextNestLevel;

      uReturn = QCBOR_SUCCESS;
   }

Done:
    return uReturn;
}


#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
/*
 * This consumes the next item. It returns the starting position of
 * the label and the length of the label. It also returns the nest
 * level of the item consumed.
 */
static QCBORError
QCBORDecode_Private_GetLabelAndConsume(QCBORDecodeContext *pMe,
                                       uint8_t            *puNestLevel,
                                       size_t             *puLabelStart,
                                       size_t             *puLabelLen)
{
   QCBORError uErr;
   QCBORItem  Item;
   uint8_t    uLevel;
   uint32_t   uLabelOffset;

   /* Get the label and consume it should it be complex */
   *puLabelStart = UsefulInputBuf_Tell(&(pMe->InBuf));

   uErr = QCBORDecode_Private_GetNextMapOrArray(pMe, NULL, &Item, &uLabelOffset);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }
   *puLabelLen = uLabelOffset - *puLabelStart;
   *puNestLevel = Item.uNestingLevel;
   uErr = QCBORDecode_Private_ConsumeItem(pMe, &Item, NULL, &uLevel);

Done:
   return uErr;
}


/* Loop over items in a map until the end of the map looking for
 * duplicates. This starts at the current position in the map, not at
 * the beginning of the map.
 *
 * This saves and restores the traversal cursor and nest tracking so
 * they are the same on exit as they were on entry.
 */
static QCBORError
QCBORDecode_Private_CheckDups(QCBORDecodeContext *pMe,
                              const uint8_t       uNestLevel,
                              const size_t        uCompareLabelStart,
                              const size_t        uCompareLabelLen)
{
   QCBORError uErr;
   size_t     uLabelStart;
   size_t     uLabelLen;
   uint8_t    uLevel;
   int        nCompare;

   const QCBORDecodeNesting SaveNesting = pMe->nesting;
   const UsefulInputBuf     Save        = pMe->InBuf;

   do {
      uErr = QCBORDecode_Private_GetLabelAndConsume(pMe, &uLevel, &uLabelStart, &uLabelLen);
      if(uErr != QCBOR_SUCCESS) {
         if(uErr == QCBOR_ERR_NO_MORE_ITEMS) {
            uErr = QCBOR_SUCCESS; /* Successful end */
         }
         break;
      }

      if(uLevel != uNestLevel) {
         break; /* Successful end of loop */
      }

      /* This check for dups works for labels that are preferred
       * serialization and are not maps. If the labels are not in
       * preferred serialization, then the check has to be more
       * complicated and is type-specific because it uses the decoded
       * value, not the encoded CBOR. It is further complicated for
       * maps because the order of items in a map that is a label
       * doesn't matter when checking that is is the duplicate of
       * another map that is a label. QCBOR so far only turns on this
       * dup checking as part of CDE checking which requires preferred
       * serialization.  See 5.6 in RFC 8949.
       */
      nCompare = UsefulInputBuf_Compare(&(pMe->InBuf),
                                         uCompareLabelStart, uCompareLabelLen,
                                         uLabelStart, uLabelLen);
      if(nCompare == 0) {
         uErr = QCBOR_ERR_DUPLICATE_LABEL;
         break;
      }
   } while (1);

   pMe->nesting = SaveNesting;
   pMe->InBuf   = Save;

   return uErr;
}


/* This does sort order and duplicate detection on a map. The and all
 * it's members must be in preferred serialization so the comparisons
 * work correctly.
 */
static QCBORError
QCBORDecode_Private_CheckMap(QCBORDecodeContext *pMe, const QCBORItem *pMapToCheck)
{
   QCBORError uErr;
   uint8_t    uNestLevel;
   size_t     offset2, offset1, length2, length1;

   const QCBORDecodeNesting SaveNesting = pMe->nesting;
   const UsefulInputBuf Save = pMe->InBuf;
   pMe->bAllowAllLabels = 1;

   /* This loop runs over all the items in the map once, comparing
    * each adjacent pair for correct ordering. It also calls CheckDup
    * on each one which also runs over the remaining items in the map
    * checking for duplicates. So duplicate checking runs in n^2.
    */

   offset2 = SIZE_MAX;
   length2 = SIZE_MAX; // To avoid uninitialized warning
   while(1) {
      uErr = QCBORDecode_Private_GetLabelAndConsume(pMe, &uNestLevel, &offset1, &length1);
      if(uErr != QCBOR_SUCCESS) {
         if(uErr == QCBOR_ERR_NO_MORE_ITEMS) {
            uErr = QCBOR_SUCCESS; /* Successful exit from loop */
         }
         break;
      }

      if(uNestLevel < pMapToCheck->uNextNestLevel) {
         break; /* Successful exit from loop */
      }

      if(offset2 != SIZE_MAX) {
         /* Check that the labels are ordered. Check is not done the
          * first time through the loop when offset2 is unset. Since
          * this does comparison of the items in encoded form they
          * must be preferred serialization encoded. See RFC 8949
          * 4.2.1.
          */
         if(UsefulInputBuf_Compare(&(pMe->InBuf), offset2, length2, offset1, length1) > 0) {
            uErr = QCBOR_ERR_UNSORTED;
            break;
         }
      }

      uErr = QCBORDecode_Private_CheckDups(pMe, pMapToCheck->uNextNestLevel, offset1, length1);
      if(uErr != QCBOR_SUCCESS) {
         break;
      }

      offset2 = offset1;
      length2 = length1;
   }

   pMe->bAllowAllLabels = 0;
   pMe->nesting = SaveNesting;
   pMe->InBuf = Save;

   return uErr;
}
#endif /* ! QCBOR_DISABLE_DECODE_CONFORMANCE */

static QCBORError
QCBORDecode_Private_GetItemChecks(QCBORDecodeContext *pMe,
                                  QCBORError          uErr,
                                  const size_t        uOffset,
                                  QCBORItem          *pDecodedItem)
{
   (void)pMe; /* Avoid warning for next two ifdefs */
   (void)uOffset;

#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
   if(uErr == QCBOR_SUCCESS &&
      (pMe->uDecodeMode & QCBOR_DECODE_MODE_MASK) >= QCBOR_ENCODE_MODE_CDE &&
      pDecodedItem->uDataType == QCBOR_TYPE_MAP) {
      /* Traverse map checking sort order and for duplicates */
      uErr = QCBORDecode_Private_CheckMap(pMe, pDecodedItem);
   }
#endif /* ! QCBOR_DISABLE_CONFORMANCE */

#ifndef QCBOR_DISABLE_TAGS
   if(uErr == QCBOR_SUCCESS &&
      !(pMe->uDecodeMode & QCBOR_DECODE_UNPROCESSED_TAG_NUMBERS) &&
      pDecodedItem->auTagNumbers[0] != CBOR_TAG_INVALID16) {
      /*  Not QCBOR v1; there are tag numbers -- check they were consumed */
      if(uOffset != pMe->uTagNumberCheckOffset || pMe->uTagNumberIndex != 255) {
         uErr = QCBOR_ERR_UNPROCESSED_TAG_NUMBER;
      }
   }
#endif /* ! QCBOR_DISABLE_TAGS */

   if(uErr != QCBOR_SUCCESS) {
      pDecodedItem->uDataType  = QCBOR_TYPE_NONE;
      pDecodedItem->uLabelType = QCBOR_TYPE_NONE;
   }

   return uErr;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_GetNext(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   QCBORError uErr;
   size_t     uOffset;

   uOffset = UsefulInputBuf_Tell(&(pMe->InBuf));
   uErr = QCBORDecode_Private_GetNextTagContent(pMe, pDecodedItem);
   uErr = QCBORDecode_Private_GetItemChecks(pMe, uErr, uOffset, pDecodedItem);
   return uErr;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_PeekNext(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   const QCBORDecodeNesting SaveNesting = pMe->nesting;
   const UsefulInputBuf Save = pMe->InBuf;

   QCBORError uErr = QCBORDecode_GetNext(pMe, pDecodedItem);

   pMe->nesting = SaveNesting;
   pMe->InBuf = Save;

   return uErr;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_VPeekNext(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      pDecodedItem->uDataType  = QCBOR_TYPE_NONE;
      pDecodedItem->uLabelType = QCBOR_TYPE_NONE;
      return;
   }

   pMe->uLastError = (uint8_t)QCBORDecode_PeekNext(pMe, pDecodedItem);
}


static void
QCBORDecode_Private_SaveTagNumbers(QCBORDecodeContext *pMe, const QCBORItem *pItem)
{
#ifndef QCBOR_DISABLE_TAGS
   memcpy(pMe->auLastTags, pItem->auTagNumbers, sizeof(pItem->auTagNumbers));
#else
   (void)pMe;
   (void)pItem;
#endif
}

/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_VGetNext(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      pDecodedItem->uDataType  = QCBOR_TYPE_NONE;
      pDecodedItem->uLabelType = QCBOR_TYPE_NONE;
      return;
   }

   pMe->uLastError = (uint8_t)QCBORDecode_GetNext(pMe, pDecodedItem);
   QCBORDecode_Private_SaveTagNumbers(pMe, pDecodedItem);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_PartialFinish(QCBORDecodeContext *pMe, size_t *puConsumed)
{
   if(puConsumed != NULL) {
      *puConsumed = pMe->InBuf.cursor;
   }

   QCBORError uReturn = pMe->uLastError;

   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }

   /* Error out if all the maps/arrays are not closed out */
   if(!DecodeNesting_IsCurrentAtTop(&(pMe->nesting))) {
      uReturn = QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED;
      goto Done;
   }

   /* Error out if not all the bytes are consumed */
   if(UsefulInputBuf_BytesUnconsumed(&(pMe->InBuf))) {
      uReturn = QCBOR_ERR_EXTRA_BYTES;
   }

Done:
   return uReturn;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_Finish(QCBORDecodeContext *pMe)
{
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
   /* Call the destructor for the string allocator if there is one.
    * Always called, even if there are errors; always have to clean up.
    */
   StringAllocator_Destruct(&(pMe->StringAllocator));
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */

   return QCBORDecode_PartialFinish(pMe, NULL);
}


#ifndef QCBOR_DISABLE_TAGS
/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
uint64_t
QCBORDecode_GetNthTagNumber(const QCBORDecodeContext *pMe,
                            const QCBORItem          *pItem,
                            uint8_t                   uIndex)
{
   if(pItem->uDataType == QCBOR_TYPE_NONE) {
      return CBOR_TAG_INVALID64;
   }
   if(uIndex >= QCBOR_MAX_TAGS_PER_ITEM) {
      return CBOR_TAG_INVALID64;
   }

   return QCBORDecode_Private_UnMapTagNumber(pMe, pItem->auTagNumbers[uIndex]);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
uint64_t
QCBORDecode_GetNthTagNumberOfLast(QCBORDecodeContext *pMe,
                                  uint8_t             uIndex)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return CBOR_TAG_INVALID64;
   }
   if(uIndex >= QCBOR_MAX_TAGS_PER_ITEM) {
      return CBOR_TAG_INVALID64;
   }

   return QCBORDecode_Private_UnMapTagNumber(pMe, pMe->auLastTags[uIndex]);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
static uint64_t
QCBORDecode_Private_GetNthTagNumberReverse(const QCBORDecodeContext *pMe,
                                           const uint16_t            puTagNumbers[],
                                           const uint32_t            uIndex)
{
   uint32_t uArrayIndex;

   /* Find number of tag numbers */
   for(uArrayIndex = QCBOR_MAX_TAGS_PER_ITEM-1; uArrayIndex > 0; uArrayIndex--) {
      if(puTagNumbers[uArrayIndex] != CBOR_TAG_INVALID16) {
         break;
      }
   }
   if(uIndex > uArrayIndex) {
      return CBOR_TAG_INVALID64;
   }

   return QCBORDecode_Private_UnMapTagNumber(pMe, puTagNumbers[uArrayIndex - uIndex]);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
uint64_t
QCBORDecode_GetNthTag(QCBORDecodeContext *pMe,
                      const QCBORItem    *pItem,
                      const uint32_t      uIndex)
{
   if(pItem->uDataType == QCBOR_TYPE_NONE) {
      return CBOR_TAG_INVALID64;
   }

   return QCBORDecode_Private_GetNthTagNumberReverse(pMe, pItem->auTagNumbers, uIndex);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
uint64_t
QCBORDecode_GetNthTagOfLast(const QCBORDecodeContext *pMe,
                            uint32_t                  uIndex)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return CBOR_TAG_INVALID64;
   }
   if(uIndex >= QCBOR_MAX_TAGS_PER_ITEM) {
      return CBOR_TAG_INVALID64;
   }

   return QCBORDecode_Private_GetNthTagNumberReverse(pMe, pMe->auLastTags, uIndex);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_GetNextTagNumber(QCBORDecodeContext *pMe, uint64_t *puTagNumber)
{
   QCBORItem   Item;
   size_t      uOffset;
   QCBORError  uErr;

   const QCBORDecodeNesting SaveNesting = pMe->nesting;
   const UsefulInputBuf Save = pMe->InBuf;

   uOffset = UsefulInputBuf_Tell(&(pMe->InBuf));
   if(uOffset == pMe->uTagNumberCheckOffset) {
      pMe->uTagNumberIndex++;
   } else {
      pMe->uTagNumberIndex = 0;
   }

   *puTagNumber = CBOR_TAG_INVALID64;
   uErr = QCBORDecode_Private_GetNextTagContent(pMe, &Item);
   if(uErr) {
      return uErr;
   }

   *puTagNumber = QCBORDecode_GetNthTagNumber(pMe, &Item, pMe->uTagNumberIndex);
   if(*puTagNumber == CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNthTagNumber(pMe, &Item, pMe->uTagNumberIndex+1) == CBOR_TAG_INVALID64 ) {
      pMe->uTagNumberIndex = QCBOR_ALL_TAGS_PROCESSED;
   }
   pMe->uTagNumberCheckOffset = uOffset;

   pMe->nesting = SaveNesting;
   pMe->InBuf = Save;

   return QCBOR_SUCCESS;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_VGetNextTagNumber(QCBORDecodeContext *pMe, uint64_t *puTagNumber)
{
   pMe->uLastError = (uint8_t)QCBORDecode_GetNextTagNumber(pMe, puTagNumber);
}

#endif /* ! QCBOR_DISABLE_TAGS */

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS

/* ===========================================================================
   MemPool -- BUILT-IN SIMPLE STRING ALLOCATOR

   This implements a simple sting allocator for indefinite-length
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


static int
MemPool_Unpack(const void *pMem, uint32_t *puPoolSize, uint32_t *puFreeOffset)
{
   // Use of UsefulInputBuf is overkill, but it is convenient.
   UsefulInputBuf UIB;

   // Just assume the size here. It was checked during SetUp so
   // the assumption is safe.
   UsefulInputBuf_Init(&UIB, (UsefulBufC){pMem,QCBOR_DECODE_MIN_MEM_POOL_SIZE});
   *puPoolSize     = UsefulInputBuf_GetUint32(&UIB);
   *puFreeOffset   = UsefulInputBuf_GetUint32(&UIB);
   return UsefulInputBuf_GetError(&UIB);
}


static int
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
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_SetMemPool(QCBORDecodeContext *pMe,
                       UsefulBuf           Pool,
                       bool                bAllStrings)
{
   // The pool size and free mem offset are packed into the beginning
   // of the pool memory. This compile time check makes sure the
   // constant in the header is correct.  This check should optimize
   // down to nothing.
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant
#endif
   if(QCBOR_DECODE_MIN_MEM_POOL_SIZE < 2 * sizeof(uint32_t)) {
      return QCBOR_ERR_MEM_POOL_SIZE;
   }
#ifdef _MSC_VER
#pragma warning(pop)
#endif

   // The pool size and free offset packed in to the beginning of pool
   // memory are only 32-bits. This check will optimize out on 32-bit
   // machines.
   if(Pool.len > UINT32_MAX) {
      return QCBOR_ERR_MEM_POOL_SIZE;
   }

   // This checks that the pool buffer given is big enough.
   if(MemPool_Pack(Pool, QCBOR_DECODE_MIN_MEM_POOL_SIZE)) {
      return QCBOR_ERR_MEM_POOL_SIZE;
   }

   QCBORDecode_SetUpAllocator(pMe, MemPool_Function, Pool.ptr, bAllStrings);

   return QCBOR_SUCCESS;
}
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */



/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_VGetNextConsume(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   QCBORDecode_VGetNext(pMe, pDecodedItem);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)QCBORDecode_Private_ConsumeItem(pMe, pDecodedItem, NULL,
         &pDecodedItem->uNextNestLevel);
   }
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_EndCheck(QCBORDecodeContext *pMe)
{
   size_t     uCursorOffset;
   QCBORError uErr;

   uErr = QCBORDecode_GetError(pMe);
   if(uErr != QCBOR_SUCCESS) {
      return uErr;
   }

   uCursorOffset = UsefulInputBuf_Tell(&(pMe->InBuf));

   if(uCursorOffset == UsefulInputBuf_GetBufferLength(&(pMe->InBuf))) {
      return QCBOR_ERR_NO_MORE_ITEMS;
   }

   return QCBOR_SUCCESS;
}


/**
 * @brief Rewind cursor to start as if map or array were just entered.
 *
 * @param[in]  pMe   The decoding context
 *
 * This affects the nesting tracking and the UsefulInputBuf.
 */
static void
QCBORDecode_Private_RewindMapOrArray(QCBORDecodeContext *pMe)
{
   /* Reset nesting tracking to the deepest bounded level */
   DecodeNesting_SetCurrentToBoundedLevel(&(pMe->nesting));

   DecodeNesting_ResetMapOrArrayCount(&(pMe->nesting));

   /* Reposition traversal cursor to the start of the map/array */
   UsefulInputBuf_Seek(&(pMe->InBuf),
                       DecodeNesting_GetMapOrArrayStart(&(pMe->nesting)));
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_Rewind(QCBORDecodeContext *pMe)
{
   if(pMe->nesting.pCurrentBounded != NULL) {
      /* In a bounded map, array or bstr-wrapped CBOR */

      if(DecodeNesting_IsBoundedType(&(pMe->nesting), QCBOR_TYPE_BYTE_STRING)) {
         /* In bstr-wrapped CBOR. */

         /* Reposition traversal cursor to start of wrapping byte string */
         UsefulInputBuf_Seek(&(pMe->InBuf),
                             pMe->nesting.pCurrentBounded->u.bs.uBstrStartOffset);
         DecodeNesting_SetCurrentToBoundedLevel(&(pMe->nesting));

      } else {
         /* In a map or array */
         QCBORDecode_Private_RewindMapOrArray(pMe);
      }

   } else {
      /* Not in anything bounded */

      /* Reposition traversal cursor to the start of input CBOR */
      UsefulInputBuf_Seek(&(pMe->InBuf), 0ULL);

      /* Reset nesting tracking to beginning of input. */
      DecodeNesting_Init(&(pMe->nesting));
   }

   pMe->uLastError = QCBOR_SUCCESS;
}





typedef struct {
   void               *pCBContext;
   QCBORItemCallback   pfCallback;
} MapSearchCallBack;

typedef struct {
   size_t   uStartOffset;
   uint16_t uItemCount;
} MapSearchInfo;


/**
 * @brief Search a map for a set of items.
 *
 * @param[in]  pMe           The decode context to search.
 * @param[in,out] pItemArray The items to search for and the items found.
 * @param[out] pInfo         Several bits of meta-info returned by search.
 * @param[in] pCallBack      Callback object or @c NULL.
 *
 * @retval QCBOR_ERR_NOT_ENTERED     Trying to search without entering a map.
 *
 * @retval QCBOR_ERR_DUPLICATE_LABEL Duplicate items (items with the same label)
 *                                   were found for one of the labels being
 *                                   search for. This duplicate detection is
 *                                   only performed for items in pItemArray,
 *                                   not every item in the map.
 *
 * @retval QCBOR_ERR_UNEXPECTED_TYPE A label was matched, but the type was
 *                                   wrong for the matchd label.
 *
 * @retval Also errors returned by QCBORDecode_GetNext().
 *
 * On input, @c pItemArray contains a list of labels and data types of
 * items to be found.
 *
 * On output, the fully retrieved items are filled in with values and
 * such. The label was matched, so it never changes.
 *
 * If an item was not found, its data type is set to @ref QCBOR_TYPE_NONE.
 *
 * This also finds the ends of maps and arrays when they are exited.
 */
static QCBORError
QCBORDecode_Private_MapSearch(QCBORDecodeContext *pMe,
                              QCBORItem          *pItemArray,
                              MapSearchInfo      *pInfo,
                              MapSearchCallBack  *pCallBack)
{
   QCBORError uReturn;
   uint64_t   uFoundItemBitMap = 0;

   if(pMe->uLastError != QCBOR_SUCCESS) {
      uReturn = pMe->uLastError;
      goto Done2;
   }

   if(!DecodeNesting_IsBoundedType(&(pMe->nesting), QCBOR_TYPE_MAP) &&
      pItemArray->uLabelType != QCBOR_TYPE_NONE) {
      /* QCBOR_TYPE_NONE as first item indicates just looking
         for the end of an array, so don't give error. */
      uReturn = QCBOR_ERR_MAP_NOT_ENTERED;
      goto Done2;
   }

   if(DecodeNesting_IsBoundedEmpty(&(pMe->nesting))) {
      // It is an empty bounded array or map
      if(pItemArray->uLabelType == QCBOR_TYPE_NONE) {
         // Just trying to find the end of the map or array
         pMe->uMapEndOffsetCache = DecodeNesting_GetMapOrArrayStart(&(pMe->nesting));
         uReturn = QCBOR_SUCCESS;
      } else {
         // Nothing is ever found in an empty array or map. All items
         // are marked as not found below.
         uReturn = QCBOR_SUCCESS;
      }
      goto Done2;
   }

   QCBORDecodeNesting SaveNesting;
   size_t uSavePos = UsefulInputBuf_Tell(&(pMe->InBuf));
   DecodeNesting_PrepareForMapSearch(&(pMe->nesting), &SaveNesting);

   /* Reposition to search from the start of the map / array */
   QCBORDecode_Private_RewindMapOrArray(pMe);

   /*
    Loop over all the items in the map or array. Each item
    could be a map or array, but label matching is only at
    the main level. This handles definite- and indefinite-
    length maps and arrays. The only reason this is ever
    called on arrays is to find their end position.

    This will always run over all items in order to do
    duplicate detection.

    This will exit with failure if it encounters an
    unrecoverable error, but continue on for recoverable
    errors.

    If a recoverable error occurs on a matched item, then
    that error code is returned.
    */
   const uint8_t uMapNestLevel = DecodeNesting_GetBoundedModeLevel(&(pMe->nesting));
   if(pInfo) {
      pInfo->uItemCount = 0;
   }
   uint8_t       uNextNestLevel;
   do {
      /* Remember offset of the item because sometimes it has to be returned */
      const size_t uOffset = UsefulInputBuf_Tell(&(pMe->InBuf));

      /* Get the item */
      QCBORItem Item;
      /* QCBORDecode_Private_GetNextTagContent() rather than GetNext()
       * because a label match is performed on recoverable errors to
       * be able to return the the error code for the found item. */
      QCBORError uResult = QCBORDecode_Private_GetNextTagContent(pMe, &Item);
      if(QCBORDecode_IsUnrecoverableError(uResult)) {
         /* The map/array can't be decoded when unrecoverable errors occur */
         uReturn = uResult;
         goto Done;
      }
      if(uResult == QCBOR_ERR_NO_MORE_ITEMS) {
         /* Unexpected end of map or array. */
         uReturn = uResult;
         goto Done;
      }

      /* See if item has one of the labels that are of interest */
      bool bMatched = false;
      for(int nIndex = 0; pItemArray[nIndex].uLabelType != QCBOR_TYPE_NONE; nIndex++) {
         if(QCBORItem_MatchLabel(Item, pItemArray[nIndex])) {
            /* A label match has been found */
            if(uFoundItemBitMap & (0x01ULL << nIndex)) {
               uReturn = QCBOR_ERR_DUPLICATE_LABEL;
               goto Done;
            }
            if(uResult != QCBOR_SUCCESS) {
               /* The label matches, but the data item is in error.
                * It is OK to have recoverable errors on items that
                * are not matched. */
               uReturn = uResult;
               goto Done;
            }
            if(!QCBORItem_MatchType(Item, pItemArray[nIndex])) {
               /* The data item is not of the type(s) requested */
               uReturn = QCBOR_ERR_UNEXPECTED_TYPE;
               goto Done;
            }

            /* Successful match. Return the item. */
            pItemArray[nIndex] = Item;
            uFoundItemBitMap |= 0x01ULL << nIndex;
            if(pInfo) {
               pInfo->uStartOffset = uOffset;
            }
            bMatched = true;
         }
      }


      if(!bMatched && pCallBack != NULL) {
         /*
          Call the callback on unmatched labels.
          (It is tempting to do duplicate detection here, but that would
          require dynamic memory allocation because the number of labels
          that might be encountered is unbounded.)
         */
         uReturn = (*(pCallBack->pfCallback))(pCallBack->pCBContext, &Item);
         if(uReturn != QCBOR_SUCCESS) {
            goto Done;
         }
      }

      /*
       Consume the item whether matched or not. This
       does the work of traversing maps and array and
       everything in them. In this loop only the
       items at the current nesting level are examined
       to match the labels.
       */
      uReturn = QCBORDecode_Private_ConsumeItem(pMe, &Item, NULL, &uNextNestLevel);
      if(uReturn != QCBOR_SUCCESS) {
         goto Done;
      }

      if(pInfo) {
         pInfo->uItemCount++;
      }

   } while (uNextNestLevel >= uMapNestLevel);

   uReturn = QCBOR_SUCCESS;

   const size_t uEndOffset = UsefulInputBuf_Tell(&(pMe->InBuf));

   // Check here makes sure that this won't accidentally be
   // QCBOR_MAP_OFFSET_CACHE_INVALID which is larger than
   // QCBOR_MAX_DECODE_INPUT_SIZE.
   // Cast to uint32_t to possibly address cases where SIZE_MAX < UINT32_MAX
   if((uint32_t)uEndOffset >= QCBOR_MAX_DECODE_INPUT_SIZE) {
      uReturn = QCBOR_ERR_INPUT_TOO_LARGE;
      goto Done;
   }
   /* Cast OK because encoded CBOR is limited to UINT32_MAX */
   pMe->uMapEndOffsetCache = (uint32_t)uEndOffset;

 Done:
   DecodeNesting_RestoreFromMapSearch(&(pMe->nesting), &SaveNesting);
   UsefulInputBuf_Seek(&(pMe->InBuf), uSavePos);

 Done2:
   /* For all items not found, set the data and label type to QCBOR_TYPE_NONE */
   for(int i = 0; pItemArray[i].uLabelType != 0; i++) {
      if(!(uFoundItemBitMap & (0x01ULL << i))) {
         pItemArray[i].uDataType  = QCBOR_TYPE_NONE;
         pItemArray[i].uLabelType = QCBOR_TYPE_NONE;
      }
   }

   return uReturn;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_SeekToLabelN(QCBORDecodeContext *pMe, int64_t nLabel)
{
   MapSearchInfo Info;
   QCBORItem     OneItemSeach[2];

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = QCBOR_TYPE_ANY;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE; // Indicates end of array

   pMe->uLastError = (uint8_t)QCBORDecode_Private_MapSearch(pMe, OneItemSeach, &Info, NULL);
   if(pMe->uLastError == QCBOR_SUCCESS) {
      UsefulInputBuf_Seek(&(pMe->InBuf), Info.uStartOffset);
   }
}


void
QCBORDecode_SeekToLabelSZ(QCBORDecodeContext *pMe, const char *szLabel)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   MapSearchInfo  Info;
   QCBORItem      OneItemSeach[2];

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = QCBOR_TYPE_ANY;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE; // Indicates end of array

   pMe->uLastError = (uint8_t)QCBORDecode_Private_MapSearch(pMe, OneItemSeach, &Info, NULL);
   if(pMe->uLastError == QCBOR_SUCCESS) {
      UsefulInputBuf_Seek(&(pMe->InBuf), Info.uStartOffset);
   }
#else
   (void)pMe;
   (void)szLabel;
   pMe->uLastError = QCBOR_ERR_LABEL_NOT_FOUND;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
}


void
QCBORDecode_Private_GetItemInMapNoCheck(QCBORDecodeContext *pMe,
                                        QCBORItem          *OneItemSeach,
                                        QCBORItem          *pItem,
                                        size_t             *puOffset)
{
   QCBORError    uErr;
   MapSearchInfo SearchInfo;

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   uErr = QCBORDecode_Private_MapSearch(pMe, OneItemSeach, &SearchInfo, NULL);

   if(uErr == QCBOR_SUCCESS && OneItemSeach[0].uDataType == QCBOR_TYPE_NONE) {
      uErr = QCBOR_ERR_LABEL_NOT_FOUND;
   }
   *pItem = OneItemSeach[0];
   *puOffset = SearchInfo.uStartOffset;

   if(uErr == QCBOR_SUCCESS) {
      QCBORDecode_Private_SaveTagNumbers(pMe, pItem);
   }

   pMe->uLastError = (uint8_t)uErr;
}


static void
QCBORDecode_Private_GetItemInMap(QCBORDecodeContext *pMe, QCBORItem *OneItemSeach, QCBORItem *pItem)
{
   QCBORError  uErr;
   size_t      uOffset;

   QCBORDecode_Private_GetItemInMapNoCheck(pMe, OneItemSeach, pItem, &uOffset);

   uErr = QCBORDecode_Private_GetItemChecks(pMe, pMe->uLastError, uOffset, pItem);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   QCBORDecode_Private_SaveTagNumbers(pMe, pItem);

Done:
   pMe->uLastError = (uint8_t)uErr;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetItemInMapN(QCBORDecodeContext *pMe,
                          const int64_t       nLabel,
                          const uint8_t       uQcborType,
                          QCBORItem          *pItem)
{
   QCBORItem OneItemSeach[2];

   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = uQcborType;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORDecode_Private_GetItemInMap(pMe, OneItemSeach, pItem);
}


/**
 * @brief Get an item by label by type.
 *
 * @param[in] pMe         The decode context.
 * @param[in] nLabel      The label to search map for.
 * @param[in] uQcborType  The QCBOR type to look for.
 * @param[out] pItem      The item found.
 * @param[out] puOffset   The offset of item for tag consumption check.
 *
 * This finds the item with the given label in currently open
 * map. This does not call QCBORDecode_Private_GetItemChecks()
 * to check tag number consumption or decode conformance.
 */
static void
QCBORDecode_GetItemInMapNoCheckN(QCBORDecodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uQcborType,
                                 QCBORItem          *pItem,
                                 size_t             *puOffset)
{
   QCBORItem OneItemSeach[2];

   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = uQcborType;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORDecode_Private_GetItemInMapNoCheck(pMe, OneItemSeach,  pItem, puOffset);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetItemInMapSZ(QCBORDecodeContext *pMe,
                           const char         *szLabel,
                           const uint8_t       uQcborType,
                           QCBORItem          *pItem)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   QCBORItem OneItemSeach[2];

   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = uQcborType;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORDecode_Private_GetItemInMap(pMe, OneItemSeach, pItem);

#else
   (void)pMe;
   (void)szLabel;
   (void)uQcborType;
   (void)pItem;
   pMe->uLastError = QCBOR_ERR_LABEL_NOT_FOUND;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
}

/**
 * @brief Get an item by string label of a particular type
 *
 * @param[in] pMe         The decode context.
 * @param[in] szLabel     The label to search map for.
 * @param[in] uQcborType  The QCBOR type to look for.
 * @param[out] pItem      The item found.
 * @param[out] puOffset   The offset of item for tag consumption check.
 *
 * This finds the item with the given label in currently open
 * map. This does not call QCBORDecode_Private_GetItemChecks()
 * to check tag number consumption or decode conformance.
 */
static void
QCBORDecode_GetItemInMapNoCheckSZ(QCBORDecodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uQcborType,
                                  QCBORItem          *pItem,
                                  size_t             *puOffset)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   QCBORItem OneItemSeach[2];

   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = uQcborType;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORDecode_Private_GetItemInMapNoCheck(pMe, OneItemSeach, pItem, puOffset);

#else
   (void)pMe;
   (void)szLabel;
   (void)uQcborType;
   (void)pItem;
   (void)puOffset;
   pMe->uLastError = QCBOR_ERR_LABEL_NOT_FOUND;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
}




/**
 * @brief Semi-private. Get pointer, length and item for an array or map.
 *
 * @param[in] pMe            The decode context.
 * @param[in] uType          CBOR major type, either array/map.
 * @param[out] pItem         The item for the array/map.
 * @param[out] pEncodedCBOR  Pointer and length of the encoded map or array.
 *
 * The next item to be decoded must be a map or array as specified by @c uType.
 *
 * @c pItem will be filled in with the label and tags of the array or map
 * in addition to @c pEncodedCBOR giving the pointer and length of the
 * encoded CBOR.
 *
 * When this is complete, the traversal cursor is at the end of the array or
 * map that was retrieved.
 */
void
QCBORDecode_Private_GetArrayOrMap(QCBORDecodeContext *pMe,
                                  const uint8_t       uType,
                                  QCBORItem          *pItem,
                                  UsefulBufC         *pEncodedCBOR)
{
   QCBORError uErr;
   uint8_t    uNestLevel;
   size_t     uStartingCursor;
   size_t     uStartOfReturned;
   size_t     uEndOfReturned;
   size_t     uTempSaveCursor;
   bool       bInMap;
   QCBORItem  LabelItem;
   bool       EndedByBreak;

   uStartingCursor = UsefulInputBuf_Tell(&(pMe->InBuf));
   bInMap = DecodeNesting_IsCurrentTypeMap(&(pMe->nesting));

   /* Could call GetNext here, but don't need to because this
    * is only interested in arrays and maps. TODO: switch to GetNext()? */
   uErr = QCBORDecode_Private_GetNextMapOrArray(pMe, NULL, pItem, NULL);
   if(uErr != QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)uErr;
      return;
   }

   uint8_t uItemDataType = pItem->uDataType;
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   if(uItemDataType == QCBOR_TYPE_MAP_AS_ARRAY) {
      uItemDataType = QCBOR_TYPE_ARRAY;
   }
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */

   if(uItemDataType != uType) {
      pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
      return;
   }

   if(bInMap) {
      /* If the item is in a map, the start of the array/map
       * itself, not the label, must be found. Do this by
       * rewinding to the starting position and fetching
       * just the label data item. QCBORDecode_Private_GetNextTagNumber()
       * doesn't do any of the array/map item counting or nesting
       * level tracking. Used here it will just fetech the label
       * data item.
       *
       * Have to save the cursor and put it back to the position
       * after the full item once the label as been fetched by
       * itself.
       */
      uTempSaveCursor = UsefulInputBuf_Tell(&(pMe->InBuf));
      UsefulInputBuf_Seek(&(pMe->InBuf), uStartingCursor);

      /* Item has been fetched once so safe to ignore error */
      (void)QCBORDecode_Private_GetNextTagNumber(pMe, &LabelItem);

      uStartOfReturned = UsefulInputBuf_Tell(&(pMe->InBuf));
      UsefulInputBuf_Seek(&(pMe->InBuf), uTempSaveCursor);
   } else {
      uStartOfReturned = uStartingCursor;
   }

   /* Consume the entire array/map to find the end */
   uErr = QCBORDecode_Private_ConsumeItem(pMe, pItem, &EndedByBreak, &uNestLevel);
   if(uErr != QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)uErr;
      goto Done;
   }

   /* Fill in returned values */
   uEndOfReturned = UsefulInputBuf_Tell(&(pMe->InBuf));
   if(EndedByBreak) {
      /* When ascending nesting levels, a break for the level above
       * was consumed. That break is not a part of what is consumed here. */
      uEndOfReturned--;
   }
   pEncodedCBOR->ptr = UsefulInputBuf_OffsetToPointer(&(pMe->InBuf), uStartOfReturned);
   pEncodedCBOR->len = uEndOfReturned - uStartOfReturned;

Done:
   return;
}


/**
 * @brief Semi-private. Get pointer, length and item count of an array or map.
 *
 * @param[in] pMe            The decode context.
 * @param[in] pTarget        The label and type of the array or map to retrieve.
 * @param[out] pItem         The item for the array/map.
 * @param[out] pEncodedCBOR  Pointer and length of the encoded map or array.
 *
 * The next item to be decoded must be a map or array as specified by @c uType.
 *
 * When this is complete, the traversal cursor is unchanged.
 */void
QCBORDecode_Private_SearchAndGetArrayOrMap(QCBORDecodeContext *pMe,
                                           QCBORItem          *pTarget,
                                           QCBORItem          *pItem,
                                           UsefulBufC         *pEncodedCBOR)
{
   MapSearchInfo      Info;
   QCBORDecodeNesting SaveNesting;
   size_t             uSaveCursor;

   pMe->uLastError = (uint8_t)QCBORDecode_Private_MapSearch(pMe, pTarget, &Info, NULL);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }
   pMe->uLastError = (uint8_t)QCBORDecode_Private_GetItemChecks(pMe, pMe->uLastError, Info.uStartOffset, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   /* Save the whole position of things so they can be restored.
    * so the cursor position is unchanged by this operation, like
    * all the other GetXxxxInMap() operations. */
   DecodeNesting_PrepareForMapSearch(&(pMe->nesting), &SaveNesting);
   uSaveCursor = UsefulInputBuf_Tell(&(pMe->InBuf));

   DecodeNesting_ResetMapOrArrayCount(&(pMe->nesting));
   UsefulInputBuf_Seek(&(pMe->InBuf), Info.uStartOffset);
   QCBORDecode_Private_GetArrayOrMap(pMe, pTarget[0].uDataType, pItem, pEncodedCBOR);

   UsefulInputBuf_Seek(&(pMe->InBuf), uSaveCursor);
   DecodeNesting_RestoreFromMapSearch(&(pMe->nesting), &SaveNesting);
}




static void
QCBORDecode_Private_ProcessTagOne(QCBORDecodeContext      *pMe,
                                  QCBORItem               *pItem,
                                  const uint8_t            uTagRequirement,
                                  const uint8_t            uQCBORType,
                                  const uint64_t           uTagNumber,
                                  QCBORTagContentCallBack *pfCB,
                                  size_t                   uOffset);

/**
 * @brief Semi-private to get an string by label to match a tag specification.
 *
 * @param[in] pMe              The decode context.
 * @param[in] nLabel           Label to search map for.
 * @param[in] uTagRequirement  Whether or not tag number is required.
 *                             See @ref QCBOR_TAG_REQUIREMENT_TAG.
 * @param[in] uQCBOR_Type      QCBOR type to search for.
 * @param[in] uTagNumber       Tag number to match.
 * @param[out] pString         The string found.
 *
 * This finds the string  with the given label in currently open
 * map. Then checks that its tag number and types matches the tag
 * specification. If not, an error is set in the decode context.
 */
void
QCBORDecode_Private_GetTaggedStringInMapN(QCBORDecodeContext  *pMe,
                                          const int64_t        nLabel,
                                          const uint8_t        uTagRequirement,
                                          const uint8_t        uQCBOR_Type,
                                          const uint64_t       uTagNumber,
                                          UsefulBufC          *pString)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                    &Item,
                                     uTagRequirement,
                                     uQCBOR_Type,
                                     uTagNumber,
                                     QCBORDecode_StringsTagCB,
                                     uOffset);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pString = Item.val.string;
   }
}


/**
 * @brief Semi-private to get an string by label to match a tag specification.
 *
 * @param[in] pMe              The decode context.
 * @param[in] szLabel           Label to search map for.
 * @param[in] uTagRequirement  Whether or not tag number is required.
 *                             See @ref QCBOR_TAG_REQUIREMENT_TAG.
 * @param[in] uQCBOR_Type      QCBOR type to search for.
 * @param[in] uTagNumber       Tag number to match.
 * @param[out] pString         The string found.
 *
 * This finds the string  with the given label in currently open
 * map. Then checks that its tag number and types matches the tag
 * specification. If not, an error is set in the decode context.
  */
void
QCBORDecode_Private_GetTaggedStringInMapSZ(QCBORDecodeContext  *pMe,
                                           const char          *szLabel,
                                           uint8_t              uTagRequirement,
                                           uint8_t              uQCBOR_Type,
                                           uint64_t             uTagNumber,
                                           UsefulBufC          *pString)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                   &Item,
                                   uTagRequirement,
                                   uQCBOR_Type,
                                   uTagNumber,
                                   QCBORDecode_StringsTagCB,
                                   uOffset);


   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pString = Item.val.string;
   }
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetItemsInMap(QCBORDecodeContext *pMe, QCBORItem *pItemList)
{
   pMe->uLastError = (uint8_t)QCBORDecode_Private_MapSearch(pMe, pItemList, NULL, NULL);
}

/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetItemsInMapWithCallback(QCBORDecodeContext *pMe,
                                      QCBORItem          *pItemList,
                                      void               *pCallbackCtx,
                                      QCBORItemCallback   pfCB)
{
   MapSearchCallBack CallBack;

   CallBack.pCBContext = pCallbackCtx;
   CallBack.pfCallback = pfCB;

   pMe->uLastError = (uint8_t)QCBORDecode_Private_MapSearch(pMe, pItemList, NULL, &CallBack);
}


#ifndef QCBOR_DISABLE_TAGS
/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_GetNextTagNumberInMapN(QCBORDecodeContext *pMe, const int64_t nLabel, uint64_t *puTagNumber)
{
   size_t         uOffset;
   MapSearchInfo  Info;
   QCBORItem      OneItemSeach[2];

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return pMe->uLastError;
   }

   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = QCBOR_TYPE_ANY;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORError uReturn = QCBORDecode_Private_MapSearch(pMe, OneItemSeach, &Info, NULL);

   uOffset = Info.uStartOffset;
   if(uOffset == pMe->uTagNumberCheckOffset) {
      pMe->uTagNumberIndex++;
   } else {
      pMe->uTagNumberIndex = 0;
   }

   *puTagNumber = CBOR_TAG_INVALID64;

   *puTagNumber = QCBORDecode_GetNthTagNumber(pMe, &OneItemSeach[0], pMe->uTagNumberIndex);
   if(*puTagNumber == CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNthTagNumber(pMe, &OneItemSeach[0], pMe->uTagNumberIndex+1) == CBOR_TAG_INVALID64 ) {
      pMe->uTagNumberIndex = QCBOR_ALL_TAGS_PROCESSED;
   }
   pMe->uTagNumberCheckOffset = uOffset;

   return uReturn;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
QCBORError
QCBORDecode_GetNextTagNumberInMapSZ(QCBORDecodeContext *pMe, const char *szLabel, uint64_t *puTagNumber)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   size_t         uOffset;
   MapSearchInfo  Info;
   QCBORItem      OneItemSeach[2];

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return pMe->uLastError;
   }

   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = QCBOR_TYPE_ANY;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORError uReturn = QCBORDecode_Private_MapSearch(pMe, OneItemSeach, &Info, NULL);


   uOffset = Info.uStartOffset;
   if(uOffset == pMe->uTagNumberCheckOffset) {
      pMe->uTagNumberIndex++;
   } else {
      pMe->uTagNumberIndex = 0;
   }

   *puTagNumber = CBOR_TAG_INVALID64;

   *puTagNumber = QCBORDecode_GetNthTagNumber(pMe, &OneItemSeach[0], pMe->uTagNumberIndex);
   if(*puTagNumber == CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNthTagNumber(pMe, &OneItemSeach[0], pMe->uTagNumberIndex+1) == CBOR_TAG_INVALID64 ) {
      pMe->uTagNumberIndex = 255; /* All tags clear for this item */
   }
   pMe->uTagNumberCheckOffset = uOffset;

   return uReturn;
#else
   (void)pMe;
   (void)szLabel;
   (void)puTagNumber;
   return QCBOR_ERR_LABEL_NOT_FOUND;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
}
#endif /* ! QCBOR_DISABLE_TAGS */


/**
 * @brief Search for a map/array by label and enter it
 *
 * @param[in] pMe  The decode context.
 * @param[in] pSearch The map/array to search for.
 *
 * @c pSearch is expected to contain one item of type map or array
 * with the label specified. The current bounded map will be searched for
 * this and if found  will be entered.
 *
 * If the label is not found, or the item found is not a map or array,
 * the error state is set.
 */
static void
QCBORDecode_Private_SearchAndEnter(QCBORDecodeContext *pMe, QCBORItem pSearch[])
{
   QCBORError     uErr;
   MapSearchInfo  SearchInfo;

   // The first item in pSearch is the one that is to be
   // entered. It should be the only one filled in. Any other
   // will be ignored unless it causes an error.
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   uErr = QCBORDecode_Private_MapSearch(pMe, pSearch, &SearchInfo, NULL);

   pMe->uLastError = (uint8_t)QCBORDecode_Private_GetItemChecks(pMe, uErr, SearchInfo.uStartOffset, pSearch);

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   if(pSearch->uDataType == QCBOR_TYPE_NONE) {
      pMe->uLastError = QCBOR_ERR_LABEL_NOT_FOUND;
      return;
   }


   /* The map or array was found. Now enter it.
    *
    * QCBORDecode_EnterBoundedMapOrArray() used here, requires the
    * next item for the pre-order traversal cursor to be the map/array
    * found by MapSearch(). The next few lines of code force the
    * cursor to that.
    *
    * There is no need to retain the old cursor because
    * QCBORDecode_EnterBoundedMapOrArray() will set it to the
    * beginning of the map/array being entered.
    *
    * The cursor is forced by: 1) setting the input buffer position to
    * the item offset found by MapSearch(), 2) setting the map/array
    * counter to the total in the map/array, 3) setting the nesting
    * level. Setting the map/array counter to the total is not
    * strictly correct, but this is OK because this cursor only needs
    * to be used to get one item and MapSearch() has already found it
    * confirming it exists.
    */
   UsefulInputBuf_Seek(&(pMe->InBuf), SearchInfo.uStartOffset);

   DecodeNesting_ResetMapOrArrayCount(&(pMe->nesting));

   DecodeNesting_SetCurrentToBoundedLevel(&(pMe->nesting));

   QCBORDecode_Private_EnterBoundedMapOrArray(pMe, pSearch->uDataType, NULL);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_EnterMapFromMapN(QCBORDecodeContext *pMe, int64_t nLabel)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = QCBOR_TYPE_MAP;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE;

   /* The map to enter was found, now finish off entering it. */
   QCBORDecode_Private_SearchAndEnter(pMe, OneItemSeach);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_EnterMapFromMapSZ(QCBORDecodeContext *pMe, const char  *szLabel)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = QCBOR_TYPE_MAP;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndEnter(pMe, OneItemSeach);
#else
   (void)szLabel;
   pMe->uLastError = QCBOR_ERR_LABEL_NOT_FOUND;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
}

/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_EnterArrayFromMapN(QCBORDecodeContext *pMe, int64_t nLabel)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = QCBOR_TYPE_ARRAY;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndEnter(pMe, OneItemSeach);
}

/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_EnterArrayFromMapSZ(QCBORDecodeContext *pMe, const char  *szLabel)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = QCBOR_TYPE_ARRAY;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndEnter(pMe, OneItemSeach);
#else
   (void)szLabel;
   pMe->uLastError = QCBOR_ERR_LABEL_NOT_FOUND;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
}


/**
 * @brief Semi-private to do the the work for EnterMap() and EnterArray().
 *
 * @param[in] pMe     The decode context
 * @param[in] uType   QCBOR_TYPE_MAP or QCBOR_TYPE_ARRAY.
 * @param[out] pItem  The data item for the map or array entered.
 *
 * The next item in the traversal must be a map or array.  This
 * consumes that item and does the book keeping to enter the map or
 * array.
 */
void
QCBORDecode_Private_EnterBoundedMapOrArray(QCBORDecodeContext *pMe,
                                           const uint8_t       uType,
                                           QCBORItem          *pItem)
{
    QCBORError uErr;

   /* Must only be called on maps and arrays. */
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state; do nothing.
      return;
   }

   /* Get the data item that is the map or array being entered. */
   QCBORItem Item;
   uErr = QCBORDecode_GetNext(pMe, &Item);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   uint8_t uItemDataType = Item.uDataType;

#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   if(uItemDataType == QCBOR_TYPE_MAP_AS_ARRAY ) {
      uItemDataType = QCBOR_TYPE_ARRAY;
   }
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */

   if(uItemDataType != uType) {
      uErr = QCBOR_ERR_UNEXPECTED_TYPE;
      goto Done;
   }

   QCBORDecode_Private_SaveTagNumbers(pMe, &Item);


   const bool bIsEmpty = (Item.uNextNestLevel <= Item.uNestingLevel);
   if(bIsEmpty) {
      if(DecodeNesting_IsCurrentDefiniteLength(&(pMe->nesting))) {
         // Undo decrement done by QCBORDecode_GetNext() so the the
         // the decrement when exiting the map/array works correctly
         pMe->nesting.pCurrent->u.ma.uCountCursor++;
      }
      // Special case to increment nesting level for zero-length maps
      // and arrays entered in bounded mode.
      DecodeNesting_Descend(&(pMe->nesting), uType);
   }

   pMe->uMapEndOffsetCache = QCBOR_MAP_OFFSET_CACHE_INVALID;

   uErr = DecodeNesting_EnterBoundedMapOrArray(&(pMe->nesting), bIsEmpty,
                                               UsefulInputBuf_Tell(&(pMe->InBuf)));

   if(pItem != NULL) {
      *pItem = Item;
   }

Done:
   pMe->uLastError = (uint8_t)uErr;
}


/**
 * @brief Exit a bounded map, array or bstr (semi-private).
 *
 * @param[in] pMe         Decode context.
 * @param[in] uEndOffset  The input buffer offset of the end of item exited.
 *
 * @returns  QCBOR_SUCCESS or an error code.
 *
 * This is the common work for exiting a level that is a bounded map,
 * array or bstr wrapped CBOR.
 *
 * One chunk of work is to set up the pre-order traversal so it is at
 * the item just after the bounded map, array or bstr that is being
 * exited. This is somewhat complex.
 *
 * The other work is to level-up the bounded mode to next higest
 * bounded mode or the top level if there isn't one.
 */
static QCBORError
QCBORDecode_Private_ExitBoundedLevel(QCBORDecodeContext *pMe,
                                     const uint32_t      uEndOffset)
{
   QCBORError uErr;

   /*
    * First the pre-order-traversal byte offset is positioned to the
    * item just after the bounded mode item that was just consumed.
    */
   UsefulInputBuf_Seek(&(pMe->InBuf), uEndOffset);

   /*
    * Next, set the current nesting level to one above the bounded
    * level that was just exited.
    *
    * DecodeNesting_CheckBoundedType() is always called before this
    * and makes sure pCurrentBounded is valid.
    */
   DecodeNesting_LevelUpCurrent(&(pMe->nesting));

   /*
    * This does the complex work of leveling up the pre-order
    * traversal when the end of a map or array or another bounded
    * level is reached.  It may do nothing, or ascend all the way to
    * the top level.
    */
   uErr = QCBORDecode_Private_NestLevelAscender(pMe, NULL, false);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   /*
    * This makes the next highest bounded level the current bounded
    * level. If there is no next highest level, then no bounded mode
    * is in effect.
    */
   DecodeNesting_LevelUpBounded(&(pMe->nesting));

   pMe->uMapEndOffsetCache = QCBOR_MAP_OFFSET_CACHE_INVALID;

Done:
   return uErr;
}


/**
 * @brief Get started exiting a map or array (semi-private)
 *
 * @param[in] pMe  The decode context
 * @param[in] uType  QCBOR_TYPE_ARRAY or QCBOR_TYPE_MAP
 *
 * This does some work for map and array exiting (but not
 * bstr exiting). Then QCBORDecode_Private_ExitBoundedLevel()
 * is called to do the rest.
 */
void
QCBORDecode_Private_ExitBoundedMapOrArray(QCBORDecodeContext *pMe,
                                          const uint8_t       uType)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      /* Already in error state; do nothing. */
      return;
   }

   QCBORError uErr;

   if(!DecodeNesting_IsBoundedType(&(pMe->nesting), uType)) {
      uErr = QCBOR_ERR_EXIT_MISMATCH;
      goto Done;
   }

   /*
    Have to set the offset to the end of the map/array
    that is being exited. If there is no cached value,
    from previous map search, then do a dummy search.
    */
   if(pMe->uMapEndOffsetCache == QCBOR_MAP_OFFSET_CACHE_INVALID) {
      QCBORItem Dummy;
      Dummy.uLabelType = QCBOR_TYPE_NONE;
      uErr = QCBORDecode_Private_MapSearch(pMe, &Dummy, NULL, NULL);
      if(uErr != QCBOR_SUCCESS) {
         goto Done;
      }
   }

   uErr = QCBORDecode_Private_ExitBoundedLevel(pMe, pMe->uMapEndOffsetCache);

Done:
   pMe->uLastError = (uint8_t)uErr;
}


// TODO: re order this file with tags stuff last. bstr is a tag thing
static QCBORError
QCBORDecode_Private_CheckTagNType(QCBORDecodeContext *pMe,
                                  const QCBORItem *pItem,
                                  const size_t uOffset,
                                  const uint8_t *uQCBORTypes,
                                  const uint64_t *uTagNumbers,
                                  const uint8_t uTagRequirement,
                                  bool *bTypeMatched);

/**
 * @brief The main work of entering some byte-string wrapped CBOR.
 *
 * @param[in] pMe             The decode context.
 * @param[in] pItem           The byte string item.
 * @param[in] uTagRequirement One of @c QCBOR_TAG_REQUIREMENT_XXX
 * @param[out] pBstr          Pointer and length of byte string entered.
 *
 * This is called once the byte string item has been decoded to do all
 * the book keeping work for descending a nesting level into the
 * nested CBOR.
 *
 * See QCBORDecode_EnterBstrWrapped() for details on uTagRequirement.
 */
static QCBORError
QCBORDecode_Private_EnterBstrWrapped(QCBORDecodeContext *pMe,
                                     const QCBORItem    *pItem,
                                     const uint8_t       uTagRequirement,
                                     const size_t        uOffset,
                                     UsefulBufC         *pBstr)
{
   bool       bTypeMatched;
   QCBORError uError;

   const uint8_t uTypes[] = {QBCOR_TYPE_WRAPPED_CBOR, QBCOR_TYPE_WRAPPED_CBOR_SEQUENCE, QCBOR_TYPE_NONE};
   const uint64_t uTagNumbers[] = {CBOR_TAG_CBOR, CBOR_TAG_CBOR_SEQUENCE, CBOR_TAG_INVALID64};


   if(pBstr) {
      *pBstr = NULLUsefulBufC;
   }

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return pMe->uLastError;
   }

   if(pItem->uDataAlloc) {
      return QCBOR_ERR_CANNOT_ENTER_ALLOCATED_STRING;
   }

   uError = QCBORDecode_Private_CheckTagNType(pMe,
                                              pItem,
                                              uOffset,
                                              uTypes, // TODO: maybe this should be empty
                                              uTagNumbers,
                                              uTagRequirement,
                                             &bTypeMatched);

   if(pItem->uDataType != QCBOR_TYPE_BYTE_STRING) {
      uError = QCBOR_ERR_BAD_TAG_CONTENT; // TODO: error
   }


   if(DecodeNesting_IsCurrentDefiniteLength(&(pMe->nesting))) {
      /* Reverse the decrement done by GetNext() for the bstr so the
       * increment in QCBORDecode_NestLevelAscender() called by
       * ExitBoundedLevel() will work right.
       */
      DecodeNesting_ReverseDecrement(&(pMe->nesting));
   }

   if(pBstr) {
      *pBstr = pItem->val.string;
   }

   /* This saves the current length of the UsefulInputBuf and then
    * narrows the UsefulInputBuf to start and length of the wrapped
    * CBOR that is being entered.
    *
    * Most of these calls are simple inline accessors so this doesn't
    * amount to much code.
    */

   const size_t uPreviousLength = UsefulInputBuf_GetBufferLength(&(pMe->InBuf));
   /* This check makes the cast of uPreviousLength to uint32_t below safe. */
   if(uPreviousLength >= QCBOR_MAX_DECODE_INPUT_SIZE) {
      uError = QCBOR_ERR_INPUT_TOO_LARGE;
      goto Done;
   }

   const size_t uStartOfBstr = UsefulInputBuf_PointerToOffset(&(pMe->InBuf),
                                                              pItem->val.string.ptr);
   /* This check makes the cast of uStartOfBstr to uint32_t below safe. */
   if(uStartOfBstr == SIZE_MAX || uStartOfBstr > QCBOR_MAX_DECODE_INPUT_SIZE) {
      /* This should never happen because pItem->val.string.ptr should
       * always be valid since it was just returned.
       */
      uError = QCBOR_ERR_INPUT_TOO_LARGE;
      goto Done;
   }

   const size_t uEndOfBstr = uStartOfBstr + pItem->val.string.len;

   UsefulInputBuf_Seek(&(pMe->InBuf), uStartOfBstr);
   UsefulInputBuf_SetBufferLength(&(pMe->InBuf), uEndOfBstr);

   uError = DecodeNesting_DescendIntoBstrWrapped(&(pMe->nesting),
                                                 (uint32_t)uPreviousLength,
                                                 (uint32_t)uStartOfBstr);
Done:
   return uError;
}


static void
QCBORDecode_Private_GetAndTell(QCBORDecodeContext *pMe, QCBORItem *Item, size_t *uOffset)
{
#ifndef QCBOR_DISABLE_TAGS
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   *uOffset = QCBORDecode_Tell(pMe);
#else
   *uOffset = SIZE_MAX;

#endif /* ! QCBOR_DISABLE_TAGS */
   pMe->uLastError = (uint8_t)QCBORDecode_Private_GetNextTagContent(pMe, Item);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_EnterBstrWrapped(QCBORDecodeContext *pMe,
                             const uint8_t       uTagRequirement,
                             UsefulBufC         *pBstr)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   pMe->uLastError = (uint8_t)QCBORDecode_Private_EnterBstrWrapped(pMe,
                                                                  &Item,
                                                                   uTagRequirement,
                                                                   uOffset,
                                                                   pBstr);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_EnterBstrWrappedFromMapN(QCBORDecodeContext *pMe,
                                     const int64_t       nLabel,
                                     const uint8_t       uTagRequirement,
                                     UsefulBufC         *pBstr)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_BYTE_STRING, &Item, &uOffset);
   pMe->uLastError = (uint8_t)QCBORDecode_Private_EnterBstrWrapped(pMe,
                                                                  &Item,
                                                                   uTagRequirement,
                                                                   uOffset,
                                                                   pBstr);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_EnterBstrWrappedFromMapSZ(QCBORDecodeContext *pMe,
                                      const char         *szLabel,
                                      const uint8_t       uTagRequirement,
                                      UsefulBufC         *pBstr)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_BYTE_STRING, &Item, &uOffset);
   pMe->uLastError = (uint8_t)QCBORDecode_Private_EnterBstrWrapped(pMe,
                                                                  &Item,
                                                                   uTagRequirement,
                                                                   uOffset,
                                                                   pBstr);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_ExitBstrWrapped(QCBORDecodeContext *pMe)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state; do nothing.
      return;
   }

   if(!DecodeNesting_IsBoundedType(&(pMe->nesting), QCBOR_TYPE_BYTE_STRING)) {
      pMe->uLastError = QCBOR_ERR_EXIT_MISMATCH;
      return;
   }

   const uint32_t uEndOfBstr = (uint32_t)UsefulInputBuf_GetBufferLength(&(pMe->InBuf));

   /*
    Reset the length of the UsefulInputBuf to what it was before
    the bstr wrapped CBOR was entered.
    */
   UsefulInputBuf_SetBufferLength(&(pMe->InBuf),
                               DecodeNesting_GetPreviousBoundedEnd(&(pMe->nesting)));


   QCBORError uErr = QCBORDecode_Private_ExitBoundedLevel(pMe, uEndOfBstr);
   pMe->uLastError = (uint8_t)uErr;
}



/**
 * @brief Process simple type true and false, a boolean
 *
 * @param[in] pMe     The decode context.
 * @param[in] pItem   The item with either true or false.
 * @param[out] pBool  The boolean value output.
 *
 * Sets the internal error if the item isn't a true or a false. Also
 * records any tag numbers as the tag numbers of the last item.
 */
static void
QCBORDecode_Private_ProcessBool(QCBORDecodeContext *pMe,
                                const QCBORItem    *pItem,
                                bool               *pBool)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      /* Already in error state, do nothing */
      return;
   }

   switch(pItem->uDataType) {
      case QCBOR_TYPE_TRUE:
         *pBool = true;
         break;

      case QCBOR_TYPE_FALSE:
         *pBool = false;
         break;

      default:
         pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
         break;
   }
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetBool(QCBORDecodeContext *pMe, bool *pValue)
{
   QCBORItem  Item;
   QCBORDecode_VGetNext(pMe, &Item);
   QCBORDecode_Private_ProcessBool(pMe, &Item, pValue);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetBoolInMapN(QCBORDecodeContext *pMe,
                          const int64_t       nLabel,
                          bool               *pValue)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);
   QCBORDecode_Private_ProcessBool(pMe, &Item, pValue);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetBoolInMapSZ(QCBORDecodeContext *pMe,
                           const char         *szLabel,
                           bool               *pValue)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);
   QCBORDecode_Private_ProcessBool(pMe, &Item, pValue);
}


/**
 * @brief Process simple values.
 *
 * @param[in] pMe     The decode context.
 * @param[in] pItem   The item with the simple value.
 * @param[out] puSimple  The simple value output.
 *
 * Sets the internal error if the item isn't a true or a false. Also
 * records any tag numbers as the tag numbers of the last item.
 */
static void
QCBORDecode_Private_ProcessSimple(QCBORDecodeContext *pMe,
                                  const QCBORItem    *pItem,
                                  uint8_t            *puSimple)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   /* It's kind of lame to remap true...undef back to simple values, but
    * this function isn't used much and to not do it would require
    * changing GetNext() behavior in an incompatible way.
    */
   switch(pItem->uDataType) {
      case QCBOR_TYPE_UKNOWN_SIMPLE:
         *puSimple = pItem->val.uSimple;
         break;

      case QCBOR_TYPE_TRUE:
         *puSimple = CBOR_SIMPLEV_TRUE;
         break;

      case QCBOR_TYPE_FALSE:
         *puSimple = CBOR_SIMPLEV_FALSE;
         break;

      case QCBOR_TYPE_NULL:
         *puSimple = CBOR_SIMPLEV_NULL;
         break;

      case QCBOR_TYPE_UNDEF:
         *puSimple = CBOR_SIMPLEV_UNDEF;
         break;

      default:
         pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
         return;
   }
}

/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetSimple(QCBORDecodeContext *pMe, uint8_t *puSimple)
{
   QCBORItem Item;
   QCBORDecode_VGetNext(pMe, &Item);
   QCBORDecode_Private_ProcessSimple(pMe, &Item, puSimple);
}

/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetSimpleInMapN(QCBORDecodeContext *pMe,
                            int64_t             nLabel,
                            uint8_t            *puSimpleValue)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);
   QCBORDecode_Private_ProcessSimple(pMe, &Item, puSimpleValue);
}

/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetSimpleInMapSZ(QCBORDecodeContext *pMe,
                             const char         *szLabel,
                             uint8_t            *puSimpleValue)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);
   QCBORDecode_Private_ProcessSimple(pMe, &Item, puSimpleValue);
}




#ifndef QCBOR_DISABLE_TAGS
// TODO:  uTagNumber might be better a list than calling this multiple times
static QCBORError
QCBORDecode_Private_Check1TagNumber(const QCBORDecodeContext *pMe,
                                    const QCBORItem          *pItem,
                                    const uint64_t            uTagNumber,
                                    const size_t              uOffset)
{
   if(pItem->auTagNumbers[0] == CBOR_TAG_INVALID16) {
      /* There are no tag numbers at all, so no unprocessed */
      return QCBOR_SUCCESS;
   }

   /* There are some tag numbers, so keep checking. This check passes
    * if there is one and only one tag number that matches uTagNumber
    */

   // TODO: behave different in v1 and v2?

   const uint64_t uInnerTag = QCBORDecode_GetNthTagNumber(pMe, pItem, 0);

   if(uInnerTag == uTagNumber && pItem->auTagNumbers[1] == CBOR_TAG_INVALID16 ) {
      /* The only tag number is the one we are processing so no unprocessed */
      return QCBOR_SUCCESS;
   }

   if(uOffset != pMe->uTagNumberCheckOffset) {
      /* processed tag numbers are for some other item, not us */
      return QCBOR_ERR_UNPROCESSED_TAG_NUMBER;
   }

   if(pMe->uTagNumberIndex != 1) {
      return QCBOR_ERR_UNPROCESSED_TAG_NUMBER;
   }

   return QCBOR_SUCCESS;
}
#endif


static QCBORError
QCBORDecode_Private_CheckTagNType(QCBORDecodeContext *pMe,
                                  const QCBORItem    *pItem,
                                  const size_t        uOffset,
                                  const uint8_t      *uQCBORTypes,
                                  const uint64_t     *uTagNumbers,
                                  const uint8_t       uTagRequirement,
                                  bool               *bTypeMatched)
{
   const int      nTagReq   = uTagRequirement & ~QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS;

   *bTypeMatched = false;
   for(const uint8_t *pTNum = uQCBORTypes; *pTNum != QCBOR_TYPE_NONE; pTNum++) {
      if(pItem->uDataType == *pTNum) {
         *bTypeMatched = true;
         break;
      }
   }

#ifndef QCBOR_DISABLE_TAGS
   bool        bTagNumberMatched;
   QCBORError  uErr;
   const uint64_t uInnerTag = QCBORDecode_GetNthTagNumber(pMe, pItem, 0);

   bTagNumberMatched = false;
   for(const uint64_t *pQType = uTagNumbers; *pQType != CBOR_TAG_INVALID64; pQType++) {
      if(uInnerTag == *pQType) {
         bTagNumberMatched = true;
         break;
      }
   }


   if(nTagReq == QCBOR_TAG_REQUIREMENT_TAG) {
      /* There must be a tag number */
      if(!bTagNumberMatched && !*bTypeMatched) {
         return QCBOR_ERR_UNEXPECTED_TYPE; // TODO: error code
      }

   } else if(nTagReq == QCBOR_TAG_REQUIREMENT_NOT_A_TAG) {
      if(bTagNumberMatched || *bTypeMatched) {
         return QCBOR_ERR_UNEXPECTED_TYPE; // TODO: error code
      }

   } else if(nTagReq == QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG) {
      /* No check necessary */
   }

   /* Now check if there are extra tags and if there's an error in them */
   if(!(uTagRequirement & QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS)) {
      /* The flag to ignore extra is not set, so keep checking */
      for(const uint64_t *pTNum = uTagNumbers; *pTNum != CBOR_TAG_INVALID64; pTNum++) {
         uErr = QCBORDecode_Private_Check1TagNumber(pMe, pItem, *pTNum, uOffset);
         if(uErr != QCBOR_SUCCESS) {
            return uErr;
         }
      }
   }

   return QCBOR_SUCCESS;
#else
   (void)pMe;
   (void)uOffset;
   (void)uTagNumbers;

   if(nTagReq != QCBOR_TAG_REQUIREMENT_TAG && bTypeMatched) {
      return QCBOR_SUCCESS;
   } else {
      return QCBOR_ERR_UNEXPECTED_TYPE;
   }

#endif

}


static void
QCBORDecode_Private_ProcessTagItemMulti(QCBORDecodeContext      *pMe,
                                        QCBORItem               *pItem,
                                        const uint8_t            uTagRequirement,
                                        const uint8_t            uQCBORTypes[],
                                        const uint64_t           uTagNumbers[],
                                        QCBORTagContentCallBack *pfCB,
                                        size_t                   uOffset)
{
   QCBORError uErr;
   bool       bTypeMatched;

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   uErr = QCBORDecode_Private_CheckTagNType(pMe,
                                            pItem,
                                            uOffset,
                                            uQCBORTypes,
                                            uTagNumbers,
                                            uTagRequirement,
                                            &bTypeMatched);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   if(!bTypeMatched) {
      /* Tag content wasn't previously processed, do it now */
      uErr = (*pfCB)(pMe, NULL, uTagNumbers[0], pItem);
      if(uErr != QCBOR_SUCCESS) {
         goto Done;
      }
   }

Done:
   pMe->uLastError = (uint8_t)uErr;
}


/*
 **/
static void
QCBORDecode_Private_ProcessTagItem(QCBORDecodeContext      *pMe,
                                   QCBORItem               *pItem,
                                   const uint8_t            uTagRequirement,
                                   const uint8_t            uQCBORTypes[],
                                   const uint64_t           uTagNumber,
                                   QCBORTagContentCallBack *pfCB,
                                   size_t                   uOffset)
{
   uint64_t auTagNumbers[2];

   auTagNumbers[0] = uTagNumber;
   auTagNumbers[1] = CBOR_TAG_INVALID64;

   QCBORDecode_Private_ProcessTagItemMulti(pMe,
                                           pItem,
                                           uTagRequirement,
                                           uQCBORTypes,
                                           auTagNumbers,
                                           pfCB,
                                           uOffset);
}


static void
QCBORDecode_Private_ProcessTagOne(QCBORDecodeContext     *pMe,
                                  QCBORItem               *pItem,
                                  const uint8_t            uTagRequirement,
                                  const uint8_t            uQCBORType,
                                  const uint64_t           uTagNumber,
                                  QCBORTagContentCallBack *pfCB,
                                  const size_t             uOffset)
{
   uint8_t auQCBORType[2];

   auQCBORType[0] = uQCBORType;
   auQCBORType[1] = QCBOR_TYPE_NONE;

   QCBORDecode_Private_ProcessTagItem(pMe,
                                      pItem,
                                      uTagRequirement,
                                      auQCBORType,
                                      uTagNumber,
                                      pfCB,
                                      uOffset);
}




/*
 * Public function, see header qcbor/qcbor_spiffy_decode.h file
 */
void
QCBORDecode_GetEpochDate(QCBORDecodeContext *pMe,
                         uint8_t             uTagRequirement,
                         int64_t            *pnTime)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     &Item,
                                     uTagRequirement,
                                     QCBOR_TYPE_DATE_EPOCH,
                                     CBOR_TAG_DATE_EPOCH,
                                     QCBORDecode_DateEpochTagCB,
                                     uOffset);
   *pnTime = Item.val.epochDate.nSeconds;
}


/*
 * Public function, see header qcbor/qcbor_spiffy_decode.h file
 */
void
QCBORDecode_GetEpochDateInMapN(QCBORDecodeContext *pMe,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnTime)
{
   QCBORItem Item;
   size_t uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     &Item,
                                     uTagRequirement,
                                     QCBOR_TYPE_DATE_EPOCH,
                                     CBOR_TAG_DATE_EPOCH,
                                     QCBORDecode_DateEpochTagCB,
                                     uOffset);
   *pnTime = Item.val.epochDate.nSeconds;
}


/*
 * Public function, see header qcbor/qcbor_spiffy_decode.h file
 */
void
QCBORDecode_GetEpochDateInMapSZ(QCBORDecodeContext *pMe,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                int64_t            *pnTime)
{
   QCBORItem Item;
   size_t uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     &Item,
                                     uTagRequirement,
                                     QCBOR_TYPE_DATE_EPOCH,
                                     CBOR_TAG_DATE_EPOCH,
                                     QCBORDecode_DateEpochTagCB,
                                     uOffset);
   *pnTime = Item.val.epochDate.nSeconds;
}


/*
 * Public function, see header qcbor/qcbor_decode.h
 */
void
QCBORDecode_GetEpochDays(QCBORDecodeContext *pMe,
                         uint8_t             uTagRequirement,
                         int64_t            *pnDays)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     &Item,
                                     uTagRequirement,
                                     QCBOR_TYPE_DAYS_EPOCH,
                                     CBOR_TAG_DAYS_EPOCH,
                                     QCBORDecode_DaysEpochTagCB,
                                     uOffset);
   *pnDays = Item.val.epochDays;
}


/*
 * Public function, see header qcbor/qcbor_decode.h
 */
void
QCBORDecode_GetEpochDaysInMapN(QCBORDecodeContext *pMe,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnDays)
{
   QCBORItem Item;
   size_t uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     &Item,
                                     uTagRequirement,
                                     QCBOR_TYPE_DAYS_EPOCH,
                                     CBOR_TAG_DAYS_EPOCH,
                                     QCBORDecode_DaysEpochTagCB,
                                     uOffset);
   *pnDays = Item.val.epochDays;
}


/*
 * Public function, see header qcbor/qcbor_decode.h
 */
void
QCBORDecode_GetEpochDaysInMapSZ(QCBORDecodeContext *pMe,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                int64_t            *pnDays)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                      &Item,
                                      uTagRequirement,
                                      QCBOR_TYPE_DAYS_EPOCH,
                                      CBOR_TAG_DAYS_EPOCH,
                                      QCBORDecode_DaysEpochTagCB,
                                      uOffset);
   *pnDays = Item.val.epochDays;
}




void
QCBORDecode_Private_GetTaggedString(QCBORDecodeContext  *pMe,
                                    const uint8_t        uTagRequirement,
                                    const uint8_t        uQCBOR_Type,
                                    const uint64_t       uTagNumber,
                                    UsefulBufC          *pStr)
{
   QCBORItem  Item;
   size_t uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     &Item,
                                      uTagRequirement,
                                      uQCBOR_Type,
                                      uTagNumber,
                                      QCBORDecode_StringsTagCB,
                                      uOffset);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pStr = Item.val.string;
   } else {
      *pStr = NULLUsefulBufC;
   }
}



static void
QCBORDecode_Private_GetMIME(QCBORDecodeContext *pMe,
                            const uint8_t       uTagRequirement,
                            QCBORItem          *pItem,
                            UsefulBufC         *pValue,
                            bool               *pbIsTag257,
                            size_t              uOffset)
{
   QCBORError uErr;

   const uint8_t puTypes[] = {QCBOR_TYPE_MIME, QCBOR_TYPE_BINARY_MIME, QCBOR_TYPE_NONE};

   const uint64_t puTNs[] = {CBOR_TAG_MIME, CBOR_TAG_BINARY_MIME, CBOR_TAG_INVALID64};

   QCBORDecode_Private_ProcessTagItemMulti(pMe,
                                           pItem,
                                           uTagRequirement,
                                           puTypes,
                                           puTNs,
                                           QCBORDecode_MIMETagCB,
                                           uOffset);
   if(pMe->uLastError) {
      return;
   }

   if(pItem->uDataType == QCBOR_TYPE_MIME) {
      *pbIsTag257 = false;
   } else if(pItem->uDataType == QCBOR_TYPE_BINARY_MIME) {
      *pbIsTag257 = true;
   }
   *pValue = pItem->val.string;


   uErr = QCBOR_SUCCESS;

   pMe->uLastError = (uint8_t)uErr;
}


void
QCBORDecode_GetMIMEMessage(QCBORDecodeContext *pMe,
                           const uint8_t       uTagRequirement,
                           UsefulBufC         *pMessage,
                           bool               *pbIsTag257)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_GetMIME(pMe,
                               uTagRequirement,
                              &Item,
                               pMessage,
                               pbIsTag257,
                               uOffset);
}

void
QCBORDecode_GetMIMEMessageInMapN(QCBORDecodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uTagRequirement,
                                 UsefulBufC         *pMessage,
                                 bool               *pbIsTag257)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_GetMIME(pMe,
                                uTagRequirement,
                               &Item,
                                pMessage,
                                pbIsTag257,
                                uOffset);
}

void
QCBORDecode_GetMIMEMessageInMapSZ(QCBORDecodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uTagRequirement,
                                  UsefulBufC         *pMessage,
                                  bool               *pbIsTag257)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_GetMIME(pMe,
                                uTagRequirement,
                               &Item,
                                pMessage,
                                pbIsTag257,
                                uOffset);
}



// Improvement: add methods for wrapped CBOR, a simple alternate
// to EnterBstrWrapped


#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA

/**
 * @brief Prototype for conversion of exponent and mantissa to unsigned integer.
 *
 * @param[in] uMantissa    The mantissa.
 * @param[in] nExponent    The exponent.
 * @param[out] puResult  The resulting integer.
 *
 * Concrete implementations of this are for exponent base 10 and 2 supporting
 * decimal fractions and big floats.
 */
typedef QCBORError (*fExponentiator)(uint64_t uMantissa, int64_t nExponent, uint64_t *puResult);


/**
 * @brief  Base 10 exponentiate a mantissa and exponent into an unsigned 64-bit integer.
 *
 * @param[in] uMantissa  The unsigned integer mantissa.
 * @param[in] nExponent  The signed integer exponent.
 * @param[out] puResult  Place to return the unsigned integer result.
 *
 * This computes: mantissa * 10 ^^ exponent as for a decimal fraction. The output is a 64-bit
 * unsigned integer.
 *
 * There are many inputs for which the result will not fit in the
 * 64-bit integer and @ref QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW will
 * be returned.
 */
static QCBORError
QCBOR_Private_Exponentitate10(const uint64_t uMantissa,
                              int64_t        nExponent,
                              uint64_t      *puResult)
{
   uint64_t uResult = uMantissa;

   if(uResult != 0) {
      /* This loop will run a maximum of 19 times because
       * UINT64_MAX < 10 ^^ 19. More than that will cause
       * exit with the overflow error
       */
      for(; nExponent > 0; nExponent--) {
         if(uResult > UINT64_MAX / 10) {
            return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
         }
         uResult = uResult * 10;
      }

      for(; nExponent < 0; nExponent++) {
         uResult = uResult / 10;
         if(uResult == 0) {
            return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
         }
      }
   }
   /* else, mantissa is zero so this returns zero */

   *puResult = uResult;

   return QCBOR_SUCCESS;
}


/**
 * @brief  Base 2 exponentiate a mantissa and exponent into an unsigned 64-bit integer.
 *
 * @param[in] uMantissa  The unsigned integer mantissa.
 * @param[in] nExponent  The signed integer exponent.
 * @param[out] puResult  Place to return the unsigned integer result.
 *
 * This computes: mantissa * 2 ^^ exponent as for a big float. The
 * output is a 64-bit unsigned integer.
 *
 * There are many inputs for which the result will not fit in the
 * 64-bit integer and @ref QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW will
 * be returned.
 */
static QCBORError
QCBOR_Private_Exponentitate2(const uint64_t uMantissa,
                             int64_t        nExponent,
                             uint64_t      *puResult)
{
   uint64_t uResult;

   uResult = uMantissa;

   /* This loop will run a maximum of 64 times because INT64_MAX <
    * 2^31. More than that will cause exit with the overflow error
    */
   while(nExponent > 0) {
      if(uResult > UINT64_MAX >> 1) {
         return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
      }
      uResult = uResult << 1;
      nExponent--;
   }

   while(nExponent < 0 ) {
      if(uResult == 0) {
         return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
      }
      uResult = uResult >> 1;
      nExponent++;
   }

   *puResult = uResult;

   return QCBOR_SUCCESS;
}


/**
 * @brief Exponentiate a signed mantissa and signed exponent to produce a signed result.
 *
 * @param[in] nMantissa  Signed integer mantissa.
 * @param[in] nExponent  Signed integer exponent.
 * @param[out] pnResult  Place to put the signed integer result.
 * @param[in] pfExp      Exponentiation function.
 *
 * @returns Error code
 *
 * @c pfExp performs exponentiation on and unsigned mantissa and
 * produces an unsigned result. This converts the mantissa from signed
 * and converts the result to signed. The exponentiation function is
 * either for base 2 or base 10 (and could be other if needed).
 */
static QCBORError
QCBOR_Private_ExponentiateNN(const int64_t  nMantissa,
                             const int64_t  nExponent,
                             int64_t       *pnResult,
                             fExponentiator pfExp)
{
   uint64_t uResult;
   uint64_t uMantissa;

   /* Take the absolute value and put it into an unsigned. */
   if(nMantissa >= 0) {
      /* Positive case is straightforward */
      uMantissa = (uint64_t)nMantissa;
   } else if(nMantissa != INT64_MIN) {
      /* The common negative case. See next. */
      uMantissa = (uint64_t)-nMantissa;
   } else {
      /* int64_t and uint64_t are always two's complement per the
       * C standard (and since QCBOR uses these it only works with
       * two's complement, which is pretty much universal these
       * days). The range of a negative two's complement integer is
       * one more that than a positive, so the simple code above might
       * not work all the time because you can't simply negate the
       * value INT64_MIN because it can't be represented in an
       * int64_t. -INT64_MIN can however be represented in a
       * uint64_t. Some compilers seem to recognize this case for the
       * above code and put the correct value in uMantissa, however
       * they are not required to do this by the C standard. This next
       * line does however work for all compilers.
       *
       * This does assume two's complement where -INT64_MIN ==
       * INT64_MAX + 1 (which wouldn't be true for one's complement or
       * sign and magnitude (but we know we're using two's complement
       * because int64_t requires it)).
       *
       * See these, particularly the detailed commentary:
       * https://stackoverflow.com/questions/54915742/does-c99-mandate-a-int64-t-type-be-available-always
       * https://stackoverflow.com/questions/37301078/is-negating-int-min-undefined-behaviour
       */
      uMantissa = (uint64_t)INT64_MAX+1;
   }

   /* Call the exponentiator passed for either base 2 or base 10.
    * Here is where most of the overflow errors are caught. */
   QCBORError uReturn = (*pfExp)(uMantissa, nExponent, &uResult);
   if(uReturn) {
      return uReturn;
   }

   /* Convert back to the sign of the original mantissa */
   if(nMantissa >= 0) {
      if(uResult > INT64_MAX) {
         return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
      }
      *pnResult = (int64_t)uResult;
   } else {
      /* (uint64_t)INT64_MAX+1 is used to represent the absolute value
       * of INT64_MIN. This assumes two's compliment representation
       * where INT64_MIN is one increment farther from 0 than
       * INT64_MAX.  Trying to write -INT64_MIN doesn't work to get
       * this because the compiler makes it an int64_t which can't
       * represent -INT64_MIN. Also see above.
       */
      if(uResult > (uint64_t)INT64_MAX+1) {
         return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
      }
      *pnResult = -(int64_t)uResult;
   }

   return QCBOR_SUCCESS;
}


/**
 * @brief Exponentiate an unsigned mantissa and signed exponent to produce an unsigned result.
 *
 * @param[in] nMantissa  Signed integer mantissa.
 * @param[in] nExponent  Signed integer exponent.
 * @param[out] puResult  Place to put the signed integer result.
 * @param[in] pfExp      Exponentiation function.
 *
 * @returns Error code
 *
 * @c pfExp performs exponentiation on and unsigned mantissa and
 * produces an unsigned result. This errors out if the mantissa
 * is negative because the output is unsigned.
 */
static QCBORError
QCBOR_Private_ExponentitateNU(const int64_t  nMantissa,
                              const int64_t  nExponent,
                              uint64_t      *puResult,
                              fExponentiator pfExp)
{
   if(nMantissa < 0) {
      return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
   }

   /* Cast to unsigned is OK because of check for negative.
    * Cast to unsigned is OK because UINT64_MAX > INT64_MAX.
    * Exponentiation is straight forward
    */
   return (*pfExp)((uint64_t)nMantissa, nExponent, puResult);
}


/**
 * @brief Exponentiate an usnigned mantissa and unsigned exponent to produce an unsigned result.
 *
 * @param[in] uMantissa  Unsigned integer mantissa.
 * @param[in] nExponent  Unsigned integer exponent.
 * @param[out] puResult  Place to put the unsigned integer result.
 * @param[in] pfExp      Exponentiation function.
 *
 * @returns Error code
 *
 * @c pfExp performs exponentiation on and unsigned mantissa and
 * produces an unsigned result so this is just a wrapper that does
 * nothing (and is likely inlined).
 */
static QCBORError
QCBOR_Private_ExponentitateUU(const uint64_t uMantissa,
                              const int64_t  nExponent,
                              uint64_t      *puResult,
                              fExponentiator pfExp)
{
   return (*pfExp)(uMantissa, nExponent, puResult);
}

#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */




/**
 * @brief Convert a CBOR big number to a uint64_t.
 *
 * @param[in] BigNumber  Bytes of the big number to convert.
 * @param[in] uMax       Maximum value allowed for the result.
 * @param[out] pResult   Place to put the unsigned integer result.
 *
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW   When the bignumber is
 *                                                too large to fit
 * @retval QCBOR_SUCCESS                          The conversion succeeded.
 *
 * Many values will overflow because a big number can represent a much
 * larger range than uint64_t.
 */
static QCBORError
QCBORDecode_Private_BigNumberToUInt(const UsefulBufC BigNumber,
                                    const uint64_t   uMax,
                                    uint64_t        *pResult)
{
   uint64_t uResult;
   size_t   uLen;

   const uint8_t *pByte = BigNumber.ptr;

   uResult = 0;
   for(uLen = BigNumber.len; uLen > 0; uLen--) {
      if(uResult > (uMax >> 8)) {
         return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
      }
      uResult = (uResult << 8) + *pByte++;
   }

   *pResult = uResult;
   return QCBOR_SUCCESS;
}


/**
 * @brief Convert a CBOR postive big number to a uint64_t.
 *
 * @param[in] BigNumber  Bytes of the big number to convert.
 * @param[out] pResult   Place to put the unsigned integer result.
 *
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW   When the bignumber is
 *                                                too large to fit
 * @retval QCBOR_SUCCESS                          The conversion succeeded.
 *
 * Many values will overflow because a big num can represent a much
 * larger range than uint64_t.
 */
static QCBORError
QCBORDecode_Private_PositiveBigNumberToUInt(const UsefulBufC BigNumber,
                                            uint64_t        *pResult)
{
   return QCBORDecode_Private_BigNumberToUInt(BigNumber, UINT64_MAX, pResult);
}


/**
 * @brief Convert a CBOR positive big number to an int64_t.
 *
 * @param[in] BigNumber  Bytes of the big number to convert.
 * @param[out] pResult   Place to put the signed integer result.
 *
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW   When the bignumber is
 *                                                too large to fit
 * @retval QCBOR_SUCCESS                          The conversion succeeded.
 *
 * Many values will overflow because a big num can represent a much
 * larger range than int64_t.
 */
static QCBORError
QCBORDecode_Private_PositiveBigNumberToInt(const UsefulBufC BigNumber,
                                           int64_t         *pResult)
{
   uint64_t    uResult;
   QCBORError  uError;

   uError = QCBORDecode_Private_BigNumberToUInt(BigNumber, INT64_MAX, &uResult);
   if(uError != QCBOR_SUCCESS) {
      return uError;
   }
   /* Cast safe because QCBORDecode_Private_BigNumberToUInt() limits to INT64_MAX */
   *pResult = (int64_t)uResult;
   return QCBOR_SUCCESS;
}


/**
 * @brief Convert a CBOR negative big number to an int64_t.
 *
 * @param[in] BigNumber  Bytes of the big number to convert.
 * @param[out] pnResult  Place to put the signed integer result.
 *
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW   When the bignumber is
 *                                                too large to fit
 * @retval QCBOR_SUCCESS                          The conversion succeeded.
 *
 * Many values will overflow because a big num can represent a much
 * larger range than int64_t.
 */
static QCBORError
QCBORDecode_Private_NegativeBigNumberToInt(const UsefulBufC BigNumber,
                                           int64_t         *pnResult)
{
   uint64_t    uResult;
   QCBORError  uError;

   /* The negative integer furthest from zero for a C int64_t is
    * INT64_MIN which is expressed as -INT64_MAX - 1. The value of a
    * negative number in CBOR is computed as -n - 1 where n is the
    * encoded integer, where n is what is in the variable BigNum. When
    * converting BigNum to a uint64_t, the maximum value is thus
    * INT64_MAX, so that when it -n - 1 is applied to it the result
    * will never be further from 0 than INT64_MIN.
    *
    *   -n - 1 <= INT64_MIN.
    *   -n - 1 <= -INT64_MAX - 1
    *    n     <= INT64_MAX.
    */
   uError = QCBORDecode_Private_BigNumberToUInt(BigNumber, INT64_MAX, &uResult);
   if(uError != QCBOR_SUCCESS) {
      return uError;
   }

   /* Now apply -n - 1. The cast is safe because
    * ConvertBigNumToUnsigned() is limited to INT64_MAX which does fit
    * is the largest positive integer that an int64_t can
    * represent. */
   *pnResult =  -(int64_t)uResult - 1;

   return QCBOR_SUCCESS;
}

/**
 * @brief Convert an integer to a big number.
 *
 * @param[in] uNum          The integer to convert.
 * @param[in] BigNumberBuf  The buffer to output the big number to.
 *
 * @returns The big number or NULLUsefulBufC is the buffer is to small.
 *
 * This always succeeds unless the buffer is too small.
 */
static UsefulBufC
QCBORDecode_Private_UIntToBigNumber(uint64_t uNum, const UsefulBuf BigNumberBuf)
{
   UsefulOutBuf UOB;

   /* With a UsefulOutBuf, there's no pointer math */
   UsefulOutBuf_Init(&UOB, BigNumberBuf);

   /* Must copy one byte even if zero.  The loop, mask and shift
    * algorithm provides endian conversion.
    */
   do {
      UsefulOutBuf_InsertByte(&UOB, uNum & 0xff, 0);
      uNum >>= 8;
   } while(uNum);

   return UsefulOutBuf_OutUBuf(&UOB);
}

#ifndef QCBOR_DISABLE_FLOAT_HW_USE
/**
 * @brief Convert a big number to double-precision float.
 *
 * @param[in] BigNumber   The big number to convert.
 *
 * @returns  The double value.
 *
 * This will always succeed. It will lose precision for larger
 * numbers. If the big number is too large to fit (more than
 * 1.7976931348623157E+308) infinity will be returned. NaN is never
 * returned.
 */
static double
QCBORDecode_Private_BigNumberToDouble(const UsefulBufC BigNumber)
{
   double dResult;
   size_t uLen;

   const uint8_t *pByte = BigNumber.ptr;

   dResult = 0.0;
   /* This will overflow and become the float value INFINITY if the number
    * is too large to fit. */
   for(uLen = BigNumber.len; uLen > 0; uLen--){
      dResult = (dResult * 256.0) + (double)*pByte++;
   }

   return dResult;
}
#endif /* ! QCBOR_DISABLE_FLOAT_HW_USE */


/**
 * @brief Convert integers and floats to an int64_t.
 *
 * @param[in] pItem   The item to convert.
 * @param[in] uConvertTypes  Bit mask list of conversion options.
 * @param[out] pnValue  The resulting converted value.
 *
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
 *                                    in uConvertTypes.
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
 *                                               or too small.
 */
static QCBORError
QCBOR_Private_ConvertInt64(const QCBORItem *pItem,
                           const uint32_t   uConvertTypes,
                           int64_t         *pnValue)
{
   switch(pItem->uDataType) {
      case QCBOR_TYPE_FLOAT:
      case QCBOR_TYPE_DOUBLE:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
            /* https://pubs.opengroup.org/onlinepubs/009695399/functions/llround.html
             http://www.cplusplus.com/reference/cmath/llround/
             */
            // Not interested in FE_INEXACT
            feclearexcept(FE_INVALID|FE_OVERFLOW|FE_UNDERFLOW|FE_DIVBYZERO);
            if(pItem->uDataType == QCBOR_TYPE_DOUBLE) {
               *pnValue = llround(pItem->val.dfnum);
            } else {
               *pnValue = lroundf(pItem->val.fnum);
            }
            if(fetestexcept(FE_INVALID|FE_OVERFLOW|FE_UNDERFLOW|FE_DIVBYZERO)) {
               // llround() shouldn't result in divide by zero, but catch
               // it here in case it unexpectedly does.  Don't try to
               // distinguish between the various exceptions because it seems
               // they vary by CPU, compiler and OS.
               return QCBOR_ERR_FLOAT_EXCEPTION;
            }
         } else {
            return  QCBOR_ERR_UNEXPECTED_TYPE;
         }
#else
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
         break;

      case QCBOR_TYPE_INT64:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_XINT64) {
            *pnValue = pItem->val.int64;
         } else {
            return  QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_UINT64:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_XINT64) {
            if(pItem->val.uint64 < INT64_MAX) {
               *pnValue = pItem->val.int64;
            } else {
               return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
            }
         } else {
            return  QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_65BIT_NEG_INT:
         /* This type occurs if the value won't fit into int64_t
          * so this is always an error. */
         return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
         break;

      default:
         return  QCBOR_ERR_UNEXPECTED_TYPE;
   }
   return QCBOR_SUCCESS;
}



#if !defined(USEFULBUF_DISABLE_ALL_FLOAT) && !defined(QCBOR_DISABLE_PREFERRED_FLOAT)
/*
 * Public function, see header qcbor/qcbor_spiffy_decode.h file
 */
void
QCBORDecode_GetNumberConvertPrecisely(QCBORDecodeContext *pMe,
                                      QCBORItem          *pNumber)
{
   QCBORItem            Item;
   struct IEEE754_ToInt ToInt;
   double               dNum;
   QCBORError           uError;

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   // TODO:VGetNext?
   uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError != QCBOR_SUCCESS) {
      *pNumber = Item;
      pMe->uLastError = (uint8_t)uError;
      return;
   }

<<<<<<< HEAD
   switch(Item.uDataType) {
=======
   pMe->uLastError = (uint8_t)QCBOR_Private_ConvertInt64(pItem,
                                                         uConvertTypes,
                                                         pnValue);
}


/**
 * @brief Convert many number types to an int64_t.
 *
 * @param[in] pItem   The item to convert.
 * @param[in] uConvertTypes  Bit mask list of conversion options.
 * @param[out] pnValue  The resulting converted value.
 *
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
 *                                    in uConvertTypes.
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
 *                                               or too small.
 */
static QCBORError
QCBOR_Private_Int64ConvertAll(const QCBORItem *pItem,
                              const uint32_t   uConvertTypes,
                              int64_t         *pnValue)
{
   switch(pItem->uDataType) {

      case QCBOR_TYPE_POSBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return QCBOR_Private_ConvertPositiveBigNumToSigned(pItem->val.bigNum, pnValue);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return QCBOR_Private_ConvertNegativeBigNumToSigned(pItem->val.bigNum, pnValue);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return QCBOR_Private_ExponentiateNN(pItem->val.expAndMantissa.Mantissa.nInt,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                 &QCBOR_Private_Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIGFLOAT) {
            return QCBOR_Private_ExponentiateNN(pItem->val.expAndMantissa.Mantissa.nInt,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  QCBOR_Private_Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t    nMantissa;
            QCBORError uErr;
            uErr = QCBOR_Private_ConvertPositiveBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return QCBOR_Private_ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  QCBOR_Private_Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t    nMantissa;
            QCBORError uErr;
            uErr = QCBOR_Private_ConvertNegativeBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return QCBOR_Private_ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  QCBOR_Private_Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t    nMantissa;
            QCBORError uErr;
            uErr = QCBOR_Private_ConvertPositiveBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return QCBOR_Private_ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  QCBOR_Private_Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t    nMantissa;
            QCBORError uErr;
            uErr = QCBOR_Private_ConvertNegativeBigNumToSigned(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return QCBOR_Private_ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  QCBOR_Private_Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;
#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */


      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;   }
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetInt64ConvertAll(QCBORDecodeContext *pMe,
                               const uint32_t      uConvertTypes,
                               int64_t            *pnValue)
{
   QCBORItem Item;

   QCBORDecode_Private_GetInt64Convert(pMe, uConvertTypes, pnValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_Int64ConvertAll(&Item,
                                                            uConvertTypes,
                                                            pnValue);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetInt64ConvertAllInMapN(QCBORDecodeContext *pMe,
                                     const int64_t       nLabel,
                                     const uint32_t      uConvertTypes,
                                     int64_t            *pnValue)
{
   QCBORItem Item;

   QCBORDecode_Private_GetInt64ConvertInMapN(pMe,
                                             nLabel,
                                             uConvertTypes,
                                             pnValue,
                                             &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_Int64ConvertAll(&Item,
                                                            uConvertTypes,
                                                            pnValue);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetInt64ConvertAllInMapSZ(QCBORDecodeContext *pMe,
                                      const char         *szLabel,
                                      const uint32_t      uConvertTypes,
                                      int64_t            *pnValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetInt64ConvertInMapSZ(pMe,
                                              szLabel,
                                              uConvertTypes,
                                              pnValue,
                                              &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_Int64ConvertAll(&Item,
                                                            uConvertTypes,
                                                            pnValue);
}


/**
 * @brief Convert many number types to an uint64_t.
 *
 * @param[in] pItem   The item to convert.
 * @param[in] uConvertTypes  Bit mask list of conversion options.
 * @param[out] puValue  The resulting converted value.
 *
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
 *                                    in uConvertTypes.
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
 *                                               or too small.
 */
static QCBORError
QCBOR_Private_ConvertUInt64(const QCBORItem *pItem,
                            const uint32_t   uConvertTypes,
                            uint64_t        *puValue)
{
   switch(pItem->uDataType) {
      case QCBOR_TYPE_DOUBLE:
      case QCBOR_TYPE_FLOAT:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
            // Can't use llround here because it will not convert values
            // greater than INT64_MAX and less than UINT64_MAX that
            // need to be converted so it is more complicated.
            feclearexcept(FE_INVALID|FE_OVERFLOW|FE_UNDERFLOW|FE_DIVBYZERO);
            if(pItem->uDataType == QCBOR_TYPE_DOUBLE) {
               if(isnan(pItem->val.dfnum)) {
                  return QCBOR_ERR_FLOAT_EXCEPTION;
               } else if(pItem->val.dfnum < 0) {
                  return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
               } else {
                  double dRounded = round(pItem->val.dfnum);
                  // See discussion in DecodeDateEpoch() for
                  // explanation of - 0x7ff
                  if(dRounded > (double)(UINT64_MAX- 0x7ff)) {
                     return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
                  }
                  *puValue = (uint64_t)dRounded;
               }
            } else {
               if(isnan(pItem->val.fnum)) {
                  return QCBOR_ERR_FLOAT_EXCEPTION;
               } else if(pItem->val.fnum < 0) {
                  return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
               } else {
                  float fRounded = roundf(pItem->val.fnum);
                  // See discussion in DecodeDateEpoch() for
                  // explanation of - 0x7ff
                  if(fRounded > (float)(UINT64_MAX- 0x7ff)) {
                     return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
                  }
                  *puValue = (uint64_t)fRounded;
               }
            }
            if(fetestexcept(FE_INVALID|FE_OVERFLOW|FE_UNDERFLOW|FE_DIVBYZERO)) {
               // round() and roundf() shouldn't result in exceptions here, but
               // catch them to be robust and thorough. Don't try to
               // distinguish between the various exceptions because it seems
               // they vary by CPU, compiler and OS.
               return QCBOR_ERR_FLOAT_EXCEPTION;
            }

         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
#else
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
         break;

>>>>>>> dev
      case QCBOR_TYPE_INT64:
      case QCBOR_TYPE_UINT64:
         *pNumber = Item;
         break;

      case QCBOR_TYPE_DOUBLE:
         ToInt = IEEE754_DoubleToInt(Item.val.dfnum);
         if(ToInt.type == IEEE754_ToInt_IS_INT) {
            pNumber->uDataType = QCBOR_TYPE_INT64;
            pNumber->val.int64 = ToInt.integer.is_signed;
         } else if(ToInt.type == IEEE754_ToInt_IS_UINT) {
            if(ToInt.integer.un_signed <= INT64_MAX) {
               /* Do the same as base QCBOR integer decoding */
               pNumber->uDataType = QCBOR_TYPE_INT64;
               pNumber->val.int64 = (int64_t)ToInt.integer.un_signed;
            } else {
               pNumber->uDataType = QCBOR_TYPE_UINT64;
               pNumber->val.uint64 = ToInt.integer.un_signed;
            }
         } else {
            *pNumber = Item;
         }
         break;

      case QCBOR_TYPE_FLOAT:
         ToInt = IEEE754_SingleToInt(Item.val.fnum);
         if(ToInt.type == IEEE754_ToInt_IS_INT) {
            pNumber->uDataType = QCBOR_TYPE_INT64;
            pNumber->val.int64 = ToInt.integer.is_signed;
         } else if(ToInt.type == IEEE754_ToInt_IS_UINT) {
            if(ToInt.integer.un_signed <= INT64_MAX) {
               /* Do the same as base QCBOR integer decoding */
               pNumber->uDataType = QCBOR_TYPE_INT64;
               pNumber->val.int64 = (int64_t)ToInt.integer.un_signed;
            } else {
               pNumber->uDataType = QCBOR_TYPE_UINT64;
               pNumber->val.uint64 = ToInt.integer.un_signed;
            }
         } else {
            *pNumber = Item;
         }
         break;

      case QCBOR_TYPE_65BIT_NEG_INT:
         if(Item.val.uint64 == UINT64_MAX) {
            /* The value -18446744073709551616 is encoded as an
             * unsigned 18446744073709551615. It's a whole number that
             * needs to be returned as a double. It can't be handled
             * by IEEE754_UintToDouble because 18446744073709551616
             * doesn't fit into a uint64_t. You can't get it by adding
             * 1 to 18446744073709551615.
             */
            pNumber->val.dfnum = -18446744073709551616.0;
            pNumber->uDataType = QCBOR_TYPE_DOUBLE;
         } else {
<<<<<<< HEAD
            dNum = IEEE754_UintToDouble(Item.val.uint64 + 1, 1);
            if(dNum == IEEE754_UINT_TO_DOUBLE_OOB) {
               *pNumber = Item;
=======
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA

      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return QCBOR_Private_ExponentitateNU(pItem->val.expAndMantissa.Mantissa.nInt,
                                   pItem->val.expAndMantissa.nExponent,
                                   puValue,
                                   QCBOR_Private_Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIGFLOAT) {
            return QCBOR_Private_ExponentitateNU(pItem->val.expAndMantissa.Mantissa.nInt,
                                   pItem->val.expAndMantissa.nExponent,
                                   puValue,
                                   QCBOR_Private_Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            uint64_t   uMantissa;
            QCBORError uErr;
            uErr = QCBOR_Private_ConvertPositiveBigNumToUnsigned(pItem->val.expAndMantissa.Mantissa.bigNum, &uMantissa);
            if(uErr != QCBOR_SUCCESS) {
               return uErr;
            }
            return QCBOR_Private_ExponentitateUU(uMantissa,
                                                 pItem->val.expAndMantissa.nExponent,
                                                 puValue,
                                                 QCBOR_Private_Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            uint64_t   uMantissa;
            QCBORError uErr;
            uErr = QCBOR_Private_ConvertPositiveBigNumToUnsigned(pItem->val.expAndMantissa.Mantissa.bigNum,
                                                                 &uMantissa);
            if(uErr != QCBOR_SUCCESS) {
               return uErr;
            }
            return QCBOR_Private_ExponentitateUU(uMantissa,
                                                 pItem->val.expAndMantissa.nExponent,
                                                 puValue,
                                                 QCBOR_Private_Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;
#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */
      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetUInt64ConvertAll(QCBORDecodeContext *pMe,
                                const uint32_t      uConvertTypes,
                                uint64_t           *puValue)
{
   QCBORItem Item;

   QCBORDecode_Private_GetUInt64Convert(pMe, uConvertTypes, puValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_UInt64ConvertAll(&Item,
                                                             uConvertTypes,
                                                             puValue);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetUInt64ConvertAllInMapN(QCBORDecodeContext *pMe,
                                      const int64_t       nLabel,
                                      const uint32_t      uConvertTypes,
                                      uint64_t           *puValue)
{
   QCBORItem Item;

   QCBORDecode_Private_GetUInt64ConvertInMapN(pMe,
                                              nLabel,
                                              uConvertTypes,
                                              puValue,
                                              &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_UInt64ConvertAll(&Item,
                                                             uConvertTypes,
                                                             puValue);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetUInt64ConvertAllInMapSZ(QCBORDecodeContext *pMe,
                                       const char         *szLabel,
                                       const uint32_t      uConvertTypes,
                                       uint64_t           *puValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetUInt64ConvertInMapSZ(pMe,
                                               szLabel,
                                               uConvertTypes,
                                               puValue,
                                               &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_UInt64ConvertAll(&Item,
                                                             uConvertTypes,
                                                             puValue);
}




#ifndef USEFULBUF_DISABLE_ALL_FLOAT
/**
 * @brief Basic conversions to a double.
 *
 * @param[in] pItem          The item to convert
 * @param[in] uConvertTypes  Bit flags indicating source types for conversion
 * @param[out] pdValue       The value converted to a double
 *
 * This does the conversions that don't need much object code,
 * the conversions from int, uint and float to double.
 *
 * See QCBOR_Private_DoubleConvertAll() for the full set
 * of conversions.
 */
static QCBORError
QCBOR_Private_ConvertDouble(const QCBORItem *pItem,
                            const uint32_t   uConvertTypes,
                            double          *pdValue)
{
   switch(pItem->uDataType) {
      case QCBOR_TYPE_FLOAT:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
            if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
               // Simple cast does the job.
               *pdValue = (double)pItem->val.fnum;
>>>>>>> dev
            } else {
               pNumber->val.dfnum = dNum;
               pNumber->uDataType = QCBOR_TYPE_DOUBLE;
            }
         }
         break;

      default:
         pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
         pNumber->uDataType = QCBOR_TYPE_NONE;
         break;
   }
}

#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT && ! QCBOR_DISABLE_PREFERRED_FLOAT */


/* Add one to the big number and put the result in a new UsefulBufC
 * from storage in UsefulBuf.
 *
 * Leading zeros must be removed before calling this.
 *
 * Code Reviewers: THIS FUNCTION DOES POINTER MATH
 */
static UsefulBufC
QCBORDecode_BigNumberCopyPlusOne(UsefulBufC BigNumber, UsefulBuf BigNumberBuf)
{
   uint8_t        uCarry;
   uint8_t        uSourceValue;
   const uint8_t *pSource;
   uint8_t       *pDest;
   ptrdiff_t      uDestBytesLeft;

   /* Start adding at the LSB */
   pSource = &((const uint8_t *)BigNumber.ptr)[BigNumber.len-1];
   pDest   = &((uint8_t *)BigNumberBuf.ptr)[BigNumberBuf.len-1];

   uCarry = 1; /* Gets set back to zero if add the next line doesn't wrap */
   *pDest = *pSource + 1;
   while(1) {
      /* Wrap around from 0xff to 0 is a defined operation for
       * unsigned addition in C.*/
      if(*pDest != 0) {
         /*  The add operation didn't wrap so no more carry. This
          * funciton only adds one, so when there is no more carry,
          * carrying is over to the end.
          */
         uCarry = 0;
      }

      uDestBytesLeft = pDest - (uint8_t *)BigNumberBuf.ptr;
      if(pSource <= (const uint8_t *)BigNumber.ptr && uCarry == 0) {
         break; /* Successful exit */
      }
      if(pSource > (const uint8_t *)BigNumber.ptr) {
         uSourceValue = *--pSource;
      } else {
         /* All source bytes processed, but not the last carry */
         uSourceValue = 0;
      }

      pDest--;
      if(uDestBytesLeft < 0) {
         return NULLUsefulBufC; /* Not enough space in destination buffer */
      }

      *pDest = uSourceValue + uCarry;
   }

   return (UsefulBufC){pDest, BigNumberBuf.len - (size_t)uDestBytesLeft};
}


/* This returns 1 when uNum is 0 */
static size_t
QCBORDecode_Private_CountNonZeroBytes(uint64_t uNum)
{
   size_t uCount = 0;
   do {
      uCount++;
      uNum >>= 8;
   } while(uNum);

   return uCount;
}


/*
 * Public function, see header qcbor/qcbor_decode.h
 */
QCBORError
QCBORDecode_ProcessBigNumberNoPreferred(const QCBORItem Item,
                                        const UsefulBuf BigNumberBuf,
                                        UsefulBufC     *pBigNumber,
                                        bool           *pbIsNegative)
{
   size_t      uLen;
   UsefulBufC  BigNumber;
   int         uType;

   uType = Item.uDataType;
   if(uType == QCBOR_TYPE_BYTE_STRING) {
      uType = *pbIsNegative ? QCBOR_TYPE_NEGBIGNUM : QCBOR_TYPE_POSBIGNUM;
   }

   static const uint8_t Zero[] = {0x00};
   BigNumber = UsefulBuf_SkipLeading(Item.val.bigNum, 0);
   if(BigNumber.len == 0) {
      BigNumber = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(Zero);
   }

   /* Compute required length so it can be returned if buffer is too small */
   switch(uType) {

      case QCBOR_TYPE_POSBIGNUM:
         uLen = BigNumber.len;
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         uLen = BigNumber.len;
         if(UsefulBuf_IsValue(UsefulBuf_SkipLeading(BigNumber, 0), 0xff) == SIZE_MAX) {
            uLen++;
         }
         break;

      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }

   *pBigNumber = (UsefulBufC){NULL, uLen};

   if(BigNumberBuf.len < uLen || uLen == 0 || BigNumberBuf.ptr == NULL) {
      return BigNumberBuf.ptr == NULL ? QCBOR_SUCCESS : QCBOR_ERR_BUFFER_TOO_SMALL;
      /* Buffer is too short or type is wrong */
   }


   if(uType == QCBOR_TYPE_POSBIGNUM) {
      *pBigNumber = UsefulBuf_Copy(BigNumberBuf, BigNumber);
      *pbIsNegative = false;
   } else if(uType == QCBOR_TYPE_NEGBIGNUM) {
      /* The messy one. Take the stuff in the buffer and copy it to
       * the new buffer, adding one to it. This might be one byte
       * bigger than the original because of the carry from adding
       * one.*/
      *pbIsNegative = true;
      *pBigNumber = QCBORDecode_BigNumberCopyPlusOne(BigNumber, BigNumberBuf);
   }

   return QCBOR_SUCCESS;
}


/*
 * Public function, see header qcbor/qcbor_decode.h
 */
QCBORError
QCBORDecode_ProcessBigNumber(const QCBORItem Item,
                             UsefulBuf       BigNumberBuf,
                             UsefulBufC     *pBigNumber,
                             bool           *pbIsNegative)
{
   QCBORError  uResult;
   size_t      uLen;
   int         uType;

   uType = Item.uDataType;

   switch(uType) {
      case QCBOR_TYPE_POSBIGNUM:
      case QCBOR_TYPE_NEGBIGNUM:
      case QCBOR_TYPE_BYTE_STRING:
         return QCBORDecode_ProcessBigNumberNoPreferred(Item, BigNumberBuf, pBigNumber, pbIsNegative);
         break;

      case QCBOR_TYPE_INT64:
         uLen = QCBORDecode_Private_CountNonZeroBytes((uint64_t)ABSOLUTE_VALUE(Item.val.int64));
         break;

      case QCBOR_TYPE_UINT64:
         uLen = QCBORDecode_Private_CountNonZeroBytes(Item.val.uint64);
         break;

      case QCBOR_TYPE_65BIT_NEG_INT:
         uLen = Item.val.uint64 == UINT64_MAX ? 9 : QCBORDecode_Private_CountNonZeroBytes(Item.val.uint64);
         break;

      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }


   *pBigNumber = (UsefulBufC){NULL, uLen};

   if(BigNumberBuf.len < uLen || uLen == 0 || BigNumberBuf.ptr == NULL) {
      return BigNumberBuf.ptr == NULL ? QCBOR_SUCCESS : QCBOR_ERR_BUFFER_TOO_SMALL;
      /* Buffer is too short or type is wrong */
   }

   uResult = QCBOR_SUCCESS;

   if(uType == QCBOR_TYPE_UINT64) {
      *pBigNumber = QCBORDecode_Private_UIntToBigNumber(Item.val.uint64, BigNumberBuf);
      *pbIsNegative = false;
   } else if(uType == QCBOR_TYPE_INT64) {
      /* Offset of 1 for negative numbers already performed */
      *pbIsNegative = Item.val.int64 < 0;
      *pBigNumber = QCBORDecode_Private_UIntToBigNumber((uint64_t)(*pbIsNegative ? -Item.val.int64 : Item.val.int64), BigNumberBuf);
   } else if(uType == QCBOR_TYPE_65BIT_NEG_INT) {
      /* Offset of 1 for negative numbers NOT already performed */
      *pbIsNegative = true;
      if(Item.val.uint64 == UINT64_MAX) {
         /* The one value that can't be done with a computation
          * because it would overflow a uint64_t */
         static const uint8_t TwoToThe64[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
         *pBigNumber = UsefulBuf_Copy(BigNumberBuf, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(TwoToThe64));
      } else {
         /* +1 because negative big numbers are encoded one less than actual */
         *pBigNumber = QCBORDecode_Private_UIntToBigNumber(Item.val.uint64 + 1, BigNumberBuf);
      }
   }

   return uResult;
}



static const uint64_t QCBORDecode_Private_BigNumberTagNumbers[] = {
   CBOR_TAG_POS_BIGNUM,
   CBOR_TAG_NEG_BIGNUM,
   CBOR_TAG_INVALID64};

static const uint8_t QCBORDecode_Private_BigNumberTypes[] = {
   QCBOR_TYPE_INT64,
   QCBOR_TYPE_UINT64,
   QCBOR_TYPE_65BIT_NEG_INT,
   QCBOR_TYPE_POSBIGNUM,
   QCBOR_TYPE_NEGBIGNUM,
   QCBOR_TYPE_NONE};

#define QCBORDecode_Private_BigNumberTypesNoPreferred &QCBORDecode_Private_BigNumberTypes[3]

/**
 * @brief Common processing for a big number tag.
 *
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[in] pItem            The item with the date.
 * @param[out] pBignumber          The returned big number
 * @param[out] pbIsNegative  The returned sign of the big number.
 *
 * Common processing for the big number tag. Mostly make sure
 * the tag content is correct and copy forward any further other tag
 * numbers.
 */
static void
QCBORDecode_Private_BigNumberRawMain(QCBORDecodeContext *pMe,
                                     const uint8_t       uTagRequirement,
                                     QCBORItem          *pItem,
                                     UsefulBufC         *pBignumber,
                                     bool               *pbIsNegative,
                                     size_t              uOffset)
{
   QCBORDecode_Private_ProcessTagItemMulti(pMe,
                                           pItem,
                                           uTagRequirement,
                                           QCBORDecode_Private_BigNumberTypesNoPreferred,
                                           QCBORDecode_Private_BigNumberTagNumbers,
                                           QCBORDecode_StringsTagCB,
                                           uOffset);
   if(pMe->uLastError) {
      return;
   }

   if(pItem->uDataType == QCBOR_TYPE_POSBIGNUM) {
      *pbIsNegative = false;
   } else if(pItem->uDataType == QCBOR_TYPE_NEGBIGNUM) {
      *pbIsNegative = true;
   }
   *pBignumber = pItem->val.bigNum;
}


static void
QCBORDecode_Private_BigNumberNoPreferredMain(QCBORDecodeContext *pMe,
                                             const uint8_t       uTagRequirement,
                                             QCBORItem          *pItem,
                                             const size_t        uOffset,
                                             UsefulBuf           BigNumberBuf,
                                             UsefulBufC         *pBigNumber,
                                             bool               *pbIsNegative)
{
   QCBORDecode_Private_ProcessTagItemMulti(pMe,
                                           pItem,
                                           uTagRequirement,
                                           QCBORDecode_Private_BigNumberTypesNoPreferred,
                                           QCBORDecode_Private_BigNumberTagNumbers,
                                           QCBORDecode_StringsTagCB,
                                           uOffset);
   if(pMe->uLastError) {
      return;
   }

   pMe->uLastError = (uint8_t)QCBORDecode_ProcessBigNumberNoPreferred(*pItem, BigNumberBuf, pBigNumber, pbIsNegative);
}


static void
QCBORDecode_Private_BigNumberMain(QCBORDecodeContext *pMe,
                                  const uint8_t       uTagRequirement,
                                  QCBORItem          *pItem,
                                  const size_t        uOffset,
                                  UsefulBuf           BigNumberBuf,
                                  UsefulBufC         *pBigNumber,
                                  bool               *pbIsNegative)
{
   QCBORDecode_Private_ProcessTagItemMulti(pMe,
                                           pItem,
                                           uTagRequirement,
                                           QCBORDecode_Private_BigNumberTypes,
                                           QCBORDecode_Private_BigNumberTagNumbers,
                                           QCBORDecode_StringsTagCB,
                                           uOffset);
   if(pMe->uLastError) {
      return;
   }

   pMe->uLastError = (uint8_t)QCBORDecode_ProcessBigNumber(*pItem, BigNumberBuf, pBigNumber, pbIsNegative);
}


/*
 * Public function, see header qcbor/qcbor_decode.h
 */
void
QCBORDecode_GetTBigNumber(QCBORDecodeContext *pMe,
                          const uint8_t       uTagRequirement,
                          UsefulBuf           BigNumberBuf,
                          UsefulBufC         *pBigNumber,
                          bool               *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_BigNumberMain(pMe, uTagRequirement, &Item, uOffset, BigNumberBuf, pBigNumber, pbIsNegative);
}

/*
 * Public function, see header qcbor/qcbor_decode.h
 */
void
QCBORDecode_GetTBigNumberInMapN(QCBORDecodeContext *pMe,
                                const int64_t       nLabel,
                                const uint8_t       uTagRequirement,
                                UsefulBuf           BigNumberBuf,
                                UsefulBufC         *pBigNumber,
                                bool               *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_BigNumberMain(pMe,
                                     uTagRequirement,
                                    &Item,
                                     uOffset,
                                     BigNumberBuf,
                                     pBigNumber,
                                     pbIsNegative);
}

/*
 * Public function, see header qcbor/qcbor_decode.h
 */
void
QCBORDecode_GetTBigNumberInMapSZ(QCBORDecodeContext *pMe,
                                 const char         *szLabel,
                                 const uint8_t       uTagRequirement,
                                 UsefulBuf           BigNumberBuf,
                                 UsefulBufC         *pBigNumber,
                                 bool               *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_BigNumberMain(pMe,
                                     uTagRequirement,
                                    &Item,
                                     uOffset,
                                     BigNumberBuf,
                                     pBigNumber,
                                     pbIsNegative);
}


/*
 * Public function, see header qcbor/qcbor_decode.h
 */
void
QCBORDecode_GetTBigNumberNoPreferred(QCBORDecodeContext *pMe,
                                     const uint8_t       uTagRequirement,
                                     UsefulBuf           BigNumberBuf,
                                     UsefulBufC         *pBigNumber,
                                     bool               *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_BigNumberNoPreferredMain(pMe, uTagRequirement, &Item, uOffset, BigNumberBuf, pBigNumber, pbIsNegative);
}

/*
 * Public function, see header qcbor/qcbor_decode.h
 */
void
QCBORDecode_GetTBigNumberNoPreferredInMapN(QCBORDecodeContext *pMe,
                                           const int64_t       nLabel,
                                           const uint8_t       uTagRequirement,
                                           UsefulBuf           BigNumberBuf,
                                           UsefulBufC         *pBigNumber,
                                           bool               *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_BigNumberNoPreferredMain(pMe, uTagRequirement, &Item, uOffset, BigNumberBuf, pBigNumber, pbIsNegative);

}

/*
 * Public function, see header qcbor/qcbor_decode.h
 */
void
QCBORDecode_GetTBigNumberNoPreferredInMapSZ(QCBORDecodeContext *pMe,
                                            const char         *szLabel,
                                            const uint8_t       uTagRequirement,
                                            UsefulBuf           BigNumberBuf,
                                            UsefulBufC         *pBigNumber,
                                            bool               *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_BigNumberNoPreferredMain(pMe, uTagRequirement, &Item, uOffset, BigNumberBuf, pBigNumber, pbIsNegative);
}



/*
 * Public function, see header qcbor/qcbor_spiffy_decode.h
 */
void
QCBORDecode_GetTBigNumberRaw(QCBORDecodeContext *pMe,
                             const uint8_t       uTagRequirement,
                             UsefulBufC         *pBignumber,
                             bool               *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_BigNumberRawMain(pMe,
                                        uTagRequirement,
                                       &Item,
                                        pBignumber,
                                        pbIsNegative,
                                        uOffset);
}

/*
 * Public function, see header qcbor/qcbor_spiffy_decode.h
 */
void
QCBORDecode_GetTBigNumberRawInMapN(QCBORDecodeContext *pMe,
                                   const int64_t       nLabel,
                                   const uint8_t       uTagRequirement,
                                   UsefulBufC         *pBigNumber,
                                   bool               *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_BigNumberRawMain(pMe,
                                        uTagRequirement,
                                       &Item,
                                        pBigNumber,
                                        pbIsNegative,
                                        uOffset);
}

/*
 * Public function, see header qcbor/qcbor_spiffy_decode.h
 */
void
QCBORDecode_GetTBigNumberRawInMapSZ(QCBORDecodeContext *pMe,
                                    const char         *szLabel,
                                    const uint8_t       uTagRequirement,
                                    UsefulBufC         *pBigNumber,
                                    bool               *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_BigNumberRawMain(pMe,
                                        uTagRequirement,
                                       &Item,
                                        pBigNumber,
                                        pbIsNegative,
                                        uOffset);
}


#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA


// TODO: relocate these notes?
/* Some notes from the work to disable tags.
 * Some are out of date since tag refactoring.
 *
 * The API for big floats and decimal fractions seems good.
 * If there's any issue with it it's that the code size to
 * implement is a bit large because of the conversion
 * to/from int and bignum that is required. There is no API
 * that doesn't do the conversion so dead stripping will never
 * leave that code out.
 *
 * The implementation itself seems correct, but not as clean
 * and neat as it could be. It could probably be smaller too.
 *
 * The implementation has three main parts / functions
 *  - The decoding of the array of two
 *  - All the tag and type checking for the various API functions
 *  - Conversion to/from bignum and int
 *
 * The type checking seems like it wastes the most code for
 * what it needs to do.
 *
 * The inlining for the conversion is probably making the
 * overall code base larger.
 *
 * The tests cases could be organized a lot better and be
 * more thorough.
 *
 * Seems also like there could be more common code in the
 * first tier part of the public API. Some functions only
 * vary by a TagSpec.
 */


static const uint8_t QCBORDecode_Private_DecimalFractionTypes[] = {
   QCBOR_TYPE_DECIMAL_FRACTION,
   QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM,
   QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM,
   QCBOR_TYPE_DECIMAL_FRACTION_POS_U64,
   QCBOR_TYPE_DECIMAL_FRACTION_NEG_U64,
   QCBOR_TYPE_NONE};

static const uint8_t QCBORDecode_Private_BigFloatTypes[] = {
   QCBOR_TYPE_BIGFLOAT,
   QCBOR_TYPE_BIGFLOAT_POS_BIGNUM,
   QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM,
   QCBOR_TYPE_BIGFLOAT_POS_U64,
   QCBOR_TYPE_BIGFLOAT_NEG_U64,
   QCBOR_TYPE_NONE};

/**
 * @brief Common processor for exponent and int64_t mantissa.
 *
 * @param[in] pMe          The decode context.
 * @param[in] uTagRequirement  Whether tag number must be present or not.
 * @param[in] uTagNumber   The tag number for which content is expected.
 * @param[in] uOffset   Cursor offset for  tag number consumption checking.
 * @param[in] pItem        The data item to process.
 * @param[out] pnMantissa  The returned mantissa as an int64_t.
 * @param[out] pnExponent  The returned exponent as an int64_t.
 *
 * This handles exponent and mantissa for base 2 and 10. This
 * is limited to a mantissa that is an int64_t. See also
 * QCBORDecode_Private_ProcessExpMantissaBig().
 *
 * On output, the item is always a fully decoded decimal fraction or
 * big float.
 *
 * This errors out if the input tag and type aren't as required.
 *
 * This always provides the correctly offset mantissa, even when the
 * input CBOR is a negative big number. This works the
 * same in QCBOR v1 and v2.
 */
static void
QCBORDecode_Private_ExpIntMantissaMain(QCBORDecodeContext  *pMe,
                                       const uint8_t        uTagRequirement,
                                       const uint64_t       uTagNumber,
                                       const size_t         uOffset,
                                       QCBORItem           *pItem,
                                       int64_t             *pnMantissa,
                                       int64_t             *pnExponent)
{
   QCBORError     uErr;
   const uint8_t *qTypes;

   if(pMe->uLastError) {
      return;
   }

   if(uTagNumber == CBOR_TAG_BIGFLOAT) {
      qTypes = QCBORDecode_Private_BigFloatTypes;
   } else {
      qTypes = QCBORDecode_Private_DecimalFractionTypes;
   }

   QCBORDecode_Private_ProcessTagItem(pMe,
                                      pItem,
                                      uTagRequirement,
                                      qTypes,
                                      uTagNumber,
                                      QCBORDecode_ExpMantissaTagCB,
                                      uOffset);

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   uErr = QCBOR_SUCCESS;
   switch (pItem->uDataType) {

      case QCBOR_TYPE_DECIMAL_FRACTION:
      case QCBOR_TYPE_BIGFLOAT:
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         *pnMantissa = pItem->val.expAndMantissa.Mantissa.nInt;
         break;

#ifndef QCBOR_DISABLE_TAGS
      /* If tags are disabled, mantissas can never be big nums */
      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         uErr = QCBORDecode_Private_PositiveBigNumberToInt(pItem->val.expAndMantissa.Mantissa.bigNum, pnMantissa);
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         uErr = QCBORDecode_Private_NegativeBigNumberToInt(pItem->val.expAndMantissa.Mantissa.bigNum, pnMantissa);
         break;
#endif /* QCBOR_DISABLE_TAGS */

      case QCBOR_TYPE_BIGFLOAT_NEG_U64:
      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_U64:
      case QCBOR_TYPE_BIGFLOAT_POS_U64:
      case QCBOR_TYPE_DECIMAL_FRACTION_POS_U64:
         uErr = QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
         break;

      default:
         uErr = QCBOR_ERR_UNEXPECTED_TYPE;
   }

   pMe->uLastError = (uint8_t)uErr;
}

static void
QCBORDecode_Private_ExpBigMantissaRawMain(QCBORDecodeContext  *pMe,
                                          const uint8_t        uTagRequirement,
                                          const uint64_t       uTagNumber,
                                          const size_t         uOffset,
                                          QCBORItem           *pItem,
                                          const UsefulBuf      BufferForMantissa,
                                          UsefulBufC          *pMantissa,
                                          bool                *pbIsNegative,
                                          int64_t             *pnExponent)
{
   QCBORError     uErr;
   uint64_t       uMantissa;
   const uint8_t *qTypes;

   if(pMe->uLastError) {
      return;
   }

   if(uTagNumber == CBOR_TAG_BIGFLOAT) {
      qTypes = QCBORDecode_Private_BigFloatTypes;
   } else {
      qTypes = QCBORDecode_Private_DecimalFractionTypes;
   }

   QCBORDecode_Private_ProcessTagItem(pMe,
                                      pItem,
                                      uTagRequirement,
                                      qTypes,
                                      uTagNumber,
                                      QCBORDecode_ExpMantissaTagCB,
                                      uOffset);

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   uErr = QCBOR_SUCCESS;

   switch (pItem->uDataType) {

      case QCBOR_TYPE_DECIMAL_FRACTION:
      case QCBOR_TYPE_BIGFLOAT:
         if(pItem->val.expAndMantissa.Mantissa.nInt >= 0) {
            uMantissa = (uint64_t)pItem->val.expAndMantissa.Mantissa.nInt;
            *pbIsNegative = false;
         } else {
            if(pItem->val.expAndMantissa.Mantissa.nInt != INT64_MIN) {
               uMantissa = (uint64_t)-pItem->val.expAndMantissa.Mantissa.nInt;
            } else {
               /* Can't negate like above when int64_t is INT64_MIN because it
                * will overflow. See ExponentNN() */
               uMantissa = (uint64_t)INT64_MAX+1;
            }
            *pbIsNegative = true;
         }
         /* Reverse the offset by 1 for type 1 negative value to be consistent
          * with big num case below which don't offset because it requires
          * big number arithmetic. This is a bug fix for QCBOR v1.5.
          */
         uMantissa--;
         *pMantissa = QCBORDecode_Private_UIntToBigNumber(uMantissa, BufferForMantissa);
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         break;

#ifndef QCBOR_DISABLE_TAGS
      /* If tags are disabled, mantissas can never be big nums */
      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         *pMantissa = pItem->val.expAndMantissa.Mantissa.bigNum;
         *pbIsNegative = false;
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         *pMantissa = pItem->val.expAndMantissa.Mantissa.bigNum;
         *pbIsNegative = true;
         break;
#endif /* QCBOR_DISABLE_TAGS */

      default:
         uErr = QCBOR_ERR_UNEXPECTED_TYPE;
   }

   pMe->uLastError = (uint8_t)uErr;
}


/**
 * @brief Decode exponent and mantissa into a big number with negative offset of 1.
 *
 * @param[in] pMe                The decode context.
 * @param[in] uTagRequirement  Whether a tag number must be present or not.
 * @param[in] pItem              Item to decode and convert.
 * @param[in] BufferForMantissa  Buffer to output mantissa into.
 * @param[out] pMantissa         The output mantissa.
 * @param[out] pbIsNegative      The sign of the output.
 * @param[out] pnExponent        The mantissa of the output.
 *
 * This is the common processing of a decimal fraction or a big float
 * into a big number. This will decode and consume all the CBOR items
 * that make up the decimal fraction or big float.
 *
 * This performs the subtraction of 1 from the negative value so the
 * caller doesn't need to. This links more object code than QCBORDecode_Private_ProcessExpMantissaBig().
 */
static void
QCBORDecode_Private_ExpBigMantissaMain(QCBORDecodeContext  *pMe,
                                       const uint8_t        uTagRequirement,
                                       const uint64_t       uTagNumber,
                                       const size_t         uOffset,
                                       QCBORItem           *pItem,
                                       const UsefulBuf      BufferForMantissa,
                                       UsefulBufC          *pMantissa,
                                       bool                *pbIsNegative,
                                       int64_t             *pnExponent)
{
   QCBORError     uErr;
   QCBORItem      TempMantissa;
   const uint8_t *qTypes;

   if(pMe->uLastError) {
      return;
   }

   if(uTagNumber == CBOR_TAG_BIGFLOAT) {
      qTypes = QCBORDecode_Private_BigFloatTypes;
   } else {
      qTypes = QCBORDecode_Private_DecimalFractionTypes;
   }

   QCBORDecode_Private_ProcessTagItem(pMe,
                                      pItem,
                                      uTagRequirement,
                                      qTypes,
                                      uTagNumber,
                                      QCBORDecode_ExpMantissaTagCB,
                                      uOffset);

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   memset(&TempMantissa, 0, sizeof(TempMantissa));

   switch (pItem->uDataType) {

      case QCBOR_TYPE_DECIMAL_FRACTION:
      case QCBOR_TYPE_BIGFLOAT:
         TempMantissa.uDataType = QCBOR_TYPE_INT64;
         TempMantissa.val.int64 = pItem->val.expAndMantissa.Mantissa.nInt;
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_POS_U64:
      case QCBOR_TYPE_BIGFLOAT_POS_U64:
         TempMantissa.uDataType = QCBOR_TYPE_UINT64;
         TempMantissa.val.uint64 = pItem->val.expAndMantissa.Mantissa.uInt;
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_U64:
      case QCBOR_TYPE_BIGFLOAT_NEG_U64:
         TempMantissa.uDataType = QCBOR_TYPE_65BIT_NEG_INT;
         TempMantissa.val.uint64 = pItem->val.expAndMantissa.Mantissa.uInt;
         break;

#ifndef QCBOR_DISABLE_TAGS
         /* If tags are disabled, mantissas can never be big nums */
      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         TempMantissa.uDataType = QCBOR_TYPE_BYTE_STRING;
         TempMantissa.val.bigNum = pItem->val.expAndMantissa.Mantissa.bigNum;
         *pbIsNegative = false;
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         TempMantissa.uDataType = QCBOR_TYPE_BYTE_STRING;
         TempMantissa.val.bigNum = pItem->val.expAndMantissa.Mantissa.bigNum;
         *pbIsNegative = true;
         break;
#endif /* ! QCBOR_DISABLE_TAGS */
   }

   *pnExponent = pItem->val.expAndMantissa.nExponent;
   uErr = QCBORDecode_ProcessBigNumber(TempMantissa, BufferForMantissa, pMantissa, pbIsNegative);

   pMe->uLastError = (uint8_t)uErr;
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTDecimalFraction(QCBORDecodeContext *pMe,
                                const uint8_t       uTagRequirement,
                                int64_t             *pnMantissa,
                                int64_t             *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ExpIntMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_DECIMAL_FRACTION,
                                          uOffset,
                                         &Item,
                                          pnMantissa,
                                          pnExponent);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTDecimalFractionInMapN(QCBORDecodeContext *pMe,
                                      const int64_t       nLabel,
                                      const uint8_t       uTagRequirement,
                                      int64_t             *pnMantissa,
                                      int64_t             *pnExponent)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpIntMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_DECIMAL_FRACTION,
                                          uOffset,
                                         &Item,
                                          pnMantissa,
                                          pnExponent);

}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTDecimalFractionInMapSZ(QCBORDecodeContext *pMe,
                                       const char         *szLabel,
                                       const uint8_t       uTagRequirement,
                                       int64_t             *pnMantissa,
                                       int64_t             *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpIntMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_DECIMAL_FRACTION,
                                          uOffset,
                                         &Item,
                                          pnMantissa,
                                          pnExponent);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTDecimalFractionBigMantissa(QCBORDecodeContext *pMe,
                                           const uint8_t       uTagRequirement,
                                           const UsefulBuf     MantissaBuffer,
                                           UsefulBufC         *pMantissa,
                                           bool               *pbMantissaIsNegative,
                                           int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_DECIMAL_FRACTION,
                                          uOffset,
                                         &Item,
                                          MantissaBuffer,
                                          pMantissa,
                                          pbMantissaIsNegative,
                                          pnExponent);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTDecimalFractionBigMantissaInMapN(QCBORDecodeContext *pMe,
                                                 const int64_t       nLabel,
                                                 const uint8_t       uTagRequirement,
                                                 const UsefulBuf     BufferForMantissa,
                                                 UsefulBufC         *pMantissa,
                                                 bool               *pbIsNegative,
                                                 int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_DECIMAL_FRACTION,
                                          uOffset,
                                         &Item,
                                          BufferForMantissa,
                                          pMantissa,
                                          pbIsNegative,
                                          pnExponent);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTDecimalFractionBigMantissaInMapSZ(QCBORDecodeContext *pMe,
                                                  const char         *szLabel,
                                                  const uint8_t       uTagRequirement,
                                                  const UsefulBuf     BufferForMantissa,
                                                  UsefulBufC         *pMantissa,
                                                  bool               *pbIsNegative,
                                                  int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_DECIMAL_FRACTION,
                                          uOffset,
                                         &Item,
                                          BufferForMantissa,
                                          pMantissa,
                                          pbIsNegative,
                                          pnExponent);
}

/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTDecimalFractionBigMantissaRaw(QCBORDecodeContext *pMe,
                                              const uint8_t       uTagRequirement,
                                              const UsefulBuf     MantissaBuffer,
                                              UsefulBufC         *pMantissa,
                                              bool               *pbMantissaIsNegative,
                                              int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaRawMain(pMe,
                                             uTagRequirement,
                                             CBOR_TAG_DECIMAL_FRACTION,
                                             uOffset,
                                            &Item,
                                             MantissaBuffer,
                                             pMantissa,
                                             pbMantissaIsNegative,
                                             pnExponent);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTDecimalFractionBigMantissaRawInMapN(QCBORDecodeContext *pMe,
                                                    const int64_t       nLabel,
                                                    const uint8_t       uTagRequirement,
                                                    const UsefulBuf     BufferForMantissa,
                                                    UsefulBufC         *pMantissa,
                                                    bool               *pbIsNegative,
                                                    int64_t            *pnExponent)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaRawMain(pMe,
                                             uTagRequirement,
                                             CBOR_TAG_DECIMAL_FRACTION,
                                             uOffset,
                                            &Item,
                                             BufferForMantissa,
                                             pMantissa,
                                             pbIsNegative,
                                             pnExponent);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTDecimalFractionBigMantissaRawInMapSZ(QCBORDecodeContext *pMe,
                                                     const char         *szLabel,
                                                     const uint8_t       uTagRequirement,
                                                     const UsefulBuf     BufferForMantissa,
                                                     UsefulBufC         *pMantissa,
                                                     bool               *pbIsNegative,
                                                     int64_t            *pnExponent)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaRawMain(pMe,
                                             uTagRequirement,
                                             CBOR_TAG_DECIMAL_FRACTION,
                                             uOffset,
                                            &Item,
                                             BufferForMantissa,
                                             pMantissa,
                                             pbIsNegative,
                                             pnExponent);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTBigFloat(QCBORDecodeContext *pMe,
                         const uint8_t       uTagRequirement,
                         int64_t             *pnMantissa,
                         int64_t             *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ExpIntMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_BIGFLOAT,
                                          uOffset,
                                         &Item,
                                          pnMantissa,
                                          pnExponent);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTBigFloatInMapN(QCBORDecodeContext *pMe,
                               const int64_t       nLabel,
                               const uint8_t       uTagRequirement,
                               int64_t            *pnMantissa,
                               int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpIntMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_BIGFLOAT,
                                          uOffset,
                                         &Item,
                                          pnMantissa,
                                          pnExponent);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTBigFloatInMapSZ(QCBORDecodeContext *pMe,
                                const char         *szLabel,
                                const uint8_t       uTagRequirement,
                                int64_t            *pnMantissa,
                                int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpIntMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_BIGFLOAT,
                                          uOffset,
                                         &Item,
                                          pnMantissa,
                                          pnExponent);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTBigFloatBigMantissa(QCBORDecodeContext *pMe,
                                    const uint8_t       uTagRequirement,
                                    const UsefulBuf     MantissaBuffer,
                                    UsefulBufC         *pMantissa,
                                    bool               *pbMantissaIsNegative,
                                    int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_BIGFLOAT,
                                          uOffset,
                                         &Item,
                                          MantissaBuffer,
                                          pMantissa,
                                          pbMantissaIsNegative,
                                          pnExponent);
}



/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTBigFloatBigMantissaInMapN(QCBORDecodeContext *pMe,
                                          const int64_t       nLabel,
                                          const uint8_t       uTagRequirement,
                                          const UsefulBuf     BufferForMantissa,
                                          UsefulBufC         *pMantissa,
                                          bool               *pbIsNegative,
                                          int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_BIGFLOAT,
                                          uOffset,
                                         &Item,
                                          BufferForMantissa,
                                          pMantissa,
                                          pbIsNegative,
                                          pnExponent);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTBigFloatBigMantissaInMapSZ(QCBORDecodeContext *pMe,
                                           const char         *szLabel,
                                           const uint8_t       uTagRequirement,
                                           const UsefulBuf     BufferForMantissa,
                                           UsefulBufC         *pMantissa,
                                           bool               *pbIsNegative,
                                           int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_BIGFLOAT,
                                          uOffset,
                                         &Item,
                                          BufferForMantissa,
                                          pMantissa,
                                          pbIsNegative,
                                          pnExponent);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTBigFloatBigMantissaRaw(QCBORDecodeContext *pMe,
                                       const uint8_t       uTagRequirement,
                                       const UsefulBuf     MantissaBuffer,
                                       UsefulBufC         *pMantissa,
                                       bool               *pbMantissaIsNegative,
                                       int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaRawMain(pMe,
                                             uTagRequirement,
                                             CBOR_TAG_BIGFLOAT,
                                             uOffset,
                                            &Item,
                                             MantissaBuffer,
                                             pMantissa,
                                             pbMantissaIsNegative,
                                             pnExponent);
}

/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTBigFloatBigMantissaRawInMapN(QCBORDecodeContext *pMe,
                                             const int64_t       nLabel,
                                             const uint8_t       uTagRequirement,
                                             const UsefulBuf     BufferForMantissa,
                                             UsefulBufC         *pMantissa,
                                             bool               *pbIsNegative,
                                             int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaRawMain(pMe,
                                             uTagRequirement,
                                             CBOR_TAG_BIGFLOAT,
                                             uOffset,
                                            &Item,
                                             BufferForMantissa,
                                             pMantissa,
                                             pbIsNegative,
                                             pnExponent);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetTBigFloatBigMantissaRawInMapSZ(QCBORDecodeContext *pMe,
                                              const char         *szLabel,
                                              const uint8_t       uTagRequirement,
                                              const UsefulBuf     BufferForMantissa,
                                              UsefulBufC         *pMantissa,
                                              bool               *pbIsNegative,
                                              int64_t            *pnExponent)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaRawMain(pMe,
                                             uTagRequirement,
                                             CBOR_TAG_BIGFLOAT,
                                             uOffset,
                                            &Item,
                                             BufferForMantissa,
                                             pMantissa,
                                             pbIsNegative,
                                             pnExponent);
}

#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */




/**
 * @brief Almost-public method to decode a number and convert to int64_t (semi-private).
 *
 * @param[in] pMe            The decode context.
 * @param[in] uConvertTypes  Bit mask list of conversion options.
 * @param[out] pnValue       Result of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetInt64Convert().
 */
void
QCBORDecode_Private_GetInt64Convert(QCBORDecodeContext *pMe,
                                    uint32_t            uConvertTypes,
                                    int64_t            *pnValue,
                                    QCBORItem          *pItem)
{
   QCBORDecode_VGetNext(pMe, pItem);
   if(pMe->uLastError) {
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_ConvertInt64(pItem,
                                                         uConvertTypes,
                                                         pnValue);
}

/**
 * @brief Almost-public method to decode a number and convert to int64_t (semi-private).
 *
 * @param[in] pMe            The decode context.
 * @param[in] nLabel         Label to find in map.
 * @param[in] uConvertTypes  Bit mask list of conversion options.
 * @param[out] pnValue       Result of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetInt64ConvertInMapN().
 */
void
QCBORDecode_Private_GetInt64ConvertInMapN(QCBORDecodeContext *pMe,
                                          int64_t             nLabel,
                                          uint32_t            uConvertTypes,
                                          int64_t            *pnValue,
                                          QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_ConvertInt64(pItem,
                                                         uConvertTypes,
                                                         pnValue);
}

/**
 * @brief Almost-public method to decode a number and convert to int64_t (semi-private).
 *
 * @param[in] pMe            The decode context.
 * @param[in] szLabel        Label to find in map.
 * @param[in] uConvertTypes  Bit mask list of conversion options.
 * @param[out] pnValue       Result of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetInt64ConvertInMapSZ().
 */
void
QCBORDecode_Private_GetInt64ConvertInMapSZ(QCBORDecodeContext *pMe,
                                           const char *         szLabel,
                                           uint32_t             uConvertTypes,
                                           int64_t             *pnValue,
                                           QCBORItem           *pItem)
{
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_ConvertInt64(pItem,
                                                         uConvertTypes,
                                                         pnValue);
}


/**
 * @brief Convert many number types to an int64_t.
 *
 * @param[in] pItem   The item to convert.
 * @param[in] uConvertTypes  Bit mask list of conversion options.
 * @param[out] pnValue  The resulting converted value.
 *
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
 *                                    in uConvertTypes.
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
 *                                               or too small.
 */
static QCBORError
QCBOR_Private_Int64ConvertAll(const QCBORItem *pItem,
                              const uint32_t   uConvertTypes,
                              int64_t         *pnValue)
{
   switch(pItem->uDataType) {

      case QCBOR_TYPE_POSBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return QCBORDecode_Private_PositiveBigNumberToInt(pItem->val.bigNum, pnValue);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return QCBORDecode_Private_NegativeBigNumberToInt(pItem->val.bigNum, pnValue);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return QCBOR_Private_ExponentiateNN(pItem->val.expAndMantissa.Mantissa.nInt,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                 &QCBOR_Private_Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIGFLOAT) {
            return QCBOR_Private_ExponentiateNN(pItem->val.expAndMantissa.Mantissa.nInt,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  QCBOR_Private_Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t    nMantissa;
            QCBORError uErr;
            uErr = QCBORDecode_Private_PositiveBigNumberToInt(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return QCBOR_Private_ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  QCBOR_Private_Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t    nMantissa;
            QCBORError uErr;
            uErr = QCBORDecode_Private_NegativeBigNumberToInt(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return QCBOR_Private_ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  QCBOR_Private_Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t    nMantissa;
            QCBORError uErr;
            uErr = QCBORDecode_Private_PositiveBigNumberToInt(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return QCBOR_Private_ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  QCBOR_Private_Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            int64_t    nMantissa;
            QCBORError uErr;
            uErr = QCBORDecode_Private_NegativeBigNumberToInt(pItem->val.expAndMantissa.Mantissa.bigNum, &nMantissa);
            if(uErr) {
               return uErr;
            }
            return QCBOR_Private_ExponentiateNN(nMantissa,
                                  pItem->val.expAndMantissa.nExponent,
                                  pnValue,
                                  QCBOR_Private_Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;
#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */


      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;   }
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetInt64ConvertAll(QCBORDecodeContext *pMe,
                               const uint32_t      uConvertTypes,
                               int64_t            *pnValue)
{
   QCBORItem Item;

   QCBORDecode_Private_GetInt64Convert(pMe, uConvertTypes, pnValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_Int64ConvertAll(&Item,
                                                            uConvertTypes,
                                                            pnValue);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetInt64ConvertAllInMapN(QCBORDecodeContext *pMe,
                                     const int64_t       nLabel,
                                     const uint32_t      uConvertTypes,
                                     int64_t            *pnValue)
{
   QCBORItem Item;

   QCBORDecode_Private_GetInt64ConvertInMapN(pMe,
                                             nLabel,
                                             uConvertTypes,
                                             pnValue,
                                             &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_Int64ConvertAll(&Item,
                                                            uConvertTypes,
                                                            pnValue);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetInt64ConvertAllInMapSZ(QCBORDecodeContext *pMe,
                                      const char         *szLabel,
                                      const uint32_t      uConvertTypes,
                                      int64_t            *pnValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetInt64ConvertInMapSZ(pMe,
                                              szLabel,
                                              uConvertTypes,
                                              pnValue,
                                              &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_Int64ConvertAll(&Item,
                                                            uConvertTypes,
                                                            pnValue);
}


/**
 * @brief Convert many number types to an uint64_t.
 *
 * @param[in] pItem   The item to convert.
 * @param[in] uConvertTypes  Bit mask list of conversion options.
 * @param[out] puValue  The resulting converted value.
 *
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
 *                                    in uConvertTypes.
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
 *                                               or too small.
 */
static QCBORError
QCBOR_Private_ConvertUInt64(const QCBORItem *pItem,
                            const uint32_t   uConvertTypes,
                            uint64_t        *puValue)
{
   switch(pItem->uDataType) {
      case QCBOR_TYPE_DOUBLE:
      case QCBOR_TYPE_FLOAT:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
            // Can't use llround here because it will not convert values
            // greater than INT64_MAX and less than UINT64_MAX that
            // need to be converted so it is more complicated.
            feclearexcept(FE_INVALID|FE_OVERFLOW|FE_UNDERFLOW|FE_DIVBYZERO);
            if(pItem->uDataType == QCBOR_TYPE_DOUBLE) {
               if(isnan(pItem->val.dfnum)) {
                  return QCBOR_ERR_FLOAT_EXCEPTION;
               } else if(pItem->val.dfnum < 0) {
                  return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
               } else {
                  double dRounded = round(pItem->val.dfnum);
                  // See discussion in DecodeDateEpoch() for
                  // explanation of - 0x7ff
                  if(dRounded > (double)(UINT64_MAX- 0x7ff)) {
                     return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
                  }
                  *puValue = (uint64_t)dRounded;
               }
            } else {
               if(isnan(pItem->val.fnum)) {
                  return QCBOR_ERR_FLOAT_EXCEPTION;
               } else if(pItem->val.fnum < 0) {
                  return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
               } else {
                  float fRounded = roundf(pItem->val.fnum);
                  // See discussion in DecodeDateEpoch() for
                  // explanation of - 0x7ff
                  if(fRounded > (float)(UINT64_MAX- 0x7ff)) {
                     return QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW;
                  }
                  *puValue = (uint64_t)fRounded;
               }
            }
            if(fetestexcept(FE_INVALID|FE_OVERFLOW|FE_UNDERFLOW|FE_DIVBYZERO)) {
               // round() and roundf() shouldn't result in exceptions here, but
               // catch them to be robust and thorough. Don't try to
               // distinguish between the various exceptions because it seems
               // they vary by CPU, compiler and OS.
               return QCBOR_ERR_FLOAT_EXCEPTION;
            }

         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
#else
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
         break;

      case QCBOR_TYPE_INT64:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_XINT64) {
            if(pItem->val.int64 >= 0) {
               *puValue = (uint64_t)pItem->val.int64;
            } else {
               return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
            }
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_UINT64:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_XINT64) {
            *puValue = pItem->val.uint64;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_65BIT_NEG_INT:
         return QCBOR_ERR_NUMBER_SIGN_CONVERSION;

      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }

   return QCBOR_SUCCESS;
}


/**
 * @brief Almost-public method to decode a number and convert to uint64_t (semi-private).
 *
 * @param[in] pMe            The decode context.
 * @param[in] uConvertTypes  Bit mask list of conversion options.
 * @param[out] puValue       Result of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetUInt64Convert().
 */
void
QCBORDecode_Private_GetUInt64Convert(QCBORDecodeContext *pMe,
                                     const uint32_t      uConvertTypes,
                                     uint64_t           *puValue,
                                     QCBORItem          *pItem)
{
   QCBORDecode_VGetNext(pMe, pItem);
   if(pMe->uLastError) {
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_ConvertUInt64(pItem,
                                                          uConvertTypes,
                                                          puValue);
}


/**
 * @brief Almost-public method to decode a number and convert to uint64_t (semi-private).
 *
 * @param[in] pMe            The decode context.
 * @param[in] nLabel         Label to find in map.
 * @param[in] uConvertTypes  Bit mask list of conversion options.
 * @param[out] puValue       Result of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetUInt64ConvertInMapN().
 */
void
QCBORDecode_Private_GetUInt64ConvertInMapN(QCBORDecodeContext *pMe,
                                           const int64_t       nLabel,
                                           const uint32_t      uConvertTypes,
                                           uint64_t            *puValue,
                                           QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_ConvertUInt64(pItem,
                                                          uConvertTypes,
                                                          puValue);
}


/**
 * @brief Almost-public method to decode a number and convert to uint64_t (semi-private).
 *
 * @param[in] pMe            The decode context.
 * @param[in] szLabel         Label to find in map.
 * @param[in] uConvertTypes  Bit mask list of conversion options.
 * @param[out] puValue       Result of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetUInt64ConvertInMapSZ().
 */
void
QCBORDecode_Private_GetUInt64ConvertInMapSZ(QCBORDecodeContext *pMe,
                                            const char         *szLabel,
                                            const uint32_t      uConvertTypes,
                                            uint64_t           *puValue,
                                            QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_ConvertUInt64(pItem,
                                                          uConvertTypes,
                                                          puValue);
}


/**
 * @brief Convert many number types to an unt64_t.
 *
 * @param[in] pItem   The item to convert.
 * @param[in] uConvertTypes  Bit mask list of conversion options.
 * @param[out] puValue  The resulting converted value.
 *
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
 *                                    in uConvertTypes.
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
 *                                               or too small.
 */
static QCBORError
QCBOR_Private_UInt64ConvertAll(const QCBORItem *pItem,
                               const uint32_t   uConvertTypes,
                               uint64_t        *puValue)
{
   switch(pItem->uDataType) { /* -Wmaybe-uninitialized falsly warns here */

      case QCBOR_TYPE_POSBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return QCBORDecode_Private_PositiveBigNumberToUInt(pItem->val.bigNum, puValue);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA

      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return QCBOR_Private_ExponentitateNU(pItem->val.expAndMantissa.Mantissa.nInt,
                                   pItem->val.expAndMantissa.nExponent,
                                   puValue,
                                   QCBOR_Private_Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIGFLOAT) {
            return QCBOR_Private_ExponentitateNU(pItem->val.expAndMantissa.Mantissa.nInt,
                                   pItem->val.expAndMantissa.nExponent,
                                   puValue,
                                   QCBOR_Private_Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            uint64_t   uMantissa;
            QCBORError uErr;
            uErr = QCBORDecode_Private_PositiveBigNumberToUInt(pItem->val.expAndMantissa.Mantissa.bigNum, &uMantissa);
            if(uErr != QCBOR_SUCCESS) {
               return uErr;
            }
            return QCBOR_Private_ExponentitateUU(uMantissa,
                                                 pItem->val.expAndMantissa.nExponent,
                                                 puValue,
                                                 QCBOR_Private_Exponentitate10);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            uint64_t   uMantissa;
            QCBORError uErr;
            uErr = QCBORDecode_Private_PositiveBigNumberToUInt(pItem->val.expAndMantissa.Mantissa.bigNum,
                                                                 &uMantissa);
            if(uErr != QCBOR_SUCCESS) {
               return uErr;
            }
            return QCBOR_Private_ExponentitateUU(uMantissa,
                                                 pItem->val.expAndMantissa.nExponent,
                                                 puValue,
                                                 QCBOR_Private_Exponentitate2);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            return QCBOR_ERR_NUMBER_SIGN_CONVERSION;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;
#endif /* QCBOR_DISABLE_EXP_AND_MANTISSA */
      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetUInt64ConvertAll(QCBORDecodeContext *pMe,
                                const uint32_t      uConvertTypes,
                                uint64_t           *puValue)
{
   QCBORItem Item;

   QCBORDecode_Private_GetUInt64Convert(pMe, uConvertTypes, puValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_UInt64ConvertAll(&Item,
                                                             uConvertTypes,
                                                             puValue);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetUInt64ConvertAllInMapN(QCBORDecodeContext *pMe,
                                      const int64_t       nLabel,
                                      const uint32_t      uConvertTypes,
                                      uint64_t           *puValue)
{
   QCBORItem Item;

   QCBORDecode_Private_GetUInt64ConvertInMapN(pMe,
                                              nLabel,
                                              uConvertTypes,
                                              puValue,
                                              &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_UInt64ConvertAll(&Item,
                                                             uConvertTypes,
                                                             puValue);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetUInt64ConvertAllInMapSZ(QCBORDecodeContext *pMe,
                                       const char         *szLabel,
                                       const uint32_t      uConvertTypes,
                                       uint64_t           *puValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetUInt64ConvertInMapSZ(pMe,
                                               szLabel,
                                               uConvertTypes,
                                               puValue,
                                               &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_UInt64ConvertAll(&Item,
                                                             uConvertTypes,
                                                             puValue);
}




#ifndef USEFULBUF_DISABLE_ALL_FLOAT
/**
 * @brief Basic conversions to a double.
 *
 * @param[in] pItem          The item to convert
 * @param[in] uConvertTypes  Bit flags indicating source types for conversion
 * @param[out] pdValue       The value converted to a double
 *
 * This does the conversions that don't need much object code,
 * the conversions from int, uint and float to double.
 *
 * See QCBOR_Private_DoubleConvertAll() for the full set
 * of conversions.
 */
static QCBORError
QCBOR_Private_ConvertDouble(const QCBORItem *pItem,
                            const uint32_t   uConvertTypes,
                            double          *pdValue)
{
   switch(pItem->uDataType) {
      case QCBOR_TYPE_FLOAT:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
            if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
               // Simple cast does the job.
               *pdValue = (double)pItem->val.fnum;
            } else {
               return QCBOR_ERR_UNEXPECTED_TYPE;
            }
         }
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
         break;

      case QCBOR_TYPE_DOUBLE:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
            if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
               *pdValue = pItem->val.dfnum;
            } else {
               return QCBOR_ERR_UNEXPECTED_TYPE;
            }
         }
         break;

      case QCBOR_TYPE_INT64:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         if(uConvertTypes & QCBOR_CONVERT_TYPE_XINT64) {
            // A simple cast seems to do the job with no worry of exceptions.
            // There will be precision loss for some values.
            *pdValue = (double)pItem->val.int64;

         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
#else
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */
         break;

      case QCBOR_TYPE_UINT64:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         if(uConvertTypes & QCBOR_CONVERT_TYPE_XINT64) {
            // A simple cast seems to do the job with no worry of exceptions.
            // There will be precision loss for some values.
            *pdValue = (double)pItem->val.uint64;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;
#else
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */

      case QCBOR_TYPE_65BIT_NEG_INT:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         // TODO: don't use float HW. We have the function to do it.
         *pdValue = -(double)pItem->val.uint64 - 1;
         break;
#else
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */

      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }

   return QCBOR_SUCCESS;
}


/**
 * @brief  Almost-public method to decode a number and convert to double (semi-private).
 *
 * @param[in] pMe            The decode context.
 * @param[in] uConvertTypes  Bit mask list of conversion options
 * @param[out] pdValue       The output of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetDoubleConvert().
 */
void
QCBORDecode_Private_GetDoubleConvert(QCBORDecodeContext *pMe,
                                     const uint32_t      uConvertTypes,
                                     double             *pdValue,
                                     QCBORItem          *pItem)
{
   QCBORDecode_VGetNext(pMe, pItem);
   if(pMe->uLastError) {
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_ConvertDouble(pItem,
                                                          uConvertTypes,
                                                          pdValue);
}


/**
 * @brief  Almost-public method to decode a number and convert to double (semi-private).
 *
 * @param[in] pMe            The decode context.
 * @param[in] nLabel         Label to find in map.
 * @param[in] uConvertTypes  Bit mask list of conversion options
 * @param[out] pdValue       The output of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetDoubleConvertInMapN().
 */
void
QCBORDecode_Private_GetDoubleConvertInMapN(QCBORDecodeContext *pMe,
                                           const int64_t       nLabel,
                                           const uint32_t      uConvertTypes,
                                           double             *pdValue,
                                           QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_ConvertDouble(pItem,
                                                          uConvertTypes,
                                                          pdValue);
}


/**
 * @brief  Almost-public method to decode a number and convert to double (semi-private).
 *
 * @param[in] pMe            The decode context.
 * @param[in] szLabel        Label to find in map.
 * @param[in] uConvertTypes  Bit mask list of conversion options
 * @param[out] pdValue       The output of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetDoubleConvertInMapSZ().
 */
void
QCBORDecode_Private_GetDoubleConvertInMapSZ(QCBORDecodeContext *pMe,
                                            const char         *szLabel,
                                            const uint32_t      uConvertTypes,
                                            double             *pdValue,
                                            QCBORItem          *pItem)
{
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_ConvertDouble(pItem,
                                                          uConvertTypes,
                                                          pdValue);
}


/**
 * @brief Convert many number types to a double.
 *
 * @param[in] pItem   The item to convert.
 * @param[in] uConvertTypes  Bit mask list of conversion options.
 * @param[out] pdValue  The resulting converted value.
 *
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
 *                                    in uConvertTypes.
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
 *                                               or too small.
 */
static QCBORError
QCBOR_Private_DoubleConvertAll(const QCBORItem *pItem,
                               const uint32_t   uConvertTypes,
                               double          *pdValue)
{
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
   /*
    * What Every Computer Scientist Should Know About Floating-Point Arithmetic
    * https://docs.oracle.com/cd/E19957-01/806-3568/ncg_goldberg.html
    */
   switch(pItem->uDataType) {

#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
      case QCBOR_TYPE_DECIMAL_FRACTION:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            // Underflow gives 0, overflow gives infinity
            *pdValue = (double)pItem->val.expAndMantissa.Mantissa.nInt *
                        pow(10.0, (double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIGFLOAT ) {
            // Underflow gives 0, overflow gives infinity
            *pdValue = (double)pItem->val.expAndMantissa.Mantissa.nInt *
                              exp2((double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;
#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */

      case QCBOR_TYPE_POSBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            *pdValue = QCBORDecode_Private_BigNumberToDouble(pItem->val.bigNum);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_NEGBIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIG_NUM) {
            *pdValue = -1-QCBORDecode_Private_BigNumberToDouble(pItem->val.bigNum);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            double dMantissa = QCBORDecode_Private_BigNumberToDouble(pItem->val.expAndMantissa.Mantissa.bigNum);
            *pdValue = dMantissa * pow(10, (double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_DECIMAL_FRACTION) {
            /* Must subtract 1 for CBOR negative integer offset */
            double dMantissa = -1-QCBORDecode_Private_BigNumberToDouble(pItem->val.expAndMantissa.Mantissa.bigNum);
            *pdValue = dMantissa * pow(10, (double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_POS_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIGFLOAT) {
            double dMantissa = QCBORDecode_Private_BigNumberToDouble(pItem->val.expAndMantissa.Mantissa.bigNum);
            *pdValue = dMantissa * exp2((double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIGFLOAT) {
            double dMantissa = -1-QCBORDecode_Private_BigNumberToDouble(pItem->val.expAndMantissa.Mantissa.bigNum);
            *pdValue = dMantissa * exp2((double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;
#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */

      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;
   }

   return QCBOR_SUCCESS;

#else
   (void)pItem;
   (void)uConvertTypes;
   (void)pdValue;
   return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* QCBOR_DISABLE_FLOAT_HW_USE */

}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetDoubleConvertAll(QCBORDecodeContext *pMe,
                                const uint32_t      uConvertTypes,
                                double             *pdValue)
{

   QCBORItem Item;

   QCBORDecode_Private_GetDoubleConvert(pMe, uConvertTypes, pdValue, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_DoubleConvertAll(&Item,
                                                             uConvertTypes,
                                                             pdValue);
}


/*
 *  Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetDoubleConvertAllInMapN(QCBORDecodeContext *pMe,
                                      const int64_t       nLabel,
                                      const uint32_t      uConvertTypes,
                                      double             *pdValue)
{
   QCBORItem Item;

   QCBORDecode_Private_GetDoubleConvertInMapN(pMe,
                                              nLabel,
                                              uConvertTypes,
                                              pdValue,
                                              &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_DoubleConvertAll(&Item,
                                                             uConvertTypes,
                                                             pdValue);
}


/*
 * Public function, see header qcbor/qcbor_decode.h file
 */
void
QCBORDecode_GetDoubleConvertAllInMapSZ(QCBORDecodeContext *pMe,
                                       const char         *szLabel,
                                       const uint32_t      uConvertTypes,
                                       double             *pdValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetDoubleConvertInMapSZ(pMe,
                                               szLabel,
                                               uConvertTypes,
                                               pdValue,
                                               &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      // The above conversion succeeded
      return;
   }

   if(pMe->uLastError != QCBOR_ERR_UNEXPECTED_TYPE) {
      // The above conversion failed in a way that code below can't correct
      return;
   }

   pMe->uLastError = (uint8_t)QCBOR_Private_DoubleConvertAll(&Item,
                                                             uConvertTypes,
                                                             pdValue);
}
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */


// TODO: re order above functions in tag number order