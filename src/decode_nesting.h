/* ==========================================================================
 * decode_nesting.c -- All inline implementation of QCBORDecodeNesting
 *
 * Copyright (c) 2016-2018, The Linux Foundation.
 * Copyright (c) 2018-2024, Laurence Lundblade.
 * Copyright (c) 2021, Arm Limited.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Forked from qcbor_decode.c on 11/28/24
 * ========================================================================== */

#ifndef decode_nesting_h
#define decode_nesting_h

#include "qcbor/qcbor_private.h"


/* When this was not all explicitly inline, the compiler decided to
 * inline everything on its own, so we know there's no loss by
 * making it all inline.
 */

static inline void
DecodeNesting_Init(QCBORDecodeNesting *pNesting)
{
   /* Assumes that *pNesting has been zero'd before this call. */
   pNesting->pLevels[0].uLevelType = QCBOR_TYPE_BYTE_STRING;
   pNesting->pCurrent = &(pNesting->pLevels[0]);
}


static inline bool
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

#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

   /* All checks passed; is a definte length map or array */
   return true;
}


static inline bool
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


static inline bool
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


static inline bool
DecodeNesting_IsBoundedEmpty(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrentBounded->u.ma.uCountCursor == QCBOR_COUNT_INDICATES_ZERO_LENGTH) {
      return true;
   } else {
      return false;
   }
}


static inline bool
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


static inline bool
DecodeNesting_IsEndOfDefiniteLengthMapOrArray(const QCBORDecodeNesting *pNesting)
{
   /* Must only be called on map / array */
   if(pNesting->pCurrent->u.ma.uCountCursor == 0) {
      return true;
   } else {
      return false;
   }
}


static inline bool
DecodeNesting_IsCurrentTypeMap(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->uLevelType == CBOR_MAJOR_TYPE_MAP) {
      return true;
   } else {
      return false;
   }
}


static inline bool
DecodeNesting_IsCurrentAtTop(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent == &(pNesting->pLevels[0])) {
      return true;
   } else {
      return false;
   }
}


static inline bool
DecodeNesting_IsCurrentBstrWrapped(const QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->uLevelType == QCBOR_TYPE_BYTE_STRING) {
      /* is a byte string */
      return true;
   }
   return false;
}


static inline uint8_t
DecodeNesting_GetCurrentLevel(const QCBORDecodeNesting *pNesting)
{
   const ptrdiff_t nLevel = pNesting->pCurrent - &(pNesting->pLevels[0]);
   /* Limit in DecodeNesting_Descend against more than
    * QCBOR_MAX_ARRAY_NESTING gaurantees cast is safe
    */
   return (uint8_t)nLevel;
}




static inline void
DecodeNesting_DecrementDefiniteLengthMapOrArrayCount(QCBORDecodeNesting *pNesting)
{
   /* Only call on a definite-length array / map */
   pNesting->pCurrent->u.ma.uCountCursor--;
}


static inline void
DecodeNesting_ZeroMapOrArrayCount(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent->u.ma.uCountCursor = 0;
}

static inline void
DecodeNesting_ResetMapOrArrayCount(QCBORDecodeNesting *pNesting)
{
   if(pNesting->pCurrent->u.ma.uCountCursor != QCBOR_COUNT_INDICATES_ZERO_LENGTH) {
      pNesting->pCurrentBounded->u.ma.uCountCursor = pNesting->pCurrentBounded->u.ma.uCountTotal;
   }
}

static inline void
DecodeNesting_ReverseDecrement(QCBORDecodeNesting *pNesting)
{
   /* Only call on a definite-length array / map */
   pNesting->pCurrent->u.ma.uCountCursor++;
}




static inline void
DecodeNesting_ClearBoundedMode(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent->u.ma.uStartOffset = QCBOR_NON_BOUNDED_OFFSET;
}


static inline QCBORError
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

static inline QCBORError
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


static inline QCBORError
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


static inline void
DecodeNesting_Ascend(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent--;
}




static inline void
DecodeNesting_SetCurrentToBoundedLevel(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent = pNesting->pCurrentBounded;
}

static inline void
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

static inline QCBORError
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


static inline uint32_t
DecodeNesting_GetPreviousBoundedEnd(const QCBORDecodeNesting *pMe)
{
   return pMe->pCurrentBounded->u.bs.uSavedEndOffset;
}


static inline uint8_t
DecodeNesting_GetBoundedModeLevel(const QCBORDecodeNesting *pNesting)
{
   const ptrdiff_t nLevel = pNesting->pCurrentBounded - &(pNesting->pLevels[0]);
   /* Limit in DecodeNesting_Descend against more than
    * QCBOR_MAX_ARRAY_NESTING gaurantees cast is safe
    */
   return (uint8_t)nLevel;
}




static inline uint32_t
DecodeNesting_GetMapOrArrayStart(const QCBORDecodeNesting *pNesting)
{
   return pNesting->pCurrentBounded->u.ma.uStartOffset;
}


static inline void
DecodeNesting_LevelUpCurrent(QCBORDecodeNesting *pNesting)
{
   pNesting->pCurrent = pNesting->pCurrentBounded - 1;
}


static inline void
DecodeNesting_LevelUpBounded(QCBORDecodeNesting *pNesting)
{
   while(pNesting->pCurrentBounded != &(pNesting->pLevels[0])) {
      pNesting->pCurrentBounded--;
      if(DecodeNesting_IsCurrentBounded(pNesting)) {
         break;
      }
   }
}




static inline void
DecodeNesting_PrepareForMapSearch(QCBORDecodeNesting *pNesting,
                                  QCBORDecodeNesting *pSave)
{
   *pSave = *pNesting;
}


static inline void
DecodeNesting_RestoreFromMapSearch(QCBORDecodeNesting *pNesting,
                                   const QCBORDecodeNesting *pSave)
{
   *pNesting = *pSave;
}

#endif /* decode_nesting_h */
