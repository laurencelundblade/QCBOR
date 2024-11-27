/* ==========================================================================
 * qcbor_tag_decode.c -- Tag content decoders
 *
 * Copyright (c) 2016-2018, The Linux Foundation.
 * Copyright (c) 2018-2024, Laurence Lundblade.
 * Copyright (c) 2021, Arm Limited.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Forked from qcbor_decode.c on 11/14/24
 * ========================================================================== */


#ifndef decode_private_h
#define decode_private_h

#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

/* These are decode functions used by the spiffy decode and number decode
 * implementation. They are internal linkage and nothing to do with
 * the public decode interface.
 */

QCBORError
QCBORDecode_Private_GetNextTagContent(QCBORDecodeContext *pMe,
                                      QCBORItem          *pDecodedItem);


void
QCBORDecode_Private_ProcessTagItemMulti(QCBORDecodeContext      *pMe,
                                        QCBORItem               *pItem,
                                        const uint8_t            uTagRequirement,
                                        const uint8_t            uQCBORTypes[],
                                        const uint64_t           uTagNumbers[],
                                        QCBORTagContentCallBack *pfCB,
                                        size_t                   uOffset);


void
QCBORDecode_Private_ProcessTagItem(QCBORDecodeContext      *pMe,
                                   QCBORItem               *pItem,
                                   const uint8_t            uTagRequirement,
                                   const uint8_t            uQCBORTypes[],
                                   const uint64_t           uTagNumber,
                                   QCBORTagContentCallBack *pfCB,
                                   size_t                   uOffset);


void
QCBORDecode_Private_GetItemInMapNoCheckSZ(QCBORDecodeContext *pMe,
                                          const char         *szLabel,
                                          const uint8_t       uQcborType,
                                          QCBORItem          *pItem,
                                          size_t             *puOffset);


void
QCBORDecode_Private_GetItemInMapNoCheckN(QCBORDecodeContext *pMe,
                                         const int64_t       nLabel,
                                         const uint8_t       uQcborType,
                                         QCBORItem          *pItem,
                                         size_t             *puOffset);


static inline void
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


uint64_t
QCBORDecode_Private_UnMapTagNumber(const QCBORDecodeContext *pMe,
                                   const uint16_t            uMappedTagNumber);


QCBORError
DecodeNesting_DescendIntoBstrWrapped(QCBORDecodeNesting *pNesting,
                                     uint32_t            uEndOffset,
                                     uint32_t            uStartOffset);


typedef struct {
   void               *pCBContext;
   QCBORItemCallback   pfCallback;
} MapSearchCallBack;

typedef struct {
   size_t   uStartOffset;
   uint16_t uItemCount;
} MapSearchInfo;

QCBORError
QCBORDecode_Private_MapSearch(QCBORDecodeContext *pMe,
                              QCBORItem          *pItemArray,
                              MapSearchInfo      *pInfo,
                              MapSearchCallBack  *pCallBack);


QCBORError
QCBORDecode_Private_ExitBoundedLevel(QCBORDecodeContext *pMe,
                                     const uint32_t      uEndOffset);


static inline void
DecodeNesting_ReverseDecrement(QCBORDecodeNesting *pNesting)
{
   /* Only call on a definite-length array / map */
   pNesting->pCurrent->u.ma.uCountCursor++;
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

#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

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


static inline uint32_t
DecodeNesting_GetPreviousBoundedEnd(const QCBORDecodeNesting *pMe)
{
   return pMe->pCurrentBounded->u.bs.uSavedEndOffset;
}

#endif /* decode_private_h */
