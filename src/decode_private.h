/* ==========================================================================
 * decode_private.c -- semi-private & inline functions for qcbor_decode.c
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
#include "qcbor/qcbor_spiffy_decode.h" /* For QCBORItemCallback */

/* These are decode functions used by the spiffy decode and number decode
 * implementation. They are internal linkage and nothing to do with
 * the public decode interface.
 */

/* Semi-private function. See qcbor_decode.c */
QCBORError
QCBORDecode_Private_GetNextTagContent(QCBORDecodeContext *pMe,
                                      QCBORItem          *pDecodedItem);


/* Semi-private function. See qcbor_decode.c */
void
QCBORDecode_Private_GetItemInMapNoCheckSZ(QCBORDecodeContext *pMe,
                                          const char         *szLabel,
                                          const uint8_t       uQcborType,
                                          QCBORItem          *pItem,
                                          size_t             *puOffset);

/* Semi-private function. See qcbor_decode.c */
void
QCBORDecode_Private_GetItemInMapNoCheckN(QCBORDecodeContext *pMe,
                                         const int64_t       nLabel,
                                         const uint8_t       uQcborType,
                                         QCBORItem          *pItem,
                                         size_t             *puOffset);


/* Semi-private function. See qcbor_decode.c */
uint64_t
QCBORDecode_Private_UnMapTagNumber(const QCBORDecodeContext *pMe,
                                   const uint16_t            uMappedTagNumber);

/* Semi-private function. See qcbor_decode.c */
QCBORError
QCBORDecode_Private_ConsumeItem(QCBORDecodeContext *pMe,
                                const QCBORItem    *pItemToConsume,
                                bool               *pbBreak,
                                uint8_t            *puNextNestLevel);

/* Semi-private function. See qcbor_decode.c */
QCBORError
QCBORDecode_Private_GetItemChecks(QCBORDecodeContext *pMe,
                                  QCBORError          uErr,
                                  const size_t        uOffset,
                                  QCBORItem          *pDecodedItem);

/* Semi-private function. See qcbor_decode.c */
QCBORError
QCBORDecode_Private_NestLevelAscender(QCBORDecodeContext *pMe,
                                      bool                bMarkEnd,
                                      bool               *pbBreak);


typedef struct {
   void               *pCBContext;
   QCBORItemCallback   pfCallback;
} MapSearchCallBack;

typedef struct {
   size_t   uStartOffset;
   uint16_t uItemCount;
} MapSearchInfo;

/* Semi-private function. See qcbor_decode.c */
QCBORError
QCBORDecode_Private_MapSearch(QCBORDecodeContext *pMe,
                              QCBORItem          *pItemArray,
                              MapSearchInfo      *pInfo,
                              MapSearchCallBack  *pCallBack);


/* Semi-private function. See qcbor_decode.c */
QCBORError
QCBORDecode_Private_ExitBoundedLevel(QCBORDecodeContext *pMe,
                                     const uint32_t      uEndOffset);


static inline void
QCBORDecode_Private_SaveTagNumbers(QCBORDecodeContext *pMe, const QCBORItem *pItem)
{
#ifndef QCBOR_DISABLE_TAGS
   memcpy(pMe->auLastTags, pItem->auTagNumbers, sizeof(pItem->auTagNumbers));
#else /* ! QCBOR_DISABLE_TAGS */
   (void)pMe;
   (void)pItem;
#endif /* ! QCBOR_DISABLE_TAGS */
}



static inline void
QCBORDecode_Private_GetAndTell(QCBORDecodeContext *pMe, QCBORItem *Item, size_t *uOffset)
{
#ifndef QCBOR_DISABLE_TAGS
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   *uOffset = QCBORDecode_Tell(pMe);
#else /* ! QCBOR_DISABLE_TAGS */
   *uOffset = SIZE_MAX;

#endif /* ! QCBOR_DISABLE_TAGS */
   pMe->uLastError = (uint8_t)QCBORDecode_Private_GetNextTagContent(pMe, Item);
}




/* Semi-private function. See qcbor_tag_decode.c */
void
QCBORDecode_Private_ProcessTagItemMulti(QCBORDecodeContext      *pMe,
                                        QCBORItem               *pItem,
                                        const uint8_t            uTagRequirement,
                                        const uint8_t            uQCBORTypes[],
                                        const uint64_t           uTagNumbers[],
                                        QCBORTagContentCallBack *pfCB,
                                        size_t                   uOffset);

/* Semi-private function. See qcbor_tag_decode.c */
void
QCBORDecode_Private_ProcessTagItem(QCBORDecodeContext      *pMe,
                                   QCBORItem               *pItem,
                                   const uint8_t            uTagRequirement,
                                   const uint8_t            uQCBORTypes[],
                                   const uint64_t           uTagNumber,
                                   QCBORTagContentCallBack *pfCB,
                                   size_t                   uOffset);
#endif /* decode_private_h */
