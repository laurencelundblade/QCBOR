/* ==========================================================================
 * qcbor_tag_decode.c -- Tag content decoders
 *
 * Copyright (c) 2025, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Forked from qcbode_decode.c on 9/5/24
 * ========================================================================== */

#include "qcbor/qcbor_tag_decode.h"
#include "qcbor/qcbor_spiffy_decode.h" /* For MapSearch & GetItemInMapNoCheck */
#include "decode_nesting.h"

#include <math.h> /* For isnan() */

#ifndef QCBOR_DISABLE_TAGS

/* ========================================================================= *
 *    Core/base Tag Number Decoding                                          *
 * ========================================================================= */

/**
 * @brief Get the next tag number per the tag number cursor.
 *
 * @param[in] pMe      The decode context
 * @param[in] pItem    The data item.
 * @param[in] uOffset  Offset in the input stream.
 * @param[out] puTagNumber  The returned tag number.
 *
 * A data item may have many tag numbers associated. This tracks
 * which one is next and returns it.
 */
static void
QCBORDecode_Private_TagNumberCursor(QCBORDecodeContext *pMe,
                                    const QCBORItem    *pItem,
                                    const size_t        uOffset,
                                    uint64_t           *puTagNumber)
{
   if(uOffset == pMe->uTagNumberCheckOffset) {
      if(pMe->uTagNumberIndex != QCBOR_ALL_TAGS_PROCESSED) {
         pMe->uTagNumberIndex++;
      }
   } else {
      pMe->uTagNumberIndex = 0;
   }

   /* QCBORDecode_GetNthTagNumber() on QCBOR_ALL_TAGS_PROCESSED
    * returns CBOR_TAG_INVALID64 */
   *puTagNumber = QCBORDecode_NthTagNumber(pMe,  pItem, pMe->uTagNumberIndex);
   if(*puTagNumber == CBOR_TAG_INVALID64 ||
      QCBORDecode_NthTagNumber(pMe, pItem, pMe->uTagNumberIndex + 1) == CBOR_TAG_INVALID64) {
      pMe->uTagNumberIndex = QCBOR_ALL_TAGS_PROCESSED;
   }
   pMe->uTagNumberCheckOffset = uOffset;
}



/* Public function; see qcbor_tag_decode.h */
QCBORError
QCBORDecode_GetNextTagNumber(QCBORDecodeContext *pMe, uint64_t *puTagNumber)
{
   QCBORItem   Item;
   size_t      uOffset;
   QCBORError  uErr;

   const QCBORDecodeNesting SaveNesting = pMe->nesting;
   const UsefulInputBuf     Save        = pMe->InBuf;

   uOffset = UsefulInputBuf_Tell(&(pMe->InBuf));
   uErr = QCBORDecode_Private_GetNextTagContent(pMe, &Item);
   if(uErr != QCBOR_SUCCESS) {
      return uErr;
   }
   QCBORDecode_Private_TagNumberCursor(pMe, &Item, uOffset, puTagNumber);

   pMe->nesting = SaveNesting;
   pMe->InBuf   = Save;

   return QCBOR_SUCCESS;
}


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_VGetNextTagNumber(QCBORDecodeContext *pMe, uint64_t *puTagNumber)
{
   pMe->uLastError = (uint8_t)QCBORDecode_GetNextTagNumber(pMe, puTagNumber);
}


/* Public function, see qcbor_tag_decode.h */
QCBORError
QCBORDecode_GetNextTagNumberInMapN(QCBORDecodeContext *pMe,
                                   const int64_t       nLabel,
                                   uint64_t           *puTagNumber)
{
   MapSearchInfo  Info;
   QCBORItem      OneItemSearch[2];
   QCBORError     uReturn;

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return pMe->uLastError;
   }

   OneItemSearch[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSearch[0].label.int64 = nLabel;
   OneItemSearch[0].uDataType   = QCBOR_TYPE_ANY;
   OneItemSearch[1].uLabelType  = QCBOR_TYPE_NONE; // Indicates end of array

   uReturn = QCBORDecode_Private_MapSearch(pMe, OneItemSearch, &Info, NULL);
   QCBORDecode_Private_TagNumberCursor(pMe, &OneItemSearch[0],  Info.uStartOffset, puTagNumber);

   return uReturn;
}


/* Public function; see qcbor_tag_decode.h */
QCBORError
QCBORDecode_GetNextTagNumberInMapSZ(QCBORDecodeContext *pMe,
                                    const char         *szLabel,
                                    uint64_t           *puTagNumber)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   MapSearchInfo  Info;
   QCBORItem      OneItemSearch[2];
   QCBORError     uReturn;

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return pMe->uLastError;
   }

   OneItemSearch[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSearch[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSearch[0].uDataType    = QCBOR_TYPE_ANY;
   OneItemSearch[1].uLabelType   = QCBOR_TYPE_NONE; // Indicates end of array

   uReturn = QCBORDecode_Private_MapSearch(pMe, OneItemSearch, &Info, NULL);
   QCBORDecode_Private_TagNumberCursor(pMe, &OneItemSearch[0], Info.uStartOffset, puTagNumber);

   return uReturn;
#else /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
   (void)pMe;
   (void)szLabel;
   (void)puTagNumber;
   return QCBOR_ERR_LABEL_NOT_FOUND;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
}


/* Public function; see qcbor_tag_decode.h */
uint64_t
QCBORDecode_NthTagNumber(const QCBORDecodeContext *pMe,
                         const QCBORItem          *pItem,
                         const size_t              uIndex)
{
   if(pItem->uDataType == QCBOR_TYPE_NONE) {
      return CBOR_TAG_INVALID64;
   }
   if(uIndex >= QCBOR_MAX_TAGS_PER_ITEM) {
      return CBOR_TAG_INVALID64;
   }

   return QCBORDecode_Private_UnMapTagNumber(pMe, pItem->auTagNumbers[uIndex]);
}


/* Public function; see qcbor_tag_decode.h */
uint64_t
QCBORDecode_NthTagNumberOfLast(QCBORDecodeContext *pMe, const size_t uIndex)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return CBOR_TAG_INVALID64;
   }
   if(uIndex >= QCBOR_MAX_TAGS_PER_ITEM) {
      return CBOR_TAG_INVALID64;
   }

   return QCBORDecode_Private_UnMapTagNumber(pMe, pMe->auLastTagNumbers[uIndex]);
}


static uint64_t
QCBORDecode_Private_GetNthTagNumberReverse(const QCBORDecodeContext *pMe,
                                           const uint16_t            puTagNumbers[],
                                           const size_t              uIndex)
{
   size_t uArrayIndex;

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


/* Public function; see qcbor_tag_decode.h */
uint64_t
QCBORDecode_GetNthTag(QCBORDecodeContext *pMe,
                      const QCBORItem    *pItem,
                      const uint32_t      uIndex)
{
   if(pItem->uDataType == QCBOR_TYPE_NONE) {
      return CBOR_TAG_INVALID64;
   }

   return QCBORDecode_Private_GetNthTagNumberReverse(pMe,
                                                     pItem->auTagNumbers,
                                                     uIndex);
}


/* Public function; see qcbor_tag_decode.h */
uint64_t
QCBORDecode_GetNthTagOfLast(const QCBORDecodeContext *pMe, uint32_t uIndex)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return CBOR_TAG_INVALID64;
   }
   if(uIndex >= QCBOR_MAX_TAGS_PER_ITEM) {
      return CBOR_TAG_INVALID64;
   }

   return QCBORDecode_Private_GetNthTagNumberReverse(pMe,
                                                     pMe->auLastTagNumbers,
                                                     uIndex);
}

#endif /* ! QCBOR_DISABLE_TAGS */



/* ========================================================================= *
 *    Support for Spiffy Decode of standard tags                             *
 * ========================================================================= */


/* Return 1 if type is in uQCBORTypes, 0 if not */
static int
QCBORDecode_Private_CheckItemType(const QCBORItem  *pItem,
                                  const uint8_t    *uQCBORTypes)
{
   const uint8_t  *pTypeNum;

   for(pTypeNum = uQCBORTypes; *pTypeNum != QCBOR_TYPE_NONE; pTypeNum++) {
      if(pItem->uDataType == *pTypeNum) {
         return 1;
      }
   }

   return 0;
}

#ifndef QCBOR_DISABLE_TAGS

/* Return 1 if inner tag number is in uTagNumbers */
static int
QCBORDecode_Private_CheckItemTagNumbers(uint64_t        uInnerTag,
                                        const uint64_t *uTagNumbers)
{
   const uint64_t *pTN;

   for(pTN = uTagNumbers; *pTN != CBOR_TAG_INVALID64; pTN++) {
      if(uInnerTag == *pTN) {
         return 1;
         break;
      }
   }

   return 0;
}


/* When extra tag numbers are not allowed, this checks that there are
 * not any. Only used in QCBOR v1 mode. */
static QCBORError
QCBORDecode_Private_CheckForExtraTagNumbers(QCBORDecodeContext *pMe,
                                            const QCBORItem    *pItem,
                                            const uint64_t     *uTagNumbers)
{
   const uint64_t  *pTNum;
   uint64_t         uTagNum;
   uint8_t          n;

   /* Look for one tag number that is not of interest. If present,
    * error out.
    */
   for(n = 0; ; n++) {
      uTagNum = QCBORDecode_NthTagNumber(pMe, pItem, n);
      if(uTagNum == CBOR_TAG_INVALID64) {
         break;
      }
      for(pTNum = uTagNumbers; *pTNum != CBOR_TAG_INVALID64; pTNum++) {
         if(uTagNum == *pTNum) {
            break;
         }
      }
      if(*pTNum == CBOR_TAG_INVALID64) {
         return QCBOR_ERR_UNEXPECTED_TAG_NUMBER;
      }
   }

   return QCBOR_SUCCESS;
}

#endif /* ! QCBOR_DISABLE_TAGS */


static QCBORError
QCBORDecode_Private_CheckTagAndType(QCBORDecodeContext          *pMe,
                                    const QCBORItem             *pItem,
                                    const size_t                 uOffset,
                                    const uint8_t               *uQCBORTypes,
                                    const uint64_t              *uTagNumbers,
                                    const enum QCBORDecodeTagReq uTagReqArg,
                                    bool                        *pbTypeMatched)
{
   QCBORError              uErr;
   enum QCBORDecodeTagReq  uTagReq;
   uint64_t                uTagNumber;

   const bool bModeQCBORv1 = pMe->uDecodeMode & QCBOR_DECODE_ALLOW_UNPROCESSED_TAG_NUMBERS;

   if(bModeQCBORv1) {
      uTagReq = (enum QCBORDecodeTagReq)((int)uTagReqArg & ~QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS);
   } else {
      if(uTagReqArg & QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS) {
         uErr = QCBOR_ERR_NOT_ALLOWED;
         goto Done;
      }
      uTagReq = uTagReqArg;
   }

   *pbTypeMatched = QCBORDecode_Private_CheckItemType(pItem, uQCBORTypes);

   if(*pbTypeMatched) {
      /* The tag content was already decoded to a type of interest. */
      *pbTypeMatched = true;
      if(uTagReq == QCBOR_TAG_REQUIREMENT_NOT_A_TAG) {
         /* If the requirement is to be not a tag (borrowed), then it
          * couldn't have been decoded by an installed decoder */
         uErr = QCBOR_ERR_UNEXPECTED_TAG_NUMBER;
         goto Done;
      }
   } else {
#ifndef QCBOR_DISABLE_TAGS
      /* The tag content has not been decoded. */
      if(bModeQCBORv1) {
         /* Use QCBORDecode_GetNthTag() not xxx to get *inner* tag. */
         uTagNumber = QCBORDecode_GetNthTag(pMe, pItem, 0);
      } else {
         QCBORDecode_Private_TagNumberCursor(pMe, pItem, uOffset, &uTagNumber);
      }

      if(uTagNumber != CBOR_TAG_INVALID64) {
         /* There was a tag number. */
         bool bOfInterest = QCBORDecode_Private_CheckItemTagNumbers(uTagNumber, uTagNumbers);
         if(bOfInterest) {
            if(uTagReq == QCBOR_TAG_REQUIREMENT_NOT_A_TAG) {
               uErr = QCBOR_ERR_UNEXPECTED_TAG_NUMBER;
               goto Done;
            }
            if(uOffset == pMe->uTagNumberCheckOffset &&
               pMe->uTagNumberIndex != QCBOR_ALL_TAGS_PROCESSED) {
               uErr = QCBOR_ERR_UNPROCESSED_TAG_NUMBER;
               goto Done;
            }
         } else {
            /* Tag number is not of interest */
            if(bModeQCBORv1) {
               if(uTagReq == QCBOR_TAG_REQUIREMENT_TAG) {
                  uErr = QCBOR_ERR_UNEXPECTED_TAG_NUMBER;
                  goto Done;
               } else if(!(uTagReqArg & QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS)) {
                  uErr = QCBOR_ERR_UNEXPECTED_TAG_NUMBER;
                  goto Done;
               }
            } else {
               /* A tag number not of interest is always an error in v2 */
               uErr = QCBOR_ERR_UNEXPECTED_TAG_NUMBER;
               goto Done;
            }
         }
      } else {
         /* There is no tag number. It could be "borrowed" tag content. */
         if(uTagReq == QCBOR_TAG_REQUIREMENT_TAG) {
            uErr = QCBOR_ERR_MISSING_TAG_NUMBER;
            goto Done;
         }
      }
   }

   if(bModeQCBORv1 && !(uTagReqArg & QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS)) {
      uErr = (uint8_t)QCBORDecode_Private_CheckForExtraTagNumbers(pMe, pItem, uTagNumbers);
      if(uErr != QCBOR_SUCCESS) {
         goto Done;
      }
#else /* ! QCBOR_DISABLE_TAGS */
      if(uTagReq == QCBOR_TAG_REQUIREMENT_TAG) {
         /* Tags are disabled and caller wants the tag checked */
         uErr = QCBOR_ERR_TAGS_DISABLED;
         goto Done;
      }
      (void)uOffset;
      (void)uTagNumbers;
      (void)uTagNumber;
#endif /* ! QCBOR_DISABLE_TAGS */
   }
   uErr = QCBOR_SUCCESS;

Done:
   return uErr;
}


/** @brief Semi-private generic spiffy decode Get tag processor.
 *
 * @param [in] pMe   The decode context.
 * @param [in] uTagReq The type of tag requirement.
 * @param [in] uQCBORTypes  The CBOR type expected.
 * @param [in] uTagNumbers  The Tag number expected.
 * @param [in] pfCB        The callback to process the tag.
 * @param [in] pCBCtx   Context for pfCB.
 * @param [in] uOffset     Needed to track tag number consumption
 * @param [in,out] pItem  Item to be decoded; decoded item
 *
 * This is the main for spiffy decoding of tag types like
 * GetEpochDate().  It is complicated because it handles the case were
 * a content decode callback was installed and when it wasn't. This
 * fans out to a lot of cases for data types and tag numbers. It also
 * the interpreter of enum QCBORDecodeTagReq.
 *
 * It is used only internally, but maybe it could be exposed so
 * implementors of tag content callbacks could also implement spiffy
 * decode Get() functions. This is probably not that important though
 * because most external tag processors wont' do both.
 *
 * It does two things: first a bunch of tag number and QCBOR type
 * checking. Then, if it is found that the tag content wasn't
 * processed, It calls the tag content processor.
 *
 * @c pItem is modified when the tag content is not decoded on input
 */
void
QCBORDecode_Private_ProcessTagItem(QCBORDecodeContext      *pMe,
                                   enum QCBORDecodeTagReq   uTagReq,
                                   const uint8_t            uQCBORTypes[],
                                   const uint64_t           uTagNumbers[],
                                   QCBORTagContentCallBack *pfCB,
                                   void                    *pCBCtx,
                                   size_t                   uOffset,
                                   QCBORItem               *pItem)
{
   QCBORError  uErr;
   bool        bTypeMatched;

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   /* First the big type and tag number evaluation */
   uErr = QCBORDecode_Private_CheckTagAndType(pMe,
                                              pItem,
                                              uOffset,
                                              uQCBORTypes,
                                              uTagNumbers,
                                              uTagReq,
                                             &bTypeMatched);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   if(!bTypeMatched) {
      /* Type & tag evaluation found the tag content wasn't processed yet */
      uErr = (*pfCB)(pMe, pCBCtx, uTagNumbers[0], pItem);
      if(uErr != QCBOR_SUCCESS) {
         goto Done;
      }
   }

Done:
   pMe->uLastError = (uint8_t)uErr;
}


/*
 * The same as QCBORDecode_Private_ProcessTagItem(), but only for one
 * tag number and one QCBOR data type.
 */
static void
QCBORDecode_Private_ProcessTagOne(QCBORDecodeContext      *pMe,
                                  enum QCBORDecodeTagReq   uTagReq,
                                  const uint8_t            uQCBORType,
                                  const uint64_t           uTagNumber,
                                  QCBORTagContentCallBack *pfCB,
                                  const size_t             uOffset,
                                  QCBORItem               *pItem)
{
   uint8_t   auQCBORType[2];
   uint64_t  auTagNumbers[2];

   auQCBORType[0] = uQCBORType;
   auQCBORType[1] = QCBOR_TYPE_NONE;

   auTagNumbers[0] = uTagNumber;
   auTagNumbers[1] = CBOR_TAG_INVALID64;

   QCBORDecode_Private_ProcessTagItem(pMe,
                                      uTagReq,
                                      auQCBORType,
                                      auTagNumbers,
                                      pfCB,
                                      NULL,
                                      uOffset,
                                      pItem);
}


/* The same as QCBORDecode_Private_ProcessTagItem(), but only runs
 * QCBORDecode_StringsTagCB for the IETF-standard string format tags
 * supported internally by QCBOR.
 */
void
QCBORDecode_Private_GetTaggedString(QCBORDecodeContext    *pMe,
                                    enum QCBORDecodeTagReq uTagReq,
                                    const uint8_t          uQCBORType,
                                    const uint64_t         uTagNumber,
                                    UsefulBufC            *pStr)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     uTagReq,
                                     uQCBORType,
                                     uTagNumber,
                                     QCBORDecode_StringsTagCB,
                                     uOffset,
                                     &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pStr = Item.val.string;
   } else {
      *pStr = NULLUsefulBufC;
   }
}


/**
 * @brief Semi-private to get an string by label to match a tag specification.
 *
 * @param[in] pMe              The decode context.
 * @param[in] nLabel           Label to search map for.
 * @param[in] uTagRequirement  See @ref QCBORDecodeTagReq.
 * @param[in] uQCBOR_Type      QCBOR type to search for.
 * @param[in] uTagNumber       Tag number to match.
 * @param[out] pString         The string found.
 *
 * This finds the string with the given label in currently open
 * map. Then checks that its tag number and types matches the tag
 * specification. If not, an error is set in the decode context.
 */
void
QCBORDecode_Private_GetTaggedStringInMapN(QCBORDecodeContext          *pMe,
                                          const int64_t                nLabel,
                                          const enum QCBORDecodeTagReq uTagReq,
                                          const uint8_t                uQCBOR_Type,
                                          const uint64_t               uTagNumber,
                                          UsefulBufC                  *pString)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe,
                                            nLabel,
                                            QCBOR_TYPE_ANY,
                                            &Item,
                                            &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     uTagReq,
                                     uQCBOR_Type,
                                     uTagNumber,
                                     QCBORDecode_StringsTagCB,
                                     uOffset,
                                     &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pString = Item.val.string;
   }
}


/**
 * @brief Semi-private to get an string by label to match a tag specification.
 *
 * @param[in] pMe              The decode context.
 * @param[in] szLabel           Label to search map for.
 * @param[in] uTagRequirement  See @ref QCBORDecodeTagReq.
 * @param[in] uQCBOR_Type      QCBOR type to search for.
 * @param[in] uTagNumber       Tag number to match.
 * @param[out] pString         The string found.
 *
 * This finds the string with the given label in currently open
 * map. Then checks that its tag number and types matches the tag
 * specification. If not, an error is set in the decode context.
  */
void
QCBORDecode_Private_GetTaggedStringInMapSZ(QCBORDecodeContext          *pMe,
                                           const char                  *szLabel,
                                           const enum QCBORDecodeTagReq uTagReq,
                                           uint8_t                      uQCBOR_Type,
                                           uint64_t                     uTagNumber,
                                           UsefulBufC                  *pString)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe,
                                             szLabel,
                                             QCBOR_TYPE_ANY,
                                             &Item,
                                             &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                    uTagReq,
                                    uQCBOR_Type,
                                    uTagNumber,
                                    QCBORDecode_StringsTagCB,
                                    uOffset,
                                     &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pString = Item.val.string;
   }
}




/* ========================================================================= *
 *    Byte String wrapped (which is a tag)                                   *
 * ========================================================================= */

/* This is only used by the spiffy decode function
 * QCBORDecode_Private_EnterBstrWrapped().  It is in the form of a
 * QCBORTagContentCallBack so it can be called through
 * QCBORDecode_Private_ProcessTagItem().  It is never installed as a
 * tag handler via QCBORDecode_InstallTagDecoders() and never called
 * through GetNext().  It is assmed that *(UsefulBufC *)pVBstr is
 * NULLUsefulBufC on input. This doesn't set it on error to save code.
 */
static QCBORError
QCBORDecode_EnterBstrTagCB(QCBORDecodeContext *pMe,
                           void               *pVBstr,
                           uint64_t            uTagNumber,
                           QCBORItem          *pItem)
{
   (void)uTagNumber; /* Not used, but required for QCBORTagContentCallBack */

   QCBORError uErr;

   if(pItem->uDataType != QCBOR_TYPE_BYTE_STRING) {
      return QCBOR_ERR_UNEXPECTED_TYPE;
   }

   if(DecodeNesting_IsCurrentDefiniteLength(&(pMe->nesting))) {
      /* Reverse the decrement done by GetNext() for the bstr so the
       * increment in QCBORDecode_NestLevelAscender() called by
       * ExitBoundedLevel() will work right.
       */
      DecodeNesting_ReverseDecrement(&(pMe->nesting));
   }

   if(pVBstr != NULL) {
      *(UsefulBufC *)pVBstr = pItem->val.string;
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
   if(uPreviousLength >= QCBOR_MAX_SIZE) {
      uErr = QCBOR_ERR_INPUT_TOO_LARGE;
      goto Done;
   }

   const size_t uStartOfBstr = UsefulInputBuf_PointerToOffset(&(pMe->InBuf), pItem->val.string.ptr);
   /* This check makes the cast of uStartOfBstr to uint32_t below safe. */
   if(uStartOfBstr == SIZE_MAX || uStartOfBstr > QCBOR_MAX_SIZE) {
      /* This should never happen because pItem->val.string.ptr should
       * always be valid since it was just returned.
       */
      uErr = QCBOR_ERR_INPUT_TOO_LARGE;
      goto Done;
   }

   const size_t uEndOfBstr = uStartOfBstr + pItem->val.string.len;

   UsefulInputBuf_Seek(&(pMe->InBuf), uStartOfBstr);
   UsefulInputBuf_SetBufferLength(&(pMe->InBuf), uEndOfBstr);

   uErr = DecodeNesting_DescendIntoBstrWrapped(&(pMe->nesting),
                                                (uint32_t)uPreviousLength,
                                                (uint32_t)uStartOfBstr);
Done:
   return uErr;
}


/**
 * @brief The main work of entering some byte-string wrapped CBOR.
 *
 * @param[in] pMe             The decode context.
 * @param[in] pItem           The byte string item.
 * @param[in] uTagRequirement See @ref QCBORDecodeTagReq.
 * @param[out] pBstr          Pointer and length of byte string entered.
 *
 * This is called once the byte string item has been decoded to do all
 * the book keeping work for descending a nesting level into the
 * nested CBOR.
 *
 * See QCBORDecode_EnterBstrWrapped() for details on uTagRequirement.
 */
static QCBORError
QCBORDecode_Private_EnterBstrWrapped(QCBORDecodeContext          *pMe,
                                     QCBORItem                   *pItem,
                                     const enum QCBORDecodeTagReq uTagReq,
                                     const size_t                 uOffset,
                                     UsefulBufC                  *pBstr)
{
   const uint8_t uTypes[] = {QBCOR_TYPE_WRAPPED_CBOR,
                             QBCOR_TYPE_WRAPPED_CBOR_SEQUENCE,
                             QCBOR_TYPE_NONE};
   const uint64_t uTagNumbers[] = {CBOR_TAG_CBOR,
                                   CBOR_TAG_CBOR_SEQUENCE,
                                   CBOR_TAG_INVALID64};

   if(pBstr) {
      *pBstr = NULLUsefulBufC;
   }

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return pMe->uLastError;
   }

   if(pItem->uDataAlloc) {
      return QCBOR_ERR_CANNOT_ENTER_ALLOCATED_STRING;
   }

   QCBORDecode_Private_ProcessTagItem(pMe,

                                      uTagReq,
                                      uTypes,
                                      uTagNumbers,
                                      QCBORDecode_EnterBstrTagCB,
                                      pBstr,
                                      uOffset,
                                      pItem);

   return pMe->uLastError;
}


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_EnterBstrWrapped(QCBORDecodeContext          *pMe,
                             const enum QCBORDecodeTagReq uTagReq,
                             UsefulBufC                  *pBstr)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   pMe->uLastError = (uint8_t)QCBORDecode_Private_EnterBstrWrapped(pMe,
                                                                  &Item,
                                                                   uTagReq,
                                                                   uOffset,
                                                                   pBstr);
}


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_EnterBstrWrappedFromMapN(QCBORDecodeContext          *pMe,
                                     const int64_t                nLabel,
                                     const enum QCBORDecodeTagReq uTagReq,
                                     UsefulBufC                  *pBstr)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe,
                                            nLabel,
                                            QCBOR_TYPE_BYTE_STRING,
                                           &Item,
                                            &uOffset);
   pMe->uLastError = (uint8_t)QCBORDecode_Private_EnterBstrWrapped(pMe,
                                                                  &Item,
                                                                   uTagReq,
                                                                   uOffset,
                                                                   pBstr);
}


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_EnterBstrWrappedFromMapSZ(QCBORDecodeContext          *pMe,
                                      const char                  *szLabel,
                                      const enum QCBORDecodeTagReq uTagReq,
                                      UsefulBufC                  *pBstr)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe,
                                             szLabel,
                                             QCBOR_TYPE_BYTE_STRING,
                                             &Item,
                                             &uOffset);
   pMe->uLastError = (uint8_t)QCBORDecode_Private_EnterBstrWrapped(pMe,
                                                                  &Item,
                                                                   uTagReq,
                                                                   uOffset,
                                                                   pBstr);
}


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_ExitBstrWrapped(QCBORDecodeContext *pMe)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
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




/* ========================================================================= *
 *    Spiffy decode of standard tags and tag content callbacks               *
 * ========================================================================= */
/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetTEpochDate(QCBORDecodeContext          *pMe,
                          const enum QCBORDecodeTagReq uTagRequirement,
                          int64_t                     *pnTime)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     uTagRequirement,
                                     QCBOR_TYPE_DATE_EPOCH,
                                     CBOR_TAG_DATE_EPOCH,
                                     QCBORDecode_DateEpochTagCB,
                                     uOffset,
                                     &Item);
   *pnTime = Item.val.epochDate.nSeconds;
}


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetTEpochDateInMapN(QCBORDecodeContext          *pMe,
                                int64_t                      nLabel,
                                const enum QCBORDecodeTagReq uTagRequirement,
                                int64_t                     *pnTime)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe,
                                            nLabel,
                                            QCBOR_TYPE_ANY,
                                            &Item,
                                            &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     uTagRequirement,
                                     QCBOR_TYPE_DATE_EPOCH,
                                     CBOR_TAG_DATE_EPOCH,
                                     QCBORDecode_DateEpochTagCB,
                                     uOffset,
                                     &Item);
   *pnTime = Item.val.epochDate.nSeconds;
}


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetTEpochDateInMapSZ(QCBORDecodeContext          *pMe,
                                 const char                  *szLabel,
                                 const enum QCBORDecodeTagReq uTagRequirement,
                                 int64_t                     *pnTime)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe,
                                             szLabel,
                                             QCBOR_TYPE_ANY,
                                             &Item,
                                             &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     uTagRequirement,
                                     QCBOR_TYPE_DATE_EPOCH,
                                     CBOR_TAG_DATE_EPOCH,
                                     QCBORDecode_DateEpochTagCB,
                                     uOffset,
                                     &Item);
   *pnTime = Item.val.epochDate.nSeconds;
}


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetTEpochDays(QCBORDecodeContext          *pMe,
                          const enum QCBORDecodeTagReq uTagRequirement,
                          int64_t                     *pnDays)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     uTagRequirement,
                                     QCBOR_TYPE_DAYS_EPOCH,
                                     CBOR_TAG_DAYS_EPOCH,
                                     QCBORDecode_DaysEpochTagCB,
                                     uOffset,
                                     &Item);
   *pnDays = Item.val.epochDays;
}


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetTEpochDaysInMapN(QCBORDecodeContext          *pMe,
                                int64_t                      nLabel,
                                const enum QCBORDecodeTagReq uTagRequirement,
                                int64_t                     *pnDays)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe,
                                            nLabel,
                                            QCBOR_TYPE_ANY,
                                            &Item,
                                            &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     uTagRequirement,
                                     QCBOR_TYPE_DAYS_EPOCH,
                                     CBOR_TAG_DAYS_EPOCH,
                                     QCBORDecode_DaysEpochTagCB,
                                     uOffset,
                                     &Item);
   *pnDays = Item.val.epochDays;
}


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetTEpochDaysInMapSZ(QCBORDecodeContext          *pMe,
                                 const char                  *szLabel,
                                 const enum QCBORDecodeTagReq uTagRequirement,
                                 int64_t                     *pnDays)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe,
                                             szLabel,
                                             QCBOR_TYPE_ANY,
                                             &Item,
                                             &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     uTagRequirement,
                                     QCBOR_TYPE_DAYS_EPOCH,
                                     CBOR_TAG_DAYS_EPOCH,
                                     QCBORDecode_DaysEpochTagCB,
                                     uOffset,
                                     &Item);
   *pnDays = Item.val.epochDays;
}




static void
QCBORDecode_Private_GetMIME(QCBORDecodeContext          *pMe,
                            const enum QCBORDecodeTagReq uTagRequirement,
                            QCBORItem                   *pItem,
                            UsefulBufC                  *pValue,
                            bool                        *pbIsTag257,
                            size_t                       uOffset)
{
   QCBORError uErr;

   const uint8_t puTypes[] = {QCBOR_TYPE_MIME, QCBOR_TYPE_BINARY_MIME, QCBOR_TYPE_NONE};
   const uint64_t puTNs[] =  {CBOR_TAG_MIME, CBOR_TAG_BINARY_MIME, CBOR_TAG_INVALID64};

   QCBORDecode_Private_ProcessTagItem(pMe,
                                      uTagRequirement,
                                      puTypes,
                                      puTNs,
                                      QCBORDecode_MIMETagCB,
                                      NULL,
                                      uOffset,
                                      pItem);
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

/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetTMIMEMessage(QCBORDecodeContext          *pMe,
                            const enum QCBORDecodeTagReq uTagRequirement,
                            UsefulBufC                  *pMessage,
                            bool                        *pbIsTag257)
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

/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetTMIMEMessageInMapN(QCBORDecodeContext          *pMe,
                                  const int64_t                nLabel,
                                  const enum QCBORDecodeTagReq uTagRequirement,
                                  UsefulBufC                  *pMessage,
                                  bool                        *pbIsTag257)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe,
                                            nLabel,
                                            QCBOR_TYPE_ANY,
                                            &Item,
                                            &uOffset);
   QCBORDecode_Private_GetMIME(pMe,
                               uTagRequirement,
                              &Item,
                               pMessage,
                               pbIsTag257,
                               uOffset);
}

/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetTMIMEMessageInMapSZ(QCBORDecodeContext          *pMe,
                                   const char                  *szLabel,
                                   const enum QCBORDecodeTagReq uTagRequirement,
                                   UsefulBufC                  *pMessage,
                                   bool                        *pbIsTag257)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe,
                                             szLabel,
                                             QCBOR_TYPE_ANY,
                                             &Item,
                                             &uOffset);
   QCBORDecode_Private_GetMIME(pMe,
                               uTagRequirement,
                              &Item,
                               pMessage,
                               pbIsTag257,
                               uOffset);
}




/* Public function; see qcbor_tag_decode.h */
QCBORError
QCBORDecode_DateEpochTagCB(QCBORDecodeContext *pDecodeCtx,
                           void               *pTagDecodersContext,
                           uint64_t            uTagNumber,
                           QCBORItem          *pDecodedItem)
{
   (void)pDecodeCtx;
   (void)pTagDecodersContext;
   (void)uTagNumber;

   QCBORError uReturn = QCBOR_SUCCESS;

#ifndef USEFULBUF_DISABLE_ALL_FLOAT
   pDecodedItem->val.epochDate.fSecondsFraction = 0;
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */

   switch (pDecodedItem->uDataType) {

      case QCBOR_TYPE_INT64:
         pDecodedItem->val.epochDate.nSeconds = pDecodedItem->val.int64;
         break;

      case QCBOR_TYPE_UINT64:
         /* This only happens for CBOR type 0 greater than INT64_MAX so it is
          * always an overflow.
          */
         uReturn = QCBOR_ERR_DATE_OVERFLOW;
         goto Done;
         break;

      case QCBOR_TYPE_DOUBLE:
      case QCBOR_TYPE_FLOAT:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
      {
         /* Convert working value to double if input was a float */
         const double d = pDecodedItem->uDataType == QCBOR_TYPE_DOUBLE ?
                   pDecodedItem->val.dfnum :
                   (double)pDecodedItem->val.fnum;

         /* The conversion from float to integer requires overflow
          * detection since floats can be much larger than integers.
          * This implementation errors out on these large float values
          * since they are beyond the age of the earth.
          *
          * These constants for the overflow check are computed by the
          * compiler. They are not computed at run time.
          *
          * The factor of 0x7ff is added/subtracted to avoid a
          * rounding error in the wrong direction when the compiler
          * computes these constants. There is rounding because a
          * 64-bit integer has 63 bits of precision where a double
          * only has 53 bits. Without the 0x7ff factor, the compiler
          * may round up and produce a double for the bounds check
          * that is larger than can be stored in a 64-bit integer. The
          * amount of 0x7ff is picked because it has 11 bits set.
          *
          * Without the 0x7ff there is a ~30 minute range of time
          * values 10 billion years in the past and in the future
          * where this code could go wrong. Some compilers
          * generate a warning or error without the 0x7ff. */
         const double dDateMax = (double)(INT64_MAX - 0x7ff);
         const double dDateMin = (double)(INT64_MIN + 0x7ff);

         if(isnan(d) || d > dDateMax || d < dDateMin) {
            uReturn = QCBOR_ERR_DATE_OVERFLOW;
            goto Done;
         }

         /* The actual conversion */
         pDecodedItem->val.epochDate.nSeconds = (int64_t)d;
         pDecodedItem->val.epochDate.fSecondsFraction =
                           d - (double)pDecodedItem->val.epochDate.nSeconds;
      }
#else /* ! QCBOR_DISABLE_FLOAT_HW_USE */

         uReturn = FLOAT_ERR_CODE_NO_FLOAT_HW(QCBOR_SUCCESS);
         goto Done;

#endif /* ! QCBOR_DISABLE_FLOAT_HW_USE */
         break;

      default:
         /* It's the arrays and maps that are unrecoverable because
          * they are not consumed here. Since this is just an error
          * condition, no extra code is added here to make the error
          * recoverable for non-arrays and maps like strings. */
         uReturn = QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT;
         goto Done;
   }

   pDecodedItem->uDataType = QCBOR_TYPE_DATE_EPOCH;

Done:
   return uReturn;
}


/* Public function; see qcbor_tag_decode.h */
QCBORError
QCBORDecode_DaysEpochTagCB(QCBORDecodeContext *pDecodeCtx,
                           void               *pTagDecodersContext,
                           uint64_t            uTagNumber,
                           QCBORItem          *pDecodedItem)
{
   (void)pDecodeCtx;
   (void)pTagDecodersContext;
   (void)uTagNumber;

   QCBORError uReturn;

   switch (pDecodedItem->uDataType) {

      case QCBOR_TYPE_INT64:
         pDecodedItem->val.epochDays = pDecodedItem->val.int64;
         pDecodedItem->uDataType     = QCBOR_TYPE_DAYS_EPOCH;
         uReturn                     = QCBOR_SUCCESS;
         break;

      case QCBOR_TYPE_UINT64:
         /* This only happens for CBOR type 0 > INT64_MAX so it is
          * always an overflow. */
         pDecodedItem->uDataType = QCBOR_TYPE_NONE;
         uReturn                 = QCBOR_ERR_DATE_OVERFLOW;
         break;

      default:
         /* It's the arrays and maps that are unrecoverable because
          * they are not consumed here. Since this is just an error
          * condition, no extra code is added here to make the error
          * recoverable for non-arrays and maps like strings. */
         pDecodedItem->uDataType = QCBOR_TYPE_NONE;
         uReturn                 = QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT;
         break;
   }

   return uReturn;
}


#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA

/**
 * @brief Figures out QCBOR data type for exponent and mantissa tags.
 *
 * @param[in] uTagToProcess  Either @ref CBOR_TAG_DECIMAL_FRACTION or
 *                           @ref CBOR_TAG_BIG_FLOAT.
 * @param[in] pDecodedItem   Item being decoded.
 *
 * @returns One of the ten values related to @ref QCBOR_TYPE_DECIMAL_FRACTION
 *          and @ref QCBOR_TYPE_BIGFLOAT
 *
 * Does mapping between a CBOR tag number and a QCBOR type with a
 * little logic and arithmetic.
 */
static uint8_t
QCBOR_Private_ExpMantissaDataType(const uint64_t   uTagToProcess,
                                  const QCBORItem *pDecodedItem)
{
   uint8_t uBase = uTagToProcess == CBOR_TAG_DECIMAL_FRACTION ?
                                       QCBOR_TYPE_DECIMAL_FRACTION :
                                       QCBOR_TYPE_BIGFLOAT;

   switch(pDecodedItem->uDataType) {
      case QCBOR_TYPE_INT64:
         return uBase;

      case QCBOR_TYPE_UINT64:
         return uBase + (QCBOR_TYPE_DECIMAL_FRACTION_POS_U64 - QCBOR_TYPE_DECIMAL_FRACTION);

      case QCBOR_TYPE_65BIT_NEG_INT:
         return uBase + (QCBOR_TYPE_DECIMAL_FRACTION_NEG_U64 - QCBOR_TYPE_DECIMAL_FRACTION);

      default:
         return (uint8_t)(uBase + pDecodedItem->uDataType - QCBOR_TYPE_POSBIGNUM + 1);
   }
}


/* Public function; see qcbor_tag_decode.h */
QCBORError
QCBORDecode_ExpMantissaTagCB(QCBORDecodeContext *pDecodeCtx,
                             void               *pTagDecodersContext,
                             uint64_t            uTagNumber,
                             QCBORItem          *pDecodedItem)
{
   (void)pTagDecodersContext;

   QCBORError uReturn;
   QCBORItem  ExponentItem;
   QCBORItem  MantissaItem;

   /* --- Make sure it is an array; track nesting level of members --- */
   if(pDecodedItem->uDataType != QCBOR_TYPE_ARRAY) {
      uReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }

   /* A check for pDecodedItem->val.uCount == 2 would work for
    * definite-length arrays, but not for indefinite. Instead remember
    * the nesting level the two integers must be at, which is one
    * deeper than that of the array. */
   const uint8_t uNestLevel = pDecodedItem->uNestingLevel + 1;

   /* --- Get the exponent --- */
   uReturn = QCBORDecode_GetNext(pDecodeCtx, &ExponentItem);
   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }
   if(ExponentItem.uNestingLevel != uNestLevel) {
      /* Array is empty or a map/array encountered when expecting an int */
      uReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }
   if(ExponentItem.uDataType == QCBOR_TYPE_INT64) {
     /* Data arriving as an unsigned int < INT64_MAX has been
      * converted to QCBOR_TYPE_INT64 and thus handled here. This is
      * also means that the only data arriving here of type
      * QCBOR_TYPE_UINT64 data will be too large for this to handle
      * and thus an error that will get handled in the next else.*/
     pDecodedItem->val.expAndMantissa.nExponent = ExponentItem.val.int64;
   } else {
      /* Wrong type of exponent or a QCBOR_TYPE_UINT64 > INT64_MAX */
      uReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }

   /* --- Get the mantissa --- */
   uReturn = QCBORDecode_GetNext(pDecodeCtx, &MantissaItem);
   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }
   if(MantissaItem.uNestingLevel != uNestLevel) {
      /* Mantissa missing or map/array encountered when expecting number */
      uReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }
   /* Stuff the mantissa data type into the item to send it up to the
    * the next level. */
   if(MantissaItem.uDataType == QCBOR_TYPE_INT64) {
      /* Data arriving as an unsigned int < INT64_MAX has been
       * converted to QCBOR_TYPE_INT64 and thus handled here. This is
       * also means that the only data arriving here of type
       * QCBOR_TYPE_UINT64 data will be too large for this to handle
       * and thus an error that will get handled in an else below. */
      pDecodedItem->val.expAndMantissa.Mantissa.nInt = MantissaItem.val.int64;
#ifndef QCBOR_DISABLE_TAGS
      /* With tags fully disabled a big number mantissa will error out
       * in the call to QCBORDecode_GetNextWithTags() because it has
       * a tag number. */
   }  else if(MantissaItem.uDataType == QCBOR_TYPE_POSBIGNUM ||
              MantissaItem.uDataType == QCBOR_TYPE_NEGBIGNUM) {
      /* Got a good big num mantissa */
      pDecodedItem->val.expAndMantissa.Mantissa.bigNum = MantissaItem.val.bigNum;
#endif /* ! QCBOR_DISABLE_TAGS */
   } else if(MantissaItem.uDataType == QCBOR_TYPE_UINT64) {
      pDecodedItem->val.expAndMantissa.Mantissa.uInt = MantissaItem.val.uint64;
   } else if(MantissaItem.uDataType == QCBOR_TYPE_65BIT_NEG_INT) {
      pDecodedItem->val.expAndMantissa.Mantissa.uInt = MantissaItem.val.uint64;
   } else {
      /* Wrong type of mantissa */
      uReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }

   /* --- Check that array only has the two numbers --- */
   if(MantissaItem.uNextNestLevel == uNestLevel) {
      /* Extra items in the decimal fraction / big float */
      /* Improvement: this should probably be an unrecoverable error. */
      uReturn = QCBOR_ERR_BAD_EXP_AND_MANTISSA;
      goto Done;
   }

   pDecodedItem->uNextNestLevel = MantissaItem.uNextNestLevel;
   pDecodedItem->uDataType      = QCBOR_Private_ExpMantissaDataType(uTagNumber, &MantissaItem);

Done:
  return uReturn;
}
#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */


/* Public function; see qcbor_tag_decode.h */
QCBORError
QCBORDecode_MIMETagCB(QCBORDecodeContext *pDecodeCtx,
                      void               *pTagDecodersContext,
                      uint64_t            uTagNumber,
                      QCBORItem          *pDecodedItem)
{
   (void)pDecodeCtx;
   (void)pTagDecodersContext;
   (void)uTagNumber;

   if(pDecodedItem->uDataType == QCBOR_TYPE_TEXT_STRING) {
      pDecodedItem->uDataType = QCBOR_TYPE_MIME;
   } else if(pDecodedItem->uDataType == QCBOR_TYPE_BYTE_STRING) {
      pDecodedItem->uDataType = QCBOR_TYPE_BINARY_MIME;
   } else {
      /* It's the arrays and maps that are unrecoverable because
       * they are not consumed here. Since this is just an error
       * condition, no extra code is added here to make the error
       * recoverable for non-arrays and maps like strings. */
      return QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT;
   }

   return QCBOR_SUCCESS;
}


/* Table of CBOR tags whose content is either a text string or a byte
 * string. The table maps the CBOR tag to the QCBOR type. The high-bit
 * of uQCBORtype indicates the content should be a byte string rather
 * than a text string. */
struct StringTagMapEntry {
   uint16_t uTagNumber;
   uint8_t  uQCBORtype;
};

#define IS_BYTE_STRING_BIT 0x80
#define QCBOR_TYPE_MASK   ~IS_BYTE_STRING_BIT

static const struct StringTagMapEntry QCBOR_Private_StringTagMap[] = {
   {CBOR_TAG_DATE_STRING,   QCBOR_TYPE_DATE_STRING},
   {CBOR_TAG_DAYS_STRING,   QCBOR_TYPE_DAYS_STRING},
   {CBOR_TAG_POS_BIGNUM,    QCBOR_TYPE_POSBIGNUM    | IS_BYTE_STRING_BIT},
   {CBOR_TAG_NEG_BIGNUM,    QCBOR_TYPE_NEGBIGNUM    | IS_BYTE_STRING_BIT},
   {CBOR_TAG_CBOR,          QBCOR_TYPE_WRAPPED_CBOR | IS_BYTE_STRING_BIT},
   {CBOR_TAG_URI,           QCBOR_TYPE_URI},
   {CBOR_TAG_B64URL,        QCBOR_TYPE_BASE64URL},
   {CBOR_TAG_B64,           QCBOR_TYPE_BASE64},
   {CBOR_TAG_REGEX,         QCBOR_TYPE_REGEX},
   {CBOR_TAG_BIN_UUID,      QCBOR_TYPE_UUID                  | IS_BYTE_STRING_BIT},
   {CBOR_TAG_CBOR_SEQUENCE, QBCOR_TYPE_WRAPPED_CBOR_SEQUENCE | IS_BYTE_STRING_BIT},
   {CBOR_TAG_INVALID16,     QCBOR_TYPE_NONE}
};

/* Public function; see qcbor_tag_decode.h */
QCBORError
QCBORDecode_StringsTagCB(QCBORDecodeContext *pDecodeCtx,
                         void               *pTagDecodersContext,
                         uint64_t            uTagNumber,
                         QCBORItem          *pDecodedItem)
{
   (void)pDecodeCtx;
   (void)pTagDecodersContext;

   int uIndex;
   for(uIndex = 0; QCBOR_Private_StringTagMap[uIndex].uTagNumber != CBOR_TAG_INVALID16; uIndex++) {
      if(QCBOR_Private_StringTagMap[uIndex].uTagNumber == uTagNumber) {
         break;
      }
   }

   const uint8_t uQCBORType = QCBOR_Private_StringTagMap[uIndex].uQCBORtype;
   if(uQCBORType == QCBOR_TYPE_NONE) {
      /* repurpose this error to mean not handled here */
      return QCBOR_ERR_UNSUPPORTED;
   }

   uint8_t uExpectedType = QCBOR_TYPE_TEXT_STRING;
   if(uQCBORType & IS_BYTE_STRING_BIT) {
      uExpectedType = QCBOR_TYPE_BYTE_STRING;
   }

   if(pDecodedItem->uDataType != uExpectedType) {
      /* It's the arrays and maps that are unrecoverable because
       * they are not consumed here. Since this is just an error
       * condition, no extra code is added here to make the error
       * recoverable for non-arrays and maps like strings. */
      return QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT;
   }

   pDecodedItem->uDataType = (uint8_t)(uQCBORType & QCBOR_TYPE_MASK);
   return QCBOR_SUCCESS;
}




#ifndef QCBOR_DISABLE_TAGS

/* Public data structure; see qcbor_tag_decode.h */
const struct QCBORTagDecoderEntry QCBORDecode_TagDecoderTablev1[] = {
   {CBOR_TAG_DATE_STRING,      QCBORDecode_StringsTagCB},
   {CBOR_TAG_DATE_EPOCH,       QCBORDecode_DateEpochTagCB},
   {CBOR_TAG_DAYS_STRING,      QCBORDecode_StringsTagCB},
   {CBOR_TAG_POS_BIGNUM,       QCBORDecode_StringsTagCB},
   {CBOR_TAG_NEG_BIGNUM,       QCBORDecode_StringsTagCB},
   {CBOR_TAG_CBOR,             QCBORDecode_StringsTagCB},
   {CBOR_TAG_URI,              QCBORDecode_StringsTagCB},
   {CBOR_TAG_B64URL,           QCBORDecode_StringsTagCB},
   {CBOR_TAG_B64,              QCBORDecode_StringsTagCB},
   {CBOR_TAG_REGEX,            QCBORDecode_StringsTagCB},
   {CBOR_TAG_BIN_UUID,         QCBORDecode_StringsTagCB},
   {CBOR_TAG_CBOR_SEQUENCE,    QCBORDecode_StringsTagCB},
   {CBOR_TAG_MIME,             QCBORDecode_MIMETagCB},
   {CBOR_TAG_BINARY_MIME,      QCBORDecode_MIMETagCB},
#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
   {CBOR_TAG_BIGFLOAT,         QCBORDecode_ExpMantissaTagCB},
   {CBOR_TAG_DECIMAL_FRACTION, QCBORDecode_ExpMantissaTagCB},
#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */
   {CBOR_TAG_DAYS_EPOCH,       QCBORDecode_DaysEpochTagCB},
   {CBOR_TAG_INVALID64,        NULL},
};

#endif /* ! QCBOR_DISABLE_TAGS */
