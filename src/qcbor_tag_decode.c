/* ==========================================================================
 * qcbor_tag_decode.c -- Tag content decoders
 *
 * Copyright (c) 2024, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created on 9/5/24 from qcbode_decode.c
 * ========================================================================== */

#include "qcbor/qcbor_tag_decode.h"
#include "decode_private.h"

#include <math.h> /* For isnan() */



#ifndef QCBOR_DISABLE_TAGS

/* Public function; see qcbor_tag_decode.h */
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


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_VGetNextTagNumber(QCBORDecodeContext *pMe, uint64_t *puTagNumber)
{
   pMe->uLastError = (uint8_t)QCBORDecode_GetNextTagNumber(pMe, puTagNumber);
}

/*
 * Public function, see header qcbor/qcbor_tag_decode.h file
 */
QCBORError
QCBORDecode_GetNextTagNumberInMapN(QCBORDecodeContext *pMe, const int64_t nLabel, uint64_t *puTagNumber)
{
   size_t         uOffset;
   MapSearchInfo  Info;
   QCBORItem      OneItemSeach[2];
   QCBORError     uReturn;

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return pMe->uLastError;
   }

   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = QCBOR_TYPE_ANY;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE; // Indicates end of array

   uReturn = QCBORDecode_Private_MapSearch(pMe, OneItemSeach, &Info, NULL);

   uOffset = Info.uStartOffset;
   if(uOffset == pMe->uTagNumberCheckOffset) {
      pMe->uTagNumberIndex++;
   } else {
      pMe->uTagNumberIndex = 0;
   }

   *puTagNumber = CBOR_TAG_INVALID64;

   *puTagNumber = QCBORDecode_GetNthTagNumber(pMe,
                                              &OneItemSeach[0],
                                              pMe->uTagNumberIndex);
   if(*puTagNumber == CBOR_TAG_INVALID64 ||
      QCBORDecode_GetNthTagNumber(pMe, &OneItemSeach[0], pMe->uTagNumberIndex+1) == CBOR_TAG_INVALID64 ) {
      pMe->uTagNumberIndex = QCBOR_ALL_TAGS_PROCESSED;
   }
   pMe->uTagNumberCheckOffset = uOffset;

   return uReturn;
}


/* Public function; see qcbor_tag_decode.h */
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

   *puTagNumber = QCBORDecode_GetNthTagNumber(pMe,
                                              &OneItemSeach[0],
                                              pMe->uTagNumberIndex);
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


/* Public function; see qcbor_tag_decode.h */
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


/* Public function; see qcbor_tag_decode.h */
uint64_t
QCBORDecode_GetNthTagNumberOfLast(QCBORDecodeContext *pMe, uint8_t uIndex)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return CBOR_TAG_INVALID64;
   }
   if(uIndex >= QCBOR_MAX_TAGS_PER_ITEM) {
      return CBOR_TAG_INVALID64;
   }

   return QCBORDecode_Private_UnMapTagNumber(pMe, pMe->auLastTags[uIndex]);
}


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
                                                     pMe->auLastTags,
                                                     uIndex);
}



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

   if(uInnerTag == uTagNumber && pItem->auTagNumbers[1] == CBOR_TAG_INVALID16) {
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
   const uint64_t *pQType;
   const uint64_t *pTNum;
   const uint8_t  *pTypeNum;

   const int nTagReq = uTagRequirement & ~QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS;

   *bTypeMatched = false;
   for(pTypeNum = uQCBORTypes; *pTypeNum != QCBOR_TYPE_NONE; pTypeNum++) {
      if(pItem->uDataType == *pTypeNum) {
         *bTypeMatched = true;
         break;
      }
   }

#ifndef QCBOR_DISABLE_TAGS
   bool        bTagNumberMatched;
   QCBORError  uErr;
   const uint64_t uInnerTag = QCBORDecode_GetNthTagNumber(pMe, pItem, 0);

   bTagNumberMatched = false;
   for(pQType = uTagNumbers; *pQType != CBOR_TAG_INVALID64; pQType++) {
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
      for(pTNum = uTagNumbers; *pTNum != CBOR_TAG_INVALID64; pTNum++) {
         uErr = QCBORDecode_Private_Check1TagNumber(pMe, pItem, *pTNum, uOffset);
         if(uErr != QCBOR_SUCCESS) {
            return uErr;
         }
      }
   }

   return QCBOR_SUCCESS;
#else /* ! QCBOR_DISABLE_TAGS */
   (void)pMe;
   (void)uOffset;
   (void)uTagNumbers;

   if(nTagReq != QCBOR_TAG_REQUIREMENT_TAG && bTypeMatched) {
      return QCBOR_SUCCESS;
   } else {
      return QCBOR_ERR_UNEXPECTED_TYPE;
   }

#endif /* ! QCBOR_DISABLE_TAGS */

}


void
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
void
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
QCBORDecode_Private_ProcessTagOne(QCBORDecodeContext      *pMe,
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

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe,
                                            nLabel,
                                            QCBOR_TYPE_ANY,
                                            &Item,
                                            &uOffset);
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

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe,
                                             szLabel,
                                             QCBOR_TYPE_ANY,
                                             &Item,
                                             &uOffset);
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

   uError = QCBORDecode_Private_CheckTagNType(pMe,
                                              pItem,
                                              uOffset,
                                              uTypes,//TODO: maybe empty?
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


/* Public function; see qcbor_tag_decode.h */
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


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_EnterBstrWrappedFromMapN(QCBORDecodeContext *pMe,
                                     const int64_t       nLabel,
                                     const uint8_t       uTagRequirement,
                                     UsefulBufC         *pBstr)
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
                                                                   uTagRequirement,
                                                                   uOffset,
                                                                   pBstr);
}


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_EnterBstrWrappedFromMapSZ(QCBORDecodeContext *pMe,
                                      const char         *szLabel,
                                      const uint8_t       uTagRequirement,
                                      UsefulBufC         *pBstr)
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
                                                                   uTagRequirement,
                                                                   uOffset,
                                                                   pBstr);
}


/* Public function; see qcbor_tag_decode.h */
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




/* Public function; see qcbor_tag_decode.h */
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


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetEpochDateInMapN(QCBORDecodeContext *pMe,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnTime)
{
   QCBORItem Item;
   size_t uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe,
                                            nLabel,
                                            QCBOR_TYPE_ANY,
                                            &Item,
                                            &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     &Item,
                                     uTagRequirement,
                                     QCBOR_TYPE_DATE_EPOCH,
                                     CBOR_TAG_DATE_EPOCH,
                                     QCBORDecode_DateEpochTagCB,
                                     uOffset);
   *pnTime = Item.val.epochDate.nSeconds;
}


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetEpochDateInMapSZ(QCBORDecodeContext *pMe,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                int64_t            *pnTime)
{
   QCBORItem Item;
   size_t uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe,
                                             szLabel,
                                             QCBOR_TYPE_ANY,
                                             &Item,
                                             &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     &Item,
                                     uTagRequirement,
                                     QCBOR_TYPE_DATE_EPOCH,
                                     CBOR_TAG_DATE_EPOCH,
                                     QCBORDecode_DateEpochTagCB,
                                     uOffset);
   *pnTime = Item.val.epochDate.nSeconds;
}


/* Public function; see qcbor_tag_decode.h */
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


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetEpochDaysInMapN(QCBORDecodeContext *pMe,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnDays)
{
   QCBORItem Item;
   size_t uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe,
                                            nLabel,
                                            QCBOR_TYPE_ANY,
                                            &Item,
                                            &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                     &Item,
                                     uTagRequirement,
                                     QCBOR_TYPE_DAYS_EPOCH,
                                     CBOR_TAG_DAYS_EPOCH,
                                     QCBORDecode_DaysEpochTagCB,
                                     uOffset);
   *pnDays = Item.val.epochDays;
}


/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetEpochDaysInMapSZ(QCBORDecodeContext *pMe,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                int64_t            *pnDays)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe,
                                             szLabel,
                                             QCBOR_TYPE_ANY,
                                             &Item,
                                             &uOffset);
   QCBORDecode_Private_ProcessTagOne(pMe,
                                      &Item,
                                      uTagRequirement,
                                      QCBOR_TYPE_DAYS_EPOCH,
                                      CBOR_TAG_DAYS_EPOCH,
                                      QCBORDecode_DaysEpochTagCB,
                                      uOffset);
   *pnDays = Item.val.epochDays;
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

/* Public function; see qcbor_tag_decode.h */
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

/* Public function; see qcbor_tag_decode.h */
void
QCBORDecode_GetMIMEMessageInMapN(QCBORDecodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uTagRequirement,
                                 UsefulBufC         *pMessage,
                                 bool               *pbIsTag257)
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
QCBORDecode_GetMIMEMessageInMapSZ(QCBORDecodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uTagRequirement,
                                  UsefulBufC         *pMessage,
                                  bool               *pbIsTag257)
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
         /* This only happens for CBOR type 0 > INT64_MAX so it is
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

         uReturn = QCBOR_ERR_HW_FLOAT_DISABLED;
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
