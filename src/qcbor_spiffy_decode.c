/* ==========================================================================
 * qcbor_spiffy_decode.c -- "Spiffy" QCBOR decoding
 *
 * Copyright (c) 2016-2018, The Linux Foundation.
 * Copyright (c) 2018-2025, Laurence Lundblade.
 * Copyright (c) 2021, Arm Limited.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Forked from qcbor_decode.c on 11/28/24
 * ========================================================================== */

#include "qcbor/qcbor_main_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "decode_nesting.h"



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


/**
 * @brief Spiffy decode get a byte string.
 *
 * @param[in] pMe       The decode context.
 * @param[in] uType     The CBOR qcbor type requested.
 * @param[out] pString  The returned string.
 *
 * This sets the spiffy decode last error if there is a problem
 * deocing or the string is not of the requested type.
 */
void
QCBORDecode_Private_GetString(QCBORDecodeContext *pMe, const uint8_t uType, UsefulBufC *pString)
{
   QCBORItem  Item;

   QCBORDecode_VGetNext(pMe, &Item);

   *pString = NULLUsefulBufC;
   if(pMe->uLastError == QCBOR_SUCCESS) {
      if(Item.uDataType == uType) {
         *pString = Item.val.string;
      } else {
         pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
      }
   }
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


/* Public function, see qcbor/qcbor_spiffy_decode.h */
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
QCBORError
QCBORDecode_Private_MapSearch(QCBORDecodeContext *pMe,
                              QCBORItem          *pItemArray,
                              MapSearchInfo      *pInfo,
                              MapSearchCallBack  *pCallBack)
{
   QCBORError uReturn;
   uint64_t   uFoundItemBitMap;
   uint8_t    uNextNestLevel;

   if(pInfo != NULL) {
      pInfo->uItemCount   = 0;
      pInfo->uStartOffset = UINT32_MAX;
   }

   uFoundItemBitMap = 0;

   if(pMe->uLastError != QCBOR_SUCCESS) {
      uReturn = pMe->uLastError;
      goto Done2;
   }

   if(!DecodeNesting_IsBoundedType(&(pMe->nesting), QCBOR_TYPE_MAP) &&
      pItemArray->uLabelType != QCBOR_TYPE_NONE) {
      /* QCBOR_TYPE_NONE as first item indicates just looking for the
       * end of an array, so don't give error. */
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
         /* Nothing is ever found in an empty array or map. All items
          * are marked as not found below. */
         uReturn = QCBOR_SUCCESS;
      }
      goto Done2;
   }

   QCBORDecodeNesting SaveNesting;
   size_t uSavePos = UsefulInputBuf_Tell(&(pMe->InBuf));
   DecodeNesting_PrepareForMapSearch(&(pMe->nesting), &SaveNesting);

   /* Reposition to search from the start of the map / array */
   QCBORDecode_Private_RewindMapOrArray(pMe);

   /* Loop over all the items in the map or array. Each item could be
    * a map or array, but label matching is only at the main
    * level. This handles definite- and indefinite- length maps and
    * arrays. The only reason this is ever called on arrays is to find
    * their end position.
    *
    * This will always run over all items in order to do duplicate
    * detection.
    *
    * This will exit with failure if it encounters an unrecoverable
    * error, but continue on for recoverable errors.
    *
    * If a recoverable error occurs on a matched item, then that error
    * code is returned.
    */
   const uint8_t uMapNestLevel = DecodeNesting_GetBoundedModeLevel(&(pMe->nesting));
   do {
      QCBORItem   Item;
      bool        bMatched;
      QCBORError  uResult;

      /* Remember offset of the item because sometimes it has to be returned */
      const size_t uOffset = UsefulInputBuf_Tell(&(pMe->InBuf));

      /* Get the item */
      /* QCBORDecode_Private_GetNextTagContent() rather than GetNext()
       * because a label match is performed on recoverable errors to
       * be able to return the the error code for the found item. */
      uResult = QCBORDecode_Private_GetNextTagContent(pMe, &Item);
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
      bMatched = false;
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
            if(pInfo != NULL) {
               pInfo->uStartOffset = uOffset;
            }
            bMatched = true;
         }
      }


      if(!bMatched && pCallBack != NULL) {
         /* Call the callback on unmatched labels.
          * (It is tempting to do duplicate detection here, but that
          * would require dynamic memory allocation because the number
          * of labels that might be encountered is unbounded.) */
         uReturn = (*(pCallBack->pfCallback))(pCallBack->pCBContext, &Item);
         if(uReturn != QCBOR_SUCCESS) {
            goto Done;
         }
      }

      /* Consume the item whether matched or not. This does the work
       * of traversing maps and array and everything in them. In this
       * loop only the items at the current nesting level are examined
       * to match the labels. */
      uReturn = QCBORDecode_Private_ConsumeItem(pMe, &Item, NULL, &uNextNestLevel);
      if(uReturn != QCBOR_SUCCESS) {
         goto Done;
      }

      if(pInfo != NULL) {
         pInfo->uItemCount++;
      }

   } while (uNextNestLevel >= uMapNestLevel);

   uReturn = QCBOR_SUCCESS;

   const size_t uEndOffset = UsefulInputBuf_Tell(&(pMe->InBuf));

   /* Check here makes sure that this won't accidentally be
    * QCBOR_MAP_OFFSET_CACHE_INVALID which is larger than
    * QCBOR_MAX_DECODE_INPUT_SIZE.  Cast to uint32_t to possibly
    * address cases where SIZE_MAX < UINT32_MAX. It is near-impossible
    * to test this, so test coverage of this function is not 100%,
    * but it is 100% when this is commented out. */
   if((uint32_t)uEndOffset >= QCBOR_MAX_SIZE) {
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


/* Public function, see qcbor/qcbor_spiffy_decode.h */
void
QCBORDecode_SeekToLabelN(QCBORDecodeContext *pMe, int64_t nLabel)
{
   MapSearchInfo Info;
   QCBORItem     OneItemSearch[2];

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   OneItemSearch[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSearch[0].label.int64 = nLabel;
   OneItemSearch[0].uDataType   = QCBOR_TYPE_ANY;
   OneItemSearch[1].uLabelType  = QCBOR_TYPE_NONE; // Indicates end of array

   pMe->uLastError = (uint8_t)QCBORDecode_Private_MapSearch(pMe, OneItemSearch, &Info, NULL);
   if(pMe->uLastError == QCBOR_SUCCESS) {
      UsefulInputBuf_Seek(&(pMe->InBuf), Info.uStartOffset);
   }
}


void
QCBORDecode_SeekToLabelSZ(QCBORDecodeContext *pMe, const char *szLabel)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   MapSearchInfo  Info;
   QCBORItem      OneItemSearch[2];

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   OneItemSearch[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSearch[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSearch[0].uDataType    = QCBOR_TYPE_ANY;
   OneItemSearch[1].uLabelType   = QCBOR_TYPE_NONE; // Indicates end of array

   pMe->uLastError = (uint8_t)QCBORDecode_Private_MapSearch(pMe, OneItemSearch, &Info, NULL);
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
                                        QCBORItem          *OneItemSearch,
                                        QCBORItem          *pItem,
                                        size_t             *puOffset)
{
   QCBORError    uErr;
   MapSearchInfo SearchInfo;

   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   uErr = QCBORDecode_Private_MapSearch(pMe, OneItemSearch, &SearchInfo, NULL);

   if(uErr == QCBOR_SUCCESS && OneItemSearch[0].uDataType == QCBOR_TYPE_NONE) {
      uErr = QCBOR_ERR_LABEL_NOT_FOUND;
   }
   *pItem = OneItemSearch[0];
   *puOffset = SearchInfo.uStartOffset;

   if(uErr == QCBOR_SUCCESS) {
      QCBORDecode_Private_SaveTagNumbers(pMe, pItem);
   }

   pMe->uLastError = (uint8_t)uErr;
}


static void
QCBORDecode_Private_GetItemInMap(QCBORDecodeContext *pMe, QCBORItem *OneItemSearch, QCBORItem *pItem)
{
   QCBORError  uErr;
   size_t      uOffset;

   QCBORDecode_Private_GetItemInMapNoCheck(pMe, OneItemSearch, pItem, &uOffset);

   uErr = QCBORDecode_Private_GetItemChecks(pMe, pMe->uLastError, uOffset, pItem);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   QCBORDecode_Private_SaveTagNumbers(pMe, pItem);

Done:
   pMe->uLastError = (uint8_t)uErr;
}


/* Public function, see qcbor/qcbor_spiffy_decode.h */
void
QCBORDecode_GetItemInMapN(QCBORDecodeContext *pMe,
                          const int64_t       nLabel,
                          const uint8_t       uQcborType,
                          QCBORItem          *pItem)
{
   QCBORItem OneItemSearch[2];

   OneItemSearch[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSearch[0].label.int64 = nLabel;
   OneItemSearch[0].uDataType   = uQcborType;
   OneItemSearch[1].uLabelType  = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORDecode_Private_GetItemInMap(pMe, OneItemSearch, pItem);
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
void
QCBORDecode_Private_GetItemInMapNoCheckN(QCBORDecodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uQcborType,
                                 QCBORItem          *pItem,
                                 size_t             *puOffset)
{
   QCBORItem OneItemSearch[2];

   OneItemSearch[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSearch[0].label.int64 = nLabel;
   OneItemSearch[0].uDataType   = uQcborType;
   OneItemSearch[1].uLabelType  = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORDecode_Private_GetItemInMapNoCheck(pMe, OneItemSearch,  pItem, puOffset);
}


/* Public function, see qcbor/qcbor_spiffy_decode.h */
void
QCBORDecode_GetItemInMapSZ(QCBORDecodeContext *pMe,
                           const char         *szLabel,
                           const uint8_t       uQcborType,
                           QCBORItem          *pItem)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   QCBORItem OneItemSearch[2];

   OneItemSearch[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSearch[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSearch[0].uDataType    = uQcborType;
   OneItemSearch[1].uLabelType   = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORDecode_Private_GetItemInMap(pMe, OneItemSearch, pItem);

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
void
QCBORDecode_Private_GetItemInMapNoCheckSZ(QCBORDecodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uQcborType,
                                  QCBORItem          *pItem,
                                  size_t             *puOffset)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   QCBORItem OneItemSearch[2];

   OneItemSearch[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSearch[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSearch[0].uDataType    = uQcborType;
   OneItemSearch[1].uLabelType   = QCBOR_TYPE_NONE; // Indicates end of array

   QCBORDecode_Private_GetItemInMapNoCheck(pMe, OneItemSearch, pItem, puOffset);

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
 */
void
QCBORDecode_Private_SearchAndGetArrayOrMap(QCBORDecodeContext *pMe,
                                           QCBORItem          *pTarget,
                                           QCBORItem          *pItem,
                                           UsefulBufC         *pEncodedCBOR)
{
   /* Heavy stack use, but it's only for a few QCBOR public methods */
   MapSearchInfo      Info;
   QCBORDecodeNesting SaveNesting;
   size_t             uSaveCursor;

   /* Find the array or map of interest */
   pMe->uLastError = (uint8_t)QCBORDecode_Private_MapSearch(pMe, pTarget, &Info, NULL);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   if(pTarget->uDataType == QCBOR_TYPE_NONE) {
      pMe->uLastError = QCBOR_ERR_LABEL_NOT_FOUND;
      return;
   }

   pMe->uLastError = (uint8_t)QCBORDecode_Private_GetItemChecks(pMe, pMe->uLastError, Info.uStartOffset, pItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }

   /* Save the traversal cursor and related */
   DecodeNesting_PrepareForMapSearch(&(pMe->nesting), &SaveNesting);
   uSaveCursor = UsefulInputBuf_Tell(&(pMe->InBuf));

   /* Get the array or map of interest */
   DecodeNesting_ResetMapOrArrayCount(&(pMe->nesting));
   UsefulInputBuf_Seek(&(pMe->InBuf), Info.uStartOffset);
   QCBORDecode_Private_GetArrayOrMap(pMe, pTarget[0].uDataType, pItem, pEncodedCBOR);

   /* Restore the traversal cursor */
   UsefulInputBuf_Seek(&(pMe->InBuf), uSaveCursor);
   DecodeNesting_RestoreFromMapSearch(&(pMe->nesting), &SaveNesting);
}




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


/* Public function, see qcbor/qcbor_spiffy_decode.h */
void
QCBORDecode_EnterMapFromMapN(QCBORDecodeContext *pMe, int64_t nLabel)
{
   QCBORItem OneItemSearch[2];
   OneItemSearch[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSearch[0].label.int64 = nLabel;
   OneItemSearch[0].uDataType   = QCBOR_TYPE_MAP;
   OneItemSearch[1].uLabelType  = QCBOR_TYPE_NONE;

   /* The map to enter was found, now finish off entering it. */
   QCBORDecode_Private_SearchAndEnter(pMe, OneItemSearch);
}


/* Public function, see qcbor/qcbor_spiffy_decode.h */
void
QCBORDecode_EnterMapFromMapSZ(QCBORDecodeContext *pMe, const char  *szLabel)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   QCBORItem OneItemSearch[2];
   OneItemSearch[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSearch[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSearch[0].uDataType    = QCBOR_TYPE_MAP;
   OneItemSearch[1].uLabelType   = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndEnter(pMe, OneItemSearch);
#else
   (void)szLabel;
   pMe->uLastError = QCBOR_ERR_LABEL_NOT_FOUND;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
}

/* Public function, see qcbor/qcbor_spiffy_decode.h */
void
QCBORDecode_EnterArrayFromMapN(QCBORDecodeContext *pMe, int64_t nLabel)
{
   QCBORItem OneItemSearch[2];
   OneItemSearch[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSearch[0].label.int64 = nLabel;
   OneItemSearch[0].uDataType   = QCBOR_TYPE_ARRAY;
   OneItemSearch[1].uLabelType  = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndEnter(pMe, OneItemSearch);
}

/* Public function, see qcbor/qcbor_spiffy_decode.h */
void
QCBORDecode_EnterArrayFromMapSZ(QCBORDecodeContext *pMe, const char  *szLabel)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   QCBORItem OneItemSearch[2];
   OneItemSearch[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSearch[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSearch[0].uDataType    = QCBOR_TYPE_ARRAY;
   OneItemSearch[1].uLabelType   = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndEnter(pMe, OneItemSearch);
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
QCBORError
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
   uErr = QCBORDecode_Private_NestLevelAscender(pMe, false, NULL);
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


/* Public function, see qcbor/qcbor_spiffy_decode.h */
void
QCBORDecode_GetBool(QCBORDecodeContext *pMe, bool *pValue)
{
   QCBORItem  Item;
   QCBORDecode_VGetNext(pMe, &Item);
   QCBORDecode_Private_ProcessBool(pMe, &Item, pValue);
}


/* Public function, see qcbor/qcbor_spiffy_decode.h */
void
QCBORDecode_GetBoolInMapN(QCBORDecodeContext *pMe,
                          const int64_t       nLabel,
                          bool               *pValue)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);
   QCBORDecode_Private_ProcessBool(pMe, &Item, pValue);
}


/* Public function, see qcbor/qcbor_spiffy_decode.h */
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

/* Public function, see qcbor/qcbor_spiffy_decode.h */
void
QCBORDecode_GetSimple(QCBORDecodeContext *pMe, uint8_t *puSimple)
{
   QCBORItem Item;
   QCBORDecode_VGetNext(pMe, &Item);
   QCBORDecode_Private_ProcessSimple(pMe, &Item, puSimple);
}

/* Public function, see qcbor/qcbor_spiffy_decode.h */
void
QCBORDecode_GetSimpleInMapN(QCBORDecodeContext *pMe,
                            int64_t             nLabel,
                            uint8_t            *puSimpleValue)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);
   QCBORDecode_Private_ProcessSimple(pMe, &Item, puSimpleValue);
}

/* Public function, see qcbor/qcbor_spiffy_decode.h */
void
QCBORDecode_GetSimpleInMapSZ(QCBORDecodeContext *pMe,
                             const char         *szLabel,
                             uint8_t            *puSimpleValue)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);
   QCBORDecode_Private_ProcessSimple(pMe, &Item, puSimpleValue);
}


// Improvement: add methods for wrapped CBOR, a simple alternate
// to EnterBstrWrapped

