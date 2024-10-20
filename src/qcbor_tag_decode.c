/* ==========================================================================
 * qcbor_tag_decode.c -- Tag content decoders
 *
 * Copyright (c) 2024, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created on 9/5/24
 * ========================================================================== */

#include "qcbor/qcbor_tag_decode.h"

#include <math.h> /* For isnan() */


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
 * @brief Figures out data type for exponent mantissa tags.
 *
 * @param[in] uTagToProcess  Either @ref CBOR_TAG_DECIMAL_FRACTION or
 *                           @ref CBOR_TAG_BIG_FLOAT.
 * @param[in] pDecodedItem   Item being decoded.
 *
 * @returns One of the 6 values between \ref QCBOR_TYPE_DECIMAL_FRACTION
 *          and @ref QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM.
 *
 * Does mapping between a CBOR tag number and a QCBOR type.  with a
 * little bit of logic and arithmatic.
 *
 * Used in serveral contexts. Does the work where sometimes the data
 * item is explicitly tagged and sometimes not.
 */
static uint8_t
QCBOR_Private_ExpMantissaDataType(const uint64_t   uTagToProcess,
                                  const QCBORItem *pDecodedItem)
{
   uint8_t uBase = uTagToProcess == CBOR_TAG_DECIMAL_FRACTION ?
                                       QCBOR_TYPE_DECIMAL_FRACTION :
                                       QCBOR_TYPE_BIGFLOAT;
   if(pDecodedItem->uDataType != QCBOR_TYPE_INT64) {
      uBase = (uint8_t)(uBase + pDecodedItem->uDataType - QCBOR_TYPE_POSBIGNUM + 1);
   }
   return uBase;
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
   QCBORItem ExponentItem;
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
   QCBORItem MantissaItem;
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
#endif /* QCBOR_DISABLE_TAGS */
   } else {
      /* Wrong type of mantissa or a QCBOR_TYPE_UINT64 > INT64_MAX */
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
   {CBOR_TAG_CBOR_SEQUENCE, QBCOR_TYPE_WRAPPED_CBOR_SEQUENCE | IS_BYTE_STRING_BIT}, // TODO: does this belong here?
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
   {CBOR_TAG_CBOR_SEQUENCE,    QCBORDecode_StringsTagCB}, // TODO: does this belong here?
   {CBOR_TAG_MIME,             QCBORDecode_MIMETagCB},
   {CBOR_TAG_BINARY_MIME,      QCBORDecode_MIMETagCB},
#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA

   {CBOR_TAG_BIGFLOAT,         QCBORDecode_ExpMantissaTagCB},
   {CBOR_TAG_DECIMAL_FRACTION, QCBORDecode_ExpMantissaTagCB},
#endif
   {CBOR_TAG_DAYS_EPOCH,       QCBORDecode_DaysEpochTagCB},
   {CBOR_TAG_INVALID64,        NULL},
};

#endif /* ! QCBOR_DISABLE_TAGS */

