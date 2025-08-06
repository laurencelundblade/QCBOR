/* ==========================================================================
 * qcbor_number_decode.c -- Number decoding beyond the basic ints and floats
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
 * Forked from qcbor_decode.c on 11/14/24.
 * ========================================================================== */


#include "qcbor/qcbor_number_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "qcbor/qcbor_tag_decode.h"
#include "ieee754.h" /* Does not use math.h */

#ifndef QCBOR_DISABLE_FLOAT_HW_USE

#include <math.h> /* For isnan(), llround(), llroudf(), round(), roundf(),
                   * pow(), exp2()
                   */
#include <fenv.h> /* feclearexcept(), fetestexcept() */

#endif /* ! QCBOR_DISABLE_FLOAT_HW_USE */


/* Order of stuff here is
 *  Simple conversions between ints and floats
 *  Complicated conversions involving big numbers, mantissa and exponent
 *  Big number decoding
 *  Mantissa and exponent decoding
 */


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
 * @brief Convert integers and floats to an int64_t.
 *
 * @param[in] pItem   The item to convert.
 * @param[in] uConvertTypes  See @ref QCBORDecodeNumberConvert.
 * @param[out] pnValue  The resulting converted value.
 *
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
 *                                    in uConvertTypes.
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
 *                                               or too small.
 */
static QCBORError
QCBOR_Private_ConvertInt64(const QCBORItem                    *pItem,
                           const enum QCBORDecodeNumberConvert uConvertTypes,
                           int64_t                            *pnValue)
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
#else /* ! QCBOR_DISABLE_FLOAT_HW_USE */
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* ! QCBOR_DISABLE_FLOAT_HW_USE */
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


/**
 * @brief Almost-public method to decode a number and convert to int64_t (semi-private).
 *
 * @param[in] pMe            The decode context.
 * @param[in] uConvertTypes  See @ref QCBORDecodeNumberConvert.
 * @param[out] pnValue       Result of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetInt64Convert().
 */
void
QCBORDecode_Private_GetInt64Convert(QCBORDecodeContext                *pMe,
                                    const enum QCBORDecodeNumberConvert uConvertTypes,
                                    int64_t                           *pnValue,
                                    QCBORItem                         *pItem)
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
 * @param[in] uConvertTypes  See @ref QCBORDecodeNumberConvert.
 * @param[out] pnValue       Result of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetInt64ConvertInMapN().
 */
void
QCBORDecode_Private_GetInt64ConvertInMapN(QCBORDecodeContext *pMe,
                                          const int64_t       nLabel,
                                          const enum QCBORDecodeNumberConvert uConvertTypes,
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
 * @param[in] uConvertTypes  See @ref QCBORDecodeNumberConvert.
 * @param[out] pnValue       Result of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetInt64ConvertInMapSZ().
 */
void
QCBORDecode_Private_GetInt64ConvertInMapSZ(QCBORDecodeContext *pMe,
                                           const char         *szLabel,
                                           const enum QCBORDecodeNumberConvert uConvertTypes,
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
 * @brief Convert many number types to an uint64_t.
 *
 * @param[in] pItem   The item to convert.
 * @param[in] uConvertTypes  See @ref QCBORDecodeNumberConvert.
 * @param[out] puValue  The resulting converted value.
 *
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
 *                                    in uConvertTypes.
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
 *                                               or too small.
 */
static QCBORError
QCBOR_Private_ConvertUInt64(const QCBORItem                    *pItem,
                            const enum QCBORDecodeNumberConvert uConvertTypes,
                            uint64_t                           *puValue)
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
#else /* ! QCBOR_DISABLE_FLOAT_HW_USE */
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* ! QCBOR_DISABLE_FLOAT_HW_USE */
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
 * @param[in] uConvertTypes  See @ref QCBORDecodeNumberConvert.
 * @param[out] puValue       Result of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetUInt64Convert().
 */
void
QCBORDecode_Private_GetUInt64Convert(QCBORDecodeContext                 *pMe,
                                     const enum QCBORDecodeNumberConvert uConvertTypes,
                                     uint64_t                           *puValue,
                                     QCBORItem                          *pItem)
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
 * @param[in] uConvertTypes  See @ref QCBORDecodeNumberConvert.
 * @param[out] puValue       Result of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetUInt64ConvertInMapN().
 */
void
QCBORDecode_Private_GetUInt64ConvertInMapN(QCBORDecodeContext *pMe,
                                           const int64_t       nLabel,
                                           const enum QCBORDecodeNumberConvert uConvertTypes,
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
 * @param[in] uConvertTypes  See @ref QCBORDecodeNumberConvert.
 * @param[out] puValue       Result of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetUInt64ConvertInMapSZ().
 */
void
QCBORDecode_Private_GetUInt64ConvertInMapSZ(QCBORDecodeContext *pMe,
                                            const char         *szLabel,
                                            const enum QCBORDecodeNumberConvert uConvertTypes,
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


#ifndef USEFULBUF_DISABLE_ALL_FLOAT
/**
 * @brief Basic conversions to a double.
 *
 * @param[in] pItem          The item to convert
 * @param[in] uConvertTypes  See @ref QCBORDecodeNumberConvert.
 * @param[out] pdValue       The value converted to a double
 *
 * This does the conversions that don't need much object code,
 * the conversions from int, uint and float to double.
 *
 * See QCBOR_Private_DoubleConvertAll() for the full set
 * of conversions.
 */
static QCBORError
QCBOR_Private_ConvertDouble(const QCBORItem                    *pItem,
                            const enum QCBORDecodeNumberConvert uConvertTypes,
                            double                             *pdValue)
{
   switch(pItem->uDataType) {
      case QCBOR_TYPE_FLOAT:
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
            if(uConvertTypes & QCBOR_CONVERT_TYPE_FLOAT) {
               *pdValue = IEEE754_SingleToDouble( UsefulBufUtil_CopyFloatToUint32(pItem->val.fnum));
            } else {
               return QCBOR_ERR_UNEXPECTED_TYPE;
            }
         }
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         return QCBOR_ERR_PREFERRED_FLOAT_DISABLED;
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
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
#else /* ! QCBOR_DISABLE_FLOAT_HW_USE */
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* ! QCBOR_DISABLE_FLOAT_HW_USE */
         break;

      case QCBOR_TYPE_UINT64:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         if(uConvertTypes & QCBOR_CONVERT_TYPE_XINT64) {
            /* IEEE754_UintToDouble() not used - it fails rather than round */
            *pdValue = (double)pItem->val.uint64;
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;
#else /* ! QCBOR_DISABLE_FLOAT_HW_USE */
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* ! QCBOR_DISABLE_FLOAT_HW_USE */

      case QCBOR_TYPE_65BIT_NEG_INT:
#ifndef QCBOR_DISABLE_FLOAT_HW_USE
         /* IEEE754_UintToDouble() not used - it fails rather than round */
         *pdValue = -(double)pItem->val.uint64 - 1;
         break;
#else /* ! QCBOR_DISABLE_FLOAT_HW_USE */
         return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* ! QCBOR_DISABLE_FLOAT_HW_USE */

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
QCBORDecode_Private_GetDoubleConvert(QCBORDecodeContext                 *pMe,
                                     const enum QCBORDecodeNumberConvert uConvertTypes,
                                     double                             *pdValue,
                                     QCBORItem                          *pItem)
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
 * @param[in] uConvertTypes  See @ref QCBORDecodeNumberConvert.
 * @param[out] pdValue       The output of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetDoubleConvertInMapN().
 */
void
QCBORDecode_Private_GetDoubleConvertInMapN(QCBORDecodeContext *pMe,
                                           const int64_t       nLabel,
                                           const enum QCBORDecodeNumberConvert uConvertTypes,
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
 * @param[in] uConvertTypes  See @ref QCBORDecodeNumberConvert.
 * @param[out] pdValue       The output of the conversion.
 * @param[in,out] pItem      Temporary space to store Item, returned item.
 *
 * See QCBORDecode_GetDoubleConvertInMapSZ().
 */
void
QCBORDecode_Private_GetDoubleConvertInMapSZ(QCBORDecodeContext *pMe,
                                            const char         *szLabel,
                                            const enum QCBORDecodeNumberConvert uConvertTypes,
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


#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
/* Public function, see qcbor/qcbor_number_decode.h */
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

   switch(Item.uDataType) {
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
         ToInt = IEEE754_SingleToInt(UsefulBufUtil_CopyFloatToUint32(Item.val.fnum));
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
            dNum = IEEE754_UintToDouble(Item.val.uint64 + 1, 1);
            if(dNum == IEEE754_UINT_TO_DOUBLE_OOB) {
               *pNumber = Item;
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

#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT */



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
 * @brief Convert many number types to an int64_t.
 *
 * @param[in] pItem   The item to convert.
 * @param[in] uConvertTypes  See @ref QCBORDecodeNumberConvert.
 * @param[out] pnValue  The resulting converted value.
 *
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
 *                                    in uConvertTypes.
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
 *                                               or too small.
 */
static QCBORError
QCBOR_Private_Int64ConvertAll(const QCBORItem                    *pItem,
                              const enum QCBORDecodeNumberConvert uConvertTypes,
                              int64_t                            *pnValue)
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

      case QCBOR_TYPE_BIGFLOAT_POS_BIGMANTISSA:
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

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGMANTISSA:
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
#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */


      default:
         return QCBOR_ERR_UNEXPECTED_TYPE;   }
}



/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetInt64ConvertAll(QCBORDecodeContext                  *pMe,
                               const enum QCBORDecodeNumberConvert  uConvertTypes,
                               int64_t                             *pnValue)
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


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetInt64ConvertAllInMapN(QCBORDecodeContext                  *pMe,
                                     const int64_t                        nLabel,
                                     const enum QCBORDecodeNumberConvert  uConvertTypes,
                                     int64_t                              *pnValue)
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


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetInt64ConvertAllInMapSZ(QCBORDecodeContext                  *pMe,
                                      const char                          *szLabel,
                                      const enum QCBORDecodeNumberConvert  uConvertTypes,
                                      int64_t                             *pnValue)
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
 * @brief Convert many number types to an unt64_t.
 *
 * @param[in] pItem   The item to convert.
 * @param[in] uConvertTypes  See @ref QCBORDecodeNumberConvert.
 * @param[out] puValue  The resulting converted value.
 *
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
 *                                    in uConvertTypes.
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
 *                                               or too small.
 */
static QCBORError
QCBOR_Private_UInt64ConvertAll(const QCBORItem                     *pItem,
                               const enum QCBORDecodeNumberConvert  uConvertTypes,
                               uint64_t                            *puValue)
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

      case QCBOR_TYPE_BIGFLOAT_POS_BIGMANTISSA:
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

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGMANTISSA:
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


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetUInt64ConvertAll(QCBORDecodeContext                  *pMe,
                                const enum QCBORDecodeNumberConvert  uConvertTypes,
                                uint64_t                            *puValue)
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


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetUInt64ConvertAllInMapN(QCBORDecodeContext                 *pMe,
                                      const int64_t                       nLabel,
                                      const enum QCBORDecodeNumberConvert uConvertTypes,
                                      uint64_t                           *puValue)
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


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetUInt64ConvertAllInMapSZ(QCBORDecodeContext                 *pMe,
                                       const char                         *szLabel,
                                       const enum QCBORDecodeNumberConvert uConvertTypes,
                                       uint64_t                           *puValue)
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
 * @brief Convert many number types to a double.
 *
 * @param[in] pItem   The item to convert.
 * @param[in] uConvertTypes See @ref QCBORDecodeNumberConvert.
 * @param[out] pdValue  The resulting converted value.
 *
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Conversion, possible, but not requested
 *                                    in uConvertTypes.
 * @retval QCBOR_ERR_UNEXPECTED_TYPE  Of a type that can't be converted
 * @retval QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW  Conversion result is too large
 *                                               or too small.
 */
static QCBORError
QCBOR_Private_DoubleConvertAll(const QCBORItem                    *pItem,
                               const enum QCBORDecodeNumberConvert uConvertTypes,
                               double                             *pdValue)
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

      case QCBOR_TYPE_BIGFLOAT_POS_BIGMANTISSA:
         if(uConvertTypes & QCBOR_CONVERT_TYPE_BIGFLOAT) {
            double dMantissa = QCBORDecode_Private_BigNumberToDouble(pItem->val.expAndMantissa.Mantissa.bigNum);
            *pdValue = dMantissa * exp2((double)pItem->val.expAndMantissa.nExponent);
         } else {
            return QCBOR_ERR_UNEXPECTED_TYPE;
         }
         break;

      case QCBOR_TYPE_BIGFLOAT_NEG_BIGMANTISSA:
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

#else /* ! QCBOR_DISABLE_FLOAT_HW_USE */
   (void)pItem;
   (void)uConvertTypes;
   (void)pdValue;
   return QCBOR_ERR_HW_FLOAT_DISABLED;
#endif /* ! QCBOR_DISABLE_FLOAT_HW_USE */

}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetDoubleConvertAll(QCBORDecodeContext                 *pMe,
                                const enum QCBORDecodeNumberConvert uConvertTypes,
                                double                             *pdValue)
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


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetDoubleConvertAllInMapN(QCBORDecodeContext                 *pMe,
                                      const int64_t                       nLabel,
                                      const enum QCBORDecodeNumberConvert uConvertTypes,
                                      double                             *pdValue)
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

/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetDoubleConvertAllInMapSZ(QCBORDecodeContext                 *pMe,
                                       const char                         *szLabel,
                                       const enum QCBORDecodeNumberConvert uConvertTypes,
                                       double                             *pdValue)
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

#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT */



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


/* Public function, see qcbor/qcbor_number_decode.h */
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


/* Public function, see qcbor/qcbor_number_decode.h */
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
       const uint64_t uIntTmp = (uint64_t)(*pbIsNegative ? -Item.val.int64 : Item.val.int64);
      *pBigNumber = QCBORDecode_Private_UIntToBigNumber(uIntTmp, BigNumberBuf);
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
QCBORDecode_Private_BigNumberRawMain(QCBORDecodeContext          *pMe,
                                     const enum QCBORDecodeTagReq uTagRequirement,
                                     QCBORItem                   *pItem,
                                     UsefulBufC                  *pBignumber,
                                     bool                        *pbIsNegative,
                                     size_t                       uOffset)
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
QCBORDecode_Private_BigNumberNoPreferredMain(QCBORDecodeContext          *pMe,
                                             const enum QCBORDecodeTagReq uTagRequirement,
                                             QCBORItem                   *pItem,
                                             const size_t                uOffset,
                                             UsefulBuf                   BigNumberBuf,
                                             UsefulBufC                 *pBigNumber,
                                             bool                       *pbIsNegative)
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
QCBORDecode_Private_BigNumberMain(QCBORDecodeContext          *pMe,
                                  const enum QCBORDecodeTagReq uTagRequirement,
                                  QCBORItem                   *pItem,
                                  const size_t                uOffset,
                                  UsefulBuf                   BigNumberBuf,
                                  UsefulBufC                 *pBigNumber,
                                  bool                       *pbIsNegative)
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


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigNumber(QCBORDecodeContext          *pMe,
                          const enum QCBORDecodeTagReq uTagRequirement,
                          UsefulBuf                    BigNumberBuf,
                          UsefulBufC                  *pBigNumber,
                          bool                        *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_BigNumberMain(pMe, uTagRequirement, &Item, uOffset, BigNumberBuf, pBigNumber, pbIsNegative);
}

/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigNumberInMapN(QCBORDecodeContext          *pMe,
                                const int64_t                nLabel,
                                const enum QCBORDecodeTagReq uTagRequirement,
                                UsefulBuf                    BigNumberBuf,
                                UsefulBufC                  *pBigNumber,
                                bool                        *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_BigNumberMain(pMe,
                                     uTagRequirement,
                                    &Item,
                                     uOffset,
                                     BigNumberBuf,
                                     pBigNumber,
                                     pbIsNegative);
}

/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigNumberInMapSZ(QCBORDecodeContext          *pMe,
                                 const char                  *szLabel,
                                 const enum QCBORDecodeTagReq uTagRequirement,
                                 UsefulBuf                    BigNumberBuf,
                                 UsefulBufC                  *pBigNumber,
                                 bool                        *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_BigNumberMain(pMe,
                                     uTagRequirement,
                                    &Item,
                                     uOffset,
                                     BigNumberBuf,
                                     pBigNumber,
                                     pbIsNegative);
}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigNumberNoPreferred(QCBORDecodeContext          *pMe,
                                     const enum QCBORDecodeTagReq uTagRequirement,
                                     UsefulBuf                    BigNumberBuf,
                                     UsefulBufC                  *pBigNumber,
                                     bool                        *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_BigNumberNoPreferredMain(pMe,
                                                uTagRequirement,
                                               &Item,
                                                uOffset,
                                                BigNumberBuf,
                                                pBigNumber,
                                                pbIsNegative);
}

/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigNumberNoPreferredInMapN(QCBORDecodeContext          *pMe,
                                           const int64_t                nLabel,
                                           const enum QCBORDecodeTagReq uTagRequirement,
                                           UsefulBuf                    BigNumberBuf,
                                           UsefulBufC                  *pBigNumber,
                                           bool                        *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_BigNumberNoPreferredMain(pMe,
                                                uTagRequirement,
                                               &Item,
                                                uOffset,
                                                BigNumberBuf,
                                                pBigNumber,
                                                pbIsNegative);

}

/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigNumberNoPreferredInMapSZ(QCBORDecodeContext          *pMe,
                                            const char                  *szLabel,
                                            const enum QCBORDecodeTagReq uTagRequirement,
                                            UsefulBuf                    BigNumberBuf,
                                            UsefulBufC                  *pBigNumber,
                                            bool                        *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_BigNumberNoPreferredMain(pMe,
                                                uTagRequirement,
                                               &Item,
                                                uOffset,
                                                BigNumberBuf,
                                                pBigNumber,
                                                pbIsNegative);
}



/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigNumberRaw(QCBORDecodeContext          *pMe,
                             const enum QCBORDecodeTagReq uTagRequirement,
                             UsefulBufC                  *pBignumber,
                             bool                        *pbIsNegative)
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

/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigNumberRawInMapN(QCBORDecodeContext          *pMe,
                                   const int64_t                nLabel,
                                   const enum QCBORDecodeTagReq uTagRequirement,
                                   UsefulBufC                  *pBigNumber,
                                   bool                        *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_BigNumberRawMain(pMe,
                                        uTagRequirement,
                                       &Item,
                                        pBigNumber,
                                        pbIsNegative,
                                        uOffset);
}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigNumberRawInMapSZ(QCBORDecodeContext          *pMe,
                                    const char                  *szLabel,
                                    const enum QCBORDecodeTagReq uTagRequirement,
                                    UsefulBufC                  *pBigNumber,
                                    bool                        *pbIsNegative)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_BigNumberRawMain(pMe,
                                        uTagRequirement,
                                       &Item,
                                        pBigNumber,
                                        pbIsNegative,
                                        uOffset);
}




#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA

static const uint8_t QCBORDecode_Private_DecimalFractionTypes[] = {
   QCBOR_TYPE_DECIMAL_FRACTION,
   QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM,
   QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM,
   QCBOR_TYPE_DECIMAL_FRACTION_POS_U64,
   QCBOR_TYPE_DECIMAL_FRACTION_NEG_U64,
   QCBOR_TYPE_NONE};

static const uint8_t QCBORDecode_Private_BigFloatTypes[] = {
   QCBOR_TYPE_BIGFLOAT,
   QCBOR_TYPE_BIGFLOAT_POS_BIGMANTISSA,
   QCBOR_TYPE_BIGFLOAT_NEG_BIGMANTISSA,
   QCBOR_TYPE_BIGFLOAT_POS_U64MANTISSA,
   QCBOR_TYPE_BIGFLOAT_NEG_U64MANTISSA,
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
QCBORDecode_Private_ExpIntMantissaMain(QCBORDecodeContext          *pMe,
                                       const enum QCBORDecodeTagReq uTagReq,
                                       const uint64_t               uTagNumber,
                                       const size_t                 uOffset,
                                       QCBORItem                   *pItem,
                                       int64_t                     *pnMantissa,
                                       int64_t                     *pnExponent)
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
                                      uTagReq,
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
      case QCBOR_TYPE_BIGFLOAT_POS_BIGMANTISSA:
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         uErr = QCBORDecode_Private_PositiveBigNumberToInt(pItem->val.expAndMantissa.Mantissa.bigNum, pnMantissa);
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_NEG_BIGMANTISSA:
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         uErr = QCBORDecode_Private_NegativeBigNumberToInt(pItem->val.expAndMantissa.Mantissa.bigNum, pnMantissa);
         break;
#endif /* ! QCBOR_DISABLE_TAGS */

      case QCBOR_TYPE_BIGFLOAT_NEG_U64MANTISSA:
      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_U64:
      case QCBOR_TYPE_BIGFLOAT_POS_U64MANTISSA:
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
                                          const enum QCBORDecodeTagReq uTagReq,
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
                                      uTagReq,
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
      case QCBOR_TYPE_BIGFLOAT_POS_BIGMANTISSA:
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         *pMantissa = pItem->val.expAndMantissa.Mantissa.bigNum;
         *pbIsNegative = false;
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_NEG_BIGMANTISSA:
         *pnExponent = pItem->val.expAndMantissa.nExponent;
         *pMantissa = pItem->val.expAndMantissa.Mantissa.bigNum;
         *pbIsNegative = true;
         break;
#endif /* ! QCBOR_DISABLE_TAGS */

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
QCBORDecode_Private_ExpBigMantissaMain(QCBORDecodeContext          *pMe,
                                       const enum QCBORDecodeTagReq uTagReq,
                                       const uint64_t               uTagNumber,
                                       const size_t                 uOffset,
                                       QCBORItem                   *pItem,
                                       const UsefulBuf              BufferForMantissa,
                                       UsefulBufC                  *pMantissa,
                                       bool                        *pbIsNegative,
                                       int64_t                     *pnExponent)
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
                                      uTagReq,
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
      case QCBOR_TYPE_BIGFLOAT_POS_U64MANTISSA:
         TempMantissa.uDataType = QCBOR_TYPE_UINT64;
         TempMantissa.val.uint64 = pItem->val.expAndMantissa.Mantissa.uInt;
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_U64:
      case QCBOR_TYPE_BIGFLOAT_NEG_U64MANTISSA:
         TempMantissa.uDataType = QCBOR_TYPE_65BIT_NEG_INT;
         TempMantissa.val.uint64 = pItem->val.expAndMantissa.Mantissa.uInt;
         break;

#ifndef QCBOR_DISABLE_TAGS
         /* If tags are disabled, mantissas can never be big nums */
      case QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_POS_BIGMANTISSA:
         TempMantissa.uDataType = QCBOR_TYPE_BYTE_STRING;
         TempMantissa.val.bigNum = pItem->val.expAndMantissa.Mantissa.bigNum;
         *pbIsNegative = false;
         break;

      case QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM:
      case QCBOR_TYPE_BIGFLOAT_NEG_BIGMANTISSA:
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


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTDecimalFraction(QCBORDecodeContext          *pMe,
                                const enum QCBORDecodeTagReq uTagRequirement,
                                int64_t                     *pnMantissa,
                                int64_t                     *pnExponent)
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


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTDecimalFractionInMapN(QCBORDecodeContext          *pMe,
                                      const int64_t                nLabel,
                                      const enum QCBORDecodeTagReq uTagReq,
                                      int64_t                     *pnMantissa,
                                      int64_t                     *pnExponent)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpIntMantissaMain(pMe,
                                          uTagReq,
                                          CBOR_TAG_DECIMAL_FRACTION,
                                          uOffset,
                                         &Item,
                                          pnMantissa,
                                          pnExponent);

}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTDecimalFractionInMapSZ(QCBORDecodeContext          *pMe,
                                       const char                  *szLabel,
                                       const enum QCBORDecodeTagReq uTagReq,
                                       int64_t                     *pnMantissa,
                                       int64_t                     *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpIntMantissaMain(pMe,
                                          uTagReq,
                                          CBOR_TAG_DECIMAL_FRACTION,
                                          uOffset,
                                         &Item,
                                          pnMantissa,
                                          pnExponent);
}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTDecimalFractionBigMantissa(QCBORDecodeContext          *pMe,
                                           const enum QCBORDecodeTagReq uTagReq,
                                           const UsefulBuf              MantissaBuffer,
                                           UsefulBufC                  *pMantissa,
                                           bool                        *pbMantissaIsNegative,
                                           int64_t                     *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaMain(pMe,
                                          uTagReq,
                                          CBOR_TAG_DECIMAL_FRACTION,
                                          uOffset,
                                         &Item,
                                          MantissaBuffer,
                                          pMantissa,
                                          pbMantissaIsNegative,
                                          pnExponent);
}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTDecimalFractionBigMantissaInMapN(QCBORDecodeContext *pMe,
                                                 const int64_t       nLabel,
                                                 const enum QCBORDecodeTagReq uTagReq,
                                                 const UsefulBuf     BufferForMantissa,
                                                 UsefulBufC         *pMantissa,
                                                 bool               *pbIsNegative,
                                                 int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaMain(pMe,
                                          uTagReq,
                                          CBOR_TAG_DECIMAL_FRACTION,
                                          uOffset,
                                         &Item,
                                          BufferForMantissa,
                                          pMantissa,
                                          pbIsNegative,
                                          pnExponent);
}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTDecimalFractionBigMantissaInMapSZ(QCBORDecodeContext *pMe,
                                                  const char         *szLabel,
                                                  const enum QCBORDecodeTagReq uTagReq,
                                                  const UsefulBuf     BufferForMantissa,
                                                  UsefulBufC         *pMantissa,
                                                  bool               *pbIsNegative,
                                                  int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaMain(pMe,
                                          uTagReq,
                                          CBOR_TAG_DECIMAL_FRACTION,
                                          uOffset,
                                         &Item,
                                          BufferForMantissa,
                                          pMantissa,
                                          pbIsNegative,
                                          pnExponent);
}

/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTDecimalFractionBigMantissaRaw(QCBORDecodeContext *pMe,
                                              const enum QCBORDecodeTagReq uTagReq,
                                              const UsefulBuf     MantissaBuffer,
                                              UsefulBufC         *pMantissa,
                                              bool               *pbMantissaIsNegative,
                                              int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaRawMain(pMe,
                                             uTagReq,
                                             CBOR_TAG_DECIMAL_FRACTION,
                                             uOffset,
                                            &Item,
                                             MantissaBuffer,
                                             pMantissa,
                                             pbMantissaIsNegative,
                                             pnExponent);
}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTDecimalFractionBigMantissaRawInMapN(QCBORDecodeContext          *pMe,
                                                    const int64_t                nLabel,
                                                    const enum QCBORDecodeTagReq uTagReq,
                                                    const UsefulBuf              BufferForMantissa,
                                                    UsefulBufC                  *pMantissa,
                                                    bool                        *pbIsNegative,
                                                    int64_t                     *pnExponent)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaRawMain(pMe,
                                             uTagReq,
                                             CBOR_TAG_DECIMAL_FRACTION,
                                             uOffset,
                                            &Item,
                                             BufferForMantissa,
                                             pMantissa,
                                             pbIsNegative,
                                             pnExponent);
}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTDecimalFractionBigMantissaRawInMapSZ(QCBORDecodeContext *pMe,
                                                     const char         *szLabel,
                                                     const enum QCBORDecodeTagReq uTagReq,
                                                     const UsefulBuf     BufferForMantissa,
                                                     UsefulBufC         *pMantissa,
                                                     bool               *pbIsNegative,
                                                     int64_t            *pnExponent)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaRawMain(pMe,
                                             uTagReq,
                                             CBOR_TAG_DECIMAL_FRACTION,
                                             uOffset,
                                            &Item,
                                             BufferForMantissa,
                                             pMantissa,
                                             pbIsNegative,
                                             pnExponent);
}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigFloat(QCBORDecodeContext          *pMe,
                         const enum QCBORDecodeTagReq uTagRequirement,
                         int64_t                     *pnMantissa,
                         int64_t                     *pnExponent)
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


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigFloatInMapN(QCBORDecodeContext          *pMe,
                               const int64_t                nLabel,
                               const enum QCBORDecodeTagReq uTagRequirement,
                               int64_t                     *pnMantissa,
                               int64_t                     *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpIntMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_BIGFLOAT,
                                          uOffset,
                                         &Item,
                                          pnMantissa,
                                          pnExponent);
}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigFloatInMapSZ(QCBORDecodeContext          *pMe,
                                const char                  *szLabel,
                                const enum QCBORDecodeTagReq uTagRequirement,
                                int64_t                     *pnMantissa,
                                int64_t                     *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpIntMantissaMain(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_BIGFLOAT,
                                          uOffset,
                                         &Item,
                                          pnMantissa,
                                          pnExponent);
}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigFloatBigMantissa(QCBORDecodeContext          *pMe,
                                    const enum QCBORDecodeTagReq uTagReq,
                                    const UsefulBuf     MantissaBuffer,
                                    UsefulBufC         *pMantissa,
                                    bool               *pbMantissaIsNegative,
                                    int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaMain(pMe,
                                          uTagReq,
                                          CBOR_TAG_BIGFLOAT,
                                          uOffset,
                                         &Item,
                                          MantissaBuffer,
                                          pMantissa,
                                          pbMantissaIsNegative,
                                          pnExponent);
}



/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigFloatBigMantissaInMapN(QCBORDecodeContext *pMe,
                                          const int64_t       nLabel,
                                          const enum QCBORDecodeTagReq uTagReq,
                                          const UsefulBuf     BufferForMantissa,
                                          UsefulBufC         *pMantissa,
                                          bool               *pbIsNegative,
                                          int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaMain(pMe,
                                          uTagReq,
                                          CBOR_TAG_BIGFLOAT,
                                          uOffset,
                                         &Item,
                                          BufferForMantissa,
                                          pMantissa,
                                          pbIsNegative,
                                          pnExponent);
}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigFloatBigMantissaInMapSZ(QCBORDecodeContext          *pMe,
                                           const char                  *szLabel,
                                           const enum QCBORDecodeTagReq uTagReq,
                                           const UsefulBuf              BufferForMantissa,
                                           UsefulBufC                  *pMantissa,
                                           bool                        *pbIsNegative,
                                           int64_t                     *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaMain(pMe,
                                          uTagReq,
                                          CBOR_TAG_BIGFLOAT,
                                          uOffset,
                                         &Item,
                                          BufferForMantissa,
                                          pMantissa,
                                          pbIsNegative,
                                          pnExponent);
}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigFloatBigMantissaRaw(QCBORDecodeContext *pMe,
                                       const enum QCBORDecodeTagReq uTagReq,
                                       const UsefulBuf     MantissaBuffer,
                                       UsefulBufC         *pMantissa,
                                       bool               *pbMantissaIsNegative,
                                       int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetAndTell(pMe, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaRawMain(pMe,
                                             uTagReq,
                                             CBOR_TAG_BIGFLOAT,
                                             uOffset,
                                            &Item,
                                             MantissaBuffer,
                                             pMantissa,
                                             pbMantissaIsNegative,
                                             pnExponent);
}

/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigFloatBigMantissaRawInMapN(QCBORDecodeContext *pMe,
                                             const int64_t       nLabel,
                                             const enum QCBORDecodeTagReq uTagReq,
                                             const UsefulBuf     BufferForMantissa,
                                             UsefulBufC         *pMantissa,
                                             bool               *pbIsNegative,
                                             int64_t            *pnExponent)
{
   QCBORItem  Item;
   size_t     uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckN(pMe, nLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaRawMain(pMe,
                                             uTagReq,
                                             CBOR_TAG_BIGFLOAT,
                                             uOffset,
                                            &Item,
                                             BufferForMantissa,
                                             pMantissa,
                                             pbIsNegative,
                                             pnExponent);
}


/* Public function, see qcbor/qcbor_number_decode.h */
void
QCBORDecode_GetTBigFloatBigMantissaRawInMapSZ(QCBORDecodeContext          *pMe,
                                              const char                  *szLabel,
                                              const enum QCBORDecodeTagReq uTagReq,
                                              const UsefulBuf              BufferForMantissa,
                                              UsefulBufC                  *pMantissa,
                                              bool                        *pbIsNegative,
                                              int64_t                     *pnExponent)
{
   QCBORItem Item;
   size_t    uOffset;

   QCBORDecode_Private_GetItemInMapNoCheckSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item, &uOffset);
   QCBORDecode_Private_ExpBigMantissaRawMain(pMe,
                                             uTagReq,
                                             CBOR_TAG_BIGFLOAT,
                                             uOffset,
                                            &Item,
                                             BufferForMantissa,
                                             pMantissa,
                                             pbIsNegative,
                                             pnExponent);
}

#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */
