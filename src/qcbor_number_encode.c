/* ===========================================================================
 * Copyright (c) 2016-2018, The Linux Foundation.
 * Copyright (c) 2018-2024, Laurence Lundblade.
 * Copyright (c) 2021, Arm Limited.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors, nor the name "Laurence Lundblade" may be used to
 *       endorse or promote products derived from this software without
 *       specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ========================================================================= */


#include "qcbor/qcbor_number_encode.h"
#include "ieee754.h"

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
#include <math.h> /* Only for NAN definition */
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */


/**
 * @file qcbor_number_encode.c
 *
 */



/*
 * Public function for adding signed integers. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_AddInt64(QCBOREncodeContext *pMe, const int64_t nNum)
{
   uint8_t  uMajorType;
   uint64_t uValue;

   if(nNum < 0) {
      /* In CBOR -1 encodes as 0x00 with major type negative int.
       * First add one as a signed integer because that will not
       * overflow. Then change the sign as needed for encoding (the
       * opposite order, changing the sign and subtracting, can cause
       * an overflow when encoding INT64_MIN). */
      int64_t nTmp = nNum + 1;
      uValue = (uint64_t)-nTmp;
      uMajorType = CBOR_MAJOR_TYPE_NEGATIVE_INT;
   } else {
      uValue = (uint64_t)nNum;
      uMajorType = CBOR_MAJOR_TYPE_POSITIVE_INT;
   }
   QCBOREncode_Private_AppendCBORHead(pMe, uMajorType, uValue, 0);
}


#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
/**
 * @brief Semi-private method to add a double using preferred encoding.
 *
 * @param[in] pMe   The encode context.
 * @param[in] dNum  The double to add.
 *
 * This converts the double to a float or half-precision if it can be done
 * without a loss of precision. See QCBOREncode_AddDouble().
 */
void
QCBOREncode_Private_AddPreferredDouble(QCBOREncodeContext *pMe, double dNum)
{
   IEEE754_union        FloatResult;
   bool                 bNoNaNPayload;
   struct IEEE754_ToInt IntResult;
   uint64_t             uNegValue;

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(IEEE754_DoubleHasNaNPayload(dNum) && !(pMe->uConfigFlags & QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD)) {
      pMe->uError = QCBOR_ERR_NOT_ALLOWED;
      return;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   if(pMe->uConfigFlags & QCBOR_ENCODE_CONFIG_FLOAT_REDUCTION) {
      IntResult = IEEE754_DoubleToInt(dNum);
      switch(IntResult.type) {
         case IEEE754_ToInt_IS_INT:
            QCBOREncode_AddInt64(pMe, IntResult.integer.is_signed);
            return;
         case IEEE754_ToInt_IS_UINT:
            QCBOREncode_AddUInt64(pMe, IntResult.integer.un_signed);
            return;
         case IEEE754_ToInt_IS_65BIT_NEG:
            {
               if(IntResult.integer.un_signed == 0) {
                  uNegValue = UINT64_MAX;
               } else {
                  uNegValue = IntResult.integer.un_signed-1;
               }
               QCBOREncode_AddNegativeUInt64(pMe, uNegValue);
            }
            return;
         case IEEE754_ToInt_NaN:
            dNum = NAN;
            bNoNaNPayload = true;
            break;
         case IEEE754_ToInt_NO_CONVERSION:
            bNoNaNPayload = true;
      }
   } else  {
      bNoNaNPayload = false;
   }

   FloatResult = IEEE754_DoubleToSmaller(dNum, true, bNoNaNPayload);

   QCBOREncode_Private_AddType7(pMe, (uint8_t)FloatResult.uSize, FloatResult.uValue);
}


/**
 * @brief Semi-private method to add a float using preferred encoding.
 *
 * @param[in] pMe   The encode context.
 * @param[in] fNum  The float to add.
 *
 * This converts the float to a half-precision if it can be done
 * without a loss of precision. See QCBOREncode_AddFloat().
 */
void
QCBOREncode_Private_AddPreferredFloat(QCBOREncodeContext *pMe, float fNum)
{
   IEEE754_union        FloatResult;
   bool                 bNoNaNPayload;
   struct IEEE754_ToInt IntResult;
   uint64_t             uNegValue;

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(IEEE754_SingleHasNaNPayload(fNum) && !(pMe->uConfigFlags & QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD)) {
      pMe->uError = QCBOR_ERR_NOT_ALLOWED;
      return;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   if(pMe->uConfigFlags & QCBOR_ENCODE_CONFIG_FLOAT_REDUCTION) {
      IntResult = IEEE754_SingleToInt(fNum);
      switch(IntResult.type) {
         case IEEE754_ToInt_IS_INT:
            QCBOREncode_AddInt64(pMe, IntResult.integer.is_signed);
            return;
         case IEEE754_ToInt_IS_UINT:
            QCBOREncode_AddUInt64(pMe, IntResult.integer.un_signed);
            return;
         case IEEE754_ToInt_IS_65BIT_NEG:
            {
               if(IntResult.integer.un_signed == 0) {
                  uNegValue = UINT64_MAX;
               } else {
                  uNegValue = IntResult.integer.un_signed-1;
               }
               QCBOREncode_AddNegativeUInt64(pMe, uNegValue);
            }
            return;
         case IEEE754_ToInt_NaN:
            fNum = NAN;
            bNoNaNPayload = true;
            break;
         case IEEE754_ToInt_NO_CONVERSION:
            bNoNaNPayload = true;
      }
   } else  {
      bNoNaNPayload = false;
   }

   FloatResult = IEEE754_SingleToHalf(fNum, bNoNaNPayload);

   QCBOREncode_Private_AddType7(pMe, (uint8_t)FloatResult.uSize, FloatResult.uValue);
}
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */




/**
 * @brief Convert a big number to unsigned integer.
 *
 * @param[in]  BigNumber  Big number to convert.
 *
 * @return Converted unsigned.
 *
 * The big number must be less than 8 bytes long.
 **/
static uint64_t
QCBOREncode_Private_BigNumberToUInt(const UsefulBufC BigNumber)
{
   uint64_t uInt;
   size_t   uIndex;

   uInt = 0;
   for(uIndex = 0; uIndex < BigNumber.len; uIndex++) {
      uInt = (uInt << 8) + UsefulBufC_NTH_BYTE(BigNumber, uIndex);
   }

   return uInt;
}


/**
 * @brief Is there a carry when you subtract 1 from the BigNumber.
 *
 * @param[in]  BigNumber  Big number to check for carry.
 *
 * @return If there is a carry, \c true.
 *
 * If this returns @c true, then @c BigNumber - 1 is one byte shorter
 * than @c BigNumber.
 **/
static bool
QCBOREncode_Private_BigNumberCarry(const UsefulBufC BigNumber)
{
   bool       bCarry;
   UsefulBufC SubBigNum;

   // Improvement: rework without recursion?

   if(BigNumber.len == 0) {
      return true; /* Subtracting one from zero-length string gives a carry */
   } else {
      SubBigNum = UsefulBuf_Tail(BigNumber, 1);
      bCarry = QCBOREncode_Private_BigNumberCarry(SubBigNum);
      if(UsefulBufC_NTH_BYTE(BigNumber, 0) == 0x00 && bCarry) {
         /* Subtracting one from 0 gives a carry */
         return true;
      } else {
         return false;
      }
   }
}


/**
 * @brief Output negative bignum bytes with subtraction of 1.
 *
 * @param[in] pMe              The decode context.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] BigNumber        The negative big number.
 */
static void
QCBOREncode_Private_AddTNegativeBigNumber(QCBOREncodeContext *pMe,
                                          const uint8_t       uTagRequirement,
                                          const UsefulBufC    BigNumber)
{
   size_t     uLen;
   bool       bCarry;
   bool       bCopiedSomething;
   uint8_t    uByte;
   UsefulBufC SubString;
   UsefulBufC NextSubString;

   QCBOREncode_Private_BigNumberTag(pMe, uTagRequirement, true);

   /* This works on any length without the need of an additional buffer */

   /* This subtracts one, possibly making the string shorter by one
    * 0x01 -> 0x00
    * 0x01 0x00 -> 0xff
    * 0x00 0x01 0x00 -> 0x00 0xff
    * 0x02 0x00 -> 0x01 0xff
    * 0xff -> 0xfe
    * 0xff 0x00 -> 0xfe 0xff
    * 0x01 0x00 0x00 -> 0xff 0xff
    *
    * This outputs the big number a byte at a time to be able to operate on
    * a big number of any length without memory allocation.
    */

   /* Compute the length up front because it goes in the encoded head */
   bCarry = QCBOREncode_Private_BigNumberCarry(UsefulBuf_Tail(BigNumber, 1));
   uLen = BigNumber.len;
   if(bCarry && BigNumber.len > 1 && UsefulBufC_NTH_BYTE(BigNumber, 0) >= 1) {
      uLen--;
   }
   QCBOREncode_Private_AppendCBORHead(pMe, CBOR_MAJOR_TYPE_BYTE_STRING, uLen,0);

   SubString = BigNumber;
   bCopiedSomething = false;
   while(SubString.len) {
      uByte = UsefulBufC_NTH_BYTE(SubString, 0);
      NextSubString = UsefulBuf_Tail(SubString, 1);
      bCarry = QCBOREncode_Private_BigNumberCarry(NextSubString);
      if(bCarry) {
         uByte--;
      }
      /* This avoids all but the last leading zero. See
       * QCBOREncode_Private_SkipLeadingZeros() */
      if(bCopiedSomething || NextSubString.len == 0 || uByte != 0) {
         UsefulOutBuf_AppendByte(&(pMe->OutBuf), uByte);
         bCopiedSomething = true;
      }
      SubString = NextSubString;
   }
}


/**
 * @brief Remove leading zeros.
 *
 * @param[in] BigNumber  The big number.
 *
 * @return Big number with no leading zeros.
 *
 * If the big number is all zeros, this returns a big number that is
 * one zero rather than the empty string.
 *
 * RFC 8949 3.4.3 does not explicitly decoders MUST handle the empty
 * string, but does say decoders MUST handle leading zeros. So
 * Postel's Law is applied here and 0 is not encoded as an empty
 * string.
 */
static UsefulBufC
QCBOREncode_Private_SkipLeadingZeros(const UsefulBufC BigNumber)
{
   UsefulBufC NLZ;
   NLZ = UsefulBuf_SkipLeading(BigNumber, 0x00);

   /* An all-zero string reduces to one 0, not an empty string. */
   if(NLZ.len == 0 &&
      BigNumber.len > 0 &&
      UsefulBufC_NTH_BYTE(BigNumber, 0) == 0x00) {
      NLZ.len = 1;
   }

   return NLZ;
}


/**
 * @brief Output a big number, preferred or not, with negative offset
 *
 * @param[in] pMe              The decode context.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] bPreferred       Uses preferred serialization if true
 * @param[in] bNegative        Indicates big number is negative or postive.
 * @param[in] BigNumber        The big number.
 *
 * Regardless of whether preferred serialization is used, if the big
 * number is negative, one is subtracted before is output per CBOR
 * convetion for big numbers. This requires a little big number
 * arithmetic and adds some object code.
 *
 * If preferred serialization is used, then if the number is smaller
 * than UINT64_MAX and postive it is output as type 0 and if it is
 * equal to or smaller than UINT64_MAX it is output as a type 1
 * integer minus one.
 *
 * See QCBOREncode_AddTBigNumberRaw() for simple copy through.
 */
void
QCBOREncode_Private_AddTBigNumberMain(QCBOREncodeContext *pMe,
                                      const uint8_t       uTagRequirement,
                                      const bool          bPreferred,
                                      const bool          bNegative,
                                      const UsefulBufC    BigNumber)
{
   uint64_t   uInt;
   bool       bIs2exp64;
   uint8_t    uMajorType;
   UsefulBufC BigNumberNLZ;

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(!bPreferred && pMe->uConfigFlags & QCBOR_ENCODE_CONFIG_ONLY_PREFERRED_BIG_NUMBERS) {
      pMe->uError = QCBOR_ERR_NOT_PREFERRED;
      return;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   BigNumberNLZ = QCBOREncode_Private_SkipLeadingZeros(BigNumber);

   static const uint8_t twoExp64[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
   bIs2exp64 = ! UsefulBuf_Compare(BigNumber, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(twoExp64));

   if(bPreferred && (BigNumberNLZ.len <= 8 || (bNegative && bIs2exp64))) {
      if(bIs2exp64) {
         /* 2^64 is a 9 byte big number. Since negative numbers are offset
          * by one in CBOR, it can be encoded as a type 1 negative. The
          * conversion below won't work because the uInt will overflow
          * before the subtraction of 1.
          */
         uInt = UINT64_MAX;
      } else {
         uInt = QCBOREncode_Private_BigNumberToUInt(BigNumberNLZ);
         if(bNegative) {
            uInt--;
         }
      }
      uMajorType = bNegative ? CBOR_MAJOR_TYPE_NEGATIVE_INT :
                               CBOR_MAJOR_TYPE_POSITIVE_INT;
      QCBOREncode_Private_AppendCBORHead(pMe, uMajorType, uInt, 0);
   } else {
      if(bNegative) {
         QCBOREncode_Private_AddTNegativeBigNumber(pMe, uTagRequirement, BigNumberNLZ);
      } else {
         QCBOREncode_AddTBigNumberRaw(pMe, false, uTagRequirement, BigNumberNLZ);
      }
   }
}




#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
/**
 * @brief  Semi-private method to add bigfloats and decimal fractions.
 *
 * @param[in] pMe               The encoding context to add the value to.
 * @param[in] uTagNumber               The type 6 tag indicating what this is to be.
 * @param[in] nMantissa          The @c int64_t mantissa if it is not a big number.
 * @param[in] nExponent          The exponent.
 *
 * This outputs either the @ref CBOR_TAG_DECIMAL_FRACTION or
 * @ref CBOR_TAG_BIGFLOAT tag. if @c uTag is @ref CBOR_TAG_INVALID64,
 * then this outputs the "borrowed" content format.
 *
 * The tag content output by this is an array with two members, the
 * exponent and then the mantissa. The mantissa can be either a big
 * number or an @c int64_t.
 *
 * This implementation cannot output an exponent further from 0 than
 * @c INT64_MAX.
 *
 * To output a mantissa that is between INT64_MAX and UINT64_MAX from 0,
 * it must be as a big number.
 *
 * Typically, QCBOREncode_AddTDecimalFraction(), QCBOREncode_AddTBigFloat(),
 * QCBOREncode_AddTDecimalFractionBigNum() or QCBOREncode_AddTBigFloatBigNum()
 * is called instead of this.
 */
void
QCBOREncode_Private_AddTExpIntMantissa(QCBOREncodeContext *pMe,
                                       const int           uTagRequirement,
                                       const uint64_t      uTagNumber,
                                       const int64_t       nExponent,
                                       const int64_t       nMantissa)
{
   /* This is for encoding either a big float or a decimal fraction,
    * both of which are an array of two items, an exponent and a
    * mantissa.  The difference between the two is that the exponent
    * is base-2 for big floats and base-10 for decimal fractions, but
    * that has no effect on the code here.
    */
   /* Separate from QCBOREncode_Private_AddTExpBigMantissa() because
    * linking QCBOREncode_AddTBigNumber() adds a lot because it
    * does preferred serialization of big numbers and the offset of 1
    * for CBOR negative numbers.
    */
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, uTagNumber);
   }
   QCBOREncode_OpenArray(pMe);
   QCBOREncode_AddInt64(pMe, nExponent);
   QCBOREncode_AddInt64(pMe, nMantissa);
   QCBOREncode_CloseArray(pMe);
}

void
QCBOREncode_Private_AddTExpBigMantissa(QCBOREncodeContext *pMe,
                                       const int           uTagRequirement,
                                       const uint64_t      uTagNumber,
                                       const int64_t       nExponent,
                                       const UsefulBufC    BigNumMantissa,
                                       const bool          bBigNumIsNegative)
{
   /* This is for encoding either a big float or a decimal fraction,
    * both of which are an array of two items, an exponent and a
    * mantissa.  The difference between the two is that the exponent
    * is base-2 for big floats and base-10 for decimal fractions, but
    * that has no effect on the code here.
    */
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, uTagNumber);
   }
   QCBOREncode_OpenArray(pMe);
   QCBOREncode_AddInt64(pMe, nExponent);
   QCBOREncode_AddTBigNumber(pMe, QCBOR_ENCODE_AS_TAG, bBigNumIsNegative, BigNumMantissa);
   QCBOREncode_CloseArray(pMe);
}


void
QCBOREncode_Private_AddTExpBigMantissaRaw(QCBOREncodeContext *pMe,
                                          const int           uTagRequirement,
                                          const uint64_t      uTagNumber,
                                          const int64_t       nExponent,
                                          const UsefulBufC    BigNumMantissa,
                                          const bool          bBigNumIsNegative)
{
   /* This is for encoding either a big float or a decimal fraction,
    * both of which are an array of two items, an exponent and a
    * mantissa.  The difference between the two is that the exponent
    * is base-2 for big floats and base-10 for decimal fractions, but
    * that has no effect on the code here.
    */
   /* Separate from QCBOREncode_Private_AddTExpBigMantissa() because
    * linking QCBOREncode_AddTBigNumber() adds a lot because it
    * does preferred serialization of big numbers and the offset of 1
    * for CBOR negative numbers.
    */
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, uTagNumber);
   }
   QCBOREncode_OpenArray(pMe);
   QCBOREncode_AddInt64(pMe, nExponent);
   QCBOREncode_AddTBigNumberRaw(pMe, QCBOR_ENCODE_AS_TAG, bBigNumIsNegative, BigNumMantissa);
   QCBOREncode_CloseArray(pMe);
}

#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */

