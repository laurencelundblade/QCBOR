/* ==========================================================================
 * ieee754.h -- Conversion between half, double & single-precision floats
 *
 * Copyright (c) 2018-2026, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in file named "LICENSE"
 *
 * Created on 7/23/18
 * ========================================================================== */


#ifndef ieee754_h
#define ieee754_h

#include <stdint.h>


/** @file ieee754.h
 *
 * This implements floating-point conversion between half, single and
 * double precision floating-point numbers, in particular conversion to
 * smaller representation (e.g., double to single) that does not lose
 * precision for CBOR preferred serialization.
 *
 * This also implements conversion of floats to whole numbers as
 * is required for dCBOR.
 *
 * This implementation works entirely with shifts and masks and does
 * not require any floating-point HW or library.
 *
 * This conforms to IEEE 754-2008, but note that it doesn't specify
 * conversions, just the encodings.
 *
 * This supports +/- inifinity, +/-0, subnormals and some NaNs.
 * For conversions from smaller to larger, NaN payloads are
 * supported. Conversion from larger to smaller always
 * results in a half-precision quiet NaN.
 *
 * A previous version of this was usable as a general library for
 * conversion. This version is reduced to what is needed for CBOR.
 */

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT

/**
 * @brief Convert half-precision float to double-precision float.
 *
 * @param[in] uHalfPrecision   Half-precision number to convert.
 *
 * @returns double-precision value.
 *
 * This is a lossless conversion because every half-precision value
 * can be represented as a double. There is no error condition.
 *
 * There is no half-precision type in C, so it is represented here as
 * a @c uint16_t. The bits of @c uHalfPrecision are as described for
 * half-precision by IEEE 754.
 */
double
IEEE754_HalfToDouble(uint16_t uHalfPrecision);


/**
 * @brief Convert single-precision float to double-precision float.
 *
 * @param[in] uSingle   float bits copied to a uint32_t.
 *
 * @returns double-precision value.
 *
 * This is a lossless conversion because every single-precision value
 * can be represented as a double. There is no error condition.
 *
 * This is in lieu of a cast that usually results in CPU instructions
 * that convert. These instructions don't reliably handle NaN payloads.
 * This does.
 */
double
IEEE754_SingleToDouble(uint32_t uSingle);


/** Holds a floating-point value that could be half, single or
 * double-precision.  The value is in a @c uint64_t that may be copied
 * to a float or double.  Simply casting uValue will usually work but
 * may generate compiler or static analyzer warnings. Using
 * UsefulBufUtil_CopyUint64ToDouble() or
 * UsefulBufUtil_CopyUint32ToFloat() will not (and will not generate
 * any extra code).
 */
typedef struct {
   enum {IEEE754_UNION_IS_HALF   = 2,
         IEEE754_UNION_IS_SINGLE = 4,
         IEEE754_UNION_IS_DOUBLE = 8,
   } uSize; /* Size of uValue */
   uint64_t uValue;
} IEEE754_union;


/** Holds result of an attempt to convert a floating-point
 * number to an int64_t or uint64_t.
 */
struct IEEE754_ToInt {
   enum {IEEE754_ToInt_IS_INT,
         IEEE754_ToInt_IS_UINT,
         IEEE754_ToInt_IS_65BIT_NEG,
         IEEE754_ToInt_NO_CONVERSION,
         IEEE754_ToInt_NaN
   } type;
   union {
      uint64_t un_signed;
      int64_t  is_signed;
   } integer;
};


/**
 * @brief Convert a double to either single or half-precision.
 *
 * @param[in] d                    The value to convert.
 *
 * @returns Unconverted value, or value converted to single or half-precision.
 *
 * This always succeeds. If the value cannot be converted without the
 * loss of precision, it is not converted.
 *
 * This handles all subnormals.
 */
IEEE754_union
IEEE754_DoubleToSmaller(double d);


/**
 * @brief Convert a single-precision float to half-precision.
 *
 * @param[in] uSingle  type @c float bits copied to a uint32_t.
 *
 * @returns Either unconverted value or value converted to half-precision.
 *
 * This always succeeds. If the value cannot be converted without the
 * loss of precision, it is not converted.
 *
 * This handles all subnormals.
 */
IEEE754_union
IEEE754_SingleToHalf(uint32_t uSingle);


/**
 * @brief Convert a double-precision float to an integer if whole number
 *
 * @param[in] d  The value to convert.
 *
 * @returns Either converted number or conversion status.
 *
 * If the value is a whole number that will fit either in a uint64_t
 * or an int64_t, it is converted. If it is a NaN, then there is no
 * conversion and the fact that it is a NaN is indicated in the
 * returned structure.  If it can't be converted, then that is
 * indicated in the returned structure.
 *
 * This always returns positive numbers as a uint64_t even if they will
 * fit in an int64_t.
 *
 * This never fails because of precision, but may fail because of range.
 */
struct IEEE754_ToInt
IEEE754_DoubleToInt(double d);


/**
 * @brief Convert a single-precision float to an integer if whole number
 *
 * @param[in] uSingle  Type @c float bits copied to a uint32_t.
 *
 * @returns Either converted number or conversion status.
 *
 * If the value is a whole number that will fit either in a uint64_t
 * or an int64_t, it is converted. If it is a NaN, then there is no
 * conversion and the fact that it is a NaN is indicated in the
 * returned structure.  If it can't be converted, then that is
 * indicated in the returned structure.
 *
 * This always returns positive numbers as a uint64_t even if they will
 * fit in an int64_t.
 *
 * This never fails because of precision, but may fail because of range.
 */
struct IEEE754_ToInt
IEEE754_SingleToInt(uint32_t uSingle);


/**
 * @brief Convert an unsigned integer to a double with no precision loss.
 *
 * @param[in] uInt  The value to convert.
 * @param[in] uIsNegative   0 if positive, 1 if negative.
 *
 * @returns Either the converted number or 0.5 if no conversion.
 *
 * The conversion will fail if the input can not be represented in the
 * 52 bits or precision that a double has. 0.5 is returned to indicate
 * no conversion. It is out-of-band from non-error results, because
 * all non-error results are whole integers.
 */
#define IEEE754_UINT_TO_DOUBLE_OOB 0.5
double
IEEE754_UintToDouble(uint64_t uInt, int uIsNegative);


#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */


/**
 * @brief Tests whether NaN is other than a positive quiet NaN.
 *
 * @param[in] dNum   Double number to test.
 *
 * @returns 0 if a non-trvial Nan, 1 if not.
 *
 * A trivial NaN is:
 *  - a NaN
 *  - sign bit doesn't indicate negative
 *  - the highest bit of the significand is 1 and the rest are zero.
 *
 * That is, a NaN not represented by 0x7ff8000000000000.
 */
 int
IEEE754_DoubleIsNonTrivialNaN(double dNum);


/**
 * @brief Tests whether NaN is other than a positive quiet NaN.
 *
 * @param[in] uSingle  type @c float bits copied to a uint32_t.
 *
 * @returns 0 if a non-trvial Nan, 1 if not.
 *
 * See IEEE754_DoubleIsNonTrivialNaN(). A single precision quiet NaN
 * is 0x7fc00000.
 */
int
IEEE754_SingleIsNonTrivialNaN(uint32_t uSingle);


#endif /* ieee754_h */

