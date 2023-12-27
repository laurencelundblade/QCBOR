/*==============================================================================
 ieee754.h -- floating-point conversion between half, double & single-precision

 Copyright (c) 2018-2024, Laurence Lundblade. All rights reserved.

 SPDX-License-Identifier: BSD-3-Clause

 See BSD-3-Clause license in README.md

 Created on 7/23/18
 =============================================================================*/

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT

#ifndef ieee754_h
#define ieee754_h

#include <stdint.h>



/*
 General comments

 This is a complete in that it handles all conversion cases including
 +/- infinity, +/- zero, subnormal numbers, qNaN, sNaN and NaN
 payloads.

 This conforms to IEEE 754-2008, but note that this doesn't specify
 conversions, just the encodings.

 NaN payloads are preserved with alignment on the LSB. The qNaN bit is
 handled differently and explicity copied. It is always the MSB of the
 significand. The NaN payload MSBs (except the qNaN bit) are truncated
 when going from double or single to half.

 TODO: what does the C cast do with NaN payloads from
 double to single? It probably depends entirely on the
 CPU.

 */

/*
 Most simply just explicilty encode the type you want, single or
 double.  This works easily everywhere since standard C supports both
 these types and so does qcbor.  This encoder also supports half
 precision and there's a few ways to use it to encode floating-point
 numbers in less space.

 Without losing precision, you can encode a single or double such that
 the special values of 0, NaN and Infinity encode as half-precision.
 This CBOR decodoer and most others should handle this properly.

 If you don't mind losing precision, then you can use half-precision.
 One way to do this is to set up your environment to use
 ___fp_16. Some compilers and CPUs support it even though it is not
 standard C. What is nice about this is that your program will use
 less memory and floating-point operations like multiplying, adding
 and such will be faster.

 Another way to make use of half-precision is to represent the values
 in your program as single or double, but encode them in CBOR as
 half-precision. This cuts the size of the encoded messages by 2 or 4,
 but doesn't reduce memory needs or speed because you are still using
 single or double in your code.

 */




/**
 * @brief Convert half-precision float to double-precision float.
 *
 * @param[in] uHalfPrecision   Half-prevision number to convert
 *
 * @returns double-presion value.
 *
 * This is a loss-less conversion because every half-precision
 * value can be represented as a double.
 *
 * There is no half-precision type in C, so it is represented
 * here as a uint16_t. The bits of @c uHalfPrecision are
 * as described for half-precision by IEEE 754.
 */
double
IEEE754_HalfToDouble(uint16_t uHalfPrecision);


/* Indicates type and size of uvalue */
// TODO: make this enum?
#define IEEE754_UNION_IS_HALF   2
#define IEEE754_UNION_IS_SINGLE 4
#define IEEE754_UNION_IS_DOUBLE 8

/** Holds a floating-point value that could be half, single or double-precision.
 * The value is in a uint64_t that may be copied to a float or double.
 * Simply casting uValue will usually work but may generate compiler or
 * static analyzer warnings. Using UsefulBufUtil_CopyUint64ToDouble()
 * or UsefulBufUtil_CopyUint32ToFloat() will not (and will not generate any extra code).
 */
typedef struct {
    uint8_t  uSize;  /* One of IEEE754_IS_xxxx */
    uint64_t uValue;
} IEEE754_union;


/**
 * @brief Convert a double to either single or half-precision.
 *
 * @param[in] d    The value to convert.
 * @param[in] bAllowHalfPrecision  If true, convert to either half or single precision.
 *
 * @returns Converted value.
 *
 * This always succeeds. If the value cannot be converted without the
 * loss of precision, it is not converted.
 *
 * This handles subnormals and NaN payloads.
 */
IEEE754_union
IEEE754_DoubleToSmaller(double d, int bAllowHalfPrecision);


/**
 * @brief Convert a single-precision float to half-precision.
 *
 * @param[in] f    The value to convert.
 *
 * @returns Converted value.
 *
 * This always succeeds. If the value cannot be converted without the
 * loss of precision, it is not converted.
 *
 * This handles subnormals and NaN payloads.
 */
IEEE754_union
IEEE754_SingleToHalf(float f);


#endif /* ieee754_h */


#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */




