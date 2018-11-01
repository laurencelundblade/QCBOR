/*==============================================================================
 
 Copyright (c) 2018, Laurence Lundblade.
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are
 met:
 * Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above
 copyright notice, this list of conditions and the following
 disclaimer in the documentation and/or other materials provided
 with the distribution.
 * Neither the name of The Linux Foundation nor the names of its
 contributors, nor the name "Laurence Lundblade" may be used to
 endorse or promote products derived from this software without
 specific prior written permission.
 
 THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ==============================================================================*/
//
//  ieee754.h
//  Indefinite
//
//  Created by Laurence Lundblade on 7/23/18.
//  Copyright © 2018 Laurence Lundblade. All rights reserved.
//

#ifndef ieee754_h
#define ieee754_h

#include <stdint.h>



/*
 General comments
 
 This is a complete in that it handles all conversion cases
 including +/- infinity, +/- zero, subnormal numbers, qNaN, sNaN
 and NaN payloads.
 
 This confirms to IEEE 754-2008, but note that this doesn't
 specify conversions, just the encodings.
 
 NaN payloads are preserved with alignment on the LSB. The
 qNaN bit is handled differently and explicity copied. It
 is always the MSB of the significand. The NaN payload MSBs
 (except the qNaN bit) are truncated when going from
 double or single to half.
 
 TODO: what does the C cast do with NaN payloads from
 double to single?
 
 
 
 */

/*
 Most simply just explicilty encode the type you want, single or double.
 This works easily everywhere since standard C supports both
 these types and so does qcbor.  This encoder also supports
 half precision and there's a few ways to use it to encode
 floating point numbers in less space.
 
 Without losing precision, you can encode a single or double
 such that the special values of 0, NaN and Infinity encode
 as half-precision.  This CBOR decodoer and most others
 should handle this properly.
 
 If you don't mind losing precision, then you can use half-precision.
 One way to do this is to set up your environment to use
 ___fp_16. Some compilers and CPUs support it even though it is not
 standard C. What is nice about this is that your program
 will use less memory and floating point operations like
 multiplying, adding and such will be faster.
 
 Another way to make use of half-precision is to represent
 the values in your program as single or double, but encode
 them in CBOR as half-precision. This cuts the size
 of the encoded messages by 2 or 4, but doesn't reduce
 memory needs or speed because you are still using
 single or double in your code.
 

 encode:
    - float as float
    - double as double
    - half as half
 - float as half_precision, for environments that don't support a half-precision type
 - double as half_precision, for environments that don't support a half-precision type
 - float with NaN, Infinity and 0 as half
 - double with NaN, Infinity and 0 as half
 
 
 
 
 */



/*
 Convert single precision float to half-precision float.
 Precision and NaN payload bits will be lost. Too large
 values will round up to infinity and too small to zero.
 */
uint16_t IEEE754_FloatToHalf(float f);


/*
 Convert half precision float to single precision float.
 This is a loss-less conversion.
 */
float IEEE754_HalfToFloat(uint16_t uHalfPrecision);


/*
 Convert double precision float to half-precision float.
 Precision and NaN payload bits will be lost. Too large
 values will round up to infinity and too small to zero.
 */
uint16_t IEEE754_DoubleToHalf(double d);


/*
 Convert half precision float to double precision float.
 This is a loss-less conversion.
 */
double IEEE754_HalfToDouble(uint16_t uHalfPrecision);



// Both tags the value and gives the size
#define IEEE754_UNION_IS_HALF   2
#define IEEE754_UNION_IS_SINGLE 4
#define IEEE754_UNION_IS_DOUBLE 8

typedef struct {
    uint8_t uSize;  // One of IEEE754_IS_xxxx
    uint64_t uValue;
} IEEE754_union;


/*
 Converts double-precision to single-precision or half-precision if possible without
 loss of precisions. If not, leaves it as a double. Only converts to single-precision
 unless bAllowHalfPrecision is set.
 */
IEEE754_union IEEE754_DoubleToSmallestInternal(double d, int bAllowHalfPrecision);

/*
 Converts double-precision to single-precision if possible without
 loss of precision. If not, leaves it as a double.
 */
static inline IEEE754_union IEEE754_DoubleToSmall(double d)
{
    return IEEE754_DoubleToSmallestInternal(d, 0);
}


/*
 Converts double-precision to single-precision or half-precision if possible without
 loss of precisions. If not, leaves it as a double.
 */
static inline IEEE754_union IEEE754_DoubleToSmallest(double d)
{
    return IEEE754_DoubleToSmallestInternal(d, 1);
}

/*
 Converts single-precision to half-precision if possible without
 loss of precision. If not leaves as single-precision.
 */
IEEE754_union IEEE754_FloatToSmallest(float f);


#endif /* ieee754_h */







