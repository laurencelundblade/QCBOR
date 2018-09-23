/*==============================================================================
 Copyright 2018 Laurence Lundblade
 
 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the
 "Software"), to deal in the Software without restriction, including
 without limitation the rights to use, copy, modify, merge, publish,
 distribute, sublicense, and/or sell copies of the Software, and to
 permit persons to whom the Software is furnished to do so, subject to
 the following conditions:
 
 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 
 (This is the MIT license)
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

uint16_t IEEE754_FloatToHalf(float f);

float IEEE754_HalfToFloat(uint16_t uHalfPrecision);

uint16_t IEEE754_DoubleToHalf(double d);

double IEEE754_HalfToDouble(uint16_t uHalfPrecision);




#define IEEE754_UNION_IS_HALF   0
#define IEEE754_UNION_IS_SINGLE 1
#define IEEE754_UNION_IS_DOUBLE 2

typedef struct {
    uint8_t uTag;  // One of IEEE754_IS_xxxx
    union {
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
    };
} IEEE754_union;


IEEE754_union IEEE754_DoubleToSmallestInternal(double d, int bAllowHalfPrecision);

/*
 Converts double-precision to half- or single-precision if possible without
 loss of precision. If not, leaves it as a double.
 */
static inline IEEE754_union IEEE754_DoubleToSmall(double d)
{
    return IEEE754_DoubleToSmallestInternal(d, 0);
}


/*
 Converts double-precision to single-precision if possible without
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







