/*==============================================================================
 ieee754.c -- floating-point conversion between half, double & single-precision

 Copyright (c) 2018-2020, Laurence Lundblade. All rights reserved.
 Copyright (c) 2021, Arm Limited. All rights reserved.

 SPDX-License-Identifier: BSD-3-Clause

 See BSD-3-Clause license in README.md

 Created on 7/23/18
 =============================================================================*/

/*
 Include before QCBOR_DISABLE_PREFERRED_FLOAT is checked as
 QCBOR_DISABLE_PREFERRED_FLOAT might be defined in qcbor/qcbor_common.h
 */
#include "qcbor/qcbor_common.h"

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT

#include "ieee754.h"
#include <string.h> // For memcpy()


/*
 This code is written for clarity and verifiability, not for size, on
 the assumption that the optimizer will do a good job. The LLVM
 optimizer, -Os, does seem to do the job and the resulting object code
 is smaller from combining code for the many different cases (normal,
 subnormal, infinity, zero...) for the conversions. GCC is no where near
 as good.

 This code has really long lines and is much easier to read because of
 them. Some coding guidelines prefer 80 column lines (can they not afford
 big displays?). It would make this code much worse even to wrap at 120
 columns.

 Dead stripping is also really helpful to get code size down when
 floating-point encoding is not needed. (If this is put in a library
 and linking is against the library, then dead stripping is automatic).

 This code works solely using shifts and masks and thus has no
 dependency on any math libraries. It can even work if the CPU doesn't
 have any floating-point support, though that isn't the most useful
 thing to do.

 The memcpy() dependency is only for CopyFloatToUint32() and friends
 which only is needed to avoid type punning when converting the actual
 float bits to an unsigned value so the bit shifts and masks can work.
 */

/*
 The references used to write this code:

 - IEEE 754-2008, particularly section 3.6 and 6.2.1

 - https://en.wikipedia.org/wiki/IEEE_754 and subordinate pages

 - https://stackoverflow.com/questions/19800415/why-does-ieee-754-reserve-so-many-nan-values

 - https://stackoverflow.com/questions/46073295/implicit-type-promotion-rules

 - https://stackoverflow.com/questions/589575/what-does-the-c-standard-state-the-size-of-int-long-type-to-be
 */



/*
 IEEE754_FloatToDouble(uint32_t uFloat) was created but is not needed. It can be retrieved from
github history if needed.
*/




// ----- Half Precsion -----------
#define HALF_NUM_SIGNIFICAND_BITS (10)
#define HALF_NUM_EXPONENT_BITS    (5)
#define HALF_NUM_SIGN_BITS        (1)

#define HALF_SIGNIFICAND_SHIFT    (0)
#define HALF_EXPONENT_SHIFT       (HALF_NUM_SIGNIFICAND_BITS)
#define HALF_SIGN_SHIFT           (HALF_NUM_SIGNIFICAND_BITS + HALF_NUM_EXPONENT_BITS)

#define HALF_SIGNIFICAND_MASK     (0x3ffU) // The lower 10 bits  // 0x03ff
#define HALF_EXPONENT_MASK        (0x1fU << HALF_EXPONENT_SHIFT) // 0x7c00 5 bits of exponent
#define HALF_SIGN_MASK            (0x01U << HALF_SIGN_SHIFT) //  // 0x8000 1 bit of sign
#define HALF_QUIET_NAN_BIT        (0x01U << (HALF_NUM_SIGNIFICAND_BITS-1)) // 0x0200

/* Biased    Biased    Unbiased   Use
    0x00       0        -15       0 and subnormal
    0x01       1        -14       Smallest normal exponent
    0x1e      30         15       Largest normal exponent
    0x1F      31         16       NaN and Infinity  */
#define HALF_EXPONENT_BIAS        (15)
#define HALF_EXPONENT_MAX         (HALF_EXPONENT_BIAS)    //  15 Unbiased
#define HALF_EXPONENT_MIN         (-HALF_EXPONENT_BIAS+1) // -14 Unbiased
#define HALF_EXPONENT_ZERO        (-HALF_EXPONENT_BIAS)   // -15 Unbiased
#define HALF_EXPONENT_INF_OR_NAN  (HALF_EXPONENT_BIAS+1)  //  16 Unbiased


// ------ Single-Precision --------
#define SINGLE_NUM_SIGNIFICAND_BITS (23)
#define SINGLE_NUM_EXPONENT_BITS    (8)
#define SINGLE_NUM_SIGN_BITS        (1)

#define SINGLE_SIGNIFICAND_SHIFT    (0)
#define SINGLE_EXPONENT_SHIFT       (SINGLE_NUM_SIGNIFICAND_BITS)
#define SINGLE_SIGN_SHIFT           (SINGLE_NUM_SIGNIFICAND_BITS + SINGLE_NUM_EXPONENT_BITS)

#define SINGLE_SIGNIFICAND_MASK     (0x7fffffU) // The lower 23 bits
#define SINGLE_EXPONENT_MASK        (0xffU << SINGLE_EXPONENT_SHIFT) // 8 bits of exponent
#define SINGLE_SIGN_MASK            (0x01U << SINGLE_SIGN_SHIFT) // 1 bit of sign
#define SINGLE_QUIET_NAN_BIT        (0x01U << (SINGLE_NUM_SIGNIFICAND_BITS-1))

/* Biased  Biased   Unbiased  Use
    0x0000     0     -127      0 and subnormal
    0x0001     1     -126      Smallest normal exponent
    0x7f     127        0      1
    0xfe     254      127      Largest normal exponent
    0xff     255      128      NaN and Infinity  */
#define SINGLE_EXPONENT_BIAS        (127)
#define SINGLE_EXPONENT_MAX         (SINGLE_EXPONENT_BIAS)    //  127 unbiased
#define SINGLE_EXPONENT_MIN         (-SINGLE_EXPONENT_BIAS+1) // -126 unbiased
#define SINGLE_EXPONENT_ZERO        (-SINGLE_EXPONENT_BIAS)   // -127 unbiased
#define SINGLE_EXPONENT_INF_OR_NAN  (SINGLE_EXPONENT_BIAS+1)  //  128 unbiased


// --------- Double-Precision ----------
#define DOUBLE_NUM_SIGNIFICAND_BITS (52)
#define DOUBLE_NUM_EXPONENT_BITS    (11)
#define DOUBLE_NUM_SIGN_BITS        (1)

#define DOUBLE_SIGNIFICAND_SHIFT    (0)
#define DOUBLE_EXPONENT_SHIFT       (DOUBLE_NUM_SIGNIFICAND_BITS)
#define DOUBLE_SIGN_SHIFT           (DOUBLE_NUM_SIGNIFICAND_BITS + DOUBLE_NUM_EXPONENT_BITS)

#define DOUBLE_SIGNIFICAND_MASK     (0xfffffffffffffULL) // The lower 52 bits
#define DOUBLE_EXPONENT_MASK        (0x7ffULL << DOUBLE_EXPONENT_SHIFT) // 11 bits of exponent
#define DOUBLE_SIGN_MASK            (0x01ULL << DOUBLE_SIGN_SHIFT) // 1 bit of sign
#define DOUBLE_QUIET_NAN_BIT        (0x01ULL << (DOUBLE_NUM_SIGNIFICAND_BITS-1))


/* Biased      Biased   Unbiased  Use
   0x00000000     0     -1023     0 and subnormal
   0x00000001     1     -1022     Smallest normal exponent
   0x000007fe  2046      1023     Largest normal exponent
   0x000007ff  2047      1024     NaN and Infinity  */
#define DOUBLE_EXPONENT_BIAS        (1023)
#define DOUBLE_EXPONENT_MAX         (DOUBLE_EXPONENT_BIAS)    // unbiased
#define DOUBLE_EXPONENT_MIN         (-DOUBLE_EXPONENT_BIAS+1) // unbiased
#define DOUBLE_EXPONENT_ZERO        (-DOUBLE_EXPONENT_BIAS)   // unbiased
#define DOUBLE_EXPONENT_INF_OR_NAN  (DOUBLE_EXPONENT_BIAS+1)  // unbiased



/*
 Convenient functions to avoid type punning, compiler warnings and
 such. The optimizer reduces them to a simple assignment.  This is a
 crusty corner of C. It shouldn't be this hard.

 These are also in UsefulBuf.h under a different name. They are copied
 here to avoid a dependency on UsefulBuf.h. There is no object code
 size impact because these always optimze down to a simple assignment.
 */
static inline uint32_t
CopyFloatToUint32(float f)
{
    uint32_t u32;
    memcpy(&u32, &f, sizeof(uint32_t));
    return u32;
}

static inline uint64_t
CopyDoubleToUint64(double d)
{
    uint64_t u64;
    memcpy(&u64, &d, sizeof(uint64_t));
    return u64;
}

static inline double
CopyUint64ToDouble(uint64_t u64)
{
    double d;
    memcpy(&d, &u64, sizeof(uint64_t));
    return d;
}

static inline float
CopyUint32ToSingle(uint32_t u32)
{
    float f;
    memcpy(&f, &u32, sizeof(uint32_t));
    return f;
}



/*
  EEE754_HalfToFloat() and others were created but are not needed. They can be retrieved from
  github history if needed.
 */


// Public function; see ieee754.h
double
IEEE754_HalfToDouble(uint16_t uHalfPrecision)
{
    // Pull out the three parts of the half-precision float.  Do all
    // the work in 64 bits because that is what the end result is.  It
    // may give smaller code size and will keep static analyzers
    // happier.
    const uint64_t uHalfSignificand      = uHalfPrecision & HALF_SIGNIFICAND_MASK;
    const int64_t  nHalfUnBiasedExponent = (int64_t)((uHalfPrecision & HALF_EXPONENT_MASK) >> HALF_EXPONENT_SHIFT) - HALF_EXPONENT_BIAS;
    const uint64_t uHalfSign             = (uHalfPrecision & HALF_SIGN_MASK) >> HALF_SIGN_SHIFT;


    // Make the three parts of hte single-precision number
    uint64_t uDoubleSignificand, uDoubleSign, uDoubleBiasedExponent;
    if(nHalfUnBiasedExponent == HALF_EXPONENT_ZERO) {
        // 0 or subnormal
        uDoubleBiasedExponent = DOUBLE_EXPONENT_ZERO + DOUBLE_EXPONENT_BIAS;
        if(uHalfSignificand) {
            // Subnormal case
            uDoubleBiasedExponent = -HALF_EXPONENT_BIAS + DOUBLE_EXPONENT_BIAS +1;
            // A half-precision subnormal can always be converted to a
            // normal double-precision float because the ranges line
            // up
            uDoubleSignificand = uHalfSignificand;
            // Shift bits from right of the decimal to left, reducing
            // the exponent by 1 each time
            do {
                uDoubleSignificand <<= 1;
                uDoubleBiasedExponent--;
            } while ((uDoubleSignificand & 0x400) == 0);
            uDoubleSignificand &= HALF_SIGNIFICAND_MASK;
            uDoubleSignificand <<= (DOUBLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS);
        } else {
            // Just zero
            uDoubleSignificand = 0;
        }
    } else if(nHalfUnBiasedExponent == HALF_EXPONENT_INF_OR_NAN) {
        // NaN or Inifinity
        uDoubleBiasedExponent = DOUBLE_EXPONENT_INF_OR_NAN + DOUBLE_EXPONENT_BIAS;
        if(uHalfSignificand) {
            // NaN
            // First preserve the NaN payload from half to single
            uDoubleSignificand = uHalfSignificand & ~HALF_QUIET_NAN_BIT;
            if(uHalfSignificand & HALF_QUIET_NAN_BIT) {
                // Next, set qNaN if needed since half qNaN bit is not
                // copied above
                uDoubleSignificand |= DOUBLE_QUIET_NAN_BIT;
            }
        } else {
            // Infinity
            uDoubleSignificand = 0;
        }
    } else {
        // Normal number
        uDoubleBiasedExponent = (uint64_t)(nHalfUnBiasedExponent + DOUBLE_EXPONENT_BIAS);
        uDoubleSignificand    = uHalfSignificand << (DOUBLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS);
    }
    uDoubleSign = uHalfSign;


    // Shift the 3 parts into place as a double-precision
    const uint64_t uDouble = uDoubleSignificand |
                            (uDoubleBiasedExponent << DOUBLE_EXPONENT_SHIFT) |
                            (uDoubleSign << DOUBLE_SIGN_SHIFT);
    return CopyUint64ToDouble(uDouble);
}






static uint32_t
IEEE754_AssembleHalf(uint32_t uHalfSign, uint32_t uHalfSignificand, int32_t nHalfUnBiasedExponent)
{
    return uHalfSignificand |
          ((uint32_t)(nHalfUnBiasedExponent + HALF_EXPONENT_BIAS) << HALF_EXPONENT_SHIFT) |
          (uHalfSign << HALF_SIGN_SHIFT);
}


// Public function; see ieee754.h
IEEE754_union
IEEE754_SingleToHalf(float f)
{
    IEEE754_union result;

    /*  Pull the need parts out of the single-precision float */
    const uint32_t uSingle                 = CopyFloatToUint32(f);
    const int32_t  nSingleUnbiasedExponent = (int32_t)((uSingle & SINGLE_EXPONENT_MASK) >> SINGLE_EXPONENT_SHIFT) - SINGLE_EXPONENT_BIAS;
    const uint32_t uSingleSignificand      = uSingle & SINGLE_SIGNIFICAND_MASK;
    const uint32_t uSingleSign             = (uSingle & SINGLE_SIGN_MASK) >> SINGLE_SIGN_SHIFT;

    // All works is done on uint32_t with conversion to uint16_t at
    // the end.  This avoids integer promotions that static analyzers
    // complain about and reduces code size.


    if(nSingleUnbiasedExponent == SINGLE_EXPONENT_ZERO) {
        if(uSingleSignificand == 0) {
            /* --- ZERO --- */
            result.uSize  = IEEE754_UNION_IS_HALF;
            result.uValue = IEEE754_AssembleHalf(uSingleSign, 0, HALF_EXPONENT_ZERO);

        } else {
            /* --- SUBNORMAL --- */
            /* Subnormals are always too small to convert to a half precision */
            /* TODO: how do we know this is true? Comparing decimal ranges in Wikipedia confirms, but want to understand in binary */
            result.uSize   = IEEE754_UNION_IS_SINGLE;
            result.uValue  = uSingle;
         }
    } else if(nSingleUnbiasedExponent == SINGLE_EXPONENT_INF_OR_NAN) {
         if(uSingleSignificand == 0) {
             /* ---- INFINITY ---- */
             result.uSize  = IEEE754_UNION_IS_HALF;
             result.uValue = IEEE754_AssembleHalf(uSingleSign, 0, HALF_EXPONENT_INF_OR_NAN);
         } else {
             /* NAN */
             const uint64_t uDroppedSingleBits = SINGLE_SIGNIFICAND_MASK >> HALF_NUM_SIGNIFICAND_BITS;
             if(!(uSingleSignificand & uDroppedSingleBits)) {
                 /* --- CONVERT TO HALF --- */
                result.uSize  = IEEE754_UNION_IS_HALF;
                result.uValue = IEEE754_AssembleHalf(uSingleSign,
                                                     uSingleSignificand >> (SINGLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS),
                                                     HALF_EXPONENT_INF_OR_NAN);

            } else {
               /* --- CAN NOT CONVERT NAN --- */
               result.uSize   = IEEE754_UNION_IS_SINGLE;
               result.uValue  = uSingle;
            }
         }
    } else {
        /* ---- REGULAR NUMBER ---- */
        /* Check to see if the single-precision exponent is in the range
         * of the half-precision exponent and if any significand bits
         * would be lost in conversion to normal half-precision. */
        if(nSingleUnbiasedExponent >= HALF_EXPONENT_MIN &&
           nSingleUnbiasedExponent <= HALF_EXPONENT_MAX &&
          (uSingleSignificand & (SINGLE_SIGNIFICAND_MASK >> HALF_NUM_SIGNIFICAND_BITS)) == 0) {
            /* --- CONVERT TO NORMAL HALF --- */
            result.uSize  = IEEE754_UNION_IS_HALF;
            result.uValue = IEEE754_AssembleHalf(uSingleSign,
                                                 uSingleSignificand >> (SINGLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS),
                                                 nSingleUnbiasedExponent);
        } else {
            /*

             Exponents -14 to -24 map to a shift of 0 to 10 of the significand.
             The largest value of a half subnormal has an exponent of -14. Subnormals are
             not normalized like normals meaning they lose precision as
             the numbers get smaller. Normals don't lose precision because
             the exponent allows all the bits of the significand to be
             significant.

             */
            /* The exponent of the largest possible half-precision subnormal is HALF_EXPONENT_MIN (-14).
             * Exponents larger than this are normal and handled above. We're going to shift
             * the significand right by at least this amount.
             */
            int nExponentDifference = -(nSingleUnbiasedExponent - HALF_EXPONENT_MIN);

            /* In addition to the shift based on the exponent's value, the single
             * significand has to be shifted right to fit into a half-precision significand */
            int nShiftAmount = nExponentDifference + (SINGLE_NUM_SIGNIFICAND_BITS - HALF_NUM_SIGNIFICAND_BITS);

            /* Must add 1 in to the possible significand because there is an implied 1 for normal values
             * and not for subnormal values. See equations here:  https://en.wikipedia.org/wiki/Single-precision_floating-point_format#Exponent_encoding */
            const uint32_t uPossibleHalfSignificand = (uSingleSignificand + (1 << SINGLE_NUM_SIGNIFICAND_BITS)) >> nShiftAmount;

            /* If only zero bits were shifted out, this can be converted to subnormal */
            if(nSingleUnbiasedExponent < HALF_EXPONENT_MIN &&
               uPossibleHalfSignificand << nShiftAmount == uSingleSignificand + (1 << SINGLE_NUM_SIGNIFICAND_BITS)) {
                /* --- CONVERT TO SUB NORMAL HALF --- */
                result.uSize  = IEEE754_UNION_IS_HALF;
                result.uValue =  IEEE754_AssembleHalf(uSingleSign,
                                                      uPossibleHalfSignificand,
                                                      HALF_EXPONENT_ZERO);
            } else {
               /* --- DO NOT CONVERT --- */
               result.uSize   = IEEE754_UNION_IS_SINGLE;
               result.uValue  = uSingle;
            }
        }
    }

    return result;
}


static uint64_t
IEEE754_AssembleSingle(uint64_t uSingleSign, uint64_t uSingleSignificand, int64_t nSingleUnBiasedExponent)
{
    return uSingleSignificand |
          ((uint64_t)(nSingleUnBiasedExponent + SINGLE_EXPONENT_BIAS) << SINGLE_EXPONENT_SHIFT) |
          (uSingleSign << SINGLE_SIGN_SHIFT);
}


/* Convert a double to a float if it can be done without loss */
static IEEE754_union
IEEE754_DoubeToSingle(double d)
{
    IEEE754_union result;

    /* Pull the three parts out of the double-precision float
     * Most work is done with uint64_t which helps avoid integer promotions
     * and static analyzer complaints.
     */
    const uint64_t uDouble = CopyDoubleToUint64(d);
    const int64_t  nDoubleUnbiasedExponent = (int64_t)((uDouble & DOUBLE_EXPONENT_MASK) >> DOUBLE_EXPONENT_SHIFT) - DOUBLE_EXPONENT_BIAS;
    const uint64_t uDoubleSign             = (uDouble & DOUBLE_SIGN_MASK) >> DOUBLE_SIGN_SHIFT;
    const uint64_t uDoubleSignificand      = uDouble & DOUBLE_SIGNIFICAND_MASK;


    if(nDoubleUnbiasedExponent == DOUBLE_EXPONENT_ZERO) {
        if(uDoubleSignificand == 0) {
            /* --- ZERO --- */
            result.uSize  = IEEE754_UNION_IS_SINGLE;
            result.uValue = IEEE754_AssembleSingle(uDoubleSign, 0, SINGLE_EXPONENT_ZERO);

        } else {
            /* --- SUBNORMAL --- */
            /* Double subnormals are always too small to convert to a single precision */
            /* TODO: how do we know this is true? Comparing decimal ranges in Wikipedia confirms, but want to understand in binary */
            /* Smallest normal double is 10e−308. Smallest subnormal single is 1.4 10e-45, so no subnormal
             * double can fit into a single of any sort.
             * TODO: describe this with exponentiation of 2 */
            result.uSize   = IEEE754_UNION_IS_DOUBLE;
            result.uValue  = uDouble;
         }
    } else if(nDoubleUnbiasedExponent == DOUBLE_EXPONENT_INF_OR_NAN) {
         if(uDoubleSignificand == 0) {
             /* ---- INFINITY ---- */
             result.uSize  = IEEE754_UNION_IS_SINGLE;
             result.uValue = IEEE754_AssembleSingle(uDoubleSign, 0, SINGLE_EXPONENT_INF_OR_NAN);
         } else {
             /* NAN */
             const uint64_t uDroppedSingleBits = DOUBLE_SIGNIFICAND_MASK >> SINGLE_NUM_SIGNIFICAND_BITS;
             if(!(uDoubleSignificand & uDroppedSingleBits)) {
                 /* --- CONVERT TO SINGLE --- */
                result.uSize  = IEEE754_UNION_IS_SINGLE;
                result.uValue = IEEE754_AssembleSingle(uDoubleSign,
                                                       uDoubleSignificand >> (DOUBLE_NUM_SIGNIFICAND_BITS - SINGLE_NUM_SIGNIFICAND_BITS),
                                                       SINGLE_EXPONENT_INF_OR_NAN);
            } else {
               /* --- CAN NOT CONVERT NAN --- */
               result.uSize   = IEEE754_UNION_IS_DOUBLE;
               result.uValue  = uDouble;
            }
         }
    } else {
        /* ---- REGULAR NUMBER ---- */
        if(nDoubleUnbiasedExponent >= SINGLE_EXPONENT_MIN &&
           nDoubleUnbiasedExponent <= SINGLE_EXPONENT_MAX &&
          (uDoubleSignificand & (DOUBLE_SIGNIFICAND_MASK >> SINGLE_NUM_SIGNIFICAND_BITS)) == 0) {
            /* --- CONVERT TO NORMAL HALF --- */
            result.uSize  = IEEE754_UNION_IS_SINGLE;
            result.uValue = IEEE754_AssembleSingle(uDoubleSign,
                                                   uDoubleSignificand >> (DOUBLE_NUM_SIGNIFICAND_BITS - SINGLE_NUM_SIGNIFICAND_BITS),
                                                   nDoubleUnbiasedExponent);
        } else {
            int64_t nExponentDifference = -(nDoubleUnbiasedExponent - SINGLE_EXPONENT_MIN);
            int64_t nShiftAmount = nExponentDifference + (DOUBLE_NUM_SIGNIFICAND_BITS - SINGLE_NUM_SIGNIFICAND_BITS);
            const uint64_t uPossibleSingleSignificand = (uDoubleSignificand + (1ULL << DOUBLE_NUM_SIGNIFICAND_BITS)) >> nShiftAmount;

            if(nDoubleUnbiasedExponent < SINGLE_EXPONENT_MIN &&
               uPossibleSingleSignificand << nShiftAmount == uDoubleSignificand + (1ULL << DOUBLE_NUM_SIGNIFICAND_BITS)) {
                /* --- CONVERT TO SUB NORMAL HALF --- */
                result.uSize  = IEEE754_UNION_IS_SINGLE;
                result.uValue = IEEE754_AssembleSingle(uDoubleSign,
                                                       uPossibleSingleSignificand,
                                                       SINGLE_EXPONENT_ZERO);
            } else {
               /* --- DO NOT CONVERT --- */
               result.uSize   = IEEE754_UNION_IS_DOUBLE;
               result.uValue  = uDouble;
            }
        }
    }

    return result;
}



/* Public function; see ieee754.h */
IEEE754_union
IEEE754_DoubleToSmaller(double d, int bAllowHalfPrecision)
{
    IEEE754_union result;

    result = IEEE754_DoubeToSingle(d);

    if(result.uSize == IEEE754_UNION_IS_SINGLE && bAllowHalfPrecision) {
        /* Cast to uint32_t is OK, because value was just successfully converted to single */
        float uSingle = CopyUint32ToSingle((uint32_t)result.uValue);
        result = IEEE754_SingleToHalf(uSingle);
    }

    return result;
}


#else

int x;

#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
