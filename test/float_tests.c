/* ==========================================================================
 * float_tests.c -- tests for float and conversion to/from half-precision
 *
 * Copyright (c) 2018-2025, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in file named "LICENSE"
 *
 * Created on 9/19/18
 * ========================================================================= */


#include "float_tests.h"
#include "qcbor/qcbor_main_encode.h"
#include "qcbor/qcbor_number_encode.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "qcbor/qcbor_number_decode.h"
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
#include <math.h> /* For INFINITY and NAN and isnan() */
#endif


/* This is off because it is affected by varying behavior of CPUs,
 * compilers and float libraries. Particularly the qNaN bit
 */
//#define QCBOR_COMPARE_TO_HW_CONVERSION


/* Make a test results code that includes three components. Return code
 * is xxxyyyzzz where zz is the error code, yy is the test number and
 * zz is check being performed
 */
static inline int32_t
MakeTestResultCode(uint32_t   uTestCase,
                   uint32_t   uTestNumber,
                   QCBORError uErrorCode)
{
   uint32_t uCode = (uTestCase * 1000000) +
                    (uTestNumber * 1000) +
                    (uint32_t)uErrorCode;
   return (int32_t)uCode;
}


#include "half_to_double_from_rfc7049.h"


#ifndef USEFULBUF_DISABLE_ALL_FLOAT


/* ----- Half Precsion ----------- */
#define HALF_NUM_SIGNIFICAND_BITS (10)
#define HALF_NUM_EXPONENT_BITS    (5)
#define HALF_NUM_SIGN_BITS        (1)

#define HALF_SIGNIFICAND_SHIFT    (0)
#define HALF_EXPONENT_SHIFT       (HALF_NUM_SIGNIFICAND_BITS)
#define HALF_SIGN_SHIFT           (HALF_NUM_SIGNIFICAND_BITS + HALF_NUM_EXPONENT_BITS)

#define HALF_SIGNIFICAND_MASK     (0x3ffU) // The lower 10 bits
#define HALF_EXPONENT_MASK        (0x1fU << HALF_EXPONENT_SHIFT) // 0x7c00 5 bits of exponent
#define HALF_SIGN_MASK            (0x01U << HALF_SIGN_SHIFT) // 0x8000 1 bit of sign
#define HALF_QUIET_NAN_BIT        (0x01U << (HALF_NUM_SIGNIFICAND_BITS-1)) // 0x0200

/* Biased    Biased    Unbiased   Use
 *  0x00       0        -15       0 and subnormal
 *  0x01       1        -14       Smallest normal exponent
 *  0x1e      30         15       Largest normal exponent
 *  0x1F      31         16       NaN and Infinity  */
#define HALF_EXPONENT_BIAS        (15)
#define HALF_EXPONENT_MAX         (HALF_EXPONENT_BIAS)    //  15 Unbiased
#define HALF_EXPONENT_MIN         (-HALF_EXPONENT_BIAS+1) // -14 Unbiased
#define HALF_EXPONENT_ZERO        (-HALF_EXPONENT_BIAS)   // -15 Unbiased
#define HALF_EXPONENT_INF_OR_NAN  (HALF_EXPONENT_BIAS+1)  //  16 Unbiased


/* ------ Single-Precision -------- */
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
 *  0x0000     0     -127      0 and subnormal
 *  0x0001     1     -126      Smallest normal exponent
 *  0x7f     127        0      1
 *  0xfe     254      127      Largest normal exponent
 *  0xff     255      128      NaN and Infinity  */
#define SINGLE_EXPONENT_BIAS        (127)
#define SINGLE_EXPONENT_MAX         (SINGLE_EXPONENT_BIAS)
#define SINGLE_EXPONENT_MIN         (-SINGLE_EXPONENT_BIAS+1)
#define SINGLE_EXPONENT_ZERO        (-SINGLE_EXPONENT_BIAS)
#define SINGLE_EXPONENT_INF_OR_NAN  (SINGLE_EXPONENT_BIAS+1)

#define SINGLE_NAN_BITS             SINGLE_EXPONENT_MASK /* NAN bits except payload */
#define SINGLE_QNAN                 0x400000
#define SINGLE_SNAN                 0x000000


/* --------- Double-Precision ---------- */
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
 * 0x00000000     0     -1023     0 and subnormal
 * 0x00000001     1     -1022     Smallest normal exponent
 * 0x000007fe  2046      1023     Largest normal exponent
 * 0x000007ff  2047      1024     NaN and Infinity  */
#define DOUBLE_EXPONENT_BIAS        (1023)
#define DOUBLE_EXPONENT_MAX         (DOUBLE_EXPONENT_BIAS)
#define DOUBLE_EXPONENT_MIN         (-DOUBLE_EXPONENT_BIAS+1)
#define DOUBLE_EXPONENT_ZERO        (-DOUBLE_EXPONENT_BIAS)
#define DOUBLE_EXPONENT_INF_OR_NAN  (DOUBLE_EXPONENT_BIAS+1)

#define DOUBLE_NAN_BITS             DOUBLE_EXPONENT_MASK /* NAN bits except payload */
#define DOUBLE_QNAN                 0x8000000000000ULL
#define DOUBLE_SNAN                 0x0000000000000ULL



#ifdef NAN_EXPERIMENT
#include <stdlib.h>
#include <stdio.h>

 int
NaNExperiments(void)
{
   // double dqNaN = UsefulBufUtil_CopyUint64ToDouble(DOUBLE_EXPONENT_MASK | DOUBLE_QUIET_NAN_BIT);
   // double dsNaN = UsefulBufUtil_CopyUint64ToDouble(DOUBLE_EXPONENT_MASK | 0x01);
   // double dqNaNPayload = UsefulBufUtil_CopyUint64ToDouble(DOUBLE_EXPONENT_MASK | DOUBLE_QUIET_NAN_BIT | 0xf00f);


   for(int i = 999; i < 1000; i++) {
      uint64_t x1 = (uint64_t)rand() % SINGLE_SIGNIFICAND_MASK;

      uint64_t uDub = DOUBLE_EXPONENT_MASK | (x1 << (DOUBLE_NUM_SIGNIFICAND_BITS - SINGLE_NUM_SIGNIFICAND_BITS));

      double dd = UsefulBufUtil_CopyUint64ToDouble(uDub);

      float ff = (float)dd;

      uint32_t uu = UsefulBufUtil_CopyFloatToUint32(ff);

      uint64_t x2 = uu & SINGLE_SIGNIFICAND_MASK;

      if(x2 != x1) {
         printf("%d: %llx %llx %llx %llx\n", i, x1, x2, x1 ^ x2, x1 & 0x200000);
      }
   }

#if 0
    float f1 = (float)dqNaN;
    float f2 = (float)dsNaN;
    float f3 = (float)dqNaNPayload;


    uint32_t uqNaN = UsefulBufUtil_CopyFloatToUint32((float)dqNaN);
    uint32_t usNaN = UsefulBufUtil_CopyFloatToUint32((float)dsNaN);
    uint32_t uqNaNPayload = UsefulBufUtil_CopyFloatToUint32((float)dqNaNPayload);

    // Result of this on x86 is that every NaN is a qNaN. The intel
    // CVTSD2SS instruction ignores the NaN payload and even converts
    // a sNaN to a qNaN.
#endif

    return 0;
}
#endif /* NAN_EXPERIMENT */


/* Returns 0 if OK, 1 if not */
static int32_t
HWCheckFloatToDouble(const uint64_t uDoubleToConvert, uint32_t uExpectedSingle)
{
#ifdef QCBOR_COMPARE_TO_HW_CONVERSION
   if(uExpectedSingle) {
      /* This test is off by default. It's purpose is to check
       * QCBOR's mask-n-shift implementation against the HW/CPU
       * instructions that do conversion between double and single.
       * It is off because it is only used on occasion to verify
       * QCBOR and because it is suspected that some HW/CPU does
       * not implement this correctly. NaN payloads are an obscure
       * feature. */
      float    f;
      double   d;
      uint32_t uSingle;

      d = UsefulBufUtil_CopyUint64ToDouble(uDoubleToConvert);

      f = (float)d;

      uSingle = UsefulBufUtil_CopyFloatToUint32(f);

      if(isnan(d)) {
         /* Some (all?) Intel CPUs always set the qNaN bit in conversion */
         uExpectedSingle |= SINGLE_QNAN;
      }

      if(uSingle != uExpectedSingle) {
         return 1;
      }
   }
#else
   (void)uDoubleToConvert;
   (void)uExpectedSingle;
#endif /* QCBOR_COMPARE_TO_HW_CONVERSION */

   return 0;
}

/* Returns 0 if OK, 1 if not */
static int32_t
HWCheckDoubleToFloat(const uint32_t uSingleToConvert, uint64_t uExpectedDouble)
{
#ifdef QCBOR_COMPARE_TO_HW_CONVERSION
   if(uExpectedDouble) {
      /* This test is off by default. It's purpose is to check
       * QCBOR's mask-n-shift implementation against the HW/CPU
       * instructions that do conversion between double and single.
       * It is off because it is only used on occasion to verify
       * QCBOR and because it is suspected that some HW/CPU does
       * not implement this correctly. NaN payloads are an obscure
       * feature. */
      float    f;
      double   d2;
      uint64_t dd;

      f = UsefulBufUtil_CopyUint32ToFloat(uSingleToConvert);

      d2 = (double)f;

      dd = UsefulBufUtil_CopyDoubleToUint64(d2);

      if(isnan(f)) {
         /* Some (all?) Intel CPUs always set the qNaN bit in conversion */
         uExpectedDouble |= DOUBLE_QNAN;
      }

      if(dd != uExpectedDouble ) {
         return 1;
      }
   }
#else
   (void)uSingleToConvert;
   (void)uExpectedDouble;
#endif /* QCBOR_COMPARE_TO_HW_CONVERSION */
   return 0;
}


#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
/* Returns 0 if OK, 1 if not */
static int32_t
CompareToCarsten(const uint64_t uDouble, const UsefulBufC TestOutput, const UsefulBufC Expected)
{
   if(Expected.len == 3) {
      /* Just works for double to half now */
      int uFloat16 = try_float16_encode(uDouble);
      uint8_t CarstenEncoded[3];
      CarstenEncoded[0] = 0xf9;
      CarstenEncoded[1] = (uint8_t)((uFloat16 & 0xff00) >> 8);
      CarstenEncoded[2] = (uint8_t)(uFloat16 & 0xff);

      UsefulBufC CarstenEncodedUB;
      CarstenEncodedUB.len = 3;
      CarstenEncodedUB.ptr = CarstenEncoded;

      if(UsefulBuf_Compare(TestOutput, CarstenEncodedUB)) {
         return 1;
      }
   }

   return 0;
}
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */


struct FloatTestCase {
   double      dNumber;
   float       fNumber;
   UsefulBufC  Preferred;
   UsefulBufC  NotPreferred;
   UsefulBufC  Deterministic;
   UsefulBufC  DCBOR;
};

/* Boundaries for destination conversions:
 *
 * smallest subnormal single  1.401298464324817e-45   2^^-149
 * largest subnormal single   1.1754942106924411e-38  2^^-126
 * smallest normal single     1.1754943508222875e-38
 * largest single             3.4028234663852886E+38
 *
 * smallest subnormal half   5.9604644775390625E-8
 * largest subnormal half    6.097555160522461E-5
 * smallest normal half      6.103515625E-5
 * largest half              65504.0
 *
 * Boundaries for origin conversions:
 * smallest subnormal double 5.0e-324  2^^-1074
 * largest subnormal double
 * smallest normal double 2.2250738585072014e-308  2^^-1022
 * largest normal double 1.7976931348623157e308 2^^-1023
 *
 * Boundaries for double conversion to 64-bit integer:
 * exponent 51, 52 significand bits set     4503599627370495
 * exponent 52, 52 significand bits set     9007199254740991
 * exponent 53, 52 bits set in significand  18014398509481982
 */

/* Always four lines per test case so shell scripts can process into
 * other formats.
 *
 * C string literals are used because they are the shortest
 * notation. They are used __with a length__ . Null termination
 * doesn't work because there are bytes with value zero.
 *
 * While the Deterministic and dCBOR standards are not complete as of mid-2025,
 * they are unlikely to change, so the tests here are likely correct.
 */
static const struct FloatTestCase FloatTestCases[] =  {
   /* Zero */
   {0.0,                                         0.0f,
    {"\xF9\x00\x00", 3},                         {"\xFB\x00\x00\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x00\x00", 3},                         {"\x00", 1}},

   /* Negative Zero */
   {-0.0,                                        -0.0f,
    {"\xF9\x80\x00", 3},                         {"\xFB\x80\x00\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x80\x00", 3},                         {"\x00", 1}},

   /* NaN */
   {NAN,                                         NAN,
    {"\xF9\x7E\x00", 3},                         {"\xFB\x7F\xF8\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x7E\x00", 3},                         {"\xF9\x7E\x00", 3}},

   /* Infinity */
   {INFINITY,                                    INFINITY,
    {"\xF9\x7C\x00", 3},                         {"\xFB\x7F\xF0\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x7C\x00", 3},                         {"\xF9\x7C\x00", 3}},

   /* Negative Infinity */
   {-INFINITY,                                   -INFINITY,
    {"\xF9\xFC\x00", 3},                         {"\xFB\xFF\xF0\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\xFC\x00", 3},                         {"\xF9\xFC\x00", 3}},

   /* 1.0 */
   {1.0,                                         1.0f,
    {"\xF9\x3C\x00", 3},                         {"\xFB\x3F\xF0\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x3C\x00", 3},                         {"\x01", 1}},

   /* -2.0 -- a negative */
   {-2.0,                                        -2.0f,
    {"\xF9\xC0\x00", 3},                         {"\xFB\xC0\x00\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\xC0\x00", 3},                         {"\x21", 1}},

   /* 1/3 */
   {0.333251953125,                              0.333251953125f,
    {"\xF9\x35\x55", 3},                         {"\xFB\x3F\xD5\x54\x00\x00\x00\x00\x00", 9},
    {"\xF9\x35\x55", 3},                         {"\xF9\x35\x55", 3}},

   /* 5.9604644775390625E-8 -- smallest half-precision subnormal */
   {5.9604644775390625E-8,                       0.0f,
    {"\xF9\x00\x01", 3},                         {"\xFB\x3E\x70\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x00\x01", 3},                         {"\xF9\x00\x01", 3}},

   /* 3.0517578125E-5 -- a half-precision subnormal */
   {3.0517578125E-5,                             0.0f,
    {"\xF9\x02\x00", 3},                         {"\xFB\x3F\x00\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x02\x00", 3},                         {"\xF9\x02\x00", 3}},

   /* 6.097555160522461E-5 -- largest half-precision subnormal */
   {6.097555160522461E-5,                        0.0f,
    {"\xF9\x03\xFF", 3},                         {"\xFB\x3F\x0F\xF8\x00\x00\x00\x00\x00", 9},
    {"\xF9\x03\xFF", 3},                         {"\xF9\x03\xFF", 3}},

   /* 6.1035156249999993E-5 -- slightly smaller than smallest half-precision normal */
   {6.1035156249999993E-5,  0.0f,
    {"\xFB\x3F\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x3F\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9},
    {"\xFB\x3F\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x3F\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9}},

   /* 6.103515625E-5 -- smallest half-precision normal */
   {6.103515625E-5,                              0.0f,
    {"\xF9\04\00", 3},                           {"\xFB\x3F\x10\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\04\00", 3},                           {"\xF9\04\00", 3}},

   /* 6.1035156250000014E-5 -- slightly larger than smallest half-precision normal */
   {6.1035156250000014E-5,                       0.0f,
    {"\xFB\x3F\x10\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x3F\x10\x00\x00\x00\x00\x00\x01", 9},
    {"\xFB\x3F\x10\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x3F\x10\x00\x00\x00\x00\x00\x01", 9}},

   /* 65504.0 -- largest half-precision */
   {65504.0,                                     0.0f,
    {"\xF9\x7B\xFF", 3},                         {"\xFB\x40\xEF\xFC\x00\x00\x00\x00\x00", 9},
    {"\xF9\x7B\xFF", 3},                         {"\x19\xFF\xE0", 3}},

   /* 65504.1 -- exponent too large and too much precision to convert to half */
   {65504.1,                                     0.0f,
    {"\xFB\x40\xEF\xFC\x03\x33\x33\x33\x33", 9}, {"\xFB\x40\xEF\xFC\x03\x33\x33\x33\x33", 9},
    {"\xFB\x40\xEF\xFC\x03\x33\x33\x33\x33", 9}, {"\xFB\x40\xEF\xFC\x03\x33\x33\x33\x33", 9}},

    /* 65536.0 -- exponent too large for half but not too much precision for single */
   {65536.0,                                     65536.0f,
    {"\xFA\x47\x80\x00\x00", 5},                 {"\xFB\x40\xF0\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x47\x80\x00\x00", 5},                 {"\x1A\x00\x01\x00\x00", 5}},

   /* 1.401298464324817e-45 -- smallest single subnormal */
   {1.401298464324817e-45,                       1.40129846E-45f,
    {"\xFA\x00\x00\x00\x01", 5},                 {"\xFB\x36\xA0\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x00\x00\x00\x01", 5},                 {"\xFA\x00\x00\x00\x01", 5}},

   /* 5.8774717541114375E-39 -- slightly smaller than the smallest single normal */
   {5.8774717541114375E-39,                      5.87747175E-39f,
    {"\xFA\x00\x40\x00\x00", 5},                 {"\xFB\x38\x00\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x00\x40\x00\x00", 5},                 {"\xFA\x00\x40\x00\x00", 5}},

   /* 1.1754942106924411e-38 -- largest single subnormal */
   {1.1754942106924411E-38,                      1.17549421E-38f,
    {"\xFA\x00\x7f\xff\xff", 5},                 {"\xFB\x38\x0f\xff\xff\xC0\x00\x00\x00", 9},
    {"\xFA\x00\x7f\xff\xff", 5},                 {"\xFA\x00\x7f\xff\xff", 5} },

   /* 1.1754943508222874E-38 -- slightly bigger than smallest single normal */
   {1.1754943508222874E-38,                      0.0f,
    {"\xFB\x38\x0f\xff\xff\xff\xff\xff\xff", 9}, {"\xFB\x38\x0f\xff\xff\xff\xff\xff\xff", 9},
    {"\xFB\x38\x0f\xff\xff\xff\xff\xff\xff", 9}, {"\xFB\x38\x0f\xff\xff\xff\xff\xff\xff", 9}},

   /* 1.1754943508222875e-38 -- smallest single normal */
   {1.1754943508222875e-38,                      1.17549435E-38f,
    {"\xFA\x00\x80\x00\x00", 5},                 {"\xFB\x38\x10\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x00\x80\x00\x00", 5},                 {"\xFA\x00\x80\x00\x00", 5}},

   /* 1.1754943508222875e-38 -- slightly bigger than smallest single normal */
   {1.1754943508222878e-38,                      0.0f,
    {"\xFB\x38\x10\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x38\x10\x00\x00\x00\x00\x00\x01", 9},
    {"\xFB\x38\x10\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x38\x10\x00\x00\x00\x00\x00\x01", 9}},

   /* 8388607 -- exponent 22 to test single exponent boundary */
   {8388607.0,                                   8388607.0f,
    {"\xFA\x4A\xFF\xFF\xFE", 5},                 {"\xFB\x41\x5F\xFF\xFF\xC0\x00\x00\x00", 9},
    {"\xFA\x4A\xFF\xFF\xFE", 5},                 {"\x1A\x00\x7F\xFF\xFF", 5}},

   /* 16777215 -- exponent 23 to test single exponent boundary */
   {16777215.0,                                  16777215.0f,
    {"\xFA\x4B\x7F\xFF\xFF", 5},                 {"\xFB\x41\x6F\xFF\xFF\xE0\x00\x00\x00", 9},
    {"\xFA\x4B\x7F\xFF\xFF", 5},                 {"\x1A\x00\xFF\xFF\xFF", 5}},

   /* 16777216 -- converts to single without loss */
   {16777216.0,                                  16777216.0f,
    {"\xFA\x4B\x80\x00\x00", 5},                 {"\xFB\x41\x70\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x4B\x80\x00\x00", 5},                 {"\x1A\x01\x00\x00\x00", 5}},

   /* 16777217 -- one more than above and fails conversion to single because of precision */
   {16777217.0,                                  0.0f,
    {"\xFB\x41\x70\x00\x00\x10\x00\x00\x00", 9}, {"\xFB\x41\x70\x00\x00\x10\x00\x00\x00", 9},
    {"\xFB\x41\x70\x00\x00\x10\x00\x00\x00", 9}, {"\x1A\x01\x00\x00\x01", 5}},

   /* 33554430 -- exponent 24 to test single exponent boundary */
   {33554430.0,                                  33554430.0f,
    {"\xFA\x4B\xFF\xFF\xFF", 5},                 {"\xFB\x41\x7F\xFF\xFF\xE0\x00\x00\x00", 9},
    {"\xFA\x4B\xFF\xFF\xFF", 5},                 {"\x1A\x01\xFF\xFF\xFE",                 5}},

   /* 4294967295 -- 2^^32 - 1 UINT32_MAX */
   {4294967295.0,                                0,
    {"\xFB\x41\xEF\xFF\xFF\xFF\xE0\x00\x00", 9}, {"\xFB\x41\xEF\xFF\xFF\xFF\xE0\x00\x00", 9},
    {"\xFB\x41\xEF\xFF\xFF\xFF\xE0\x00\x00", 9}, {"\x1A\xFF\xFF\xFF\xFF",                 5}},

   /* 4294967296 -- 2^^32, UINT32_MAX + 1 */
   {4294967296.0,                                4294967296.0f,
    {"\xFA\x4F\x80\x00\x00",                 5}, {"\xFB\x41\xF0\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x4F\x80\x00\x00",                 5}, {"\x1B\x00\x00\x00\x01\x00\x00\x00\x00", 9}},

   /* 2251799813685248 -- exponent 51, 0 significand bits set, to test double exponent boundary */
   {2251799813685248.0,                          2251799813685248.0f,
    {"\xFA\x59\x00\x00\x00",                 5}, {"\xFB\x43\x20\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x59\x00\x00\x00",                 5}, {"\x1B\x00\x08\x00\x00\x00\x00\x00\x00", 9}},

   /* 4503599627370495 -- exponent 51, 52 significand bits set to test double exponent boundary*/
   {4503599627370495.0,                          0,
    {"\xFB\x43\x2F\xFF\xFF\xFF\xFF\xFF\xFE", 9}, {"\xFB\x43\x2F\xFF\xFF\xFF\xFF\xFF\xFE", 9},
    {"\xFB\x43\x2F\xFF\xFF\xFF\xFF\xFF\xFE", 9}, {"\x1B\x00\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9}},

   /* 9007199254740991 -- exponent 52, 52 significand bits set to test double exponent boundary */
   {9007199254740991.0,                          0,
    {"\xFB\x43\x3F\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x43\x3F\xFF\xFF\xFF\xFF\xFF\xFF", 9},
    {"\xFB\x43\x3F\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\x1B\x00\x1F\xFF\xFF\xFF\xFF\xFF\xFF", 9}},

   /* 18014398509481982 -- exponent 53, 52 bits set in significand (double lacks precision for 18014398509481983) */
   {18014398509481982.0,                         0,
    {"\xFB\x43\x4F\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x43\x4F\xFF\xFF\xFF\xFF\xFF\xFF", 9},
    {"\xFB\x43\x4F\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\x1B\x00\x3F\xFF\xFF\xFF\xFF\xFF\xFE", 9}},

   /* 18014398509481984 -- next largest possible double above 18014398509481982  */
   {18014398509481984.0,                         18014398509481984.0f,
    {"\xFA\x5A\x80\x00\x00",                 5}, {"\xFB\x43\x50\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x5A\x80\x00\x00",                 5}, {"\x1B\x00\x40\x00\x00\x00\x00\x00\x00", 9}},

   /* 18446742974197924000.0.0 -- largest single that can convert to uint64 */
   {18446742974197924000.0,                      18446742974197924000.0f,
    {"\xFA\x5F\x7F\xFF\xFF",                 5}, {"\xFB\x43\xEF\xFF\xFF\xE0\x00\x00\x00", 9},
    {"\xFA\x5F\x7F\xFF\xFF",                 5}, {"\x1B\xFF\xFF\xFF\x00\x00\x00\x00\x00", 9}},

   /* 18446744073709550000.0 -- largest double that can convert to uint64, almost UINT64_MAX (18446744073709551615) */
   {18446744073709550000.0,                      0,
    {"\xFB\x43\xEF\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x43\xEF\xFF\xFF\xFF\xFF\xFF\xFF", 9},
    {"\xFB\x43\xEF\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\x1B\xFF\xFF\xFF\xFF\xFF\xFF\xF8\x00", 9}},

   /* 18446744073709552000.0 -- just too large to convert to uint64, but converts to a single, just over UINT64_MAX  */
   {18446744073709552000.0,                      18446744073709552000.0f,
    {"\xFA\x5F\x80\x00\x00",                 5}, {"\xFB\x43\xF0\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\x5F\x80\x00\x00",                 5}, {"\xFA\x5F\x80\x00\x00",                 5}},

   /* -4294967295 -- negative UINT32_MAX */
   {-4294967295.0,                               0,
    {"\xFB\xC1\xEF\xFF\xFF\xFF\xE0\x00\x00", 9}, {"\xFB\xC1\xEF\xFF\xFF\xFF\xE0\x00\x00", 9},
    {"\xFB\xC1\xEF\xFF\xFF\xFF\xE0\x00\x00", 9}, {"\x3A\xFF\xFF\xFF\xFE", 5}},

   /* -9223372036854774784.0 -- most negative double that converts to int64 */
   {-9223372036854774784.0,                      0,
    {"\xFB\xC3\xDF\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\xC3\xDF\xFF\xFF\xFF\xFF\xFF\xFF", 9},
    {"\xFB\xC3\xDF\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\x3B\x7F\xFF\xFF\xFF\xFF\xFF\xFB\xFF", 9}},

   /* -18446742974197923840.0 -- large negative that converts to float, but too large for int64 */
   {-18446742974197923840.0,                     -18446742974197923840.0f,
    {"\xFA\xDF\x7F\xFF\xFF",                 5}, {"\xFB\xC3\xEF\xFF\xFF\xE0\x00\x00\x00", 9},
    {"\xFA\xDF\x7F\xFF\xFF",                 5}, {"\x3B\xFF\xFF\xFE\xFF\xFF\xFF\xFF\xFF", 9}},

   /* 3.4028234663852886E+38 -- largest possible single */
   {3.4028234663852886E+38,                      3.40282347E+38f,
    {"\xFA\x7F\x7F\xFF\xFF",                 5}, {"\xFB\x47\xEF\xFF\xFF\xE0\x00\x00\x00", 9},
    {"\xFA\x7F\x7F\xFF\xFF",                 5}, {"\xFA\x7F\x7F\xFF\xFF",                 5}},

   /* 3.402823466385289E+38 -- slightly larger than largest possible single */
   {3.402823466385289E+38,                       0.0f,
    {"\xFB\x47\xEF\xFF\xFF\xE0\x00\x00\x01", 9}, {"\xFB\x47\xEF\xFF\xFF\xE0\x00\x00\x01", 9},
    {"\xFB\x47\xEF\xFF\xFF\xE0\x00\x00\x01", 9}, {"\xFB\x47\xEF\xFF\xFF\xE0\x00\x00\x01", 9}},

   /* 3.402823669209385e+38 -- exponent larger by one than largest possible single */
   {3.402823669209385e+38,                       0.0f,
    {"\xFB\x47\xF0\x00\x00\x00\x00\x00\x00", 9}, {"\xFB\x47\xF0\x00\x00\x00\x00\x00\x00", 9},
    {"\xFB\x47\xF0\x00\x00\x00\x00\x00\x00", 9}, {"\xFB\x47\xF0\x00\x00\x00\x00\x00\x00", 9}},

   /* 5.0e-324 -- smallest double subnormal normal */
   {5.0e-324,                                    0.0f,
    {"\xFB\x00\x00\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x00\x00\x00\x00\x00\x00\x00\x01", 9},
    {"\xFB\x00\x00\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x00\x00\x00\x00\x00\x00\x00\x01", 9}},

   /* 2.2250738585072009E−308 -- largest double subnormal */
   {2.2250738585072009e-308,                     0.0f,
    {"\xFB\x00\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x00\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9},
    {"\xFB\x00\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x00\x0F\xFF\xFF\xFF\xFF\xFF\xFF", 9}},

   /* 2.2250738585072014e-308 -- smallest double normal */
   {2.2250738585072014e-308,                     0.0f,
    {"\xFB\x00\x10\x00\x00\x00\x00\x00\x00", 9}, {"\xFB\x00\x10\x00\x00\x00\x00\x00\x00", 9},
    {"\xFB\x00\x10\x00\x00\x00\x00\x00\x00", 9}, {"\xFB\x00\x10\x00\x00\x00\x00\x00\x00", 9}},

   /* 1.7976931348623157E308 -- largest double normal */
   {1.7976931348623157e308,                      0.0f,
    {"\xFB\x7F\xEF\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x7F\xEF\xFF\xFF\xFF\xFF\xFF\xFF", 9},
    {"\xFB\x7F\xEF\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x7F\xEF\xFF\xFF\xFF\xFF\xFF\xFF", 9}},

   /* -18446744073709551616.0 -- largest that encodes into negative uint64 (65-bit neg) */
   {-18446744073709551616.0,                     -18446744073709551616.0f,
    {"\xFA\xDF\x80\x00\x00",                 5}, {"\xFB\xC3\xF0\x00\x00\x00\x00\x00\x00", 9},
    {"\xFA\xDF\x80\x00\x00",                 5}, {"\x3B\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 9}},

   /* List terminator */
   {0.0, 0.0f, {NULL, 0}, {NULL, 0}, {NULL, 0}, {NULL, 0} }
};


/* Public function. See float_tests.h
 *
 * This is the main test of floating-point encoding / decoding. It is
 * data-driven by the above tables. It works better than tests below that
 * it mostly replaces because it tests one number at a time, rather than
 * putting them all in a map. It is much easier to debug test failures
 * and to add new tests. */
int32_t
FloatValuesTests(void)
{
   unsigned int                 uTestIndex;
   const struct FloatTestCase  *pTestCase;
   MakeUsefulBufOnStack(        TestOutBuffer, 20);
   UsefulBufC                   TestOutput;
   QCBOREncodeContext           EnCtx;
   QCBORError                   uErr;
   QCBORDecodeContext           DCtx;
   QCBORItem                    Item;

   /* Test a variety of doubles and some singles */
   for(uTestIndex = 0; FloatTestCases[uTestIndex].Preferred.len != 0; uTestIndex++) {
      pTestCase = &FloatTestCases[uTestIndex];

      if(uTestIndex == 2) {
         uErr = 0;
      }

      /* Preferred encode of double precision */
      QCBOREncode_Init(&EnCtx, TestOutBuffer);
      QCBOREncode_AddDouble(&EnCtx, pTestCase->dNumber);
      uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);

      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex, 1, uErr);;
      }
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      if(UsefulBuf_Compare(TestOutput, pTestCase->Preferred)) {
         return MakeTestResultCode(uTestIndex, 2, 200);
      }

      if(CompareToCarsten(UsefulBufUtil_CopyDoubleToUint64(pTestCase->dNumber), TestOutput, pTestCase->Preferred)) {
         return MakeTestResultCode(uTestIndex, 3, 200);
      }
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
      if(UsefulBuf_Compare(TestOutput, pTestCase->NotPreferred)) {
         return MakeTestResultCode(uTestIndex, 4, 200);
      }
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */


      /* Preferred encode of single precision */
      if(pTestCase->fNumber != 0.0) {
         QCBOREncode_Init(&EnCtx, TestOutBuffer);
         QCBOREncode_AddFloat(&EnCtx, pTestCase->fNumber);
         uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);

         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex, 10, uErr);;
         }
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         if(UsefulBuf_Compare(TestOutput, pTestCase->Preferred)) {
            return MakeTestResultCode(uTestIndex, 11, 200);
         }

         if(CompareToCarsten(UsefulBufUtil_CopyDoubleToUint64(pTestCase->dNumber), TestOutput, pTestCase->Preferred)) {
            return MakeTestResultCode(uTestIndex, 12, 200);
         }
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         /* no non-preferred serialization for singles to check against */
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
      }


      /* Non-preferred encode of double */
      QCBOREncode_Init(&EnCtx, TestOutBuffer);
      QCBOREncode_AddDoubleNoPreferred(&EnCtx, pTestCase->dNumber);
      uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);
      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex, 20, uErr);;
      }
      if(UsefulBuf_Compare(TestOutput, pTestCase->NotPreferred)) {
         return MakeTestResultCode(uTestIndex, 21, 200);
      }

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      /* Deterministic encode */
      QCBOREncode_Init(&EnCtx, TestOutBuffer);
      QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_DETERMINISTIC);
      QCBOREncode_AddDouble(&EnCtx, pTestCase->dNumber);
      uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);

      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex, 30, uErr);;
      }
      if(UsefulBuf_Compare(TestOutput, pTestCase->Deterministic)) {
         return MakeTestResultCode(uTestIndex, 31, 200);
      }

      /* dCBOR encode of double */
      QCBOREncode_Init(&EnCtx, TestOutBuffer);
      QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_DCBOR);
      QCBOREncode_AddDouble(&EnCtx, pTestCase->dNumber);
      uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);

      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex, 40, uErr);;
      }
      if(UsefulBuf_Compare(TestOutput, pTestCase->DCBOR)) {
         return MakeTestResultCode(uTestIndex, 41, 200);
      }

      /* dCBOR encode of single */
      if(pTestCase->fNumber != 0.0) {
         QCBOREncode_Init(&EnCtx, TestOutBuffer);
         QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_DCBOR);
         QCBOREncode_AddFloat(&EnCtx, pTestCase->fNumber);
         uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);

         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex, 50, uErr);;
         }
         if(UsefulBuf_Compare(TestOutput, pTestCase->DCBOR)) {
            return MakeTestResultCode(uTestIndex, 51, 200);
         }
      }

#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */

      /* Decode preferred decode */
      QCBORDecode_Init(&DCtx, pTestCase->Preferred, 0);
      uErr = QCBORDecode_GetNext(&DCtx, &Item);
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex, 60, uErr);
      }
      if(Item.uDataType != QCBOR_TYPE_DOUBLE) {
         return MakeTestResultCode(uTestIndex, 61, 0);
      }
      if(isnan(pTestCase->dNumber)) {
         if(!isnan(Item.val.dfnum)) {
            return MakeTestResultCode(uTestIndex, 62, 0);
         }
      } else {
         if(Item.val.dfnum != pTestCase->dNumber) {
            return MakeTestResultCode(uTestIndex, 63, 0);
         }
      }
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
      if(pTestCase->Preferred.len == 3) {
         if(uErr != QCBOR_ERR_PREFERRED_FLOAT_DISABLED) {
            return MakeTestResultCode(uTestIndex, 64, uErr);
         }
      } else if(pTestCase->Preferred.len == 5) {
         /* When QCBOR_DISABLE_PREFERRED_FLOAT is set, single-precision is not
          * converted to double when decoding, so test differently. len == 5
          * indicates single-precision in the encoded CBOR. */
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex, 65, uErr);
         }
         if(Item.uDataType != QCBOR_TYPE_FLOAT) {
            return MakeTestResultCode(uTestIndex, 66, 0);
         }
         if(isnan(pTestCase->dNumber)) {
            if(!isnan(Item.val.fnum)) {
               return MakeTestResultCode(uTestIndex, 67, 0);
            }
         } else {
            if(Item.val.fnum != pTestCase->fNumber) {
               return MakeTestResultCode(uTestIndex, 68, 0);
            }
         }
      } else {
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex, 69, uErr);
         }
         if(Item.uDataType != QCBOR_TYPE_DOUBLE) {
            return MakeTestResultCode(uTestIndex, 70, 0);
         }
         if(isnan(pTestCase->dNumber)) {
            if(!isnan(Item.val.dfnum)) {
               return MakeTestResultCode(uTestIndex, 71, 0);
            }
         } else {
            if(Item.val.dfnum != pTestCase->dNumber) {
               return MakeTestResultCode(uTestIndex, 72, 0);
            }
         }
      }
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */

      /* Decode not preferred */
      QCBORDecode_Init(&DCtx, pTestCase->NotPreferred, 0);
      uErr = QCBORDecode_GetNext(&DCtx, &Item);
      if(uErr != QCBOR_SUCCESS) {
         return MakeTestResultCode(uTestIndex, 80, uErr);;
      }
      if(Item.uDataType != QCBOR_TYPE_DOUBLE) {
         return MakeTestResultCode(uTestIndex, 81, 0);
      }
      if(isnan(pTestCase->dNumber)) {
         if(!isnan(Item.val.dfnum)) {
            return MakeTestResultCode(uTestIndex, 82, 0);
         }
      } else {
         if(Item.val.dfnum != pTestCase->dNumber) {
            return MakeTestResultCode(uTestIndex, 83, 0);
         }
      }
   }

   return 0;
}


/* Can't use the types double and float here because there's no compile
 * time initializer in C to construct NaNs.

 * The tests: encode the double in the 4 different ways and see the result is as expected
 *            encode the single in the 4 different ways and see the result is as expected
 *            decode the preferred and non-preferred (deterministic is always the same as preferred; DCBOR is not reversable)
 */
struct NaNTestCase {
   uint64_t    uDouble; /* Converted to double in test */
   uint32_t    uSingle; /* Converted to single in test */
   uint64_t    uExpectedDouble;
   uint32_t    uExpectedSingle;
   UsefulBufC  Preferred;
   UsefulBufC  NotPreferred;
   UsefulBufC  Deterministic;
   UsefulBufC  DCBOR;
};

/* Always four lines per test case so shell scripts can process into
 * other formats.
 *
 * C string literals are used because they are the shortest
 * notation. They are used __with a length__ . Null termination
 * doesn't work because there are bytes with value zero.
 *
 * While the deterministic and dCBOR standards are not complete as of mid-2025,
 * they are unlikely to change, so the tests here are likely correct.
 */
/* This assumes that the signficand of a float is made up of the qNaN bit and
 * the payload. The qNaN bit is the most signficant. If not a qNaN, then it
 * is an sNaN. For an sNaN not to be the floating point value, its significand
 * must be non-zero. */
static const struct NaNTestCase NaNTestCases[] =  {
   /* Reminder: DOUBLE_NAN_BITS | x00 is INFINITY, not a NaN */

   /* double qNaN -- shortens to half */
   {DOUBLE_NAN_BITS | DOUBLE_QNAN,               0,
    DOUBLE_NAN_BITS | DOUBLE_QNAN,               0,
    {"\xF9\x7E\x00", 3},                         {"\xFB\x7F\xF8\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\x7E\x00", 3},                         {"\xF9\x7E\x00", 3}},

   /* double negative qNaN -- shortens to half */
   {DOUBLE_SIGN_MASK | DOUBLE_NAN_BITS | DOUBLE_QNAN, 0,
    DOUBLE_SIGN_MASK| DOUBLE_NAN_BITS | DOUBLE_QNAN,  0,
    {"\xF9\xFE\x00", 3},                         {"\xFB\xFF\xF8\x00\x00\x00\x00\x00\x00", 9},
    {"\xF9\xFE\x00", 3},                         {"\xF9\x7E\x00", 3}},

   /* double sNaN with payload of rightmost bit set -- no shorter encoding */
   {DOUBLE_NAN_BITS | DOUBLE_SNAN | 0x01,        0,
    DOUBLE_NAN_BITS | DOUBLE_SNAN | 0x01,        0,
    {"\xFB\x7F\xF0\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\x7F\xF0\x00\x00\x00\x00\x00\x01", 9},
    {"\xFB\x7F\xF0\x00\x00\x00\x00\x00\x01", 9}, {"\xF9\x7E\x00", 3}},

   /* double negative sNaN with payload of rightmost bit set -- no shorter encoding */
   {DOUBLE_SIGN_MASK | DOUBLE_NAN_BITS | DOUBLE_SNAN | 0x01,        0,
    DOUBLE_SIGN_MASK | DOUBLE_NAN_BITS | DOUBLE_SNAN | 0x01,        0,
    {"\xFB\xFF\xF0\x00\x00\x00\x00\x00\x01", 9}, {"\xFB\xFF\xF0\x00\x00\x00\x00\x00\x01", 9},
    {"\xFB\xFF\xF0\x00\x00\x00\x00\x00\x01", 9}, {"\xF9\x7E\x00", 3}},

   /* double qNaN with 9 leftmost payload bits set -- shortens to half */
   {DOUBLE_NAN_BITS | DOUBLE_QNAN | 0x7fc0000000000,  0,
    DOUBLE_NAN_BITS | DOUBLE_QNAN | 0x7fc0000000000,  0,
    {"\xF9\x7F\xFF", 3},                         {"\xFB\x7F\xFF\xFC\x00\x00\x00\x00\x00", 9},
    {"\xF9\x7F\xFF", 3},                         {"\xF9\x7E\x00", 3}},

   /* double sNaN with 10 rightmost payload bits set -- no shorter encoding */
   {DOUBLE_NAN_BITS | DOUBLE_SNAN | 0x03ff,      0,
    DOUBLE_NAN_BITS | DOUBLE_SNAN | 0x03ff,      0,
    {"\xFB\x7F\xF0\x00\x00\x00\x00\x03\xFF", 9}, {"\xFB\x7F\xF0\x00\x00\x00\x00\x03\xFF", 9},
    {"\xFB\x7F\xF0\x00\x00\x00\x00\x03\xFF", 9}, {"\xF9\x7E\x00", 3}},

   /* double qNaN with 22 leftmost payload bits set -- shortens to single */
   {DOUBLE_NAN_BITS | DOUBLE_QNAN | 0x7ffffe0000000,  0,
    DOUBLE_NAN_BITS | DOUBLE_QNAN | 0x7ffffe0000000,  SINGLE_NAN_BITS | 0x7fffff,
    {"\xFA\x7F\xFF\xFF\xFF", 5},                 {"\xFB\x7F\xFF\xFF\xFF\xE0\x00\x00\x00", 9},
    {"\xFA\x7F\xFF\xFF\xFF", 5},                 {"\xF9\x7E\x00", 3}},

   /* double negative qNaN with 22 leftmost payload bits set -- shortens to single */
   {DOUBLE_SIGN_MASK | DOUBLE_NAN_BITS | DOUBLE_QNAN | 0x7ffffe0000000,  0,
    DOUBLE_SIGN_MASK | DOUBLE_NAN_BITS | DOUBLE_QNAN | 0x7ffffe0000000,  SINGLE_SIGN_MASK | SINGLE_NAN_BITS | 0x7fffff,
    {"\xFA\xFF\xFF\xFF\xFF", 5},                 {"\xFB\xFF\xFF\xFF\xFF\xE0\x00\x00\x00", 9},
    {"\xFA\xFF\xFF\xFF\xFF", 5},                 {"\xF9\x7E\x00", 3}},

   /* double sNaN with 23rd leftmost payload bit set -- shortens to single */
   {DOUBLE_NAN_BITS | DOUBLE_SNAN | 0x0000020000000,  0,
    DOUBLE_NAN_BITS | DOUBLE_SNAN | 0x0000020000000,  SINGLE_NAN_BITS | 0x01,
    {"\xFA\x7F\x80\x00\x01", 5},                 {"\xFB\x7F\xF0\x00\x00\x20\x00\x00\x00", 9},
    {"\xFA\x7F\x80\x00\x01", 5},                 {"\xF9\x7E\x00", 3}},

   /* double sNaN with randomly chosen bit pattern -- shortens to single */
   {DOUBLE_NAN_BITS | DOUBLE_SNAN | 0x43d7c40000000,  0,
    DOUBLE_NAN_BITS | DOUBLE_SNAN | 0x43d7c40000000,  SINGLE_NAN_BITS | 0x21ebe2,
    {"\xFA\x7F\xA1\xEB\xE2", 5},                 {"\xFB\x7F\xF4\x3D\x7C\x40\x00\x00\x00", 9},
    {"\xFA\x7F\xA1\xEB\xE2", 5},                 {"\xF9\x7E\x00", 3}},

   /* double sNaN with 23 leftmost payload bits set -- no shorter encoding */
   {DOUBLE_NAN_BITS | DOUBLE_SNAN | 0x7fffff0000000,  0,
    DOUBLE_NAN_BITS | DOUBLE_SNAN | 0x7fffff0000000,  0,
    {"\xFB\x7F\xF7\xFF\xFF\xF0\x00\x00\x00", 9}, {"\xFB\x7F\xF7\xFF\xFF\xF0\x00\x00\x00", 9},
    {"\xFB\x7F\xF7\xFF\xFF\xF0\x00\x00\x00", 9}, {"\xF9\x7E\x00", 3}},

   /* double qNaN with all bits set -- no shorter encoding */
   {DOUBLE_NAN_BITS | DOUBLE_QNAN | 0x7ffffffffffff,  0,
    DOUBLE_NAN_BITS | DOUBLE_QNAN | 0x7ffffffffffff,  0,
    {"\xFB\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xFB\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 9},
    {"\xFB\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 9}, {"\xF9\x7E\x00", 3}},

   /* single qNaN with payload 0x00 -- shortens to half */
   {0,                                           SINGLE_NAN_BITS | SINGLE_QNAN,
    DOUBLE_NAN_BITS | DOUBLE_QNAN,               0,
    {"\xF9\x7E\x00", 3},                         {"\xFA\x7F\xC0\x00\x00", 5},
    {"\xF9\x7E\x00", 3},                         {"\xF9\x7E\x00", 3}},

   /* sNan with payload 0x00 is not a NaN, it's infinity */

   /* single sNan with payload 0x01 -- no shorter encoding */
   {0,                                           SINGLE_NAN_BITS | SINGLE_SNAN | 0x01,
    DOUBLE_NAN_BITS | (0x01 << 29),              0,
    {"\xFA\x7F\x80\x00\x01", 5},                 {"\xFA\x7F\x80\x00\x01", 5},
    {"\xFA\x7F\x80\x00\x01", 5},                 {"\xF9\x7E\x00", 3}},

   /* single qNaN with 9 bit payload -- shortens to half */
   {0,                                           SINGLE_NAN_BITS | SINGLE_QNAN | 0x3fe000,
    DOUBLE_NAN_BITS | ((SINGLE_QNAN | 0x3fe000ULL) << 29),   0,
    {"\xF9\x7F\xFF", 3},                         {"\xFA\x7F\xFF\xE0\x00", 5},
    {"\xF9\x7F\xFF", 3},                         {"\xF9\x7E\x00", 3}},

   /* single qNaN with 10 bit payload -- no shorter encoding */
   {0,                                           SINGLE_NAN_BITS | SINGLE_QNAN | 0x3ff000,
    DOUBLE_NAN_BITS | ((SINGLE_QNAN | 0x3ff000ULL) << 29), 0,
    {"\xFA\x7F\xFF\xF0\x00", 5},                 {"\xFA\x7F\xFF\xF0\x00", 5},
    {"\xFA\x7F\xFF\xF0\x00", 5},                 {"\xF9\x7E\x00", 3}},

   /* single sNaN with 9 bit payload -- shortens to half */
   {0,                                           SINGLE_NAN_BITS | SINGLE_SNAN | 0x3fe000,
    DOUBLE_NAN_BITS | ((SINGLE_SNAN | 0x3fe000ULL) << 29), 0,
    {"\xF9\x7D\xFF", 3},                         {"\xFA\x7F\xBF\xE0\x00", 5},
    {"\xF9\x7D\xFF", 3},                         {"\xF9\x7E\x00", 3}},

   /* single sNaN with 10 bit payload -- no shorter encoding */
   {0,                                           SINGLE_NAN_BITS | SINGLE_SNAN | 0x3ff000,
    DOUBLE_NAN_BITS | ((SINGLE_SNAN | 0x3ff000ULL) << 29), 0,
    {"\xFA\x7F\xBF\xF0\x00", 5},                 {"\xFA\x7F\xBF\xF0\x00", 5},
    {"\xFA\x7F\xBF\xF0\x00", 5},                 {"\xF9\x7E\x00", 3}},

   /* List terminator */
   {0, 0, 0, 0, {NULL, 0}, {NULL, 0}, {NULL, 0}, {NULL, 0} }
};


/* Public function. See float_tests.h */
int32_t
NaNPayloadsTest(void)
{
   const struct NaNTestCase    *pNaNTestCase;
   unsigned int                 uTestIndex;
   QCBORError                   uErr;
   QCBOREncodeContext           EnCtx;
   MakeUsefulBufOnStack(        TestOutBuffer, 20);
   UsefulBufC                   TestOutput;
   QCBORDecodeContext           DCtx;
   QCBORItem                    Item;
   uint64_t                     uDecoded;

   /* Test a variety of NaNs with payloads */
   for(uTestIndex = 0; NaNTestCases[uTestIndex].Preferred.len != 0; uTestIndex++) {
      pNaNTestCase = &NaNTestCases[uTestIndex];

      if(uTestIndex == 7) {
         uErr = 99; /* For setting break points for a particular test */
      }

      if(pNaNTestCase->uDouble) {
         /* NaN Encode of Preferred */
         QCBOREncode_Init(&EnCtx, TestOutBuffer);
         QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);
         QCBOREncode_AddDouble(&EnCtx, UsefulBufUtil_CopyUint64ToDouble(pNaNTestCase->uDouble));
         uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex+100, 10, uErr);;
         }
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         if(UsefulBuf_Compare(TestOutput, pNaNTestCase->Preferred)) {
            return MakeTestResultCode(uTestIndex+100, 11, 200);
         }
         if(CompareToCarsten(pNaNTestCase->uDouble, TestOutput, pNaNTestCase->Preferred)) {
            return MakeTestResultCode(uTestIndex+100, 12, 200);
         }
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         if(UsefulBuf_Compare(TestOutput, pNaNTestCase->NotPreferred)) {
            return MakeTestResultCode(uTestIndex+100, 122, 200);
         }
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */

         if(HWCheckFloatToDouble(pNaNTestCase->uDouble, pNaNTestCase->uSingle)) {
            return MakeTestResultCode(uTestIndex+100, 121, 200);
         }

         /* NaN Encode of Not Preferred */
         QCBOREncode_Init(&EnCtx, TestOutBuffer);
         QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);
         QCBOREncode_AddDoubleNoPreferred(&EnCtx, UsefulBufUtil_CopyUint64ToDouble(pNaNTestCase->uDouble));
         uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex+100, 13, uErr);;
         }
         if(UsefulBuf_Compare(TestOutput, pNaNTestCase->NotPreferred)) {
            return MakeTestResultCode(uTestIndex+100, 14, 200);
         }

         /* NaN Decode of Preferred */
         QCBORDecode_Init(&DCtx, pNaNTestCase->Preferred, 0);
         QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);
         uErr = QCBORDecode_GetNext(&DCtx, &Item);
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex+100, 15, uErr);
         }
         uDecoded = UsefulBufUtil_CopyDoubleToUint64(Item.val.dfnum);
         if(uDecoded != pNaNTestCase->uDouble) {
            return MakeTestResultCode(uTestIndex+100, 11, 200);
         }
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         if(pNaNTestCase->Preferred.len == 9) {
            if(uErr != QCBOR_SUCCESS) {
               return MakeTestResultCode(uTestIndex+100, 17, uErr);
            }

            uDecoded = UsefulBufUtil_CopyDoubleToUint64(Item.val.dfnum);
            if(uDecoded != pNaNTestCase->uDouble) {
               return MakeTestResultCode(uTestIndex+100, 18, 200);
            }
         } else if(pNaNTestCase->Preferred.len == 5) {
            if(Item.uDataType != QCBOR_TYPE_FLOAT) {
               return MakeTestResultCode(uTestIndex, 19, 0);
            }

            uint32_t uDecoded2x = UsefulBufUtil_CopyFloatToUint32(Item.val.fnum);

            if(uDecoded2x != pNaNTestCase->uExpectedSingle) {
               return MakeTestResultCode(uTestIndex, 20, 0);
            }
         } else {
            /* Serialized to half precision */
            if(Item.uDataType != QCBOR_TYPE_NONE) {
               return MakeTestResultCode(uTestIndex, 21, 0);
            }
         }
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */

         /* NaN Decode of Not Preferred */
         QCBORDecode_Init(&DCtx, pNaNTestCase->NotPreferred, 0);
         QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);
         uErr = QCBORDecode_GetNext(&DCtx, &Item);
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex+100, 22, uErr);
         }
         uDecoded = UsefulBufUtil_CopyDoubleToUint64(Item.val.dfnum);
         if(uDecoded != pNaNTestCase->uDouble) {
            return MakeTestResultCode(uTestIndex+100, 23, 200);
         }

         /* Deterministic NaN Encode */
         QCBOREncode_Init(&EnCtx, TestOutBuffer);
         QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_DETERMINISTIC| QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);
         QCBOREncode_AddDouble(&EnCtx, UsefulBufUtil_CopyUint64ToDouble(pNaNTestCase->uDouble));
         uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex+100, 24, uErr);;
         }
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         if(UsefulBuf_Compare(TestOutput, pNaNTestCase->Preferred)) {
            return MakeTestResultCode(uTestIndex+100, 241, 200);
         }
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         if(UsefulBuf_Compare(TestOutput, pNaNTestCase->NotPreferred)) {
            return MakeTestResultCode(uTestIndex+100, 25, 200);
         }
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */

         /* NaN Encode of DCBOR */
         QCBOREncode_Init(&EnCtx, TestOutBuffer);
         QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_DCBOR | QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);
         QCBOREncode_AddDouble(&EnCtx, UsefulBufUtil_CopyUint64ToDouble(pNaNTestCase->uDouble));
         uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex+100, 26, uErr);;
         }
         if(UsefulBuf_Compare(TestOutput, pNaNTestCase->DCBOR)) {
            return MakeTestResultCode(uTestIndex+100, 27, 200);
         }
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         if(uErr != QCBOR_ERR_PREFERRED_FLOAT_DISABLED) {
            return MakeTestResultCode(uTestIndex+100, 28, uErr);
         }
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */

      } else {
         /* --- uSingle tests ---- */
         /* NaN Encode of Preferred */
         QCBOREncode_Init(&EnCtx, TestOutBuffer);
         QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);
         QCBOREncode_AddFloat(&EnCtx, UsefulBufUtil_CopyUint32ToFloat(pNaNTestCase->uSingle));
         uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex+100, 29, uErr);;
         }
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         if(UsefulBuf_Compare(TestOutput, pNaNTestCase->Preferred)) {
            return MakeTestResultCode(uTestIndex+100, 30, 200);
         }
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         if(UsefulBuf_Compare(TestOutput, pNaNTestCase->NotPreferred)) {
            return MakeTestResultCode(uTestIndex+100, 31, 200);
         }
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */

         /* NaN Encode of Not Preferred */
         QCBOREncode_Init(&EnCtx, TestOutBuffer);
         QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);
         QCBOREncode_AddFloatNoPreferred(&EnCtx, UsefulBufUtil_CopyUint32ToFloat(pNaNTestCase->uSingle));
         uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex+100, 32, uErr);;
         }
         if(UsefulBuf_Compare(TestOutput, pNaNTestCase->NotPreferred)) {
            return MakeTestResultCode(uTestIndex+100, 33, 200);
         }

         /* NaN Decode of Preferred */
         QCBORDecode_Init(&DCtx, pNaNTestCase->Preferred, 0);
         QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);
         uErr = QCBORDecode_GetNext(&DCtx, &Item);
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex+100, 34, uErr);
         }
         uDecoded = UsefulBufUtil_CopyDoubleToUint64(Item.val.dfnum);
         if(uDecoded != pNaNTestCase->uExpectedDouble) {
            return MakeTestResultCode(uTestIndex+100, 35, 200);
         }
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         if(pNaNTestCase->Preferred.len == 5) {
            uint32_t uDecoded2x = UsefulBufUtil_CopyFloatToUint32(Item.val.fnum);
            if(uDecoded2x != pNaNTestCase->uSingle) {
               return MakeTestResultCode(uTestIndex+100, 36, 200);
            }
         } else {
            if(uErr != QCBOR_ERR_PREFERRED_FLOAT_DISABLED) {
               return MakeTestResultCode(uTestIndex+100, 37, 200);
            }
         }
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */

         /* NaN Decode of Not Preferred */
         QCBORDecode_Init(&DCtx, pNaNTestCase->NotPreferred, 0);
         QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);
         uErr = QCBORDecode_GetNext(&DCtx, &Item);
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex+100, 38, uErr);
         }
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         uDecoded = UsefulBufUtil_CopyDoubleToUint64(Item.val.dfnum);
         if(uDecoded != pNaNTestCase->uExpectedDouble) {
            return MakeTestResultCode(uTestIndex+100, 39, 200);
         }
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         if(pNaNTestCase->NotPreferred.len == 5) {
            uint32_t uDecoded22 = UsefulBufUtil_CopyFloatToUint32(Item.val.fnum);
            if(uDecoded22 != pNaNTestCase->uSingle) {
               return MakeTestResultCode(uTestIndex+100, 40, 200);
            }
         }
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */

         if(HWCheckDoubleToFloat(pNaNTestCase->uSingle, pNaNTestCase->uExpectedDouble)) {
            return MakeTestResultCode(uTestIndex+100, 401, 200);
         }

         /* Deterministic NaN Encode */
         QCBOREncode_Init(&EnCtx, TestOutBuffer);
         QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_DETERMINISTIC| QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);
         QCBOREncode_AddFloat(&EnCtx, UsefulBufUtil_CopyUint32ToFloat(pNaNTestCase->uSingle));
         uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex+100, 41, uErr);;
         }
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         if(UsefulBuf_Compare(TestOutput, pNaNTestCase->Deterministic)) {
            return MakeTestResultCode(uTestIndex+100, 42, 200);
         }
#else /* ! #ifndef QCBOR_DISABLE_PREFERRED_FLOAT */
         if(UsefulBuf_Compare(TestOutput, pNaNTestCase->NotPreferred)) {
            return MakeTestResultCode(uTestIndex+100, 43, 200);
         }
#endif /* ! #ifndef QCBOR_DISABLE_PREFERRED_FLOAT */

         /* NaN Encode of DCBOR */
         QCBOREncode_Init(&EnCtx, TestOutBuffer);
         QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_DCBOR | QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD);
         QCBOREncode_AddFloat(&EnCtx, UsefulBufUtil_CopyUint32ToFloat(pNaNTestCase->uSingle));
         uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         if(uErr != QCBOR_SUCCESS) {
            return MakeTestResultCode(uTestIndex+100, 44, uErr);;
         }
         if(UsefulBuf_Compare(TestOutput, pNaNTestCase->DCBOR)) {
            return MakeTestResultCode(uTestIndex+100, 45, 200);
         }
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         if(uErr != QCBOR_ERR_PREFERRED_FLOAT_DISABLED) {
            return MakeTestResultCode(uTestIndex+100, 46, uErr);
         }
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
      }
   }

   /* Special one-off for 100% coverage */
   QCBOREncode_Init(&EnCtx, TestOutBuffer);
   QCBOREncode_Config(&EnCtx, QCBOR_ENCODE_CONFIG_DCBOR);
   QCBOREncode_AddFloat(&EnCtx, 0);
   uErr = QCBOREncode_Finish(&EnCtx, &TestOutput);
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
   if(uErr != QCBOR_SUCCESS) {
      return MakeTestResultCode(199, 100, uErr);;
   }
   if(UsefulBuf_Compare(TestOutput, UsefulBuf_FROM_SZ_LITERAL("\x00"))) {
      return MakeTestResultCode(199, 101, 200);
   }
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
   if(uErr != QCBOR_ERR_PREFERRED_FLOAT_DISABLED) {
      return MakeTestResultCode(uTestIndex+100, 261, uErr);
   }
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */

   return 0;
}


/* Public function. See float_tests.h */
int32_t
HalfPrecisionAgainstRFCCodeTest(void)
{
   QCBORItem          Item;
   QCBORDecodeContext DC;
   unsigned char      pbHalfBytes[2];
   uint8_t            uHalfPrecInitialByte;
   double             d;
   UsefulBuf_MAKE_STACK_UB(EncodedBytes, 3);
   UsefulOutBuf      UOB;
   uint32_t          uHalfP;


   for(uHalfP = 0; uHalfP < 0xffff; uHalfP += 60) {
      pbHalfBytes[1] = (uint8_t)(uHalfP & 0xff);
      pbHalfBytes[0] = (uint8_t)(uHalfP >> 8); /* uHalfP is always less than 0xffff */
      d = decode_half(pbHalfBytes);

      /* Construct the CBOR for the half-precision float by hand */
      UsefulOutBuf_Init(&UOB, EncodedBytes);

      uHalfPrecInitialByte = (uint8_t)(HALF_PREC_FLOAT + (CBOR_MAJOR_TYPE_SIMPLE << 5)); /* 0xf9 */
      UsefulOutBuf_AppendByte(&UOB, uHalfPrecInitialByte); /* initial byte */
      UsefulOutBuf_AppendUint16(&UOB, (uint16_t)uHalfP);   /* argument */

      /* Now parse the hand-constructed CBOR. This will invoke the
       * conversion to a float
       */
      QCBORDecode_Init(&DC, UsefulOutBuf_OutUBuf(&UOB), 0);
      QCBORDecode_GetNext(&DC, &Item);
      if(Item.uDataType != QCBOR_TYPE_DOUBLE) {
         return -1;
      }

      if(isnan(d)) {
         /* The RFC code uses the native instructions which may or may not
          * handle sNaN, qNaN and NaN payloads correctly. This test just
          * makes sure it is a NaN and doesn't worry about the type of NaN
          */
         if(!isnan(Item.val.dfnum)) {
            return -3;
         }
      } else {
         if(Item.val.dfnum != d) {
            return -2;
         }
      }
   }
   return 0;
}

#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT */


/*
 * Some encoded floating point numbers that are used for both
 * encode and decode tests.
 *
 * [0.0,  // Half
 *  3.14, // Double
 *  0.0,  // Double
 *  NaN,  // Double
 *  Infinity, // Double
 *  0.0,  // Half (Duplicate because of use in encode tests)
 *  3.140000104904175, // Single  XXX
 *  0.0,  // Single  XXX
 *  NaN,  // Single XXX
 *  Infinity, // Single XXX
 *  {100: 0.0, 101: 3.1415926, "euler": 2.718281828459045, 105: 0.0,
 *   102: 0.0, 103: 3.141592502593994, "euler2": 2.7182817459106445, 106: 0.0}]
 */
static const uint8_t spExpectedFloats[] = {
   0x8B,
      0xF9, 0x00, 0x00,
      0xFB, 0x40, 0x09, 0x1E, 0xB8, 0x51, 0xEB, 0x85, 0x1F,
      0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x7F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xF9, 0x00, 0x00,
      0xFA, 0x40, 0x48, 0xF5, 0xC3,
      0xFA, 0x00, 0x00, 0x00, 0x00,
      0xFA, 0x7F, 0xC0, 0x00, 0x00,
      0xFA, 0x7F, 0x80, 0x00, 0x00,
      0xA8,
         0x18, 0x64,
          0xF9, 0x00, 0x00,
         0x18, 0x65,
          0xFB, 0x40, 0x09, 0x21, 0xFB, 0x4D, 0x12, 0xD8, 0x4A,
         0x65, 0x65, 0x75, 0x6C, 0x65, 0x72,
          0xFB, 0x40, 0x05, 0xBF, 0x0A, 0x8B, 0x14, 0x57, 0x69,
         0x18, 0x69,
          0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x18, 0x66,
          0xF9, 0x00, 0x00,
         0x18, 0x67,
          0xFA, 0x40, 0x49, 0x0F, 0xDA,
         0x66, 0x65, 0x75, 0x6C, 0x65, 0x72, 0x32,
          0xFA, 0x40, 0x2D, 0xF8, 0x54,
         0x18, 0x6A,
          0xFA, 0x00, 0x00, 0x00, 0x00};

#ifndef USEFULBUF_DISABLE_ALL_FLOAT
static const uint8_t spExpectedFloatsNoHalf[] = {
   0x8B,
      0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x40, 0x09, 0x1E, 0xB8, 0x51, 0xEB, 0x85, 0x1F,
      0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFB, 0x7F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xFA, 0x00, 0x00, 0x00, 0x00,
      0xFA, 0x40, 0x48, 0xF5, 0xC3,
      0xFA, 0x00, 0x00, 0x00, 0x00,
      0xFA, 0x7F, 0xC0, 0x00, 0x00,
      0xFA, 0x7F, 0x80, 0x00, 0x00,
      0xA8,
         0x18, 0x64,
          0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x18, 0x65,
          0xFB, 0x40, 0x09, 0x21, 0xFB, 0x4D, 0x12, 0xD8, 0x4A,
         0x65, 0x65, 0x75, 0x6C, 0x65, 0x72,
          0xFB, 0x40, 0x05, 0xBF, 0x0A, 0x8B, 0x14, 0x57, 0x69,
         0x18, 0x69,
          0xFB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x18, 0x66,
          0xFA, 0x00, 0x00, 0x00, 0x00,
         0x18, 0x67,
          0xFA, 0x40, 0x49, 0x0F, 0xDA,
         0x66, 0x65, 0x75, 0x6C, 0x65, 0x72, 0x32,
          0xFA, 0x40, 0x2D, 0xF8, 0x54,
         0x18, 0x6A,
          0xFA, 0x00, 0x00, 0x00, 0x00};


/* Public function. See float_tests.h */
int32_t
GeneralFloatEncodeTests(void)
{
   /* See FloatNumberTests() for tests that really cover lots of float values.
    * Add new tests for new values or decode modes there.
    * This test is primarily to cover all the float encode methods. */

   UsefulBufC Encoded;
   UsefulBufC ExpectedFloats;
   QCBORError uErr;

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
   UsefulBuf_MAKE_STACK_UB(OutBuffer, sizeof(spExpectedFloats));
   ExpectedFloats = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedFloats);
   (void)spExpectedFloatsNoHalf; /* Avoid unused variable error */
#else
   UsefulBuf_MAKE_STACK_UB(OutBuffer, sizeof(spExpectedFloatsNoHalf));
   ExpectedFloats = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedFloatsNoHalf);
   (void)spExpectedFloats; /* Avoid unused variable error */
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */

   QCBOREncodeContext EC;
   QCBOREncode_Init(&EC, OutBuffer);
   QCBOREncode_OpenArray(&EC);

   QCBOREncode_AddDouble(&EC, 0.0);
   QCBOREncode_AddDouble(&EC, 3.14);
   QCBOREncode_AddDoubleNoPreferred(&EC, 0.0);
   QCBOREncode_AddDoubleNoPreferred(&EC, NAN);
   QCBOREncode_AddDoubleNoPreferred(&EC, INFINITY);

   QCBOREncode_AddFloat(&EC, 0.0);
   QCBOREncode_AddFloat(&EC, 3.14f);
   QCBOREncode_AddFloatNoPreferred(&EC, 0.0f);
   QCBOREncode_AddFloatNoPreferred(&EC, NAN);
   QCBOREncode_AddFloatNoPreferred(&EC, INFINITY);

   QCBOREncode_OpenMap(&EC);

   QCBOREncode_AddDoubleToMapN(&EC, 100, 0.0);
   QCBOREncode_AddDoubleToMapN(&EC, 101, 3.1415926);
   QCBOREncode_AddDoubleToMap(&EC, "euler", 2.71828182845904523536);
   QCBOREncode_AddDoubleNoPreferredToMapN(&EC, 105, 0.0);

   QCBOREncode_AddFloatToMapN(&EC, 102, 0.0f);
   QCBOREncode_AddFloatToMapN(&EC, 103, 3.1415926f);
   QCBOREncode_AddFloatToMap(&EC, "euler2", 2.71828182845904523536f);
   QCBOREncode_AddFloatNoPreferredToMapN(&EC, 106, 0.0f);

   QCBOREncode_CloseMap(&EC);
   QCBOREncode_CloseArray(&EC);

   uErr = QCBOREncode_Finish(&EC, &Encoded);
   if(uErr) {
      return -1;
   }

   if(UsefulBuf_Compare(Encoded, ExpectedFloats)) {
      return -3;
   }

   return 0;
}

#endif /* USEFULBUF_DISABLE_ALL_FLOAT */


/* Public function. See float_tests.h */
int32_t
GeneralFloatDecodeTests(void)
{
   /* See FloatNumberTests() for tests that really covers the float values.
    * This is retained to cover GetDouble() and decode of a single 0 */

   QCBORItem          Item;
   QCBORError         uErr;
   QCBORDecodeContext DC;
   UsefulBufC TestData = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedFloats);
   QCBORDecode_Init(&DC, TestData, 0);

   QCBORDecode_GetNext(&DC, &Item);
   if(Item.uDataType != QCBOR_TYPE_ARRAY) {
      return MakeTestResultCode(0, 1, 0);
   }

   /* 0.0 half-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_PREF_FLOAT(QCBOR_SUCCESS)
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != 0.0
#else /* QCBOR_DISABLE_PREFERRED_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
   ) {
      return MakeTestResultCode(0, 2, uErr);
   }

   /* 3.14 double-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != 3.14
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 3, uErr);
   }

   /* 0.0 double-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != 0.0
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 4, uErr);
   }

   /* NaN double-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || !isnan(Item.val.dfnum)
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 5, uErr);
   }

   /* Infinity double-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != INFINITY
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 6, uErr);
   }

   /* 0.0 half-precision (again) */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_PREF_FLOAT(QCBOR_SUCCESS)
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != 0.0
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
   ) {
      return MakeTestResultCode(0, 7, uErr);
   }

   /* 3.140000104904175 single-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || 3.1400001049041748 != Item.val.dfnum
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
      || Item.uDataType != QCBOR_TYPE_FLOAT
      || 3.140000f != Item.val.fnum
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 8, uErr);
   }

   /* 0.0 single-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != 0.0
#else /* QCBOR_DISABLE_FLOAT_HW_USE */
      || Item.uDataType != QCBOR_TYPE_FLOAT
      || Item.val.fnum != 0.0f
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 9, uErr);
   }

   /* NaN single-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || !isnan(Item.val.dfnum)
#else /* QCBOR_DISABLE_PREFERRED_FLOAT */
      || Item.uDataType != QCBOR_TYPE_FLOAT
      || !isnan(Item.val.fnum)
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 10, uErr);
   }

   /* Infinity single-precision */
   uErr = QCBORDecode_GetNext(&DC, &Item);
   if(uErr != FLOAT_ERR_CODE_NO_FLOAT(QCBOR_SUCCESS)
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || Item.uDataType != QCBOR_TYPE_DOUBLE
      || Item.val.dfnum != INFINITY
#else /* QCBOR_DISABLE_PREFERRED_FLOAT */
      || Item.uDataType != QCBOR_TYPE_FLOAT
      || Item.val.fnum != INFINITY
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
#else /* USEFULBUF_DISABLE_ALL_FLOAT */
      || Item.uDataType != QCBOR_TYPE_NONE
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   ) {
      return MakeTestResultCode(0, 11, uErr);
   }
   /* Sufficent test coverage. Don't need to decode the rest. */


#ifndef USEFULBUF_DISABLE_ALL_FLOAT
   /* Now tests for spiffy decode main function */
   TestData = UsefulBuf_FROM_BYTE_ARRAY_LITERAL(spExpectedFloats);
   double d;
   QCBORDecode_Init(&DC, TestData, 0);
   QCBORDecode_EnterArray(&DC, NULL);

   /* 0.0 half-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != FLOAT_ERR_CODE_NO_PREF_FLOAT(QCBOR_SUCCESS)
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || d != 0.0
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
      ) {
      return MakeTestResultCode(1, 1, uErr);
   }

   /* 3.14 double-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != QCBOR_SUCCESS || d != 3.14) {
      return MakeTestResultCode(1, 2, uErr);
   }

   /* 0.0 double-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != QCBOR_SUCCESS || d != 0.0) {
      return MakeTestResultCode(1, 3, uErr);
   }

   /* NaN double-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != QCBOR_SUCCESS || !isnan(d)) {
      return MakeTestResultCode(1, 4, uErr);
   }

   /* Infinity double-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != QCBOR_SUCCESS || d != INFINITY) {
      return MakeTestResultCode(1, 5, uErr);
   }

   /* 0.0 half-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != FLOAT_ERR_CODE_NO_PREF_FLOAT(QCBOR_SUCCESS)
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || d != 0.0
#endif /* QCBOR_DISABLE_PREFERRED_FLOAT */
      ) {
      return MakeTestResultCode(1, 6, uErr);
   }

   /* 3.140000104904175 single-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != FLOAT_ERR_CODE_NO_PREF_FLOAT(QCBOR_SUCCESS) /* Different in 2.0 and 1.6 */
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || d != 3.140000104904175
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
      ) {
      return MakeTestResultCode(1, 7, uErr);
   }

   /* 0.0 single-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != FLOAT_ERR_CODE_NO_PREF_FLOAT(QCBOR_SUCCESS) /* Different in 2.0 and 1.6 */
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || d != 0.0
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
      ) {
      return MakeTestResultCode(1, 8, uErr);
   }

   /* NaN single-precision */
   QCBORDecode_GetDouble(&DC, &d);
   if(uErr != FLOAT_ERR_CODE_NO_PREF_FLOAT(QCBOR_SUCCESS) /* Different in 2.0 and 1.6 */
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
      || !isnan(d)
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
      ) {
      return MakeTestResultCode(1, 9, uErr);
   }

   /* Infinity single-precision */
   QCBORDecode_GetDouble(&DC, &d);
   uErr = QCBORDecode_GetAndResetError(&DC);
   if(uErr != FLOAT_ERR_CODE_NO_PREF_FLOAT(QCBOR_SUCCESS) /* Different in 2.0 and 1.6 */
#ifndef QCBOR_DISABLQCBOR_DISABLE_PREFERRED_FLOATE_FLOAT_HW_USE
      || d != INFINITY
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
      ) {
      return MakeTestResultCode(1, 10, uErr);
   }

#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
   return 0;
}

