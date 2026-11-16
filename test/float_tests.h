/* ===========================================================================
 * float_tests.h -- tests for floats and conversion to/from half-precision
 *
 * Copyright (c) 2018-2025, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in file named "LICENSE"
 *
 * Created on 9/19/18
 * ==========================================================================*/

#ifndef float_tests_h
#define float_tests_h

#include <stdint.h>



/*
 * This tests floating point encoding, decoding
 * and conversion for lots of different values.
 * It covers Preferred Serialization processing
 * of floating point.  It's focus is on the numbers
 * not the encode/decode functions.
 */
int32_t FloatValuesTests(void);

int32_t FloatDecodeTest(void);

/*
 * This calls each and every method for encoding
 * floating-point numbers.
 */
int32_t GeneralFloatEncodeTests(void);


/*
 * Tests float decoding, including error codes in scenarios
 * where various float features are disabled. This also
 * tests decoding using spiffy decode methods.
 */
int32_t GeneralFloatDecodeTests(void);



/* The float test cases are exported so they can be used in
 * qdv/more_tests/... Just a local hack export for test.
 */
#include "UsefulBuf.h"

struct FloatTestCase {

   /* Always filled in with the test value */
   double      dNumber;

   /* Float representation of dNumber, but only when the exact same
    * value can be represented as a float with no precision loss. */
   float       fNumber;

   /* The preferred CBOR serialization. Both dNumber and fNumber encode
    * to this. */
   /* TODO: Preferred vs PreferredPlus, which is only to do with NaNs */
   UsefulBufC  Preferred;

   /* Always the direct type 7 encoding of dNumber in 9 bytes with no reduction. */
   UsefulBufC  NotPreferred;

   /* Not that important as have turned out to be exactly the same as Preferred */
   UsefulBufC  Deterministic;
   UsefulBufC  DCBOR;
};


extern const struct FloatTestCase FloatTestCases[];


#endif /* float_tests_h */
