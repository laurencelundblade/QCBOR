/*==============================================================================
 float_tests.h -- tests for float and conversion to/from half-precision

 Copyright (c) 2018-2020, Laurence Lundblade. All rights reserved.

 SPDX-License-Identifier: BSD-3-Clause

 See BSD-3-Clause license in README.md

 Created on 9/19/18
 =============================================================================*/

#ifndef float_tests_h
#define float_tests_h

#include <stdint.h>

#ifndef QCBOR_CONFIG_DISABLE_ENCODE_IEEE754

int32_t HalfPrecisionDecodeBasicTests(void);

int32_t DoubleAsSmallestTest(void);

int32_t HalfPrecisionAgainstRFCCodeTest(void);

#endif /* QCBOR_CONFIG_DISABLE_ENCODE_IEEE754 */


#endif /* float_tests_h */
