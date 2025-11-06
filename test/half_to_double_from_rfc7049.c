/*

 Copyright (c) 2013 IETF Trust and the persons identified as the
 document authors.  All rights reserved.

 Copyright (c) 2021, Arm Limited. All rights reserved.

 This document is subject to BCP 78 and the IETF Trust's Legal
 Provisions Relating to IETF Documents
 (http://trustee.ietf.org/license-info) in effect on the date of
 publication of this document.  Please review these documents
 carefully, as they describe your rights and restrictions with respect
 to this document.  Code Components extracted from this document must
 include Simplified BSD License text as described in Section 4.e of
 the Trust Legal Provisions and are provided without warranty as
 described in the Simplified BSD License.

 */

/*
 This code is from RFC 7049/8949. It is not used in the main implementation
 because:
   a) it adds a dependency on <math.h> and ldexp().
   b) the license may be an issue

 QCBOR does support half-precision, but rather than using
 floating-point math like this, it does it with bit shifting
 and masking.

 This code is here to test that code.

 */

#include "half_to_double_from_rfc7049.h"

#include <math.h>

#ifndef USEFULBUF_DISABLE_ALL_FLOAT
double decode_half(const unsigned char *halfp) {
    int half = (halfp[0] << 8) + halfp[1];
    int exp = (half >> 10) & 0x1f;
    int mant = half & 0x3ff;
    double val;
    if (exp == 0) val = ldexp(mant, -24);
    else if (exp != 31) val = ldexp(mant + 1024, exp - 25);
    else val = mant == 0 ? INFINITY : NAN;
    return half & 0x8000 ? -val : val;
}


/* This is a first version from Carsten in July 2025 to be published in
 * an RFC. Probably there will be updates. */
/* returns 0..0xFFFF if float16 encoding possible, -1 otherwise.
   b64 is a binary64 floating point as an unsigned long. */
int try_float16_encode(unsigned long b64) {
  unsigned long s16 = (b64 >> 48) & 0x8000UL;
  unsigned long mant = b64 & 0xfffffffffffffUL;
  unsigned long exp = b64 >> 52 & 0x7ffUL;
  if (exp == 0 && mant == 0)    /* f64 denorms are out of range */
    return (int)s16;                 /* so handle 0.0 and -0.0 only */
  if (exp >= 999 && exp < 1009) { /* f16 denorm, exp16 = 0 */
    if (mant & ((1UL << (1051 - exp)) - 1))
      return -1;                /* bits lost in f16 denorm */
    return (int)(s16 + ((mant + 0x10000000000000UL) >> (1051 - exp)));
  }
  if (mant & 0x3ffffffffffUL)   /* bits lost in f16 */
    return -1;
  if (exp >= 1009 && exp <= 1038) /* normalized f16 */
    return (int)(s16 + ((exp - 1008) << 10) + (mant >> 42));
  if (exp == 2047)              /* Inf, NaN */
    return (int)(s16 + 0x7c00UL + (mant >> 42));
  return -1;
}


#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
