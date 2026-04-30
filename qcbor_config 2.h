/* ==========================================================================
 * qcbor_config.h -- common ifdef config
 *
 * Copyright (c) 2026, Laurence Lundblade.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Created by Laurence Lundblade on 4/30/26.
 * ========================================================================== */


#ifndef decode_nesting_h
#define decode_nesting_h

//#define QCBOR_DISABLE_FLOAT_HW_USE
//#define QCBOR_DISABLE_PREFERRED_FLOAT
//#define QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
//#define QCBOR_DISABLE_ENCODE_USAGE_GUARDS
//#define QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
//#define QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
//#define QCBOR_DISABLE_UNCOMMON_TAGS
//#define USEFULBUF_DISABLE_ALL_FLOAT
//#define QCBOR_DISABLE_TAGS
//#define QCBOR_DISABLE_NON_INTEGER_LABELS


/*

A: just part of XCode project as a pre fix header file; released, but not used other than by XCode project



B: Don't release it. Then


B: Release it or no


CMake has this list, but we don't use cmake to create the XCode project and don't want to, at least not yet.
 Also don't want to remake the XCode project for every change


 If this isn't released, it goes in QDV. How to include it in all builds without
 errors?








 */

#endif /* Header_h */
