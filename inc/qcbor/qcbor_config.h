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


#ifndef qcbor_config_h
#define qcbor_config_h


/**
 * @file qcbor_config.h
 *
 * Compile-time feature-disabling and size configuration.
 */


/**
 * If defined, this names the configuration header which will be
 * included instead of `"qcbor/qcbor_config.h". It allows for special
 * builds, building vendored copies of QCBOR and such. This macro is
 * never used for installed builds (they install a customized
 * copy of this file). When setting this, consider using
 * a different name like "my_config.h" to avoid confusing include
 * path accidents.
 *
 * This macro is mentioned here only to document it along side the
 * other configuration macros. Since it names this file, changing it
 * here has no effect. Instead set it on the compiler command line.
 */
//#define QCBOR_CONFIG_FILE "qcbor/qcbor_config.h"


/**
 * The options for disabling floating-point are detailed in the section
 * on @ref Floating-Point. In short, `QCBOR_DISABLE_PREFERRED_FLOAT`
 * eliminates a lot of floating-point-related code, particularly
 * half-precision support.
*/
//#define QCBOR_DISABLE_FLOAT_HW_USE


/**
 * `QCBOR_DISABLE_FLOAT_HW_USE` eliminates
 * dependency on the math library and `<math.h>.
 */
//#define QCBOR_DISABLE_PREFERRED_FLOAT


 /**
  * `USEFULBUF_DISABLE_ALL_FLOAT` eliminates all float-point dependency,
  * such that the types double and float aren't used.
  */
//#define USEFULBUF_DISABLE_ALL_FLOAT


/** `QCBOR_DISABLE_ENCODE_USAGE_GUARDS` affects encoding only. It doesn't
 * disable any encoding features, just extra error checking that helps
 * debugging.  Disable it when you are confident that an encoding
 * implementation is complete and correct.
 */
//#define QCBOR_DISABLE_ENCODE_USAGE_GUARDS


/** Indefinite lengths are a feature of CBOR that makes encoding simpler
 * and the decoding more complex. They allow the encoder to not have to
 * know the length of a string, map, or array when they start encoding
 * it. Their main use is when encoding has to be done on a very
 * constrained device.  Conversely, when decoding on a very constrained
 * device, it is good to prohibit use of indefinite lengths so the
 * decoder can be smaller.
 *
 * The QCBOR decode API processes both definite and indefinite lengths
 * with the same API, except that to decode indefinite-length strings, a
 * storage allocator must be configured.
 *
 * To reduce the size of the decoder, define
 * `QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS`, particularly if you are not
 * configuring a storage allocator.
 */
//#define QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS


/**
 * Further reduction can be acheived by defining
 * `QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS`, which will result in an error
 * when an indefinite-length map or array arrives for decoding.
 */
//#define QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS


/** `QCBOR_DISABLE_UNCOMMON_TAGS` disables the decoding of explicit tags for
 * base 64, regex, UUID and MIME data. This just disables the automatic
 * recognition of these from a major type 6 tag.
 */
//#define QCBOR_DISABLE_UNCOMMON_TAGS


/**
 *`QCBOR_DISABLE_EXP_AND_MANTISSA` disables the decoding of decimal
 * fractions and big floats.
 */
//#define QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA


/**
 * @anchor QCBOR_DISABLE_TAGS
 *
 * `QCBOR_DISABLE_TAGS` disables decoding of all CBOR tags. If the input
 * contains any tag, an unrecoverable error (@ref
 * QCBOR_ERR_TAGS_DISABLED) is raised.  When this option is enabled, the
 * decoder is suitable only for protocols that do not use CBOR tags.
 *
 * Setting `QCBOR_DISABLE_TAGS` reduces the size of the decoder core —
 * particularly QCBORDecode_VGetNext() — by approximately 500 bytes.
 *
 * “Borrowed” tag content formats (for example, an epoch-based date
 * encoded without the corresponding tag number) can still be
 * decoded.
 */
//#define QCBOR_DISABLE_TAGS


/**
 * `QCBOR_DISABLE_NON_INTEGER_LABELS` causes any label that doesn't fit
 * in an int64_t to result in a @ref QCBOR_ERR_MAP_LABEL_TYPE error.
 * This also disables `QCBOR_DECODE_MODE_MAP_AS_ARRAY` and
 * `QCBOR_DECODE_MODE_MAP_STRINGS_ONLY`. It is fairly common for
 * CBOR-based protocols to use only small integers as labels.
 */
//#define QCBOR_DISABLE_NON_INTEGER_LABELS


/** Everything that can be disabled, the above-mentioned items, is disabled.*/
//#define QCBOR_DISABLE_ALL




/* Maximum nesting depth of arrays and maps. See QCBOR_MAX_ARRAY_NESTING
 * in qcbor_common.h for the default, limits and memory cost. */
//#define QCBOR_MAX_ARRAY_NESTING  35


/* See QCBOR_NUM_MAPPED_TAGS in qcbor_common.h for the default, limits
 * and memory cost. */
//#define QCBOR_NUM_MAPPED_TAGS  4


/* See QCBOR_MAX_TAGS_PER_ITEM in qcbor_common.h for the default, limits
 * and memory cost. */
//#define QCBOR_MAX_TAGS_PER_ITEM 4

#endif /* qcbor_config_h */
