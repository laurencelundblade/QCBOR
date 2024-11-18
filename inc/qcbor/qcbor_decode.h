/* ===========================================================================
 * Copyright (c) 2016-2018, The Linux Foundation.
 * Copyright (c) 2018-2024, Laurence Lundblade.
 * Copyright (c) 2021, Arm Limited.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors, nor the name "Laurence Lundblade" may be used to
 *       endorse or promote products derived from this software without
 *       specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ========================================================================= */


#ifndef qcbor_decode_h
#define qcbor_decode_h


#include "qcbor/qcbor_common.h"
#include "qcbor/qcbor_private.h"
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#if 0
} /* Keep editor indention formatting happy */
#endif
#endif


/**
 * @file qcbor_decode.h
 *
 * @anchor BasicDecode
 * # QCBOR Basic Decode
 *
 * This section discusses decoding assuming familiarity with the
 * general description of this encoder-decoder in section @ref
 * Overview.
 *
 * Encoded CBOR has a tree structure where the leaf nodes are
 * non-aggregate types like integers and strings and the intermediate
 * nodes are either arrays or maps. Fundamentally, CBOR decoding is a
 * pre-order traversal of this tree with CBOR sequences a minor
 * exception. Calling QCBORDecode_GetNext() repeatedly will perform
 * this. QCBOR maintains an internal traversal cursor. It is possible
 * to decode any CBOR by only calling QCBORDecode_GetNext(), though
 * this doesn't take advantage of many QCBOR features.
 *
 * QCBORDecode_GetNext() returns a 56 byte structure called
 * @ref QCBORItem that describes the decoded item including:
 * - The data itself, integer, string, floating-point number...
 * - The label if present
 * - Unprocessed tags
 * - Nesting level
 * - Allocation type (primarily of interest for indefinite length strings)
 *
 * For strings, this structure contains a pointer and length back into
 * the original data.
 *
 * Most of the tags that QCBOR supports directly are decoded into a
 * representation in @ref QCBORItem.
 *
 * A string allocator must be used when decoding indefinite length
 * strings. See QCBORDecode_SetMemPool() or
 * QCBORDecode_SetUpAllocator(). @ref QCBORItem indicates if a string
 * was allocated with the string allocator.
 *
 * This pre-order traversal gives natural decoding of arrays where the
 * array members are taken in order. Maps can be decoded this way too,
 * but the @ref SpiffyDecode APIs that allow searching maps by label
 * are often more convenient.
 *
 * @anchor Decode-Errors-Overview
 * # Decode Errors Overview
 *
 * The simplest way to handle decoding errors is to make use of the
 * internal error tracking. The only error code check necessary is
 * at the end when QCBORDecode_Finish() is called. To do this:
 *
 * - Use QCBORDecode_VGetNext(), QCBORDecode_VPeekNext()
 *  and any or all of the functions in qcbor_spiffy_decode.h. Don't use
 *  QCBORDecode_GetNext() or QCBORDecode_PeekNext().
 * - Call QCBORDecode_Finish() and check its return code.
 * - Do not reference any decoded data until after
 *    QCBORDecode_Finish() returns success.
 *
 * Once an encoding error has been encountered, the error state is
 * entered and further decoding function calls will do nothing.  It is
 * safe to continue calling decoding functions after an error. No
 * error checking is necessary making the code to decode a protocol
 * simpler.  The two exceptions are QCBORDecode_GetNext() and
 * QCBORDecode_PeekNext() which will try to decode even if the decoder
 * is in the error state. Use QCBORDecode_VGetNext() and
 * QCBORDecode_VPeekNext() instead.
 *
 * While some protocols are simple enough to be decoded this way, many
 * aren’t because the data items earlier in the protocol determine how
 * later data items are to be decoded. In that case it is necessary to
 * call QCBORDecode_GetError() to know the earlier items were
 * successfully decoded before examining their value or type.
 *
 * The internal decode error state can be reset by reinitializing the
 * decoder or calling QCBORDecode_GetErrorAndReset(). Code calling
 * QCBOR may take advantage of the internal error state to halt
 * futher decoding and propagate errors it detects using
 * QCBORDecode_SetError().
 *
 * It is only useful to reset the error state by calling
 * QCBORDecode_GetErrorAndReset() on recoverable errors. Examples of
 * recoverable errors are a map entry not being found or integer
 * overflow or underflow during conversion. Examples of unrecoverable
 * errors are hitting the end of the input and array or map nesting
 * beyond the limits of the implementation. See
 * QCBORDecode_IsUnrecoverableError().Trying to reset and decode after
 * an unrecoverable error will usually just lead to another error.
 *
 * It is possible to use QCBORDecode_GetNext() and
 * QCBORDecode_PeekNext() to decode an entire protocol. However, that is
 * usually more work, more code and less convenient than using spiffy
 * decode functions.
 *
 * It is also possible to mix the use of QCBORDecode_GetNext() with
 * QCBORDecode_VGetNext() and the spiffy decode functions, but
 * QCBORDecode_GetError() must be called and return QCBOR_SUCCESS before
 * QCBORDecode_GetNext() is called.
 *
 * The effect of a decoding error on the traversal cursor position
 * varies by the decoding method called. It is unaffected by spiffy
 * decode methods that get items by map label.
 * QCBORDecode_GetInt64InMapN() is an example of this. The traversal
 * cursor will be advanced by most other decode methods even when
 * there is a decode error, often leaving it in an indeterminate
 * position. If it is necessary to continue to decoding after an
 * error, QCBORDecode_Rewind() can be used to reset it to a known-good
 * position.
 *
 * When using spiffy decode methods to get an item by label from a map
 * the whole map is internally traversed including nested arrays and
 * maps. If there is any unrecoverable error during that traversal,
 * the retrieval by label will fail. The unrecoverable error will be
 * returned even if it is not because the item being sought is in
 * error. Recoverable errors will be ignored unless they are on the
 * item being sought, in which case the unrecoverable error will be
 * returned. Unrecoverable errors are those indicated by
 * QCBORDecode_IsUnrecoverableError().
 *
 * @anchor Disabilng-Tag-Decoding
 * # Disabilng Tag Decoding
 *
 * If QCBOR_DISABLE_TAGS is defined, all code for decoding tags will
 * be omitted reducing the core decoder, QCBORDecode_VGetNext(), by
 * about 400 bytes. If a tag number is encountered in the decoder
 * input the unrecoverable error @ref QCBOR_ERR_TAGS_DISABLED will be
 * returned.  No input with tags can be decoded.
 *
 * Decode functions like QCBORDecode_GetEpochDate() and
 * QCBORDecode_GetDecimalFraction() that can decode the tag content
 * even if the tag number is absent are still available.  Typically
 * they won't be linked in because of dead stripping. The
 * @c uTagRequirement parameter has no effect, but if it is
 * @ref QCBOR_TAG_REQUIREMENT_TAG, @ref QCBOR_ERR_TAGS_DISABLED
 * will be set.
 */

/**
 * The decode mode options.
 */
typedef enum {
   /** See QCBORDecode_Init() */
   QCBOR_DECODE_MODE_NORMAL = 0,
   /** See QCBORDecode_Init() */
   QCBOR_DECODE_MODE_MAP_STRINGS_ONLY = 1,
   /** See QCBORDecode_Init() */
   QCBOR_DECODE_MODE_MAP_AS_ARRAY = 2,
   /**
    * This checks that the input is encoded with preferred
    * serialization. The checking is performed as each item is
    * decoded. If no QCBORDecode_GetXxx() is called for an item,
    * there's no check on that item. Preferred serialization was first
    * defined in section 4.1 of RFC 8949, but is more sharply in
    * draft-ietf-cbor-cde. Summarizing, the requirements are: the use
    * of definite-length encoding only, integers, including string
    * lengths and tags, must be in shortest form, and floating-point
    * numbers must be reduced to shortest form all the way to
    * half-precision. */
   QCBOR_DECODE_MODE_PREFERRED = 3,

   /** This checks that maps in the input are sorted by label as
    * described in RFC 8949 section 4.2.1.  This also performs
    * duplicate label checking.  This mode adds considerable CPU-time
    * expense to decoding, though it is probably only of consequence
    * for large inputs on slow CPUs.
    *
    * This also performs all the checks that
    * QCBOR_DECODE_MODE_PREFERRED does. */
   QCBOR_DECODE_MODE_CDE = 4,
   
   /** This requires integer-float unification. It performs all the checks that
    * QCBOR_DECODE_MODE_CDE does. */
   QCBOR_DECODE_MODE_DCBOR = 5,

   /** Makes QCBOR v2 compatible with v1. The error @ref QCBOR_ERR_UNPROCESSED_TAG_NUMBER is not returned.
    * This can be or'd with the above modes. */
   QCBOR_DECODE_UNPROCESSED_TAG_NUMBERS = 8,

   /* This is stored in uint8_t in places; never add values > 255 */
} QCBORDecodeMode;

#define QCBOR_DECODE_MODE_MASK 0x07


/**
 * The maximum size of input to the decoder. Slightly less than
 * @c UINT32_MAX to make room for some special indicator values.
 */
#define QCBOR_MAX_DECODE_INPUT_SIZE (UINT32_MAX - 2)

/**
 * The maximum number of tags that may occur on an individual nested
 * item. Typically 4.
 */
#define QCBOR_MAX_TAGS_PER_ITEM QCBOR_MAX_TAGS_PER_ITEM1



/* Do not renumber these. Code depends on some of these values. */
/** The data type is unknown, unset or invalid. */
#define QCBOR_TYPE_NONE           0

/** Never used in QCBORItem. Used by functions that match QCBOR types. */
#define QCBOR_TYPE_ANY            1

/** Type for an integer that decoded either between @c INT64_MIN and
 *  @c INT32_MIN or @c INT32_MAX and @c INT64_MAX. Data is in member
 *  @c val.int64. See also \ref QCBOR_TYPE_65BIT_NEG_INT */
#define QCBOR_TYPE_INT64          2

/** Type for an integer that decoded to a more than @c INT64_MAX and
 *  @c UINT64_MAX.  Data is in member @c val.uint64. */
#define QCBOR_TYPE_UINT64         3

/** Type for an array. See comments on @c val.uCount. */
#define QCBOR_TYPE_ARRAY          4

/** Type for a map. See comments on @c val.uCount. */
#define QCBOR_TYPE_MAP            5

/** Type for a buffer full of bytes. Data is in @c val.string. */
#define QCBOR_TYPE_BYTE_STRING    6

/** Type for a UTF-8 string. It is not NULL-terminated. See
 *  QCBOREncode_AddText() for a discussion of line endings in CBOR. Data
 *  is in @c val.string.  */
#define QCBOR_TYPE_TEXT_STRING    7

/** Type for a positive big number. Data is in @c val.bignum, a
 *  pointer and a length. See QCBORDecode_ProcessBigNumber(). */
#define QCBOR_TYPE_POSBIGNUM      9

/** Type for a negative big number. Data is in @c val.bignum, a
 *  pointer and a length. Type 1 integers in the range of [-2^64,
 *  -2^63 - 1] are returned in this type.  1 MUST be subtracted from
 *  what is returned to get the actual value. This is because of the
 *  way CBOR negative numbers are represented. QCBOR doesn't do this
 *  because it can't be done without storage allocation and QCBOR
 *  avoids storage allocation for the most part.  For example, if 1 is
 *  subtraced from a negative big number that is the two bytes 0xff
 *  0xff, the result would be 0x01 0x00 0x00, one byte longer than
 *  what was received. See QCBORDecode_ProcessBigNumber(). */
#define QCBOR_TYPE_NEGBIGNUM     10

/** Type for [RFC 3339] (https://tools.ietf.org/html/rfc3339) date
 *  string, possibly with time zone. Data is in @c val.string . Note this
 *  was previously in @c val.dateString, however this is the same as
 *  val.string being the same type in same union. val.dateString will
 *  be deprecated.. */
#define QCBOR_TYPE_DATE_STRING   11

/** Type for integer seconds since Jan 1970 + floating-point
 *  fraction. Data is in @c val.epochDate */
#define QCBOR_TYPE_DATE_EPOCH    12

/** The CBOR major type "simple" has a small integer value indicating
 *  what it is. The standard CBOR simples are true, false, null, undef
 *  (values 20-23) and float-point numbers (values 25-27).  The values
 *  0-19 and 32-255 are unassigned and may be used if registered with
 *  in the IANA Simple Values Registry.  If these unassigned simple
 *  values occur in the input they will be decoded as this.  The value
 *  is in @c val.uSimple. */
#define QCBOR_TYPE_UKNOWN_SIMPLE 13

/** A decimal fraction made of decimal exponent and integer mantissa.
 *  See @ref expAndMantissa and QCBOREncode_AddTDecimalFraction(). */
#define QCBOR_TYPE_DECIMAL_FRACTION            14

/** A decimal fraction made of decimal exponent and positive big
 *  number mantissa. See @ref expAndMantissa and
 *  QCBOREncode_AddTDecimalFractionBigMantissa(). */
#define QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM 15

/** A decimal fraction made of decimal exponent and negative big
 *  number mantissa. See @ref expAndMantissa and
 *  QCBOREncode_AddTDecimalFractionBigMantissa(). */
#define QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM 16

/** A decimal fraction made of decimal exponent and positive
 * uint64_t . See QCBOREncode_AddTDecimalFractionBigMantissa(). */
#define QCBOR_TYPE_DECIMAL_FRACTION_POS_U64    79

/** A decimal fraction made of decimal exponent and negative big
 *  number mantissa. See @ref expAndMantissa and
 *  QCBOREncode_AddTDecimalFractionBigMantissa(). */
#define QCBOR_TYPE_DECIMAL_FRACTION_NEG_U64    80

/** A floating-point number made of base-2 exponent and integer
 *  mantissa.  See @ref expAndMantissa and
 *  QCBOREncode_AddTBigFloat(). */
#define QCBOR_TYPE_BIGFLOAT                    17

/** A floating-point number made of base-2 exponent and positive big
 *  number mantissa.  See @ref expAndMantissa and
 *  QCBOREncode_AddTBigFloatBigMantissa(). */
// TODO: rename to BIGMANTISSA?
#define QCBOR_TYPE_BIGFLOAT_POS_BIGNUM         18

/** A floating-point number made of base-2 exponent and negative big
 *  number mantissa.  See @ref expAndMantissa and
 *  QCBOREncode_AddTBigFloatBigMantissa(). */
#define QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM         19

/** A floating-point number made of base-2 exponent and positive big
 *  number mantissa.  See @ref expAndMantissa and
 *  QCBOREncode_AddTBigFloatBigMantissa(). */
// TODO: rename to U64MANTISSA
#define QCBOR_TYPE_BIGFLOAT_POS_U64            82

/** A floating-point number made of base-2 exponent and negative big
 *  number mantissa.  See @ref expAndMantissa and
 *  QCBOREncode_AddTBigFloatBigMantissa(). */
#define QCBOR_TYPE_BIGFLOAT_NEG_U64            83

/** Type for the simple value false. */
#define QCBOR_TYPE_FALSE         20

/** Type for the simple value true. */
#define QCBOR_TYPE_TRUE          21

/** Type for the simple value null. */
#define QCBOR_TYPE_NULL          22

/** Type for the simple value undef. */
#define QCBOR_TYPE_UNDEF         23

/** Type for a floating-point number. Data is in @c val.fnum. */
#define QCBOR_TYPE_FLOAT         26

/** Type for a double floating-point number. Data is in @c val.dfnum. */
#define QCBOR_TYPE_DOUBLE        27

/** Special type for integers between -2^63 - 1 to -2^64 that
 * can't be returned as @ref QCBOR_TYPE_INT64 because they don't fit
 * in an int64_t. The value is returned in @c val.uint64, but this
 * isn't the number transmitted. Do this arithmatic (carefully to
 * avoid over/underflow) to get the value transmitted: - val.uint64 - 1.
 * See QCBOREncode_AddNegativeUInt64() for a longer explanation
 * and warning. */
#define QCBOR_TYPE_65BIT_NEG_INT 28

#define QCBOR_TYPE_BREAK         31 /* Used internally; never returned */

/** For @ref QCBOR_DECODE_MODE_MAP_AS_ARRAY decode mode, a map that is
 *  being traversed as an array. See QCBORDecode_Init() */
#define QCBOR_TYPE_MAP_AS_ARRAY  32

/** Encoded CBOR that is wrapped in a byte string. Often used when the
 *  CBOR is to be hashed for signing or HMAC. See also @ref
 *  QBCOR_TYPE_WRAPPED_CBOR_SEQUENCE. Data is in @c val.string. */
#define QBCOR_TYPE_WRAPPED_CBOR  36

/** A URI as defined in RFC 3986.  Data is in @c val.string. */
#define QCBOR_TYPE_URI           44

/** Text is base64 URL encoded in RFC 4648.  The base64 encoding is
 *  NOT removed. Data is in @c val.string. */
#define QCBOR_TYPE_BASE64URL     45

/** Text is base64 encoded in RFC 4648.  The base64 encoding is NOT
 *  removed. Data is in @c val.string. */
#define QCBOR_TYPE_BASE64        46

/** PERL-compatible regular expression. Data is in @c val.string. */
#define QCBOR_TYPE_REGEX         47

/** Non-binary MIME per RFC 2045.  See also @ref
 *  QCBOR_TYPE_BINARY_MIME. Data is in @c val.string. */
#define QCBOR_TYPE_MIME          48

/** Binary UUID per RFC 4122.  Data is in @c val.string. */
#define QCBOR_TYPE_UUID          49

/** A CBOR sequence per RFC 8742. See also @ ref
 *  QBCOR_TYPE_WRAPPED_CBOR.  Data is in @c val.string. */
#define QBCOR_TYPE_WRAPPED_CBOR_SEQUENCE  75

/** Binary MIME per RFC 2045. See also @ref QCBOR_TYPE_MIME. Data is
 *  in @c val.string. */
#define QCBOR_TYPE_BINARY_MIME   76

/** Type for [RFC 8943](https://tools.ietf.org/html/rfc8943) date
 *  string, a date with no time or time zone info. Data is in
 *  @c val.string */
#define QCBOR_TYPE_DAYS_STRING   77

/** Type for integer days since Jan 1 1970 described in
 *  [RFC 8943](https://tools.ietf.org/html/rfc8943). Data is in
 *  @c val.epochDays */
#define QCBOR_TYPE_DAYS_EPOCH    78

/* 79, 80, 82, 83 is used above for decimal fraction and big float */


#define QCBOR_TYPE_TAG_NUMBER 127 /* Used internally; never returned */

/** Start of user-defined data types. The range is mainly for user-defined tag content
 * decoders. See QCBORTagContentCallBack */
#define QCBOR_TYPE_START_USER_DEFINED 128

/** End of user-defined data types. */
#define QCBOR_TYPE_END_USER_DEFINED 255


/**
 * The largest value in @c utags that is unmapped and can be used without
 * mapping it through QCBORDecode_GetNthTagNumber().
 */
#define QCBOR_LAST_UNMAPPED_TAG (CBOR_TAG_INVALID16 - QCBOR_NUM_MAPPED_TAGS - 1)


/**
 * @anchor expAndMantissa
 *
 * This holds the value for big floats and decimal fractions, as an
 * exponent and mantissa.  For big floats the base for exponentiation
 * is 2. For decimal fractions it is 10. Whether an instance is a big
 * float or decimal fraction is known by context, usually by @c uDataType
 * in @ref QCBORItem which might be @ref QCBOR_TYPE_DECIMAL_FRACTION,
 * @ref QCBOR_TYPE_BIGFLOAT, ...
 *
 * The mantissa may be an @c int64_t or a big number. This is again
 * determined by context, usually @c uDataType in @ref QCBORItem which
 * might be @ref QCBOR_TYPE_DECIMAL_FRACTION,
 * @ref QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM, ...  The sign of the
 * big number also comes from the context
 * (@ref QCBOR_TYPE_DECIMAL_FRACTION_POS_BIGNUM,
 * @ref QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM,...).
 *
 * @c bigNum is big endian or network byte order. The most significant
 * byte is first.
 *
 * When @c Mantissa is @c int64_t, it represents the true value of the
 * mantissa with the offset of 1 for CBOR negative values
 * applied. When it is a negative big number
 * (@ref QCBOR_TYPE_DECIMAL_FRACTION_NEG_BIGNUM or
 * @ref QCBOR_TYPE_BIGFLOAT_NEG_BIGNUM), the offset of 1 has NOT been
 * applied (doing so requires somewhat complex big number arithmetic
 * and may increase the length of the big number). To get the correct
 * value @c bigNum must be incremented by one before use.
 *
 * Also see QCBOREncode_AddTDecimalFraction(),
 * QCBOREncode_AddTBigFloat(), QCBOREncode_AddTDecimalFractionBigNum()
 * and QCBOREncode_AddTBigFloatBigNum().
 */
typedef struct  {
   int64_t nExponent;
   union {
      int64_t    nInt;
      uint64_t   uInt;
      UsefulBufC bigNum;
   } Mantissa;
} QCBORExpAndMantissa;


/**
 * This holds a decoded data item. It is returned by the
 * QCBORDecode_GetNext(), the principle decoding function.
 * It holds the type, value, label, tags and other details
 * of the decoded data item.
 *
 * This is typically 56 bytes on 64-bit CPUs and 52 bytes on 32-bit
 * CPUs (the CPU and the system's ABI determine this size).
 */
typedef struct _QCBORItem {
   /** Tells what element of the @c val union to use. One of @ref
    *  QCBOR_TYPE_INT64, @ref QCBOR_TYPE_ARRAY, ...*/
   uint8_t  uDataType;

   /** Tells what element of the @c label union to use. One of
    *  @ref QCBOR_TYPE_INT64, @ref QCBOR_TYPE_BYTE_STRING, ...*/
   uint8_t  uLabelType;

   /** Holds the nesting depth for arrays and map. 0 is the top level
    *  with no arrays or maps entered. */
   uint8_t  uNestingLevel;

   /** Holds the nesting level of the next item after this one.  If
    *  less than @c uNestingLevel, this item was the last one in an
    *  arry or map and it closed out at least one nesting level. */
   uint8_t  uNextNestLevel;

   /** 1 if a @c val that is a string is allocated with string
    * allocator, 0 if not. Always 0 unless an allocator has been set
    * up by calling QCBORDecode_SetMemPool() or
    * QCBORDecode_SetUpAllocator(). */
   uint8_t  uDataAlloc;

   /** 1 if a @c label that is a string is allocated with string
    * allocator, 0 if not. Always 0 unless an allocator has been set
    * up by calling QCBORDecode_SetMemPool() or
    * QCBORDecode_SetUpAllocator(). */
   uint8_t  uLabelAlloc;

   /** The union holding the item's value. Select union member based
    *  on @c uDataType. */
   union {
      /** The value for @c uDataType @ref QCBOR_TYPE_INT64. */
      int64_t     int64;
      /** The value for @c uDataType @ref QCBOR_TYPE_UINT64. */
      uint64_t    uint64;
      /** The value for @c uDataType @ref QCBOR_TYPE_BYTE_STRING and
       *  @ref QCBOR_TYPE_TEXT_STRING. Also
       *  for many tags whose content is a string such @ref QCBOR_TYPE_DAYS_STRING
       *  and @ref QCBOR_TYPE_URI. */
      UsefulBufC  string;
      /** The "value" for @c uDataType @ref QCBOR_TYPE_ARRAY or @ref
       *  QCBOR_TYPE_MAP, the number of items in the array or map.  It
       *  is @c UINT16_MAX when decoding indefinite-lengths maps and
       *  arrays. Detection of the end of a map or array is best done
       *  with @c uNestLevel and @c uNextNestLevel so as to work for
       *  both definite and indefinite length maps and arrays. */
      uint16_t    uCount;
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
      /** The value for @c uDataType @ref QCBOR_TYPE_DOUBLE. */
      double      dfnum;
      /** The value for @c uDataType @ref QCBOR_TYPE_FLOAT. */
      float       fnum;
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
      /** The value for @c uDataType @ref QCBOR_TYPE_DATE_EPOCH, the
       *  number of seconds after or before Jan 1, 1970. This has a
       *  range of 500 billion years. Floating-point dates are
       *  converted to this integer + fractional value. If the input
       *  value is beyond the 500 billion-year range (e.g., +/i
       *  infinity, large floating point values, NaN)
       *  @ref QCBOR_ERR_DATE_OVERFLOW will be returned. If the input
       *  is floating-point and QCBOR has been compiled with
       *  floating-point disabled, one of the various floating-point
       *  disabled errors will be returned. */
      struct {
         int64_t  nSeconds;
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
         double   fSecondsFraction;
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */
      } epochDate;

      /** The value for @c uDataType @ref QCBOR_TYPE_DAYS_EPOCH -- the
       *  number of days before or after Jan 1, 1970. */
      int64_t     epochDays;

      /** The value for @c uDataType @ref QCBOR_TYPE_POSBIGNUM and
       * @ref QCBOR_TYPE_NEGBIGNUM.  */
      UsefulBufC  bigNum;

      /** See @ref QCBOR_TYPE_UKNOWN_SIMPLE */
      uint8_t     uSimple;
#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
      QCBORExpAndMantissa expAndMantissa;
#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */
      uint64_t    uTagNumber; /* Used internally during decoding */

      /* For use by user-defined tag content handlers */
      uint8_t     userDefined[24];
   } val;

   /** Union holding the different label types selected based on @c uLabelType */
   union {
      /** The label for @c uLabelType for @ref QCBOR_TYPE_INT64 */
      int64_t     int64;
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
      /** The label for @c uLabelType for @ref QCBOR_TYPE_UINT64 */
      uint64_t    uint64;
      /** The label for @c uLabelType @ref QCBOR_TYPE_BYTE_STRING and
       *  @ref QCBOR_TYPE_TEXT_STRING */
      UsefulBufC  string;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
   } label;

#ifndef QCBOR_DISABLE_TAGS
   /**
    * PRIVATE MEMBER
    * Use  QCBORDecode_GetNthTagNumber() to retrieve tag numbers on an item.
    * Also see @ref Tags-Overview.
    *
    * In QCBOR v1 this was named uTags and was in the reverse order.
    * It wasn't explicitly described as private, but was implicitly private.
    */
   QCBORMappedTagNumbers auTagNumbers;
#endif
} QCBORItem;

/**
 * An array or map's length is indefinite when it has this value.
 */
#define QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH UINT16_MAX




/**
 * @brief Prototype for the implementation of a string allocator.
 *
 * @param[in] pAllocateCxt Pointer to context for the particular
 *                         allocator implementation. Its contents
 *                         depend on how a particular string allocator
 *                         works. Typically, it will contain a pointer
 *                         to the memory pool and some booking keeping
 *                         data.
 *
 * @param[in] pOldMem      Points to some memory previously allocated
 *                         that is either to be freed or to be
 *                         reallocated to be larger. It is @c NULL for
 *                         new allocations and when called as the
 *                         destructor.
 *
 * @param[in] uNewSize     Size of memory to be allocated or new size
 *                         for a chunk being reallocated. Zero when
 *                         called to free memory or when called as the
 *                         destructor.
 *
 * @return Either the allocated buffer is returned, or
 *         @ref NULLUsefulBufC. @ref NULLUsefulBufC is returned on a
 *         failed allocation and in the two cases where there is
 *         nothing to return.
 *
 * This function must be implemented for a custom string
 * allocator. See QCBORDecode_SetUpAllocator().
 *
 * This is not needed if the built-in string allocator available
 * through QCBORDecode_SetMemPool() is used.
 *
 * After being set up by a call to QCBORDecode_SetUpAllocator(),
 * this is called back in four modes:
 *
 * - allocate: @c uNewSize is the amount to allocate. @c pOldMem is
 *  @c NULL.
 *
 * - free: @c uNewSize is 0. @c pOldMem points to the memory to be
 * freed.  When the decoder calls this, it will always be for the most
 * recent block that was either allocated or reallocated.
 *
 * - reallocate: @c pOldMem is the block to reallocate. @c uNewSize is
 * its new size.  When the decoder calls this, it will always be for the
 * most recent block that was either allocated or reallocated.
 *
 * - destruct: @c pOldMem is @c NULL and @c uNewSize is 0. This is
 * called when the decoding is complete by
 * QCBORDecode_Finish(). Usually, the strings allocated by a string
 * allocator are in use after the decoding is completed so this
 * usually will not free those strings. Many string allocators will
 * not need to do anything in this mode.
 *
 * The strings allocated by this will have @c uDataAlloc set to true
 * in the @ref QCBORItem when they are returned. The user of the
 * strings will have to free them. How they free them, depends on the
 * design of the string allocator.
 */
typedef UsefulBuf (* QCBORStringAllocate)(void   *pAllocateCxt,
                                          void   *pOldMem,
                                          size_t  uNewSize);


/**
 * For the built-in string allocator available via
 * QCBORDecode_SetMemPool(), this is the size overhead needed
 * internally.  The amount of memory available for decoded strings is
 * the size of the buffer given to QCBORDecode_SetMemPool() less this
 * amount.
 *
 * This doesn't apply to custom string allocators, only to the one
 * available via QCBORDecode_SetMemPool().
 */
#define QCBOR_DECODE_MIN_MEM_POOL_SIZE 8




/**
 * QCBORDecodeContext holds the context for decoding CBOR.  It is
 * about 300 bytes, so it can go on the stack.  The contents are
 * opaque, and the caller should not access any internal items.  A
 * context may be re-used serially as long as it is re initialized.
 */
typedef struct _QCBORDecodeContext QCBORDecodeContext;


/**
 * Initialize the CBOR decoder context.
 *
 * @param[in] pCtx         The context to initialize.
 * @param[in] EncodedCBOR  The buffer with CBOR encoded bytes to be decoded.
 * @param[in] nMode        See below and @ref QCBORDecodeMode.
 *
 * Initialize context for a pre-order traversal of the encoded CBOR
 * tree.
 *
 * Most CBOR decoding can be completed by calling this function to
 * start and QCBORDecode_GetNext() in a loop.
 *
 * If indefinite-length strings are to be decoded, then
 * QCBORDecode_SetMemPool() or QCBORDecode_SetUpAllocator() must be
 * called to set up a string allocator.
 *
 * Three decoding modes are supported.  In normal mode, @ref
 * QCBOR_DECODE_MODE_NORMAL, maps are decoded and strings and integers
 * are accepted as map labels. If a label is other than these, the
 * error @ref QCBOR_ERR_MAP_LABEL_TYPE is returned by
 * QCBORDecode_GetNext().
 *
 * TODO: get rid of QCBOR_DECODE_MODE_MAP_STRINGS_ONLY in v2?
 * In strings-only mode, @ref QCBOR_DECODE_MODE_MAP_STRINGS_ONLY, only
 * text strings are accepted for map labels.  This lines up with CBOR
 * that converts to JSON. The error @ref QCBOR_ERR_MAP_LABEL_TYPE is
 * returned by QCBORDecode_GetNext() if anything but a text string
 * label is encountered.
 *
 * In @ref QCBOR_DECODE_MODE_MAP_AS_ARRAY maps are treated as special
 * arrays.  They will be returned with special @c uDataType @ref
 * QCBOR_TYPE_MAP_AS_ARRAY and @c uCount, the number of items, will be
 * double what it would be for a normal map because the labels are
 * also counted. This mode is useful for decoding CBOR that has labels
 * that are not integers or text strings, but the caller must manage
 * much of the map decoding.
 */
void
QCBORDecode_Init(QCBORDecodeContext *pCtx, UsefulBufC EncodedCBOR, QCBORDecodeMode nMode);


/**
 * @brief Set up the MemPool string allocator for indefinite-length strings.
 *
 * @param[in] pCtx         The decode context.
 * @param[in] MemPool      The pointer and length of the memory pool.
 * @param[in] bAllStrings  If true, all strings, even of definite
 *                         length, will be allocated with the string
 *                         allocator.
 *
 * @return Error if the MemPool was greater than @c UINT32_MAX
 *         or less than @ref QCBOR_DECODE_MIN_MEM_POOL_SIZE.
 *
 * Indefinite-length strings (text and byte) cannot be decoded unless
 * there is a string allocator configured. MemPool is a simple
 * built-in string allocator that allocates bytes from a memory pool
 * handed to it by calling this function.  The memory pool is just a
 * pointer and length for some block of memory that is to be used for
 * string allocation. It can come from the stack, heap or other.
 *
 * The memory pool must be @ref QCBOR_DECODE_MIN_MEM_POOL_SIZE plus
 * space for all the strings allocated.  There is no overhead per
 * string allocated. A conservative way to size this buffer is to make
 * it the same size as the CBOR being decoded plus @ref
 * QCBOR_DECODE_MIN_MEM_POOL_SIZE.
 *
 * This memory pool is used for all indefinite-length strings that are
 * text strings or byte strings, including strings used as labels.
 *
 * The pointers to strings in @ref QCBORItem will point into the
 * memory pool set here. They do not need to be individually
 * freed. Just discard the buffer when they are no longer needed.
 *
 * If @c bAllStrings is set, then the size will be the overhead plus
 * the space to hold **all** strings, definite and indefinite-length,
 * value or label. The advantage of this is that after the decode is
 * complete, the original memory holding the encoded CBOR does not
 * need to remain valid.
 *
 * This simple allocator is not hard linked to the QCBOR decoder.
 * Assuming dead-stripping of unused symbols is being performed, this
 * simple allocator will not be linked in unless
 * QCBORDecode_SetMemPool() is called.
 *
 * See also QCBORDecode_SetUpAllocator() to set up a custom allocator
 * if this one isn't sufficient.
 */
QCBORError
QCBORDecode_SetMemPool(QCBORDecodeContext *pCtx,
                       UsefulBuf           MemPool,
                       bool                bAllStrings);


/**
 * @brief Sets up a custom string allocator for indefinite-length strings
 *
 * @param[in] pCtx                 The decoder context to set up an
 *                                 allocator for.
 * @param[in] pfAllocateFunction   Pointer to function that will be
 *                                 called by QCBOR for allocations and
 *                                 frees.
 * @param[in] pAllocateContext     Context passed to @c
 *                                 pfAllocateFunction.
 * @param[in] bAllStrings          If true, all strings, even of definite
 *                                 length, will be allocated with the
 *                                 string allocator.
 *
 * Indefinite-length strings (text and byte) cannot be decoded unless
 * a string allocator is configured. QCBORDecode_SetUpAllocator()
 * allows the caller to configure an external string allocator
 * implementation if the internal string allocator is
 * unsuitable. See QCBORDecode_SetMemPool() to configure the internal
 * allocator.
 *
 * The string allocator configured here is a custom one designed
 * and implemented by the caller.  See @ref QCBORStringAllocate for
 * the requirements for a string allocator implementation.
 *
 * A malloc-based string external allocator can be obtained by calling
 * @c QCBORDecode_MakeMallocStringAllocator(). It will return a
 * function and pointer that can be given here as @c pAllocatorFunction
 * and @c pAllocatorContext. It uses standard @c malloc() so @c free()
 * must be called on all strings marked by @c uDataAlloc @c == @c 1 or
 * @c uLabelAlloc @c == @c 1 in @ref QCBORItem. Note this is in a
 * separate GitHub repository.
 */
void
QCBORDecode_SetUpAllocator(QCBORDecodeContext *pCtx,
                           QCBORStringAllocate pfAllocateFunction,
                           void               *pAllocateContext,
                           bool                bAllStrings);


/**
 * @brief Get the next item (integer, byte string, array...) in the
 * preorder traversal of the CBOR tree.
 *
 * @param[in]  pCtx          The decoder context.
 * @param[out] pDecodedItem  The decoded CBOR item.
 *
 * @c pDecodedItem is filled from the decoded item. Generally, the
 * following data is returned in the structure:
 *
 * - @c uDataType which indicates which member of the @c val union the
 *   data is in. This decoder figures out the type based on the CBOR
 *   major type, the CBOR "additionalInfo", the CBOR optional tags and
 *   the value of the integer.
 *
 * - The value of the item, which might be an integer, a pointer and a
 *   length, the count of items in an array, a floating-point number or
 *   other.
 *
 * - The nesting level for maps and arrays.
 *
 * - The label for an item in a map, which may be a text or byte string
 *   or an integer.
 *
 * - The unprocessed tag numbers for which the item is the tag content.
 *
 * See @ref QCBORItem for all the details about what is returned.
 *
 * This function handles arrays and maps. When an array or map is
 * first encountered a @ref QCBORItem will be returned with major type
 * @ref QCBOR_TYPE_ARRAY or @ref QCBOR_TYPE_MAP.  @c
 * QCBORItem.val.uNestLevel gives the nesting level of the opening of
 * the array or map. When the next item is fetched, it will be the
 * first one in the array or map and its @c QCBORItem.val.uNestLevel
 * will be one more than that of the opening of the array or map.
 *
 * Nesting level 0 is the top-most nesting level. The first item
 * decoded always has nesting level 0. A map or array at the top level
 * has nesting level 0 and the members of the array or map have
 * nesting level 1.
 *
 * Here is an example of how the nesting level is reported for a CBOR
 * sequence with no arrays or maps at all.
 *
 * @code
 * Data Item           Nesting Level
 * integer                     0
 * byte string                 0
 * @endcode
 *
 * Here is an example of how the nesting level is reported for a CBOR
 * sequence with a simple array and some top-level items.
 *
 * @code
 * Data Item           Nesting Level
 * integer                     0
 * array with 2 items          0
 *    byte string              1
 *    byte string              1
 * integer                     0
 * @endcode
 *
 * Here's a more complex example that is not a CBOR sequence
 *
 * @code
 * Data Item           Nesting Level
 * map with 4 items            0
 *    text string              1
 *    array with 3 integers    1
 *       integer               2
 *       integer               2
 *       integer               2
 *    text string              1
 *    byte string              1
 * @endcode
 *
 * In @ref QCBORItem, @c uNextNestLevel is the nesting level for the
 * next call to QCBORDecode_VGetNext(). It indicates if any maps or
 * arrays were closed out during the processing of the just-fetched
 * @ref QCBORItem. This processing includes a look-ahead for any
 * breaks that close out indefinite-length arrays or maps. This value
 * is needed to be able to understand the hierarchical structure. If
 * @c uNextNestLevel is not equal to @c uNestLevel the end of the
 * current map or array has been encountered. This works for both
 * definite and indefinite-length arrays so it is the best way to find the
 * end of a map or array. Alternatively, for definite-length arrays,
 * @c QCBORItem.val.uCount contains the number of items in the
 * array. For indefinite-length arrays, @c QCBORItem.val.uCount
 * is @c UINT16_MAX.
 *
 * See extensive discussion in @ref Tag-Decoding.
 *
 * See [Decode Error Overview](#Decode-Errors-Overview).
 *
 * If a decoding error occurs or previously occured, @c uDataType and
 * @c uLabelType will be set to @ref QCBOR_TYPE_NONE. If there is no
 * need to know the specific error, it is sufficient to check for @ref
 * QCBOR_TYPE_NONE.
 *
 * Errors fall in several categories:
 *
 * - Not well-formed errors are those where there is something
 *   syntactically and fundamentally wrong with the CBOR being
 *   decoded. Decoding should stop completely.
 *
 * - Invalid CBOR is well-formed, but still not correct. It is
 *   probably best to stop decoding, but not necessary.
 *
 * - This implementation has some size limits. They should rarely be
 *   encountered. If they are it may because something is wrong with
 *   the CBOR, for example an array size is incorrect.
 *
 * - There are a few CBOR constructs that are not handled without some
 *   extra configuration. These are indefinite length strings and maps
 *   with labels that are not strings or integers. See
 *   QCBORDecode_Init().  Also, the QCBOR library may have been
 *   compiled with some features disabled to reduce code size and this
 *   can result in some errors.
 *
 * - Resource exhaustion. This only occurs when a string allocator is
 *   configured to handle indefinite-length strings as other than
 *   that, this implementation does no dynamic memory allocation.
 *
 * x
 * | __Not well-formed errors__  ||
 * | @ref QCBOR_ERR_HIT_END                 | Partial data item; need more input bytes to complete decoding |
 * | @ref QCBOR_ERR_UNSUPPORTED             | Input contains CBOR with reserved additional info values |
 * | @ref QCBOR_ERR_BAD_TYPE_7              | Simple value encoded as two-byte integer rather than one |
 * | @ref QCBOR_ERR_BAD_BREAK               | Break occured outside an indefinite-length map or such |
 * | @ref QCBOR_ERR_BAD_INT                 | Length of integer is bad |
 * | @ref QCBOR_ERR_INDEFINITE_STRING_CHUNK | One of the chunks in indefinite-length string is the wrong type |
 * | __Invalid CBOR__  ||
 * | @ref QCBOR_ERR_NO_MORE_ITEMS        | Need more input data items to decode |
 * | @ref QCBOR_ERR_BAD_EXP_AND_MANTISSA | The structure of a big float or big number is invalid |
 * | @ref QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT | The content of a tag is of the wrong type |
 * | __Implementation Limits__  ||
 * | @ref QCBOR_ERR_INT_OVERFLOW                  | Input integer smaller than INT64_MIN |
 * | @ref QCBOR_ERR_ARRAY_DECODE_TOO_LONG         | Array or map has more elements than can be handled |
 * | @ref QCBOR_ERR_DATE_OVERFLOW                 | Date larger than can be handled |
 * | @ref QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP | Nesting deeper than can be handled |
 * | @ref QCBOR_ERR_STRING_TOO_LONG               | Encountered a string longer than size_t can hold less 4 bytes |
 * | @ref QCBOR_ERR_TOO_MANY_TAGS                 | Tag nesting deeper than limit, typically 4 |
 * | __Configuration errors__  ||
 * | @ref QCBOR_ERR_NO_STRING_ALLOCATOR        | Encountered indefinite-length string with no allocator configured |
 * | @ref QCBOR_ERR_MAP_LABEL_TYPE             | A map label that is not a string on an integer |
 * | @ref QCBOR_ERR_HALF_PRECISION_DISABLED    | Half-precision input, but disabled in QCBOR library |
 * | @ref QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED  | Indefinite-length input, but disabled in QCBOR library |
 * | @ref QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED | Indefinite-length input, but disabled in QCBOR library |
 * | @ref QCBOR_ERR_ALL_FLOAT_DISABLED             | Library compiled with floating-point support turned off. |
 * | __Resource exhaustion errors__  ||
 * | @ref QCBOR_ERR_STRING_ALLOCATE | The string allocator is unable to allocate more memory |
 */
void
QCBORDecode_VGetNext(QCBORDecodeContext *pCtx, QCBORItem *pDecodedItem);


/**
 * @brief Preorder traversal like QCBORDecode_VGetNext() without use
 * of internal error state.
 *
 * @param[in]  pCtx          The decoder context.
 * @param[out] pDecodedItem  The decoded CBOR item.
 *
 * @return See error table of decoding errors set by QCBORDecode_VGetNext().
 *
 * This is the same as QCBORDecode_VGetNext() except it
 * doesn't set the internal decoding error and will attempt to decode
 * even if the decoder is in the error state.
 */
QCBORError
QCBORDecode_GetNext(QCBORDecodeContext *pCtx, QCBORItem *pDecodedItem);


/**
 * @brief Get the next item, fully consuming it if it is a map or array.
 *
 * @param[in]  pCtx          The decoder context.
 * @param[out] pDecodedItem  The decoded CBOR item.
 *
 * @c pItem returned is the same as QCBORDecode_VGetNext(). If the
 * item is an array or map, the entire contents of the array or map
 * will be consumed leaving the cursor after the array or map.
 *
 * If an array or map is being consumed by this, an error will occur
 * if any of the items in the array or map are in error.
 *
 * If the item is a tag the contents of which is an array or map, like
 * a big float, @c pItem will identify it as such and the contents
 * will be consumed, but the validity of the tag won't be checked
 * other than for being well-formed.
 *
 * In order to go back to decode the contents of an array or map
 * consumed by this, the decoder must be rewound using
 * QCBORDecode_Rewind().
 */
void
QCBORDecode_VGetNextConsume(QCBORDecodeContext *pCtx, QCBORItem *pDecodedItem);


/**
 * @brief Get the next data item without consuming it.
 *
 * @param[in]  pCtx          The decoder context.
 * @param[out] pDecodedItem  The decoded CBOR item.
 *
 * This is the same as QCBORDecode_VGetNext() but does not consume the
 * data item. This only looks ahead one item. Calling it repeatedly
 * will just return the same item over and over.
 *
 * This uses about 200 bytes of stack, far more than anything else
 * here in qcbor_decode.h because it saves a copy of most of the
 * decode context temporarily.
 *
 * This is useful for looking ahead to determine the type of a data
 * item to know which type-specific spiffy decode function to call or
 * decoding protocols where the types of later data items
 * depending on type of earlier ones.
 *
 * The error must be retrieved with QCBORDecode_GetError() and checked
 * to know the peek was successful before referencing the contents of
 * @c pDecodedItem.
 */
void
QCBORDecode_VPeekNext(QCBORDecodeContext *pCtx, QCBORItem *pDecodedItem);


/**
 * @brief Get the next data item without consuming it without use
 * of internal error state.
 *
 * @param[in]  pCtx          The decoder context.
 * @param[out] pDecodedItem  The decoded CBOR item.
 *
 * This is the same as QCBORDecode_VPeekNext() except it doesn't set
 * the internal decoding error and will attempt to decode even if the
 * decoder is in the error state.
 */
QCBORError
QCBORDecode_PeekNext(QCBORDecodeContext *pCtx, QCBORItem *pDecodedItem);


/**
 * @brief Get the current traversal cursort offset in the input CBOR.
 *
 * @param[in]  pCtx   The decoder context.
 *
 * @returns The traversal cursor offset or @c UINT32_MAX.

 * The position returned is always the start of the next item that
 * would be next decoded with QCBORDecode_VGetNext(). The cursor
 * returned may be at the end of the input in which case the next call
 * to QCBORDecode_VGetNext() will result in the @ref
 * QCBOR_ERR_NO_MORE_ITEMS. See also QCBORDecode_AtEnd().
 *
 * If the decoder is in error state from previous decoding,
 * @c UINT32_MAX is returned.
 *
 * When decoding map items, the position returned is always of the
 * label, never the value.
 *
 * For indefinite-length arrays and maps, the break byte is consumed
 * when the last item in the array or map is consumed so the cursor is
 * at the next item to be decoded as expected.
 *
 * There are some special rules for the traversal cursor when fetching
 * map items by label. See the description of @SpiffyDecode.
 *
 * When traversal is bounded because an array or map has been entered
 * (e.g., QCBORDecode_EnterMap()) and all items in the array or map
 * have been consumed, the position returned will be of the item
 * outside of the array or map. The array or map must be exited before
 * QCBORDecode_VGetNext() will decode it.
 *
 * In many cases the position returned will be in the middle of
 * an array or map. It will not be possible to start decoding at
 * that location with another instance of the decoder and go to
 * the end. It is not valid CBOR. If the input is a CBOR sequence
 * and the position is not in the moddle of an array or map
 * then it is possible to decode to the end.
 *
 * There is no corresponding seek method because it is too complicated
 * to restore the internal decoder state that tracks nesting.
 */
static uint32_t
QCBORDecode_Tell(QCBORDecodeContext *pCtx);


/**
 * @brief Tell whether cursor is at end of the input.
 *
 * @param[in] pCtx   The decoder context.
 *
 * @returns Error code possibly indicating end of input.
 *
 * This returns the same as QCBORDecode_GetError() except that @ref
 * QCBOR_ERR_NO_MORE_ITEMS is returned if the travseral cursor is at
 * the end of the CBOR input bytes (not the end of an entered array or
 * map).
 */
QCBORError
QCBORDecode_EndCheck(QCBORDecodeContext *pCtx);


#ifndef QCBOR_DISABLE_TAGS
/**
 * @brief Returns the tag numbers for an item.
 *
 * @param[in] pCtx    The decoder context.
 * @param[out] puTagNumber  The returned tag number.
 *
 * In QCBOR v2, all tag numbers on an item MUST be fetched with this
 * method. If not, @ref QCBOR_ERR_UNPROCESSED_TAG_NUMBER will
 * occur. This is a major change from QCBORv1. The QCBOR v1 behavior
 * is too lax for proper CBOR decoding. When a tag number occurs it
 * indicates the item is a new data type (except for a few tag numbers
 * that are hints).  Note also that in RFC 7049, tag numbers were
 * incorrectly characterized as optional implying they could be
 * ignored.
 *
 * In typical item decoding, tag numbers are not used, not present and
 * not expected. There's no need to call this.
 *
 * When the protocol being decoded does use a tag number then this
 * must be called for the items were the tag numbers occur before the
 * items themselves are decoded. Making this call prevents the
 * @ref QCBOR_ERR_UNPROCESSED_TAG_NUMBER error, but the caller still has to
 * check that the tag number is the right one. Probably the tag number
 * will be used to switch the flow of the decoder.
 *
 * It's possible that an item might use the presence/absence of a tag
 * number to switch the flow of decoding. If there's a possibility of
 * a tag number then this must be called.
 *
 * If this is called and there is no tag number, then this will return
 * @ref QCBOR_SUCCESS and the tag number returned will be
 * @ref CBOR_TAG_INVALID64.
 *
 * Usually there is only one tag number per item, but CBOR allows
 * more. That it allows nesting of tags where the content of one tag
 * is another tag. If there are multiple tag numbers, this must be
 * called multiple times. This only returns one tag number at a time,
 * because tag numbers are typically processed one at a time.
 *
 * If there is an error decoding the tag or the item it is on, the
 * error code will be set and the tag number @ref CBOR_TAG_INVALID64
 * will be returned. That is, @ref CBOR_TAG_INVALID64 will be returned if
 * there is a decode error or there is no tag number.
 */
void
QCBORDecode_VGetNextTagNumber(QCBORDecodeContext *pCtx, uint64_t *puTagNumber);


/**
 * @brief Returns the tag numbers for an item.
 *
 * @param[in] pCtx    The decoder context.
 * @param[out] puTagNumber  The returned tag number.
 *
 * @return See error table of decoding errors set by QCBORDecode_VGetNext().
 *
 * Like QCBORDecode_VGetNextTagNumber(), but returns the
 * error rather than set last error.
 */
QCBORError
QCBORDecode_GetNextTagNumber(QCBORDecodeContext *pCtx, uint64_t *puTagNumber);



/**
 * @brief Returns the tag numbers for a decoded item.
 *
 * @param[in] pCtx    The decoder context.
 * @param[in] pItem The CBOR item to get the tag for.
 * @param[in] uIndex The index of the tag to get.
 *
 * @returns The nth tag number or @ref CBOR_TAG_INVALID64.
 *
 * Typically, this is only used with @ref QCBOR_DECODE_CONFIG_UNPROCESSED_TAG_NUMBERS.
 * Normally, tag numbers are processed QCBORDecode_VGetNextTagNumber() or
 * QCBORTagContentCallBack.
 *
 * When QCBOR decodes an item that is a tag, it will fully decode tags
 * it is able to. Tags that it is unable to process are put in a list
 * in the QCBORItem.
 *
 * Tags nest. Here the tag with index 0 is the outermost, the one
 * furthest form the data item that is the tag content. This is
 * the opposite order of QCBORDecode_GetNthTag(), but more
 * useful.
 *
 * Deep tag nesting is rare so this implementation imposes a limit of
 * @ref QCBOR_MAX_TAGS_PER_ITEM on nesting and returns @ref
 * QCBOR_ERR_TOO_MANY_TAGS if there are more. This is a limit of this
 * implementation, not of CBOR. (To be able to handle deeper nesting,
 * the constant can be increased and the library recompiled. It will
 * use more memory).
 *
 * See also @ref Tag-Decoding @ref CBORTags, @ref Tag-Usage and @ref Tags-Overview.
 *
 * To reduce memory used by a @ref QCBORItem, tag numbers larger than
 * @c UINT16_MAX are mapped so the tag numbers in @c uTags should be
 * accessed with this function rather than directly.
 *
 * This returns @ref CBOR_TAG_INVALID64 if any error occurred when
 * getting the item. This is also returned if there are no tags on the
 * item or no tag at @c uIndex.
 */
uint64_t
QCBORDecode_GetNthTagNumber(const QCBORDecodeContext *pCtx, const QCBORItem *pItem, uint8_t uIndex);


/**
 * @brief Returns the tag numbers for last-decoded item.
 *
 * @param[in] pCtx    The decoder context.
 * @param[in] uIndex The index of the tag to get.
 *
 * @returns The nth tag number or @ref CBOR_TAG_INVALID64.
 *
 * This returns tags of the most recently decoded item. See
 * QCBORDecode_GetNthTagNumber(). This is particularly of use for spiffy
 * decode functions that don't return a @ref QCBORItem.
 *
 * This does not work for QCBORDecode_GetNext(),
 * QCBORDecode_PeekNext(), QCBORDecode_VPeekNext() or
 * QCBORDecode_VGetNextConsume() but these all return a
 * @ref QCBORItem, so it is not necessary.
 *
 * If a decoding error is set, then this returns @ref CBOR_TAG_INVALID64.
 */
uint64_t
QCBORDecode_GetNthTagNumberOfLast(QCBORDecodeContext *pCtx, uint8_t uIndex);


#endif /* ! QCBOR_DISABLE_TAGS */

/**
 * @brief Check that a decode completed successfully.
 *
 * @param[in]  pCtx  The context to check.
 *
 * @returns The internal tracked decode error or @ref QCBOR_SUCCESS.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * This should always be called at the end of a decode to determine if
 * it completed successfully.  For some protocols, checking the return
 * value here may be the only error check necessary.
 *
 * This returns the internal tracked error if the decoder is in the
 * error state, the same one returned by QCBORDecode_GetError().  This
 * performs final checks at the end of the decode, and may also return
 * @ref QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN
 * or @ref QCBOR_ERR_EXTRA_BYTES.
 *
 * This calls the destructor for the string allocator, if one is in
 * use. Because of this, It can't be called multiple times like
 * QCBORDecode_PartialFinish().
 *
 * Some CBOR protocols use a CBOR sequence defined in [RFC 8742]
 * (https://tools.ietf.org/html/rfc8742). A CBOR sequence typically
 * doesn't start out with a map or an array. The end of the CBOR is
 * determined in some other way, perhaps by external framing, or by
 * the occurrence of some particular CBOR data item or such. The
 * buffer given to decode must start out with valid CBOR, but it can
 * have extra bytes at the end that are not CBOR or CBOR that is to be
 * ignored.
 *
 * QCBORDecode_Finish() should still be called when decoding CBOR
 * sequences to check that the input decoded was well-formed. If the
 * input was well-formed and there are extra bytes at the end @ref
 * QCBOR_ERR_EXTRA_BYTES will be returned.  This can be considered a
 * successful decode.  See also QCBORDecode_PartialFinish().
 */
QCBORError
QCBORDecode_Finish(QCBORDecodeContext *pCtx);


/**
 * @brief Return number of bytes consumed so far.
 *
 * @param[in]  pCtx        The context to check.
 * @param[out] puConsumed  The number of bytes consumed so far.
 *                          May be @c NULL.
 *
 * @returns The same as QCBORDecode_Finish();
 *
 * This is primarily for partially decoding CBOR sequences. It is the
 * same as QCBORDecode_Finish() except it returns the number of bytes
 * consumed and doesn't call the destructor for the string allocator
 * (See @ref QCBORDecode_SetMemPool()).
 *
 * When this is called before all input bytes are consumed, @ref
 * QCBOR_ERR_EXTRA_BYTES will be returned as QCBORDecode_Finish()
 * does. For typical use of this, that particular error is disregarded.
 *
 * Decoding with the same @ref QCBORDecodeContext can continue after
 * calling this and this may be called many times.
 *
 * Another way to resume decoding is to call QCBORDecode_Init() with the
 * bytes not decoded, but this only works on CBOR sequences when the
 * decoding stopped with no open arrays, maps or byte strings.
 */
QCBORError
QCBORDecode_PartialFinish(QCBORDecodeContext *pCtx, size_t *puConsumed);


/**
 * @brief  Retrieve the undecoded input buffer.
 *
 * @param[in]  pCtx  The decode context.
 *
 * @return The input that was given to QCBORDecode_Init().
 *
 * A simple convenience method, should it be useful to get the original input back.
 */
static UsefulBufC
QCBORDecode_RetrieveUndecodedInput(QCBORDecodeContext *pCtx);


/**
 * @brief Get the decoding error.
 *
 * @param[in] pCtx    The decoder context.
 * @return            The decoding error.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * The returns the tracked internal error code. All decoding functions
 * set the internal error except QCBORDecode_GetNext() and
 * QCBORDecode_PeekNext().
 *
 * For many protocols it is only necessary to check the return code
 * from QCBORDecode_Finish() at the end of all the decoding.  It is
 * unnecessary to call this.
 *
 * For some protocols, the decoding sequence depends on the types,
 * values or labels of data items. If so, this must be called before
 * using decoded values to know the decode was a success and the
 * type, value and label is valid.
 *
 * Some errors, like integer conversion overflow, date string format
 * may not affect the flow of a protocol. The protocol decoder may
 * wish to proceed even if they occur. In that case
 * QCBORDecode_GetAndResetError() may be called after these data items
 * are fetched.
 */
static QCBORError
QCBORDecode_GetError(QCBORDecodeContext *pCtx);


/**
 * @brief Get and reset the decoding error.
 *
 * @param[in] pCtx    The decoder context.
 * @returns The decoding error.
 *
 * This returns the same as QCBORDecode_GetError() and also resets the
 * error state to @ref QCBOR_SUCCESS.
 */
static QCBORError
QCBORDecode_GetAndResetError(QCBORDecodeContext *pCtx);


/**
 * @brief Whether an error indicates non-well-formed CBOR.
 *
 * @param[in] uErr    The QCBOR error code.
 * @return @c true if the error code indicates non-well-formed CBOR.
 */
static bool
QCBORDecode_IsNotWellFormedError(QCBORError uErr);


/**
 * @brief Whether a decoding error is recoverable.
 *
 * @param[in] uErr    The QCBOR error code.
 * @return @c true if the error code indicates and uncrecoverable error.
 *
 * When an error is unrecoverable, no further decoding of the input is
 * possible.  CBOR is a compact format with almost no redundancy so
 * errors like incorrect lengths or array counts are
 * unrecoverable. Unrecoverable errors also occur when implementation
 * limits such as the limit on array and map nesting are encountered.
 * When the built-in decoding of a tag like an epoch date encounters
 * an error such as a data item of an unexpected type, this is also an
 * unrecoverable error because the internal decoding doesn't try to
 * decode everything in the tag.
 *
 * The unrecoverable errors are a range of the errors in
 * @ref QCBORError.
 */
static bool
QCBORDecode_IsUnrecoverableError(QCBORError uErr);


/**
 * @brief Manually set error condition, or set user-defined error.
 *
 * @param[in] pCtx    The decoder context.
 * @param[in] uError  The error code to set.
 *
 * Once set, none of the QCBORDecode methods will do anything and the
 * error code set will stay until cleared with
 * QCBORDecode_GetAndResetError().  A user-defined error can be set
 * deep in some decoding layers to short-circuit further decoding
 * and propagate up.
 *
 * When the error condition is set, QCBORDecode_VGetNext() will always
 * return an item with data and label type as @ref QCBOR_TYPE_NONE.
 *
 * The main intent of this is to set a user-defined error code in the
 * range of @ref QCBOR_ERR_FIRST_USER_DEFINED to
 * @ref QCBOR_ERR_LAST_USER_DEFINED, but it is OK to set QCBOR-defined
 * error codes too.
 */
static void
QCBORDecode_SetError(QCBORDecodeContext *pCtx, QCBORError uError);


/**
 * @brief Decode a preferred serialization big number.
 *
 * @param[in] Item    The number to process.
 * @param[in] BigNumberBuf  The buffer to output to.
 * @param[out] pBigNumber   The resulting big number.
 * @param[in,out] pbIsNegative  The sign of the resulting big number.
 *
 * This exists to process an item that is expected to be a big number
 * encoded with preferred serialization.  This processing is not part
 * of the main decoding because of the number of CBOR types it
 * involves, because it needs a buffer to output to, and to keep code
 * size of the core decoding small.
 *
 * This can also be used to do the subtraction of 1 for negative big
 * numbers even if preferred serialization of big numbers is not in
 * use.
 *
 * This works on all CBOR type 0 and 1 integers and all tag 2 and 3
 * big numbers.  In terms of QCBOR types, this works on
 * \ref QCBOR_TYPE_INT64, \ref QCBOR_TYPE_UINT64,
 * \ref QCBOR_TYPE_65BIT_NEG, \ref QCBOR_TYPE_POSBIGNUM and
 * \ref QCBOR_TYPE_NEGBIGNUM. This also works on
 * \ref QCBOR_TYPE_BYTES in which case pIsNegative
 * becomes an in parameter indicating the sign.
 *
 * This always returns the result as a big number. The integer types 0
 * and 1 are converted. Leading zeros are removed. The value 0 is
 * always returned as a one-byte big number with the value 0x00.
 *
 * If \c BigNumberBuf is too small, \c pBigNum.ptr will be \c NULL and \c
 * pBigNum.len reports the required length. The size of \c BigNumberBuf
 * might have to be one larger than the size of the tag 2 or 3 being
 * decode because of two cases. In CBOR the value of a tag 3 big
 * number is -n - 1. The subtraction of one might have a carry.  For
 * example, an encoded tag 3 that is 0xff, is returned here as 0x01
 * 0x00.  The other case is a empty tag 2 which is returned as a
 * one-byte big number with the value 0x00.  (This is the only place
 * in all of RFC 8949 except for indefinite length strings where the
 * encoded buffer off the wire can't be returned directly, the only
 * place some storage allocation is required.)
 *
 * This is the decode-side implementation of preferred serialization
 * of big numbers described in section 3.4.3 of RFC 8949. It
 * implements the decode-side unification of big numbers and regular
 * integers.
 *
 * This can also be used if you happen to want type 0 and type 1
 * integers converted to big numbers.
 *
 * See also QCBORDecode_ProcessBigNumberNoPreferred().
 *
 * If QCBOR is being used in an environment with a full big number
 * library, it may be better (less object code) to use the big number
 * library than this, particularly to subtract one for tag 3.
 *
 * Finally, the object code for this function is suprisingly large,
 * almost 1KB. This is due to the number of CBOR data types, and the
 * big number math required to subtract one and the buffer sizing
 * issue it brings.
 */
QCBORError
QCBORDecode_ProcessBigNumber(const QCBORItem Item,
                             UsefulBuf       BigNumberBuf,
                             UsefulBufC     *pBigNumber,
                             bool           *pbIsNegative);


/**
 * @brief Decode a big number.
 *
 * @param[in] Item    The number to process.
 * @param[in] BigNumberBuf  The buffer to output to.
 * @param[out] pBigNumber   The resulting big number.
 * @param[out] pbIsNegative  The sign of the resulting big number.
 *
 * This is the same as QCBORDecode_ProcessBigNumber(), but doesn't
 * allow type 0 and 1 integers. It only works on tag 2 and 3 big numbers.
 * The main work this does is handle the offset of 1 for negative big
 * number decoding.
 */
QCBORError
QCBORDecode_ProcessBigNumberNoPreferred(const QCBORItem Item,
                                        UsefulBuf       BigNumberBuf,
                                        UsefulBufC     *pBigNumber,
                                        bool           *pbIsNegative);



/**
 * @brief Convert int64_t to smaller integers safely.
 *
 * @param [in]  src   An @c int64_t.
 * @param [out] dest  A smaller sized integer to convert to.
 *
 * @return 0 on success -1 if not
 *
 * When decoding an integer, the CBOR decoder will return the value as
 * an int64_t unless the integer is in the range of @c INT64_MAX and
 * @c UINT64_MAX. That is, unless the value is so large that it can only be
 * represented as a @c uint64_t, it will be an @c int64_t.
 *
 * CBOR itself doesn't size the individual integers it carries at
 * all. The only limits it puts on the major integer types is that they
 * are 8 bytes or less in length. Then encoders like this one use the
 * smallest number of 1, 2, 4 or 8 bytes to represent the integer based
 * on its value. There is thus no notion that one data item in CBOR is
 * a 1-byte integer and another is a 4-byte integer.
 *
 * The interface to this CBOR encoder only uses 64-bit integers. Some
 * CBOR protocols or implementations of CBOR protocols may not want to
 * work with something smaller than a 64-bit integer.  Perhaps an array
 * of 1,000 integers needs to be sent and none has a value larger than
 * 50,000 and are represented as @c uint16_t.
 *
 * The sending / encoding side is easy. Integers are temporarily widened
 * to 64-bits as a parameter passing through QCBOREncode_AddInt64() and
 * encoded in the smallest way possible for their value, possibly in
 * less than an @c uint16_t.
 *
 * On the decoding side the integers will be returned at @c int64_t even if
 * they are small and were represented by only 1 or 2 bytes in the
 * encoded CBOR. The functions here will convert integers to a small
 * representation with an overflow check.
 *
 * (The decoder could have support 8 different integer types and
 * represented the integer with the smallest type automatically, but
 * this would have made the decoder more complex and code calling the
 * decoder more complex in most use cases.  In most use cases on 64-bit
 * machines it is no burden to carry around even small integers as
 * 64-bit values).
 */
static inline int
QCBOR_Int64ToInt32(int64_t src, int32_t *dest)
{
   if(src > INT32_MAX || src < INT32_MIN) {
      return -1;
   } else {
      *dest = (int32_t) src;
   }
   return 0;
}

static inline int
QCBOR_Int64ToInt16(int64_t src, int16_t *dest)
{
   if(src > INT16_MAX || src < INT16_MIN) {
      return -1;
   } else {
      *dest = (int16_t) src;
   }
   return 0;
}

static inline int
QCBOR_Int64ToInt8(int64_t src, int8_t *dest)
{
   if(src > INT8_MAX || src < INT8_MIN) {
      return -1;
   } else {
      *dest = (int8_t) src;
   }
   return 0;
}

static inline int
QCBOR_Int64ToUInt32(int64_t src, uint32_t *dest)
{
   if(src > UINT32_MAX || src < 0) {
      return -1;
   } else {
      *dest = (uint32_t) src;
   }
   return 0;
}

/**
 * https://github.com/laurencelundblade/QCBOR/pull/243
 * For backwards compatibility
 */
#define QCBOR_Int64UToInt16 QCBOR_Int64ToUInt16

static inline int
QCBOR_Int64ToUInt16(int64_t src, uint16_t *dest)
{
   if(src > UINT16_MAX || src < 0) {
      return -1;
   } else {
      *dest = (uint16_t) src;
   }
   return 0;
}

static inline int
QCBOR_Int64ToUInt8(int64_t src, uint8_t *dest)
{
   if(src > UINT8_MAX || src < 0) {
      return -1;
   } else {
      *dest = (uint8_t) src;
   }
   return 0;
}

static inline int
QCBOR_Int64ToUInt64(int64_t src, uint64_t *dest)
{
   if(src < 0) {
      return -1;
   } else {
      *dest = (uint64_t) src;
   }
   return 0;
}





/* ========================================================================= *
 *    BEGINNING OF DEPRECATED FUNCTIONS                                      *
 *                                                                           *
 *    There is no plan to remove these in future versions.                   *
 *    They just have been replaced by something better.                      *
 * ========================================================================= */

/**
 * TODO: Initialize the CBOR decoder context with QCBOR v1 compatibility (deprecated).
 *
 * @param[in] pCtx         The context to initialize.
 *
 * This is listed as deprecated even though it is new in QCBOR v2 because
 * it recommended that v1 mode not be used because the tag number processing
 * is too loose.
 *
 * This links in a fair bit of object code for all the tag handlers that were
 * always present in v1. If you don't care about them, use pass XXX to init().
 *
 * This is the same as QCBORDecode_Init() except it changes the
 * tag number decoding behavior in two ways:
 *
 * First, it sets @ref QCBOR_DECODE_CONFIG_UNPROCESSED_TAG_NUMBERS which
 * causes no error to be returned when un processed tag numbers are encountered.
 *
 * Second, it installs all the same tag handlers that v1 had hardwwired.
 *    QCBORDecode_InstallTagDecoders(pMe, QCBORDecode_TagDecoderTablev1, NULL);
 */
void
QCBORDecode_CompatibilityV1(QCBORDecodeContext *pCtx);



#ifndef QCBOR_DISABLE_TAGS

/**
 * @brief Returns the tag numbers for an item. (deprecated).
 *
 * @param[in] pCtx    The decoder context.
 * @param[in] uIndex The index of the tag to get.
 *
 * This is the same as QCBORDecode_GetNthTagNumber() but the order is
 * opposite when there are multiple tags. @c uIndex 0 is the tag
 * number closest to the tag content. QCBORDecode_GetNthTagNumber() is
 * more useful for checking the next tag number and switching the
 * decode flow.
 */
uint64_t
QCBORDecode_GetNthTag(QCBORDecodeContext *pCtx, const QCBORItem *pItem, uint32_t uIndex);


/**
 * @brief Returns the tag numbers for last-decoded item (deprecated).
 *
 * @param[in] pCtx    The decoder context.
 * @param[in] uIndex The index of the tag to get.
 *
 * @returns The nth tag number or CBOR_TAG_INVALID64.
 *
 * This is the same as QCBORDecode_GetNthTagNumberOfLast() but the
 * order is opposite when there are multiple tags. @c uIndex 0 is the
 * tag number closest to the tag content.
 * QCBORDecode_GetNthTagNumber() is more useful for checking
 * the next tag number and switching the decode flow.
 */
uint64_t
QCBORDecode_GetNthTagOfLast(const QCBORDecodeContext *pCtx, uint32_t uIndex);

#endif /* ! QCBOR_DISABLE_TAGS */
/* ========================================================================= *
 *    END OF DEPRECATED FUNCTIONS                                            *
 * ========================================================================= */




/* ========================================================================= *
 *    BEGINNING OF PRIVATE INLINE IMPLEMENTATION                             *
 * ========================================================================= */

static inline uint32_t
QCBORDecode_Tell(QCBORDecodeContext *pMe)
{
   if(pMe->uLastError) {
      return UINT32_MAX;
   }

   /* Cast is safe because decoder input size is restricted. */
   return (uint32_t)UsefulInputBuf_Tell(&(pMe->InBuf));
}

static inline UsefulBufC
QCBORDecode_RetrieveUndecodedInput(QCBORDecodeContext *pMe)
{
   return UsefulInputBuf_RetrieveUndecodedInput(&(pMe->InBuf));
}

static inline QCBORError
QCBORDecode_GetError(QCBORDecodeContext *pMe)
{
    return (QCBORError)pMe->uLastError;
}

static inline QCBORError
QCBORDecode_GetAndResetError(QCBORDecodeContext *pMe)
{
    const QCBORError uReturn = (QCBORError)pMe->uLastError;
    pMe->uLastError = QCBOR_SUCCESS;
    return uReturn;
}

static inline bool
QCBORDecode_IsNotWellFormedError(const QCBORError uErr)
{
   if(uErr >= QCBOR_START_OF_NOT_WELL_FORMED_ERRORS &&
      uErr <= QCBOR_END_OF_NOT_WELL_FORMED_ERRORS) {
      return true;
   } else {
      return false;
   }
}

static inline bool
QCBORDecode_IsUnrecoverableError(const QCBORError uErr)
{
   if(uErr >= QCBOR_START_OF_UNRECOVERABLE_DECODE_ERRORS &&
      uErr <= QCBOR_END_OF_UNRECOVERABLE_DECODE_ERRORS) {
      return true;
   } else {
      return false;
   }
}


static inline void
QCBORDecode_SetError(QCBORDecodeContext *pMe, QCBORError uError)
{
   pMe->uLastError = (uint8_t)uError;
}

/* ======================================================================== *
 *    END OF PRIVATE INLINE IMPLEMENTATION                                  *
 * ======================================================================== */


/* A few cross checks on size constants and special value lengths */
#if  QCBOR_MAP_OFFSET_CACHE_INVALID < QCBOR_MAX_DECODE_INPUT_SIZE
#error QCBOR_MAP_OFFSET_CACHE_INVALID is too large
#endif

#if QCBOR_NON_BOUNDED_OFFSET < QCBOR_MAX_DECODE_INPUT_SIZE
#error QCBOR_NON_BOUNDED_OFFSET is too large
#endif

#ifdef __cplusplus
}
#endif

#endif /* qcbor_decode_h */
