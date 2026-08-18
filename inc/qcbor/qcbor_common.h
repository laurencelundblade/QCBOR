/* ==========================================================================
 * qcbor_common -- Common definitions for encding and decoding.
 *
 * Copyright (c) 2016-2018, The Linux Foundation.
 * Copyright (c) 2018-2026, Laurence Lundblade.
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

/* See https://www.securitytheory.com/qcbor-docs/ for the full
 * searchable documnetation built from these headers.
 */

#ifndef qcbor_common_h
#define qcbor_common_h


#ifdef __cplusplus
extern "C" {
#if 0
} // Keep editor indention formatting happy
#endif
#endif

/**
 * @file qcbor_common.h
 *
 * qcbor_common.h contains error codes and constant values that are
 * common between encoding and decoding.
 */


/* This is a beta (not ready for commercial use) release of 2.0.0 */

/* Pre-processor magic turns version integers into a standard version string. */
#define QCBOR_PRIVATE_STR1(x) #x
#define QCBOR_PRIVATE_STR(x) QCBOR_PRIVATE_STR1(x)

/**
 * @addtogroup QCBORVersions QCBOR Version Number
 * @brief Standard macros for semantic versioning
 *
 * QCBOR follows semantic versioning starting at 1.3.0. MAJOR increments
 * on breaking API changes, MINOR on backwards-compatible additions,
 * PATCH on backwards-compatible bug fixes.
 * @{
 */
#define QCBOR_VERSION_MAJOR 2 /**< Major version number. */
#define QCBOR_VERSION_MINOR 0 /**< Minor version number. */
#define QCBOR_VERSION_PATCH 0 /**< Patch version number. */

/** Pre-release tag: "-alpha.1", "-beta.2", "-rc.1" during pre-release;
 * "" for a final release */
#define QCBOR_VERSION_PRERELEASE "-beta.1"

/** Standard-format version string. This strings appears in library binaries. */
#define QCBOR_VERSION_STRING  QCBOR_PRIVATE_STR(QCBOR_VERSION_MAJOR) "." \
                              QCBOR_PRIVATE_STR(QCBOR_VERSION_MINOR) "." \
                              QCBOR_PRIVATE_STR(QCBOR_VERSION_PATCH) \
                              QCBOR_VERSION_PRERELEASE

/** A combined version number for simple scalar version comparison */
#define QCBOR_VERSION_NUMBER  QCBOR_VERSION_MAJOR * 10000 + \
                              QCBOR_VERSION_MINOR * 100 + \
                              QCBOR_VERSION_PATCH)

/**
 * This indicates a version of QCBOR that supports spiffy
 * decode. All versions since 2020 support spiffy decode.
 */
#define QCBOR_SPIFFY_DECODE

/** @} */

/* Banner embedded in object code for display by 'strings' shell command */
#define QCBOR_VERSION_BANNER "libqcbor " QCBOR_VERSION_STRING




/* Standard CBOR Major type for positive integers of various lengths. */
#define CBOR_MAJOR_TYPE_POSITIVE_INT 0

/* Standard CBOR Major type for negative integer of various lengths. */
#define CBOR_MAJOR_TYPE_NEGATIVE_INT 1

/* Standard CBOR Major type for an array of arbitrary 8-bit bytes. */
#define CBOR_MAJOR_TYPE_BYTE_STRING  2

/* Standard CBOR Major type for a UTF-8 string. Note this is true 8-bit UTF8
 * with no encoding and no NULL termination. */
#define CBOR_MAJOR_TYPE_TEXT_STRING  3

/* Standard CBOR Major type for an ordered array of other CBOR data items. */
#define CBOR_MAJOR_TYPE_ARRAY        4

/* Standard CBOR Major type for CBOR MAP. Maps an array of pairs. The
 * first item in the pair is the "label" (key, name or identfier) and the second
 * item is the value.  */
#define CBOR_MAJOR_TYPE_MAP          5

/* Standard CBOR major type for a tag number. This creates a CBOR "tag" that
 * is the tag number and a data item that follows as the tag content.
 *
 * Note that this was called an optional tag in RFC 7049, but there's
 * not really anything optional about it. It was misleading. It is
 * renamed in RFC 8949.
 */
#define CBOR_MAJOR_TYPE_TAG          6
#define CBOR_MAJOR_TYPE_OPTIONAL     6

/* Standard CBOR simple types like float, the values true, false, null... */
#define CBOR_MAJOR_TYPE_SIMPLE       7




/*
 * Tags that are used with CBOR_MAJOR_TYPE_OPTIONAL. These
 * are types defined in RFC 8949 and some additional ones
 * in the IANA CBOR tags registry.
 */
/** See QCBOREncode_AddTDateString(). */
#define CBOR_TAG_DATE_STRING    0
/** See QCBOREncode_AddTDateEpoch(). */
#define CBOR_TAG_DATE_EPOCH     1
/** A postive big number. See QCBOREncode_AddTBigNumber(),
 * QCBORDecode_GetTBigNumber() and QCBORDecode_StringsTagCB(). */
#define CBOR_TAG_POS_BIGNUM     2
/** A negative big number. See QCBOREncode_AddTBigNumber(),
 * QCBORDecode_GetTBigNumber() and QCBORDecode_StringsTagCB(). */
#define CBOR_TAG_NEG_BIGNUM     3
/** CBOR tag for a two-element array representing a fraction with a
 *  mantissa and base-10 scaling factor. See
 *  QCBOREncode_AddTDecimalFraction() and @ref expAndMantissa. */
#define CBOR_TAG_DECIMAL_FRACTION  4
/** CBOR tag for a two-element array representing a fraction with a
 *  mantissa and base-2 scaling factor. See QCBOREncode_AddTBigFloat()
 *  and @ref expAndMantissa. */
#define CBOR_TAG_BIGFLOAT       5
/** Not Decoded by QCBOR. Tag for COSE format encryption with no
 *  recipient identification. See [RFC 9052, COSE]
 *  (https://www.rfc-editor.org/rfc/rfc9052.html). No API is provided
 *  for this tag. */
#define CBOR_TAG_COSE_ENCRYPT0 16
#define CBOR_TAG_COSE_ENCRYPTO 16
/** Not Decoded by QCBOR. Tag for COSE format MAC'd data with no
 *  recipient identification. See [RFC 9052, COSE]
 *  (https://www.rfc-editor.org/rfc/rfc9052.html). No API is provided for this
 *  tag. */
#define CBOR_TAG_COSE_MAC0     17
/** Tag for COSE format single signature signing. No API is provided
 *  for this tag. See [RFC 9052, COSE]
 *  (https://www.rfc-editor.org/rfc/rfc9052.html). */
#define CBOR_TAG_COSE_SIGN1    18
/** A hint that the following byte string should be encoded in
 *  Base64URL when converting to JSON or similar text-based
 *  representations. Call @c
 *  QCBOREncode_AddTagNumber(pCtx,CBOR_TAG_ENC_AS_B64URL) before the call to
 *  QCBOREncode_AddBytes(). */
#define CBOR_TAG_ENC_AS_B64URL 21
/** A hint that the following byte string should be encoded in Base64
 *  when converting to JSON or similar text-based
 *  representations. Call @c
 *  QCBOREncode_AddTagNumber(pCtx,CBOR_TAG_ENC_AS_B64) before the call to
 *  QCBOREncode_AddBytes(). */
#define CBOR_TAG_ENC_AS_B64    22
/** A hint that the following byte string should be encoded in base-16
 *  format per [RFC 4648]
 *  (https://www.rfc-editor.org/rfc/rfc4648.html) when converting to
 *  JSON or similar text-based representations. Essentially, Base-16
 *  encoding is the standard case- insensitive hex encoding and may be
 *  referred to as "hex". Call @c QCBOREncode_AddTagNumber(pCtx,CBOR_TAG_ENC_AS_B16)
 *  before the call to QCBOREncode_AddBytes(). */
#define CBOR_TAG_ENC_AS_B16    23
/** See QCBORDecode_EnterBstrWrapped()). */
#define CBOR_TAG_CBOR          24
/** See QCBOREncode_AddTURI(). */
#define CBOR_TAG_URI           32
/** See QCBOREncode_AddTB64URLText(). */
#define CBOR_TAG_B64URL        33
/** See QCBOREncode_AddB64Text(). */
#define CBOR_TAG_B64           34
/** See QCBOREncode_AddTRegex(). */
#define CBOR_TAG_REGEX         35
/** See QCBOREncode_AddMIMEData(). */
#define CBOR_TAG_MIME          36
/** See QCBOREncode_AddTBinaryUUID(). */
#define CBOR_TAG_BIN_UUID      37
/** The data is a CBOR Web Token per [RFC 8392]
 *  (https://www.rfc-editor.org/rfc/rfc8392.html). No API is provided for this
 *  tag. */
#define CBOR_TAG_CWT           61
/** Tag for COSE format encryption. See [RFC 9052, COSE]
 * (https://www.rfc-editor.org/rfc/rfc9052.html). No API is provided for this
 *  tag. */
#define CBOR_TAG_CBOR_SEQUENCE 63
/** Not Decoded by QCBOR. Tag for COSE format encrypt. See [RFC 9052, COSE]
 * (https://www.rfc-editor.org/rfc/rfc9052.html). No API is provided for this
 *  tag. */
#define CBOR_TAG_COSE_ENCRYPT  96
#define CBOR_TAG_ENCRYPT       96
/** Not Decoded by QCBOR. Tag for COSE format MAC. See [RFC 9052, COSE]
 * (https://www.rfc-editor.org/rfc/rfc9052.html). No API is provided for this
    tag. */
#define CBOR_TAG_COSE_MAC      97
#define CBOR_TAG_MAC           97
/** Not Decoded by QCBOR. Tag for COSE format signed data. See [RFC 9052, COSE]
 * (https://www.rfc-editor.org/rfc/rfc9052.html). No API is provided for this
    tag. */
#define CBOR_TAG_COSE_SIGN     98
#define CBOR_TAG_SIGN          98
/** Tag for date counted by days from Jan 1 1970 per [RFC 8943]
 *  (https://www.rfc-editor.org/rfc/rfc8943.html). See
 *  QCBOREncode_AddTDaysEpoch(). */
#define CBOR_TAG_DAYS_EPOCH    100
/** Not Decoded by QCBOR. World geographic coordinates. See ISO 6709, [RFC 5870]
 *  (https://www.rfc-editor.org/rfc/rfc5870.html) and WGS-84. No API is
 *  provided for this tag. */
#define CBOR_TAG_GEO_COORD     103
/** Binary MIME.*/
#define CBOR_TAG_BINARY_MIME   257
/** Tag for date string without time or time zone per [RFC 8943]
 *  (https://www.rfc-editor.org/rfc/rfc8943.html). See
 *  QCBOREncode_AddTDaysString(). */
#define CBOR_TAG_DAYS_STRING   1004
/** The magic number, self-described CBOR. No API is provided for this
 * tag. */
#define CBOR_TAG_CBOR_MAGIC    55799

/** The 16-bit invalid tag from the CBOR tags registry */
#define CBOR_TAG_INVALID16 0xffff
/** The 32-bit invalid tag from the CBOR tags registry */
#define CBOR_TAG_INVALID32 0xffffffff
/** The 64-bit invalid tag from the CBOR tags registry */
#define CBOR_TAG_INVALID64 0xffffffffffffffffULL

/** Allows tag content handler installed by QCBORDecode_InstallTagDecoders to match any tag number */
#define CBOR_TAG_ANY (CBOR_TAG_INVALID64 - 1)




/**
 * Error codes returned by QCBOR Encoder-Decoder.
 *
 * They are grouped to keep the code size of
 * QCBORDecode_IsNotWellFormedError() and
 * QCBORDecode_IsUnrecoverableError() minimal.
 *
 *    1..19: Encode errors
 *    20..: Decode errors
 *    20-39: QCBORDecode_IsNotWellFormedError()
 *    30..59: QCBORDecode_IsUnrecoverableError()
 *    60..: Other decode errors
 *
 * Error renumbering may occur in the future when new error codes are
 * added for new QCBOR features.
 */
typedef enum {
   /** The encode or decode completed correctly. */
   QCBOR_SUCCESS = 0,

   /** The buffer provided for the encoded output when doing encoding
    *   was too small and the encoded output will not fit. */
   QCBOR_ERR_BUFFER_TOO_SMALL = 1,

   /** The @ref UsefulOutBuf for encoding is corrupted. */
   QCBOR_ERR_UB_BAD = 2,

   /** The @ref UsefulOutBuf for encoding returned an insert point error
    *  (should never happen). */
   QCBOR_ERR_USEFULBUF_INSERT_POINT = 3,

   /** The operation can only  be performed in streaming mode.
    *  See QCBOREncode_SetStream() .*/
   QCBOR_ERR_NOT_STREAMING = 4,

   /** The operation cannot be performed in streaming mode.
    *  See QCBOREncode_SetStream() */
   QCBOR_ERR_NOT_ALLOWED_IN_STREAMING = 5,

   /** The streaming flush callback returned an error.
    *  See QCBOREncode_SetStream(). */
   QCBOR_ERR_STREAM_FLUSH = 6,

   /* 7 and 8 are for UsefuBuf, but can be used here too. */

   /** During encoding, an attempt to create simple value between 24
    *  and 31. */
   QCBOR_ERR_ENCODE_UNSUPPORTED = 9,

   /** During encoding, the length of the encoded CBOR exceeded
    *  @ref QCBOR_MAX_SIZE, which is slightly less than
    *  @c UINT32_MAX. */
   QCBOR_ERR_BUFFER_TOO_LARGE = 10,

   /** During encoding, nesting deeper than @ref QCBOR_MAX_ARRAY_NESTING
    *  occurred. Arrays, maps, byte-string wrapping, and some string
    *  encoding contribute to the nesting depth. */
   QCBOR_ERR_ENCODE_NESTING_TOO_DEEP = 11,
   /** Alias for ::QCBOR_ERR_ENCODE_NESTING_TOO_DEEP for backward compatibility. */
   QCBOR_ERR_ARRAY_NESTING_TOO_DEEP = QCBOR_ERR_ENCODE_NESTING_TOO_DEEP,


   /** During encoding, the type of close doesn't match what is open. Also
    * an indefinite-length string chunk is of the wrong type or
    * no indefinite-length string is open. */
   QCBOR_ERR_CLOSE_MISMATCH = 12,
   QCBOR_ERR_NESTED_TYPE_MISMATCH = 12,

   /** During encoding, the array or map had too many items in it. The
    * limits are @ref QCBOR_MAX_ITEMS_IN_ARRAY and
    * @ref QCBOR_MAX_ITEMS_IN_MAP. */
   QCBOR_ERR_ARRAY_TOO_LONG = 13,

   /** During encoding, more arrays or maps were closed than
    *  opened. This is a coding error on the part of the caller of the
    *  encoder. */
   QCBOR_ERR_TOO_MANY_CLOSES = 14,

   /** During encoding, the number of array or map opens was not
    *  matched by the number of closes. Also occurs with opened byte
    *  strings that are not closed. */
   QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN = 15,

   /** During encoding, opening a byte string while a byte string is
    *  open is not allowed. */
   QCBOR_ERR_OPEN_BYTE_STRING = 16,

   /** Trying to cancel a byte string wrapping after items have been
    *  added to it. */
   QCBOR_ERR_CANNOT_CANCEL = 17,

#define QCBOR_START_OF_NOT_WELL_FORMED_ERRORS 20

   /** During decoding, the CBOR is not well-formed because a simple
    *  value between 0 and 31 is encoded in a two-byte integer rather
    *  than one. */
   QCBOR_ERR_BAD_TYPE_7 = 20,

   /** During decoding, returned by QCBORDecode_Finish() if all the
    *  inputs bytes have not been consumed. This is considered not
    *  well-formed. */
   QCBOR_ERR_EXTRA_BYTES = 21,

   /** During decoding, some CBOR construct was encountered that this
    *  decoder doesn't support, primarily this is the reserved
    *  additional info values, 28 through 30. The CBOR is not
    *  well-formed.
    */
   QCBOR_ERR_UNSUPPORTED = 22,

   /** During decoding, the an array or map was not fully consumed.
    *  Returned by QCBORDecode_Finish(). The CBOR is not
    *  well-formed. */
   QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED = 23,

   /** During decoding, an integer type is encoded with a bad length
    *  (that of an indefinite length string). The CBOR is not-well
    *  formed. */
   QCBOR_ERR_BAD_INT = 24,

#define QCBOR_START_OF_UNRECOVERABLE_DECODE_ERRORS 30

   /** During decoding, one of the chunks in an indefinite-length
    *  string is not of the type of the start of the string.  The CBOR
    *  is not well-formed.  This error makes no further decoding
    *  possible. */
   QCBOR_ERR_INDEFINITE_STRING_CHUNK = 30,

   /** During decoding, hit the end of the given data to decode. For
    *  example, a byte string of 100 bytes was expected, but the end
    *  of the input was hit before finding those 100 bytes.  Corrupted
    *  CBOR input will often result in this error. See also
    *  @ref QCBOR_ERR_NO_MORE_ITEMS. The CBOR is not well-formed.
    *  This error makes no further decoding possible. */
   QCBOR_ERR_HIT_END = 31,

   /** During decoding, a break occurred outside an indefinite-length
    *  item. The CBOR is not well-formed. This error makes no further
    *  decoding possible. */
   QCBOR_ERR_BAD_BREAK = 32,

#define QCBOR_END_OF_NOT_WELL_FORMED_ERRORS 39

   /** During decoding, the input is too large. It is greater than
    *  QCBOR_MAX_SIZE. This is an implementation limit.
    *  This error makes no further decoding possible. */
   QCBOR_ERR_INPUT_TOO_LARGE = 40,

   /** Decoding exceeded @ref QCBOR_MAX_ARRAY_NESTING.
    *  Arrays, maps, and byte-string wrapping contribute to the nesting depth.
    *  No further decoding is possible.
    */
   QCBOR_ERR_DECODE_NESTING_TOO_DEEP = 41,
   /** Alias for ::QCBOR_ERR_DECODE_NESTING_TOO_DEEP for backward compatibility. */
   QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP = QCBOR_ERR_DECODE_NESTING_TOO_DEEP,

   /** During decoding, the array or map had too many items in it.
    *  This limit is @ref QCBOR_MAX_ITEMS_IN_ARRAY (65,534) for
    *  arrays and @ref QCBOR_MAX_ITEMS_IN_MAP (32,767) for maps. This
    *  error makes no further decoding possible. */
   QCBOR_ERR_ARRAY_DECODE_TOO_LONG = 42,

   /** When decoding, a string's size is greater than what a size_t
    *  can hold less 4. In all but some very strange situations this
    *  is because of corrupt input CBOR and should be treated as
    *  such. The strange situation is a CPU with a very small size_t
    *  (e.g., a 16-bit CPU) and a large string (e.g., > 65KB). This
    *  error makes no further decoding possible. */
   QCBOR_ERR_STRING_TOO_LONG = 43,

   /** Something is wrong with a decimal fraction or bigfloat such as
    *  it not consisting of an array with two integers. This error
    *  makes no further decoding possible. */
   QCBOR_ERR_BAD_EXP_AND_MANTISSA = 44,

   /** Unable to decode an indefinite-length string because no string
    *  allocator was configured. See QCBORDecode_SetMemPool() or
    *  QCBORDecode_SetUpAllocator().  This error makes no further
    *  decoding possible.*/
   QCBOR_ERR_NO_STRING_ALLOCATOR = 45,

   /** Error allocating memory for a string, usually out of memory.
    * This primarily occurs decoding indefinite-length strings. This
    * error makes no further decoding possible. */
   QCBOR_ERR_STRING_ALLOCATE = 46,

   /** During decoding, the type of the label for a map entry is not
    *  one that can be handled in the current decoding mode. Typically
    *  this is because a label is not an integer or a string. This is
    *  an implementation limit. */
   QCBOR_ERR_MAP_LABEL_TYPE = 47,

   /** When the built-in tag decoding encounters an unexpected type,
    *  this error is returned. This error is unrecoverable because the
    *  built-in tag decoding doesn't try to consume the unexpected
    *  type. In previous versions of QCBOR this was considered a
    *  recoverable error hence QCBOR_ERR_BAD_TAG_CONTENT. Going
    *  back further, RFC 7049 use the name "optional tags". That name
    *  is no longer used because "optional" was causing confusion. See
    *  also @ref QCBOR_ERR_RECOVERABLE_BAD_TAG_CONTENT. */
   QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT = 48,
   QCBOR_ERR_BAD_TAG_CONTENT = 48,
   QCBOR_ERR_BAD_OPT_TAG = 48,

   /** Indefinite length string handling is disabled and there is an
    *  indefinite length string in the input CBOR. */
   QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED = 49,

   /** Indefinite length arrays and maps handling are disabled and
    *  there is an indefinite length map or array in the input
    *  CBOR. */
   QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED = 50,

   /** All decoding of tags (major type 6) has been disabled and a tag
    *  occurred in the decode input. */
   QCBOR_ERR_TAGS_DISABLED = 51,

   /** Indefinite lengths are disallowed by
    * @ref QCBOR_DECODE_MODE_NO_INDEF_LENGTH */
   QCBOR_ERR_INDEF_LENGTH = 52,

   /** @ref QCBOR_DECODE_MODE_ONLY_SHORTEST_CBOR_ARGUMENT is set and
    * an item with non-shortest-length argument was decoded. */
   QCBOR_ERR_NOT_SHORTEST_CBOR_ARGUMENT = 53,

   /** @ref QCBOR_DECODE_MODE_ONLY_SHORTEST_FLOAT is set and a float
    * that wasn't encoded in the shortest form was decoded. */
   QCBOR_ERR_NOT_SHORTEST_FLOAT = 54,

   /** A map is unsorted and @ref QCBOR_DECODE_MODE_ONLY_SORTED_MAPS
    * is set. */
   QCBOR_ERR_UNSORTED = 55,

   /** Non-reduced floats disallowed by
    * @ref QCBOR_DECODE_MODE_ONLY_REDUCED_FLOATS */
   QCBOR_ERR_FLOAT_NOT_REDUCED = 56,

   /** A simple type other than true, false or null was encountered
    * and ref QCBOR_DECODE_MODE_ONLY_BASIC_SIMPLE_VALUES is set. */
   QCBOR_ERR_NOT_BASIC_SIMPLE_VALUE = 57,

   /** Conformance checking requested, but not possible because it is disabled in some way. */
   QCBOR_ERR_CANT_CHECK_CONFORMANCE = 58,

   QCBOR_ERR_NOT_PREFERRED_BIGNUM = 59,

   // TODO: is conformance check failure really an uncrecoverable error?

#define QCBOR_END_OF_UNRECOVERABLE_DECODE_ERRORS 59

   /** More than @ref QCBOR_MAX_TAGS_PER_ITEM tag numbers on a single
    *  @ref QCBORItem, or more than @ref QCBOR_NUM_MAPPED_TAGS distinct
    *  tag numbers greater than @ref QCBOR_LAST_UNMAPPED_TAG within a
    *  single @ref QCBORDecodeContext. @ref QCBOR_MAX_TAGS_PER_ITEM
    *  and @ref QCBOR_NUM_MAPPED_TAGS are configurable limits of
    *  QCBOR. */
   QCBOR_ERR_TOO_MANY_TAGS = 60,

   /** When decoding for a specific type, the type was not expected.  */
   QCBOR_ERR_UNEXPECTED_TYPE = 61,

   /** Duplicate label detected in a map. */
   QCBOR_ERR_DUPLICATE_LABEL = 62,

   /** During decoding, the buffer given to QCBORDecode_SetMemPool()
    *  is either too small, smaller than
    *  @ref QCBOR_DECODE_MIN_MEM_POOL_SIZE or too large, larger than
    *  UINT32_MAX. */
   QCBOR_ERR_MEM_POOL_SIZE = 63,

   /** During decoding, an integer smaller than INT64_MIN was received
    *  (CBOR can represent integers smaller than INT64_MIN, but C
    *  cannot). */
   QCBOR_ERR_INT_OVERFLOW = 64,

   /** During decoding, a date greater than +- 292 billion years from
    *  Jan 1 1970 encountered during parsing. This is an
    *  implementation limit. */
   QCBOR_ERR_DATE_OVERFLOW = 65,

   /** During decoding, @c QCBORDecode_ExitXxx() was called for a
    *  different type than @c QCBORDecode_EnterXxx(). */
   QCBOR_ERR_EXIT_MISMATCH = 66,

   /** All well-formed data items have been consumed and there are no
    *  more. If parsing a CBOR stream this indicates the non-error end
    *  of the stream. If not parsing a CBOR stream/sequence, this
    *  probably indicates that some data items expected are not
    *  present.  See also @ref QCBOR_ERR_HIT_END. */
   QCBOR_ERR_NO_MORE_ITEMS = 67,

   /** When finding an item by label, an item with the requested label
    *  was not found. */
   QCBOR_ERR_LABEL_NOT_FOUND = 68,

   /** Number conversion failed because of sign. For example a
    *  negative int64_t can't be converted to a uint64_t */
   QCBOR_ERR_NUMBER_SIGN_CONVERSION = 69,

   /** When converting a decoded number, the value is too large or too
    *  small for the conversion target. */
   QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW = 70,

   /** Trying to get an item by label when a map has not been
    *  entered. */
   QCBOR_ERR_MAP_NOT_ENTERED = 71,

   /** A callback indicates processing should not continue for some
    *  non-CBOR reason. */
   QCBOR_ERR_CALLBACK_FAIL = 72,

   /** This error code is deprecated. Instead,
    *  @ref QCBOR_ERR_PREFERRED_FLOAT_DISABLED,
    *  @ref QCBOR_ERR_HW_FLOAT_DISABLED or @ref QCBOR_ERR_ALL_FLOAT_DISABLED
    *  is returned depending on the specific floating-point functionality
    *  that is disabled and the type of floating-point input. */
   QCBOR_ERR_FLOAT_DATE_DISABLED = 73,

   /** Support for preferred serialization is disabled (QCBOR
    * was compiled with QCBOR_DISABLE_PREFERRED_FLOAT). */
   QCBOR_ERR_PREFERRED_FLOAT_DISABLED = 74,
   QCBOR_ERR_HALF_PRECISION_DISABLED = 74, /* Deprecated */

   /** Use of floating-point HW is disabled. This affects all type
    *  conversions to and from double and float types. */
   QCBOR_ERR_HW_FLOAT_DISABLED = 75,

   /** Unable to complete operation because a floating-point value
    *  that is a NaN (not a number), that is too large, too small,
    *  infinity or -infinity was encountered in encoded CBOR. Usually
    *  this because conversion of the float-point value was being
    *  attempted. */
   QCBOR_ERR_FLOAT_EXCEPTION = 76,

   /** Floating point support is completely turned off,
    *  encoding/decoding floating point numbers is not possible. */
   QCBOR_ERR_ALL_FLOAT_DISABLED = 77,

   /** Like @ref QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT, but recoverable.
    * If an implementation decodes a tag and can and does consume the
    * whole tag contents when it is not the correct tag content, this
    * error can be returned. None of the built-in tag decoders do this
    * (to save object code). */
   QCBOR_ERR_RECOVERABLE_BAD_TAG_CONTENT = 78,

   /** Attempt to output non-preferred, non-deterministic or non-dCBOR
    * when not allowed by mode. See
    * @ref QCBOR_ENCODE_CONFIG_ONLY_PREFERRED_BIG_NUMBERS,
    * @ref QCBOR_ENCODE_CONFIG_DISALLOW_NON_PREFERRED_NUMBERS,
    * @ref QCBOR_ENCODE_CONFIG_PREFERRED,
    * @ref QCBOR_ENCODE_CONFIG_DETERMINISTIC,
    * @ref QCBOR_ENCODE_CONFIG_DCBOR.
     */
   QCBOR_ERR_NOT_PREFERRED = 79,

   /** Trying to do something that is not allowed. */
   QCBOR_ERR_NOT_ALLOWED = 80,

   /** QCBORDecode_EnterBstrWrapped() cannot be used on
    * indefinite-length strings because they exist in the memory pool for
    * a @ref QCBORStringAllocate. */
   QCBOR_ERR_CANNOT_ENTER_ALLOCATED_STRING = 81,

   /** Can't output a negative zero big num */
   QCBOR_ERR_NO_NEGATIVE_ZERO = 87,

   /** A tag number was not expected such as one is encountered with
    * @ref QCBOR_TAG_REQUIREMENT_NOT_A_TAG. */
   QCBOR_ERR_UNEXPECTED_TAG_NUMBER = 89,

   /** In QCBOR v2, tag numbers must be processed by QCBORDecode_GetNextTagNumber().
    * See @ref QCBOR_DECODE_MODE_ALLOW_UNPROCESSED_TAG_NUMBERS. */
   QCBOR_ERR_UNPROCESSED_TAG_NUMBER = 90,

   /** A tag number is expected, but missing. */
   QCBOR_ERR_MISSING_TAG_NUMBER = 91,

   /** NaN payloads are an error unless explicitly allowed by @ref QCBOR_DECODE_MODE_ALLOW_NAN_PAYLOADS */
   QCBOR_ERR_NAN_PAYLOAD = 92,

   /** A range of error codes that can be made use of by the
    * caller. QCBOR internally does nothing with these except notice
    * that they are not QCBOR_SUCCESS. See QCBORDecode_SetError(). */
   QCBOR_ERR_FIRST_USER_DEFINED = 128,

   /** See @ref QCBOR_ERR_FIRST_USER_DEFINED */
   QCBOR_ERR_LAST_USER_DEFINED = 255

   /* This is stored in uint8_t; never add values > 255 */
} QCBORError;


/**
 * @brief Get string describing an error code.
 *
 * @param[in] uErr   The error code.
 *
 * @return  NULL-terminated string describing error or "Unidentified
 *          error" if the error is not known.
 *
 * This is not thread-safe because it uses a static buffer
 * for formatting, but this is only a diagnostic and the only
 * consequence is the wrong description.
 */
const char *
qcbor_err_to_str(QCBORError uErr);




/**
 * @addtogroup QCBORLimitations  QCBOR Limitations and Maximum Sizes
 * @brief This describes QCBOR's maximums and limitations
 *
 * @{
 */
/**
 * The maximum size in bytes for input to decode or encoder
 * output. This cannot be changed.
 *
 * The public interface uses @c size_t for lengths, but internally
 * QCBOR holds them in 32 bits.  The limit is slightly less than @c
 * UINT32_MAX (4GB) to accommodate testing and a sentinel value.
 */
#define QCBOR_MAX_SIZE  (UINT32_MAX - 100)


/**
 * This is the maximum nesting depth of definite and indefinite-length
 * arrays and maps for encoding and decoding. Byte-string wrapping and
 * unwrapping also count towards nesting depth, as does encoding of
 * segmented strings.
 *
 * This value can be changed when building QCBOR; see
 * @ref ChangingMaxLimits. The default of 35 is intended for
 * less-constrained systems, which are the more common case. For very
 * constrained systems, it may be reduced to 7. Before QCBOR v1.7.0
 * the default was 15.
 *
 * Expected size in bytes on a 64-bit CPU:
 *
 * | Structure                   |  7  | 15 (previous default) | 35 (default) |
 * |-----------------------------| --- | --------------------- | ------------ |
 * | @ref QCBOREncodeContext     | 136 | 200                   | 360          |
 * | @ref QCBORDecodeContext     | 256 | 352                   | 592          |
 * | @ref QCBORSavedDecodeCursor | 168 | 264                   | 504          |
 *
 * Each nesting level costs 8 bytes in @ref QCBOREncodeContext and 12
 * bytes in each of @ref QCBORDecodeContext and
 * @ref QCBORSavedDecodeCursor (these sizes may vary by CPU type and
 * compiler). The size of these structures is the only cost of
 * changing this limit. It cannot be set above 255 because levels are
 * indexed by a @c uint8_t. Values below 7 are untested.
 */
#ifndef QCBOR_MAX_ARRAY_NESTING
#define QCBOR_MAX_ARRAY_NESTING  35
#endif



/**
 * The maximum number of items in a single definite or
 * indefinite-length array when encoding or decoding. See also
 * @ref QCBOR_MAX_ITEMS_IN_MAP. This cannot be changed.
 */
#define QCBOR_MAX_ITEMS_IN_ARRAY (UINT16_MAX-1)
/* -1 is because the value UINT16_MAX is used to indicate
 * indefinite-length.
 */


/**
 * The maximum number of entries (label-value pairs) in a single
 * definite or indefinite-length map when encoding or decoding. See
 * also @ref QCBOR_MAX_ITEMS_IN_ARRAY. This cannot be changed.
 */
#define QCBOR_MAX_ITEMS_IN_MAP  (QCBOR_MAX_ITEMS_IN_ARRAY/2)


/**
 * @def QCBOR_NUM_MAPPED_TAGS
 *
 * The number of distinct tag numbers greater than
 * @ref QCBOR_LAST_UNMAPPED_TAG (typically 65,530) that a single
 * @ref QCBORDecodeContext can handle. Tag numbers at or below that
 * threshold are stored directly and are not subject to this limit.
 *
 * To keep data structures small and avoid dynamic memory allocation,
 * QCBOR stores large tag numbers in a fixed-size mapping table and
 * refers to them internally by table index. Once the table is full,
 * decoding an item carrying a further distinct large tag number
 * returns @ref QCBOR_ERR_TOO_MANY_TAGS.
 *
 * Note that the limit is on *distinct* tag numbers per context, not
 * on occurrences: the same large tag number appearing many times
 * consumes one entry.
 *
 * This value can be changed when building QCBOR; see
 * @ref ChangingMaxLimits. Each additional
 * mapped tag number adds 8 bytes to both @ref QCBORDecodeContext and
 * @ref QCBORSavedDecodeCursor.  Raising this by one also lowers
 * @ref QCBOR_LAST_UNMAPPED_TAG by one.
 */
#ifndef QCBOR_NUM_MAPPED_TAGS
#define QCBOR_NUM_MAPPED_TAGS  4
#endif


/**
 * @def QCBOR_MAX_TAGS_PER_ITEM
 *
 * The maximum number of tag numbers that may be nested on a single
 * CBOR item.
 *
 * This limit exists so that @ref QCBORItem stays small: it is passed
 * by value and is typically stack-allocated, so its size matters on
 * constrained targets.
 *
 * This value can be changed when building QCBOR; see
 * @ref ChangingMaxLimits. Each additional tag adds 2 bytes to
 * @ref QCBORItem, 2 bytes to @ref QCBORDecodeContext and
 * increases stack use while decoding by 2 bytes.
 *
 * See also @ref QCBOR_NUM_MAPPED_TAGS, which limits distinct large tag
 * numbers per decode context rather than nesting depth per item.
 */
#ifndef QCBOR_MAX_TAGS_PER_ITEM
#define QCBOR_MAX_TAGS_PER_ITEM  4
#endif

/** @} */


/** @cond DOXYGEN_IGNORE */

/* Largest value QCBOR_MAX_ARRAY_NESTING can be set to. Limited
 * by indexing with 8-bit integer */
#define QCBOR_MAX_MAX_ARRAY_NESTING 255

#if QCBOR_MAX_ARRAY_NESTING > QCBOR_MAX_MAX_ARRAY_NESTING
#error QCBOR_MAX_ARRAY_NESTING must be less than 256
#endif


/* Largest value QCBOR_MAX_TAGS_PER_ITEM can be set to. This limit is
 * actually in the implementation of TooManyTagsTest(), but 512 tags is
 * a ridiculous amount so no need to improve the test. */
#define QCBOR_MAX_MAX_TAGS_PER_ITEM 512

/* It will probably work with 1, but lots of tests fail with 1. */
#define QCBOR_MIN_MAX_TAGS_PER_ITEM 2

#if QCBOR_MAX_TAGS_PER_ITEM > QCBOR_MAX_MAX_TAGS_PER_ITEM
#error QCBOR_MAX_TAGS_PER_ITEM must be less than 512
#endif

#if QCBOR_MAX_TAGS_PER_ITEM < QCBOR_MIN_MAX_TAGS_PER_ITEM
#error QCBOR_MAX_TAGS_PER_ITEM must be more than 2
#endif



/* Largest value QCBOR_MAX_NUM_MAPPED_TAGS can be set to. This limit
 * is in the implementation of TooManyTagsTest(), but 50 tags is a
 * ridiculous amount so no need to improve the test. */
#define QCBOR_MAX_NUM_MAPPED_TAGS 50

#if QCBOR_NUM_MAPPED_TAGS > QCBOR_MAX_NUM_MAPPED_TAGS
#error QCBOR_NUM_MAPPED_TAGS must be less than 50
#endif

/** @endcond */



#ifdef __cplusplus
}
#endif

#endif /* qcbor_common_h */
