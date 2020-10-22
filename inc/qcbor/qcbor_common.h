/*==============================================================================
 Copyright (c) 2016-2018, The Linux Foundation.
 Copyright (c) 2018-2020, Laurence Lundblade.
 All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of The Linux Foundation nor the names of its
      contributors, nor the name "Laurence Lundblade" may be used to
      endorse or promote products derived from this software without
      specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 =============================================================================*/


#ifndef qcbor_common_h
#define qcbor_common_h


/**
 @file qcbor_common.h

 This define indicates a version of QCBOR that supports spiffy decode,
 the decode functions found in qcbor_spiffy_decode.h.

 Versions of QCBOR that support spiffy decode are backwards compatible
 with previous versions, but there are a few minor exceptions such as
 some aspects of tag handling that are different. This define can be
 used handle these variances.
*/
#define QCBOR_SPIFFY_DECODE




/* Standard CBOR Major type for positive integers of various lengths */
#define CBOR_MAJOR_TYPE_POSITIVE_INT 0

/* Standard CBOR Major type for negative integer of various lengths */
#define CBOR_MAJOR_TYPE_NEGATIVE_INT 1

/* Standard CBOR Major type for an array of arbitrary 8-bit bytes. */
#define CBOR_MAJOR_TYPE_BYTE_STRING  2

/* Standard CBOR Major type for a UTF-8 string. Note this is true 8-bit UTF8
 with no encoding and no NULL termination */
#define CBOR_MAJOR_TYPE_TEXT_STRING  3

/* Standard CBOR Major type for an ordered array of other CBOR data items */
#define CBOR_MAJOR_TYPE_ARRAY        4

/* Standard CBOR Major type for CBOR MAP. Maps an array of pairs. The
 first item in the pair is the "label" (key, name or identfier) and the second
 item is the value.  */
#define CBOR_MAJOR_TYPE_MAP          5

/* Standard CBOR optional tagging. This tags things like dates and URLs */
#define CBOR_MAJOR_TYPE_OPTIONAL     6

/* Standard CBOR extra simple types like floats and the values true and false */
#define CBOR_MAJOR_TYPE_SIMPLE       7


/*
 These are special values for the AdditionalInfo bits that are part of
 the first byte.  Mostly they encode the length of the data item.
 */
#define LEN_IS_ONE_BYTE    24
#define LEN_IS_TWO_BYTES   25
#define LEN_IS_FOUR_BYTES  26
#define LEN_IS_EIGHT_BYTES 27
#define ADDINFO_RESERVED1  28
#define ADDINFO_RESERVED2  29
#define ADDINFO_RESERVED3  30
#define LEN_IS_INDEFINITE  31


/*
 24 is a special number for CBOR. Integers and lengths
 less than it are encoded in the same byte as the major type.
 */
#define CBOR_TWENTY_FOUR   24


/*
 Tags that are used with CBOR_MAJOR_TYPE_OPTIONAL. These
 are types defined in RFC 7049 and some additional ones
 in the IANA CBOR tags registry.
 */
/** See QCBOREncode_AddDateString(). */
#define CBOR_TAG_DATE_STRING    0
/** See QCBOREncode_AddDateEpoch(). */
#define CBOR_TAG_DATE_EPOCH     1
/** See QCBOREncode_AddPositiveBignum(). */
#define CBOR_TAG_POS_BIGNUM     2
/** See QCBOREncode_AddNegativeBignum(). */
#define CBOR_TAG_NEG_BIGNUM     3
/** CBOR tag for a two-element array representing a fraction with a
    mantissa and base-10 scaling factor. See QCBOREncode_AddDecimalFraction()
    and @ref expAndMantissa.
  */
#define CBOR_TAG_DECIMAL_FRACTION  4
/** CBOR tag for a two-element array representing a fraction with a
    mantissa and base-2 scaling factor. See QCBOREncode_AddBigFloat()
    and @ref expAndMantissa. */
#define CBOR_TAG_BIGFLOAT       5
/** Not Decoded by QCBOR. Tag for COSE format encryption with no recipient
    identification. See [RFC 8152, COSE]
    (https://tools.ietf.org/html/rfc8152). No API is provided for this
    tag. */
#define CBOR_TAG_COSE_ENCRYPTO 16
/** Not Decoded by QCBOR. Tag for COSE format MAC'd data with no recipient
    identification. See [RFC 8152, COSE]
    (https://tools.ietf.org/html/rfc8152). No API is provided for this
    tag.*/
#define CBOR_TAG_COSE_MAC0     17
/** Tag for COSE format single signature signing. No API is provided
    for this tag. See [RFC 8152, COSE]
    (https://tools.ietf.org/html/rfc8152). */
#define CBOR_TAG_COSE_SIGN1    18
/** A hint that the following byte string should be encoded in
    Base64URL when converting to JSON or similar text-based
    representations. Call @c
    QCBOREncode_AddTag(pCtx,CBOR_TAG_ENC_AS_B64URL) before the call to
    QCBOREncode_AddBytes(). */
#define CBOR_TAG_ENC_AS_B64URL 21
/** A hint that the following byte string should be encoded in Base64
    when converting to JSON or similar text-based
    representations. Call @c
    QCBOREncode_AddTag(pCtx,CBOR_TAG_ENC_AS_B64) before the call to
    QCBOREncode_AddBytes(). */
#define CBOR_TAG_ENC_AS_B64    22
/** A hint that the following byte string should be encoded in base-16
    format per [RFC 4648] (https://tools.ietf.org/html/rfc4648) when
    converting to JSON or similar text-based
    representations. Essentially, Base-16 encoding is the standard
    case- insensitive hex encoding and may be referred to as
    "hex". Call @c QCBOREncode_AddTag(pCtx,CBOR_TAG_ENC_AS_B16) before
    the call to QCBOREncode_AddBytes(). */
#define CBOR_TAG_ENC_AS_B16    23
/** See QCBORDecode_EnterBstrWrapped()). */
#define CBOR_TAG_CBOR          24
/** See QCBOREncode_AddURI(). */
#define CBOR_TAG_URI           32
/** See QCBOREncode_AddB64URLText(). */
#define CBOR_TAG_B64URL        33
/** See QCBOREncode_AddB64Text(). */
#define CBOR_TAG_B64           34
/** See QCBOREncode_AddRegex(). */
#define CBOR_TAG_REGEX         35
/** See QCBOREncode_AddMIMEData(). */
#define CBOR_TAG_MIME          36
/** See QCBOREncode_AddBinaryUUID(). */
#define CBOR_TAG_BIN_UUID      37
/** The data is a CBOR Web Token per [RFC 8392]
    (https://tools.ietf.org/html/rfc8932). No API is provided for this
    tag. */
#define CBOR_TAG_CWT           61
/** Tag for COSE format encryption. See [RFC 8152, COSE]
    (https://tools.ietf.org/html/rfc8152). No API is provided for this
    tag. */
#define CBOR_TAG_CBOR_SEQUENCE 63


#define CBOR_TAG_ENCRYPT       96
/** Not Decoded by QCBOR. Tag for COSE format MAC. See [RFC 8152, COSE]
    (https://tools.ietf.org/html/rfc8152). No API is provided for this
    tag. */
#define CBOR_TAG_MAC           97
/** Not Decoded by QCBOR. Tag for COSE format signed data. See [RFC 8152, COSE]
    (https://tools.ietf.org/html/rfc8152). No API is provided for this
    tag. */
#define CBOR_TAG_SIGN          98
/** Not Decoded by QCBOR. World geographic coordinates. See ISO 6709, [RFC 5870]
    (https://tools.ietf.org/html/rfc5870) and WGS-84. No API is
    provided for this tag. */
#define CBOR_TAG_GEO_COORD     103
/** Binary MIME.*/
#define CBOR_TAG_BINARY_MIME   257
/** The magic number, self-described CBOR. No API is provided for this
    tag. */
#define CBOR_TAG_CBOR_MAGIC    55799

/** The 16-bit invalid tag from the CBOR tags registry */
#define CBOR_TAG_INVALID16 0xffff
/** The 32-bit invalid tag from the CBOR tags registry */
#define CBOR_TAG_INVALID32 0xffffffff
/** The 64-bit invalid tag from the CBOR tags registry */
#define CBOR_TAG_INVALID64 0xffffffffffffffff



/*
 Values for the 5 bits for items of major type 7
 */
#define CBOR_SIMPLEV_FALSE   20
#define CBOR_SIMPLEV_TRUE    21
#define CBOR_SIMPLEV_NULL    22
#define CBOR_SIMPLEV_UNDEF   23
#define CBOR_SIMPLEV_ONEBYTE 24
#define HALF_PREC_FLOAT      25
#define SINGLE_PREC_FLOAT    26
#define DOUBLE_PREC_FLOAT    27
#define CBOR_SIMPLE_BREAK    31
#define CBOR_SIMPLEV_RESERVED_START  CBOR_SIMPLEV_ONEBYTE
#define CBOR_SIMPLEV_RESERVED_END    CBOR_SIMPLE_BREAK




/**
 Error codes returned by QCBOR Encoder and Decoder.
 Encode errors are 1..8
 Decode errors are 9..43
     Not well-formed errors are 9..16
     Unrecoverable decode errors are 15..24
        (partial overlap with not well-formed errors)
   Other decode errors are 25..43

 The errors are order and grouped intentionally to keep the code size
 of QCBORDecode_IsNotWellFormedError() and
 QCBORDecode_IsUnrecoverableError() minimal. Error renumbering may
 occur in the future when new error codes are added for new QCBOR
 features.
 */
typedef enum {
   /** The encode or decode completely correctly. */
   QCBOR_SUCCESS = 0,

   /** The buffer provided for the encoded output when doing encoding
       was too small and the encoded output will not fit. */
   QCBOR_ERR_BUFFER_TOO_SMALL = 1,

   /** During encoding, an attempt to create simple value between 24
       and 31. */
   QCBOR_ERR_ENCODE_UNSUPPORTED = 2,

   /** During encoding, the length of the encoded CBOR exceeded @c
       UINT32_MAX. */
   QCBOR_ERR_BUFFER_TOO_LARGE = 3,

   /** During encoding, the array or map nesting was deeper than this
       implementation can handle. Note that in the interest of code
       size and memory use, this implementation has a hard limit on
       array nesting. The limit is defined as the constant @ref
       QCBOR_MAX_ARRAY_NESTING. */
   QCBOR_ERR_ARRAY_NESTING_TOO_DEEP = 4,

   /** During encoding, @c QCBOREncode_CloseXxx() called with a
       different type than is currently open.  */
   QCBOR_ERR_CLOSE_MISMATCH = 5,

   /** During encoding, the array or map had too many items in it.
       This limit @ref QCBOR_MAX_ITEMS_IN_ARRAY, typically 65,535. */
   QCBOR_ERR_ARRAY_TOO_LONG = 6,

   /** During encoding, more arrays or maps were closed than
       opened. This is a coding error on the part of the caller of the
       encoder. */
   QCBOR_ERR_TOO_MANY_CLOSES = 7,

   /** During encoding the number of array or map opens was not
       matched by the number of closes. */
   QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN = 8,

#define QCBOR_START_OF_NOT_WELL_FORMED_ERRORS 9

   /** During decoding, the CBOR is not well-formed because a simple
       value between 0 and 31 is encoded in a two-byte integer rather
       than one. */
   QCBOR_ERR_BAD_TYPE_7 = 9,

   /** During decoding, returned by QCBORDecode_Finish() if all the
       inputs bytes have not been consumed. This is considered not
       well-formed. */
   QCBOR_ERR_EXTRA_BYTES = 10,

   /** During decoding, some CBOR construct was encountered that this
       decoder doesn't support, primarily this is the reserved
       additional info values, 28 through 30. The CBOR is not
       well-formed.*/
   QCBOR_ERR_UNSUPPORTED = 11,

   /** During decoding, the an array or map was not fully consumed.
       Returned by QCBORDecode_Finish(). The CBOR is not
       well-formed. */
   QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED = 12,

   /** During decoding, an integer type is encoded with a bad length
       (that of an indefinite length string). The CBOR is not-well
       formed. */
   QCBOR_ERR_BAD_INT = 13,

#define QCBOR_START_OF_UNRECOVERABLE_DECODE_ERRORS 14

   /** During decoding, one of the chunks in an indefinite-length
       string is not of the type of the start of the string.  The CBOR
       is not well-formed.  This error makes no further decoding
       possible. */
   QCBOR_ERR_INDEFINITE_STRING_CHUNK = 14,

   /** During decoding, hit the end of the given data to decode. For
       example, a byte string of 100 bytes was expected, but the end
       of the input was hit before finding those 100 bytes.  Corrupted
       CBOR input will often result in this error. See also @ref
       QCBOR_ERR_NO_MORE_ITEMS. The CBOR is not well-formed.  This
       error makes no further decoding possible. */
   QCBOR_ERR_HIT_END = 15,

   /** During decoding, a break occurred outside an indefinite-length
       item. The CBOR is not well-formed. This error makes no further
       decoding possible. */
   QCBOR_ERR_BAD_BREAK = 16,

#define QCBOR_END_OF_NOT_WELL_FORMED_ERRORS 16

   /** During decoding, the input is too large. It is greater than
       QCBOR_MAX_DECODE_INPUT_SIZE. This is an implementation limit.
       This error makes no further decoding possible. */
   QCBOR_ERR_INPUT_TOO_LARGE = 17,

   /** During decoding, the array or map nesting was deeper than this
       implementation can handle. Note that in the interest of code
       size and memory use, this implementation has a hard limit on
       array nesting. The limit is defined as the constant @ref
       QCBOR_MAX_ARRAY_NESTING. This error makes no further decoding
       possible. */
   QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP = 18,

   /** During decoding, the array or map had too many items in it.
       This limit @ref QCBOR_MAX_ITEMS_IN_ARRAY, typically 65,534,
       UINT16_MAX - 1. This error makes no further decoding
       possible. */
   QCBOR_ERR_ARRAY_DECODE_TOO_LONG = 19,

   /** When decoding, a string's size is greater than what a size_t
       can hold less 4. In all but some very strange situations this
       is because of corrupt input CBOR and should be treated as
       such. The strange situation is a CPU with a very small size_t
       (e.g., a 16-bit CPU) and a large string (e.g., > 65KB). This
       error makes no further decoding possible. */
   QCBOR_ERR_STRING_TOO_LONG = 20,

   /** Something is wrong with a decimal fraction or bigfloat such as
       it not consisting of an array with two integers. This error
       makes no further decoding possible. */
   QCBOR_ERR_BAD_EXP_AND_MANTISSA = 21,

   /** Unable to decode an indefinite-length string because no string
       allocator was configured. See QCBORDecode_SetMemPool() or
       QCBORDecode_SetUpAllocator().  This error makes no further
       decoding possible.*/
   QCBOR_ERR_NO_STRING_ALLOCATOR = 22,

   /** Error allocating space for a string, usually for an
       indefinite-length string. This error makes no further decoding
       possible. */
   QCBOR_ERR_STRING_ALLOCATE = 23,

#define QCBOR_END_OF_UNRECOVERABLE_DECODE_ERRORS 23

   /** More than @ref QCBOR_MAX_TAGS_PER_ITEM tags encounterd for a
       CBOR ITEM.  @ref QCBOR_MAX_TAGS_PER_ITEM is a limit of this
       implementation.  During decoding, too many tags in the
       caller-configured tag list, or not enough space in @ref
       QCBORTagListOut. This error makes no further decoding
       possible.  */
   QCBOR_ERR_TOO_MANY_TAGS = 24,

   /** During decoding, the type of the label for a map entry is not
       one that can be handled in the current decoding mode. Typically
       this is because a label is not an intger or a string. This is
       an implemation limit. */
   QCBOR_ERR_MAP_LABEL_TYPE = 25,

   /** When decodeing for a specific type, the type was not was
       expected.  */
   QCBOR_ERR_UNEXPECTED_TYPE = 26,

   /** This occurs when decoding one of the tags that QCBOR processed
       internally.  The content of a tag was of the wrong type. (They
       were known as "Optional Tags" in RFC 7049. */
   QCBOR_ERR_BAD_OPT_TAG = 27,

   /** Duplicate label in map detected */
   QCBOR_ERR_DUPLICATE_LABEL = 28,

   /** During decoding, the buffer given to QCBORDecode_SetMemPool()
       is either too small, smaller than
       QCBOR_DECODE_MIN_MEM_POOL_SIZE or too large, larger than
       UINT32_MAX. */
   QCBOR_ERR_MEM_POOL_SIZE = 29,

   /** During decoding, an integer smaller than INT64_MIN was received
       (CBOR can represent integers smaller than INT64_MIN, but C
       cannot). */
   QCBOR_ERR_INT_OVERFLOW = 30,

   /** During decoding, a date greater than +- 292 billion years from
       Jan 1 1970 encountered during parsing. This is an
       implementation limit. */
   QCBOR_ERR_DATE_OVERFLOW = 31,

   /** During decoding, @c QCBORDecode_ExitXxx() was called for a
       different type than @c QCBORDecode_EnterXxx(). */
   QCBOR_ERR_EXIT_MISMATCH = 32,

   /** All well-formed data items have been consumed and there are no
       more. If parsing a CBOR stream this indicates the non-error end
       of the stream. If parsing a CBOR stream / sequence, this
       probably indicates that some data items expected are not
       present.  See also @ref QCBOR_ERR_HIT_END. */
   QCBOR_ERR_NO_MORE_ITEMS = 33,

   /** When finding an item by lablel, an item with the requested label
       was not found. */
   QCBOR_ERR_LABEL_NOT_FOUND = 34,

   /** Number conversion failed because of sign. For example a
       negative int64_t can't be converted to a uint64_t */
   QCBOR_ERR_NUMBER_SIGN_CONVERSION = 35,

   /** When converting a decoded number, the value is too large or to
       small for the conversion target */
   QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW = 36,

   /** Trying to get an item by label when a map has not been
       entered. */
   QCBOR_ERR_MAP_NOT_ENTERED = 37,

   /** A callback indicates processing should not continue for some
       non-CBOR reason */
   QCBOR_ERR_CALLBACK_FAIL = 38,

   /** Decoding of floating-point epoch dates is unsupported and a
       floating-point date was encountered by the decoder. */
   QCBOR_ERR_FLOAT_DATE_DISABLED = 39,

   /** Support for half-precision float decoding is disabled. */
   QCBOR_ERR_HALF_PRECISION_DISABLED = 40,

   /** Use of floating-point HW is disabled. This affects all type
       conversions to and from double and float types. */
   QCBOR_ERR_HW_FLOAT_DISABLED = 41,

   /** Unable to complete operation because a floating-point value
       that is a NaN (not a number), that is too large, too small,
       infinity or -infinity was encountered in encoded CBOR. Usually
       this because conversion of the float-point value was being
       attempted. */
    QCBOR_ERR_FLOAT_EXCEPTION = 42,

   /* This is stored in uint8_t; never add values > 255 */
} QCBORError;


/* Function for getting an error string from an error code */
const char *qcbor_err_to_str(QCBORError err);



/**
 The maximum nesting of arrays and maps when encoding or decoding. The
 error @ref QCBOR_ERR_ARRAY_NESTING_TOO_DEEP will be returned on
 encoding or QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP on decoding if it is exceeded.
 */
#define QCBOR_MAX_ARRAY_NESTING  QCBOR_MAX_ARRAY_NESTING1


/**
 The maximum number of items in a single array or map when encoding of
 decoding.
 */
// -1 is because the value UINT16_MAX is used to track indefinite-length arrays
#define QCBOR_MAX_ITEMS_IN_ARRAY (UINT16_MAX-1)


/**
 This is deprecated. See QCBORDecode_GetNthTag() and QCBORDecode_GetNthTagOfLast()
 for tag handling.

 The maximum number of tags that can be in @ref QCBORTagListIn and passed to
 QCBORDecode_SetCallerConfiguredTagList()
 */
#define QCBOR_MAX_CUSTOM_TAGS    16


#endif /* qcbor_common_h */
