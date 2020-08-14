/*============================================================================
  qcbor_spiffy_decode.h -- higher-level easier-to-use CBOR decoding.

  Copyright (c) 2020, Laurence Lundblade. All rights reserved.

  SPDX-License-Identifier: BSD-3-Clause

  See BSD-3-Clause license in README.md

  Forked from qcbor_decode.h on 7/23/2020
  ============================================================================*/
#ifndef qcbor_spiffy_decode_h
#define qcbor_spiffy_decode_h


#include "qcbor/qcbor_decode.h"


#ifdef __cplusplus
extern "C" {
#if 0
} // Keep editor indention formatting happy
#endif
#endif


/**
 @file qcbor_spiffy_decode.h

 Q C B O R   S p i f f y   D e c o d e

 Spiffy decode is extra decode features over and above the basic
 decode features that generally are easier to use, mirror the encoding
 functions better and can result in smaller code size for larger and
 more complex CBOR protocols.  In particular, spiffy decode
 facilitates getting the next data item of a specific type, setting an
 error if it is not of that type. It facilitates explicitly entering
 and exiting arrays and maps. It facilates fetching items by label
 from a map including duplicate label detection.

 Encoded CBOR can be viewed to have a tree structure where the leaf
 nodes are non-aggregate types like integers and strings and the
 intermediate nodes are either arrays or maps. Fundamentally, all
 decoding is a pre-order traversal of the tree. Calling QCBORDecode_GetNext()
 repeatedly will perform this.

 This pre-order traversal gives natural decoding of arrays where the
 array members are taken in order, but does not give natural decoding
 of maps where access by label is usually preferred.  Using the
 QCBORDecode_EnterMap() and GetXxxInMapX methods, map items can be
 accessed by label. QCBORDecode_EnterMap() bounds decoding to a
 particular map. GetXxxInMap methods allows decoding the item of a
 particular label in the particular map. This can be used with nested
 maps by using QCBORDecode_EnterMapFromMapX().

 When QCBORDecode_EnterMap() is called, pre-order traversal continues
 to work. There is a cursor that is run over the tree with calls to
 QCBORDecode_GetNext(). This can be intermixed with calls to
 GetXxxInMapX. The pre-order traversal is limited just to the map
 entered. Attempts to QCBORDecode_GetNext() beyond the end of the map
 will give the @ref QCBOR_ERR_NO_MORE_ITEMS error.

 There is also QCBORDecode_EnterArray() to decode arrays. It will narrow the
 traversal to the extent of the array entered.

 GetXxxInMapX supports duplicate label detection and will result in an
 error if the map has duplicate labels.

 GetXxxInMap is implemented by performing the pre-order traversal of
 the map to find the labeled item everytime it is called. It doesn't
 build up a hash table, a binary search tree or some other efficiently
 searchable structure internally. For simple trees this is fine and
 for high-speed CPUs this is fine, but for complex trees on slow CPUs,
 it may have performance issues (these have not be quantified
 yet). One way ease this is to use QCBORDecode_GetItemsInMap() which
 allows decoding of a list of items expected in an map in one
 traveral.

 @anchor Decode-Errors
  TODO: internal error for GetNext()?

 Like encoding, decoding maintains an internal error state. Once a call
 to the decoder returns an error, this error state is entered and
 subsequent decoder calls do nothing. This allows for prettier and
 cleaner decoding code. In some cases the only error check that may be
 necessary is the return code from QCBORDecode_Finish().

 The internal error can be
 retrived with QCBORDecode_GetError(). Any further attempts to get
 specific data types will do nothing so it is safe for code to get
 many items without checking the error on each one as long as there is
 an error check before any data is used.  The error state is reset
 only by re initializing the decoder or
 QCBORDecode_GetErrorAndReset().  QCBORDecode_GetErrorAndReset() is
 mainly useful after a failure to get an item in a map by label.

 An easy and clean way to use this decoder is to always use EnterMap
 and EnterArray for each array or map. They will error if the input
 CBOR is not the expected array or map.  Then use GetInt, GetString to
 get the individual items of of the maps and arrays making use of the
 internal error tracking provided by this decoder. The only error
 check needed is the call to Finish.

 In some CBOR protocols, the type of a data item may be
 variable. Maybe even the type of one data item is dependent on
 another. In such designs, GetNext has to be used and the internal
 error checking can't be relied upon.

 Error reporting when searching maps is not accurate for
 some errors. They are report as not found rather
 than overflow and such.


 ----
  GetNext will always try to get something. The other Get functions
 will not try if there is an error.

 Make it a decode option for GetNext to not try? That way it is
 the same as all Get functions and can be used in the mix
 with them?

 GetNext is how you get things in an array you don't
 know the type of.

 ----

 @anchor Tag-Matcing

 Data types beyond the basic CBOR types of numbers, strings, maps and
 arrays can be defined and tagged. The main registry of these new
 types is in in the IANA registry. These new types may be simple such
 as indicating an number is actually a date, or they of moderate
 complexity such as defining a decimal fraction that is an array of
 several items, or they may be very complex such as format for signing
 and encryption.

 When these new types occur in a protocol they may be tagged to
 explicitly identify them or they may not be tagged, with there type
 being determined implicitly. A common means of implicit tagging is
 that the type of the value of a map entry is implied by the label of
 the map entry. For example a data item labeled "birth date" is always
 to be of type epoch date.

 The decoding functions for these new types takes a tag requirement
 parameter to say whether the tag must be present, must be absent or
 whether either is OK.

 If the parameter indicates the tag is required (@ref
 QCBOR_TAG_REQUIREMENT_MATCH_TAG), then
 @ref QCBOR_ERR_UNEXPECTED_TYPE
 is set if a tag with one of the expected values is absent. To decode
 correctly the contents of the tag must also be of the correct
 type. For example, to decode an epoch date the tag with value 1 must
 be resent and the content must be an integer or floating-point value.

 If the parameter indicates no tag is required (@ref
 QCBOR_TAG_REQUIREMENT_NO_TAG), then
 @ref QCBOR_ERR_UNEXPECTED_TYPE is
 set if type of the content is not what is expected. In the example of
 an epoch date, the data type must be an integer or floating-point
 value. The tag value of 1 must not be present.

 If the parameter indicated either the tags presence or absence is OK
 ( @ref QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG ), then the data item(s)
 will be decoded as long as they are of the correct type whether there
 is a tag or not.  Use of this option is however highly
 discouraged. It is a violation of the CBOR specification for tags to
 be optional this way. A CBOR protocol must say whether a tag is
 always to be present or always to be absent. (A protocol might say
 that tags are never used or always used in a general statement, or
 might say it on an item-by-item basis).
*/


/** Conversion will proceed if the CBOR item to be decoded is an
    integer or either type 0 (unsigned) or type 1 (negative). */
#define QCBOR_CONVERT_TYPE_XINT64           0x01
/** Conversion will proceed if the CBOR item to be decoded is either
    double, single or half-precision floating-point (major type 7). */
#define QCBOR_CONVERT_TYPE_FLOAT            0x02
/** Conversion will proceed if the CBOR item to be decoded is a big
    number, positive or negative (tag 2 or tag 3). */
#define QCBOR_CONVERT_TYPE_BIG_NUM          0x04
/** Conversion will proceed if the CBOR item to be decoded is a
    decimal fraction (tag 4). */
#define QCBOR_CONVERT_TYPE_DECIMAL_FRACTION 0x08
/** Conversion will proceed if the CBOR item to be decoded is a big
    float (tag 5). */
#define QCBOR_CONVERT_TYPE_BIGFLOAT         0x10


/** The data item must have the correct tag data type being
    fetched. It is an error if it does not. For example, an epoch date
    must have tag 1. */
#define QCBOR_TAG_REQUIREMENT_MATCH_TAG     0
/** The data item must be of the type expected for content data type
    being fetched. It is an error if it does. For example, an epoch
    date must be either an integer or a floating-point number. */
#define QCBOR_TAG_REQUIREMENT_NO_TAG        1
/** Either of the above two are allowed. This is highly discourged by
    the CBOR specification. One of the above to should be used
    instead. */
#define QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG  2


/**
 @brief Decode next item into a signed 64-bit integer.

 @param[in] pCtx   The decode context.
 @param[out] pnValue  The returned 64-bit signed integer.

 The CBOR data item to decode must be a positive or negative integer
 (CBOR major type 0 or 1). If not @ref QCBOR_ERR_UNEXPECTED_TYPE is set.

 If the CBOR integer is either too large or too small to fit in an
 int64_t, the error @ref QCBOR_ERR_INT_OVERFLOW or @ref
 QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW is set.  Note that type 0
 unsigned integers can be larger than will fit in an int64_t and type
 1 negative integers can be smaller than will fit in an int64_t.

 See @ref Decode-Errors for discussion on how error handling works.

 See also QCBORDecode_GetUInt64(), QCBORDecode_GetInt64Convert() and
 QCBORDecode_GetInt64ConvertAll().
 */
static void QCBORDecode_GetInt64(QCBORDecodeContext *pCtx,
                                 int64_t            *pnValue);

static void QCBORDecode_GetInt64InMapN(QCBORDecodeContext *pCtx,
                                       int64_t             nLabel,
                                       int64_t            *pnValue);

static void QCBORDecode_GetInt64InMapSZ(QCBORDecodeContext *pCtx,
                                        const char         *szLabel,
                                        int64_t            *pnValue);


/**
 @brief Decode next item into a signed 64-bit integer with basic conversions.

 @param[in] pCtx   The decode context.
 @param[in] uConvertTypes The integer conversion options.
 @param[out] pnValue  The returned 64-bit signed integer.

 @c uConvertTypes controls what conversions this will perform and thus
 what CBOR types will be decoded.  @c uConvertType is a bit map
 listing the conversions to be allowed. This function supports @ref
 QCBOR_CONVERT_TYPE_XINT64 and @ref QCBOR_CONVERT_TYPE_FLOAT
 conversions.

 See @ref Decode-Errors for discussion on how error handling works.

 If the CBOR data type can never be convered by this function or the
 conversion was not selected in @c uConversionTypes @ref
 @ref QCBOR_ERR_UNEXPECTED_TYPE is set.

 When converting floating-point values, the integer is rounded to the
 nearest integer using llround(). By default, floating-point suport is
 enabled for QCBOR.

 If floating-point HW use is disabled this will set
 @ref QCBOR_ERR_HW_FLOAT_DISABLED if a single-precision
 number is encountered. If half-precision support is disabled,
 this will set QCBOR_ERR_HALF_PRECISION_DISABLED if
 a half-precision number is encountered.

 See also QCBORDecode_GetInt64ConvertAll() which will perform the same
 conversions as this and a lot more at the cost of adding more object
 code to your executable.
 */
static void QCBORDecode_GetInt64Convert(QCBORDecodeContext *pCtx,
                                        uint32_t            uConvertTypes,
                                        int64_t            *pnValue);

static void QCBORDecode_GetInt64ConvertInMapN(QCBORDecodeContext *pCtx,
                                              int64_t             nLabel,
                                              uint32_t            uConvertTypes,
                                              int64_t            *pnValue);

static void QCBORDecode_GetInt64ConvertInMapSZ(QCBORDecodeContext *pCtx,
                                               const char         *szLabel,
                                               uint32_t            uConvertTypes,
                                               int64_t            *pnValue);


/**
 @brief Decode next item into a signed 64-bit integer with conversions.

 @param[in] pCtx   The decode context.
 @param[in] uConvertTypes The integer conversion options.
 @param[out] pnValue  The returned 64-bit signed integer.

 This is the same as QCBORDecode_GetInt64Convert() but additionally
 supports conversion from positive and negative bignums, decimal
 fractions and big floats, including decimal fractions and big floats
 that use bignums. The conversion types supported are @ref
 QCBOR_CONVERT_TYPE_XINT64, @ref QCBOR_CONVERT_TYPE_FLOAT, @ref
 QCBOR_CONVERT_TYPE_BIG_NUM, @ref QCBOR_CONVERT_TYPE_DECIMAL_FRACTION
 and @ref QCBOR_CONVERT_TYPE_BIGFLOAT.

 See @ref Decode-Errors for discussion on how error handling works.

 Note that most these types can support numbers much larger that can
 be represented by in a 64-bit integer, so @ref @ref
 QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW may often be encountered.

 When converting bignums and decimal fractions @ref
 QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW will be set if the result is
 below 1, unless the mantissa is zero, in which case the coversion is
 successful and the value of 0 is returned. TODO: is this right?

 See also QCBORDecode_GetInt64ConvertAll() which does some of these
 conversions, but links in much less object code. See also
 QCBORDecode_GetUInt64ConvertAll().
 */
void QCBORDecode_GetInt64ConvertAll(QCBORDecodeContext *pCtx,
                                    uint32_t            uConvertTypes,
                                    int64_t            *pnValue);

void QCBORDecode_GetInt64ConvertAllInMapN(QCBORDecodeContext *pCtx,
                                          int64_t             nLabel,
                                          uint32_t            uConvertTypes,
                                          int64_t            *pnValue);

void QCBORDecode_GetInt64ConvertAllInMapSZ(QCBORDecodeContext *pCtx,
                                           const char         *szLabel,
                                           uint32_t            uConvertTypes,
                                           int64_t            *pnValue);


/**
 @brief Decode next item into an unsigned 64-bit integer.

 @param[in] pCtx   The decode context.
 @param[out] puValue  The returned 64-bit unsigned integer.

 This is the same as QCBORDecode_GetInt64(), but returns an unsigned integer
 and thus can only decode CBOR positive integers.
 @ref QCBOR_ERR_NUMBER_SIGN_CONVERSION is set if the input is a negative
 integer.

 See @ref Decode-Errors for discussion on how error handling works.

 See also QCBORDecode_GetUInt64Convert() and QCBORDecode_GetUInt64ConvertAll().
*/
static void QCBORDecode_GetUInt64(QCBORDecodeContext *pCtx,
                                  uint64_t           *puValue);

static void QCBORDecode_GetUInt64InMapN(QCBORDecodeContext *pCtx,
                                        int64_t             nLabel,
                                        uint64_t           *puValue);

static void QCBORDecode_GetUInt64InMapSZ(QCBORDecodeContext *pCtx,
                                         const char         *szLabel,
                                         uint64_t           *puValue);


/**
 @brief Decode next item as an unsigned 64-bit integer with basic conversions.

 @param[in] pCtx   The decode context.
 @param[in] uConvertTypes The integer conversion options.
 @param[out] puValue  The returned 64-bit unsigned integer.

 This is the same as QCBORDecode_GetInt64Convert(), but returns an
 unsigned integer and thus sets @ref QCBOR_ERR_NUMBER_SIGN_CONVERSION
 is set if the value to be decoded is negatve.

 If floating-point HW use is disabled this will set
 @ref QCBOR_ERR_HW_FLOAT_DISABLED if a single-precision
 number is encountered. If half-precision support is disabled,
 this will set QCBOR_ERR_HALF_PRECISION_DISABLED if
 a half-precision number is encountered.

 See also QCBORDecode_GetUInt64Convert() and
 QCBORDecode_GetUInt64ConvertAll().
*/
static void QCBORDecode_GetUInt64Convert(QCBORDecodeContext *pCtx,
                                         uint32_t            uConvertTypes,
                                         uint64_t           *puValue);

static void QCBORDecode_GetUInt64ConvertInMapN(QCBORDecodeContext *pCtx,
                                               int64_t             nLabel,
                                               uint32_t            uConvertTypes,
                                               uint64_t           *puValue);

static void QCBORDecode_GetUInt64ConvertInMapSZ(QCBORDecodeContext *pCtx,
                                                const char         *szLabel,
                                                uint32_t            uConvertTypes,
                                                uint64_t           *puValue);


/**
 @brief Decode next item into an unsigned 64-bit integer with conversions

 @param[in] pCtx   The decode context.
 @param[in] uConvertTypes The integer conversion options.
 @param[out] puValue  The returned 64-bit unsigned integer.

 This is the same as QCBORDecode_GetInt64ConvertAll(), but returns an
 unsigned integer and thus sets @ref QCBOR_ERR_NUMBER_SIGN_CONVERSION
 if the value to be decoded is negatve.

 See also QCBORDecode_GetUInt64() and
 QCBORDecode_GetUInt64Convert().
*/
void QCBORDecode_GetUInt64ConvertAll(QCBORDecodeContext *pCtx,
                                     uint32_t           uConvertTypes,
                                     uint64_t          *puValue);

void QCBORDecode_GetUInt64ConvertAllInMapN(QCBORDecodeContext *pCtx,
                                           int64_t             nLabel,
                                           uint32_t            uConvertTypes,
                                           uint64_t           *puValue);

void QCBORDecode_GetUInt64ConvertAllInMapSZ(QCBORDecodeContext *pCtx,
                                            const char         *szLabel,
                                            uint32_t            uConvertTypes,
                                            uint64_t           *puValue);


/**
 @brief Decode next item into a double floating-point value.

 @param[in] pCtx   The decode context
 @param[out] pValue  The returned floating-point value.

 The CBOR data item to decode must be a hafl-precision,
 single-precision or double-precision floating-point value.  If not
 @ref QCBOR_ERR_UNEXPECTED_TYPE is set.

 If floating-point HW use is disabled this will set
 @ref QCBOR_ERR_HW_FLOAT_DISABLED if a single-precision
 number is encountered. If half-precision support is disabled,
 this will set QCBOR_ERR_HALF_PRECISION_DISABLED if
 a half-precision number is encountered.

 See @ref Decode-Errors for discussion on how error handling works.

 See also QCBORDecode_GetDoubleConvert() and
 QCBORDecode_GetDoubleConvertAll().
*/
static void QCBORDecode_GetDouble(QCBORDecodeContext *pCtx,
                                  double             *pValue);

static void QCBORDecode_GetDoubleInMapN(QCBORDecodeContext *pCtx,
                                        int64_t             nLabel,
                                        double             *pdValue);

static void QCBORDecode_GetDoubleInMapSZ(QCBORDecodeContext *pCtx,
                                         const char         *szLabel,
                                         double             *pdValue);


/**
 @brief Decode next item into a double floating-point value with basic conversion.

 @param[in] pCtx   The decode context.
 @param[in] uConvertTypes The integer conversion options.
 @param[out] pdValue  The returned floating-point value.

 This will decode CBOR integer and floating-point numbers, returning
 them as a double floating-point number. This function supports @ref
 QCBOR_CONVERT_TYPE_XINT64 and @ref QCBOR_CONVERT_TYPE_FLOAT
 conversions. If the CBOR is not one of the requested types or a type
 not supported by this function, @ref QCBOR_ERR_UNEXPECTED_TYPE is
 set.

 See @ref Decode-Errors for discussion on how error handling works.

 If floating-point HW use is disabled this will set
 @ref QCBOR_ERR_HW_FLOAT_DISABLED if a single-precision
 number is encountered. If half-precision support is disabled,
 this will set QCBOR_ERR_HALF_PRECISION_DISABLED if
 a half-precision number is encountered.

 Positive and negative integers can always be converted to
 floating-point, so this will never error on type 0 or 1 CBOR.

 Note that a large 64-bit integer can have more precision (64 bits)
 than even a double floating-point (52 bits) value, so there is loss
 of precision in some conversions.

 See also QCBORDecode_GetDouble() and QCBORDecode_GetDoubleConvertAll().
*/
static void QCBORDecode_GetDoubleConvert(QCBORDecodeContext *pCtx,
                                         uint32_t            uConvertTypes,
                                         double             *pdValue);

static void QCBORDecode_GetDoubleConvertInMapN(QCBORDecodeContext *pCtx,
                                               int64_t            nLabel,
                                               uint32_t           uConvertTypes,
                                               double            *pdValue);

static void QCBORDecode_GetDoubleConvertInMapSZ(QCBORDecodeContext *pCtx,
                                                const char         *szLabel,
                                                uint32_t            uConvertTypes,
                                                double             *pdValue);


/**
 @brief Decode next item as a double floating-point value with conversion.

 @param[in] pCtx   The decode context.
 @param[in] uConvertTypes The integer conversion options.
 @param[out] pdValue  The returned floating-point value.

 This is the same as QCBORDecode_GetDoubleConvert() but supports many
 more conversions at the cost of linking in more object code. The
 conversion types supported are @ref QCBOR_CONVERT_TYPE_XINT64, @ref
 QCBOR_CONVERT_TYPE_FLOAT, @ref QCBOR_CONVERT_TYPE_BIG_NUM, @ref
 QCBOR_CONVERT_TYPE_DECIMAL_FRACTION and @ref
 QCBOR_CONVERT_TYPE_BIGFLOAT.

 Big numbers, decimal fractions and big floats that are too small or
 too large to be reprented as a souble floating-point number will be
 returned as plus or minus zero or infinity. There is also often loss
 of precision in the conversion.

 See also QCBORDecode_GetDoubleConvert() and QCBORDecode_GetDoubleConvert().
*/
void QCBORDecode_GetDoubleConvertAll(QCBORDecodeContext *pCtx,
                                     uint32_t            uConvertTypes,
                                     double             *pdValue);

void QCBORDecode_GetDoubleConvertAllInMapN(QCBORDecodeContext *pCtx,
                                           int64_t             nLabel,
                                           uint32_t            uConvertTypes,
                                           double             *pdValue);

void QCBORDecode_GetDoubleConvertAllInMapSZ(QCBORDecodeContext *pCtx,
                                            const char         *szLabel,
                                            uint32_t            uConvertTypes,
                                            double             *pdValue);




/**
 @brief Decode the next item as a byte string

 @param[in] pCtx   The decode context
 @param[out] pBytes  The decoded byte string

 The CBOR item to decode must be a byte string, CBOR type 2.

 See @ref Decode-Errors for discussion on how error handling works.

 If the CBOR tem to decode is not a byte string, the @ref
 QCBOR_ERR_UNEXPECTED_TYPE error is set.
 */
static void QCBORDecode_GetBytes(QCBORDecodeContext *pCtx, UsefulBufC *pBytes);

static void QCBORDecode_GetBytesInMapN(QCBORDecodeContext *pCtx,
                                       int64_t             nLabel,
                                       UsefulBufC         *pBytes);

static void QCBORDecode_GetBytesInMapSZ(QCBORDecodeContext *pCtx,
                                        const char         *szLabel,
                                        UsefulBufC         *pBytes);


/**
 @brief Decode the next item as a text string.

 @param[in] pCtx   The decode context.
 @param[out] pText  The decoded byte string.

 The CBOR item to decode must be a text string, CBOR type 3.

 See @ref Decode-Errors for discussion on how error handling works.  It the CBOR item
 to decode is not a text string, the @ref QCBOR_ERR_UNEXPECTED_TYPE
 error is set.
*/
static void QCBORDecode_GetText(QCBORDecodeContext *pCtx, UsefulBufC *pText);

static void QCBORDecode_GetTextInMapN(QCBORDecodeContext *pCtx,
                                      int64_t             nLabel,
                                      UsefulBufC         *pText);

static void QCBORDecode_GetTextInMapSZ(QCBORDecodeContext *pCtx,
                                       const char         *szLabel,
                                       UsefulBufC         *pText);




/**
 @brief Decode the next item as a Boolean.

 @param[in] pCtx   The decode context.
 @param[out] pbBool  The decoded byte string.

 The CBOR item to decode must be either the CBOR simple value (CBOR
 type 7) @c true or @c false.

 See @ref Decode-Errors for discussion on how error handling works.  It
 the CBOR item to decode is not true or false the @ref
 QCBOR_ERR_UNEXPECTED_TYPE error is set.
*/
void QCBORDecode_GetBool(QCBORDecodeContext *pCtx, bool *pbBool);

void QCBORDecode_GetBoolInMapN(QCBORDecodeContext *pCtx,
                               int64_t             nLabel,
                               bool               *pbBool);

void QCBORDecode_GetBoolInMapSZ(QCBORDecodeContext *pCtx,
                                const char         *szLabel,
                                bool               *pbBool);




/**
 @brief Decode the next item as a date string.

 @param[in] pCtx             The decode context.
 @param[in] uTagRequirement  One of @c QCBOR_TAGSPEC_MATCH_XXX.
 @param[out] pDateString            The decoded URI.

 See @ref Decode-Errors for discussion on how error handling works.

 See @ref Tag-Matcing for discussion on tag requirements.
*/
static void QCBORDecode_GetDateString(QCBORDecodeContext *pCtx,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC         *pDateString);

static void QCBORDecode_GetDateStringInMapN(QCBORDecodeContext *pCtx,
                                            int64_t             nLabel,
                                            uint8_t             uTagRequired,
                                            UsefulBufC         *pDateString);

static void QCBORDecode_GetDateStringInMapSZ(QCBORDecodeContext *pCtx,
                                             const char         *szLabel,
                                             uint8_t             uTagRequired,
                                             UsefulBufC         *pDateString);



/**
 @brief Decode the next item as an epoch date.

 @param[in] pCtx             The decode context.
 @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 @param[out] pnTime            The decoded epoch date.

 This will handle floating-point dates, but always returns them as an @c int64_t
 discarding the fractional part. Use QCBORDecode_GetNext() instead of this to get the
 fractional part.

 Floating-point dates that are plus infinity, minus infinity or NaN (not-a-number) will
 result in the @ref QCBOR_ERR_DATE_OVERFLOW error. If the QCBOR library
 is compiled with floating-point disabled, @ref QCBOR_ERR_HW_FLOAT_DISABLED
 is set. If compiled with preferred float disabled, half-precision dates will result
 in the @ref QCBOR_ERR_HALF_PRECISION_DISABLED error.

 See @ref Decode-Errors for discussion on how error handling works.

 See @ref Tag-Matcing for discussion on tag requirements.

 See also QCBOREncode_AddDateEpoch() and @ref QCBORItem.
*/
void QCBORDecode_GetEpochDate(QCBORDecodeContext *pCtx,
                             uint8_t              uTagRequirement,
                             int64_t             *pnTime);

void QCBORDecode_GetEpochDateInMapN(QCBORDecodeContext *pCtx,
                                    int64_t             nLabel,
                                    uint8_t             uTagRequirement,
                                    int64_t            *pnTime);

void QCBORDecode_GetEpochDateInMapSZ(QCBORDecodeContext *pCtx,
                                     const char         *szLabel,
                                     uint8_t             uTagRequirement,
                                     int64_t            *pnTime);


/**
 @brief Decode the next item as a big number.

 @param[in] pCtx             The decode context.
 @param[in] uTagRequirement  One of @c QCBOR_TAGSPEC_MATCH_XXX.
 @param[out] pValue          The returned big number.
 @param[out] pbIsNegative    Is @c true if the big number is negative. This
                             is only valid when @c uTagRequirement is
                             @ref QCBOR_TAG_REQUIREMENT_MATCH_TAG.

 See @ref Decode-Errors for discussion on how error handling works.

 The big number is in network byte order. The first byte in @c pValue
 is the most significant byte. There may be leading zeros.

 The negative value is computed as -1 - n, where n is the postive big
 number in @C pValue.

 See @ref Tag-Matcing for discussion on tag requirements.

 Determination of the sign of the big number depends on the tag
 requirement of the protocol using the big number. If the protocol
 requires tagging, @ref QCBOR_TAG_REQUIREMENT_MATCH_TAG, then the sign
 indication is in the protocol and @c pbIsNegative indicates the
 sign. If the protocol prohibits tagging, @ref
 QCBOR_TAG_REQUIREMENT_NO_TAG, then the protocol design must have some
 way of indicating the sign.

 See also QCBORDecode_GetInt64ConvertAll(),
 QCBORDecode_GetUInt64ConvertAll() and
 QCBORDecode_GetDoubleConvertAll() which can convert big numbers.
*/
// Improvement: Add function that at least convert integers to big nums
void QCBORDecode_GetBignum(QCBORDecodeContext *pCtx,
                           uint8_t             uTagRequirement,
                           UsefulBufC         *pValue,
                           bool               *pbIsNegative);

void QCBORDecode_GetBignumInMapN(QCBORDecodeContext *pCtx,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC         *pValue,
                                 bool               *pbIsNegative);

void QCBORDecode_GetBignumInMapSZ(QCBORDecodeContext *pCtx,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  UsefulBufC         *pValue,
                                  bool               *pbIsNegative);


#ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
/**
 @brief Decode the next item as a decimal fraction.

 @param[in] pCtx             The decode context.
 @param[in] uTagRequirement  One of @c QCBOR_TAGSPEC_MATCH_XXX.
 @param[out] pnMantissa      The mantissa.
 @param[out] pnExponent      The base 10 exponent.

 See @ref Decode-Errors for discussion on how error handling works.

 The  value of this is computed by:

     mantissa * ( 10 ** exponent )

 In the encoded CBOR, the mantissa and exponent may be of CBOR type 0
 (positive integer), type 1 (negative integer), type 2 tag 2 (positive
 big number) or type 2 tag 3 (negative big number). This
 implementation will attempt to convert all of these to an @c
 int64_t. If the value won't fit, @ref
 QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW or
 QCBOR_ERR_BAD_EXP_AND_MANTISSA will be set.

 This implementation limits the exponent to between @c INT64_MIN and
 @c INT64_MAX while CBOR allows the range of @c -UINT64_MAX to
 @c UINT64_MAX.

 Various format and type issues will result in @ref
 QCBOR_ERR_BAD_EXP_AND_MANTISSA being set.

 See @ref Tag-Matcing for discussion on tag requirements.

 See also QCBORDecode_GetInt64ConvertAll(),
 QCBORDecode_GetUInt64ConvertAll() and
 QCBORDecode_GetDoubleConvertAll() which can convert big numbers.
*/
void QCBORDecode_GetDecimalFraction(QCBORDecodeContext *pCtx,
                                    uint8_t             uTagRequirement,
                                    int64_t            *pnMantissa,
                                    int64_t            *pnExponent);

void QCBORDecode_GetDecimalFractionInMapN(QCBORDecodeContext *pCtx,
                                          int64_t             nLabel,
                                          uint8_t             uTagRequirement,
                                          int64_t            *pnMantissa,
                                          int64_t            *pnExponent);

void QCBORDecode_GetDecimalFractionInMapSZ(QCBORDecodeContext *pMe,
                                           const char         *szLabel,
                                           uint8_t             uTagRequirement,
                                           int64_t            *pnMantissa,
                                           int64_t            *pnExponent);


/**
 @brief Decode the next item as a decimal fraction with a big number mantissa.

 @param[in] pCtx             The decode context.
 @param[in] uTagRequirement  One of @c QCBOR_TAGSPEC_MATCH_XXX.
 @param[in] MantissaBuffer The buffer in which to put the mantissa.
 @param[out] pMantissa      The big num mantissa.
 @param[out] pbMantissaIsNegative  Is @c true if @c pMantissa is negative.
 @param[out] pnExponent      The base 10 exponent.

 This is the same as QCBORDecode_GetDecimalFraction() except the
 mantissa is returned as a big number.

 In the encoded CBOR, the mantissa may be a type 0 (positive integer),
 type 1 (negative integer), type 2 tag 2 (positive big number) or type
 2 tag 3 (negative big number). This implementation will convert all
 these to a big number. The limit to this conversion is the size of @c
 MantissaBuffer.

 See also QCBORDecode_GetInt64ConvertAll(),
 QCBORDecode_GetUInt64ConvertAll() and
 QCBORDecode_GetDoubleConvertAll() which can convert decimal
 fractions.
*/
void QCBORDecode_GetDecimalFractionBig(QCBORDecodeContext *pCtx,
                                       uint8_t             uTagRequirement,
                                       UsefulBuf           MantissaBuffer,
                                       UsefulBufC         *pMantissa,
                                       bool               *pbMantissaIsNegative,
                                       int64_t            *pnExponent);

void QCBORDecode_GetDecimalFractionBigInMapN(QCBORDecodeContext *pCtx,
                                             int64_t             nLabel,
                                             uint8_t             uTagRequirement,
                                             UsefulBuf           MantissaBuffer,
                                             UsefulBufC         *pbMantissaIsNegative,
                                             bool               *pbIsNegative,
                                             int64_t            *pnExponent);

void QCBORDecode_GetDecimalFractionBigInMapSZ(QCBORDecodeContext *pCtx,
                                              const char         *szLabel,
                                              uint8_t             uTagRequirement,
                                              UsefulBuf           MantissaBuffer,
                                              UsefulBufC         *pMantissa,
                                              bool               *pbMantissaIsNegative,
                                              int64_t            *pnExponent);


/**
 @brief Decode the next item as a big float.

 @param[in] pCtx             The decode context.
 @param[in] uTagRequirement  One of @c QCBOR_TAGSPEC_MATCH_XXX.
 @param[out] pnMantissa      The mantissa.
 @param[out] pnExponent      The base 2 exponent.

 This is the same as QCBORDecode_GetDecimalFraction() with the
 important distinction that the value is computed by:

     mantissa * ( 2 ** exponent )

 See also QCBORDecode_GetInt64ConvertAll(),
 QCBORDecode_GetUInt64ConvertAll() and
 QCBORDecode_GetDoubleConvertAll() which can convert big floats.
 */
void QCBORDecode_GetBigFloat(QCBORDecodeContext *pCtx,
                             uint8_t             uTagRequirement,
                             int64_t            *pnMantissa,
                             int64_t            *pnExponent);

void QCBORDecode_GetBigFloatInMapN(QCBORDecodeContext *pCtx,
                                   int64_t             nLabel,
                                   uint8_t             uTagRequirement,
                                   int64_t            *pnMantissa,
                                   int64_t            *pnExponent);

void QCBORDecode_GetBigFloatInMapSZ(QCBORDecodeContext *pCtx,
                                    const char         *szLabel,
                                    uint8_t             uTagRequirement,
                                    int64_t            *pnMantissa,
                                    int64_t            *pnExponent);


/**
 @brief Decode the next item as a big float with a big number mantissa.

 @param[in] pCtx             The decode context.
 @param[in] uTagRequirement  One of @c QCBOR_TAGSPEC_MATCH_XXX.
 @param[in] MantissaBuffer The buffer in which to put the mantissa.
 @param[out] pMantissa      The big num mantissa.
 @param[out] pbMantissaIsNegative  Is @c true if @c pMantissa is negative.
 @param[out] pnExponent      The base 2 exponent.

 This is the same as QCBORDecode_GetDecimalFractionBig() with the
 important distinction that the value is computed by:

     mantissa * ( 2 ** exponent )

 See also QCBORDecode_GetInt64ConvertAll(),
 QCBORDecode_GetUInt64ConvertAll() and
 QCBORDecode_GetDoubleConvertAll() which can convert big floats.
 */
void QCBORDecode_GetBigFloatBig(QCBORDecodeContext *pCtx,
                                uint8_t             uTagRequirement,
                                UsefulBuf           MantissaBuffer,
                                UsefulBufC         *pMantissa,
                                bool               *pbMantissaIsNegative,
                                int64_t            *pnExponent);

void QCBORDecode_GetBigFloatBigInMapN(QCBORDecodeContext *pCtx,
                                      int64_t             nLabel,
                                      uint8_t             uTagRequirement,
                                      UsefulBuf           MantissaBuffer,
                                      UsefulBufC         *pMantissa,
                                      bool               *pbMantissaIsNegative,
                                      int64_t            *pnExponent);

void QCBORDecode_GetBigFloatBigInMapSZ(QCBORDecodeContext *pCtx,
                                       const char         *szLabel,
                                       uint8_t             uTagRequirement,
                                       UsefulBuf           MantissaBuffer,
                                       UsefulBufC         *pMantissa,
                                       bool               *pbMantissaIsNegative,
                                       int64_t            *pnExponent);
#endif /* #ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA */


/**
 @brief Decode the next item as a URI.

 @param[in] pCtx             The decode context.
 @param[in] uTagRequirement  One of @c QCBOR_TAGSPEC_MATCH_XXX.
 @param[out] pURI            The decoded URI.

 See @ref Decode-Errors for discussion on how error handling works.

 See @ref Tag-Matcing for discussion on tag requirements.
 */
static void QCBORDecode_GetURI(QCBORDecodeContext *pCtx,
                               uint8_t             uTagRequirement,
                               UsefulBufC         *pURI);

static void QCBORDecode_GetURIInMapN(QCBORDecodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint8_t             uTagRequirement,
                                     UsefulBufC         *pURI);

static void QCBORDecode_GetURIInMapSZ(QCBORDecodeContext *pCtx,
                                      const char *        szLabel,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC         *pURI);


/**
 @brief Decode the next item as base64 encoded text.

 @param[in] pCtx             The decode context.
 @param[in] uTagRequirement  One of @c QCBOR_TAGSPEC_MATCH_XXX.
 @param[out] pB64Text          The decoded base64 text.

 See @ref Decode-Errors for discussion on how error handling works.

 See @ref Tag-Matcing for discussion on tag requirements.

 Note that this doesn not actually remove the base64 encoding.
*/
static void QCBORDecode_GetB64(QCBORDecodeContext *pCtx,
                               uint8_t             uTagRequirement,
                               UsefulBufC         *pB64Text);

static void QCBORDecode_GetB64InMapN(QCBORDecodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint8_t             uTagRequirement,
                                     UsefulBufC         *pB64Text);

static void QCBORDecode_GetB64InMapSZ(QCBORDecodeContext *pCtx,
                                      const char         *szLabel,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC         *pB64Text);

/**
 @brief Decode the next item as base64URL encoded text.

 @param[in] pCtx             The decode context.
 @param[in] uTagRequirement  One of @c QCBOR_TAGSPEC_MATCH_XXX.
 @param[out] pB64Text          The decoded base64 text.

 See @ref Decode-Errors for discussion on how error handling works.

 See @ref Tag-Matcing for discussion on tag requirements.

 Note that this doesn not actually remove the base64 encoding.
*/
static void QCBORDecode_GetB64URL(QCBORDecodeContext *pCtx,
                                  uint8_t             uTagRequirement,
                                  UsefulBufC         *pB64Text);

static void QCBORDecode_GetB64URLInMapN(QCBORDecodeContext *pCtx,
                                        int64_t             nLabel,
                                        uint8_t             uTagRequirement,
                                        UsefulBufC         *pB64Text);

static void QCBORDecode_GetB64URLInMapSZ(QCBORDecodeContext *pCtx,
                                         const char         *szLabel,
                                         uint8_t             uTagRequirement,
                                         UsefulBufC         *pB64Text);

/**
 @brief Decode the next item as a regular expression.

 @param[in] pCtx             The decode context.
 @param[in] uTagRequirement  One of @c QCBOR_TAGSPEC_MATCH_XXX.
 @param[out] pRegex          The decoded regular expression.

 See @ref Decode-Errors for discussion on how error handling works.

 See @ref Tag-Matcing for discussion on tag requirements.
 */
static void QCBORDecode_GetRegex(QCBORDecodeContext *pCtx,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC         *pRegex);

static void QCBORDecode_GetRegexInMapN(QCBORDecodeContext *pCtx,
                                       int64_t             nLabel,
                                       uint8_t             uTagRequirement,
                                       UsefulBufC         *pRegex);

static void QCBORDecode_GetRegexInMapSZ(QCBORDecodeContext *pCtx,
                                        const char *        szLabel,
                                        uint8_t             uTagRequirement,
                                        UsefulBufC         *pRegex);


/**
 @brief Decode the next item as a MIME message

 @param[in] pCtx             The decode context.
 @param[in] uTagRequirement  One of @c QCBOR_TAGSPEC_MATCH_XXX.
 @param[out] pMessage        The decoded regular expression.
 @param[out] pbIsNot7Bit     @c true if MIME is binary or 8-bit.

 See @ref Decode-Errors for discussion on how error handling works.

 See @ref Tag-Matcing for discussion on tag requirements.

 The MIME message itself is not parsed.

 This decodes both tag 36 and 257. If it is tag 257, pbIsNot7Bit
 is @c true. While it is clear that tag 36 can't contain,
 binary or 8-bit MIME, it is probably legal for tag 257
 to contain 7-bit MIME. Hopefully in most uses the
 Content-Transfer-Encoding header is present and the
 contents of pbIsNot7Bit can be ignored. It may be NULL.
*/
static void QCBORDecode_GetMIMEMessage(QCBORDecodeContext *pCtx,
                                       uint8_t             uTagRequirement,
                                       UsefulBufC         *pMessage,
                                       bool               *pbIsNot7Bit);

static void QCBORDecode_GetMIMEMessageInMapN(QCBORDecodeContext *pCtx,
                                            int64_t              nLabel,
                                            uint8_t              uTagRequirement,
                                            UsefulBufC          *pMessage,
                                            bool                *pbIsNot7Bit);


static void QCBORDecode_GetMIMEMessageInMapSZ(QCBORDecodeContext *pCtx,
                                              const char         *szLabel,
                                              uint8_t             uTagRequirement,
                                              UsefulBufC         *pMessage,
                                              bool               *pbIsNot7Bit);

/**
 @brief Decode the next item as a UUID

 @param[in] pCtx             The decode context.
 @param[in] uTagRequirement  One of @c QCBOR_TAGSPEC_MATCH_XXX.
 @param[out] pUUID            The decoded UUID

 See @ref Decode-Errors for discussion on how error handling works.

 See @ref Tag-Matcing for discussion on tag requirements.
 */
static inline void QCBORDecode_GetBinaryUUID(QCBORDecodeContext *pCtx,
                                             uint8_t             uTagRequirement,
                                             UsefulBufC         *pUUID);

inline static void QCBORDecode_GetBinaryUUIDInMapN(QCBORDecodeContext *pCtx,
                                                   int64_t             nLabel,
                                                   uint8_t             uTagRequirement,
                                                   UsefulBufC         *pUUID);

inline static void QCBORDecode_GetBinaryUUIDInMapSZ(QCBORDecodeContext *pCtx,
                                                    const char         *szLabel,
                                                    uint8_t             uTagRequirement,
                                                    UsefulBufC         *pUUID);



/**
 @brief Enter a map for decoding and searching.

 @param[in] pCtx   The decode context.

 The next item in the CBOR input must be map or this sets an error.

 This puts the decoder in bounded mode which narrows decoding to the
 map entered and enables getting items by label.

 All items in the map must be well-formed to be able to search it by
 label because a full traversal is done for each search. If not, the
 search will retun an error for the item that is not well-formed.
 This will be the first non-well-formed item which may not be the item
 with the label that is the target of the search.

 Nested maps can be decoded like this by entering each map in turn.

 Call QCBORDecode_ExitMap() to exit the current map decoding
 level. When all map decoding layers are exited then bounded mode is
 fully exited.

 While in bounded mode, QCBORDecode_GetNext() works as usual on the
 map and the in-order traversal cursor is maintained. It starts out at
 the first item in the map just entered. Attempts to get items off the
 end of the map will give error @ref QCBOR_ERR_NO_MORE_ITEMS rather
 going to the next item after the map as it would when not in bounded
 mode.

 Exiting leaves the pre-order cursor at the data item following the
 last entry in the map or at the end of the input CBOR if there
 nothing after the map.

 Entering and Exiting a map is a way to skip over an entire map and
 its contents. After QCBORDecode_ExitMap(), the pre-order traversal
 cursor will be at the first item after the map.

 See @ref Decode-Errors for discussion on how error handling works.

 See also QCBORDecode_EnterArray() and QCBORDecode_EnterBstrWrapped().
 Entering and exiting any nested combination of maps, arrays and
 bstr-wrapped CBOR is supported up to the maximum of @ref
 QCBOR_MAX_ARRAY_NESTING.
 */
static void QCBORDecode_EnterMap(QCBORDecodeContext *pCtx);

void QCBORDecode_EnterMapFromMapN(QCBORDecodeContext *pCtx, int64_t nLabel);

void QCBORDecode_EnterMapFromMapSZ(QCBORDecodeContext *pCtx, const char *szLabel);


/**
 @brief Exit a map that has been enetered.

 @param[in] pCtx   The decode context.

 A map must have been entered for this to succeed.

 The items in the map that was entered do not have to have been
 consumed for this to succeed.

 This sets thepre-order traversal cursor to the item after
 the map that was exited.
*/
static void QCBORDecode_ExitMap(QCBORDecodeContext *pCtx);


/**
 @brief Enter an array for decoding in bounded mode.

 @param[in] pCtx   The decode context.

 This enters an array for decodig in bounded mode. The items in array are decoded
 in order the same as when not in bounded mode, but the decoding will not
 proceed past the end or the array. The error @ref  QCBOR_ERR_NO_MORE_ITEMS
 will be set when the end of the array is encountered. To decode past the
 end of the array, QCBORDecode_ExitArray() must be called. Also, QCBORDecode_Finish()
 will return an error if all arrays that were  enetered are not exited.

 This works the same for definite and indefinite length arrays.

 See @ref Decode-Errors for discussion on how error handling works.

 If attempting to enter a data item that is not an array @ref QCBOR_ERR_UNEXPECTED_TYPE
 wil be set.

 Nested arrays and maps may be entered to a depth of @ref QCBOR_MAX_ARRAY_NESTING.

 See also QCBORDecode_ExitArray(), QCBORDecode_EnterMap() and QCBORDecode_EnterBstrWrapped().
*/
static void QCBORDecode_EnterArray(QCBORDecodeContext *pCtx);

void QCBORDecode_EnterArrayFromMapN(QCBORDecodeContext *pMe, int64_t uLabel);

void QCBORDecode_EnterArrayFromMapSZ(QCBORDecodeContext *pMe, const char *szLabel);


/**
 @brief Exit an array that has been enetered.

 @param[in] pCtx   The decode context.

 An array must have been entered for this to succeed.

 The items in the array that was entered do not have to have been
 consumed for this to succeed.

 This sets thepre-order traversal cursor to the item after
 the array that was exited.
*/
static void QCBORDecode_ExitArray(QCBORDecodeContext *pCtx);




/**
 @brief Decode some byte-string wrapped CBOR.

 @param[in] pCtx   The decode context.
 @param[in] uTagRequirement Whether or not the byte string must be tagged.
 @param[out] pBstr  Pointer and length of byte-string wrapped CBOR (optional).

 This is for use on some CBOR that has been wrapped in a
 byte string. There are several ways that this can occur.

 First is tag 24 and tag 63. Tag 24
 wraps a single CBOR data item and 63 a CBOR sequence.
 This implementation doesn't distinguish between the two
 (it would be more code and doesn't seem important).

 The @ref Tag-Matcing discussion on the tag requirement applies here
 just the same as any other tag.

 In other cases, CBOR is wrapped in a byte string, but
 it is identified as CBOR by other means. The contents
 of a COSE payload are one example of that. They can
 be identified by the COSE content type, or they can
 be identified as CBOR indirectly by the protocol that
 uses COSE. for example, if a blob of CBOR is identified
 as a CWT, then the COSE payload is CBOR.
 To enter into CBOR of this type use the
 @ref QCBOR_TAG_REQUIREMENT_NO_TAG as the \c uTagRequirement argument.

 Note that byte string wrapped CBOR can also be
 decoded by getting the byte string with QCBORDecode_GetItem() or
 QCBORDecode_GetByteString() and feeding it into another
 instance of QCBORDecode. Doing it with this function
 has the advantage of using less memory as another
 instance of QCBORDecode is not necessary.

 When the wrapped CBOR is entered with this function,
 the pre-order traversal and such are bounded to
 the wrapped CBOR. QCBORDecode_ExitBstrWrapped()
 must be called resume processing CBOR outside
 the wrapped CBOR.

 If @c pBstr is not @c NULL the pointer and length of the wrapped
 CBOR will be returned. This is usually not needed, but sometimes
 useful, particularly in the case of verifying signed data like the
 COSE payload. This is usually the pointer and length of the
 data is that is hashed or MACed.

 See @ref Decode-Errors for discussion on how error handling works.

 See also QCBORDecode_ExitBstrWrapped(), QCBORDecode_EnterMap() and QCBORDecode_EnterArray().

 */
void QCBORDecode_EnterBstrWrapped(QCBORDecodeContext *pCtx,
                                  uint8_t             uTagRequirement,
                                  UsefulBufC         *pBstr);

void QCBORDecode_EnterBstrWrappedFromMapN(QCBORDecodeContext *pCtx,
                                          int64_t             nLabel,
                                          uint8_t             uTagRequirement,
                                          UsefulBufC         *pBstr);

void QCBORDecode_EnterBstrWrappedFromMapSZ(QCBORDecodeContext *pCtx,
                                           const char         *szLabel,
                                           uint8_t             uTagRequirement,
                                           UsefulBufC         *pBstr);


/**
 @brief Exit some bstr-wrapped CBOR  has been enetered.

 @param[in] pCtx   The decode context.

 Bstr-wrapped CBOR must have been entered for this to succeed.

 The items in the wrapped CBOR that was entered do not have to have been
 consumed for this to succeed.

 The this sets thepre-order traversal cursor to the item after
 the byte string that was exited.
*/
void QCBORDecode_ExitBstrWrapped(QCBORDecodeContext *pCtx);


/**
 @brief Indicate if decoder is in bound mode.
 @param[in] pCtx   The decode context.

 @return true is returned if a map, array or bstr wrapped
 CBOR has been entered. This only returns false
 if all maps, arrays and bstr wrapped CBOR levels
 have been exited.
 */
bool QCBORDecode_InBoundedMode(QCBORDecodeContext *pCtx);


/**
 @brief Get an item in map by label and type.

 @param[in] pCtx   The decode context.
 @param[in] nLabel The integer label.
 @param[in] uQcborType  The QCBOR type. One of @c QCBOR_TYPE_XXX.
 @param[out] pItem  The returned item.

 A map must have been entered to use this. If not @ref xxx is set. TODO: which error?

 The map is searched for an item of the requested label and type.
 @ref QCBOR_TYPE_ANY can be given to search for the label without
 matching the type.

 This will always search the entire map. This will always perform
  duplicate label detection, setting @ref QCBOR_ERR_DUPLICATE_LABEL if there is more than
 one occurance of the label being searched for.

 Duplicate label detection is performed for the item being sought, but only
 for the item being sought.

 This performs a full decode of every item in the map
 being searched, which involves a full traversal
 of every item. For  maps with little nesting, this
 is of little consequence, but may be of consequence for large deeply nested
 CBOR structures on slow CPUs.

 See @ref Decode-Errors for discussion on how error handling works.

 See also QCBORDecode_GetItemsInMap().
*/
void QCBORDecode_GetItemInMapN(QCBORDecodeContext *pCtx,
                               int64_t             nLabel,
                               uint8_t             uQcborType,
                               QCBORItem          *pItem);

void QCBORDecode_GetItemInMapSZ(QCBORDecodeContext *pCtx,
                                const char         *szLabel,
                                uint8_t             uQcborType,
                                QCBORItem          *pItem);


/**
 @brief Get a group of labeled items all at once from a map

 @param[in] pCtx   The decode context.
 @param[in,out] pItemList  On input the items to search for. On output the returned items.

 This gets several labeled items out of a map.

 @c pItemList is an array of items terminated by an item
 with @c uLabelType @ref QCBOR_TYPE_NONE.

 On input the labels to search for are in the @c uLabelType and
 label fields in the items in @c pItemList.

 Also on input are the requested QCBOR types in the field @c uDataType.
 To match any type, searching just by label, @c uDataType
 can be @ref QCBOR_TYPE_ANY.

 This is a CPU-efficient way to decode a bunch of items in a map. It
 is more efficient than scanning each individually because the map
 only needs to be traversed once.

 If any duplicate labels are detected, this returns @ref QCBOR_ERR_DUPLICATE_LABEL.

 See @ref Decode-Errors for discussion on how error handling works.

 This will return maps and arrays that are in the map, but
 provides no way to descend into and decode them. Use
 QCBORDecode_EnterMapinMapN(), QCBORDecode_EnterArrayInMapN()
 and such to descend into and process maps and arrays.

 See also QCBORDecode_GetItemInMapN().
 */
QCBORError QCBORDecode_GetItemsInMap(QCBORDecodeContext *pCtx, QCBORItem *pItemList);


/**
 @brief Per-item callback for map searching.

 @param[in] pCallbackCtx  Pointer to the caller-defined context for the callback
 @param[in] pItem  The item from the map.

 @return  The return value is intended for QCBOR errors, not general protocol decoding
 errors. If this returns other than @ref QCBOR_SUCCESS, the search will stop and
 the value it returns will be set in QCBORDecode_GetItemsInMapWithCallback(). The
 special error, @ref QCBOR_ERR_CALLBACK_FAIL, can be returned to indicate some
 protocol processing error that is not a CBOR error. The specific details of the protocol
  processing error can be returned the call back context.
 */
typedef QCBORError (*QCBORItemCallback)(void *pCallbackCtx, const QCBORItem *pItem);


/**
 @brief Get a group of labeled items all at once from a map with a callback

 @param[in] pCtx   The decode context.
 @param[in,out] pItemList  On input the items to search for. On output the returned items.
 @param[in,out] pCallbackCtx Pointer to a context structure for @ref QCBORItemCallback
 @param[in] pfCB pointer to function of type @ref QCBORItemCallback that is called on unmatched items.

 This searchs a map like QCBORDecode_GetItemsInMap(), but calls a callback on items not
 matched rather than ignoring them. If @c pItemList is empty, the call back will be called
 on every item in the map.

 LIke QCBORDecode_GetItemsInMap(), this only matches and calls back on the items at the
 top level of the map entered. Items in nested maps/arrays are skipped over and not candidate for
 matching or the callback.

 See QCBORItemCallback() for error handling. TODO: does this set last error?
 */
QCBORError QCBORDecode_GetItemsInMapWithCallback(QCBORDecodeContext *pCtx,
                                                 QCBORItem          *pItemList,
                                                 void               *pCallbackCtx,
                                                 QCBORItemCallback   pfCB);





/* ===========================================================================
   BEGINNING OF PRIVATE INLINE IMPLEMENTATION
   ========================================================================== */


// Semi-private
void QCBORDecode_EnterBoundedMapOrArray(QCBORDecodeContext *pMe, uint8_t uType);

// Semi-private
inline static void QCBORDecode_EnterMap(QCBORDecodeContext *pMe) {
   QCBORDecode_EnterBoundedMapOrArray(pMe, QCBOR_TYPE_MAP);
}

// Semi-private
inline static void QCBORDecode_EnterArray(QCBORDecodeContext *pMe) {
   QCBORDecode_EnterBoundedMapOrArray(pMe, QCBOR_TYPE_ARRAY);
}

// Semi-private
void QCBORDecode_ExitBoundedMapOrArray(QCBORDecodeContext *pMe, uint8_t uType);


static inline void QCBORDecode_ExitArray(QCBORDecodeContext *pMe)
{
   QCBORDecode_ExitBoundedMapOrArray(pMe, QCBOR_TYPE_ARRAY);
}

static inline void QCBORDecode_ExitMap(QCBORDecodeContext *pMe)
{
   QCBORDecode_ExitBoundedMapOrArray(pMe, QCBOR_TYPE_MAP);
}


// Semi-private
void
QCBORDecode_GetInt64ConvertInternal(QCBORDecodeContext *pMe,
                                    uint32_t            uConvertTypes,
                                    int64_t            *pnValue,
                                    QCBORItem          *pItem);

// Semi-private
void
QCBORDecode_GetInt64ConvertInternalInMapN(QCBORDecodeContext *pMe,
                                          int64_t             nLabel,
                                          uint32_t            uConvertTypes,
                                          int64_t            *pnValue,
                                          QCBORItem          *pItem);

// Semi-private
void
QCBORDecode_GetInt64ConvertInternalInMapSZ(QCBORDecodeContext *pMe,
                                           const char         *szLabel,
                                           uint32_t            uConvertTypes,
                                           int64_t            *pnValue,
                                           QCBORItem          *pItem);

inline static void
QCBORDecode_GetInt64Convert(QCBORDecodeContext *pMe,
                            uint32_t            uConvertTypes,
                            int64_t            *pnValue)
{
    QCBORItem Item;
    QCBORDecode_GetInt64ConvertInternal(pMe, uConvertTypes, pnValue, &Item);
}

inline static void
QCBORDecode_GetInt64ConvertInMapN(QCBORDecodeContext *pMe,
                                  int64_t            nLabel,
                                  uint32_t           uConvertTypes,
                                  int64_t           *pnValue)
{
   QCBORItem Item;
   QCBORDecode_GetInt64ConvertInternalInMapN(pMe,
                                             nLabel,
                                             uConvertTypes,
                                             pnValue, &Item);
}

inline static void
QCBORDecode_GetInt64ConvertInMapSZ(QCBORDecodeContext *pMe,
                                   const char         *szLabel,
                                   uint32_t            uConvertTypes,
                                   int64_t            *pnValue)
{
   QCBORItem Item;
   QCBORDecode_GetInt64ConvertInternalInMapSZ(pMe,
                                              szLabel,
                                              uConvertTypes,
                                              pnValue, &Item);
}

inline static void
QCBORDecode_GetInt64(QCBORDecodeContext *pMe, int64_t *pnValue)
{
    QCBORDecode_GetInt64Convert(pMe, QCBOR_CONVERT_TYPE_XINT64, pnValue);
}

inline static void
QCBORDecode_GetInt64InMapN(QCBORDecodeContext *pMe,
                           int64_t nLabel,
                           int64_t *pnValue)
{
   QCBORDecode_GetInt64ConvertInMapN(pMe,
                                     nLabel,
                                     QCBOR_CONVERT_TYPE_XINT64,
                                     pnValue);
}

inline static void
QCBORDecode_GetInt64InMapSZ(QCBORDecodeContext *pMe,
                            const char *szLabel,
                            int64_t *pnValue)
{
   QCBORDecode_GetInt64ConvertInMapSZ(pMe,
                                      szLabel,
                                      QCBOR_CONVERT_TYPE_XINT64,
                                      pnValue);
}




// Semi-private
void
QCBORDecode_GetUInt64ConvertInternal(QCBORDecodeContext *pMe,
                                     uint32_t            uConvertTypes,
                                     uint64_t           *puValue,
                                     QCBORItem          *pItem);

// Semi-private
void
QCBORDecode_GetUInt64ConvertInternalInMapN(QCBORDecodeContext *pMe,
                                           int64_t             nLabel,
                                           uint32_t            uConvertTypes,
                                           uint64_t           *puValue,
                                           QCBORItem          *pItem);

// Semi-private
void
QCBORDecode_GetUInt64ConvertInternalInMapSZ(QCBORDecodeContext *pMe,
                                            const char         *szLabel,
                                            uint32_t            uConvertTypes,
                                            uint64_t           *puValue,
                                            QCBORItem          *pItem);


void QCBORDecode_GetUInt64Convert(QCBORDecodeContext *pMe,
                                  uint32_t uConvertTypes,
                                  uint64_t *puValue)
{
    QCBORItem Item;
    QCBORDecode_GetUInt64ConvertInternal(pMe, uConvertTypes, puValue, &Item);
}

inline static void
QCBORDecode_GetUInt64ConvertInMapN(QCBORDecodeContext *pMe,
                                   int64_t            nLabel,
                                   uint32_t           uConvertTypes,
                                   uint64_t          *puValue)
{
   QCBORItem Item;
   QCBORDecode_GetUInt64ConvertInternalInMapN(pMe,
                                              nLabel,
                                              uConvertTypes,
                                              puValue,
                                              &Item);
}

inline static void
QCBORDecode_GetUInt64ConvertInMapSZ(QCBORDecodeContext *pMe,
                                    const char         *szLabel,
                                    uint32_t            uConvertTypes,
                                    uint64_t           *puValue)
{
   QCBORItem Item;
   QCBORDecode_GetUInt64ConvertInternalInMapSZ(pMe,
                                               szLabel,
                                               uConvertTypes,
                                               puValue,
                                               &Item);
}

static inline void
QCBORDecode_GetUInt64(QCBORDecodeContext *pMe, uint64_t *puValue)
{
    QCBORDecode_GetUInt64Convert(pMe, QCBOR_CONVERT_TYPE_XINT64, puValue);
}

inline static void
QCBORDecode_GetUInt64InMapN(QCBORDecodeContext *pMe,
                            int64_t             nLabel,
                            uint64_t           *puValue)
{
   QCBORDecode_GetUInt64ConvertInMapN(pMe,
                                      nLabel,
                                      QCBOR_CONVERT_TYPE_XINT64,
                                      puValue);
}

inline static void
QCBORDecode_GetUInt64InMapSZ(QCBORDecodeContext *pMe,
                             const char         *szLabel,
                             uint64_t           *puValue)
{
   QCBORDecode_GetUInt64ConvertInMapSZ(pMe,
                                       szLabel,
                                       QCBOR_CONVERT_TYPE_XINT64,
                                       puValue);
}



// Semi-private
void
QCBORDecode_GetDoubleConvertInternal(QCBORDecodeContext *pMe,
                                     uint32_t            uConvertTypes,
                                     double             *pValue,
                                     QCBORItem          *pItem);

// Semi-private
void
QCBORDecode_GetDoubleConvertInternalInMapN(QCBORDecodeContext *pMe,
                                           int64_t            nLabel,
                                           uint32_t           uConvertTypes,
                                           double            *pdValue,
                                           QCBORItem         *pItem);

// Semi-private
void
QCBORDecode_GetDoubleConvertInternalInMapSZ(QCBORDecodeContext *pMe,
                                            const char         *szLabel,
                                            uint32_t            uConvertTypes,
                                            double             *pdValue,
                                            QCBORItem          *pItem);


inline static void
QCBORDecode_GetDoubleConvert(QCBORDecodeContext *pMe,
                             uint32_t            uConvertTypes,
                             double             *pdValue)
{
    QCBORItem Item;
    QCBORDecode_GetDoubleConvertInternal(pMe, uConvertTypes, pdValue, &Item);
}

inline static void
QCBORDecode_GetDoubleConvertInMapN(QCBORDecodeContext *pMe,
                                   int64_t             nLabel,
                                   uint32_t            uConvertTypes,
                                   double             *pdValue)
{
   QCBORItem Item;
   QCBORDecode_GetDoubleConvertInternalInMapN(pMe,
                                              nLabel,
                                              uConvertTypes,
                                              pdValue,
                                              &Item);
}

inline static void
QCBORDecode_GetDoubleConvertInMapSZ(QCBORDecodeContext *pMe,
                                    const char         *szLabel,
                                    uint32_t            uConvertTypes,
                                    double             *pdValue)
{
   QCBORItem Item;
   QCBORDecode_GetDoubleConvertInternalInMapSZ(pMe,
                                               szLabel,
                                               uConvertTypes,
                                               pdValue,
                                               &Item);
}

inline static void
QCBORDecode_GetDouble(QCBORDecodeContext *pMe, double *pValue)
{
    QCBORDecode_GetDoubleConvert(pMe, QCBOR_CONVERT_TYPE_FLOAT, pValue);
}

inline static void
QCBORDecode_GetDoubleInMapN(QCBORDecodeContext *pMe,
                            int64_t             nLabel,
                            double             *pdValue)
{
   QCBORDecode_GetDoubleConvertInMapN(pMe,
                                      nLabel,
                                      QCBOR_CONVERT_TYPE_FLOAT,
                                      pdValue);
}

inline static void
QCBORDecode_GetDoubleInMapSZ(QCBORDecodeContext *pMe,
                             const char         *szLabel,
                             double             *pdValue)
{
   QCBORDecode_GetDoubleConvertInMapSZ(pMe,
                                       szLabel,
                                       QCBOR_CONVERT_TYPE_FLOAT,
                                       pdValue);
}



// Semi private
#define QCBOR_TAGSPEC_NUM_TYPES 3
// TODO: make content types 4 to help out epoch dates?
/* TODO: This structure can probably be rearranged so the initialization
 of it takes much less code. */
typedef struct {
   /* One of QCBOR_TAGSPEC_MATCH_xxx */
   uint8_t uTagRequirement;
   /* The tagged type translated into QCBOR_TYPE_XXX. Used to match explicit
      tagging */
   uint8_t uTaggedTypes[QCBOR_TAGSPEC_NUM_TYPES];
   /* The types of the content, which are used to match implicit tagging */
   uint8_t uAllowedContentTypes[QCBOR_TAGSPEC_NUM_TYPES];
} TagSpecification;

// Semi private
void QCBORDecode_GetTaggedStringInternal(QCBORDecodeContext *pMe,
                                         TagSpecification    TagSpec,
                                         UsefulBufC         *pBstr);


// Semi private
void QCBORDecode_GetTaggedItemInMapN(QCBORDecodeContext *pMe,
                                     int64_t             nLabel,
                                     TagSpecification    TagSpec,
                                     QCBORItem          *pItem);

// Semi private
void QCBORDecode_GetTaggedItemInMapSZ(QCBORDecodeContext *pMe,
                                      const char *        szLabel,
                                      TagSpecification    TagSpec,
                                      QCBORItem          *pItem);

// Semi private
void QCBORDecode_GetTaggedStringInMapN(QCBORDecodeContext *pMe,
                                       int64_t             nLabel,
                                       TagSpecification    TagSpec,
                                       UsefulBufC         *pString);

// Semi private
void QCBORDecode_GetTaggedStringInMapSZ(QCBORDecodeContext *pMe,
                                        const char *        szLabel,
                                        TagSpecification    TagSpec,
                                        UsefulBufC         *pString);


// Semi private
QCBORError QCBORDecode_GetMIMEInternal(uint8_t     uTagRequirement,
                                       const       QCBORItem *pItem,
                                       UsefulBufC *pMessage,
                                       bool       *pbIsNot7Bit);



static inline void
QCBORDecode_GetBytes(QCBORDecodeContext *pMe,  UsefulBufC *pValue)
{
   // Complier should make this just 64-bit integer parameter
   const TagSpecification TagSpec =
      {
         QCBOR_TAG_REQUIREMENT_NO_TAG,
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInternal(pMe, TagSpec, pValue);
}

inline static void
QCBORDecode_GetBytesInMapN(QCBORDecodeContext *pMe,
                           int64_t             nLabel,
                           UsefulBufC         *pBstr)
{
   const TagSpecification TagSpec =
      {
         QCBOR_TAG_REQUIREMENT_NO_TAG,
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };
   QCBORDecode_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pBstr);
}

inline static void
QCBORDecode_GetBytesInMapSZ(QCBORDecodeContext *pMe,
                            const char         *szLabel,
                            UsefulBufC         *pBstr)
{
   const TagSpecification TagSpec =
      {
         QCBOR_TAG_REQUIREMENT_NO_TAG,
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pBstr);
}

static inline void
QCBORDecode_GetText(QCBORDecodeContext *pMe,  UsefulBufC *pValue)
{
   // Complier should make this just 64-bit integer parameter
   const TagSpecification TagSpec =
      {
         QCBOR_TAG_REQUIREMENT_NO_TAG,
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInternal(pMe, TagSpec, pValue);
}

inline static void
QCBORDecode_GetTextInMapN(QCBORDecodeContext *pMe,
                          int64_t             nLabel,
                          UsefulBufC         *pText)
{
   // This TagSpec only matches text strings; it also should optimize down
   // to passing a 64-bit integer
   const TagSpecification TagSpec =
      {
         QCBOR_TAG_REQUIREMENT_NO_TAG,
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pText);
}


inline static void
QCBORDecode_GetTextInMapSZ(QCBORDecodeContext *pMe,
                           const               char *szLabel,
                           UsefulBufC         *pText)
{
   const TagSpecification TagSpec =
      {
         QCBOR_TAG_REQUIREMENT_NO_TAG,
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pText);
}


static inline void
QCBORDecode_GetDateString(QCBORDecodeContext *pMe,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pValue)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_DATE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInternal(pMe, TagSpec, pValue);
}


inline static void
QCBORDecode_GetDateStringInMapN(QCBORDecodeContext *pMe,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                UsefulBufC         *pText)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_DATE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pText);
}

inline static void
QCBORDecode_GetDateStringInMapSZ(QCBORDecodeContext *pMe,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC         *pText)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_DATE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pText);
}


static inline void QCBORDecode_GetURI(QCBORDecodeContext *pMe,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC         *pUUID)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_URI, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInternal(pMe, TagSpec, pUUID);
}


inline static void \
QCBORDecode_GetURIInMapN(QCBORDecodeContext *pMe,
                         int64_t             nLabel,
                         uint8_t             uTagRequirement,
                         UsefulBufC         *pUUID)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_URI, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pUUID);
}


inline static void
QCBORDecode_GetURIInMapSZ(QCBORDecodeContext *pMe,
                          const char         *szLabel,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pUUID)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_URI, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pUUID);
}



static inline void QCBORDecode_GetB64(QCBORDecodeContext *pMe,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC         *pB64Text)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_BASE64, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInternal(pMe, TagSpec, pB64Text);
}


inline static void QCBORDecode_GetB64InMapN(QCBORDecodeContext *pMe,
                                            int64_t             nLabel,
                                            uint8_t             uTagRequirement,
                                            UsefulBufC         *pB64Text)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_BASE64, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pB64Text);
}

inline static void
QCBORDecode_GetB64InMapSZ(QCBORDecodeContext *pMe,
                          const char         *szLabel,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pB64Text)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_BASE64, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };
   QCBORDecode_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pB64Text);
}


static inline void
QCBORDecode_GetB64URL(QCBORDecodeContext *pMe,
                      uint8_t             uTagRequirement,
                      UsefulBufC         *pB64Text)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_BASE64URL, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInternal(pMe, TagSpec, pB64Text);
}


inline static void
QCBORDecode_GetB64URLInMapN(QCBORDecodeContext *pMe,
                            int64_t             nLabel,
                            uint8_t             uTagRequirement,
                            UsefulBufC         *pB64Text)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_BASE64URL, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pB64Text);
}


inline static void
QCBORDecode_GetB64URLInMapSZ(QCBORDecodeContext *pMe,
                             const char         *szLabel,
                             uint8_t             uTagRequirement,
                             UsefulBufC         *pB64Text)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_BASE64URL, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pB64Text);
}


static inline void QCBORDecode_GetRegex(QCBORDecodeContext *pMe,
                                        uint8_t             uTagRequirement,
                                        UsefulBufC         *pRegex)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_REGEX, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInternal(pMe, TagSpec, pRegex);
}


static inline void
QCBORDecode_GetRegexInMapN(QCBORDecodeContext *pMe,
                           int64_t             nLabel,
                           uint8_t             uTagRequirement,
                           UsefulBufC         *pRegex)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_REGEX, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pRegex);
}


static inline void
QCBORDecode_GetRegexInMapSZ(QCBORDecodeContext *pMe,
                            const char *        szLabel,
                            uint8_t             uTagRequirement,
                            UsefulBufC         *pRegex)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_REGEX, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_TEXT_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pRegex);
}


static inline void
QCBORDecode_GetMIMEMessage(QCBORDecodeContext *pMe,
                           uint8_t             uTagRequirement,
                           UsefulBufC         *pMessage,
                           bool               *pbIsNot7Bit)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      // Already in error state, do nothing
      return;
   }

   QCBORItem  Item;
   QCBORError uError = QCBORDecode_GetNext(pMe, &Item);
   if(uError != QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)uError;
      return;
   }

   pMe->uLastError = (uint8_t)QCBORDecode_GetMIMEInternal(uTagRequirement,
                                                          &Item,
                                                          pMessage,
                                                          pbIsNot7Bit);
}


static inline void
QCBORDecode_GetMIMEMessageInMapN(QCBORDecodeContext *pMe,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC         *pMessage,
                                 bool               *pbIsNot7Bit)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_ANY, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)QCBORDecode_GetMIMEInternal(uTagRequirement,
                                                             &Item,
                                                             pMessage,
                                                             pbIsNot7Bit);
   }
}


static inline void
QCBORDecode_GetMIMEMessageInMapSZ(QCBORDecodeContext *pMe,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  UsefulBufC         *pMessage,
                                  bool               *pbIsNot7Bit)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_ANY, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)QCBORDecode_GetMIMEInternal(uTagRequirement,
                                                             &Item,
                                                             pMessage,
                                                             pbIsNot7Bit);
   }
}



static inline void
QCBORDecode_GetBinaryUUID(QCBORDecodeContext *pMe,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pUUID)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_UUID, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInternal(pMe, TagSpec, pUUID);
}


inline static void
QCBORDecode_GetBinaryUUIDInMapN(QCBORDecodeContext *pMe,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                UsefulBufC         *pUUID)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_UUID, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapN(pMe, nLabel, TagSpec, pUUID);
}

inline static void
QCBORDecode_GetBinaryUUIDInMapSZ(QCBORDecodeContext *pMe,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC         *pUUID)
{
   const TagSpecification TagSpec =
      {
         uTagRequirement,
         {QCBOR_TYPE_UUID, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE},
         {QCBOR_TYPE_BYTE_STRING, QCBOR_TYPE_NONE, QCBOR_TYPE_NONE}
      };

   QCBORDecode_GetTaggedStringInMapSZ(pMe, szLabel, TagSpec, pUUID);
}



#ifdef __cplusplus
}
#endif

#endif /* qcbor_spiffy_decode_h */
