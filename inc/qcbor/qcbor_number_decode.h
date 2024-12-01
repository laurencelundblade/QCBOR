/* ==========================================================================
 * qcbor_number_decode.h -- CBOR number decoding.
 *
 * Copyright (c) 2020-2024, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in file named "LICENSE"
 *
 * Forked from qcbor_decode.h on 11/23/2024
 * ========================================================================== */
#ifndef qcbor_number_decode_h
#define qcbor_number_decode_h


#include "qcbor/qcbor_decode.h"


#ifdef __cplusplus
extern "C" {
#if 0
} // Keep editor indention formatting happy
#endif
#endif



/**
 * @file qcbor_number
 */

/** Conversion will proceed if the CBOR item to be decoded is an
 *  integer or either type 0 (unsigned) or type 1 (negative). */
#define QCBOR_CONVERT_TYPE_XINT64           0x01
/** Conversion will proceed if the CBOR item to be decoded is either
 *  double, single or half-precision floating-point (major type 7). */
#define QCBOR_CONVERT_TYPE_FLOAT            0x02
/** Conversion will proceed if the CBOR item to be decoded is a big
 *  number, positive or negative (tag 2 or tag 3). */
#define QCBOR_CONVERT_TYPE_BIG_NUM          0x04
/** Conversion will proceed if the CBOR item to be decoded is a
 *  decimal fraction (tag 4). */
#define QCBOR_CONVERT_TYPE_DECIMAL_FRACTION 0x08
/** Conversion will proceed if the CBOR item to be decoded is a big
 *  float (tag 5). */
#define QCBOR_CONVERT_TYPE_BIGFLOAT         0x10




/**
 * @brief Decode next item into a signed 64-bit integer.
 *
 * @param[in] pCtx      The decode context.
 * @param[out] pnValue  The returned 64-bit signed integer.
 *
 * The CBOR data item to decode must be a positive or negative integer
 * (CBOR major type 0 or 1). If not @ref QCBOR_ERR_UNEXPECTED_TYPE is set.
 *
 * If the CBOR integer is either too large or too small to fit in an
 * int64_t, the error @ref QCBOR_ERR_INT_OVERFLOW or
 * @ref QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW is set.  Note that type 0
 * unsigned integers can be larger than will fit in an int64_t and
 * type 1 negative integers can be smaller than will fit in an
 * int64_t.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_GetUInt64(), QCBORDecode_GetInt64Convert(),
 * QCBORDecode_GetInt64ConvertAll() and QCBORDecode_GetDoubleConvert()
 */
static void
QCBORDecode_GetInt64(QCBORDecodeContext *pCtx,
                     int64_t            *pnValue);

static void
QCBORDecode_GetInt64InMapN(QCBORDecodeContext *pCtx,
                           int64_t             nLabel,
                           int64_t            *pnValue);

static void
QCBORDecode_GetInt64InMapSZ(QCBORDecodeContext *pCtx,
                            const char         *szLabel,
                            int64_t            *pnValue);


/**
 * @brief Decode next item into a signed 64-bit integer with basic conversions.
 *
 * @param[in] pCtx           The decode context.
 * @param[in] uConvertTypes  The integer conversion options.
 * @param[out] pnValue       The returned 64-bit signed integer.
 *
 * @c uConvertTypes controls what conversions this will perform and
 * thus what CBOR types will be decoded.  @c uConvertType is a bit map
 * listing the conversions to be allowed. This function supports
 * @ref QCBOR_CONVERT_TYPE_XINT64 and @ref QCBOR_CONVERT_TYPE_FLOAT
 * conversions.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * If the CBOR data type can never be convered by this function or the
 * conversion was not selected in @c uConversionTypes
 * @ref QCBOR_ERR_UNEXPECTED_TYPE is set.
 *
 * When converting floating-point values, the integer is rounded to
 * the nearest integer using llround(). By default, floating-point
 * suport is enabled for QCBOR.
 *
 * If floating-point HW use is disabled this will set
 * @ref QCBOR_ERR_HW_FLOAT_DISABLED if a single-precision number is
 * encountered. If half-precision support is disabled, this will set
 * @ref QCBOR_ERR_HALF_PRECISION_DISABLED if a half-precision number
 * is encountered.
 *
 * If floating-point usage is disabled this will set
 * @ref QCBOR_ERR_ALL_FLOAT_DISABLED if a floating point value is
 * encountered.
 *
 * See also QCBORDecode_GetInt64ConvertAll() which will perform the
 * same conversions as this and a lot more at the cost of adding more
 * object code to your executable.
 */
static void
QCBORDecode_GetInt64Convert(QCBORDecodeContext *pCtx,
                            uint32_t            uConvertTypes,
                            int64_t            *pnValue);

static void
QCBORDecode_GetInt64ConvertInMapN(QCBORDecodeContext *pCtx,
                                  int64_t             nLabel,
                                  uint32_t            uConvertTypes,
                                  int64_t            *pnValue);

static void
QCBORDecode_GetInt64ConvertInMapSZ(QCBORDecodeContext *pCtx,
                                   const char         *szLabel,
                                   uint32_t            uConvertTypes,
                                   int64_t            *pnValue);




/**
 * @brief Decode next item into a signed 64-bit integer with conversions.
 *
 * @param[in] pCtx           The decode context.
 * @param[in] uConvertTypes  The integer conversion options.
 * @param[out] pnValue       The returned 64-bit signed integer.
 *
 * This is the same as QCBORDecode_GetInt64Convert() but additionally
 * supports conversion from positive and negative bignums, decimal
 * fractions and big floats, including decimal fractions and big floats
 * that use bignums. The conversion types supported are
 * @ref QCBOR_CONVERT_TYPE_XINT64, @ref QCBOR_CONVERT_TYPE_FLOAT,
 * @ref QCBOR_CONVERT_TYPE_BIG_NUM,
 * @ref QCBOR_CONVERT_TYPE_DECIMAL_FRACTION and
 * @ref QCBOR_CONVERT_TYPE_BIGFLOAT.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * Note that most these types can support numbers much larger that can
 * be represented by in a 64-bit integer, so
 * @ref QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW may often be encountered.
 *
 * When converting bignums and decimal fractions,
 * @ref QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW will be set if the result
 * is below 1, unless the mantissa is zero, in which case the
 * coversion is successful and the value of 0 is returned.
 *
 * See also QCBORDecode_GetInt64ConvertAll() which does some of these
 * conversions, but links in much less object code. See also
 * QCBORDecode_GetUInt64ConvertAll().
 *
 * This relies on CBOR tags to identify big numbers, decimal fractions
 * and big floats. It will not attempt to decode non-tag CBOR that might
 * be one of these.  (If QCBOR_DISABLE_TAGS is set, this is effectively
 * the same as QCBORDecode_GetInt64Convert() because all the additional
 * number types this decodes are tags).
 */
void
QCBORDecode_GetInt64ConvertAll(QCBORDecodeContext *pCtx,
                               uint32_t            uConvertTypes,
                               int64_t            *pnValue);

void
QCBORDecode_GetInt64ConvertAllInMapN(QCBORDecodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint32_t            uConvertTypes,
                                     int64_t            *pnValue);

void
QCBORDecode_GetInt64ConvertAllInMapSZ(QCBORDecodeContext *pCtx,
                                      const char         *szLabel,
                                      uint32_t            uConvertTypes,
                                      int64_t            *pnValue);


/**
 * @brief Decode next item into an unsigned 64-bit integer.
 *
 * @param[in] pCtx      The decode context.
 * @param[out] puValue  The returned 64-bit unsigned integer.
 *
 * This is the same as QCBORDecode_GetInt64(), but returns an unsigned integer
 * and thus can only decode CBOR positive integers.
 * @ref QCBOR_ERR_NUMBER_SIGN_CONVERSION is set if the input is a negative
 * integer.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_GetUInt64Convert() and QCBORDecode_GetUInt64ConvertAll().
 */
static void
QCBORDecode_GetUInt64(QCBORDecodeContext *pCtx,
                      uint64_t           *puValue);

static void
QCBORDecode_GetUInt64InMapN(QCBORDecodeContext *pCtx,
                            int64_t             nLabel,
                            uint64_t           *puValue);

static void
QCBORDecode_GetUInt64InMapSZ(QCBORDecodeContext *pCtx,
                             const char         *szLabel,
                             uint64_t           *puValue);


/**
 * @brief Decode next item as an unsigned 64-bit integer with basic conversions.
 *
 * @param[in] pCtx           The decode context.
 * @param[in] uConvertTypes  The integer conversion options.
 * @param[out] puValue       The returned 64-bit unsigned integer.
 *
 * This is the same as QCBORDecode_GetInt64Convert(), but returns an
 * unsigned integer and thus sets @ref QCBOR_ERR_NUMBER_SIGN_CONVERSION
 * if the value to be decoded is negatve.
 *
 * If floating-point HW use is disabled this will set
 * @ref QCBOR_ERR_HW_FLOAT_DISABLED if a single-precision number is
 * encountered. If half-precision support is disabled, this will set
 * @ref QCBOR_ERR_HALF_PRECISION_DISABLED if a half-precision number
 * is encountered.
 *
 * If floating-point usage is disabled this will set
 * @ref QCBOR_ERR_ALL_FLOAT_DISABLED if a floating point value is
 * encountered.
 *
 * See also QCBORDecode_GetUInt64Convert() and
 * QCBORDecode_GetUInt64ConvertAll().
 */
static void
QCBORDecode_GetUInt64Convert(QCBORDecodeContext *pCtx,
                             uint32_t            uConvertTypes,
                             uint64_t           *puValue);

static void
QCBORDecode_GetUInt64ConvertInMapN(QCBORDecodeContext *pCtx,
                                   int64_t             nLabel,
                                   uint32_t            uConvertTypes,
                                   uint64_t           *puValue);

static void
QCBORDecode_GetUInt64ConvertInMapSZ(QCBORDecodeContext *pCtx,
                                    const char         *szLabel,
                                    uint32_t            uConvertTypes,
                                    uint64_t           *puValue);


/**
 * @brief Decode next item into an unsigned 64-bit integer with conversions
 *
 * @param[in] pCtx           The decode context.
 * @param[in] uConvertTypes  The integer conversion options.
 * @param[out] puValue       The returned 64-bit unsigned integer.
 *
 * This is the same as QCBORDecode_GetInt64ConvertAll(), but returns
 * an unsigned integer and thus sets @ref QCBOR_ERR_NUMBER_SIGN_CONVERSION
 * if the value to be decoded is negatve.
 *
 * See also QCBORDecode_GetUInt64() and QCBORDecode_GetUInt64Convert().
 */
void
QCBORDecode_GetUInt64ConvertAll(QCBORDecodeContext *pCtx,
                                uint32_t            uConvertTypes,
                                uint64_t           *puValue);

void
QCBORDecode_GetUInt64ConvertAllInMapN(QCBORDecodeContext *pCtx,
                                      int64_t             nLabel,
                                      uint32_t            uConvertTypes,
                                      uint64_t           *puValue);

void
QCBORDecode_GetUInt64ConvertAllInMapSZ(QCBORDecodeContext *pCtx,
                                       const char         *szLabel,
                                       uint32_t            uConvertTypes,
                                       uint64_t           *puValue);




#ifndef USEFULBUF_DISABLE_ALL_FLOAT
/**
 * @brief Decode next item into a double floating-point value.
 *
 * @param[in] pCtx     The decode context.
 * @param[out] pValue  The returned floating-point value.
 *
 * The CBOR data item to decode must be a half-precision,
 * single-precision or double-precision floating-point value. If not
 * @ref QCBOR_ERR_UNEXPECTED_TYPE is set.
 *
 * If floating-point HW use is disabled this will set
 * @ref QCBOR_ERR_HW_FLOAT_DISABLED if a single-precision number is
 * encountered. If half-precision support is disabled, this will set
 * @ref QCBOR_ERR_HALF_PRECISION_DISABLED if a half-precision number
 * is encountered.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_GetDoubleConvert() and
 * QCBORDecode_GetDoubleConvertAll().
 */
static void
QCBORDecode_GetDouble(QCBORDecodeContext *pCtx,
                      double             *pValue);

static void
QCBORDecode_GetDoubleInMapN(QCBORDecodeContext *pCtx,
                            int64_t             nLabel,
                            double             *pdValue);

static void
QCBORDecode_GetDoubleInMapSZ(QCBORDecodeContext *pCtx,
                             const char         *szLabel,
                             double             *pdValue);


/**
 * @brief Decode next item into a double floating-point with basic conversion.
 *
 * @param[in] pCtx           The decode context.
 * @param[in] uConvertTypes  The integer conversion options.
 * @param[out] pdValue       The returned floating-point value.
 *
 * This will decode CBOR integer and floating-point numbers, returning
 * them as a double floating-point number. This function supports

 * @ref QCBOR_CONVERT_TYPE_XINT64 and @ref QCBOR_CONVERT_TYPE_FLOAT
 * conversions. If the encoded CBOR is not one of the requested types
 * or a type not supported by this function, @ref QCBOR_ERR_UNEXPECTED_TYPE
 * is set.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * If floating-point HW use is disabled this will set
 * @ref QCBOR_ERR_HW_FLOAT_DISABLED if a single-precision number is
 * encountered. If half-precision support is disabled, this will set
 * @ref QCBOR_ERR_HALF_PRECISION_DISABLED if a half-precision number is
 * encountered.
 *
 * Positive and negative integers can always be converted to
 * floating-point, so this will never error on CBOR major type 0 or 1.
 *
 * Note that a large 64-bit integer can have more precision (64 bits)
 * than even a double floating-point (52 bits) value, so there is loss
 * of precision in some conversions.
 *
 * See also QCBORDecode_GetDouble() and QCBORDecode_GetDoubleConvertAll().
 */
static void
QCBORDecode_GetDoubleConvert(QCBORDecodeContext *pCtx,
                             uint32_t            uConvertTypes,
                             double             *pdValue);

static void
QCBORDecode_GetDoubleConvertInMapN(QCBORDecodeContext *pCtx,
                                   int64_t             nLabel,
                                   uint32_t            uConvertTypes,
                                   double             *pdValue);

static void
QCBORDecode_GetDoubleConvertInMapSZ(QCBORDecodeContext *pCtx,
                                    const char         *szLabel,
                                    uint32_t            uConvertTypes,
                                    double             *pdValue);


/**
 * @brief Decode next item as a double floating-point value with conversion.
 *
 * @param[in] pCtx           The decode context.
 * @param[in] uConvertTypes  The integer conversion options.
 * @param[out] pdValue       The returned floating-point value.
 *
 * This is the same as QCBORDecode_GetDoubleConvert() but supports
 * many more conversions at the cost of linking in more object
 * code. The conversion types supported are @ref QCBOR_CONVERT_TYPE_XINT64,
 * @ref QCBOR_CONVERT_TYPE_FLOAT, @ref QCBOR_CONVERT_TYPE_BIG_NUM,
 * @ref QCBOR_CONVERT_TYPE_DECIMAL_FRACTION and
 * @ref QCBOR_CONVERT_TYPE_BIGFLOAT.
 *
 * Big numbers, decimal fractions and big floats that are too small or
 * too large to be reprented as a double floating-point number will be
 * returned as plus or minus zero or infinity rather than setting an
 * under or overflow error.
 *
 * There is often loss of precision in the conversion.
 *
 * See also QCBORDecode_GetDoubleConvert() and QCBORDecode_GetDoubleConvert().
 */
void
QCBORDecode_GetDoubleConvertAll(QCBORDecodeContext *pCtx,
                                uint32_t            uConvertTypes,
                                double             *pdValue);

void
QCBORDecode_GetDoubleConvertAllInMapN(QCBORDecodeContext *pCtx,
                                      int64_t             nLabel,
                                      uint32_t            uConvertTypes,
                                      double             *pdValue);

void
QCBORDecode_GetDoubleConvertAllInMapSZ(QCBORDecodeContext *pCtx,
                                       const char         *szLabel,
                                       uint32_t            uConvertTypes,
                                       double             *pdValue);

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
/**
 * @brief dCBOR Decode next as a number with precision-preserving conversions.
 *
 * @param[in] pCtx           The decode context.
 * @param[out] pNumber       The returned number.
 *
 * This gets the next item as a number and returns it as a C data type
 * such that no precision is lost.
 *
 * This is primarily works with integers and floats for both the
 * to-be-decoded CBOR and the decoded types.
 *
 * The CBOR input can be integers (major type 0 or 1) or floats (major
 * type 7).  If not these, \ref QCBOR_ERR_UNEXPECTED_TYPE will be set.
 *
 * The conversion is as follows.
 *
 * Whole numbers from \c INT64_MIN to \c INT64_MAX will be returned as
 * int64_t indicated as \ref QCBOR_TYPE_INT64. This includes
 * conversion of floating-point values that are whole numbers.
 *
 * Whole numbers from \c INT64_MAX +1 to \c UINT64_MAX will be
 * returned as uint64_t indicated as \ref QCBOR_TYPE_UINT64, again
 * including conversion of floating-point values that are whole
 * numbers.
 *
 * Most other numbers are returned as a double as indicated by
 * \ref QCBOR_TYPE_DOUBLE floating point with one set of exceptions.
 *
 * The exception is negative whole numbers in the range of -(2^63 + 1)
 * to -(2^64) that have too much precision to be represented as a
 * double. Doubles have only 52 bits of precision, so they can't
 * precisely represent every whole integer in this range. CBOR can
 * represent these values with 64-bits of precision and when this
 * function encounters them they are returned as \ref
 * QCBOR_TYPE_65BIT_NEG_INT.  See the description of this type for
 * instructions to gets its value.  Also see
 * QCBORDecode_ProcessBigNumber().
 *
 * To give an example, the value -18446744073709551616 can't be
 * represented by an int64_t or uint64_t, but can be represented by a
 * double so it is returned by this function as a double. The value
 * -18446744073709551617 however can't be represented by a double
 * because it has too much precision, so it is returned as \ref
 * QCBOR_TYPE_65BIT_NEG_INT.
 *
 * This is useful for DCBOR which essentially combines floats and
 * integers into one number space.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_GetNumberConvertPreciselyBig().
 */
void
QCBORDecode_GetNumberConvertPrecisely(QCBORDecodeContext *pCtx,
                                      QCBORItem          *pNumber);

#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT  */
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */


/**
 * @brief Decode a preferred serialization big number.
 *
 * @param[in] Item              The number to process.
 * @param[in] BigNumberBuf      The buffer to output to.
 * @param[out] pBigNumber       The resulting big number.
 * @param[in,out] pbIsNegative  The sign of the resulting big number.
 *
 * This exists to process a @ref QCBORItem that is expected to be a
 * big number encoded with preferred serialization. This will turn the
 * types listed in the table below into a big number. In particular it
 * will apply the offset of one needed to get the actual value for
 * @ref QCBOR_TYPE_NEGBIGNUM.  Leading zeros are removed. The value 0
 * is always returned as a one-byte big number with the value 0x00.
 *
 *| Type |
 * | ---- |
 * | @ref QCBOR_TYPE_INT64 |
 * | @ref QCBOR_TYPE_UINT64 |
 * | @ref QCBOR_TYPE_65BIT_NEG_INT |
 * | @ref QCBOR_TYPE_POSBIGNUM |
 * | @ref QCBOR_TYPE_NEGBIGNUM |
 * | @ref QCBOR_TYPE_BYTE_STRING |
 * | ---- |
 *
 * For the type @ref QCBOR_TYPE_BYTES, @c pIsNegative becomes an in
 * parameter indicating the sign.
 *
 * If @c BigNumberBuf is too small, @c pBigNum.ptr will be @c NULL and
 * @c pBigNum.len reports the required length. Note that the size of
 * the output buffer, @c *pBigNumberBuf, should be 1 byte larger than
 * the size of the @c Item.val.bignum when the input @c Item is @ref
 * QCBOR_TYPE_NEGBIGNUM because the application of the offset of one
 * for negative numbers may have an arithmetic carry. A way to size
 * the output buffer is MIN(9, Item.val.bignum.len + 1). 9 comes from
 * the length of they type @ref QCBOR_TYPE_65BIT_NEG plus the
 * possibility of an arithmetic carry.
 *
 * The object code for this is surprisingly large at about 1KB.  This
 * is to apply the offset of one for the negative values and to
 * operate all the data types used by big number specific preferred
 * serialization.
 *
 * See @ref BigNumbers for a useful overview of CBOR big numbers and
 * QCBOR's support for them. See also
 * QCBORDecode_ProcessBigNumberNoPreferred(),
 * QCBORDecode_GetTBigNumber() and QCBOREncode_AddTBigNumber().
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
 * allow @ref QCBOR_TYPE_INT64, @ref QCBOR_TYPE_UINT64 and @ref
 * QCBOR_TYPE_65BIT_NEG_INT.
 */
QCBORError
QCBORDecode_ProcessBigNumberNoPreferred(const QCBORItem Item,
                                        UsefulBuf       BigNumberBuf,
                                        UsefulBufC     *pBigNumber,
                                        bool           *pbIsNegative);





/**
 * @brief Decode next item as a big number encoded using preferred serialization.
 *
 * @param[in] pCtx              The decode context.
 * @param[in] uTagRequirement   @ref QCBOR_TAG_REQUIREMENT_TAG or related.
 * @param[in] BigNumberBuf      The buffer to write the result into.
 * @param[out] pBigNumber       The decoded big number, most significant
 *                              byte first (network byte order).
 * @param[in,out] pbIsNegative  Set to true if the resulting big number is negative.
 *
 * This decodes CBOR tag numbers 2 and 3, positive and negative big
 * numbers, as defined in [RFC 8949 section 3.4.3]
 * (https://www.rfc-editor.org/rfc/rfc8949.html#section-3.4.3).  This
 * decodes preferred serialization described specifically for big
 * numbers.
 *
 * See QCBORDecode_PreferedBigNumber() which performs the bulk of this.
 *
 * The type processing rules are as follows.
 *
 * This always succeeds on type 0 and 1 integers (@ref QCBOR_TYPE_INT64,
 * @ref QCBOR_TYPE_UINT64 and @ref QCBOR_TYPE_65BIT_NEG_INT) no matter what
 * @c uTagRequirement is. The rest of the rules pertain to what happens
 * if the CBOR is not type 0 or type 1.
 *
 * If @c uTagRequirement is @ref QCBOR_TAG_REQUIREMENT_TAG, this
 * expects a full tag 2 or tag 3 big number.
 *
 * If @c uTagRequreiement is @ref QCBOR_TAG_REQUIREMENT_NOT_A_TAG then
 * this expects a byte string.
 *
 * If @ref QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG, then this will succeed on
 * either a byte string or a tag 2 or 3.
 *
 * If the item is a bare byte string, not a tag 2 or 3, then
 * @c pbIsNegative is an input parameter that determines the sign of the
 * big number. The sign must be known because the decoding of a
 * positive big number is different than a negative.
 *
 * This works whether or not QCBORDecode_StringsTagCB() is installed
 * to process tags 2 and 3.
 *
 * See @ref BigNumbers for a useful overview of CBOR big numbers and
 * QCBOR's support for them. See QCBOREncode_AddTBigNumber(), the
 * encode counter part for this. See also
 * QCBORDecode_GetTBigNumberNoPreferred() and
 * QCBORDecode_GetTBigNumberRaw().
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 */
void
QCBORDecode_GetTBigNumber(QCBORDecodeContext *pCtx,
                          const uint8_t       uTagRequirement,
                          UsefulBuf           BigNumberBuf,
                          UsefulBufC         *pBigNumber,
                          bool               *pbIsNegative);

void
QCBORDecode_GetTBigNumberInMapN(QCBORDecodeContext *pCtx,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                UsefulBuf           BigNumberBuf,
                                UsefulBufC         *pBigNumber,
                                bool               *pbIsNegative);

void
QCBORDecode_GetTBigNumberInMapSZ(QCBORDecodeContext *pCtx,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBuf           BigNumberBuf,
                                 UsefulBufC         *pBigNumber,
                                 bool               *pbIsNegative);


/**
 * @brief Decode next item as a big number without preferred serialization.
 *
 * @param[in] pCtx              The decode context.
 * @param[in] uTagRequirement   @ref QCBOR_TAG_REQUIREMENT_TAG or related.
 * @param[in] BigNumberBuf      The buffer to write the result into.
 * @param[out] pBigNumber       The decoded big number, most significant
 *                              byte first (network byte order).
 * @param[in,out] pbIsNegative  Set to true if the returned big number is negative.
 *
 * This is the same as QCBORDecode_GetTBigNumber(), but will error out
 * on type 0 and 1 integers as it doesn't support the preferred
 * serialization specific for big numbers.
 *
 * See @ref BigNumbers for a useful overview of CBOR big numbers and
 * QCBOR's support for them. See QCBOREncode_AddTBigNumberNoPreferred(),
 * the encode counter part for this. See also QCBORDecode_GetTBigNumber()
 * and QCBORDecode_GetTBigNumberRaw().
 */
void
QCBORDecode_GetTBigNumberNoPreferred(QCBORDecodeContext *pCtx,
                                     const uint8_t       uTagRequirement,
                                     UsefulBuf           BigNumberBuf,
                                     UsefulBufC         *pBigNumber,
                                     bool               *pbIsNegative);

void
QCBORDecode_GetTBigNumberNoPreferredInMapN(QCBORDecodeContext *pCtx,
                                          int64_t             nLabel,
                                          uint8_t             uTagRequirement,
                                          UsefulBuf           BigNumberBuf,
                                          UsefulBufC         *pBigNumber,
                                          bool               *pbIsNegative);

void
QCBORDecode_GetTBigNumberNoPreferredInMapSZ(QCBORDecodeContext *pCtx,
                                           const char         *szLabel,
                                           uint8_t             uTagRequirement,
                                           UsefulBuf           BigNumberBuf,
                                           UsefulBufC         *pBigNumber,
                                           bool               *pbIsNegative);


 /**
  * @brief Decode the next item as a big number with no processing
  *
  * @param[in] pCtx             The decode context.
  * @param[in] uTagRequirement  @ref QCBOR_TAG_REQUIREMENT_TAG or related.
  * @param[out] pBigNumber          The decoded big number, most significant
  * byte first (network byte order).
  * @param[out] pbIsNegative    Is @c true if the big number is negative. This
  *                             is only valid when @c uTagRequirement is
  *                             @ref QCBOR_TAG_REQUIREMENT_TAG.
  *
  * This decodes CBOR tag numbers 2 and 3, positive and negative big
  * numbers, as defined in [RFC 8949 section 3.4.3]
  * (https://www.rfc-editor.org/rfc/rfc8949.html#section-3.4.3).
  *
  * This returns the byte string representing the big number
  * directly. It does not apply the required the offset of one for
  * negative big numbers. It will error out big numbers that have been
  * encoded as type 0 and 1 integer because of big number preferred
  * serialization.
  *
  * This is most useful when a big number library has been linked, and
  * it can be (trivially) used to perform the offset of one for
  * negative numbers.
  *
  * This links in much less object code than QCBORDecode_GetTBigNumber() and
  * QCBORDecode_GetTBigNumberNoPreferred().
  *
  * This does the same minimal processing as installing QCBORDecode_StringsTagCB()
  * installed to handle @ref CBOR_TAG_POS_BIGNUM and @ref CBOR_TAG_NEG_BIGNUM
  * so QCBORDecode_VGetNext() returns a @ref QCBORItem of type
  * @ref QCBOR_TYPE_POSBIGNUM or @ref QCBOR_TYPE_POSBIGNUM
  *
  * See @ref BigNumbers for a useful overview of CBOR big numbers and
  * QCBOR's support for them. See QCBOREncode_AddTBigNumberRaw() for
  * the encoding counter part. See QCBORDecode_GetTBigNumber() which
  * does perform the offset for negative numbers and handles preferred
  * serialization big numbers.
  *
  * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
  *
  * See @ref Tag-Usage for discussion on tag requirements.
  */
void
QCBORDecode_GetTBigNumberRaw(QCBORDecodeContext *pCtx,
                             const uint8_t       uTagRequirement,
                             UsefulBufC         *pBigNumber,
                             bool               *pbIsNegative);

void
QCBORDecode_GetTBigNumberRawInMapN(QCBORDecodeContext *pMe,
                                   const int64_t       nLabel,
                                   const uint8_t       uTagRequirement,
                                   UsefulBufC         *pBigNumber,
                                   bool               *pbIsNegative);

void
QCBORDecode_GetTBigNumberRawInMapSZ(QCBORDecodeContext *pMe,
                                   const char        *szLabel,
                                   const uint8_t       uTagRequirement,
                                   UsefulBufC         *pBigNumber,
                                   bool               *pbIsNegative);





#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
/**
 * @brief Decode the next item as a decimal fraction.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pnMantissa      The mantissa.
 * @param[out] pnExponent      The base 10 exponent.
 *
 * The input to decode must be a decimal fraction as defined in
 * [RFC 8949 section 3.4.4]
 * (https://www.rfc-editor.org/rfc/rfc8949.html#section-3.4.4).  That
 * is, an array of two numbers, the first of which is the exponent and
 * the second is the mantissa.
 *
 * Depending on @c uTagRequirement, the tag number
 * @ref CBOR_TAG_DECIMAL_FRACTION (4) may or may not need to be
 * present before the array. See @ref Tag-Usage.
 *
 * The exponent must always be an integer (CBOR type 0 or 1). The
 * mantissa may be an integer or a big number. If it is a big number,
 * the tag number 2 or 3 must be present.
 *
 * The exponent is limited to between @c INT64_MIN and
 * @c INT64_MAX while CBOR allows the range of @c -UINT64_MAX to @c UINT64_MAX.
 *
 * The mantissa is always returned as an @c int64_t.  If the value
 * won't fit, @ref QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW will be
 * set. Use QCBORDecode_GetTDecimalFractionBigMantissa() to avoid the
 * limit to @c int64_t.
 *
 * The value of this is computed by:
 *
 *     mantissa * ( 10 ** exponent )
 *
 * Various format and type issues will result in @ref QCBOR_ERR_BAD_EXP_AND_MANTISSA
 * being set.  See @ref Decode-Errors-Overview "Decode Errors
 * Overview".
 *
 * See also QCBORDecode_GetInt64ConvertAll(),
 * QCBORDecode_GetUInt64ConvertAll() and
 * QCBORDecode_GetDoubleConvertAll() which can also decode decimal
 * fractions.
 *
 * See also @ref CBOR_TAG_DECIMAL_FRACTION,
 * QCBOREncode_AddTDecimalFraction(), @ref QCBOR_TYPE_DECIMAL_FRACTION.
 *
 * If QCBOR_DISABLE_TAGS is set, the only input this will decode is an
 * array of two integers. It will set an error if the the array is
 * preceded by by a tag number or if the mantissa is a big number.
 */
void
QCBORDecode_GetTDecimalFraction(QCBORDecodeContext *pCtx,
                                uint8_t             uTagRequirement,
                                int64_t            *pnMantissa,
                                int64_t            *pnExponent);

void
QCBORDecode_GetTDecimalFractionInMapN(QCBORDecodeContext *pCtx,
                                      int64_t             nLabel,
                                      uint8_t             uTagRequirement,
                                      int64_t            *pnMantissa,
                                      int64_t            *pnExponent);

void
QCBORDecode_GetTDecimalFractionInMapSZ(QCBORDecodeContext *pMe,
                                       const char         *szLabel,
                                       uint8_t             uTagRequirement,
                                       int64_t            *pnMantissa,
                                       int64_t            *pnExponent);

/**
 * @brief Decode the next item as a decimal fraction with a big number mantissa.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[in] MantissaBuffer   The buffer in which to put the mantissa.
 * @param[out] pMantissa       The big num mantissa.
 * @param[out] pbMantissaIsNegative  Is @c true if @c pMantissa is negative.
 * @param[out] pnExponent      The base 10 exponent.
 *
 * This is the same as QCBORDecode_GetTDecimalFraction() except the
 * mantissa is returned as a big number.
 *
 * In the encoded CBOR, the mantissa may be a type 0 (positive
 * integer), type 1 (negative integer), type 2 tag 2 (positive big
 * number) or type 2 tag 3 (negative big number). This implementation
 * will convert all these to a big number. The limit to this
 * conversion is the size of @c MantissaBuffer.
 *
 * See also QCBORDecode_GetInt64ConvertAll(),
 * QCBORDecode_GetUInt64ConvertAll() and
 * QCBORDecode_GetDoubleConvertAll() which can convert decimal
 * fractions.
 *
 * See also @ref CBOR_TAG_DECIMAL_FRACTION,
 * QCBOREncode_AddTDecimalFractionBigMantissa(), @ref QCBOR_TYPE_DECIMAL_FRACTION
 * and QCBORDecode_GetTDecimalFraction().
 */
void
QCBORDecode_GetTDecimalFractionBigMantissa(QCBORDecodeContext *pCtx,
                                           uint8_t             uTagRequirement,
                                           UsefulBuf           MantissaBuffer,
                                           UsefulBufC         *pMantissa,
                                           bool               *pbMantissaIsNegative,
                                           int64_t            *pnExponent);

void
QCBORDecode_GetTDecimalFractionBigMantissaInMapN(QCBORDecodeContext *pCtx,
                                                 int64_t             nLabel,
                                                 uint8_t             uTagRequirement,
                                                 UsefulBuf           MantissaBuffer,
                                                 UsefulBufC         *pbMantissaIsNegative,
                                                 bool               *pbIsNegative,
                                                 int64_t            *pnExponent);

void
QCBORDecode_GetTDecimalFractionBigMantissaInMapSZ(QCBORDecodeContext *pCtx,
                                                  const char         *szLabel,
                                                  uint8_t             uTagRequirement,
                                                  UsefulBuf           MantissaBuffer,
                                                  UsefulBufC         *pMantissa,
                                                  bool               *pbMantissaIsNegative,
                                                  int64_t            *pnExponent);


/**
 * @brief Decode the next item as a decimal fraction with a big number mantissa raw.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[in] MantissaBuffer   The buffer in which to put the mantissa.
 * @param[out] pMantissa       The big num mantissa.
 * @param[out] pbMantissaIsNegative  Is @c true if @c pMantissa is negative.
 * @param[out] pnExponent      The base 10 exponent.
 *
 * This is the same as QCBORDecode_GetTDecimalFractionBigMantissa() except the
 * negative mantissas are NOT offset by one and this links in less object code.
 *
 * In the encoded CBOR, the mantissa may be a type 0 (positive
 * integer), type 1 (negative integer), type 2 tag 2 (positive big
 * number) or type 2 tag 3 (negative big number). This implementation
 * will convert all these to a big number. The limit to this
 * conversion is the size of @c MantissaBuffer.
 *
 * See also QCBORDecode_GetInt64ConvertAll(),
 * QCBORDecode_GetUInt64ConvertAll() and
 * QCBORDecode_GetDoubleConvertAll() which can convert decimal
 * fractions.
 *
 * See also @ref CBOR_TAG_DECIMAL_FRACTION,
 * QCBOREncode_AddTDecimalFractionBigMantissaRaw(), @ref QCBOR_TYPE_DECIMAL_FRACTION
 * and QCBORDecode_GetTDecimalFractionBigMantissa().
 */
void
QCBORDecode_GetTDecimalFractionBigMantissaRaw(QCBORDecodeContext *pCtx,
                                              uint8_t             uTagRequirement,
                                              UsefulBuf           MantissaBuffer,
                                              UsefulBufC         *pMantissa,
                                              bool               *pbMantissaIsNegative,
                                              int64_t            *pnExponent);

void
QCBORDecode_GetTDecimalFractionBigMantissaRawInMapN(QCBORDecodeContext *pCtx,
                                                    int64_t             nLabel,
                                                    uint8_t             uTagRequirement,
                                                    UsefulBuf           MantissaBuffer,
                                                    UsefulBufC         *pbMantissaIsNegative,
                                                    bool               *pbIsNegative,
                                                    int64_t            *pnExponent);

void
QCBORDecode_GetTDecimalFractionBigMantissaRawInMapSZ(QCBORDecodeContext *pCtx,
                                                     const char         *szLabel,
                                                     uint8_t             uTagRequirement,
                                                     UsefulBuf           MantissaBuffer,
                                                     UsefulBufC         *pMantissa,
                                                     bool               *pbMantissaIsNegative,
                                                     int64_t            *pnExponent);


/**
 * @brief Decode the next item as a big float.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pnMantissa      The mantissa.
 * @param[out] pnExponent      The base 2 exponent.
 *
 * The input to decode must be a big float defined in [RFC 8949 section 3.4.4]
 * (https://www.rfc-editor.org/rfc/rfc8949.html#section-3.4.4).  That
 * is, an array of two numbers, the first of which is the exponent and
 * the second is the mantissa.
 *
 * Depending on @c uTagRequirement, the tag number
 * @ref CBOR_TAG_BIG_FLOAT (5) may or may not need to be present
 * before the array. See @ref Tag-Usage.
 *
 * The exponent must always be an integer (CBOR type 0 or 1). The
 * mantissa may be an integer or a big number. If it is a big number,
 * the tag number 2 or 3 must be present.
 *
 * This implementation limits the exponent to between @c INT64_MIN and
 * @c INT64_MAX while CBOR allows the range of @c -UINT64_MAX to @c UINT64_MAX.
 *
 * The mantissa is always returned as an @c int64_t.  If the value
 * won't fit, @ref QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW will be
 * set. Use QCBORDecode_GetBigFloastBigNumber() to avoid the
 * limit to @c int64_t.
 *
 *     mantissa * ( 2 ** exponent )
 *
 * Various format and type issues will result in
 * @ref  QCBOR_ERR_BAD_EXP_AND_MANTISSA being set. See
 * @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_GetInt64ConvertAll(),
 * QCBORDecode_GetUInt64ConvertAll() and
 * QCBORDecode_GetDoubleConvertAll() which can convert big floats.
 *
 * See also @ref CBOR_TAG_BIGFLOAT, QCBOREncode_AddTBigFloat(),
 * @ref QCBOR_TYPE_BIGFLOAT and QCBORDecode_GetTBigFloatBigMantissa().
 *
 * If QCBOR_DISABLE_TAGS is set, the only input this will decode is an
 * array of two integers. It will set an error if the the array is
 * preceded by by a tag number or if the mantissa is a big number.
 */
void
QCBORDecode_GetTBigFloat(QCBORDecodeContext *pCtx,
                         uint8_t             uTagRequirement,
                         int64_t            *pnMantissa,
                         int64_t            *pnExponent);

void
QCBORDecode_GetTBigFloatInMapN(QCBORDecodeContext *pCtx,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnMantissa,
                               int64_t            *pnExponent);

void
QCBORDecode_GetTBigFloatInMapSZ(QCBORDecodeContext *pCtx,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                int64_t            *pnMantissa,
                                int64_t            *pnExponent);


/**
 * @brief Decode the next item as a big float with a big number mantissa.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[in] MantissaBuffer   The buffer in which to put the mantissa.
 * @param[out] pMantissa       The big num mantissa.
 * @param[out] pbMantissaIsNegative  Is @c true if @c pMantissa is negative.
 * @param[out] pnExponent      The base 2 exponent.
 *
 * This is the same as QCBORDecode_GetTBigFloat() except the mantissa
 * is returned as a big number. The only limit to precision is the
 * size of @c MantissaBuffer.
 *
 * The encoded mantissa may be an integer or a big number.  The
 * standard CBOR offset of 1 for negative is applied, so the mantissa can be used as
 * returned.
 *
 * See also @ref CBOR_TAG_BIGFLOAT,
 * QCBOREncode_AddTBigFloatBigNumber(), @ref QCBOR_TYPE_BIGFLOAT and
 * QCBORDecode_GetTBigFloat().
 */
void
QCBORDecode_GetTBigFloatBigMantissa(QCBORDecodeContext *pCtx,
                                    uint8_t             uTagRequirement,
                                    UsefulBuf           MantissaBuffer,
                                    UsefulBufC         *pMantissa,
                                    bool               *pbMantissaIsNegative,
                                    int64_t            *pnExponent);


void
QCBORDecode_GetTBigFloatBigMantissaInMapN(QCBORDecodeContext *pCtx,
                                          int64_t             nLabel,
                                          uint8_t             uTagRequirement,
                                          UsefulBuf           MantissaBuffer,
                                          UsefulBufC         *pMantissa,
                                          bool               *pbMantissaIsNegative,
                                          int64_t            *pnExponent);

void
QCBORDecode_GetTBigFloatBigMantissaInMapSZ(QCBORDecodeContext *pCtx,
                                           const char         *szLabel,
                                           uint8_t             uTagRequirement,
                                           UsefulBuf           MantissaBuffer,
                                           UsefulBufC         *pMantissa,
                                           bool               *pbMantissaIsNegative,
                                           int64_t            *pnExponent);


/**
 * @brief Decode the next item as a big float with a big number mantissa with out offsetting the mantissa
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[in] MantissaBuffer   The buffer in which to put the mantissa.
 * @param[out] pMantissa       The big num mantissa.
 * @param[out] pbMantissaIsNegative  Is @c true if @c pMantissa is negative.
 * @param[out] pnExponent      The base 2 exponent.
 *
 * This is the same as QCBORDecode_GetBigFloat() except the mantissa
 * is returned as a big number. The only limit to precision is the
 * size of @c MantissaBuffer.
 *
 * The encoded mantissa may be an integer or a big number.  The
 * standard CBOR offset of 1 for negative is NOT applied. If the ma
 * mantissa is negative, one must be added to get it's actual value.
 *
 * Because this doesn't offset the negative big numbers, this links in
 * a lot less object code. It is suitable for uses where a big number
 * library is already linked in for other purposes as it can trivially
 * do the increment by one.
 *
 * See also @ref CBOR_TAG_BIGFLOAT,
 * QCBOREncode_AddTBigFloatBigNumber(), @ref QCBOR_TYPE_BIGFLOAT and
 * QCBORDecode_GetTBigFloat().
 */
void
QCBORDecode_GetTBigFloatBigMantissaRaw(QCBORDecodeContext *pCtx,
                                       uint8_t             uTagRequirement,
                                       UsefulBuf           MantissaBuffer,
                                       UsefulBufC         *pMantissa,
                                       bool               *pbMantissaIsNegative,
                                       int64_t            *pnExponent);


void
QCBORDecode_GetTBigFloatBigMantissaRawInMapN(QCBORDecodeContext *pCtx,
                                             int64_t             nLabel,
                                             uint8_t             uTagRequirement,
                                             UsefulBuf           MantissaBuffer,
                                             UsefulBufC         *pMantissa,
                                             bool               *pbMantissaIsNegative,
                                             int64_t            *pnExponent);

void
QCBORDecode_GetTBigFloatBigMantissaRawInMapSZ(QCBORDecodeContext *pCtx,
                                              const char         *szLabel,
                                              uint8_t             uTagRequirement,
                                              UsefulBuf           MantissaBuffer,
                                              UsefulBufC         *pMantissa,
                                              bool               *pbMantissaIsNegative,
                                              int64_t            *pnExponent);

#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */


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
 *    BEGINNING OF DEPRECATED FUNCTION DECLARATIONS                          *
 *                                                                           *
 *    There is no plan to remove these in future versions.                   *
 *    They just have been replaced by something better.                      *
 * ========================================================================= */


/* Deprecated. Use QCBORDecode_GetTBigNumberRaw() instead. */
static void
QCBORDecode_GetBignum(QCBORDecodeContext *pCtx,
                      uint8_t             uTagRequirement,
                      UsefulBufC         *pValue,
                      bool               *pbIsNegative);

/* Deprecated. Use QCBORDecode_GetTBigNumberRawInMapN() instead. */
static void
QCBORDecode_GetBignumInMapN(QCBORDecodeContext *pCtx,
                            int64_t             nLabel,
                            uint8_t             uTagRequirement,
                            UsefulBufC         *pValue,
                            bool               *pbIsNegative);

/* Deprecated. Use QCBORDecode_GetTBigNumberRawInMapSZ() instead. */
static void
QCBORDecode_GetBignumInMapSZ(QCBORDecodeContext *pCtx,
                             const char         *szLabel,
                             uint8_t             uTagRequirement,
                             UsefulBufC         *pValue,
                             bool               *pbIsNegative);

#ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
/* Deprecated. Use QCBORDecode_GetTDecimalFraction() instead. */
static void
QCBORDecode_GetDecimalFraction(QCBORDecodeContext *pCtx,
                               uint8_t             uTagRequirement,
                               int64_t            *pnMantissa,
                               int64_t            *pnExponent);

/* Deprecated. Use QCBORDecode_GetTDecimalFractionInMapN() instead. */
static void
QCBORDecode_GetDecimalFractionInMapN(QCBORDecodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint8_t             uTagRequirement,
                                     int64_t            *pnMantissa,
                                     int64_t            *pnExponent);

/* Deprecated. Use QCBORDecode_GetTDecimalFractionInMapSZ() instead. */
static void
QCBORDecode_GetDecimalFractionInMapSZ(QCBORDecodeContext *pMe,
                                      const char         *szLabel,
                                      uint8_t             uTagRequirement,
                                      int64_t            *pnMantissa,
                                      int64_t            *pnExponent);

/* Deprecated. Use QCBORDecode_GetTDecimalFractionBigMantissaRaw() instead. */
/*
 TODO: integrate this comment better
* For QCBOR before v1.5, this function had a bug where
* by the negative mantissa sometimes had the offset of
* one applied, making this function somewhat usless for
* negative mantissas. Specifically if the to-be-decode CBOR
* was a type 1 integer the offset was applied and when it
* was a tag 3, the offset was not applied. It is possible
* that a tag 3 could contain a value in the range of a type 1
* integer. @ref QCBORExpAndMantissa is
* correct and can be used instead of this. */
static void
QCBORDecode_GetDecimalFractionBig(QCBORDecodeContext *pCtx,
                                  uint8_t             uTagRequirement,
                                  UsefulBuf           MantissaBuffer,
                                  UsefulBufC         *pMantissa,
                                  bool               *pbMantissaIsNegative,
                                  int64_t            *pnExponent);

/* Deprecated. Use QCBORDecode_GetTDecimalFractionBigMantissaRawInMapN() instead */
static void
QCBORDecode_GetDecimalFractionBigInMapN(QCBORDecodeContext *pCtx,
                                        int64_t             nLabel,
                                        uint8_t             uTagRequirement,
                                        UsefulBuf           MantissaBuffer,
                                        UsefulBufC         *pbMantissaIsNegative,
                                        bool               *pbIsNegative,
                                        int64_t            *pnExponent);

/* Deprecated. Use QCBORDecode_GetTDecimalFractionBigMantissaRawInMapSZ() instead. */
static void
QCBORDecode_GetDecimalFractionBigInMapSZ(QCBORDecodeContext *pCtx,
                                         const char         *szLabel,
                                         uint8_t             uTagRequirement,
                                         UsefulBuf           MantissaBuffer,
                                         UsefulBufC         *pMantissa,
                                         bool               *pbMantissaIsNegative,
                                         int64_t            *pnExponent);

/* Deprecated. Use QCBORDecode_GetTBigFloat() instead. */
static void
QCBORDecode_GetBigFloat(QCBORDecodeContext *pCtx,
                        uint8_t             uTagRequirement,
                        int64_t            *pnMantissa,
                        int64_t            *pnExponent);

/* Deprecated. Use QCBORDecode_GetTBigFloatInMapN() instead. */
static void
QCBORDecode_GetBigFloatInMapN(QCBORDecodeContext *pCtx,
                              int64_t             nLabel,
                              uint8_t             uTagRequirement,
                              int64_t            *pnMantissa,
                              int64_t            *pnExponent);

/* Deprecated. Use QCBORDecode_GetTBigFloatInMapSZ() instead. */
static void
QCBORDecode_GetBigFloatInMapSZ(QCBORDecodeContext *pCtx,
                               const char         *szLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnMantissa,
                               int64_t            *pnExponent);

/* Deprecated. Use QCBORDecode_GetTBigFloatBigMantissaRaw() instead. */
static void
QCBORDecode_GetBigFloatBig(QCBORDecodeContext *pCtx,
                           uint8_t             uTagRequirement,
                           UsefulBuf           MantissaBuffer,
                           UsefulBufC         *pMantissa,
                           bool               *pbMantissaIsNegative,
                           int64_t            *pnExponent);

/* Deprecated. Use QCBORDecode_GetTBigFloatBigMantissaRawInMapN() instead. */
static void
QCBORDecode_GetBigFloatBigInMapN(QCBORDecodeContext *pCtx,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBuf           MantissaBuffer,
                                 UsefulBufC         *pMantissa,
                                 bool               *pbMantissaIsNegative,
                                 int64_t            *pnExponent);

/* Deprecated. Use QCBORDecode_GetTBigFloatBigMantissaRawInMapSZ() instead. */
static void
QCBORDecode_GetBigFloatBigInMapSZ(QCBORDecodeContext *pCtx,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  UsefulBuf           MantissaBuffer,
                                  UsefulBufC         *pMantissa,
                                  bool               *pbMantissaIsNegative,
                                  int64_t            *pnExponent);
#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */


/* ========================================================================= *
 *    END OF DEPRECATED FUNCTION DECLARATIONS                                *
 * ========================================================================= */




/* ========================================================================= *
 *    BEGINNING OF PRIVATE INLINE IMPLEMENTATION                             *
 * ========================================================================= */


/* Semi-private funcion used by public inline functions. See qcbor_number_decode.c */
void
QCBORDecode_Private_GetUInt64Convert(QCBORDecodeContext *pCtx,
                                     uint32_t            uConvertTypes,
                                     uint64_t           *puValue,
                                     QCBORItem          *pItem);


/* Semi-private funcion used by public inline functions. See qcbor_number_decode.c */
void
QCBORDecode_Private_GetUInt64ConvertInMapN(QCBORDecodeContext *pCtx,
                                           int64_t             nLabel,
                                           uint32_t            uConvertTypes,
                                           uint64_t           *puValue,
                                           QCBORItem          *pItem);


/* Semi-private funcion used by public inline functions. See qcbor_number_decode.c */
void
QCBORDecode_Private_GetUInt64ConvertInMapSZ(QCBORDecodeContext *pCtx,
                                            const char         *szLabel,
                                            uint32_t            uConvertTypes,
                                            uint64_t           *puValue,
                                            QCBORItem          *pItem);

/* Semi-private funcion used by public inline functions. See qcbor_number_decode.c */
void
QCBORDecode_Private_GetInt64Convert(QCBORDecodeContext *pCtx,
                                    uint32_t            uConvertTypes,
                                    int64_t            *pnValue,
                                    QCBORItem          *pItem);

/* Semi-private funcion used by public inline functions. See qcbor_number_decode.c */
void
QCBORDecode_Private_GetInt64ConvertInMapN(QCBORDecodeContext *pCtx,
                                          int64_t             nLabel,
                                          uint32_t            uConvertTypes,
                                          int64_t            *pnValue,
                                          QCBORItem          *pItem);

/* Semi-private funcion used by public inline functions. See qcbor_number_decode.c */
void
QCBORDecode_Private_GetInt64ConvertInMapSZ(QCBORDecodeContext *pCtx,
                                           const char         *szLabel,
                                           uint32_t            uConvertTypes,
                                           int64_t            *pnValue,
                                           QCBORItem          *pItem);


#ifndef USEFULBUF_DISABLE_ALL_FLOAT
/* Semi-private funcion used by public inline functions. See qcbor_number_decode.c */
void
QCBORDecode_Private_GetDoubleConvert(QCBORDecodeContext *pCtx,
                                     uint32_t            uConvertTypes,
                                     double             *pValue,
                                     QCBORItem          *pItem);

/* Semi-private funcion used by public inline functions. See qcbor_number_decode.c */
void
QCBORDecode_Private_GetDoubleConvertInMapN(QCBORDecodeContext *pCtx,
                                           int64_t             nLabel,
                                           uint32_t            uConvertTypes,
                                           double             *pdValue,
                                           QCBORItem          *pItem);

/* Semi-private funcion used by public inline functions. See qcbor_number_decode.c */
void
QCBORDecode_Private_GetDoubleConvertInMapSZ(QCBORDecodeContext *pCtx,
                                            const char         *szLabel,
                                            uint32_t            uConvertTypes,
                                            double             *pdValue,
                                            QCBORItem          *pItem);
#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT */


/* Semi-private funcion used by public inline functions. See qcbor_tag_decode.c */
void
QCBORDecode_Private_GetTaggedString(QCBORDecodeContext  *pMe,
                                    uint8_t              uTagRequirement,
                                    uint8_t              uQCBOR_Type,
                                    uint64_t             uTagNumber,
                                    UsefulBufC          *pBstr);


/* Semi-private funcion used by public inline functions. See qcbor_tag_decode.c */
void
QCBORDecode_Private_GetTaggedStringInMapN(QCBORDecodeContext  *pMe,
                                          const int64_t        nLabel,
                                          const uint8_t        uTagRequirement,
                                          const uint8_t        uQCBOR_Type,
                                          const uint64_t       uTagNumber,
                                          UsefulBufC          *pString);


/* Semi-private funcion used by public inline functions. See qcbor_tag_decode.c */
void
QCBORDecode_Private_GetTaggedStringInMapSZ(QCBORDecodeContext  *pMe,
                                           const char          *szLabel,
                                           uint8_t              uTagRequirement,
                                           uint8_t              uQCBOR_Type,
                                           uint64_t             uTagNumber,
                                           UsefulBufC          *pString);




static inline void
QCBORDecode_GetUInt64Convert(QCBORDecodeContext *pMe,
                             const uint32_t     uConvertTypes,
                             uint64_t           *puValue)
{
    QCBORItem Item;
    QCBORDecode_Private_GetUInt64Convert(pMe, uConvertTypes, puValue, &Item);
}

static inline void
QCBORDecode_GetUInt64ConvertInMapN(QCBORDecodeContext *pMe,
                                   const int64_t       nLabel,
                                   const uint32_t      uConvertTypes,
                                   uint64_t           *puValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetUInt64ConvertInMapN(pMe,
                                              nLabel,
                                              uConvertTypes,
                                              puValue,
                                              &Item);
}

static inline void
QCBORDecode_GetUInt64ConvertInMapSZ(QCBORDecodeContext *pMe,
                                    const char         *szLabel,
                                    const uint32_t     uConvertTypes,
                                    uint64_t           *puValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetUInt64ConvertInMapSZ(pMe,
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

static inline void
QCBORDecode_GetUInt64InMapN(QCBORDecodeContext *pMe,
                            const int64_t       nLabel,
                            uint64_t           *puValue)
{
   QCBORDecode_GetUInt64ConvertInMapN(pMe,
                                      nLabel,
                                      QCBOR_CONVERT_TYPE_XINT64,
                                      puValue);
}

static inline void
QCBORDecode_GetUInt64InMapSZ(QCBORDecodeContext *pMe,
                             const char         *szLabel,
                             uint64_t           *puValue)
{
   QCBORDecode_GetUInt64ConvertInMapSZ(pMe,
                                       szLabel,
                                       QCBOR_CONVERT_TYPE_XINT64,
                                       puValue);
}



static inline void
QCBORDecode_GetInt64Convert(QCBORDecodeContext *pMe,
                            const uint32_t      uConvertTypes,
                            int64_t            *pnValue)
{
    QCBORItem Item;
    QCBORDecode_Private_GetInt64Convert(pMe, uConvertTypes, pnValue, &Item);
}

static inline void
QCBORDecode_GetInt64ConvertInMapN(QCBORDecodeContext *pMe,
                                  const int64_t       nLabel,
                                  const uint32_t      uConvertTypes,
                                  int64_t            *pnValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetInt64ConvertInMapN(pMe,
                                             nLabel,
                                             uConvertTypes,
                                             pnValue,
                                             &Item);
}

static inline void
QCBORDecode_GetInt64ConvertInMapSZ(QCBORDecodeContext *pMe,
                                   const char         *szLabel,
                                   const uint32_t     uConvertTypes,
                                   int64_t            *pnValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetInt64ConvertInMapSZ(pMe,
                                              szLabel,
                                              uConvertTypes,
                                              pnValue,
                                              &Item);
}

static inline void
QCBORDecode_GetInt64(QCBORDecodeContext *pMe, int64_t *pnValue)
{
    QCBORDecode_GetInt64Convert(pMe, QCBOR_CONVERT_TYPE_XINT64, pnValue);
}

static inline void
QCBORDecode_GetInt64InMapN(QCBORDecodeContext *pMe,
                           const int64_t       nLabel,
                           int64_t            *pnValue)
{
   QCBORDecode_GetInt64ConvertInMapN(pMe,
                                     nLabel,
                                     QCBOR_CONVERT_TYPE_XINT64,
                                     pnValue);
}

static inline void
QCBORDecode_GetInt64InMapSZ(QCBORDecodeContext *pMe,
                            const char         *szLabel,
                            int64_t            *pnValue)
{
   QCBORDecode_GetInt64ConvertInMapSZ(pMe,
                                      szLabel,
                                      QCBOR_CONVERT_TYPE_XINT64,
                                      pnValue);
}



#ifndef USEFULBUF_DISABLE_ALL_FLOAT
static inline void
QCBORDecode_GetDoubleConvert(QCBORDecodeContext *pMe,
                             const uint32_t      uConvertTypes,
                             double             *pdValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetDoubleConvert(pMe, uConvertTypes, pdValue, &Item);
}

static inline void
QCBORDecode_GetDoubleConvertInMapN(QCBORDecodeContext *pMe,
                                   const int64_t       nLabel,
                                   uint32_t            uConvertTypes,
                                   double             *pdValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetDoubleConvertInMapN(pMe,
                                              nLabel,
                                              uConvertTypes,
                                              pdValue,
                                              &Item);
}

static inline void
QCBORDecode_GetDoubleConvertInMapSZ(QCBORDecodeContext *pMe,
                                    const char         *szLabel,
                                    const uint32_t      uConvertTypes,
                                    double             *pdValue)
{
   QCBORItem Item;
   QCBORDecode_Private_GetDoubleConvertInMapSZ(pMe,
                                               szLabel,
                                               uConvertTypes,
                                               pdValue,
                                               &Item);
}

static inline void
QCBORDecode_GetDouble(QCBORDecodeContext *pMe, double *pValue)
{
   QCBORDecode_GetDoubleConvert(pMe, QCBOR_CONVERT_TYPE_FLOAT, pValue);
}

static inline void
QCBORDecode_GetDoubleInMapN(QCBORDecodeContext *pMe,
                            const int64_t       nLabel,
                            double             *pdValue)
{
   QCBORDecode_GetDoubleConvertInMapN(pMe,
                                      nLabel,
                                      QCBOR_CONVERT_TYPE_FLOAT,
                                      pdValue);
}

static inline void
QCBORDecode_GetDoubleInMapSZ(QCBORDecodeContext *pMe,
                             const char         *szLabel,
                             double             *pdValue)
{
   QCBORDecode_GetDoubleConvertInMapSZ(pMe,
                                       szLabel,
                                       QCBOR_CONVERT_TYPE_FLOAT,
                                       pdValue);
}
#endif /* USEFULBUF_DISABLE_ALL_FLOAT */




/* ======================================================================== *
 *    END OF PRIVATE INLINE IMPLEMENTATION                                  *
 * ======================================================================== */




/* ========================================================================= *
 *    BEGINNING OF INLINES FOR DEPRECATED FUNCTIONS                          *
 * ========================================================================= */


static inline void /* Deprecated */
QCBORDecode_GetBignum(QCBORDecodeContext *pMe,
                      uint8_t             uTagRequirement,
                      UsefulBufC         *pBigNumber,
                      bool               *pbIsNegative)
{
   QCBORDecode_GetTBigNumberRaw(pMe, uTagRequirement, pBigNumber, pbIsNegative);
}

static inline void /* Deprecated */
QCBORDecode_GetBignumInMapN(QCBORDecodeContext *pMe,
                            int64_t             nLabel,
                            uint8_t             uTagRequirement,
                            UsefulBufC         *pBigNumber,
                            bool               *pbIsNegative)
{
   QCBORDecode_GetTBigNumberRawInMapN(pMe, nLabel, uTagRequirement, pBigNumber, pbIsNegative);
}

static inline void /* Deprecated */
QCBORDecode_GetBignumInMapSZ(QCBORDecodeContext *pMe,
                             const char         *szLabel,
                             uint8_t             uTagRequirement,
                             UsefulBufC         *pBigNumber,
                             bool               *pbIsNegative)
{
   QCBORDecode_GetTBigNumberRawInMapSZ(pMe, szLabel, uTagRequirement, pBigNumber, pbIsNegative);
}

#ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
static inline void /* Deprecated */
QCBORDecode_GetDecimalFraction(QCBORDecodeContext *pMe,
                               uint8_t             uTagRequirement,
                               int64_t            *pnMantissa,
                               int64_t            *pnExponent)
{
   QCBORDecode_GetTDecimalFraction(pMe, uTagRequirement, pnMantissa, pnExponent);
}

static inline void /* Deprecated */
QCBORDecode_GetDecimalFractionInMapN(QCBORDecodeContext *pMe,
                                     int64_t             nLabel,
                                     uint8_t             uTagRequirement,
                                     int64_t            *pnMantissa,
                                     int64_t            *pnExponent)
{
   QCBORDecode_GetTDecimalFractionInMapN(pMe, nLabel, uTagRequirement, pnMantissa, pnExponent);
}

static inline void /* Deprecated */
QCBORDecode_GetDecimalFractionInMapSZ(QCBORDecodeContext *pMe,
                                      const char         *szLabel,
                                      uint8_t             uTagRequirement,
                                      int64_t            *pnMantissa,
                                      int64_t            *pnExponent)
{
   QCBORDecode_GetTDecimalFractionInMapSZ(pMe, szLabel, uTagRequirement, pnMantissa, pnExponent);
}


static inline void /* Deprecated */
QCBORDecode_GetDecimalFractionBig(QCBORDecodeContext *pMe,
                                  uint8_t             uTagRequirement,
                                  UsefulBuf           MantissaBuffer,
                                  UsefulBufC         *pMantissa,
                                  bool               *pbMantissaIsNegative,
                                  int64_t            *pnExponent)
{
   QCBORDecode_GetTDecimalFractionBigMantissaRaw(pMe, uTagRequirement, MantissaBuffer, pMantissa, pbMantissaIsNegative, pnExponent);
}

static inline void /* Deprecated */
QCBORDecode_GetDecimalFractionBigInMapN(QCBORDecodeContext *pMe,
                                        int64_t             nLabel,
                                        uint8_t             uTagRequirement,
                                        UsefulBuf           MantissaBuffer,
                                        UsefulBufC         *pMantissa,
                                        bool               *pbMantissaIsNegative,
                                        int64_t            *pnExponent)
{
   QCBORDecode_GetTDecimalFractionBigMantissaRawInMapN(pMe,
                                                       nLabel,
                                                       uTagRequirement,
                                                       MantissaBuffer,
                                                       pMantissa,
                                                       pbMantissaIsNegative,
                                                       pnExponent);
}

static inline void /* Deprecated */
QCBORDecode_GetDecimalFractionBigInMapSZ(QCBORDecodeContext *pMe,
                                         const char         *szLabel,
                                         uint8_t             uTagRequirement,
                                         UsefulBuf           MantissaBuffer,
                                         UsefulBufC         *pMantissa,
                                         bool               *pbMantissaIsNegative,
                                         int64_t            *pnExponent)
{
   QCBORDecode_GetTDecimalFractionBigMantissaRawInMapSZ(pMe, szLabel, uTagRequirement, MantissaBuffer, pMantissa, pbMantissaIsNegative, pnExponent);

}

static inline void /* Deprecated */
QCBORDecode_GetBigFloat(QCBORDecodeContext *pMe,
                        uint8_t             uTagRequirement,
                        int64_t            *pnMantissa,
                        int64_t            *pnExponent)
{
   QCBORDecode_GetTBigFloat(pMe, uTagRequirement, pnMantissa, pnExponent);
}

static inline void /* Deprecated */
QCBORDecode_GetBigFloatInMapN(QCBORDecodeContext *pMe,
                              int64_t             nLabel,
                              uint8_t             uTagRequirement,
                              int64_t            *pnMantissa,
                              int64_t            *pnExponent)
{
   QCBORDecode_GetTBigFloatInMapN(pMe, nLabel, uTagRequirement, pnMantissa, pnExponent);
}

static inline void /* Deprecated */
QCBORDecode_GetBigFloatInMapSZ(QCBORDecodeContext *pMe,
                               const char         *szLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnMantissa,
                               int64_t            *pnExponent)
{
   QCBORDecode_GetTBigFloatInMapSZ(pMe, szLabel, uTagRequirement, pnMantissa, pnExponent);
}

static inline void /* Deprecated */
QCBORDecode_GetBigFloatBig(QCBORDecodeContext *pMe,
                           uint8_t             uTagRequirement,
                           UsefulBuf           MantissaBuffer,
                           UsefulBufC         *pMantissa,
                           bool               *pbMantissaIsNegative,
                           int64_t            *pnExponent)
{
   QCBORDecode_GetTBigFloatBigMantissaRaw(pMe,
                                          uTagRequirement,
                                          MantissaBuffer,
                                          pMantissa,
                                          pbMantissaIsNegative,
                                          pnExponent);
}

static inline void /* Deprecated */
QCBORDecode_GetBigFloatBigInMapN(QCBORDecodeContext *pMe,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBuf           MantissaBuffer,
                                 UsefulBufC         *pMantissa,
                                 bool               *pbMantissaIsNegative,
                                 int64_t            *pnExponent)
{
   QCBORDecode_GetTBigFloatBigMantissaRawInMapN(pMe,
                                                nLabel,
                                                uTagRequirement,
                                                MantissaBuffer,
                                                pMantissa,
                                                pbMantissaIsNegative,
                                                pnExponent);
}

static inline void /* Deprecated */
QCBORDecode_GetBigFloatBigInMapSZ(QCBORDecodeContext *pMe,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  UsefulBuf           MantissaBuffer,
                                  UsefulBufC         *pMantissa,
                                  bool               *pbMantissaIsNegative,
                                  int64_t            *pnExponent)
{
   QCBORDecode_GetTBigFloatBigMantissaRawInMapSZ(pMe,
                                                 szLabel,
                                                 uTagRequirement,
                                                 MantissaBuffer,
                                                 pMantissa,
                                                 pbMantissaIsNegative,
                                                 pnExponent);
}
#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */


/* ========================================================================= *
 *    END OF INLINES FOR DEPRECATED FUNCTIONS                                *
 * ========================================================================= */


#ifdef __cplusplus
}
#endif

#endif /* qcbor_number_decode_h */
