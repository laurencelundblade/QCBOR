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

#ifndef qcbor_number_encode_h
#define qcbor_number_encode_h


#include "qcbor/qcbor_common.h"
#include "qcbor/qcbor_private.h"
#include "qcbor/qcbor_main_encode.h"
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#if 0
} // Keep editor indention formatting happy
#endif
#endif


/**
 * @file qcbor_number_encode.h
 *
 * This file contains functions for encoding numbers.
 *
 * @anchor Floating-Point
 *
 * ## Floating-Point
 *
 * By default QCBOR fully supports IEEE 754 floating-point:
 *  - Encode/decode of double, single and half-precision
 *  - CBOR preferred serialization of floating-point
 *  - Floating-point epoch dates
 *
 * For the most part, the type double is used in the interface for
 * floating-point values. In the default configuration, all decoded
 * floating-point values are returned as a double.
 *
 * With CBOR preferred serialization, the encoder outputs the smallest
 * representation of the double or float that preserves precision. Zero,
 * NaN and infinity are always output as a half-precision, each taking
 * just 2 bytes. This reduces the number of bytes needed to encode
 * double and single-precision, especially if zero, NaN and infinity are
 * frequently used.
 *
 * To avoid use of preferred serialization in the standard configuration
 * when encoding, use QCBOREncode_AddDoubleNoPreferred() or
 * QCBOREncode_AddFloatNoPreferred().
 *
 * This implementation of preferred floating-point serialization and
 * half-precision does not depend on the CPU having floating-point HW or
 * the compiler bringing in a (sometimes large) library to compensate
 * for lack of CPU support. This implementation uses shifts and masks
 * rather than floating-point functions.
 *
 * To reduce overall object code by about 900 bytes, define
 * QCBOR_DISABLE_PREFERRED_FLOAT. This will eliminate all support for
 * preferred serialization and half-precision. An error will be returned
 * when attempting to decode half-precision. A float will always be
 * encoded and decoded as 32-bits and a double will always be encoded
 * and decoded as 64 bits.
 *
 * Note that even if QCBOR_DISABLE_PREFERRED_FLOAT is not defined all
 * the float-point encoding object code can be avoided by never calling
 * any functions that encode double or float. Just not calling
 * floating-point functions will reduce object code by about 500 bytes.
 *
 * On CPUs that have no floating-point hardware,
 * QCBOR_DISABLE_FLOAT_HW_USE should be defined in most cases. If it is
 * not, then the compiler will bring in possibly large software
 * libraries to compensate. Defining QCBOR_DISABLE_FLOAT_HW_USE reduces
 * object code size on CPUs with floating-point hardware by a tiny
 * amount and eliminates the need for <math.h>
 *
 * When QCBOR_DISABLE_FLOAT_HW_USE is defined, trying to decoding
 * floating-point dates will give error
 * @ref QCBOR_ERR_FLOAT_DATE_DISABLED and decoded single-precision
 * numbers will be returned as @ref QCBOR_TYPE_FLOAT instead of
 * converting them to double as usual.
 *
 * If both QCBOR_DISABLE_FLOAT_HW_USE and QCBOR_DISABLE_PREFERRED_FLOAT
 * are defined, then the only thing QCBOR can do is encode/decode a C
 * float type as 32-bits and a C double type as 64-bits. Floating-point
 * epoch dates will be unsupported.
 *
 * If USEFULBUF_DISABLE_ALL_FLOAT is defined, then floating point
 * support is completely disabled. Decoding functions return
 * @ref QCBOR_ERR_ALL_FLOAT_DISABLED if a floating point value is
 * encountered during decoding. Functions that are encoding floating
 * point values are not available.
 */


/**
 * The size of the buffer to be passed to QCBOREncode_EncodeHead(). It
 * is one byte larger than sizeof(uint64_t) + 1, the actual maximum
 * size of the head of a CBOR data item because
 * QCBOREncode_EncodeHead() needs one extra byte to work.
 */
#define QCBOR_HEAD_BUFFER_SIZE  (sizeof(uint64_t) + 2)



/**
 * @brief  Add a signed 64-bit integer to the encoded output.
 *
 * @param[in] pCtx   The encoding context to add the integer to.
 * @param[in] nNum   The integer to add.
 *
 * The integer will be encoded and added to the CBOR output.
 *
 * This function figures out the size and the sign and encodes using
 * CBOR preferred serialization. Specifically, it will select CBOR major type
 * 0 or 1 based on sign and will encode to 1, 2, 4 or 8 bytes
 * depending on the value of the integer. Values less than 24
 * effectively encode to one byte because they are encoded in with the
 * CBOR major type. This is a neat and efficient characteristic of
 * CBOR that can be taken advantage of when designing CBOR-based
 * protocols. If integers can be kept between -23 and 23
 * they will be encoded in one byte including the major type.
 *
 * If you pass a smaller integer, like @c int16_t or a small value,
 * like 100, the encoding will still be CBOR's most compact that can
 * represent the value.  For example, CBOR always encodes the value 0
 * as one byte, 0x00. The representation as 0x00 includes
 * identification of the type as an integer too as the major type for
 * an integer is 0. See 
 * [RFC 8949 Appendix A](https://www.rfc-editor.org/rfc/rfc8949.html#section-appendix.a)
 * for more examples of CBOR encoding. This compact encoding is
 * preferred serialization CBOR as per
 * [RFC 8949 section 4.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.1)
 *
 * There are no functions to add @c int16_t or @c int32_t because they
 * are not necessary because this always encodes to the smallest
 * number of bytes based on the value.
 *
 * If the encoding context is in an error state, this will do
 * nothing. If an error occurs when adding this integer, the internal
 * error flag will be set, and the error will be returned when
 * QCBOREncode_Finish() is called.
 *
 * See also QCBOREncode_AddUInt64().
 */
void
QCBOREncode_AddInt64(QCBOREncodeContext *pCtx, int64_t nNum);

/** See QCBOREncode_AddInt64(). */
static void
QCBOREncode_AddInt64ToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nNum);

/** See QCBOREncode_AddInt64(). */
static void
QCBOREncode_AddInt64ToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, int64_t nNum);


/**
 * @brief  Add an unsigned 64-bit integer to the encoded output.
 *
 * @param[in] pCtx  The encoding context to add the integer to.
 * @param[in] uNum  The integer to add.
 *
 * The integer is encoded and added to the CBOR output.
 *
 * The only reason so use this function is for integers larger than
 * @c INT64_MAX and smaller than @c UINT64_MAX. Otherwise
 * QCBOREncode_AddInt64() will work fine.
 *
 * Error handling is the same as for QCBOREncode_AddInt64().
 */
static void
QCBOREncode_AddUInt64(QCBOREncodeContext *pCtx, uint64_t uNum);

/** See QCBOREncode_AddUInt64(). */
static void
QCBOREncode_AddUInt64ToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel, uint64_t uNum);

/** See QCBOREncode_AddUInt64(). */
static void
QCBOREncode_AddUInt64ToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, uint64_t uNum);


/**
 * @brief Add a negative 64-bit integer to encoded output
 *
 * @param[in] pCtx  The encoding context to add the integer to.
 * @param[in] uNum  The integer to add.
 *
 * QCBOREncode_AddInt64() is much better to encode negative integers
 * than this.  What this can do is add integers with one more
 * significant bit than an int64_t (a "65-bit" integer if you count
 * the sign as a bit) which is possible because CBOR happens to
 * support such integers.
 *
 * The actual value encoded is -uNum - 1. That is, give 0 for uNum to
 * transmit -1, give 1 to transmit -2 and give UINT64_MAX to transmit
 * -UINT64_MAX-1 (18446744073709551616). The interface is odd like
 * this so all negative values CBOR can represent can be encoded by
 * QCBOR (making this a complete CBOR implementation).
 *
 * The most negative value QCBOREncode_AddInt64() can encode is
 * -9223372036854775808 which is -(2^63) or negative 0x800000000000.
 * This can encode from -9223372036854775809 to -18446744073709551616
 * or -(2^63 +1)  to -(2^64). Note that it is not possible to represent
 * positive or negative 18446744073709551616 in any standard C data
 * type.
 *
 * Negative integers are normally decoded in QCBOR with type
 * @ref QCBOR_TYPE_INT64.  Integers in the range of -9223372036854775809
 * to -18446744073709551616 are returned as @ref QCBOR_TYPE_65BIT_NEG_INT.
 *
 * WARNING: some CBOR decoders will be unable to decode -(2^63 + 1) to
 * -(2^64).  Also, most CPUs do not have registers that can represent
 * this range.  If you need 65-bit negative integers, you likely need
 * negative 66, 67 and 68-bit negative integers so it is likely better
 * to use CBOR big numbers where you can have any number of bits. See
 * QCBOREncode_AddTBigNumber() and @ref Serialization.
 */
static void
QCBOREncode_AddNegativeUInt64(QCBOREncodeContext *pCtx, uint64_t uNum);

/** See QCBOREncode_AddNegativeUInt64(). */
static void
QCBOREncode_AddNegativeUInt64ToMap(QCBOREncodeContext *pCtx, const char *szLabel, uint64_t uNum);

/** See QCBOREncode_AddNegativeUInt64(). */
static void
QCBOREncode_AddNegativeUInt64ToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, uint64_t uNum);


#ifndef USEFULBUF_DISABLE_ALL_FLOAT
/**
 * @brief Add a double-precision floating-point number to the encoded output.
 *
 * @param[in] pCtx  The encoding context to add the double to.
 * @param[in] dNum  The double-precision number to add.
 *
 * This encodes using preferred serialization, selectively encoding
 * the input floating-point number as either double-precision,
 * single-precision or half-precision. Infinity, NaN and 0 are always
 * encoded as half-precision. The reduction to single-precision or
 * half-precision is only performed if there is no loss or precision.
 *
 * Half-precision floating-point numbers take up 2 bytes, half that of
 * single-precision, one quarter of double-precision. This can reduce
 * the size of encoded output a lot, especially if the values 0,
 * infinity and NaN occur frequently.
 *
 * QCBOR decoding returns double-precision reversing this reduction.
 *
 * Normally this outputs only CBOR major type 7.  If
 * QCBOREncode_SerializationdCBOR() is called to enter dCBOR mode,
 * floating-point inputs that are whole integers are further reduced
 * to CBOR type 0 and 1. This is a unification of the floating-point
 * and integer number spaces such that there is only one encoding of
 * any numeric value. Note that this will result in the whole integers
 * from -(2^63+1) to -(2^64) being encode as CBOR major type 1 which
 * can't be directly decoded into an int64_t or uint64_t. See
 * QCBORDecode_GetNumberConvertPrecisely(), a good method to use to
 * decode dCBOR.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 *
 * It is possible that preferred serialization is disabled when the
 * QCBOR library was built. In that case, this functions the same as
 * QCBOREncode_AddDoubleNoPreferred().
 *
 * See also QCBOREncode_AddDoubleNoPreferred(), QCBOREncode_AddFloat()
 * and QCBOREncode_AddFloatNoPreferred() and @ref Floating-Point.
 *
 * By default, this will error out on an attempt to encode a NaN with
 * a payload. See QCBOREncode_Allow() and @ref
 * QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD.
 * If preferred serialization is disabled at compliation, this check for
 * for NaN payloads is disabled.
 */
static void
QCBOREncode_AddDouble(QCBOREncodeContext *pCtx, double dNum);

/** See QCBOREncode_AddDouble(). */
static void
QCBOREncode_AddDoubleToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel, double dNum);

/** See QCBOREncode_AddDouble(). */
static void
QCBOREncode_AddDoubleToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, double dNum);


/**
 * @brief Add a single-precision floating-point number to the encoded output.
 *
 * @param[in] pCtx  The encoding context to add the single to.
 * @param[in] fNum  The single-precision number to add.
 *
 * This is identical to QCBOREncode_AddDouble() except the input is
 * single-precision. It also supports dCBOR.
 *
 * See also QCBOREncode_AddDouble(), QCBOREncode_AddDoubleNoPreferred(),
 * and QCBOREncode_AddFloatNoPreferred() and @ref Floating-Point.
 */
static void
QCBOREncode_AddFloat(QCBOREncodeContext *pCtx, float fNum);

/** See QCBOREncode_AddFloat(). */
static void
QCBOREncode_AddFloatToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel, float fNum);

/** See QCBOREncode_AddFloat(). */
static void
QCBOREncode_AddFloatToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, float dNum);


/**
 * @brief Add a double-precision floating-point number without preferred encoding.
 *
 * @param[in] pCtx  The encoding context to add the double to.
 * @param[in] dNum  The double-precision number to add.
 *
 * Output a double-precision float straight-through with no checking or
 * processing for preferred serialization, dCBOR or other.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 *
 * See also QCBOREncode_AddDouble(), QCBOREncode_AddFloat(), and
 * QCBOREncode_AddFloatNoPreferred() and @ref Floating-Point.
 */
static void
QCBOREncode_AddDoubleNoPreferred(QCBOREncodeContext *pCtx, double dNum);

/** See QCBOREncode_AddDoubleNoPreferred(). */
static void
QCBOREncode_AddDoubleNoPreferredToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel, double dNum);

/** See QCBOREncode_AddDoubleNoPreferred(). */
static void
QCBOREncode_AddDoubleNoPreferredToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, double dNum);


/**
 * @brief Add a single-precision floating-point number without preferred encoding.
 *
 * @param[in] pCtx  The encoding context to add the double to.
 * @param[in] fNum  The single-precision number to add.
 *
 * Output a single-precision float straight-through with no checking or
 * processing for preferred serializtion, dCBOR or other.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 *
 * See also QCBOREncode_AddDouble(), QCBOREncode_AddFloat(), and
 * QCBOREncode_AddDoubleNoPreferred() and @ref Floating-Point.
 */
static void
QCBOREncode_AddFloatNoPreferred(QCBOREncodeContext *pCtx, float fNum);

/** See QCBOREncode_AddFloatNoPreferred(). */
static void
QCBOREncode_AddFloatNoPreferredToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel, float fNum);

/** See QCBOREncode_AddFloatNoPreferred(). */
static void
QCBOREncode_AddFloatNoPreferredToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, float fNum);
#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT */



/**
 * @brief Add a byte string to the encoded output.
 *
 * @param[in] pCtx   The encoding context to add the bytes to.
 * @param[in] Bytes  Pointer and length of the input data.
 *
 * Simply adds the bytes to the encoded output as CBOR major type 2.
 *
 * If called with @c Bytes.len equal to 0, an empty string will be
 * added. When @c Bytes.len is 0, @c Bytes.ptr may be @c NULL.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 */
static void
QCBOREncode_AddBytes(QCBOREncodeContext *pCtx, UsefulBufC Bytes);

/** See QCBOREncode_AddBytes(). */
static void
QCBOREncode_AddBytesToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC Bytes);

/** See QCBOREncode_AddBytes(). */
static void
QCBOREncode_AddBytesToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, UsefulBufC Bytes);


/**
 * @brief Set up to write a byte string value directly to encoded output.
 *
 * @param[in] pCtx     The encoding context to add the bytes to.
 * @param[out] pPlace  Pointer and length of place to write byte string value.
 *
 * QCBOREncode_AddBytes() is the normal way to encode a byte string.
 * This is for special cases and by passes some of the pointer safety.
 *
 * The purpose of this is to output the bytes that make up a byte
 * string value directly to the QCBOR output buffer so you don't need
 * to have a copy of it in memory. This is particularly useful if the
 * byte string is large, for example, the encrypted payload of a
 * COSE_Encrypt message. The payload encryption algorithm can output
 * directly to the encoded CBOR buffer, perhaps by making it the
 * output buffer for some function (e.g. symmetric encryption) or by
 * multiple writes.
 *
 * The pointer in @c pPlace is where to start writing. Writing is just
 * copying bytes to the location by the pointer in @c pPlace.  Writing
 * past the length in @c pPlace will be writing off the end of the
 * output buffer.
 *
 * If there is no room in the output buffer @ref NULLUsefulBuf will be
 * returned and there is no need to call QCBOREncode_CloseBytes().
 *
 * The byte string must be closed by calling QCBOREncode_CloseBytes().
 *
 * Warning: this bypasses some of the usual checks provided by QCBOR
 * against writing off the end of the encoded output buffer.
 */
void
QCBOREncode_OpenBytes(QCBOREncodeContext *pCtx, UsefulBuf *pPlace);

/** See QCBOREncode_OpenBytes(). */
static void
QCBOREncode_OpenBytesInMapSZ(QCBOREncodeContext *pCtx,
                             const char         *szLabel,
                             UsefulBuf          *pPlace);

/** See QCBOREncode_OpenBytes(). */
static void
QCBOREncode_OpenBytesInMapN(QCBOREncodeContext *pCtx,
                            int64_t             nLabel,
                            UsefulBuf          *pPlace);


/**
 *  @brief Close out a byte string written directly to encoded output.
 *
 *  @param[in] pCtx      The encoding context to add the bytes to.
 *  @param[out] uAmount  The number of bytes written, the length of the
 *                       byte string.
 *
 * This closes out a call to QCBOREncode_OpenBytes().  This inserts a
 * CBOR header at the front of the byte string value to make it a
 * well-formed byte string.
 *
 * If there was no call to QCBOREncode_OpenBytes() then @ref
 * QCBOR_ERR_TOO_MANY_CLOSES is set.
 */
void
QCBOREncode_CloseBytes(QCBOREncodeContext *pCtx, size_t uAmount);


/**
 * @brief Add a big number to encoded output using preferred serialization.
 *
 * @param[in] pCtx             The encoding context to add to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] bNegative        If true, @c BigNumber is negative.
 * @param[in] BigNumber        Pointer and length of the big number,
 *                             most significant byte first (network
 *                             byte order).
 *
 * This encodes CBOR tag numbers 2 and 3, positive and negative big
 * numbers, as defined in 
 * [RFC 8949 section 3.4.3](https://www.rfc-editor.org/rfc/rfc8949.html#section-3.4.3).
 *
 * This performs the offset of one required when encoding negative
 * numbers.
 *
 * Leading zeros are not encoded.
 *
 * This uses preferred serialization described specifically for big
 * numbers. Positive values between 0 and (2^64)-1 are encoded as
 * common type 0 integers. Negative values between -(2^64) and -1 are
 * encoded as common type 1 integers.
 *
 * See @ref BigNumbers for a useful overview of CBOR big numbers and
 * QCBOR's support for them. See
 * QCBOREncode_AddTBigNumberNoPreferred() to encode without conversion
 * to common integer types 0 and 1. See QCBOREncode_AddTBigNumberRaw()
 * for encoding that is simple pass through as a byte string that
 * links in much less object code. See QCBORDecode_GetTBigNumber() for
 * the decoder counter part.
 */
static void
QCBOREncode_AddTBigNumber(QCBOREncodeContext *pCtx,
                          uint8_t             uTagRequirement,
                          bool                bNegative,
                          UsefulBufC          BigNumber);

/** See QCBOREncode_AddTBigNumber(). */
static void
QCBOREncode_AddTBigNumberToMapSZ(QCBOREncodeContext *pCtx,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 bool                bNegative,
                                 UsefulBufC          BigNumber);

/** See QCBOREncode_AddTBigNumber(). */
static void
QCBOREncode_AddTBigNumberToMapN(QCBOREncodeContext *pCtx,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                bool                bNegative,
                                UsefulBufC          BigNumber);


/**
 * @brief Add a big number to encoded output without preferred serialization.
 *
 * @param[in] pCtx             The encoding context to add to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] bNegative        If true, @c BigNumber is negative.
 * @param[in] BigNumber        Pointer and length of the big number,
 *                             most significant byte first (network
 *                             byte order).
 *
 * This is the same as QCBOREncode_AddTBigNumber(), without preferred
 * serialization. This always outputs tag 2 or 3, never type 0 or 1
 * integers.
 *
 * Leading zeros are removed before encoding.
 *
 * See @ref BigNumbers for a useful overview of CBOR big numbers and
 * QCBOR's support for them. See also QCBOREncode_AddTBigNumber().
 * See QCBORDecode_GetTBigNumberNoPreferred(), the decode counter part
 * for this.
 */
static void
QCBOREncode_AddTBigNumberNoPreferred(QCBOREncodeContext *pCtx,
                                     uint8_t             uTagRequirement,
                                     bool                bNegative,
                                     UsefulBufC          BigNumber);

/** See QCBOREncode_AddTBigNumberNoPreferred(). */
static void
QCBOREncode_AddTBigNumberNoPreferredToMapSZ(QCBOREncodeContext *pCtx,
                                            const char         *szLabel,
                                            uint8_t             uTagRequirement,
                                            bool                bNegative,
                                            UsefulBufC          BigNumber);

/** See QCBOREncode_AddTBigNumberNoPreferred(). */
static void
QCBOREncode_AddTBigNumberNoPreferredToMapN(QCBOREncodeContext *pCtx,
                                           int64_t             nLabel,
                                           uint8_t             uTagRequirement,
                                           bool                bNegative,
                                           UsefulBufC          BigNumber);


/**
 * @brief Add a big number to encoded output with no processing.
 *
 * @param[in] pCtx             The encoding context to add to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] bNegative        If true @c BigNumber is negative.
 * @param[in] BigNumber        Pointer and length of the big number,
 *                             most significant byte first (network
 *                             byte order).
 *
 * All this does is output tag number 2 or 3 depending on @c bNegative
 * and then output @c BigNumber as a byte string. If @c
 * uTagRequirement is @ref QCBOR_ENCODE_AS_BORROWED, the tag number is
 * not even output and this equivalent to QCBOREncode_AddBytes().
 *
 * No leading zeros are removed. No offset of one is performed for
 * negative numbers. There is no conversion to type 0 and type 1
 * integers.
 *
 * This is mostly an inline implementation that links in no additional
 * object from the QCBOR library.
 *
 * This is most useful when a big number library has been linked, and
 * it can be (trivially) used to perform the offset of one for
 * negative numbers.
 *
 * See @ref BigNumbers for a useful overview of CBOR big numbers and
 * QCBOR's support for them. See QCBORDecode_GetTBigNumberRaw(), the
 * decode counter part for this. See also QCBOREncode_AddTBigNumber().
 */
static void
QCBOREncode_AddTBigNumberRaw(QCBOREncodeContext *pCtx,
                             uint8_t             uTagRequirement,
                             bool                bNegative,
                             UsefulBufC          BigNumber);

/** See QCBOREncode_AddTBigNumberRaw(). */
static void
QCBOREncode_AddTBigNumberRawToMapSZ(QCBOREncodeContext *pCtx,
                                    const char         *szLabel,
                                    uint8_t             uTagRequirement,
                                    bool                bNegative,
                                    UsefulBufC          BigNumber);

/** See QCBOREncode_AddTBigNumberRaw(). */
static void
QCBOREncode_AddTBigNumberRawToMapN(QCBOREncodeContext *pCtx,
                                   int64_t             nLabel,
                                   uint8_t             uTagRequirement,
                                   bool                bNegative,
                                   UsefulBufC          BigNumber);



#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
/**
 * @brief Add a decimal fraction.
 *
 * @param[in] pCtx             Encoding context to add the decimal fraction to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] nMantissa        The mantissa.
 * @param[in] nBase10Exponent  The exponent.
 *
 * The value is nMantissa * 10 ^ nBase10Exponent.
 *
 * A decimal fraction is good for exact representation of some values
 * that can't be represented exactly with standard C (IEEE 754)
 * floating-point numbers.  Much larger and much smaller numbers can
 * also be represented than floating-point because of the larger
 * number of bits in the exponent.
 *
 * The decimal fraction is conveyed as two integers, a mantissa and a
 * base-10 scaling factor.
 *
 * For example, 273.15 is represented by the two integers 27315 and -2.
 *
 * The exponent and mantissa have the range from @c INT64_MIN to
 * @c INT64_MAX for both encoding and decoding (CBOR allows
 * @c -UINT64_MAX to @c UINT64_MAX, but this implementation doesn't
 * support this range to reduce code size and interface complexity a
 * little).
 *
 * CBOR Preferred serialization of the integers is used, thus they
 * will be encoded in the smallest number of bytes possible.
 *
 * See also QCBOREncode_AddTDecimalFractionBigNumber() for a decimal
 * fraction with arbitrarily large precision and
 * QCBOREncode_AddTBigFloat().
 *
 * There is no representation of positive or negative infinity or NaN
 * (Not a Number). Use QCBOREncode_AddDouble() to encode them.
 *
 * See @ref expAndMantissa for decoded representation.
 */
static void
QCBOREncode_AddTDecimalFraction(QCBOREncodeContext *pCtx,
                                uint8_t             uTagRequirement,
                                int64_t             nMantissa,
                                int64_t             nBase10Exponent);

/** See QCBOREncode_AddTDecimalFraction(). */
static void
QCBOREncode_AddTDecimalFractionToMapSZ(QCBOREncodeContext *pCtx,
                                       const char         *szLabel,
                                       uint8_t             uTagRequirement,
                                       int64_t             nMantissa,
                                       int64_t             nBase10Exponent);

/** See QCBOREncode_AddTDecimalFraction(). */
static void
QCBOREncode_AddTDecimalFractionToMapN(QCBOREncodeContext *pCtx,
                                      int64_t             nLabel,
                                      uint8_t             uTagRequirement,
                                      int64_t             nMantissa,
                                      int64_t             nBase10Exponent);



/**
 * @brief Add a decimal fraction with a big number mantissa..
 *
 * @param[in] pCtx             Encoding context to add the decimal fraction to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] Mantissa         The big number mantissa.
 * @param[in] bIsNegative      false if mantissa is positive, true if negative.
 * @param[in] nBase10Exponent  The exponent.
 *
 * This is the same as QCBOREncode_AddTDecimalFraction() except the
 * mantissa is a big number (See QCBOREncode_AddTBignumber())
 * allowing for arbitrarily large precision.
 *
 * Preferred serialization of the big number is used. This means it may be converted to
 * a type 0 or type 1 integers making the result the same as QCBOREncode_AddTDecimalFraction().
 * This also offsets negative big numbers by one.
 *
 * If you want the big number to be copied straight through without the conversion to type 0
 * and 1 integers and without the offset of 1 (and much smaller objet code) use QCBOREncode_AddTBigFloatBigMantissaRaw().
 *
 * See @ref expAndMantissa for decoded representation.
 */
static void
QCBOREncode_AddTDecimalFractionBigMantissa(QCBOREncodeContext *pCtx,
                                           uint8_t             uTagRequirement,
                                           UsefulBufC          Mantissa,
                                           bool                bIsNegative,
                                           int64_t             nBase10Exponent);

/** See QCBOREncode_AddTDecimalFractionBigMantissa(). */
static void
QCBOREncode_AddTDecimalFractionBigMantissaToMapSZ(QCBOREncodeContext *pCtx,
                                                  const char         *szLabel,
                                                  uint8_t             uTagRequirement,
                                                  UsefulBufC          Mantissa,
                                                  bool                bIsNegative,
                                                  int64_t             nBase10Exponent);

/** See QCBOREncode_AddTDecimalFractionBigMantissa(). */
static void
QCBOREncode_AddTDecimalFractionBigMantissaToMapN(QCBOREncodeContext *pCtx,
                                                 int64_t             nLabel,
                                                 uint8_t             uTagRequirement,
                                                 UsefulBufC          Mantissa,
                                                 bool                bIsNegative,
                                                 int64_t             nBase10Exponent);
/**
 * @brief Add a decimal fraction with a raw big number mantissa.
 *
 * @param[in] pCtx             The encoding context to add the bigfloat to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] Mantissa         The mantissa.
 * @param[in] bIsNegative      false if mantissa is positive, true if negative.
 * @param[in] nBase10Exponent   The exponent.
 *
 * This is the same as QCBOREncode_AddTDecimalFractionBigMantissa() except the mantissa
 * is not corrected by one and links in much less object code.
 */static void
QCBOREncode_AddTDecimalFractionBigMantissaRaw(QCBOREncodeContext *pCtx,
                                              uint8_t             uTagRequirement,
                                              UsefulBufC          Mantissa,
                                              bool                bIsNegative,
                                              int64_t             nBase10Exponent);

/** See QCBOREncode_AddTDecimalFractionBigMantissaRaw(). */
static void
QCBOREncode_AddTDecimalFractionBigMantissaRawToMapSZ(QCBOREncodeContext *pCtx,
                                                     const char         *szLabel,
                                                     uint8_t             uTagRequirement,
                                                     UsefulBufC          Mantissa,
                                                     bool                bIsNegative,
                                                     int64_t             nBase10Exponent);

/** See QCBOREncode_AddTDecimalFractionBigMantissaRaw(). */
static void
QCBOREncode_AddTDecimalFractionBigMantissaRawToMapN(QCBOREncodeContext *pCtx,
                                                    int64_t             nLabel,
                                                    uint8_t             uTagRequirement,
                                                    UsefulBufC          Mantissa,
                                                    bool                bIsNegative,
                                                    int64_t             nBase10Exponent);



/**
 * @brief Add a big floating-point number to the encoded output.
 *
 * @param[in] pCtx             The encoding context to add the bigfloat to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] nMantissa        The mantissa.
 * @param[in] nBase2Exponent   The exponent.
 *
 * The value is nMantissa * 2 ^ nBase2Exponent.
 *
 * "Bigfloats", as CBOR terms them, are similar to IEEE floating-point
 * numbers in having a mantissa and base-2 exponent, but they are not
 * supported by hardware or encoded the same. They explicitly use two
 * CBOR-encoded integers to convey the mantissa and exponent, each of
 * which can be 8, 16, 32 or 64 bits. With both the mantissa and
 * exponent 64 bits they can express more precision and a larger range
 * than an IEEE double floating-point number. See
 * QCBOREncode_AddTBigFloatBigMantissa() for even more precision.
 *
 * For example, 1.5 would be represented by a mantissa of 3 and an
 * exponent of -1.
 *
 * The exponent has a range from @c INT64_MIN to
 * @c INT64_MAX for both encoding and decoding (CBOR allows @c
 * -UINT64_MAX to @c UINT64_MAX, but this implementation doesn't
 * support this range to reduce code size and interface complexity a
 * little).
 *
 * CBOR preferred serialization of the integers is used, thus they will
 * be encoded in the smallest number of bytes possible.
 *
 * This can also be used to represent floating-point numbers in
 * environments that don't support IEEE 754.
 *
 * See @ref expAndMantissa for decoded representation.
 */
static void
QCBOREncode_AddTBigFloat(QCBOREncodeContext *pCtx,
                         uint8_t             uTagRequirement,
                         int64_t             nMantissa,
                         int64_t             nBase2Exponent);

/** See QCBOREncode_AddTBigFloat(). */
static void
QCBOREncode_AddTBigFloatToMapSZ(QCBOREncodeContext *pCtx,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                int64_t             nMantissa,
                                int64_t             nBase2Exponent);

/** See QCBOREncode_AddTBigFloat(). */
static void
QCBOREncode_AddTBigFloatToMapN(QCBOREncodeContext *pCtx,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               int64_t             nMantissa,
                               int64_t             nBase2Exponent);


/**
 * @brief Add a big floating-point number with a big number mantissa.
 *
 * @param[in] pCtx             The encoding context to add the bigfloat to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] Mantissa         The mantissa.
 * @param[in] bIsNegative      false if mantissa is positive, true if negative.
 * @param[in] nBase2Exponent   The exponent.
 *
 * This is the same as QCBOREncode_AddTBigFloat() except the mantissa
 * is a big number (See QCBOREncode_AddTBigMantissa()) allowing for
 * arbitrary precision.
 *
 *The big number will be offset by 1 if negative and preferred serialization will be used (tag 0 and 1).
 *
 * If you want the big number to be copied straight through without the conversion to type 0
 * and 1 integers and without the offset of 1 (and much smaller objet code) use QCBOREncode_AddTBigFloatBigMantissa().
 *
 * See @ref expAndMantissa for decoded representation.
 */
static void
QCBOREncode_AddTBigFloatBigMantissa(QCBOREncodeContext *pCtx,
                                    uint8_t             uTagRequirement,
                                    UsefulBufC          Mantissa,
                                    bool                bIsNegative,
                                    int64_t             nBase2Exponent);

/** See QCBOREncode_AddTBigFloatBigMantissa(). */
static void
QCBOREncode_AddTBigFloatBigMantissaToMapSZ(QCBOREncodeContext *pCtx,
                                           const char         *szLabel,
                                           uint8_t             uTagRequirement,
                                           UsefulBufC          Mantissa,
                                           bool                bIsNegative,
                                           int64_t             nBase2Exponent);

/** See QCBOREncode_AddTBigFloatBigMantissa(). */
static void
QCBOREncode_AddTBigFloatBigMantissaToMapN(QCBOREncodeContext *pCtx,
                                          int64_t             nLabel,
                                          uint8_t             uTagRequirement,
                                          UsefulBufC          Mantissa,
                                          bool                bIsNegative,
                                          int64_t             nBase2Exponent);


/**
 * @brief Add a big floating-point number with a big number mantissa.
 *
 * @param[in] pCtx             The encoding context to add the bigfloat to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] Mantissa         The mantissa.
 * @param[in] bIsNegative      false if mantissa is positive, true if negative.
 * @param[in] nBase2Exponent   The exponent.
 *
 * This is the same as QCBOREncode_AddTBigFloatBigMantissa() except the mantissa
 * is not corrected by one and links in much less object code.
 */
static void
QCBOREncode_AddTBigFloatBigMantissaRaw(QCBOREncodeContext *pCtx,
                                       uint8_t             uTagRequirement,
                                       UsefulBufC          Mantissa,
                                       bool                bIsNegative,
                                       int64_t             nBase2Exponent);


/** See QCBOREncode_AddTBigFloatBigMantissaRaw(). */
static void
QCBOREncode_AddTBigFloatBigMantissaRawToMapSZ(QCBOREncodeContext *pCtx,
                                              const char         *szLabel,
                                              uint8_t             uTagRequirement,
                                              UsefulBufC          Mantissa,
                                              bool                bIsNegative,
                                              int64_t             nBase2Exponent);

/** See QCBOREncode_AddTBigFloatBigMantissaRaw(). */
static void
QCBOREncode_AddTBigFloatBigMantissaRawToMapN(QCBOREncodeContext *pCtx,
                                             int64_t             nLabel,
                                             uint8_t             uTagRequirement,
                                             UsefulBufC          Mantissa,
                                             bool                bIsNegative,
                                             int64_t             nBase2Exponent);


#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */


/* ========================================================================= *
 *    BEGINNING OF DEPRECATED FUNCTION DECLARATIONS                          *
 *                                                                           *
 *    There is no plan to remove these in future versions.                   *
 *    They just have been replaced by something better.                      *
 * ========================================================================= */

/** @deprecated Use QCBOREncode_AddInt64ToMapSZ() instead. */
static void
QCBOREncode_AddInt64ToMap(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nNum);

/** @deprecated Use QCBOREncode_AddUInt64ToMapSZ() instead. */
static void
QCBOREncode_AddUInt64ToMap(QCBOREncodeContext *pCtx, const char *szLabel, uint64_t uNum);

#ifndef USEFULBUF_DISABLE_ALL_FLOAT
/** @deprecated Use QCBOREncode_AddDoubleToMapSZ() instead. */
static void
QCBOREncode_AddDoubleToMap(QCBOREncodeContext *pCtx, const char *szLabel, double dNum);

/** @deprecated Use QCBOREncode_AddFloatToMapSZ() instead. */
static void
QCBOREncode_AddFloatToMap(QCBOREncodeContext *pCtx, const char *szLabel, float fNum);

/** @deprecated Use QCBOREncode_AddDoubleNoPreferredToMapSZ() instead. */
static void
QCBOREncode_AddDoubleNoPreferredToMap(QCBOREncodeContext *pCtx, const char *szLabel, double dNum);

/** @deprecated Use QCBOREncode_AddFloatNoPreferredToMapSZ() instead. */
static void
QCBOREncode_AddFloatNoPreferredToMap(QCBOREncodeContext *pCtx, const char *szLabel, float fNum);
#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT */


/** @deprecated Use QCBOREncode_AddTBigNumberRaw() instead. */
static void
QCBOREncode_AddTPositiveBignum(QCBOREncodeContext *pCtx,
                               uint8_t             uTagRequirement,
                               UsefulBufC          BigNumber);

/** @deprecated Use QCBOREncode_AddTBigNumberRawToMapSZ() instead. */
static void
QCBOREncode_AddTPositiveBignumToMapSZ(QCBOREncodeContext *pCtx,
                                      const char         *szLabel,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC          BigNumber);

/** @deprecated Use QCBOREncode_AddTBigNumberRawToMapN() instead. */
static void
QCBOREncode_AddTPositiveBignumToMapN(QCBOREncodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint8_t             uTagRequirement,
                                     UsefulBufC          BigNumber);


/** @deprecated Use QCBOREncode_AddTBigNumberRaw() instead. */
static void
QCBOREncode_AddPositiveBignum(QCBOREncodeContext *pCtx,
                              UsefulBufC          BigNumber);

/** @deprecated Use QCBOREncode_AddTBigNumberRawToMapSZ() instead. */
static void
QCBOREncode_AddPositiveBignumToMap(QCBOREncodeContext *pCtx,
                                   const char         *szLabel,
                                   UsefulBufC          BigNumber);

/** @deprecated Use QCBOREncode_AddTBigNumberRawToMapN() instead. */
static void
QCBOREncode_AddPositiveBignumToMapN(QCBOREncodeContext *pCtx,
                                    int64_t             nLabel,
                                    UsefulBufC          BigNumber);


/** @deprecated Use QCBOREncode_AddTBigNumberRaw() instead. */
static void
QCBOREncode_AddTNegativeBignum(QCBOREncodeContext *pCtx,
                               uint8_t             uTagRequirement,
                               UsefulBufC          BigNumber);

/** @deprecated Use QCBOREncode_AddTBigNumberRawToMapSZ() instead. */
static void
QCBOREncode_AddTNegativeBignumToMapSZ(QCBOREncodeContext *pCtx,
                                      const char         *szLabel,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC          BigNumber);

/** @deprecated Use QCBOREncode_AddTBigNumberRawToMapN() instead. */
static void
QCBOREncode_AddTNegativeBignumToMapN(QCBOREncodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint8_t             uTagRequirement,
                                     UsefulBufC          BigNumber);

/** @deprecated Use QCBOREncode_AddTBigNumberRaw() instead. */
static void
QCBOREncode_AddNegativeBignum(QCBOREncodeContext *pCtx,
                              UsefulBufC          BigNumber);

/** @deprecated Use QCBOREncode_AddTBigNumberRawToMapSZ() instead. */
static void
QCBOREncode_AddNegativeBignumToMap(QCBOREncodeContext *pCtx,
                                   const char         *szLabel,
                                   UsefulBufC          BigNumber);

/** @deprecated Use QCBOREncode_AddTBigNumberRawToMapN() instead. */
static void
QCBOREncode_AddNegativeBignumToMapN(QCBOREncodeContext *pCtx,
                                    int64_t             nLabel,
                                    UsefulBufC          BigNumber);


#ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
/** @deprecated Use QCBOREncode_AddTDecimalFraction() instead.*/
static void
QCBOREncode_AddDecimalFraction(QCBOREncodeContext *pCtx,
                               int64_t             nMantissa,
                               int64_t             nBase10Exponent);

/** @deprecated Use QCBOREncode_AddTDecimalFractionToMapSZ() instead. */
static void
QCBOREncode_AddDecimalFractionToMap(QCBOREncodeContext *pCtx,
                                    const char         *szLabel,
                                    int64_t             nMantissa,
                                    int64_t             nBase10Exponent);

/** @deprecated Use QCBOREncode_AddTDecimalFractionToMapN() instead. */
static void
QCBOREncode_AddDecimalFractionToMapN(QCBOREncodeContext *pCtx,
                                     int64_t             nLabel,
                                     int64_t             nMantissa,
                                     int64_t             nBase10Exponent);

/** @deprecated Use QCBOREncode_AddTDecimalFractionBigMantissaRaw() instead. */
static void
QCBOREncode_AddTDecimalFractionBigNum(QCBOREncodeContext *pCtx,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC          Mantissa,
                                      bool                bIsNegative,
                                      int64_t             nBase10Exponent);

/** @deprecated Use QCBOREncode_AddTDecimalFractionBigMantissaRawToMapSZ() instead. */
static void
QCBOREncode_AddTDecimalFractionBigNumToMapSZ(QCBOREncodeContext *pCtx,
                                             const char         *szLabel,
                                             uint8_t             uTagRequirement,
                                             UsefulBufC          Mantissa,
                                             bool                bIsNegative,
                                             int64_t             nBase10Exponent);

/** @deprecated Use QCBOREncode_AddTDecimalFractionBigMantissaRawToMapN() instead. */
static void
QCBOREncode_AddTDecimalFractionBigNumToMapN(QCBOREncodeContext *pCtx,
                                            int64_t             nLabel,
                                            uint8_t             uTagRequirement,
                                            UsefulBufC          Mantissa,
                                            bool                bIsNegative,
                                            int64_t             nBase10Exponent);

/** @deprecated Use QCBOREncode_AddTDecimalFractionBigMantissaRaw() instead. */
static void
QCBOREncode_AddDecimalFractionBigNum(QCBOREncodeContext *pCtx,
                                     UsefulBufC          Mantissa,
                                     bool                bIsNegative,
                                     int64_t             nBase10Exponent);

/** @deprecated Use QCBOREncode_AddTDecimalFractionBigMantissaRawToMapSZ() instead. */
static void
QCBOREncode_AddDecimalFractionBigNumToMapSZ(QCBOREncodeContext *pCtx,
                                            const char         *szLabel,
                                            UsefulBufC          Mantissa,
                                            bool                bIsNegative,
                                            int64_t             nBase10Exponent);

/** @deprecated Use QCBOREncode_AddTDecimalFractionBigMantissaRawToMapN() instead. */
static void
QCBOREncode_AddDecimalFractionBigNumToMapN(QCBOREncodeContext *pCtx,
                                           int64_t             nLabel,
                                           UsefulBufC          Mantissa,
                                           bool                bIsNegative,
                                           int64_t             nBase10Exponent);

/** @deprecated Use QCBOREncode_AddTBigFloat() instead. */
static void
QCBOREncode_AddBigFloat(QCBOREncodeContext *pCtx,
                        int64_t             nMantissa,
                        int64_t             nBase2Exponent);

/** @deprecated Use QCBOREncode_AddTBigFloatToMapSZ() instead. */
static void
QCBOREncode_AddBigFloatToMap(QCBOREncodeContext *pCtx,
                             const char         *szLabel,
                             int64_t             nMantissa,
                             int64_t             nBase2Exponent);

/** @deprecated Use QCBOREncode_AddTBigFloatToMapN() instead. */
static void
QCBOREncode_AddBigFloatToMapN(QCBOREncodeContext *pCtx,
                              int64_t             nLabel,
                              int64_t             nMantissa,
                              int64_t             nBase2Exponent);

/** @deprecated Use QCBOREncode_AddTBigFloatBigMantissaRaw() instead. */
static void
QCBOREncode_AddTBigFloatBigNum(QCBOREncodeContext *pCtx,
                               uint8_t             uTagRequirement,
                               UsefulBufC          Mantissa,
                               bool                bIsNegative,
                               int64_t             nBase2Exponent);

/** @deprecated Use QCBOREncode_AddTBigFloatBigMantissaRawToMapSZ() instead. */
static void
QCBOREncode_AddTBigFloatBigNumToMapSZ(QCBOREncodeContext *pCtx,
                                      const char         *szLabel,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC          Mantissa,
                                      bool                bIsNegative,
                                      int64_t             nBase2Exponent);

/** @deprecated Use QCBOREncode_AddTBigFloatBigMantissaRawToMapN() instead. */
static void
QCBOREncode_AddTBigFloatBigNumToMapN(QCBOREncodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint8_t             uTagRequirement,
                                     UsefulBufC          Mantissa,
                                     bool                bIsNegative,
                                     int64_t             nBase2Exponent);

/** @deprecated Use QCBOREncode_AddTBigFloatBigMantissaRaw() instead. */
static void
QCBOREncode_AddBigFloatBigNum(QCBOREncodeContext *pCtx,
                              UsefulBufC          Mantissa,
                              bool                bIsNegative,
                              int64_t             nBase2Exponent);

/** @deprecated Use QCBOREncode_AddTBigFloatBigMantissaRawToMapSZ() instead. */
static void
QCBOREncode_AddBigFloatBigNumToMap(QCBOREncodeContext *pCtx,
                                   const char         *szLabel,
                                   UsefulBufC          Mantissa,
                                   bool                bIsNegative,
                                   int64_t             nBase2Exponent);

/** @deprecated Use QCBOREncode_AddTBigFloatBigMantissaRawToMapN() instead. */
static void
QCBOREncode_AddBigFloatBigNumToMapN(QCBOREncodeContext *pCtx,
                                    int64_t             nLabel,
                                    UsefulBufC          Mantissa,
                                    bool                bIsNegative,
                                    int64_t             nBase2Exponent);

#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */



/* ========================================================================= *
 *    END OF DEPRECATED FUNCTION DECLARATIONS                                *
 * ========================================================================= */





/* ========================================================================= *
 *    BEGINNING OF PRIVATE INLINE IMPLEMENTATION                             *
 * ========================================================================= */

/** @private See qcbor_main_number_encode.c */
void
QCBOREncode_Private_AddPreferredDouble(QCBOREncodeContext *pMe, const double dNum);


/** @private See qcbor_main_number_encode.c */
void
QCBOREncode_Private_AddPreferredFloat(QCBOREncodeContext *pMe, const float fNum);



/** @private See qcbor_main_number_encode.c */
void
QCBOREncode_Private_AddTBigNumberMain(QCBOREncodeContext *pMe,
                                      const uint8_t       uTagRequirement,
                                      bool                bPreferred,
                                      const bool          bNegative,
                                      const UsefulBufC    BigNumber);

/** @private See qcbor_main_number_encode.c */
void
QCBOREncode_Private_AddTExpIntMantissa(QCBOREncodeContext *pMe,
                                       const int           uTagRequirement,
                                       const uint64_t      uTagNumber,
                                       const int64_t       nExponent,
                                       const int64_t       nMantissa);


/** @private See qcbor_main_number_encode.c */
void
QCBOREncode_Private_AddTExpBigMantissa(QCBOREncodeContext *pMe,
                                       const int           uTagRequirement,
                                       const uint64_t      uTagNumber,
                                       const int64_t       nExponent,
                                       const UsefulBufC    BigNumMantissa,
                                       const bool          bBigNumIsNegative);


/** @private See qcbor_main_number_encode.c */
void
QCBOREncode_Private_AddTExpBigMantissaRaw(QCBOREncodeContext *pMe,
                                          const int           uTagRequirement,
                                          const uint64_t      uTagNumber,
                                          const int64_t       nExponent,
                                          const UsefulBufC    BigNumMantissa,
                                          const bool          bBigNumIsNegative);


#include "qcbor/qcbor_tag_encode.h"


static inline void
QCBOREncode_AddInt64ToMapSZ(QCBOREncodeContext *pMe,
                            const char        *szLabel,
                            const int64_t      nNum)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddInt64(pMe, nNum);
}

static inline void
QCBOREncode_AddInt64ToMap(QCBOREncodeContext *pMe, const char *szLabel, int64_t nNum)
{
   QCBOREncode_AddInt64ToMapSZ(pMe, szLabel, nNum);
}

static inline void
QCBOREncode_AddInt64ToMapN(QCBOREncodeContext *pMe,
                           const int64_t       nLabel,
                           const int64_t       nNum)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddInt64(pMe, nNum);
}


static inline void
QCBOREncode_AddUInt64(QCBOREncodeContext *pMe, const uint64_t uValue)
{
   QCBOREncode_Private_AppendCBORHead(pMe, CBOR_MAJOR_TYPE_POSITIVE_INT, uValue, 0);
}


static inline void
QCBOREncode_AddUInt64ToMapSZ(QCBOREncodeContext *pMe,
                             const char         *szLabel,
                             const uint64_t      uNum)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddUInt64(pMe, uNum);
}

static inline void
QCBOREncode_AddUInt64ToMap(QCBOREncodeContext *pMe, const char *szLabel, uint64_t uNum)
{
   QCBOREncode_AddUInt64ToMapSZ(pMe, szLabel, uNum);
}

static inline void
QCBOREncode_AddUInt64ToMapN(QCBOREncodeContext *pMe,
                            const int64_t       nLabel,
                            const uint64_t      uNum)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddUInt64(pMe, uNum);
}


static inline void
QCBOREncode_AddNegativeUInt64(QCBOREncodeContext *pMe, const uint64_t uValue)
{
   QCBOREncode_Private_AppendCBORHead(pMe, CBOR_MAJOR_TYPE_NEGATIVE_INT, uValue, 0);
}

static inline void
QCBOREncode_AddNegativeUInt64ToMap(QCBOREncodeContext *pMe, const char *szLabel, uint64_t uNum)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddNegativeUInt64(pMe, uNum);
}

static inline void
QCBOREncode_AddNegativeUInt64ToMapN(QCBOREncodeContext *pMe, int64_t nLabel, uint64_t uNum)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddNegativeUInt64(pMe, uNum);
}





#ifndef USEFULBUF_DISABLE_ALL_FLOAT

/**
 * @brief Add a double in with no processing.
 * @private
 */
static inline void
QCBOREncode_Private_AddDoubleRaw(QCBOREncodeContext *pMe, const double dNum)
{
   QCBOREncode_Private_AddType7(pMe,
                                sizeof(uint64_t),
                                UsefulBufUtil_CopyDoubleToUint64(dNum));
}

static inline void
QCBOREncode_AddDoubleNoPreferred(QCBOREncodeContext *pMe, const double dNum)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(pMe->uConfigFlags & QCBOR_ENCODE_CONFIG_DISALLOW_NON_PREFERRED_NUMBERS) {
      pMe->uError = QCBOR_ERR_NOT_PREFERRED;
      return;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   QCBOREncode_Private_AddDoubleRaw(pMe, dNum);
}

static inline void
QCBOREncode_AddDouble(QCBOREncodeContext *pMe, const double dNum)
{
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
   QCBOREncode_Private_AddPreferredDouble(pMe, dNum);
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
   QCBOREncode_Private_AddDoubleRaw(pMe, dNum);
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
}

static inline void
QCBOREncode_AddDoubleToMapSZ(QCBOREncodeContext *pMe,
                             const char         *szLabel,
                             const double        dNum)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddDouble(pMe, dNum);
}

static inline void
QCBOREncode_AddDoubleToMap(QCBOREncodeContext *pMe, const char *szLabel, double dNum)
{
   QCBOREncode_AddDoubleToMapSZ(pMe, szLabel, dNum);
}

static inline void
QCBOREncode_AddDoubleToMapN(QCBOREncodeContext *pMe,
                            const int64_t       nLabel,
                            const double        dNum)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddDouble(pMe, dNum);
}

/**
 * @brief Add a float in with no processing.
 * @private
 */
static inline void
QCBOREncode_Private_AddFloatRaw(QCBOREncodeContext *pMe, const float fNum)
{
   QCBOREncode_Private_AddType7(pMe,
                                sizeof(uint32_t),
                                UsefulBufUtil_CopyFloatToUint32(fNum));
}

static inline void
QCBOREncode_AddFloatNoPreferred(QCBOREncodeContext *pMe, const float fNum)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(pMe->uConfigFlags & QCBOR_ENCODE_CONFIG_DISALLOW_NON_PREFERRED_NUMBERS) {
      pMe->uError = QCBOR_ERR_NOT_PREFERRED;
      return;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   QCBOREncode_Private_AddFloatRaw(pMe, fNum);
}

static inline void
QCBOREncode_AddFloat(QCBOREncodeContext *pMe, const float fNum)
{
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
   QCBOREncode_Private_AddPreferredFloat(pMe, fNum);
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
   QCBOREncode_Private_AddFloatRaw(pMe, fNum);
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
}

static inline void
QCBOREncode_AddFloatToMapSZ(QCBOREncodeContext *pMe,
                            const char         *szLabel,
                            const float         dNum)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddFloat(pMe, dNum);
}

static inline void
QCBOREncode_AddFloatToMap(QCBOREncodeContext *pMe, const char *szLabel, float fNum)
{
   QCBOREncode_AddFloatToMapSZ(pMe, szLabel, fNum);
}

static inline void
QCBOREncode_AddFloatToMapN(QCBOREncodeContext *pMe,
                           const int64_t       nLabel,
                           const float         fNum)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddFloat(pMe, fNum);
}

static inline void
QCBOREncode_AddDoubleNoPreferredToMapSZ(QCBOREncodeContext *pMe,
                                        const char         *szLabel,
                                        const double        dNum)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddDoubleNoPreferred(pMe, dNum);
}

static inline void
QCBOREncode_AddDoubleNoPreferredToMap(QCBOREncodeContext *pMe, const char *szLabel, double dNum)
{
   QCBOREncode_AddDoubleNoPreferredToMapSZ(pMe, szLabel, dNum);
}

static inline void
QCBOREncode_AddDoubleNoPreferredToMapN(QCBOREncodeContext *pMe,
                                       const int64_t       nLabel,
                                       const double        dNum)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddDoubleNoPreferred(pMe, dNum);
}

static inline void
QCBOREncode_AddFloatNoPreferredToMapSZ(QCBOREncodeContext *pMe,
                                       const char         *szLabel,
                                       const float         dNum)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddFloatNoPreferred(pMe, dNum);
}

static inline void
QCBOREncode_AddFloatNoPreferredToMap(QCBOREncodeContext *pMe, const char *szLabel, float fNum)
{
   QCBOREncode_AddFloatNoPreferredToMapSZ(pMe, szLabel, fNum);
}

static inline void
QCBOREncode_AddFloatNoPreferredToMapN(QCBOREncodeContext *pMe,
                                      const int64_t       nLabel,
                                      const float         dNum)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddFloatNoPreferred(pMe, dNum);
}
#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT */




static inline void
QCBOREncode_AddTBigNumber(QCBOREncodeContext *pMe,
                          const uint8_t       uTagRequirement,
                          const bool          bNegative,
                          const UsefulBufC    BigNumber)
{
   QCBOREncode_Private_AddTBigNumberMain(pMe, uTagRequirement, true, bNegative, BigNumber);
}


static inline void
QCBOREncode_AddTBigNumberToMapSZ(QCBOREncodeContext *pMe,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 bool                bNegative,
                                 UsefulBufC          BigNumber)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTBigNumber(pMe, uTagRequirement, bNegative, BigNumber);
}

static inline void
QCBOREncode_AddTBigNumberToMapN(QCBOREncodeContext *pMe,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                bool                bNegative,
                                UsefulBufC          BigNumber)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTBigNumber(pMe, uTagRequirement, bNegative, BigNumber);
}

static inline void
QCBOREncode_AddTBigNumberNoPreferred(QCBOREncodeContext *pMe,
                                     const uint8_t       uTagRequirement,
                                     const bool          bNegative,
                                     const UsefulBufC    BigNumber)
{
   QCBOREncode_Private_AddTBigNumberMain(pMe, uTagRequirement, false, bNegative, BigNumber);
}

static inline void
QCBOREncode_AddTBigNumberNoPreferredToMapSZ(QCBOREncodeContext *pMe,
                                            const char         *szLabel,
                                            uint8_t             uTagRequirement,
                                            bool                bNegative,
                                            UsefulBufC          BigNumber)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTBigNumberNoPreferred(pMe, uTagRequirement, bNegative, BigNumber);
}

static inline void
QCBOREncode_AddTBigNumberNoPreferredToMapN(QCBOREncodeContext *pMe,
                                           int64_t             nLabel,
                                           uint8_t             uTagRequirement,
                                           bool                bNegative,
                                           UsefulBufC          BigNumber)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTBigNumberNoPreferred(pMe, uTagRequirement, bNegative, BigNumber);
}

/**
 * @brief Add the tag number for a big number (private).
 * @private
 *
 * @param[in] pMe  The decode context.
 * @param[in] uTagRequirement
 * @param[in] bNegative  If true, big number is negative.
 */
static inline void
QCBOREncode_Private_BigNumberTag(QCBOREncodeContext *pMe,
                                 const uint8_t       uTagRequirement,
                                 bool                bNegative)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, bNegative ? CBOR_TAG_NEG_BIGNUM : CBOR_TAG_POS_BIGNUM);
   }
}


static inline void
QCBOREncode_AddTBigNumberRaw(QCBOREncodeContext *pMe,
                             const uint8_t       uTagRequirement,
                             bool                bNegative,
                             const UsefulBufC    BigNumber)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(pMe->uConfigFlags & QCBOR_ENCODE_CONFIG_ONLY_PREFERRED_BIG_NUMBERS) {
      pMe->uError = QCBOR_ERR_NOT_PREFERRED;
      return;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   QCBOREncode_Private_BigNumberTag(pMe, uTagRequirement, bNegative);
   QCBOREncode_AddBytes(pMe, BigNumber);
}

static inline void
QCBOREncode_AddTBigNumberRawToMapSZ(QCBOREncodeContext *pMe,
                                    const char         *szLabel,
                                    const uint8_t       uTagRequirement,
                                    bool                bNegative,
                                    const UsefulBufC    BigNumber)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTBigNumberRaw(pMe, uTagRequirement, bNegative, BigNumber);
}


static inline void
QCBOREncode_AddTBigNumberRawToMapN(QCBOREncodeContext *pMe,
                                   int64_t             nLabel,
                                   const uint8_t       uTagRequirement,
                                   bool                bNegative,
                                   const UsefulBufC    BigNumber)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTBigNumberRaw(pMe, uTagRequirement, bNegative, BigNumber);
}





#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA

static inline void
QCBOREncode_AddTDecimalFraction(QCBOREncodeContext *pMe,
                                const uint8_t       uTagRequirement,
                                const int64_t       nMantissa,
                                const int64_t       nBase10Exponent)
{
   QCBOREncode_Private_AddTExpIntMantissa(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_DECIMAL_FRACTION,
                                          nBase10Exponent,
                                          nMantissa);
}

static inline void
QCBOREncode_AddTDecimalFractionToMapSZ(QCBOREncodeContext *pMe,
                                       const char         *szLabel,
                                       const uint8_t       uTagRequirement,
                                       const int64_t       nMantissa,
                                       const int64_t       nBase10Exponent)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTDecimalFraction(pMe,
                                   uTagRequirement,
                                   nMantissa,
                                   nBase10Exponent);
}

static inline void
QCBOREncode_AddTDecimalFractionToMapN(QCBOREncodeContext *pMe,
                                      const int64_t       nLabel,
                                      const uint8_t       uTagRequirement,
                                      const int64_t       nMantissa,
                                      const int64_t       nBase10Exponent)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTDecimalFraction(pMe,
                                   uTagRequirement,
                                   nMantissa,
                                   nBase10Exponent);
}



static inline void
QCBOREncode_AddTDecimalFractionBigMantissa(QCBOREncodeContext *pMe,
                                           const uint8_t       uTagRequirement,
                                           const UsefulBufC    Mantissa,
                                           const bool          bIsNegative,
                                           const int64_t       nBase10Exponent)
{
   QCBOREncode_Private_AddTExpBigMantissa(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_DECIMAL_FRACTION,
                                          nBase10Exponent,
                                          Mantissa,
                                          bIsNegative);
}


static inline void
QCBOREncode_AddTDecimalFractionBigMantissaToMapSZ(QCBOREncodeContext *pMe,
                                                  const char         *szLabel,
                                                  const uint8_t       uTagRequirement,
                                                  const UsefulBufC    Mantissa,
                                                  const bool          bIsNegative,
                                                  const int64_t       nBase10Exponent)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTDecimalFractionBigMantissa(pMe,
                                              uTagRequirement,
                                              Mantissa,
                                              bIsNegative,
                                              nBase10Exponent);
}

static inline void
QCBOREncode_AddTDecimalFractionBigMantissaToMapN(QCBOREncodeContext *pMe,
                                                 const int64_t       nLabel,
                                                 const uint8_t       uTagRequirement,
                                                 const UsefulBufC    Mantissa,
                                                 const bool          bIsNegative,
                                                 const int64_t       nBase10Exponent)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTDecimalFractionBigMantissa(pMe,
                                              uTagRequirement,
                                              Mantissa,
                                              bIsNegative,
                                              nBase10Exponent);
}

static inline void
QCBOREncode_AddTDecimalFractionBigMantissaRaw(QCBOREncodeContext *pMe,
                                              const uint8_t       uTagRequirement,
                                              const UsefulBufC    Mantissa,
                                              const bool          bIsNegative,
                                              const int64_t       nBase10Exponent)
{
   QCBOREncode_Private_AddTExpBigMantissaRaw(pMe,
                                             uTagRequirement,
                                             CBOR_TAG_DECIMAL_FRACTION,
                                             nBase10Exponent,
                                             Mantissa,
                                             bIsNegative);
}


static inline void
QCBOREncode_AddTDecimalFractionBigMantissaRawToMapSZ(QCBOREncodeContext *pMe,
                                                     const char         *szLabel,
                                                     const uint8_t       uTagRequirement,
                                                     const UsefulBufC    Mantissa,
                                                     const bool          bIsNegative,
                                                     const int64_t       nBase10Exponent)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTDecimalFractionBigMantissaRaw(pMe,
                                                 uTagRequirement,
                                                 Mantissa,
                                                 bIsNegative,
                                                 nBase10Exponent);
}

static inline void
QCBOREncode_AddTDecimalFractionBigMantissaRawToMapN(QCBOREncodeContext *pMe,
                                                    const int64_t       nLabel,
                                                    const uint8_t       uTagRequirement,
                                                    const UsefulBufC    Mantissa,
                                                    const bool          bIsNegative,
                                                    const int64_t       nBase10Exponent)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTDecimalFractionBigMantissaRaw(pMe,
                                                 uTagRequirement,
                                                 Mantissa,
                                                 bIsNegative,
                                                 nBase10Exponent);
}


static inline void
QCBOREncode_AddTBigFloat(QCBOREncodeContext *pMe,
                         const uint8_t       uTagRequirement,
                         const int64_t       nMantissa,
                         const int64_t       nBase2Exponent)
{
   QCBOREncode_Private_AddTExpIntMantissa(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_BIGFLOAT,
                                          nBase2Exponent,
                                          nMantissa);
}

static inline void
QCBOREncode_AddTBigFloatToMapSZ(QCBOREncodeContext *pMe,
                                const char         *szLabel,
                                const uint8_t       uTagRequirement,
                                const int64_t       nMantissa,
                                const int64_t       nBase2Exponent)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTBigFloat(pMe, uTagRequirement, nMantissa, nBase2Exponent);
}

static inline void
QCBOREncode_AddTBigFloatToMapN(QCBOREncodeContext *pMe,
                               const int64_t       nLabel,
                               const uint8_t       uTagRequirement,
                               const int64_t       nMantissa,
                               const int64_t       nBase2Exponent)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTBigFloat(pMe, uTagRequirement, nMantissa, nBase2Exponent);
}


static inline void
QCBOREncode_AddTBigFloatBigMantissa(QCBOREncodeContext *pMe,
                                    const uint8_t       uTagRequirement,
                                    const UsefulBufC    Mantissa,
                                    const bool          bIsNegative,
                                    const int64_t       nBase2Exponent)
{
   QCBOREncode_Private_AddTExpBigMantissa(pMe,
                                          uTagRequirement,
                                          CBOR_TAG_BIGFLOAT,
                                          nBase2Exponent,
                                          Mantissa,
                                          bIsNegative);
}

static inline void
QCBOREncode_AddTBigFloatBigMantissaToMapSZ(QCBOREncodeContext *pMe,
                                           const char         *szLabel,
                                           const uint8_t       uTagRequirement,
                                           const UsefulBufC    Mantissa,
                                           const bool          bIsNegative,
                                           const int64_t       nBase2Exponent)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTBigFloatBigMantissa(pMe,
                                       uTagRequirement,
                                       Mantissa,
                                       bIsNegative,
                                       nBase2Exponent);
}

static inline void
QCBOREncode_AddTBigFloatBigMantissaToMapN(QCBOREncodeContext *pMe,
                                          const int64_t       nLabel,
                                          const uint8_t       uTagRequirement,
                                          const UsefulBufC    Mantissa,
                                          const bool          bIsNegative,
                                          const int64_t       nBase2Exponent)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTBigFloatBigMantissa(pMe,
                                       uTagRequirement,
                                       Mantissa,
                                       bIsNegative,
                                       nBase2Exponent);
}


static inline void
QCBOREncode_AddTBigFloatBigMantissaRaw(QCBOREncodeContext *pMe,
                                       const uint8_t       uTagRequirement,
                                       const UsefulBufC    Mantissa,
                                       const bool          bIsNegative,
                                       const int64_t       nBase2Exponent)
{
   QCBOREncode_Private_AddTExpBigMantissaRaw(pMe,
                                             uTagRequirement,
                                             CBOR_TAG_BIGFLOAT,
                                             nBase2Exponent,
                                             Mantissa,
                                             bIsNegative);
}

static inline void
QCBOREncode_AddTBigFloatBigMantissaRawToMapSZ(QCBOREncodeContext *pMe,
                                              const char         *szLabel,
                                              const uint8_t       uTagRequirement,
                                              const UsefulBufC    Mantissa,
                                              const bool          bIsNegative,
                                              const int64_t       nBase2Exponent)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTBigFloatBigMantissaRaw(pMe,
                                          uTagRequirement,
                                          Mantissa,
                                          bIsNegative,
                                          nBase2Exponent);
}

static inline void
QCBOREncode_AddTBigFloatBigMantissaRawToMapN(QCBOREncodeContext *pMe,
                                             const int64_t       nLabel,
                                             const uint8_t       uTagRequirement,
                                             const UsefulBufC    Mantissa,
                                             const bool          bIsNegative,
                                             const int64_t       nBase2Exponent)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTBigFloatBigMantissaRaw(pMe,
                                          uTagRequirement,
                                          Mantissa,
                                          bIsNegative,
                                          nBase2Exponent);
}

#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */



/* ======================================================================== *
 *    END OF PRIVATE INLINE IMPLEMENTATION                                  *
 * ======================================================================== */




/* ========================================================================= *
 *    BEGINNING OF INLINES FOR DEPRECATED FUNCTIONS                          *
 * ========================================================================= */


static inline void /* Deprecated */
QCBOREncode_AddTPositiveBignum(QCBOREncodeContext *pMe,
                               const uint8_t       uTagRequirement,
                               const UsefulBufC    BigNumber)
{
   QCBOREncode_AddTBigNumberRaw(pMe, uTagRequirement, false, BigNumber);
}

static inline void  /* Deprecated */
QCBOREncode_AddTPositiveBignumToMapSZ(QCBOREncodeContext *pMe,
                                      const char         *szLabel,
                                      const uint8_t       uTagRequirement,
                                      const UsefulBufC    BigNumber)
{
   QCBOREncode_AddTBigNumberRawToMapSZ(pMe, szLabel, uTagRequirement, false, BigNumber);
}

static inline void  /* Deprecated */
QCBOREncode_AddTPositiveBignumToMapN(QCBOREncodeContext *pMe,
                                     const int64_t       nLabel,
                                     const uint8_t       uTagRequirement,
                                     const UsefulBufC    BigNumber)
{
   QCBOREncode_AddTBigNumberRawToMapN(pMe, nLabel, uTagRequirement, false, BigNumber);
}

static inline void  /* Deprecated */
QCBOREncode_AddPositiveBignum(QCBOREncodeContext *pMe, const UsefulBufC BigNumber)
{
   QCBOREncode_AddTBigNumberRaw(pMe, QCBOR_ENCODE_AS_TAG, false, BigNumber);
}

static inline void  /* Deprecated */
QCBOREncode_AddPositiveBignumToMap(QCBOREncodeContext *pMe,
                                   const char         *szLabel,
                                   const UsefulBufC    BigNumber)
{
   QCBOREncode_AddTBigNumberRawToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, false, BigNumber);
}

static inline void  /* Deprecated */
QCBOREncode_AddPositiveBignumToMapN(QCBOREncodeContext *pMe,
                                    const int64_t       nLabel,
                                    const UsefulBufC    BigNumber)
{
   QCBOREncode_AddTBigNumberRawToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, false, BigNumber);
}

static inline void  /* Deprecated */
QCBOREncode_AddTNegativeBignum(QCBOREncodeContext *pMe,
                               const uint8_t       uTagRequirement,
                               const UsefulBufC    BigNumber)
{
   QCBOREncode_AddTBigNumberRaw(pMe, uTagRequirement, true, BigNumber);
}

static inline void  /* Deprecated */
QCBOREncode_AddTNegativeBignumToMapSZ(QCBOREncodeContext *pMe,
                                      const char         *szLabel,
                                      const uint8_t       uTagRequirement,
                                      const UsefulBufC    BigNumber)
{
   QCBOREncode_AddTBigNumberRawToMapSZ(pMe,
                                       szLabel,
                                       uTagRequirement,
                                       true,
                                       BigNumber);
}

static inline void  /* Deprecated */
QCBOREncode_AddTNegativeBignumToMapN(QCBOREncodeContext *pMe,
                                     const int64_t       nLabel,
                                     const uint8_t       uTagRequirement,
                                     const UsefulBufC    BigNumber)
{
   QCBOREncode_AddTBigNumberRawToMapN(pMe,
                                      nLabel,
                                      uTagRequirement,
                                      true,
                                      BigNumber);
}

static inline void  /* Deprecated */
QCBOREncode_AddNegativeBignum(QCBOREncodeContext *pMe, const UsefulBufC BigNumber)
{
   QCBOREncode_AddTBigNumberRaw(pMe, QCBOR_ENCODE_AS_TAG, true, BigNumber);
}

static inline void  /* Deprecated */
QCBOREncode_AddNegativeBignumToMap(QCBOREncodeContext *pMe,
                                   const char         *szLabel,
                                   const UsefulBufC    BigNumber)
{
   QCBOREncode_AddTBigNumberRawToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, true, BigNumber);
}

static inline void  /* Deprecated */
QCBOREncode_AddNegativeBignumToMapN(QCBOREncodeContext *pMe,
                                    const int64_t       nLabel,
                                    const UsefulBufC    BigNumber)
{
   QCBOREncode_AddTBigNumberRawToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, true, BigNumber);

}

#ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
static inline void /* Deprecated */
QCBOREncode_AddDecimalFraction(QCBOREncodeContext *pMe,
                               const int64_t       nMantissa,
                               const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFraction(pMe,
                                   QCBOR_ENCODE_AS_TAG,
                                   nMantissa,
                                   nBase10Exponent);
}

static inline void /* Deprecated */
QCBOREncode_AddDecimalFractionToMap(QCBOREncodeContext *pMe,
                                    const char         *szLabel,
                                    const int64_t       nMantissa,
                                    const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFractionToMapSZ(pMe,
                                          szLabel,
                                          QCBOR_ENCODE_AS_TAG,
                                          nMantissa,
                                          nBase10Exponent);
}

static inline void /* Deprecated */
QCBOREncode_AddDecimalFractionToMapN(QCBOREncodeContext *pMe,
                                     const int64_t       nLabel,
                                     const int64_t       nMantissa,
                                     const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFractionToMapN(pMe,
                                         nLabel,
                                         QCBOR_ENCODE_AS_TAG,
                                         nMantissa,
                                         nBase10Exponent);
}


static inline void /* Deprecated */
QCBOREncode_AddTDecimalFractionBigNum(QCBOREncodeContext *pMe,
                                      const uint8_t       uTagRequirement,
                                      const UsefulBufC    Mantissa,
                                      const bool          bIsNegative,
                                      const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFractionBigMantissaRaw(pMe,
                                                 uTagRequirement,
                                                 Mantissa,
                                                 bIsNegative,
                                                 nBase10Exponent);
}


static inline void /* Deprecated */
QCBOREncode_AddTDecimalFractionBigNumToMapSZ(QCBOREncodeContext *pMe,
                                             const char         *szLabel,
                                             const uint8_t       uTagRequirement,
                                             const UsefulBufC    Mantissa,
                                             const bool          bIsNegative,
                                             const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFractionBigMantissaRawToMapSZ(pMe,
                                                        szLabel,
                                                        uTagRequirement,
                                                        Mantissa,
                                                        bIsNegative,
                                                        nBase10Exponent);
}

static inline void /* Deprecated */
QCBOREncode_AddTDecimalFractionBigNumToMapN(QCBOREncodeContext *pMe,
                                            const int64_t       nLabel,
                                            const uint8_t       uTagRequirement,
                                            const UsefulBufC    Mantissa,
                                            const bool          bIsNegative,
                                            const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFractionBigMantissaRawToMapN(pMe,
                                                       nLabel,
                                                       uTagRequirement,
                                                       Mantissa,
                                                       bIsNegative,
                                                       nBase10Exponent);
}

static inline void /* Deprecated */
QCBOREncode_AddDecimalFractionBigNum(QCBOREncodeContext *pMe,
                                     const UsefulBufC    Mantissa,
                                     const bool          bIsNegative,
                                     const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFractionBigMantissaRaw(pMe,
                                                 QCBOR_ENCODE_AS_TAG,
                                                 Mantissa,
                                                 bIsNegative,
                                                 nBase10Exponent);
}

static inline void /* Deprecated */
QCBOREncode_AddDecimalFractionBigNumToMapSZ(QCBOREncodeContext *pMe,
                                            const char         *szLabel,
                                            const UsefulBufC    Mantissa,
                                            const bool          bIsNegative,
                                            const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFractionBigMantissaRawToMapSZ(pMe,
                                                        szLabel,
                                                        QCBOR_ENCODE_AS_TAG,
                                                        Mantissa,
                                                        bIsNegative,
                                                        nBase10Exponent);
}

static inline void /* Deprecated */
QCBOREncode_AddDecimalFractionBigNumToMapN(QCBOREncodeContext *pMe,
                                           const int64_t       nLabel,
                                           const UsefulBufC    Mantissa,
                                           const bool          bIsNegative,
                                           const int64_t       nBase10Exponent)
{
   QCBOREncode_AddTDecimalFractionBigMantissaRawToMapN(pMe,
                                                       nLabel,
                                                       QCBOR_ENCODE_AS_TAG,
                                                       Mantissa,
                                                       bIsNegative,
                                                       nBase10Exponent);
}


static inline void /* Deprecated */
QCBOREncode_AddBigFloat(QCBOREncodeContext *pMe,
                        const int64_t       nMantissa,
                        const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloat(pMe,
                            QCBOR_ENCODE_AS_TAG,
                            nMantissa,
                            nBase2Exponent);
}

static inline void /* Deprecated */
QCBOREncode_AddBigFloatToMap(QCBOREncodeContext *pMe,
                             const char         *szLabel,
                             const int64_t       nMantissa,
                             const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloatToMapSZ(pMe,
                                   szLabel,
                                   QCBOR_ENCODE_AS_TAG,
                                   nMantissa,
                                   nBase2Exponent);
}

static inline void /* Deprecated */
QCBOREncode_AddBigFloatToMapN(QCBOREncodeContext *pMe,
                              const int64_t       nLabel,
                              const int64_t       nMantissa,
                              const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloatToMapN(pMe,
                                  nLabel,
                                  QCBOR_ENCODE_AS_TAG,
                                  nMantissa,
                                  nBase2Exponent);
}

static inline void /* Deprecated */
QCBOREncode_AddTBigFloatBigNum(QCBOREncodeContext *pMe,
                               const uint8_t       uTagRequirement,
                               const UsefulBufC    Mantissa,
                               const bool          bIsNegative,
                               const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloatBigMantissaRaw(pMe,
                                          uTagRequirement,
                                          Mantissa,
                                          bIsNegative,
                                          nBase2Exponent);
}

static inline void /* Deprecated */
QCBOREncode_AddTBigFloatBigNumToMapSZ(QCBOREncodeContext *pMe,
                                      const char         *szLabel,
                                      const uint8_t       uTagRequirement,
                                      const UsefulBufC    Mantissa,
                                      const bool          bIsNegative,
                                      const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloatBigMantissaRawToMapSZ(pMe,
                                                 szLabel,
                                                 uTagRequirement,
                                                 Mantissa,
                                                 bIsNegative,
                                                 nBase2Exponent);
}

static inline void /* Deprecated */
QCBOREncode_AddTBigFloatBigNumToMapN(QCBOREncodeContext *pMe,
                                     const int64_t       nLabel,
                                     const uint8_t       uTagRequirement,
                                     const UsefulBufC    Mantissa,
                                     const bool          bIsNegative,
                                     const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloatBigMantissaRawToMapN(pMe,
                                                nLabel,
                                                uTagRequirement,
                                                Mantissa,
                                                bIsNegative,
                                                nBase2Exponent);
}


static inline void /* Deprecated */
QCBOREncode_AddBigFloatBigNum(QCBOREncodeContext *pMe,
                              const UsefulBufC    Mantissa,
                              const bool          bIsNegative,
                              const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloatBigMantissaRaw(pMe,
                                          QCBOR_ENCODE_AS_TAG,
                                          Mantissa,
                                          bIsNegative,
                                          nBase2Exponent);
}

static inline void /* Deprecated */
QCBOREncode_AddBigFloatBigNumToMap(QCBOREncodeContext *pMe,
                                   const char         *szLabel,
                                   const UsefulBufC    Mantissa,
                                   const bool          bIsNegative,
                                   const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloatBigMantissaRawToMapSZ(pMe,
                                                 szLabel,
                                                 QCBOR_ENCODE_AS_TAG,
                                                 Mantissa,
                                                 bIsNegative,
                                                 nBase2Exponent);
}

static inline void /* Deprecated */
QCBOREncode_AddBigFloatBigNumToMapN(QCBOREncodeContext *pMe,
                                    const int64_t       nLabel,
                                    const UsefulBufC    Mantissa,
                                    const bool          bIsNegative,
                                    const int64_t       nBase2Exponent)
{
   QCBOREncode_AddTBigFloatBigMantissaRawToMapN(pMe,
                                                nLabel,
                                                QCBOR_ENCODE_AS_TAG,
                                                Mantissa,
                                                bIsNegative,
                                                nBase2Exponent);
}

#endif /* ! QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA */

/* ========================================================================= *
 *    END OF INLINES FOR DEPRECATED FUNCTIONS                                *
 * ========================================================================= */


#ifdef __cplusplus
}
#endif

#endif /* qcbor_number_encode_h */
