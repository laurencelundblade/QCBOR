/* ===========================================================================
 * qcbor_tag_encode.h
 * Forked from qcbor_encode.h 12/17/2024
 *
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

#ifndef qcbor_tag_encode_h
#define qcbor_tag_encode_h


#include "qcbor/qcbor_common.h"
#include "qcbor/qcbor_private.h"
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#if 0
} // Keep editor indention formatting happy
#endif
#endif


/**
 * @file qcbor_tag_encode.h
 *
 * @anchor Tags-Overview
 *
 * ## Tags Overview
 *
 * Any CBOR data item can be made into a tag to add semantics, define a
 * new data type or such. Some tags are fully standardized and some are
 * just registered. Others are not registered and used in a proprietary
 * way.
 *
 * Encoding and decoding of many of the registered tags is fully
 * implemented by QCBOR. It is also possible to encode and decode tags
 * that are not directly supported.  For many use cases the built-in tag
 * support should be adequate.
 *
 * For example, the registered epoch date tag is supported in encoding
 * by QCBOREncode_AddTDateEpoch() and in decoding by @ref
 * QCBOR_TYPE_DATE_EPOCH and the @c epochDate member of @ref
 * QCBORItem. This is typical of the built-in tag support. There is an
 * API to encode data for it and a @c QCBOR_TYPE_XXX when it is decoded.
 *
 * Tags are registered in the [IANA CBOR Tags Registry]
 * (https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml). There
 * are roughly three options to create a new tag. First, a public
 * specification can be created and the new tag registered with IANA.
 * This is the most formal. Second, the new tag can be registered with
 * IANA with just a short description rather than a full specification.
 * These tags must be greater than 256. Third, a tag can be used without
 * any IANA registration, though the registry should be checked to see
 * that the new value doesn't collide with one that is registered. The
 * value of these tags must be 256 or larger.
 *
 * See also @ref CBORTags and @ref Tag-Usage
 *
 * The encoding side of tags not built-in is handled by
 * QCBOREncode_AddTagNumber() and is relatively simple. Tag decoding is more
 * complex and mainly handled by QCBORDecode_GetNext(). Decoding of the
 * structure of tagged data not built-in (if there is any) has to be
 * implemented by the caller.
 */


/**
 * Output the full CBOR tag. See @ref CBORTags, @ref Tag-Usage and
 * @ref Tags-Overview.
 */
#define QCBOR_ENCODE_AS_TAG      0

/**
 * Output only the 'borrowed' content format for the relevant tag.
 * See @ref CBORTags, @ref Tag-Usage and @ref Tags-Overview.
 */
#define QCBOR_ENCODE_AS_BORROWED 1



/**
 * @brief Add a tag number.
 *
 * @param[in] pCtx  The encoding context to add the tag to.
 * @param[in] uTag  The tag to add
 *
 * This outputs a CBOR major type 6 item that tags the next data item
 * that is output usually to indicate it is some new data type.
 *
 * For many of the common standard tags, a function to encode data
 * using it is provided and this is not needed. For example,
 * QCBOREncode_AddTDateEpoch() already exists to output integers
 * representing dates with the right tag.
 *
 * The tag is applied to the next data item added to the encoded
 * output. That data item that is to be tagged can be of any major
 * CBOR type. Any number of tags can be added to a data item by
 * calling this multiple times before the data item is added.
 *
 * See @ref Tags-Overview for discussion of creating new non-standard
 * tags. See QCBORDecode_GetNext() for discussion of decoding custom
 * tags.
 */
static void
QCBOREncode_AddTagNumber(QCBOREncodeContext *pCtx, uint64_t uTag);


/**
 * @brief  Add an epoch-based date.
 *
 * @param[in] pCtx             The encoding context to add the date to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] nDate            Number of seconds since 1970-01-01T00:00Z
 *                             in UTC time.
 *
 * As per RFC 8949 this is similar to UNIX/Linux/POSIX dates. This is
 * the most compact way to specify a date and time in CBOR. Note that
 * this is always UTC and does not include the time zone.  Use
 * QCBOREncode_AddDateString() if you want to include the time zone.
 *
 * The preferred integer serialization rules apply here so the date will be
 * encoded in a minimal number of bytes. Until about the year 2106
 * these dates will encode in 6 bytes -- one byte for the tag, one
 * byte for the type and 4 bytes for the integer. After that it will
 * encode to 10 bytes.
 *
 * Negative values are supported for dates before 1970.
 *
 * If you care about leap-seconds and that level of accuracy, make sure
 * the system you are running this code on does it correctly. This code
 * just takes the value passed in.
 *
 * This implementation cannot encode fractional seconds using float or
 * double even though that is allowed by CBOR, but you can encode them
 * if you want to by calling QCBOREncode_AddTagNumber() and QCBOREncode_AddDouble().
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 *
 * See also QCBOREncode_AddTDaysEpoch().
 */
static void
QCBOREncode_AddTDateEpoch(QCBOREncodeContext *pCtx,
                          uint8_t             uTagRequirement,
                          int64_t             nDate);

/** See QCBOREncode_AddTDateEpoch(). */
static void
QCBOREncode_AddTDateEpochToMapSZ(QCBOREncodeContext *pCtx,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 int64_t             nDate);

/** See QCBOREncode_AddTDateEpoch(). */
static void
QCBOREncode_AddTDateEpochToMapN(QCBOREncodeContext *pCtx,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                int64_t             nDate);


/**
 *  @brief  Add an epoch-based day-count date.
 *
 *  @param[in] pCtx             The encoding context to add the date to.
 *  @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                              @ref QCBOR_ENCODE_AS_BORROWED.
 *  @param[in] nDays            Number of days before or after 1970-01-0.
 *
 * This date format is described in
 * [RFC 8943] (https://www.rfc-editor.org/rfc/rfc8943.html).
 *
 * The preferred integer serialization rules apply here so the date
 * will be encoded in a minimal number of bytes. Until about the year
 * 2149 these dates will encode in 4 bytes -- one byte for the tag,
 * one byte for the type and 2 bytes for the integer.
 *
 * See also QCBOREncode_AddTDateEpoch().
 */
static void
QCBOREncode_AddTDaysEpoch(QCBOREncodeContext *pCtx,
                          uint8_t             uTagRequirement,
                          int64_t             nDays);

/** See QCBOREncode_AddTDaysEpoch(). */
static void
QCBOREncode_AddTDaysEpochToMapSZ(QCBOREncodeContext *pCtx,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 int64_t             nDays);

/** See QCBOREncode_AddTDaysEpoch(). */
static void
QCBOREncode_AddTDaysEpochToMapN(QCBOREncodeContext *pCtx,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                int64_t             nDays);


/**
 * @brief Add a binary UUID to the encoded output.
 *
 * @param[in] pCtx             The encoding context to add the UUID to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] Bytes            Pointer and length of the binary UUID.
 *
 * A binary UUID as defined in [RFC 4122]
 * (https://www.rfc-editor.org/rfc/rfc4122.html) is added to the
 * output.
 *
 * It is output as CBOR major type 2, a binary string, with tag @ref
 * CBOR_TAG_BIN_UUID indicating the binary string is a UUID.
 */
static void
QCBOREncode_AddTBinaryUUID(QCBOREncodeContext *pCtx,
                           uint8_t             uTagRequirement,
                           UsefulBufC          Bytes);

/** See QCBOREncode_AddTBinaryUUID(). */
static void
QCBOREncode_AddTBinaryUUIDToMapSZ(QCBOREncodeContext *pCtx,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  UsefulBufC          Bytes);

/** See QCBOREncode_AddTBinaryUUID(). */
static void
QCBOREncode_AddTBinaryUUIDToMapN(QCBOREncodeContext *pCtx,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC          Bytes);


/**
 * @brief Add a text URI to the encoded output.
 *
 * @param[in] pCtx             The encoding context to add the URI to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] URI              Pointer and length of the URI.
 *
 * The format of URI must be per [RFC 3986]
 * (https://www.rfc-editor.org/rfc/rfc3986.html).
 *
 * It is output as CBOR major type 3, a text string, with tag @ref
 * CBOR_TAG_URI indicating the text string is a URI.
 *
 * A URI in a NULL-terminated string, @c szURI, can be easily added with
 * this code:
 *
 *      QCBOREncode_AddTURI(pCtx, QCBOR_ENCODE_AS_TAG, UsefulBuf_FromSZ(szURI));
 */
static void
QCBOREncode_AddTURI(QCBOREncodeContext *pCtx,
                    uint8_t             uTagRequirement,
                    UsefulBufC          URI);

/** See QCBOREncode_AddTURI(). */
static void
QCBOREncode_AddTURIToMapSZ(QCBOREncodeContext *pCtx,
                           const char         *szLabel,
                           uint8_t             uTagRequirement,
                           UsefulBufC          URI);

/** See QCBOREncode_AddTURI(). */
static void
QCBOREncode_AddTURIToMapN(QCBOREncodeContext *pCtx,
                          int64_t             nLabel,
                          uint8_t             uTagRequirement,
                          UsefulBufC          URI);


/**
 * @brief Add Base64-encoded text to encoded output.
 *
 * @param[in] pCtx             The encoding context to add the base-64 text to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] B64Text          Pointer and length of the base-64 encoded text.
 *
 * The text content is Base64 encoded data per [RFC 4648]
 * (https://www.rfc-editor.org/rfc/rfc4648.html).
 *
 * It is output as CBOR major type 3, a text string, with tag @ref
 * CBOR_TAG_B64 indicating the text string is Base64 encoded.
 */
static void
QCBOREncode_AddTB64Text(QCBOREncodeContext *pCtx,
                        uint8_t             uTagRequirement,
                        UsefulBufC          B64Text);

/** See QCBOREncode_AddTB64Text(). */
static void
QCBOREncode_AddTB64TextToMapSZ(QCBOREncodeContext *pCtx,
                               const char         *szLabel,
                               uint8_t             uTagRequirement,
                               UsefulBufC          B64Text);

/** See QCBOREncode_AddTB64Text(). */
static void
QCBOREncode_AddTB64TextToMapN(QCBOREncodeContext *pCtx,
                              int64_t nLabel,
                              uint8_t uTagRequirement,
                              UsefulBufC B64Text);


/**
 * @brief Add base64url encoded data to encoded output.
 *
 * @param[in] pCtx             The encoding context to add the base64url to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] B64Text          Pointer and length of the base64url encoded text.
 *
 * The text content is base64URL encoded text as per
 * [RFC 4648] (https://www.rfc-editor.org/rfc/rfc4648.html).
 *
 * It is output as CBOR major type 3, a text string, with tag
 * @ref CBOR_TAG_B64URL indicating the text string is a Base64url
 * encoded.
 */
static void
QCBOREncode_AddTB64URLText(QCBOREncodeContext *pCtx,
                           uint8_t             uTagRequirement,
                           UsefulBufC          B64Text);

/** See QCBOREncode_AddTB64URLText(). */
static void
QCBOREncode_AddTB64URLTextToMapSZ(QCBOREncodeContext *pCtx,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  UsefulBufC          B64Text);

/** See QCBOREncode_AddTB64URLText(). */
static void
QCBOREncode_AddTB64URLTextToMapN(QCBOREncodeContext *pCtx,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC          B64Text);


/**
 * @brief Add Perl Compatible Regular Expression.
 *
 * @param[in] pCtx             Encoding context to add the regular expression to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] Regex            Pointer and length of the regular expression.
 *
 * The text content is Perl Compatible Regular
 * Expressions (PCRE) / JavaScript syntax [ECMA262].
 *
 * It is output as CBOR major type 3, a text string, with tag @ref
 * CBOR_TAG_REGEX indicating the text string is a regular expression.
 */
static void
QCBOREncode_AddTRegex(QCBOREncodeContext *pCtx,
                      uint8_t            uTagRequirement,
                      UsefulBufC         Regex);

/** See QCBOREncode_AddTRegex(). */
static void
QCBOREncode_AddTRegexToMapSZ(QCBOREncodeContext *pCtx,
                             const char         *szLabel,
                             uint8_t             uTagRequirement,
                             UsefulBufC          Regex);

/** See QCBOREncode_AddTRegex(). */
static void
QCBOREncode_AddTRegexToMapN(QCBOREncodeContext *pCtx,
                            int64_t             nLabel,
                            uint8_t             uTagRequirement,
                            UsefulBufC          Regex);


/**
 * @brief MIME encoded data to the encoded output.
 *
 * @param[in] pCtx             The encoding context to add the MIME data to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] MIMEData         Pointer and length of the MIME data.
 *
 * The text content is in MIME format per [RFC 2045]
 * (https://www.rfc-editor.org/rfc/rfc2045.html) including the headers.
 *
 * It is output as CBOR major type 2, a binary string, with tag
 * @ref CBOR_TAG_BINARY_MIME indicating the string is MIME data.  This
 * outputs tag 257, not tag 36, as it can carry any type of MIME
 * binary, 7-bit, 8-bit, quoted-printable and base64 where tag 36
 * cannot.
 *
 * Previous versions of QCBOR, those before spiffy decode, output tag
 * 36. Decoding supports both tag 36 and 257.  (if the old behavior
 * with tag 36 is needed, copy the inline functions below and change
 * the tag number).
 *
 * See also QCBORDecode_GetMIMEMessage() and
 * @ref QCBOR_TYPE_BINARY_MIME.
 *
 * This does no translation of line endings. See QCBOREncode_AddText()
 * for a discussion of line endings in CBOR.
 */
static void
QCBOREncode_AddTMIMEData(QCBOREncodeContext *pCtx,
                         uint8_t             uTagRequirement,
                         UsefulBufC          MIMEData);

/** See QCBOREncode_AddTMIMEData(). */
static void
QCBOREncode_AddTMIMEDataToMapSZ(QCBOREncodeContext *pCtx,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                UsefulBufC          MIMEData);

/** See QCBOREncode_AddTMIMEData(). */
static void
QCBOREncode_AddTMIMEDataToMapN(QCBOREncodeContext *pCtx,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               UsefulBufC          MIMEData);


/**
 * @brief  Add an RFC 3339 date string
 *
 * @param[in] pCtx             The encoding context to add the date to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] szDate           Null-terminated string with date to add.
 *
 * The string szDate should be in the form of
 * [RFC 3339] (https://www.rfc-editor.org/rfc/rfc3339.html) as defined
 * by section 3.3 in [RFC 4287] (https://www.rfc-editor.org/rfc/rfc4287.html).
 * This is as described in section 3.4.1 in [RFC 8949]
 * (https://www.rfc-editor.org/rfc/rfc8949.html#section3.1.4).
 *
 * Note that this function doesn't validate the format of the date
 * string at all. If you add an incorrect format date string, the
 * generated CBOR will be incorrect and the receiver may not be able
 * to handle it.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 *
 * See also QCBOREncode_AddTDayString().
 */
static void
QCBOREncode_AddTDateString(QCBOREncodeContext *pCtx,
                           uint8_t             uTagRequirement,
                           const char         *szDate);

/** See QCBOREncode_AddTDateString(). */
static void
QCBOREncode_AddTDateStringToMapSZ(QCBOREncodeContext *pCtx,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  const char         *szDate);

/** See QCBOREncode_AddTDateString(). */
static void
QCBOREncode_AddTDateStringToMapN(QCBOREncodeContext *pCtx,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 const char         *szDate);


/**
 * @brief  Add a date-only string.
 *
 * @param[in] pCtx             The encoding context to add the date to.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] szDate           Null-terminated string with date to add.
 *
 * This date format is described in
 * [RFC 8943] (https://www.rfc-editor.org/rfc/rfc8943.html), but that mainly
 * references RFC 3339.  The string szDate must be in the forrm
 * specified the ABNF for a full-date in
 * [RFC 3339] (https://www.rfc-editor.org/rfc/rfc3339.html). Examples of this
 * are "1985-04-12" and "1937-01-01".  The time and the time zone are
 * never included.
 *
 * Note that this function doesn't validate the format of the date
 * string at all. If you add an incorrect format date string, the
 * generated CBOR will be incorrect and the receiver may not be able
 * to handle it.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 *
 * See also QCBOREncode_AddTDateString().
 */
static void
QCBOREncode_AddTDaysString(QCBOREncodeContext *pCtx,
                           uint8_t             uTagRequirement,
                           const char         *szDate);

/** See QCBOREncode_AddTDaysString(). */
static void
QCBOREncode_AddTDaysStringToMapSZ(QCBOREncodeContext *pCtx,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  const char         *szDate);

/** See QCBOREncode_AddTDaysString(). */
static void
QCBOREncode_AddTDaysStringToMapN(QCBOREncodeContext *pCtx,
                                 int64_t             nLabel,
                                 uint8_t             uTagRequirement,
                                 const char         *szDate);




/* ========================================================================= *
 *    BEGINNING OF DEPRECATED FUNCTION DECLARATIONS                          *
 *                                                                           *
 *    There is no plan to remove these in future versions.                   *
 *    They just have been replaced by something better.                      *
 * ========================================================================= */

/** @deprecated Use QCBOREncode_AddTDateEpoch() instead. */
static void
QCBOREncode_AddDateEpoch(QCBOREncodeContext *pCtx, int64_t nDate);

/** @deprecated Use QCBOREncode_AddTDateEpochToMapSZ() instead. */
static void
QCBOREncode_AddDateEpochToMap(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nDate);

/** @deprecated Use QCBOREncode_AddTDateEpochToMapN() instead. */
static void
QCBOREncode_AddDateEpochToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, int64_t nDate);

/** @deprecated Use QCBOREncode_AddTBinaryUUID() instead. */
static void
QCBOREncode_AddBinaryUUID(QCBOREncodeContext *pCtx, UsefulBufC Bytes);

/** @deprecated Use QCBOREncode_AddTBinaryUUIDToMapSZ() instead. */
static void
QCBOREncode_AddBinaryUUIDToMap(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC Bytes);

/** @deprecated Use QCBOREncode_AddTBinaryUUIDToMapN() instead. */
static void
QCBOREncode_AddBinaryUUIDToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, UsefulBufC Bytes);

/** @deprecated Use QCBOREncode_AddTagNumber() instead. */
static void
QCBOREncode_AddTag(QCBOREncodeContext *pCtx, uint64_t uTag);

/** @deprecated Use QCBOREncode_AddTURI() instead. */
static void
QCBOREncode_AddURI(QCBOREncodeContext *pCtx, UsefulBufC URI);

/** @deprecated Use QCBOREncode_AddTURIToMapSZ() instead. */
static void
QCBOREncode_AddURIToMap(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC URI);

/** @deprecated Use QCBOREncode_AddTURIToMapN() instead. */
static void
QCBOREncode_AddURIToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, UsefulBufC URI);

/** @deprecated Use QCBOREncode_AddTB64Text() instead. */
static void
QCBOREncode_AddB64Text(QCBOREncodeContext *pCtx, UsefulBufC B64Text);

/** @deprecated Use QCBOREncode_AddTB64TextToMapSZ() instead. */
static void
QCBOREncode_AddB64TextToMap(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC B64Text);

/** @deprecated Use QCBOREncode_AddTB64TextToMapN() instead. */
static void
QCBOREncode_AddB64TextToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, UsefulBufC B64Text);

/** @deprecated Use QCBOREncode_AddTB64URLText() instead. */
static void
QCBOREncode_AddB64URLText(QCBOREncodeContext *pCtx, UsefulBufC B64Text);

/** @deprecated Use QCBOREncode_AddTB64URLTextToMapSZ() instead. */
static void
QCBOREncode_AddB64URLTextToMap(QCBOREncodeContext *pCtx,
                               const char         *szLabel,
                               UsefulBufC          B64Text);

/** @deprecated Use QCBOREncode_AddTB64URLTextToMapN() instead. */
static void
QCBOREncode_AddB64URLTextToMapN(QCBOREncodeContext *pCtx,
                                int64_t             nLabel,
                                UsefulBufC          B64Text);

/** @deprecated Use QCBOREncode_AddTRegex() instead. */
static void
QCBOREncode_AddRegex(QCBOREncodeContext *pCtx, UsefulBufC Regex);

/** @deprecated Use QCBOREncode_AddTRegexToMapSZ() instead. */
static void
QCBOREncode_AddRegexToMap(QCBOREncodeContext *pCtx,
                          const char         *szLabel,
                          UsefulBufC          Regex);

/** @deprecated Use QCBOREncode_AddTRegexToMapN() instead. */
static void
QCBOREncode_AddRegexToMapN(QCBOREncodeContext *pCtx,
                           int64_t             nLabel,
                           UsefulBufC          Regex);

/** @deprecated Use QCBOREncode_AddTMIMEData() instead. */
static void
QCBOREncode_AddMIMEData(QCBOREncodeContext *pCtx, UsefulBufC MIMEData);

/** @deprecated Use QCBOREncode_AddTMIMEDataToMapSZ() instead. */
static void
QCBOREncode_AddMIMEDataToMap(QCBOREncodeContext *pCtx,
                             const char         *szLabel,
                             UsefulBufC          MIMEData);

/** @deprecated Use QCBOREncode_AddTMIMEDataToMapN() instead. */
static void
QCBOREncode_AddMIMEDataToMapN(QCBOREncodeContext *pCtx,
                              int64_t             nLabel,
                              UsefulBufC          MIMEData);

/** @deprecated Use QCBOREncode_AddTDateString() instead. */
static void
QCBOREncode_AddDateString(QCBOREncodeContext *pCtx, const char *szDate);

/** @deprecated Use QCBOREncode_AddTDateStringToMapSZ() instead. */
static void
QCBOREncode_AddDateStringToMap(QCBOREncodeContext *pCtx,
                               const char         *szLabel,
                               const char         *szDate);

/** @deprecated Use QCBOREncode_AddTDateStringToMapN() instead. */
static void
QCBOREncode_AddDateStringToMapN(QCBOREncodeContext *pCtx,
                                int64_t             nLabel,
                                const char         *szDate);


/* ========================================================================= *
 *    END OF DEPRECATED FUNCTION DECLARATIONS                                *
 * ========================================================================= */




/* ========================================================================= *
 *    BEGINNING OF PRIVATE INLINE IMPLEMENTATION                             *
 * ========================================================================= */


static inline void
QCBOREncode_AddTagNumber(QCBOREncodeContext *pMe, const uint64_t uTag)
{
   QCBOREncode_Private_AppendCBORHead(pMe, CBOR_MAJOR_TYPE_TAG, uTag, 0);
}


static inline void
QCBOREncode_AddTag(QCBOREncodeContext *pMe, const uint64_t uTag)
{
   QCBOREncode_AddTagNumber(pMe, uTag);
}


static inline void
QCBOREncode_AddTDateEpoch(QCBOREncodeContext *pMe,
                          const uint8_t       uTag,
                          const int64_t       nDate)
{
   if(uTag == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, CBOR_TAG_DATE_EPOCH);
   }
   QCBOREncode_AddInt64(pMe, nDate);
}

static inline void
QCBOREncode_AddTDateEpochToMapSZ(QCBOREncodeContext *pMe,
                                 const char         *szLabel,
                                 const uint8_t       uTag,
                                 const int64_t       nDate)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTDateEpoch(pMe, uTag, nDate);
}

static inline void
QCBOREncode_AddTDateEpochToMapN(QCBOREncodeContext *pMe,
                                const int64_t       nLabel,
                                const uint8_t       uTag,
                                const int64_t       nDate)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTDateEpoch(pMe, uTag, nDate);
}

static inline void
QCBOREncode_AddDateEpoch(QCBOREncodeContext *pMe,
                         const int64_t       nDate)
{
   QCBOREncode_AddTDateEpoch(pMe, QCBOR_ENCODE_AS_TAG, nDate);
}

static inline void
QCBOREncode_AddDateEpochToMap(QCBOREncodeContext *pMe,
                              const char         *szLabel,
                              const int64_t       nDate)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddDateEpoch(pMe, nDate);
}

static inline void
QCBOREncode_AddDateEpochToMapN(QCBOREncodeContext *pMe,
                               const int64_t       nLabel,
                               const int64_t       nDate)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddDateEpoch(pMe, nDate);
}


static inline void
QCBOREncode_AddTDaysEpoch(QCBOREncodeContext *pMe,
                          const uint8_t       uTag,
                          const int64_t       nDays)
{
   if(uTag == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, CBOR_TAG_DAYS_EPOCH);
   }
   QCBOREncode_AddInt64(pMe, nDays);
}

static inline void
QCBOREncode_AddTDaysEpochToMapSZ(QCBOREncodeContext *pMe,
                                 const char         *szLabel,
                                 const uint8_t       uTag,
                                 const int64_t       nDays)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTDaysEpoch(pMe, uTag, nDays);
}

static inline void
QCBOREncode_AddTDaysEpochToMapN(QCBOREncodeContext *pMe,
                                const int64_t       nLabel,
                                const uint8_t       uTag,
                                const int64_t       nDays)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTDaysEpoch(pMe, uTag, nDays);
}



static inline void
QCBOREncode_AddTBinaryUUID(QCBOREncodeContext *pMe,
                           const uint8_t       uTagRequirement,
                           const UsefulBufC    Bytes)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, CBOR_TAG_BIN_UUID);
   }
   QCBOREncode_AddBytes(pMe, Bytes);
}

static inline void
QCBOREncode_AddTBinaryUUIDToMapSZ(QCBOREncodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uTagRequirement,
                                  const UsefulBufC    Bytes)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTBinaryUUID(pMe, uTagRequirement, Bytes);
}

static inline void
QCBOREncode_AddTBinaryUUIDToMapN(QCBOREncodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uTagRequirement,
                                 const UsefulBufC    Bytes)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTBinaryUUID(pMe, uTagRequirement, Bytes);
}

static inline void
QCBOREncode_AddBinaryUUID(QCBOREncodeContext *pMe, const UsefulBufC Bytes)
{
   QCBOREncode_AddTBinaryUUID(pMe, QCBOR_ENCODE_AS_TAG, Bytes);
}

static inline void
QCBOREncode_AddBinaryUUIDToMap(QCBOREncodeContext *pMe,
                               const char         *szLabel,
                               const UsefulBufC    Bytes)
{
   QCBOREncode_AddTBinaryUUIDToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, Bytes);
}

static inline void
QCBOREncode_AddBinaryUUIDToMapN(QCBOREncodeContext *pMe,
                                const int64_t       nLabel,
                                const UsefulBufC    Bytes)
{
   QCBOREncode_AddTBinaryUUIDToMapN(pMe,
                                    nLabel,
                                    QCBOR_ENCODE_AS_TAG,
                                    Bytes);
}


static inline void
QCBOREncode_AddTURI(QCBOREncodeContext *pMe,
                    const uint8_t       uTagRequirement,
                    const UsefulBufC    URI)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, CBOR_TAG_URI);
   }
   QCBOREncode_AddText(pMe, URI);
}

static inline void
QCBOREncode_AddTURIToMapSZ(QCBOREncodeContext *pMe,
                           const char         *szLabel,
                           const uint8_t       uTagRequirement,
                           const UsefulBufC    URI)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTURI(pMe, uTagRequirement, URI);
}

static inline void
QCBOREncode_AddTURIToMapN(QCBOREncodeContext *pMe,
                          const int64_t       nLabel,
                          const uint8_t       uTagRequirement,
                          const UsefulBufC    URI)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTURI(pMe, uTagRequirement, URI);
}

static inline void
QCBOREncode_AddURI(QCBOREncodeContext *pMe, const UsefulBufC URI)
{
   QCBOREncode_AddTURI(pMe, QCBOR_ENCODE_AS_TAG, URI);
}

static inline void
QCBOREncode_AddURIToMap(QCBOREncodeContext *pMe,
                        const char         *szLabel,
                        const UsefulBufC    URI)
{
   QCBOREncode_AddTURIToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, URI);
}

static inline void
QCBOREncode_AddURIToMapN(QCBOREncodeContext *pMe,
                         const int64_t       nLabel,
                         const UsefulBufC    URI)
{
   QCBOREncode_AddTURIToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, URI);
}



static inline void
QCBOREncode_AddTB64Text(QCBOREncodeContext *pMe,
                        const uint8_t       uTagRequirement,
                        const UsefulBufC    B64Text)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, CBOR_TAG_B64);
   }
   QCBOREncode_AddText(pMe, B64Text);
}

static inline void
QCBOREncode_AddTB64TextToMapSZ(QCBOREncodeContext *pMe,
                               const char         *szLabel,
                               const uint8_t       uTagRequirement,
                               const UsefulBufC    B64Text)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTB64Text(pMe, uTagRequirement, B64Text);
}

static inline void
QCBOREncode_AddTB64TextToMapN(QCBOREncodeContext *pMe,
                              const int64_t       nLabel,
                              const uint8_t       uTagRequirement,
                              const UsefulBufC    B64Text)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTB64Text(pMe, uTagRequirement, B64Text);
}

static inline void
QCBOREncode_AddB64Text(QCBOREncodeContext *pMe, const UsefulBufC B64Text)
{
   QCBOREncode_AddTB64Text(pMe, QCBOR_ENCODE_AS_TAG, B64Text);
}

static inline void
QCBOREncode_AddB64TextToMap(QCBOREncodeContext *pMe,
                            const char         *szLabel,
                            const UsefulBufC    B64Text)
{
   QCBOREncode_AddTB64TextToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, B64Text);
}

static inline void
QCBOREncode_AddB64TextToMapN(QCBOREncodeContext *pMe,
                             const int64_t       nLabel,
                             const UsefulBufC    B64Text)
{
   QCBOREncode_AddTB64TextToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, B64Text);
}



static inline void
QCBOREncode_AddTB64URLText(QCBOREncodeContext *pMe,
                           const uint8_t       uTagRequirement,
                           const UsefulBufC    B64Text)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, CBOR_TAG_B64URL);
   }
   QCBOREncode_AddText(pMe, B64Text);
}

static inline void
QCBOREncode_AddTB64URLTextToMapSZ(QCBOREncodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uTagRequirement,
                                  const UsefulBufC    B64Text)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTB64URLText(pMe, uTagRequirement, B64Text);
}

static inline void
QCBOREncode_AddTB64URLTextToMapN(QCBOREncodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uTagRequirement,
                                 const UsefulBufC    B64Text)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTB64URLText(pMe, uTagRequirement, B64Text);
}

static inline void
QCBOREncode_AddB64URLText(QCBOREncodeContext *pMe, const UsefulBufC B64Text)
{
   QCBOREncode_AddTB64URLText(pMe, QCBOR_ENCODE_AS_TAG, B64Text);
}

static inline void
QCBOREncode_AddB64URLTextToMap(QCBOREncodeContext *pMe,
                               const char         *szLabel,
                               const UsefulBufC    B64Text)
{
   QCBOREncode_AddTB64URLTextToMapSZ(pMe,
                                     szLabel,
                                     QCBOR_ENCODE_AS_TAG,
                                     B64Text);
}

static inline void
QCBOREncode_AddB64URLTextToMapN(QCBOREncodeContext *pMe,
                                const int64_t       nLabel,
                                const UsefulBufC    B64Text)
{
   QCBOREncode_AddTB64URLTextToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, B64Text);
}


static inline void
QCBOREncode_AddTRegex(QCBOREncodeContext *pMe,
                      const uint8_t       uTagRequirement,
                      const UsefulBufC    Bytes)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, CBOR_TAG_REGEX);
   }
   QCBOREncode_AddText(pMe, Bytes);
}

static inline void
QCBOREncode_AddTRegexToMapSZ(QCBOREncodeContext *pMe,
                             const char         *szLabel,
                             const uint8_t       uTagRequirement,
                             const UsefulBufC    Bytes)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTRegex(pMe, uTagRequirement, Bytes);
}

static inline void
QCBOREncode_AddTRegexToMapN(QCBOREncodeContext *pMe,
                            const int64_t       nLabel,
                            const uint8_t       uTagRequirement,
                            const UsefulBufC    Bytes)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTRegex(pMe, uTagRequirement, Bytes);
}

static inline void
QCBOREncode_AddRegex(QCBOREncodeContext *pMe, const UsefulBufC Bytes)
{
   QCBOREncode_AddTRegex(pMe, QCBOR_ENCODE_AS_TAG, Bytes);
}

static inline void
QCBOREncode_AddRegexToMap(QCBOREncodeContext *pMe,
                          const char         *szLabel,
                          const UsefulBufC    Bytes)
{
   QCBOREncode_AddTRegexToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, Bytes);
}

static inline void
QCBOREncode_AddRegexToMapN(QCBOREncodeContext *pMe,
                           const int64_t       nLabel,
                           const UsefulBufC    Bytes)
{
   QCBOREncode_AddTRegexToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, Bytes);

}


static inline void
QCBOREncode_AddTMIMEData(QCBOREncodeContext *pMe,
                         const uint8_t       uTagRequirement,
                         const UsefulBufC    MIMEData)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, CBOR_TAG_BINARY_MIME);
   }
   QCBOREncode_AddBytes(pMe, MIMEData);
}

static inline void
QCBOREncode_AddTMIMEDataToMapSZ(QCBOREncodeContext *pMe,
                                const char         *szLabel,
                                const uint8_t       uTagRequirement,
                                const UsefulBufC    MIMEData)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTMIMEData(pMe, uTagRequirement, MIMEData);
}

static inline void
QCBOREncode_AddTMIMEDataToMapN(QCBOREncodeContext *pMe,
                               const int64_t       nLabel,
                               const uint8_t       uTagRequirement,
                               const UsefulBufC    MIMEData)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTMIMEData(pMe, uTagRequirement, MIMEData);
}

static inline void
QCBOREncode_AddMIMEData(QCBOREncodeContext *pMe, UsefulBufC MIMEData)
{
   QCBOREncode_AddTMIMEData(pMe, QCBOR_ENCODE_AS_TAG, MIMEData);
}

static inline void
QCBOREncode_AddMIMEDataToMap(QCBOREncodeContext *pMe,
                             const char         *szLabel,
                             const UsefulBufC    MIMEData)
{
   QCBOREncode_AddTMIMEDataToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, MIMEData);
}

static inline void
QCBOREncode_AddMIMEDataToMapN(QCBOREncodeContext *pMe,
                              const int64_t       nLabel,
                              const UsefulBufC    MIMEData)
{
   QCBOREncode_AddTMIMEDataToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, MIMEData);
}


static inline void
QCBOREncode_AddTDateString(QCBOREncodeContext *pMe,
                           const uint8_t       uTagRequirement,
                           const char         *szDate)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, CBOR_TAG_DATE_STRING);
   }
   QCBOREncode_AddSZString(pMe, szDate);
}

static inline void
QCBOREncode_AddTDateStringToMapSZ(QCBOREncodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uTagRequirement,
                                  const char         *szDate)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTDateString(pMe, uTagRequirement, szDate);
}

static inline void
QCBOREncode_AddTDateStringToMapN(QCBOREncodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uTagRequirement,
                                 const char         *szDate)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTDateString(pMe, uTagRequirement, szDate);
}

static inline void
QCBOREncode_AddDateString(QCBOREncodeContext *pMe, const char *szDate)
{
   QCBOREncode_AddTDateString(pMe, QCBOR_ENCODE_AS_TAG, szDate);
}

static inline void
QCBOREncode_AddDateStringToMap(QCBOREncodeContext *pMe,
                               const char         *szLabel,
                               const char         *szDate)
{
   QCBOREncode_AddTDateStringToMapSZ(pMe, szLabel, QCBOR_ENCODE_AS_TAG, szDate);
}

static inline void
QCBOREncode_AddDateStringToMapN(QCBOREncodeContext *pMe,
                                const int64_t       nLabel,
                                const char         *szDate)
{
   QCBOREncode_AddTDateStringToMapN(pMe, nLabel, QCBOR_ENCODE_AS_TAG, szDate);
}


static inline void
QCBOREncode_AddTDaysString(QCBOREncodeContext *pMe,
                           const uint8_t       uTagRequirement,
                           const char         *szDate)
{
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, CBOR_TAG_DAYS_STRING);
   }
   QCBOREncode_AddSZString(pMe, szDate);
}

static inline void
QCBOREncode_AddTDaysStringToMapSZ(QCBOREncodeContext *pMe,
                                  const char         *szLabel,
                                  const uint8_t       uTagRequirement,
                                  const char         *szDate)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddTDaysString(pMe, uTagRequirement, szDate);
}

static inline void
QCBOREncode_AddTDaysStringToMapN(QCBOREncodeContext *pMe,
                                 const int64_t       nLabel,
                                 const uint8_t       uTagRequirement,
                                 const char         *szDate)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddTDaysString(pMe, uTagRequirement, szDate);
}


/* ======================================================================== *
 *    END OF PRIVATE INLINE IMPLEMENTATION                                  *
 * ======================================================================== */


#ifdef __cplusplus
}
#endif

#endif /* qcbor_tag_encode_h */
