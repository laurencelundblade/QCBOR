/* ==========================================================================
 * qcbor_tag_decode.h -- Tag decoding
 *
 * Copyright (c) 2024, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Forked from qcbor_decode.c on 9/5/24
 * ========================================================================== */

#ifndef qcbor_tag_decode_h
#define qcbor_tag_decode_h

#include "qcbor/qcbor_main_decode.h"


#ifdef __cplusplus
extern "C" {
#if 0
} // Keep editor indention formatting happy
#endif
#endif

/**
 * @file qcbor_tag_decode.h
 *
 * This file defines the interface for tag decoders that turn tags
 * into custom QCBORItems with custom user-defined CBOR_TYPEs using
 * callbacks.
 *
 * This also gives function prototypes for callbacks that are supplied
 * for standard CBOR data types like dates and big numbers.
 *
 * This is one of two main facilities for handling tags in CBOR. The
 * other is QCBORDecode_GetNextTagNumber().
 *
 * This file is new in QCBOR v2.
 *
 * @anchor Tag-Decoding
 *
 * ## Tags Decoding
 *
 * TODO: lots to write here
 *
 *  * @anchor Tag-Usage
 * ## Tag Usage
 *
 * Data types beyond the basic CBOR types of numbers, strings, maps and
 * arrays are called tags. The main registry of these new types is in
 * the IANA CBOR tags registry. These new types may be simple such a
 * number that is to be interpreted as a date, or of moderate complexity
 * such as defining a decimal fraction that is an array containing a
 * mantissa and exponent, or complex such as format for signing and
 * encryption.
 *
 * When a tag occurs in a protocol it is encoded as an integer tag
 * number plus the content of the tag.
 *
 * The content format of a tag may also be "borrowed". For example, a
 * protocol definition may say that a particular data item is an epoch
 * date just like tag 1, but not actually tag 1. In practice the
 * difference is the presence or absence of the integer tag number in
 * the encoded CBOR.
 *
 * The decoding functions for these new types takes a tag requirement
 * parameter to say whether the item is a tag, is just borrowing the
 * content format and is not a tag, or whether either is OK.
 *
 * If the parameter indicates the item must be a tag (@ref
 * QCBOR_TAG_REQUIREMENT_TAG), then @ref QCBOR_ERR_UNEXPECTED_TYPE is
 * set if it is not one of the expected tag types. To decode correctly
 * the contents of the tag must also be of the correct type. For
 * example, to decode an epoch date tag the content must be an integer
 * or floating-point value.
 *
 * If the parameter indicates it should not be a tag
 * (@ref  QCBOR_TAG_REQUIREMENT_NOT_A_TAG), then
 *  @ref QCBOR_ERR_UNEXPECTED_TYPE set if it is a tag or the type of the
 * encoded CBOR is not what is expected.  In the example of an epoch
 * date, the data type must be an integer or floating-point value. This
 * is the case where the content format of a tag is borrowed.
 *
 * The parameter can also indicate that either a tag or no tag is
 * allowed ( @ref QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG ).  A good protocol
 * design should however be clear and choose one or the other and not
 * need this option. This is a way to implement "be liberal in what you
 * accept", however these days that is less in favor. See
 * https://tools.ietf.org/id/draft-thomson-postel-was-wrong-03.html.
 *
 * Map searching works with indefinite length strings. A string
 * allocator must be set up the same as for any handling of indefinite
 * length strings.  However, It currently over-allocates memory from the
 * string pool and thus requires a much larger string pool than it
 * should. The over-allocation happens every time a map is searched by
 * label.  (This may be corrected in the future).
 *
 *
 * TODO: this text isn't right
 * In v1, some spiffy decode functions ignored tag numbers and
 * some didn't.  For example, GetInt64 ignored and GetString didn't.
 * The "GetXxx" where Xxxx is a tag ignore conditionally based
 * on an argument.
 * (Would be good to verify this with tests)
 *
 * Do we fix the behavior of GetString in v1?  Relax so it
 * allows tag numbers like the rest? Probably.
 *
 * In v2, the whole mechanism is with GetTagNumbers. They are
 * never ignored and they must always be consumed.
 *
 * With v2 in v1 mode, the functions that were ignoring
 * tags must go back to ignoring them.
 *
 * How does TagRequirement work in v2?
 *
 * GetInt64 and GetString require all tag numbs to be processed
 * to work.
 */



/** The data item must be a tag of the expected type. It is an error
 *  if it is not. For example when calling QCBORDecode_GetEpochDate(),
 *  the data item must be an @ref CBOR_TAG_DATE_EPOCH tag.  See
 *  @ref Tag-Usage. */
#define QCBOR_TAG_REQUIREMENT_TAG 0

/** The data item must be of the type expected for content data type
 *  being fetched. It is an error if it is not. For example, when
 *  calling QCBORDecode_GetEpochDate() and it must not be an @ref
 *  CBOR_TAG_DATE_EPOCH tag. See @ref Tag-Usage. */
#define QCBOR_TAG_REQUIREMENT_NOT_A_TAG  1

/** Either of the above two are allowed. This allows implementation of
 *  being liberal in what you receive, but it is better if CBOR-based
 *  protocols pick one and stick to and not required the reciever to
 *  take either. See @ref Tag-Usage. */
#define QCBOR_TAG_REQUIREMENT_OPTIONAL_TAG 2

/** Add this into the above value if other tags not processed by QCBOR
 *  are to be allowed to surround the data item. See @ref Tag-Usage. */
#define QCBOR_TAG_REQUIREMENT_ALLOW_ADDITIONAL_TAGS 0x80


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

QCBORError
QCBORDecode_GetNextTagNumberInMapN(QCBORDecodeContext *pCtx, int64_t nLabel, uint64_t *puTagNumber);


QCBORError
QCBORDecode_GetNextTagNumberInMapSZ(QCBORDecodeContext *pCtx, const char *szLabel, uint64_t *puTagNumber);



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
 * @brief Decode some byte-string wrapped CBOR.
 *
 * @param[in] pCtx    The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pBstr  Pointer and length of byte-string wrapped CBOR (optional).
 *
 * This is for use on some CBOR that has been wrapped in a byte
 * string. There are several ways that this can occur.
 *
 * First is tag 24 and tag 63. Tag 24 wraps a single CBOR data item
 * and 63 a CBOR sequence.  This implementation doesn't distinguish
 * between the two (it would be more code and doesn't seem important).
 *
 * The @ref Tag-Usage discussion on the tag requirement applies here
 * just the same as any other tag.
 *
 * In other cases, CBOR is wrapped in a byte string, but it is
 * identified as CBOR by other means. The contents of a COSE payload
 * are one example of that. They can be identified by the COSE content
 * type, or they can be identified as CBOR indirectly by the protocol
 * that uses COSE. for example, if a blob of CBOR is identified as a
 * CWT, then the COSE payload is CBOR.  To enter into CBOR of this
 * type use the @ref QCBOR_TAG_REQUIREMENT_NOT_A_TAG as the \c
 * uTagRequirement argument.
 *
 * Note that byte string wrapped CBOR can also be decoded by getting
 * the byte string with QCBORDecode_GetItem() or
 * QCBORDecode_GetByteString() and feeding it into another instance of
 * QCBORDecode. Doing it with this function has the advantage of using
 * less memory as another instance of QCBORDecode is not necessary.
 *
 * When the wrapped CBOR is entered with this function, the pre-order
 * traversal and such are bounded to the wrapped
 * CBOR. QCBORDecode_ExitBstrWrapped() must be called to resume
 * processing CBOR outside the wrapped CBOR.
 *
 * This does not work on indefinite-length strings. The
 * error @ref QCBOR_ERR_CANNOT_ENTER_ALLOCATED_STRING will be set.
 *
 * If @c pBstr is not @c NULL the pointer and length of the wrapped
 * CBOR will be returned. This is usually not needed, but sometimes
 * useful, particularly in the case of verifying signed data like the
 * COSE payload. This is usually the pointer and length of the data is
 * that is hashed or MACed.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_ExitBstrWrapped(), QCBORDecode_EnterMap() and
 * QCBORDecode_EnterArray().
 */
void
QCBORDecode_EnterBstrWrapped(QCBORDecodeContext *pCtx,
                             uint8_t             uTagRequirement,
                             UsefulBufC         *pBstr);

void
QCBORDecode_EnterBstrWrappedFromMapN(QCBORDecodeContext *pCtx,
                                     int64_t             nLabel,
                                     uint8_t             uTagRequirement,
                                     UsefulBufC         *pBstr);

void
QCBORDecode_EnterBstrWrappedFromMapSZ(QCBORDecodeContext *pCtx,
                                      const char         *szLabel,
                                      uint8_t             uTagRequirement,
                                      UsefulBufC         *pBstr);


/**
 * @brief Exit some bstr-wrapped CBOR  has been enetered.
 *
 * @param[in] pCtx  The decode context.
 *
 * Bstr-wrapped CBOR must have been entered for this to succeed.
 *
 * The items in the wrapped CBOR that was entered do not have to have
 * been consumed for this to succeed.
 *
 * The this sets the traversal cursor to the item after the
 * byte string that was exited.
 */
void
QCBORDecode_ExitBstrWrapped(QCBORDecodeContext *pCtx);




/**
 * @brief Decode the next item as a date string.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pDateString     The decoded date.
 *
 * This decodes the standard CBOR date/time string tag, integer tag
 * number of 0, or encoded CBOR that is not a tag, but borrows the
 * date string content format.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_DATE_STRING, QCBOREncode_AddDateString() and
 * @ref QCBOR_TYPE_DATE_STRING.
 */
static void
QCBORDecode_GetDateString(QCBORDecodeContext *pCtx,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pDateString);

static void
QCBORDecode_GetDateStringInMapN(QCBORDecodeContext *pCtx,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                UsefulBufC         *pDateString);

static void
QCBORDecode_GetDateStringInMapSZ(QCBORDecodeContext *pCtx,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC         *pDateString);


/**
 * @brief Decode the next item as an epoch date.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pnTime          The decoded epoch date.
 *
 * This decodes the standard CBOR epoch date/time tag, integer tag
 * number of 1. This will also decode any integer or floating-point
 * number as an epoch date (a tag 1 epoch date is just an integer or
 * floating-point number).
 *
 * This will set @ref QCBOR_ERR_DATE_OVERFLOW if the input integer
 * will not fit in an @c int64_t. Note that an @c int64_t can
 * represent a range of over 500 billion years with one second
 * resolution.
 *
 * Floating-point dates are always returned as an @c int64_t. The
 * fractional part is discarded.
 *
 * If the input is a floating-point date and the QCBOR library is
 * compiled with some or all floating-point features disabled, the
 * following errors will be set.  If the input is half-precision and
 * half-precision is disabled @ref QCBOR_ERR_HALF_PRECISION_DISABLED
 * is set. This function needs hardware floating-point to convert the
 * floating-point value to an integer so if HW floating point is
 * disabled @ref QCBOR_ERR_HW_FLOAT_DISABLED is set. If all
 * floating-point is disabled then @ref QCBOR_ERR_ALL_FLOAT_DISABLED
 * is set.  A previous version of this function would return
 * @ref QCBOR_ERR_FLOAT_DATE_DISABLED in some, but not all, cases when
 * floating-point decoding was disabled.
 *
 * Floating-point dates that are plus infinity, minus infinity or NaN
 * (not-a-number) will result in the @ref QCBOR_ERR_DATE_OVERFLOW
 * error.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_DATE_EPOCH, QCBOREncode_AddTDateEpoch() and
 * @ref QCBOR_TYPE_DATE_EPOCH.
*/
void
QCBORDecode_GetEpochDate(QCBORDecodeContext *pCtx,
                         uint8_t             uTagRequirement,
                         int64_t            *pnTime);

void
QCBORDecode_GetEpochDateInMapN(QCBORDecodeContext *pCtx,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnTime);

void
QCBORDecode_GetEpochDateInMapSZ(QCBORDecodeContext *pCtx,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                int64_t            *pnTime);



/**
 * @brief Decode the next item as a date-only string.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pDateString     The decoded date.
 *
 * This decodes the CBOR date-only string tag, integer tag number of
 * 1004, or encoded CBOR that is not a tag, but borrows the date-only
 * string content format. An example of the format is "1985-04-12".
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_DAYS_STRING, QCBOREncode_AddDaysString() and
 * @ref QCBOR_TYPE_DAYS_STRING.
 */
static void
QCBORDecode_GetDaysString(QCBORDecodeContext *pCtx,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pDateString);

static void
QCBORDecode_GetDaysStringInMapN(QCBORDecodeContext *pCtx,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                UsefulBufC         *pDateString);

static void
QCBORDecode_GetDaysStringInMapSZ(QCBORDecodeContext *pCtx,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC         *pDateString);


/**
 * @brief Decode the next item as an days-count epoch date.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pnDays          The decoded epoch date.
 *
 * This decodes the CBOR epoch date tag, integer tag number of 100, or
 * encoded CBOR that is not a tag, but borrows the content format. The
 * date is the number of days (not number of seconds) before or after
 * Jan 1, 1970.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_DAYS_EPOCH, QCBOREncode_AddTDaysEpoch() and
 * @ref QCBOR_TYPE_DAYS_EPOCH.
*/
void
QCBORDecode_GetEpochDays(QCBORDecodeContext *pCtx,
                         uint8_t             uTagRequirement,
                         int64_t            *pnDays);

void
QCBORDecode_GetEpochDaysInMapN(QCBORDecodeContext *pCtx,
                               int64_t             nLabel,
                               uint8_t             uTagRequirement,
                               int64_t            *pnDays);

void
QCBORDecode_GetEpochDaysInMapSZ(QCBORDecodeContext *pCtx,
                                const char         *szLabel,
                                uint8_t             uTagRequirement,
                                int64_t            *pnDays);


/**
 * @brief Decode the next item as a URI.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pURI            The decoded URI.
 *
 * This decodes a standard CBOR URI tag, integer tag number of 32, or
 * encoded CBOR that is not a tag, that is a URI encoded in a text
 * string.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_URI, QCBOREncode_AddTURI() and
 *  @ref QCBOR_TYPE_URI.
 */
static void
QCBORDecode_GetURI(QCBORDecodeContext *pCtx,
                   uint8_t             uTagRequirement,
                   UsefulBufC         *pURI);

static void
QCBORDecode_GetURIInMapN(QCBORDecodeContext *pCtx,
                         int64_t             nLabel,
                         uint8_t             uTagRequirement,
                         UsefulBufC         *pURI);

static void
QCBORDecode_GetURIInMapSZ(QCBORDecodeContext *pCtx,
                          const char *        szLabel,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pURI);


/**
 * @brief Decode the next item as base64 encoded text.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pB64Text        The decoded base64 text.
 *
 * This decodes a standard CBOR base64 tag, integer tag number of 34,
 * or encoded CBOR that is not a tag, that is base64 encoded bytes
 * encoded in a text string.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * Note that this does not actually remove the base64 encoding.
 *
 * See also @ref CBOR_TAG_B64, QCBOREncode_AddB64Text() and
 * @ref QCBOR_TYPE_BASE64.
 */
static void
QCBORDecode_GetB64(QCBORDecodeContext *pCtx,
                   uint8_t             uTagRequirement,
                   UsefulBufC         *pB64Text);

static void
QCBORDecode_GetB64InMapN(QCBORDecodeContext *pCtx,
                         int64_t             nLabel,
                         uint8_t             uTagRequirement,
                         UsefulBufC         *pB64Text);

static void
QCBORDecode_GetB64InMapSZ(QCBORDecodeContext *pCtx,
                          const char         *szLabel,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pB64Text);

/**
 * @brief Decode the next item as base64URL encoded text.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pB64Text        The decoded base64 text.
 *
 * This decodes a standard CBOR base64url tag, integer tag number of
 * 33, or encoded CBOR that is not a tag, that is base64url encoded
 * bytes encoded in a text string.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * Note that this does not actually remove the base64url encoding.
 *
 * See also @ref CBOR_TAG_B64URL, QCBOREncode_AddTB64URLText() and
 * @ref QCBOR_TYPE_BASE64URL.
 */
static void
QCBORDecode_GetB64URL(QCBORDecodeContext *pCtx,
                      uint8_t             uTagRequirement,
                      UsefulBufC         *pB64Text);

static void
QCBORDecode_GetB64URLInMapN(QCBORDecodeContext *pCtx,
                            int64_t             nLabel,
                            uint8_t             uTagRequirement,
                            UsefulBufC         *pB64Text);

static void
QCBORDecode_GetB64URLInMapSZ(QCBORDecodeContext *pCtx,
                             const char         *szLabel,
                             uint8_t             uTagRequirement,
                             UsefulBufC         *pB64Text);

/**
 * @brief Decode the next item as a regular expression.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pRegex          The decoded regular expression.
 *
 * This decodes a standard CBOR regex tag, integer tag number of 35,
 * or encoded CBOR that is not a tag, that is a PERL-compatible
 * regular expression encoded in a text string.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_REGEX, QCBOREncode_AddTRegex() and
 * @ref QCBOR_TYPE_REGEX.
 */
static void
QCBORDecode_GetRegex(QCBORDecodeContext *pCtx,
                     uint8_t             uTagRequirement,
                     UsefulBufC         *pRegex);

static void
QCBORDecode_GetRegexInMapN(QCBORDecodeContext *pCtx,
                           int64_t             nLabel,
                           uint8_t             uTagRequirement,
                           UsefulBufC         *pRegex);

static void
QCBORDecode_GetRegexInMapSZ(QCBORDecodeContext *pCtx,
                            const char *        szLabel,
                            uint8_t             uTagRequirement,
                             UsefulBufC         *pRegex);


/**
 * @brief Decode the next item as a MIME message.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pMessage        The decoded regular expression.
 * @param[out] pbIsTag257      @c true if tag was 257. May be @c NULL.
 *
 * This decodes the standard CBOR MIME and binary MIME tags, integer
 * tag numbers of 36 or 257, or encoded CBOR that is not a tag, that
 * is a MIME message encoded in a text or binary string.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * The MIME message itself is not parsed.
 *
 * This decodes both tag 36 and 257. If it is tag 257, pbIsTag257 is
 * @c true. The difference between the two is that tag 36 is utf8 and
 * tag 257 is a byte string that can carry binary MIME. QCBOR
 * processes them exactly the same. Possibly the difference can be
 * ignored.  NULL can be passed to have no value returned.
 *
 * See also @ref CBOR_TAG_MIME, @ref CBOR_TAG_BINARY_MIME,
 * QCBOREncode_AddTMIMEData(), @ref QCBOR_TYPE_MIME and
 * @ref QCBOR_TYPE_BINARY_MIME.
 *
 * This does no translation of line endings. See QCBOREncode_AddText()
 * for a discussion of line endings in CBOR.
 */
void
QCBORDecode_GetMIMEMessage(QCBORDecodeContext *pCtx,
                           uint8_t             uTagRequirement,
                           UsefulBufC         *pMessage,
                           bool               *pbIsTag257);

 void
QCBORDecode_GetMIMEMessageInMapN(QCBORDecodeContext *pCtx,
                                 int64_t              nLabel,
                                 uint8_t              uTagRequirement,
                                 UsefulBufC          *pMessage,
                                 bool                *pbIsTag257);


void
QCBORDecode_GetMIMEMessageInMapSZ(QCBORDecodeContext *pCtx,
                                  const char         *szLabel,
                                  uint8_t             uTagRequirement,
                                  UsefulBufC         *pMessage,
                                  bool               *pbIsTag257);

/**
 * @brief Decode the next item as a UUID.
 *
 * @param[in] pCtx             The decode context.
 * @param[in] uTagRequirement  One of @c QCBOR_TAG_REQUIREMENT_XXX.
 * @param[out] pUUID           The decoded UUID
 *
 * This decodes a standard CBOR UUID tag, integer tag number of 37, or
 * encoded CBOR that is not a tag, that is a UUID encoded in a byte
 * string.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See @ref Tag-Usage for discussion on tag requirements.
 *
 * See also @ref CBOR_TAG_BIN_UUID, QCBOREncode_AddTBinaryUUID() and
 * @ref QCBOR_TYPE_UUID.
 */
static void
QCBORDecode_GetBinaryUUID(QCBORDecodeContext *pCtx,
                          uint8_t             uTagRequirement,
                          UsefulBufC         *pUUID);

static void
QCBORDecode_GetBinaryUUIDInMapN(QCBORDecodeContext *pCtx,
                                int64_t             nLabel,
                                uint8_t             uTagRequirement,
                                UsefulBufC         *pUUID);

static void
QCBORDecode_GetBinaryUUIDInMapSZ(QCBORDecodeContext *pCtx,
                                 const char         *szLabel,
                                 uint8_t             uTagRequirement,
                                 UsefulBufC         *pUUID);




/**
 * @brief Prototype for callback for decoding tag content.
 *
 * @param[in] pCtx                Decode context.
 * @param[in] pTagDecodersContext  Optional context for tag decoders.
 * @param[in] uTagNumber          The tag number indicated for the content.
 * @param[in,out] pItem           On input, the item for the first and
 *                                possibly only item for the tag content.
 *                                On output, holds the decoded tag content.
 *
 * This is one of two main facilities for processing CBOR tags. This
 * allows callbacks to be installed that fire when a particular tag
 * number is encountered. The callback consumes the tag content and
 * turns it into a @ref QCBORItem of a new type. The new QCBORItem is
 * returned in normal decoding with QCBORDecode_VGetNext() and
 * related.
 *
 * The other facility is QCBORDecode_GetNextTagNumber(). Note als that
 * tag processing is substantially changed in QCBOR v2.
 *
 * A CBOR tag consists of a tag number and tag content. The tag
 * content might be a simple non-aggregate type like an integer or it
 * may be a complex protocol message. This facility is oriented around
 * simple tag content as the output of it must be fit into a
 * @ref QCBORItem.
 *
 * When called, the contents of pItem is the first item in the tag
 * content. If it is an array or map then the items in it can be
 * fetched by calling QCBORDecode_GetNext() and such.  All the items
 * in the tag content must be consumed.
 *
 * The callback modifies pItem. It puts the output of tag content
 * decoding in pItem. It assigns a QCBOR_TYPE integer in the range of
 * @ref QCBOR_TYPE_START_USER_DEFINED to @ref
 * QCBOR_TYPE_END_USER_DEFINED. Any of the members of the union @c val
 * may be used to hold the decoded content.  @c val.userDefined is a
 * 24 byte buffer that can be used.
 *
 * The tag number is passed in so as to allow one callback to be
 * installed for several different tag numbers.
 *
 * The callback must be installed with
 * QCBORDecode_InstallTagDecoders().
 *
 * A callback context may given when the callback is installed.  It
 * will be passed in here as pTagDecodesrContext. There is only one
 * context for all tag content decoders. None of the standard tag
 * decoders here use it. The callback context can be used to make a
 * very elaborite tag content decoder.
 *
 * Tags can nest. Callbacks fire first on then inner most tag.  They
 * are called until all tags are processed or a tag number for which
 * there is no processor is encountered.
 *
 * Standard CBOR defines tags for big numbers, the tag content for
 * which is a byte string. The standard decoder supplied for this
 * fires on the tag number for a positive or negative big number,
 * checks that the tag content is a byte string and changes the CBOR
 * type of the item from a byte string to either @ref
 * QCBOR_TYPE_POSBIGNUM or @ref QCBOR_TYPE_NEGBIGNUM.
 *
 * Standard CBOR defines a tag for big floats, the tag content of
 * which is an array of the mantissa and the exponent. The mantissa
 * may be a big number. Since callbacks fire from the inside out, the
 * big number content decoder will fire first and the big float
 * decoder will get @ref QCBOR_TYPE_POSBIGNUM instead of a tag number and
 * a byte string.
 */
typedef QCBORError (QCBORTagContentCallBack)(QCBORDecodeContext *pCtx,
                                             void               *pTagDecodersContext,
                                             uint64_t            uTagNumber,
                                             QCBORItem          *pItem);

#ifndef QCBOR_DISABLE_TAGS

/**
 * An entry in the tag decoders table installed with QCBORDecode_InstallTagDecoders().
 *
 * The table is searched in order for the first match on
 * @c uTagNumber. Then @c pfContentDecoder is called.
 */
struct QCBORTagDecoderEntry {
   uint64_t                  uTagNumber;
   QCBORTagContentCallBack  *pfContentDecoder;
};


/**
 * @brief Set the custom tag decoders.
 *
 * @param[in] pCtx         The decode context.
 * @param[in] pTagDecoderTable  The table of tag struct QCBORTagDecoderEntry content decoders.
 *                              The table is terminated by an entry with a @c NULL pfContentDecoder.
 *
 * @param[in] pTagDecodersContext  Context passed to tag decoders. May be @c NULL.
 *
 * There is only one table of tag decoders at a time. A call to this replaces
 * the previous table.
 */
static void
QCBORDecode_InstallTagDecoders(QCBORDecodeContext                *pCtx,
                               const struct QCBORTagDecoderEntry *pTagDecoderTable,
                               void                              *pTagDecodersContext);


/**
 * A table of tag handlers that provides QCBOR v1 compatibility
 *
 * Install this with QCBORDecode_InstallTagDecoders().
 */
extern const struct QCBORTagDecoderEntry QCBORDecode_TagDecoderTablev1[];

#endif /* ! QCBOR_DISABLE_TAGS */


/**
 * @brief Convert different epoch date formats in to the QCBOR epoch date format.
 *
 * @param[in] pDecodeCtx           Decode context.
 * @param[in] pTagDecodersContext  Optional context for tag decoders.
 * @param[in] uTagNumber           The tag number indicated for the content.
 * @param[in,out]  pDecodedItem    The data item to convert.
 *
 * @retval QCBOR_ERR_DATE_OVERFLOW              65-bit negative integer.
 * @retval QCBOR_ERR_FLOAT_DATE_DISABLED        Float-point date in input,
 *                                              floating-point date disabled.
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED         Float-point date in input,
 *                                              all floating-point disabled.
 * @retval QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT  Unexpected and unrecoverable
 *                                              error decoding date.
 *
 * The epoch date tag defined in QCBOR allows for floating-point
 * dates. It even allows a protocol to flop between date formats when
 * ever it wants.  Floating-point dates aren't that useful as they are
 * only needed for dates beyond the age of the earth.
 *
 * This works for the following tag numbers:
 *   @ref CBOR_TAG_DATE_EPOCH
 *
 * This converts all the date formats into one format of an unsigned
 * integer plus a floating-point fraction.
 *
 * This is a call back to be installed by QCBORDecode_InstallTagDecoders().
 */
QCBORError
QCBORDecode_DateEpochTagCB(QCBORDecodeContext *pDecodeCtx,
                           void               *pTagDecodersContext,
                           uint64_t            uTagNumber,
                           QCBORItem          *pDecodedItem);


/**
 * @brief Convert the days epoch date.
 *
 * @param[in] pDecodeCtx           Decode context.
 * @param[in] pTagDecodersContext  Optional context for tag decoders.
 * @param[in] uTagNumber           The tag number indicated for the content.
 * @param[in,out]  pDecodedItem    The data item to convert.
 *
 * @retval QCBOR_ERR_DATE_OVERFLOW              65-bit negative integer.
 * @retval QCBOR_ERR_FLOAT_DATE_DISABLED        Float-point date in input,
 *                                              floating-point date disabled.
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED         Float-point date in input,
 *                                              all floating-point disabled.
 * @retval QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT  Unexpected and unrecoverable
 *                                              error decoding date.
 *
 * This works for the following tag numbers:
 *   @ref CBOR_TAG_DAYS_EPOCH
 *
 * This is much simpler than the other epoch date format because
 * floating-porint is not allowed. This is mostly a simple type check.
 *
 * This is a call back to be installed by QCBORDecode_InstallTagDecoders().
 */
QCBORError
QCBORDecode_DaysEpochTagCB(QCBORDecodeContext *pDecodeCtx,
                           void               *pTagDecodersContext,
                           uint64_t            uTagNumber,
                           QCBORItem          *pDecodedItem);


/**
 * @brief Process standard CBOR tags whose content is a string.
 *
 * @param[in] pDecodeCtx           Decode context.
 * @param[in] pTagDecodersContext  Optional context for tag decoders.
 * @param[in] uTagNumber           The tag number indicated for the content.
 * @param[in,out]  pDecodedItem    The data item to convert.
 *
 * @returns  This returns QCBOR_SUCCESS if the tag was procssed,
 *           @ref QCBOR_ERR_UNSUPPORTED if the tag was not processed and
 *           @ref QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT if the content type was wrong for the tag.
 *
 * Process the standard CBOR tags  whose content is a byte string or a text
 * string and for which the string is just passed on to the caller.
 *
 * This works for :
 *    @ref CBOR_TAG_DATE_STRING,
 *    @ref CBOR_TAG_POS_BIGNUM,
 *    @ref CBOR_TAG_NEG_BIGNUM,
 *    @ref CBOR_TAG_CBOR,
 *    @ref CBOR_TAG_URI,
 *    @ref CBOR_TAG_B64URL,
 *    @ref CBOR_TAG_B64,
 *    @ref CBOR_TAG_REGEX,
 *    @ref CBOR_TAG_DAYS_STRING,
 *    @ref CBOR_TAG_BIN_UUID,
 *    @ref CBOR_TAG_CBOR_SEQUENCE
 *
 * This maps the CBOR tag to the QCBOR type and checks the tag content
 * type.  Nothing more.
 *
 * This is a call back to be installed by QCBORDecode_InstallTagDecoders().
 */
QCBORError
QCBORDecode_StringsTagCB(QCBORDecodeContext *pDecodeCtx,
                         void               *pTagDecodersContext,
                         uint64_t            uTagNumber,
                         QCBORItem          *pDecodedItem);


/**
 * @brief Decode the MIME type tag
 *
 * @param[in] pDecodeCtx           Decode context.
 * @param[in] pTagDecodersContext  Optional context for tag decoders.
 * @param[in] uTagNumber           The tag number indicated for the content.
 * @param[in,out]  pDecodedItem    The data item to convert.
 *
 * Handle the text and binary MIME type tags. Slightly too complicated
 * for or QCBORDecode_StringsTagCB() because the RFC 7049 MIME type was
 * incorrectly text-only.
 *
 * This works for :
 *     @ref CBOR_TAG_BINARY_MIME,
 *     @ref CBOR_TAG_MIME
 *
 * This is a call back to be installed by QCBORDecode_InstallTagDecoders().
 */
QCBORError
QCBORDecode_MIMETagCB(QCBORDecodeContext *pDecodeCtx,
                      void               *pTagDecodersContext,
                      uint64_t            uTagNumber,
                      QCBORItem          *pDecodedItem);


/**
 * @brief Decode decimal fractions and big floats.
 *
 * @param[in] pDecodeCtx           Decode context.
 * @param[in] pTagDecodersContext  Optional context for tag decoders.
 * @param[in] uTagNumber           The tag number indicated for the content.
 * @param[in,out]  pDecodedItem    The data item to convert.
 *
 * @returns  Decoding errors from getting primitive data items or
 *           @ref QCBOR_ERR_BAD_EXP_AND_MANTISSA.
 *
 * When called pDecodedItem must be the array with two members, the
 * exponent and mantissa.
 *
 * Fetch and decode the exponent and mantissa and put the result back
 * into pDecodedItem.
 *
 * This stuffs the type of the mantissa into pDecodedItem with the
 * expectation the caller will process it.
 *
 * This works for:
 *     @ref CBOR_TAG_DECIMAL_FRACTION,
 *     @ref CBOR_TAG_BIGFLOAT
 *
 * This is a call back to be installed by QCBORDecode_InstallTagDecoders().
 */
QCBORError
QCBORDecode_ExpMantissaTagCB(QCBORDecodeContext *pDecodeCtx,
                             void               *pTagDecodersContext,
                             uint64_t            uTagNumber,
                             QCBORItem          *pDecodedItem);




/* ========================================================================= *
 *    BEGINNING OF DEPRECATED FUNCTIONS                                      *
 *                                                                           *
 *    There is no plan to remove these in future versions.                   *
 *    They just have been replaced by something better.                      *
 * ========================================================================= */

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
 *    BEGINNING OF PRIVATE AND INLINE IMPLEMENTATION                             *
 * ========================================================================= */

/* Semi-private used by public inline functions. See qcbor_tag_decode.c */
void
QCBORDecode_Private_GetTaggedString(QCBORDecodeContext  *pMe,
                                    uint8_t              uTagRequirement,
                                    uint8_t              uQCBOR_Type,
                                    uint64_t             uTagNumber,
                                    UsefulBufC          *pBstr);

/* Semi-private used by public inline functions. See qcbor_tag_decode.c */
void
QCBORDecode_Private_GetTaggedStringInMapN(QCBORDecodeContext  *pMe,
                                          const int64_t        nLabel,
                                          const uint8_t        uTagRequirement,
                                          const uint8_t        uQCBOR_Type,
                                          const uint64_t       uTagNumber,
                                          UsefulBufC          *pString);

/* Semi-private used by public inline functions. See qcbor_tag_decode.c */
void
QCBORDecode_Private_GetTaggedStringInMapSZ(QCBORDecodeContext  *pMe,
                                           const char          *szLabel,
                                           uint8_t              uTagRequirement,
                                           uint8_t              uQCBOR_Type,
                                           uint64_t             uTagNumber,
                                           UsefulBufC          *pString);

/* Semi-private function. See qcbor_tag_decode.c */
void
QCBORDecode_Private_ProcessTagItemMulti(QCBORDecodeContext      *pMe,
                                        QCBORItem               *pItem,
                                        const uint8_t            uTagRequirement,
                                        const uint8_t            uQCBORTypes[],
                                        const uint64_t           uTagNumbers[],
                                        QCBORTagContentCallBack *pfCB,
                                        size_t                   uOffset);

/* Semi-private function. See qcbor_tag_decode.c */
void
QCBORDecode_Private_ProcessTagItem(QCBORDecodeContext      *pMe,
                                   QCBORItem               *pItem,
                                   const uint8_t            uTagRequirement,
                                   const uint8_t            uQCBORTypes[],
                                   const uint64_t           uTagNumber,
                                   QCBORTagContentCallBack *pfCB,
                                   size_t                   uOffset);


#ifndef QCBOR_DISABLE_TAGS
static inline void
QCBORDecode_InstallTagDecoders(QCBORDecodeContext                *pMe,
                               const struct QCBORTagDecoderEntry *pTagDecoderTable,
                               void                              *pTagDecodersContext)
{
   pMe->pTagDecoderTable    = pTagDecoderTable;
   pMe->pTagDecodersContext = pTagDecodersContext;
}

#endif /* ! QCBOR_DISABLE_TAGS */




static inline void
QCBORDecode_GetDateString(QCBORDecodeContext *pMe,
                          const uint8_t       uTagRequirement,
                          UsefulBufC         *pValue)
{
   QCBORDecode_Private_GetTaggedString(pMe,
                                       uTagRequirement,
                                       QCBOR_TYPE_DATE_STRING,
                                       CBOR_TAG_DATE_STRING,
                                       pValue);
}

static inline void
QCBORDecode_GetDateStringInMapN(QCBORDecodeContext *pMe,
                                const int64_t       nLabel,
                                const uint8_t       uTagRequirement,
                                UsefulBufC         *pText)
{
   QCBORDecode_Private_GetTaggedStringInMapN(pMe,
                                              nLabel,
                                              uTagRequirement,
                                              QCBOR_TYPE_DATE_STRING,
                                              CBOR_TAG_DATE_STRING,
                                              pText);
}

static inline void
QCBORDecode_GetDateStringInMapSZ(QCBORDecodeContext *pMe,
                                 const char         *szLabel,
                                 const uint8_t       uTagRequirement,
                                 UsefulBufC         *pText)
{
   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe,
                                              szLabel,
                                              uTagRequirement,
                                              QCBOR_TYPE_DATE_STRING,
                                              CBOR_TAG_DATE_STRING,
                                              pText);
}

static inline void
QCBORDecode_GetDaysString(QCBORDecodeContext *pMe,
                          const uint8_t       uTagRequirement,
                          UsefulBufC         *pValue)
{
   QCBORDecode_Private_GetTaggedString(pMe,
                                       uTagRequirement,
                                       QCBOR_TYPE_DATE_STRING,
                                       CBOR_TAG_DATE_STRING,
                                       pValue);
}

static inline void
QCBORDecode_GetDaysStringInMapN(QCBORDecodeContext *pMe,
                                const int64_t       nLabel,
                                const uint8_t       uTagRequirement,
                                UsefulBufC         *pText)
{
   QCBORDecode_Private_GetTaggedStringInMapN(pMe,
                                             nLabel,
                                             uTagRequirement,
                                             QCBOR_TYPE_DAYS_STRING,
                                             CBOR_TAG_DAYS_STRING,
                                             pText);
}

static inline void
QCBORDecode_GetDaysStringInMapSZ(QCBORDecodeContext *pMe,
                                 const char         *szLabel,
                                 const uint8_t       uTagRequirement,
                                 UsefulBufC         *pText)
{
   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe,
                                              szLabel,
                                              uTagRequirement,
                                              QCBOR_TYPE_DAYS_STRING,
                                              CBOR_TAG_DAYS_STRING,
                                              pText);

}


static inline void
QCBORDecode_GetURI(QCBORDecodeContext *pMe,
                   const uint8_t       uTagRequirement,
                   UsefulBufC         *pUUID)
{
   QCBORDecode_Private_GetTaggedString(pMe,
                                       uTagRequirement,
                                       QCBOR_TYPE_URI,
                                       CBOR_TAG_URI,
                                       pUUID);
}

static inline void
QCBORDecode_GetURIInMapN(QCBORDecodeContext *pMe,
                         const int64_t       nLabel,
                         const uint8_t       uTagRequirement,
                         UsefulBufC         *pUUID)
{
   QCBORDecode_Private_GetTaggedStringInMapN(pMe,
                                              nLabel,
                                              uTagRequirement,
                                              QCBOR_TYPE_URI,
                                              CBOR_TAG_URI,
                                              pUUID);
}

static inline void
QCBORDecode_GetURIInMapSZ(QCBORDecodeContext *pMe,
                          const char         *szLabel,
                          const uint8_t       uTagRequirement,
                          UsefulBufC         *pUUID)
{
   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe,
                                              szLabel,
                                              uTagRequirement,
                                              QCBOR_TYPE_URI,
                                              CBOR_TAG_URI,
                                              pUUID);
}


static inline void
QCBORDecode_GetB64(QCBORDecodeContext *pMe,
                   const uint8_t       uTagRequirement,
                   UsefulBufC         *pB64Text)
{
   QCBORDecode_Private_GetTaggedString(pMe,
                                       uTagRequirement,
                                       QCBOR_TYPE_BASE64,
                                       CBOR_TAG_B64,
                                       pB64Text);
}

static inline void
QCBORDecode_GetB64InMapN(QCBORDecodeContext *pMe,
                         const int64_t       nLabel,
                         const uint8_t       uTagRequirement,
                         UsefulBufC         *pB64Text)
{
   QCBORDecode_Private_GetTaggedStringInMapN(pMe,
                                             nLabel,
                                             uTagRequirement,
                                             QCBOR_TYPE_BASE64,
                                             CBOR_TAG_B64,
                                             pB64Text);
}

static inline void
QCBORDecode_GetB64InMapSZ(QCBORDecodeContext *pMe,
                          const char         *szLabel,
                          const uint8_t       uTagRequirement,
                          UsefulBufC         *pB64Text)
{
   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe,
                                              szLabel,
                                              uTagRequirement,
                                              QCBOR_TYPE_BASE64,
                                              CBOR_TAG_B64,
                                              pB64Text);
}


static inline void
QCBORDecode_GetB64URL(QCBORDecodeContext *pMe,
                      const uint8_t       uTagRequirement,
                      UsefulBufC         *pB64Text)
{
   QCBORDecode_Private_GetTaggedString(pMe,
                                       uTagRequirement,
                                       QCBOR_TYPE_BASE64URL,
                                       CBOR_TAG_B64URL,
                                       pB64Text);
}

static inline void
QCBORDecode_GetB64URLInMapN(QCBORDecodeContext *pMe,
                            const int64_t       nLabel,
                            const uint8_t       uTagRequirement,
                            UsefulBufC         *pB64Text)
{
   QCBORDecode_Private_GetTaggedStringInMapN(pMe,
                                              nLabel,
                                              uTagRequirement,
                                              QCBOR_TYPE_BASE64URL,
                                              CBOR_TAG_B64URL,
                                              pB64Text);
}

static inline void
QCBORDecode_GetB64URLInMapSZ(QCBORDecodeContext *pMe,
                             const char         *szLabel,
                             const uint8_t       uTagRequirement,
                             UsefulBufC         *pB64Text)
{
   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe,
                                              szLabel,
                                              uTagRequirement,
                                              QCBOR_TYPE_BASE64URL,
                                              CBOR_TAG_B64URL,
                                              pB64Text);
}


static inline void
QCBORDecode_GetRegex(QCBORDecodeContext *pMe,
                     const uint8_t      uTagRequirement,
                     UsefulBufC         *pRegex)
{
   QCBORDecode_Private_GetTaggedString(pMe,
                                       uTagRequirement,
                                       QCBOR_TYPE_REGEX,
                                       CBOR_TAG_REGEX,
                                       pRegex);
}

static inline void
QCBORDecode_GetRegexInMapN(QCBORDecodeContext *pMe,
                           const int64_t       nLabel,
                           const uint8_t       uTagRequirement,
                           UsefulBufC         *pRegex)
{
   QCBORDecode_Private_GetTaggedStringInMapN(pMe,
                                              nLabel,
                                              uTagRequirement,
                                              QCBOR_TYPE_REGEX,
                                              CBOR_TAG_REGEX,
                                              pRegex);
}

static inline void
QCBORDecode_GetRegexInMapSZ(QCBORDecodeContext *pMe,
                            const char *        szLabel,
                            const uint8_t       uTagRequirement,
                            UsefulBufC         *pRegex)
{
   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe,
                                              szLabel,
                                              uTagRequirement,
                                              QCBOR_TYPE_REGEX,
                                              CBOR_TAG_REGEX,
                                              pRegex);
}


static inline void
QCBORDecode_GetBinaryUUID(QCBORDecodeContext *pMe,
                          const uint8_t       uTagRequirement,
                          UsefulBufC         *pUUID)
{
   QCBORDecode_Private_GetTaggedString(pMe,
                                       uTagRequirement,
                                       QCBOR_TYPE_UUID,
                                       CBOR_TAG_BIN_UUID,
                                       pUUID);
}

static inline void
QCBORDecode_GetBinaryUUIDInMapN(QCBORDecodeContext *pMe,
                                const int64_t       nLabel,
                                const uint8_t       uTagRequirement,
                                UsefulBufC         *pUUID)
{
   QCBORDecode_Private_GetTaggedStringInMapN(pMe,
                                             nLabel,
                                             uTagRequirement,
                                             QCBOR_TYPE_UUID,
                                             CBOR_TAG_BIN_UUID,
                                             pUUID);
}

static inline void
QCBORDecode_GetBinaryUUIDInMapSZ(QCBORDecodeContext *pMe,
                                 const char         *szLabel,
                                 const uint8_t       uTagRequirement,
                                 UsefulBufC         *pUUID)
{
   QCBORDecode_Private_GetTaggedStringInMapSZ(pMe,
                                              szLabel,
                                              uTagRequirement,
                                              QCBOR_TYPE_UUID,
                                              CBOR_TAG_BIN_UUID,
                                              pUUID);
}


/* ======================================================================== *
 *    END OF PRIVATE INLINE IMPLEMENTATION                                  *
 * ======================================================================== */


#ifdef __cplusplus
}
#endif

#endif /* qcbor_tag_decode_h */
