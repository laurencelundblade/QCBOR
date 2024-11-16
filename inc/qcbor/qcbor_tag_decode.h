/* ==========================================================================
 * qcbor_tag_decode.h -- Tag content decoders
 *
 * Copyright (c) 2024, Laurence Lundblade. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in README.md
 *
 * Created on 9/5/24
 * ========================================================================== */

#ifndef qcbor_tag_decode_h
#define qcbor_tag_decode_h

#include "qcbor/qcbor_decode.h"

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
 */



/*

 In v1, some spiffy decode functions ignored tag numbers and
 some didn't.  For example, GetInt64 ignored and GetString didn't.
 The "GetXxx" where Xxxx is a tag ignore conditionally based
 on an argument.
 (Would be good to verify this with tests)

 Do we fix the behavior of GetString in v1?  Relax so it
 allows tag numbers like the rest? Probably.

 In v2, the whole mechanism is with GetTagNumbers. They are
 never ignored and they must always be consumed.

 With v2 in v1 mode, the functions that were ignoring
 tags must go back to ignoring them.

 How does TagRequirement work in v2?

 GetInt64 and GetString require all tag numbs to be processed
 to work.


 */


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




/* ------------------------------------------------------------------------
 * Inline implementations of public functions defined above.
 * ---- */
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

#endif /* qcbor_tag_decode_h */
