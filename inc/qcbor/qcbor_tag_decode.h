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


/*
 



 */


/*
 * @brief Prototype for callback for decoding tag content.
 *
 * @param[in] pCtx   Decode context
 * @param[in] pTagDecoderContext  Optional context for tag decoders.
 * @param[in] uTagNumber  The tag number indicated for the content
 * @param[in,out]   On input the item for the first and possibly only
 *                  item for the tag content. On output, holds the
 *                  decoded tag content.
 *
 * Create functions that match this prototype and configure them with
 * QCBORDecode_InstallTagDecoders().
 */
typedef QCBORError (QCBORTagContentCallBack)(QCBORDecodeContext *pCtx, 
                                             void               *pTagDecoderContext,
                                             uint64_t            uTagNumber,
                                             QCBORItem          *pItem);


/*
 * An entry in the tag decoders table installed with QCBORDecode_InstallTagDecoders().
 *
 * The table is searched in order for the first match on
 * @ref uTagNumber. Then pfContentDecoder is called.
 *
 * CBOR_TAG_ANY will match all tag numbers. If used,
 * it should be last in the table.
 */
struct QCBORTagDecoderEntry {
   uint64_t                  uTagNumber;
   QCBORTagContentCallBack  *pfContentDecoder;
};


/* Set the custom tag decoders. pBlock is an array of entries terminated by a NULL function pointer or invalid tag number*/
static void
QCBORDecode_InstallTagDecoders(QCBORDecodeContext                *pCtx,
                               const struct QCBORTagDecoderEntry *pTagDecoderTable,
                               void                              *pTagDecodersContext);


/*
 * A table of tag handlers that provides QCBOR v1 compatibility
 *
 * Install this with QCBORDecode_InstallTagDecoders().
 */
extern const struct QCBORTagDecoderEntry QCBORDecode_TagDecoderTablev1[];


/**
 * @brief Convert different epoch date formats in to the QCBOR epoch date format
 *
 * pDecodedItem[in,out]  The data item to convert.
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
 */
QCBORError
QCBORDecode_DateEpochTagCB(QCBORDecodeContext *pDecodeCtx,
                           void               *pTagDecodersContext,
                           uint64_t            uTagNumber,
                           QCBORItem          *pDecodedItem);


/**
 * @brief Convert the days epoch date.
 *
 * @param[in,out] pDecodedItem  The data item to convert.
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
 */
QCBORError
QCBORDecode_DaysEpochTagCB(QCBORDecodeContext *pDecodeCtx,
                           void               *pTagDecodersContext,
                           uint64_t            uTagNumber,
                           QCBORItem          *pDecodedItem);


/**
 * @brief Process standard CBOR tags whose content is a string.
 *
 * @param[in] uTagNumber              The tag.
 * @param[in,out] pDecodedItem  The data item.
 *
 * @returns  This returns QCBOR_SUCCESS if the tag was procssed,
 *           \ref QCBOR_ERR_UNSUPPORTED if the tag was not processed and
 *           \ref QCBOR_ERR_UNRECOVERABLE_TAG_CONTENT if the content type was wrong for the tag.
 *
 * Process the standard CBOR tags  whose content is a byte string or a text
 * string and for which the string is just passed on to the caller.
 *
 * This works for :
 *    CBOR_TAG_DATE_STRING
 *    CBOR_TAG_POS_BIGNUM
 *    CBOR_TAG_NEG_BIGNUM
 *    CBOR_TAG_CBOR
 *    CBOR_TAG_URI
 *    CBOR_TAG_B64URL
 *    CBOR_TAG_B64
 *    CBOR_TAG_B64
 *    CBOR_TAG_REGEX
 *    CBOR_TAG_DAYS_STRING
 *    CBOR_TAG_BIN_UUID
 *    CBOR_TAG_CBOR_SEQUENCE
 *
 * This maps the CBOR tag to the QCBOR type and checks the content
 * type.  Nothing more. It may not be the most important
 * functionality, but it part of implementing as much of RFC 8949 as
 * possible.
 */
QCBORError
QCBORDecode_StringsTagCB(QCBORDecodeContext *pDecodeCtx,
                         void               *pTagDecodersContext,
                         uint64_t            uTagNumber,
                         QCBORItem          *pDecodedItem);


/**
 * @brief Decode the MIME type tag
 *
 * @param[in,out] pDecodedItem   The item to decode.
 *
 *  Handle the text and binary MIME type tags. Slightly too complicated
 *  f or ProcessTaggedString() because the RFC 7049 MIME type was
 *  incorreclty text-only.
 *
 * This works for :
 *     CBOR_TAG_BINARY_MIME
 *     CBOR_TAG_MIME
 */
QCBORError
QCBORDecode_MIMETagCB(QCBORDecodeContext *pDecodeCtx,
                      void               *pTagDecodersContext,
                      uint64_t            uTagNumber,
                      QCBORItem          *pDecodedItem);

/**
 * @brief Decode decimal fractions and big floats.
 *
 * @param[in] pDecodeCtx               The decode context.
 * @param[in,out] pDecodedItem  On input the array data item that
 *                              holds the mantissa and exponent.  On
 *                              output the decoded mantissa and
 *                              exponent.
 *
 * @returns  Decoding errors from getting primitive data items or
 *           \ref QCBOR_ERR_BAD_EXP_AND_MANTISSA.
 *
 * When called pDecodedItem must be the array with two members, the
 * exponent and mantissa.
 *
 * This will fetch and decode the exponent and mantissa and put the
 * result back into pDecodedItem.
 *
 * This does no checking or processing of tag numbers. That is to be
 * done by the code that calls this.
 *
 * This stuffs the type of the mantissa into pDecodedItem with the expectation
 * the caller will process it.
 *
 * This works for:
 *     CBOR_TAG_DECIMAL_FRACTION
 *     CBOR_TAG_BIGFLOAT
 */
QCBORError
QCBORDecode_ExpMantissaTagCB(QCBORDecodeContext *pDecodeCtx,
                             void               *pTagDecodersContext,
                             uint64_t            uTagNumber,
                             QCBORItem          *pDecodedItem);


/* ------------------------------------------------------------------------
 * Inline implementations of public functions defined above.
 * ---- */
static inline void
QCBORDecode_InstallTagDecoders(QCBORDecodeContext *pMe, 
                               const struct QCBORTagDecoderEntry *pTagDecoderTable,
                               void *pTagDecodersContext)
{
   pMe->pTagDecoderTable    = pTagDecoderTable;
   pMe->pTagDecodersContext = pTagDecodersContext;
}



#endif /* qcbor_tag_decode_h */
