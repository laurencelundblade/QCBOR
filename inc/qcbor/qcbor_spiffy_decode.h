/* ==========================================================================
 * qcbor_spiffy_decode.h -- higher-level easier-to-use CBOR decoding.
 *
 * Copyright (c) 2020-2025, Laurence Lundblade. All rights reserved.
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * See BSD-3-Clause license in file named "LICENSE"
 *
 * Forked from qcbor_decode.h on 7/23/2020
 * ========================================================================== */

#ifndef qcbor_spiffy_decode_h
#define qcbor_spiffy_decode_h

#include "qcbor/qcbor_spiffy_decode.h"
#include "qcbor/qcbor_number_decode.h" /* For v1 compatibility, not dependency */


#ifdef __cplusplus
extern "C" {
#if 0
} // Keep editor indention formatting happy
#endif
#endif



/**
 * @file qcbor_spiffy_decode.h
 *
 * @anchor SpiffyDecode
 * # Spiffy Decode
 *
 * This section discusses spiffy decoding assuming familiarity with
 * the general description of decoding in the
 * @ref BasicDecode section. See also qcbor_tag_decode.h
 * and qcbor_number_decode.h for more spiffy decode
 * functions.
 *
 * Spiffy decode is extra decode features over and above the @ref
 * BasicDecode features that generally are easier to use, mirror the
 * encoding functions better and can result in smaller code size for
 * larger and more complex CBOR protocols.  In particular, spiffy
 * decode facilitates getting the next data item of a specific type,
 * setting an error if it is not of that type. It facilitates
 * explicitly entering and exiting arrays and maps. It facilates
 * fetching items by label from a map including duplicate label
 * detection.
 *
 * Encoded CBOR can be viewed to have a tree structure where the leaf
 * nodes are non-aggregate types like integers and strings and the
 * intermediate nodes are either arrays or maps. Fundamentally, all
 * decoding is a pre-order traversal of the tree. Calling
 * QCBORDecode_GetNext() repeatedly will perform this.
 *
 * This pre-order traversal gives natural decoding of arrays where the
 * array members are taken in order, but does not give natural decoding
 * of maps where access by label is usually preferred.  Using the
 * QCBORDecode_EnterMap() and QCBORDecode_GetXxxxInMapX() methods like
 * QCBORDecode_GetInt64InMapN(), map items can be accessed by
 * label. QCBORDecode_EnterMap() bounds decoding to a particular
 * map. QCBORDecode_GetXxxxInMapX() methods allows decoding the item of
 * a particular label in the particular map. This can be used with
 * nested maps by using QCBORDecode_EnterMapFromMapX().
 *
 * When QCBORDecode_EnterMap() is called, pre-order traversal
 * continues to work. There is a cursor that is run over the tree with
 * calls to QCBORDecode_GetNext(). Attempts to use
 * QCBORDecode_GetNext() beyond the end of the map will give the
 * @ref QCBOR_ERR_NO_MORE_ITEMS error.
 *
 * Use of the traversal cursor can be mixed with the fetching of items
 * by label with some caveats. When a non-aggregate item like an
 * integer or string is fetched by label, the traversal cursor is
 * unaffected so the mixing can be done freely.  When an aggregate
 * item is entered by label (by QCBORDecode_EnterMapFromMapN() and
 * similar), the traversal cursor is set to the item after the
 * subordinate aggregate item when it is exited. This will not matter
 * to many use cases. Use cases that mix can be sure to separate
 * traversal by the cursor from fetching by label.
 * QCBORDecode_Rewind() may be useful to reset the traversal cursor
 * after fetching aggregate items by label.
 *
 * (This behavior was incorrectly documented in QCBOR 1.2 and prior
 * which described aggregate and non-aggregate as behaving the same.
 * Rather than changing to make aggregate and non-aggregate
 * consistent, the behavior is retained and documented because 1) it
 * is usable as is, 2) a change would bring backward compatibility
 * issues, 3) the change would increase the decode context size and
 * code size.  In QCBOR 1.3 test cases were added to validate the
 * behavior. No problems were uncovered.)
 *
 * QCBORDecode_EnterArray() can be used to narrow the traversal to the
 * extent of the array.
 *
 * All the QCBORDecode_GetXxxxInMapX() methods support duplicate label
 * detection and will result in an error if the map has duplicate
 * labels.
 *
 * All the QCBORDecode_GetXxxxInMapX() methods are implemented by
 * performing the pre-order traversal of the map to find the labeled
 * item everytime it is called. It doesn't build up a hash table, a
 * binary search tree or some other efficiently searchable structure
 * internally. For small maps this is fine and for high-speed CPUs
 * this is fine, but for large, perhaps deeply nested, maps on slow
 * CPUs, it may have performance issues (these have not be
 * quantified). One way ease this is to use
 * QCBORDecode_GetItemsInMap() which allows decoding of a list of
 * items expected in an map in one traveral.
 *
 * * Map searching works with indefinite length strings. A string
 * allocator must be set up the same as for any handling of indefinite
 * length strings.  However, It currently over-allocates memory from the
 * string pool and thus requires a much larger string pool than it
 * should. The over-allocation happens every time a map is searched by
 * label.  (This may be corrected in the future).
 */




/**
 * @brief Decode the next item as a byte string
 *
 * @param[in] pCtx     The decode context.
 * @param[out] pBytes  The decoded byte string.
 *
 * The CBOR item to decode must be a byte string, CBOR type 2.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * If the CBOR item to decode is not a byte string, the
 * @ref QCBOR_ERR_UNEXPECTED_TYPE error is set.
 *
 * See also QCBORDecode_EnterBstrWrapped().
 */
static inline void
QCBORDecode_GetByteString(QCBORDecodeContext *pCtx,
                          UsefulBufC         *pBytes);

/** See  QCBORDecode_GetByteString(). */
static void
QCBORDecode_GetByteStringInMapN(QCBORDecodeContext *pCtx,
                                int64_t             nLabel,
                                UsefulBufC         *pBytes);

/** See  QCBORDecode_GetByteString(). */
static void
QCBORDecode_GetByteStringInMapSZ(QCBORDecodeContext *pCtx,
                                 const char         *szLabel,
                                 UsefulBufC         *pBytes);


/**
 * @brief Decode the next item as a text string.
 *
 * @param[in] pCtx    The decode context.
 * @param[out] pText  The decoded byte string.
 *
 * The CBOR item to decode must be a text string, CBOR type 3.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 * It the CBOR item to decode is not a text string, the
 * @ref QCBOR_ERR_UNEXPECTED_TYPE error is set.
 *
 * This does no translation of line endings. See QCBOREncode_AddText()
 * for a discussion of line endings in CBOR.
 */
static inline void
QCBORDecode_GetTextString(QCBORDecodeContext *pCtx,
                          UsefulBufC         *pText);

/** See  QCBORDecode_GetTextString(). */
static void
QCBORDecode_GetTextStringInMapN(QCBORDecodeContext *pCtx,
                                int64_t             nLabel,
                                UsefulBufC         *pText);

/** See  QCBORDecode_GetTextString(). */
static void
QCBORDecode_GetTextStringInMapSZ(QCBORDecodeContext *pCtx,
                                 const char         *szLabel,
                                 UsefulBufC         *pText);




/**
 * @brief Enter an array for decoding in bounded mode.
 *
 * @param[in] pCtx    The decode context.
 * @param[out] pItem  The optionally returned QCBORItem that has the
 *                    label and tags for the array. May be @c NULL (and
 *                    usually is).
 *
 * This enters an array for decoding in bounded mode. The items in
 * the array are decoded in order the same as when not in bounded mode,
 * but the decoding will not proceed past the end or the array.
 *
 * The typical way to iterate over items in an array is to call
 * QCBORDecode_VGetNext() until QCBORDecode_GetError() returns
 * @ref QCBOR_ERR_NO_MORE_ITEMS. Other methods like QCBORDecode_GetInt64(),
 * QCBORDecode_GetBignum() and such may also be called until
 * QCBORDecode_GetError() doesn't return QCBOR_SUCCESS.
 *
 * Another option is to get the array item count from
 * @c pItem->val.uCount, but note that that will not work with
 * indefinte-length arrays, where as QCBORDecode_GetError() will.
 *
 * Nested decoding of arrays may be handled by calling
 * QCBORDecode_EnterArray() or by using QCBORDecode_VGetNext() to
 * descend into and back out of the nested array.
 *
 * QCBORDecode_Rewind() can be called to restart decoding from the
 * first item in the array.
 *
 * When all decoding in an array is complete, QCBORDecode_ExitArray() must
 * be called. It is a decoding error to not have a corresponding call
 * to QCBORDecode_ExitArray() for every call to QCBORDecode_EnterArray().
 * If not, @ref QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN will be returned when
 * QCBORDecode_Finish() is called.
 *
 * After QCBORDecode_ExitArray() is called the traversal cusor is at
 * the item right after the array. This is true whether or not all
 * items in the array were consumed. QCBORDecode_ExitArray() can even
 * be called right after QCBORDecode_EnterArray() as a way to skip
 * over an array and all its contents.
 *
 * This works the same for definite and indefinite length arrays.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * If attempting to enter a data item that is not an array
 * @ref QCBOR_ERR_UNEXPECTED_TYPE wil be set.
 *
 * Nested arrays and maps may be entered to a depth of
 * @ref QCBOR_MAX_ARRAY_NESTING.
 *
 * See also QCBORDecode_ExitArray(), QCBORDecode_EnterMap(),
 * QCBORDecode_EnterBstrWrapped() and QCBORDecode_GetArray().
 */
static void
QCBORDecode_EnterArray(QCBORDecodeContext *pCtx, QCBORItem *pItem);

/** See QCBORDecode_EnterArray(). */
void
QCBORDecode_EnterArrayFromMapN(QCBORDecodeContext *pMe, int64_t uLabel);

/** See QCBORDecode_EnterArray(). */
void
QCBORDecode_EnterArrayFromMapSZ(QCBORDecodeContext *pMe, const char *szLabel);


/**
 * @brief Exit an array that has been enetered.
 *
 * @param[in] pCtx  The decode context.
 *
 * An array must have been entered for this to succeed.
 *
 * The items in the array that was entered do not have to have been
 * consumed for this to succeed.
 *
 * This sets the traversal cursor to the item after the
 * array that was exited.
 *
 * This will result in an error if any item in the array is not well
 * formed (since all items in the array must be decoded to find its
 * end), or there are not enough items in the array.
 */
static void
QCBORDecode_ExitArray(QCBORDecodeContext *pCtx);


/**
 * @brief Get the encoded bytes that make up an array.
 *
 * @param[in] pCtx           The decode context.
 * @param[out] pItem         Place to return the item.
 * @param[out] pEncodedCBOR  Place to return pointer and length of the array.
 *
 * The next item to decode must be an array.
 *
 * The encoded bytes of the array will be returned. They can be
 * decoded by another decoder instance.
 *
 * @c pItem will have the label and tags for the array. It is filled
 * in the same as if QCBORDecode_GetNext() were called on the array item. In
 * particular, the array count will be filled in for definite-length
 * arrays and set to @c UINT16_MAX for indefinite-length arrays.
 *
 * This works on both definite and indefinite length arrays (unless
 * indefinite length array decoding has been disabled).
 *
 * The pointer returned is to the data item that opens the array. The
 * length in bytes includes it and all the member data items. If the array
 * occurs in another map and thus has a label, the label is not included
 * in what is returned.
 *
 * If the array is preceeded by tags, those encoded tags are included
 * in the encoded CBOR that is returned.
 *
 * QCBORDecode_GetArray() consumes the entire array and leaves the
 * traversal cursor at the item after the array.
 * QCBORDecode_GetArrayFromMapN() and QCBORDecode_GetArrayFromMapSZ()
 * don't affect the traversal cursor.
 *
 * This traverses the whole array and every subordinate array or map in
 * it. This is necessary to determine the length of the array.
 *
 * This will fail if any item in the array is not well-formed.
 *
 * This uses a few hundred bytes of stack, more than most methods.
 *
 * See also QCBORDecode_EnterArray().
 */
static void
QCBORDecode_GetArray(QCBORDecodeContext *pCtx,
                     QCBORItem          *pItem,
                     UsefulBufC         *pEncodedCBOR);

/** See QCBORDecode_GetArray(). */
static void
QCBORDecode_GetArrayFromMapN(QCBORDecodeContext *pCtx,
                             int64_t             nLabel,
                             QCBORItem          *pItem,
                             UsefulBufC         *pEncodedCBOR);

/** See QCBORDecode_GetArray(). */
static void
QCBORDecode_GetArrayFromMapSZ(QCBORDecodeContext *pCtx,
                              const char         *szLabel,
                              QCBORItem          *pItem,
                              UsefulBufC         *pEncodedCBOR);



/**
 * @brief Enter a map for decoding and searching.
 *
 * @param[in] pCtx    The decode context.
 * @param[out] pItem  The optionally returned QCBORItem that has the
 *                    label and tags for the map. May be @c NULL (and
 *                    usually is).
 *
 * The next item in the CBOR input must be map or this sets an error.
 *
 * This puts the decoder in bounded mode which narrows decoding to the
 * map entered and enables getting items by label.
 *
 * All items in the map must be well-formed to be able to search it by
 * label because a full traversal is done for each search. If not, the
 * search will retun an error for the item that is not well-formed.
 * This will be the first non-well-formed item which may not be the
 * item with the label that is the target of the search.
 *
 * Nested maps can be decoded like this by entering each map in turn.
 *
 * Call QCBORDecode_ExitMap() to exit the current map decoding
 * level. When all map decoding layers are exited then bounded mode is
 * fully exited.
 *
 * While in bounded mode, QCBORDecode_GetNext() works as usual on the
 * map and the traversal cursor is maintained. It starts out
 * at the first item in the map just entered. Attempts to get items
 * off the end of the map will give error @ref QCBOR_ERR_NO_MORE_ITEMS
 * rather going to the next item after the map as it would when not in
 * bounded mode.
 *
 * It is possible to mix use of the traversal cursor with the fetching
 * of items in a map by label with the caveat that fetching
 * non-aggregate items by label behaves differently from entering subordinate
 * aggregate items by label.  See dicussion in @ref SpiffyDecode.
 *
 * Exiting leaves the traversal cursor at the data item following the
 * last entry in the map or at the end of the input CBOR if there
 * nothing after the map.
 *
 * Entering and Exiting a map is a way to skip over an entire map and
 * its contents. After QCBORDecode_ExitMap(), the traversal
 * cursor will be at the first item after the map.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_EnterArray() and
 * QCBORDecode_EnterBstrWrapped().  Entering and exiting any nested
 * combination of maps, arrays and bstr-wrapped CBOR is supported up
 * to the maximum of @ref QCBOR_MAX_ARRAY_NESTING.
 *
 * See also QCBORDecode_GetMap().
 */
static void
QCBORDecode_EnterMap(QCBORDecodeContext *pCtx, QCBORItem *pItem);

/** See QCBORDecode_EnterMap(). */
void
QCBORDecode_EnterMapFromMapN(QCBORDecodeContext *pCtx, int64_t nLabel);

/** See QCBORDecode_EnterMap(). */
void
QCBORDecode_EnterMapFromMapSZ(QCBORDecodeContext *pCtx, const char *szLabel);


/**
 * @brief Exit a map that has been enetered.
 *
 * @param[in] pCtx  The decode context.
 *
 * A map must have been entered for this to succeed.
 *
 * The items in the map that was entered do not have to have been
 * consumed for this to succeed.
 *
 * This sets the traversal cursor to the item after the map
 * that was exited.
 *
 * This will result in an error if any item in the map is not well
 * formed (since all items in the map must be decoded to find its
 * end), or there are not enough items in the map.
 */
static void
QCBORDecode_ExitMap(QCBORDecodeContext *pCtx);


/**
 * @brief Get the bytes that make up a map.
 *
 * @param[in] pCtx           The decode context.
 * @param[out] pItem         Place to return the item.
 * @param[out] pEncodedCBOR  Place to return pointer and length of the map.
 *
 * The next item to decode must be a map.
 *
 * The encoded bytes of the map will be returned. They can be
 * decoded by another decoder instance.
 *
 *  @c pItem will have the label and tags for the array. It is filled
 * in the same as if QCBORDecode_GetNext() were called on the map item. In
 * particular, the map count will be filled in for definite-length
 * maps and set to @c UINT16_MAX for indefinite-length maps.
 *
 * This works on both definite and indefinite length maps (unless
 * indefinite length map decoding has been disabled).
 *
 * The pointer returned is to the data item that opens the map. The
 * length in bytes includes it and all the member data items. If the map
 * occurs in another map and thus has a label, the label is not included
 * in what is returned.
 *
 * If the map is preceeded by tags, those encoded tags are included in
 * the encoded CBOR that is returned.
 *
 * QCBORDecode_GetMap() consumes the entire array and leaves the
 * traversal cursor at the item after the map.
 * QCBORDecode_GetMapFromMapN() and QCBORDecode_GetMapFromMapSZ()
 * don't affect the traversal cursor.
 *
 * This traverses the whole map and every subordinate array or map in
 * it. This is necessary to determine the length of the map. The
 * traversal cursor is left at the first item after the map.
 *
 * This will fail if any item in the map is not well-formed.
 *
 * This uses a few hundred bytes of stack, more than most methods.
 *
 * See also QCBORDecode_EnterMap().
 */
static void
QCBORDecode_GetMap(QCBORDecodeContext *pCtx,
                   QCBORItem          *pItem,
                   UsefulBufC         *pEncodedCBOR);

/** See QCBORDecode_GetMap(). */
static void
QCBORDecode_GetMapFromMapN(QCBORDecodeContext *pCtx,
                           int64_t             nLabel,
                           QCBORItem          *pItem,
                           UsefulBufC         *pEncodedCBOR);

/** See QCBORDecode_GetMap(). */
static void
QCBORDecode_GetMapFromMapSZ(QCBORDecodeContext *pCtx,
                            const char         *szLabel,
                            QCBORItem          *pItem,
                            UsefulBufC         *pEncodedCBOR);


/**
 * @brief Reset traversal cursor to start of map, array, byte-string
 *        wrapped CBOR or start of input.
 *
 * @param[in] pCtx  The decode context.
 *
 * If an array, map or wrapping byte string has been entered this sets
 * the traversal cursor to its beginning. If several arrays, maps or
 * byte strings have been entered, this sets the traversal cursor to
 * the beginning of the one most recently entered.
 *
 * If no map or array has been entered, this resets the traversal
 * cursor to the beginning of the input CBOR.
 *
 * This also resets the error state.
 */
void
QCBORDecode_Rewind(QCBORDecodeContext *pCtx);


/**
 * @brief Position traversal cursor by map label.
 *
 * @param[in] pCtx  The decode context.
 * @param[in] nLabel  The map label to seek too.
 *
 * On failure, such as map label not found, this sets the last error
 * and doesn't change the traversal cursor.  On success the traversal
 * cursor is moved to the map label item.
 */
void
QCBORDecode_SeekToLabelN(QCBORDecodeContext *pCtx, int64_t nLabel);


/**
 * @brief Position traversal cursor by map label.
 *
 * @param[in] pCtx  The decode context.
 * @param[in] nLabel  The map label to seek too.
 *
 * On failure, such as map label not found, this sets the last error
 * and doesn't change the traversal cursor.  On success the traversal
 * cursor is moved to the map label item.
 */
void
QCBORDecode_SeekToLabelSZ(QCBORDecodeContext *pMe, const char *szLabel);


/**
 * @brief Get an item in map by label and type.
 *
 * @param[in] pCtx    The decode context.
 * @param[in] nLabel  The integer label.
 * @param[in] uQcborType  The QCBOR type. One of @c QCBOR_TYPE_XXX.
 * @param[out] pItem  The returned item.
 *
 * A map must have been entered to use this. If not
 * @ref QCBOR_ERR_MAP_NOT_ENTERED is set.
 *
 * The map is searched for an item of the requested label and type.
 * @ref QCBOR_TYPE_ANY can be given to search for the label without
 * matching the type.
 *
 * This will always search the entire map. This will always perform
 * duplicate label detection, setting @ref QCBOR_ERR_DUPLICATE_LABEL
 * if there is more than one occurance of the label being searched
 * for.
 *
 * Duplicate label detection is performed for the item being sought
 * and only for the item being sought.
 *
 * This performs a full decode of every item in the map being
 * searched which involves a full traversal of every item. For maps
 * with little nesting, this is of little consequence, but may be of
 * consequence for large deeply nested CBOR structures on slow CPUs.
 *
 * The position of the traversal cursor is not changed.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * See also QCBORDecode_GetItemsInMap() for error discussion.
 */
void
QCBORDecode_GetItemInMapN(QCBORDecodeContext *pCtx,
                          int64_t             nLabel,
                          uint8_t             uQcborType,
                          QCBORItem          *pItem);

/** See QCBORDecode_GetItemInMapN(). */
void
QCBORDecode_GetItemInMapSZ(QCBORDecodeContext *pCtx,
                           const char         *szLabel,
                           uint8_t             uQcborType,
                           QCBORItem          *pItem);


/**
 * @brief Get a group of labeled items all at once from a map
 *
 * @param[in] pCtx           The decode context.
 * @param[in,out] pItemList  On input, the items to search for. On output,
 *                           the returne *d items.
 *
 * This gets several labeled items out of a map.
 *
 * @c pItemList is an array of items terminated by an item with @c
 * uLabelType @ref QCBOR_TYPE_NONE.
 *
 * On input the labels to search for are in the @c uLabelType and
 * label fields in the items in @c pItemList.
 *
 * Also on input are the requested QCBOR types in the field
 * @c uDataType.  To match any type, searching just by label,
 * @c uDataType can be @ref QCBOR_TYPE_ANY.
 *
 * This is a CPU-efficient way to decode a bunch of items in a map. It
 * is more efficient than scanning each individually because the map
 * only needs to be traversed once.
 *
 * Warning, this does not check that the tag numbers have been
 * consumed or checked. This can be remedied by checking that
 * every pItemList.auTagNumbers is empty or has tag numbers that are
 * expected. While tag numbers were once described as "optional",
 * they really do have critical information that should not be ignored.
 * See @ref TagDecoding
 *
 * This function works well with tag content decoders as described in
 * QCBORDecode_InstallTagDecoders().
 *
 * This will return maps and arrays that are in the map, but provides
 * no way to descend into and decode them. Use
 * QCBORDecode_EnterMapinMapN(), QCBORDecode_EnterArrayInMapN() and
 * such to descend into and process maps and arrays.
 *
 * The position of the traversal cursor is not changed.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview".
 *
 * The following errors are set:
 *
 * @ref QCBOR_ERR_MAP_NOT_ENTERED when calling this without previousl
 * calling QCBORDecode_EnterMap() or other methods to enter a map.
 *
 * @ref QCBOR_ERR_DUPLICATE_LABEL when one of the labels being searched
 * for is duplicate.
 *
 * @ref QCBOR_ERR_HIT_END or other errors classifed as not-well-formed
 * by QCBORDecode_IsNotWellFormed() as it is not possible to traverse
 * maps that have any non-well formed items.
 *
 * @ref QCBOR_ERR_UNEXPECTED_TYPE when the type of an item found by
 * matching a label is not the type requested.
 *
 * @ref QCBOR_ERR_ARRAY_NESTING_TOO_DEEP and other implementation
 * limit errors as it is not possible to travere a map beyond the
 * limits of the implementation.
 *
 * The error may occur on items that are not being searched for.  For
 * example, it is impossible to traverse over a map that has an array in
 * it that is not closed or over array and map nesting deeper than this
 * implementation can track.
 *
 * See also QCBORDecode_GetItemInMapN().
 */
void
QCBORDecode_GetItemsInMap(QCBORDecodeContext *pCtx, QCBORItem *pItemList);


/**
 * @brief Per-item callback for map searching.
 *
 * @param[in] pCallbackCtx  Pointer to the caller-defined context for the callback.
 * @param[in] pItem         The item from the map.
 *
 * The error set is intended for QCBOR errors, not general protocol
 * decoding errors. If this sets other than @ref QCBOR_SUCCESS, the
 * search will stop and the value it returns will be set in
 * QCBORDecode_GetItemsInMapWithCallback(). The special error,
 * @ref QCBOR_ERR_CALLBACK_FAIL, can be returned to indicate some
 * protocol processing error that is not a CBOR error. The specific
 * details of the protocol processing error can be returned the call
 * back context.
 */
typedef QCBORError (*QCBORItemCallback)(void            *pCallbackCtx,
                                        const QCBORItem *pItem);


/**
 * @brief Get a group of labeled items all at once from a map with a callback.
 *
 * @param[in] pCtx              The decode context.
 * @param[in,out] pItemList     On input, the items to search for. On output,
 *                              the returne *d items.
 * @param[in,out] pCallbackCtx  Pointer to a context structure for
 *                              @ref QCBORItemCallback
 * @param[in] pfCB              Pointer to function of type
 *                              @ref QCBORItemCallback that is called on
 *                              unmatched items.
 *
 * This searchs a map like QCBORDecode_GetItemsInMap(), but calls a
 * callback on items not matched rather than ignoring them. If @c
 * pItemList is empty, the call back will be called on every item in the
 * map.
 *
 * Like QCBORDecode_GetItemsInMap(), this only matches and calls back on
 * the items at the top level of the map entered. Items in nested
 * maps and arrays are skipped over and not candidate for matching or the
 * callback.
 *
 * See QCBORItemCallback() for error handling.
 */
void
QCBORDecode_GetItemsInMapWithCallback(QCBORDecodeContext *pCtx,
                                      QCBORItem          *pItemList,
                                      void               *pCallbackCtx,
                                      QCBORItemCallback   pfCB);

/**
 * @brief Decode the next item as a Boolean.
 *
 * @param[in] pCtx     The decode context.
 * @param[out] pbBool  The decoded byte string.
 *
 * The CBOR item to decode must be either the CBOR simple value (CBOR
 * type 7) @c true or @c false.
 *
 * Please see @ref Decode-Errors-Overview "Decode Errors Overview". If
 * the CBOR item to decode is not true or false the @ref
 * QCBOR_ERR_UNEXPECTED_TYPE error is set.
*/
void
QCBORDecode_GetBool(QCBORDecodeContext *pCtx, bool *pbBool);

/** See QCBORDecode_GetBool(). */
void
QCBORDecode_GetBoolInMapN(QCBORDecodeContext *pCtx,
                          int64_t             nLabel,
                          bool               *pbBool);

/** See QCBORDecode_GetBool(). */
void
QCBORDecode_GetBoolInMapSZ(QCBORDecodeContext *pCtx,
                           const char         *szLabel,
                           bool               *pbBool);


/**
 * @brief Decode the next item as a null.
 *
 * @param[in] pCtx  The decode context.
 *
 * The CBOR item to decode must be the CBOR simple value (CBOR type 7)
 * @c null. The reason to call this is to see if an error is returned
 * or not indicating whether the item is a CBOR null. If it is not
 * then the @ref QCBOR_ERR_UNEXPECTED_TYPE error is set.
 */
static void
QCBORDecode_GetNull(QCBORDecodeContext *pCtx);

/** See QCBORDecode_GetNull(). */
static void
QCBORDecode_GetNullInMapN(QCBORDecodeContext *pCtx, int64_t nLabel);

/** See QCBORDecode_GetNull(). */
static void
QCBORDecode_GetNullInMapSZ(QCBORDecodeContext *pCtx, const char *szLabel);


/**
 * @brief Decode the next item as a CBOR "undefined" item.
 *
 * @param[in] pCtx  The decode context.
 *
 * The CBOR item to decode must be the CBOR simple value (CBOR type 7)
 * @c undefined. The reason to call this is to see if an error is
 * returned or not indicating whether the item is a CBOR undefed
 * item. If it is not then the @ref QCBOR_ERR_UNEXPECTED_TYPE error is
 * set.
 */
static void
QCBORDecode_GetUndefined(QCBORDecodeContext *pCtx);

/** See QCBORDecode_GetUndefined(). */
static void
QCBORDecode_GetUndefinedInMapN(QCBORDecodeContext *pCtx, int64_t nLabel);

/** See QCBORDecode_GetUndefined(). */
static void
QCBORDecode_GetUndefinedInMapSZ(QCBORDecodeContext *pCtx, const char *szLabel);


/**
 * @brief Decode the next item as a CBOR simple value.
 *
 * @param[in] pCtx            The decode context.
 * @param[out] puSimpleValue  The simplle value returned.
 *
 * The purpose of this is to get a CBOR simple value other than a
 * Boolean, NULL or "undefined", but this works on all simple
 * values. See QCBOREncode_AddSimple() for more details on simple
 * values in general.
 *
 * See QCBORDecode_GetBool(), QCBORDecode_GetNull(),
 * QCBORDecode_GetUndefined() for the preferred way of getting those
 * simple values.
 */
void
QCBORDecode_GetSimple(QCBORDecodeContext *pCtx, uint8_t *puSimpleValue);

/** See QCBORDecode_GetSimple(). */
void
QCBORDecode_GetSimpleInMapN(QCBORDecodeContext *pCtx,
                            int64_t             nLabel,
                            uint8_t            *puSimpleValue);

/** See QCBORDecode_GetSimple(). */
void
QCBORDecode_GetSimpleInMapSZ(QCBORDecodeContext *pCtx,
                             const char         *szLabel,
                             uint8_t            *puSimpleValue);






/* ========================================================================= *
 *    BEGINNING OF PRIVATE INLINE IMPLEMENTATION                             *
 * ========================================================================= */


/** @private  Semi-private function. See qcbor_spiffy_decode.c */
void
QCBORDecode_Private_GetString(QCBORDecodeContext *pMe,
                              uint8_t             uType,
                              UsefulBufC         *pText);

/** @private  Semi-private function. See qcbor_spiffy_decode.c */
void
QCBORDecode_Private_EnterBoundedMapOrArray(QCBORDecodeContext *pCtx,
                                           uint8_t             uType,
                                           QCBORItem          *pItem);

/** @private  Semi-private function. See qcbor_spiffy_decode.c */
void
QCBORDecode_Private_ExitBoundedMapOrArray(QCBORDecodeContext *pCtx,
                                          uint8_t             uType);

/** @private  Semi-private function. See qcbor_main_decode.c */
void
QCBORDecode_Private_GetArrayOrMap(QCBORDecodeContext *pCtx,
                                  uint8_t             uType,
                                  QCBORItem          *pItem,
                                  UsefulBufC         *pEncodedCBOR);

/** @private  Semi-private function. See qcbor_spiffy_decode.c */
void
QCBORDecode_Private_SearchAndGetArrayOrMap(QCBORDecodeContext *pCtx,
                                           QCBORItem          *pTarget,
                                           QCBORItem          *pItem,
                                           UsefulBufC         *pEncodedCBOR);

/** @private  Semi-private data structure.  */
typedef struct {
   void               *pCBContext;
   QCBORItemCallback   pfCallback;
} MapSearchCallBack;

/** @private  Semi-private data structure.  */
typedef struct {
   size_t   uStartOffset;
   uint16_t uItemCount;
} MapSearchInfo;

/** @private  Semi-private function. See qcbor_spiffy_decode.c */
QCBORError
QCBORDecode_Private_MapSearch(QCBORDecodeContext *pMe,
                              QCBORItem          *pItemArray,
                              MapSearchInfo      *pInfo,
                              MapSearchCallBack  *pCallBack);

/** @private  Semi-private function. See qcbor_spiffy_decode.c */
QCBORError
QCBORDecode_Private_ExitBoundedLevel(QCBORDecodeContext *pMe,
                                     const uint32_t      uEndOffset);


/** @private  Semi-private function. See qcbor_decode.c */
void
QCBORDecode_Private_GetItemInMapNoCheckSZ(QCBORDecodeContext *pMe,
                                          const char         *szLabel,
                                          const uint8_t       uQcborType,
                                          QCBORItem          *pItem,
                                          size_t             *puOffset);

/** @private  Semi-private function. See qcbor_decode.c */
void
QCBORDecode_Private_GetItemInMapNoCheckN(QCBORDecodeContext *pMe,
                                         const int64_t       nLabel,
                                         const uint8_t       uQcborType,
                                         QCBORItem          *pItem,
                                         size_t             *puOffset);


static inline void
QCBORDecode_EnterMap(QCBORDecodeContext *pMe, QCBORItem *pItem) {
   QCBORDecode_Private_EnterBoundedMapOrArray(pMe, QCBOR_TYPE_MAP, pItem);
}

static inline void
QCBORDecode_EnterArray(QCBORDecodeContext *pMe, QCBORItem *pItem) {
   QCBORDecode_Private_EnterBoundedMapOrArray(pMe, QCBOR_TYPE_ARRAY, pItem);
}


static inline void
QCBORDecode_ExitArray(QCBORDecodeContext *pMe)
{
   QCBORDecode_Private_ExitBoundedMapOrArray(pMe, QCBOR_TYPE_ARRAY);
}

static inline void
QCBORDecode_ExitMap(QCBORDecodeContext *pMe)
{
   QCBORDecode_Private_ExitBoundedMapOrArray(pMe, QCBOR_TYPE_MAP);
}


static inline void
QCBORDecode_GetArray(QCBORDecodeContext *pMe,
                     QCBORItem          *pItem,
                     UsefulBufC         *pEncodedCBOR)
{
   QCBORDecode_Private_GetArrayOrMap(pMe, QCBOR_TYPE_ARRAY, pItem, pEncodedCBOR);
}


static inline void
QCBORDecode_GetArrayFromMapN(QCBORDecodeContext *pMe,
                             const int64_t       nLabel,
                             QCBORItem          *pItem,
                             UsefulBufC         *pEncodedCBOR)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = QCBOR_TYPE_ARRAY;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndGetArrayOrMap(pMe, OneItemSeach, pItem, pEncodedCBOR);
}


static inline void
QCBORDecode_GetArrayFromMapSZ(QCBORDecodeContext *pMe,
                              const char         *szLabel,
                              QCBORItem          *pItem,
                              UsefulBufC         *pEncodedCBOR)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = QCBOR_TYPE_ARRAY;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndGetArrayOrMap(pMe, OneItemSeach, pItem, pEncodedCBOR);
#else
   (void)szLabel;
   (void)pItem;
   (void)pEncodedCBOR;
   pMe->uLastError =  QCBOR_ERR_MAP_LABEL_TYPE;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
}

static inline void
QCBORDecode_GetMap(QCBORDecodeContext *pMe,
                   QCBORItem          *pItem,
                   UsefulBufC         *pEncodedCBOR)
{
   QCBORDecode_Private_GetArrayOrMap(pMe, QCBOR_TYPE_MAP, pItem, pEncodedCBOR);
}


static inline void
QCBORDecode_GetMapFromMapN(QCBORDecodeContext *pMe,
                           const int64_t       nLabel,
                           QCBORItem          *pItem,
                           UsefulBufC         *pEncodedCBOR)
{
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType  = QCBOR_TYPE_INT64;
   OneItemSeach[0].label.int64 = nLabel;
   OneItemSeach[0].uDataType   = QCBOR_TYPE_MAP;
   OneItemSeach[1].uLabelType  = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndGetArrayOrMap(pMe, OneItemSeach, pItem, pEncodedCBOR);
}


static inline void
QCBORDecode_GetMapFromMapSZ(QCBORDecodeContext *pMe,
                            const char         *szLabel,
                            QCBORItem          *pItem,
                            UsefulBufC         *pEncodedCBOR)
{
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   QCBORItem OneItemSeach[2];
   OneItemSeach[0].uLabelType   = QCBOR_TYPE_TEXT_STRING;
   OneItemSeach[0].label.string = UsefulBuf_FromSZ(szLabel);
   OneItemSeach[0].uDataType    = QCBOR_TYPE_MAP;
   OneItemSeach[1].uLabelType   = QCBOR_TYPE_NONE;

   QCBORDecode_Private_SearchAndGetArrayOrMap(pMe, OneItemSeach, pItem, pEncodedCBOR);
#else
   (void)szLabel;
   (void)pItem;
   (void)pEncodedCBOR;
   pMe->uLastError =  QCBOR_ERR_MAP_LABEL_TYPE;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
}


static inline void
QCBORDecode_GetByteString(QCBORDecodeContext *pMe, UsefulBufC *pBytes)
{
   QCBORDecode_Private_GetString(pMe, QCBOR_TYPE_BYTE_STRING, pBytes);
}

static inline void
QCBORDecode_GetByteStringInMapN(QCBORDecodeContext *pMe,
                                const int64_t       nLabel,
                                UsefulBufC         *pBytes)
{
   QCBORItem  Item;

   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_BYTE_STRING, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pBytes = Item.val.string;
   } else {
      *pBytes = NULLUsefulBufC;
   }
}

static inline void
QCBORDecode_GetByteStringInMapSZ(QCBORDecodeContext *pMe,
                                 const char         *szLabel,
                                 UsefulBufC         *pBytes)
{
   QCBORItem  Item;

   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_BYTE_STRING, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pBytes = Item.val.string;
   } else {
      *pBytes = NULLUsefulBufC;
   }
}


static inline void
QCBORDecode_GetTextString(QCBORDecodeContext *pMe, UsefulBufC *pText)
{
   QCBORDecode_Private_GetString(pMe, QCBOR_TYPE_TEXT_STRING, pText);
}

static inline void
QCBORDecode_GetTextStringInMapN(QCBORDecodeContext *pMe,
                                const int64_t       nLabel,
                                UsefulBufC         *pText)
{
   QCBORItem  Item;

   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_TEXT_STRING, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pText = Item.val.string;
   } else {
      *pText = NULLUsefulBufC;
   }
}

static inline void
QCBORDecode_GetTextStringInMapSZ(QCBORDecodeContext *pMe,
                                 const char         *szLabel,
                                 UsefulBufC         *pText)
{
   QCBORItem  Item;

   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_TEXT_STRING, &Item);

   if(pMe->uLastError == QCBOR_SUCCESS) {
      *pText = Item.val.string;
   } else {
      *pText = NULLUsefulBufC;
   }
}


static inline void
QCBORDecode_GetNull(QCBORDecodeContext *pMe)
{
   QCBORItem item;

   QCBORDecode_VGetNext(pMe, &item);
   if(pMe->uLastError == QCBOR_SUCCESS && item.uDataType != QCBOR_TYPE_NULL) {
      pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
   }
}

static inline void
QCBORDecode_GetNullInMapN(QCBORDecodeContext *pMe,
                          const int64_t       nLabel)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_NULL, &Item);
}

static inline void
QCBORDecode_GetNullInMapSZ(QCBORDecodeContext *pMe,
                           const char         *szLabel)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_NULL, &Item);
}

static inline void
QCBORDecode_GetUndefined(QCBORDecodeContext *pMe)
{
   QCBORItem item;

   QCBORDecode_VGetNext(pMe, &item);
   if(pMe->uLastError == QCBOR_SUCCESS && item.uDataType != QCBOR_TYPE_UNDEF) {
      pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
   }
}

static inline void
QCBORDecode_GetUndefinedInMapN(QCBORDecodeContext *pMe,
                               const int64_t       nLabel)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapN(pMe, nLabel, QCBOR_TYPE_UNDEF, &Item);
}

static inline void
QCBORDecode_GetUndefinedInMapSZ(QCBORDecodeContext *pMe,
                                const char         *szLabel)
{
   QCBORItem Item;
   QCBORDecode_GetItemInMapSZ(pMe, szLabel, QCBOR_TYPE_UNDEF, &Item);
}


/* ======================================================================== *
 *    END OF PRIVATE INLINE IMPLEMENTATION                                  *
 * ======================================================================== */



#ifdef __cplusplus
}
#endif

#endif /* qcbor_spiffy_decode_h */
