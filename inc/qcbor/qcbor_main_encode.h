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

#ifndef qcbor_main_encode_h
#define qcbor_main_encode_h


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
 * @file qcbor_main_encode.h
 *
 * @anchor Encoding
 *
 * ## Encoding
 *
 * A common encoding usage mode is to invoke the encoding twice. First
 * with the output buffer as @ref SizeCalculateUsefulBuf to compute the
 * length of the needed output buffer. The correct sized output buffer
 * is allocated. The encoder is invoked a second time with the allocated
 * output buffer.
 *
 * The double invocation is not required if the maximum output buffer
 * size can be predicted. This is usually possible for simple CBOR
 * structures.
 *
 * If a buffer too small to hold the encoded output is given, the error
 * @ref QCBOR_ERR_BUFFER_TOO_SMALL will be returned. Data will never be
 * written off the end of the output buffer no matter which functions
 * here are called or what parameters are passed to them.
 *
 * The encoding error handling is simple. The only possible errors are
 * trying to encode structures that are too large or too complex. There
 * are no internal malloc calls so there will be no failures for out of
 * memory.  The error state is tracked internally, so there is no need
 * to check for errors when encoding. Only the return code from
 * QCBOREncode_Finish() need be checked as once an error happens, the
 * encoder goes into an error state and calls to it to add more data
 * will do nothing. An error check is not needed after every data item
 * is added.
 *
 * Encoding generally proceeds by calling QCBOREncode_Init(), calling
 * lots of @c QCBOREncode_AddXxx() functions and calling
 * QCBOREncode_Finish(). There are many @c QCBOREncode_AddXxx()
 * functions for various data types. The input buffers need only to be
 * valid during the @c QCBOREncode_AddXxx() calls as the data is copied
 * into the output buffer.
 *
 * There are three `Add` functions for each data type. The first / main
 * one for the type is for adding the data item to an array.  The second
 * one's name ends in `ToMap`, is used for adding data items to maps and
 * takes a string argument that is its label in the map. The third one
 * ends in `ToMapN`, is also used for adding data items to maps, and
 * takes an integer argument that is its label in the map.
 *
 * The simplest aggregate type is an array, which is a simple ordered
 * set of items without labels the same as JSON arrays. Call
 * QCBOREncode_OpenArray() to open a new array, then various @c
 * QCBOREncode_AddXxx() functions to put items in the array and then
 * QCBOREncode_CloseArray(). Nesting to the limit @ref
 * QCBOR_MAX_ARRAY_NESTING is allowed.  All opens must be matched by
 * closes or an encoding error will be returned.
 *
 * The other aggregate type is a map which does use labels. The `Add`
 * functions that end in `ToMap` and `ToMapN` are convenient ways to add
 * labeled data items to a map. You can also call any type of `Add`
 * function once to add a label of any type and then call any type of
 * `Add` again to add its value.
 *
 * Note that when you nest arrays or maps in a map, the nested array or
 * map has a label.
 *
 * Many CBOR-based protocols start with an array or map. This makes
 * them self-delimiting. No external length or end marker is needed to
 * know the end. It is also possible to not start this way, in which case
 * this it is usually called a CBOR sequence which is described in
 * [RFC 8742](https://www.rfc-editor.org/rfc/rfc8742.html).
 * This encoder supports either just by whether the first item added is an
 * array, map or other.
 *
 * If QCBOR is compiled with QCBOR_DISABLE_ENCODE_USAGE_GUARDS defined,
 * the errors QCBOR_ERR_CLOSE_MISMATCH, QCBOR_ERR_ARRAY_TOO_LONG,
 * QCBOR_ERR_TOO_MANY_CLOSES, QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN, and
 * QCBOR_ERR_ENCODE_UNSUPPORTED will never be returned. It is up to the
 * caller to make sure that opened maps, arrays and byte-string wrapping
 * is closed correctly and that QCBOREncode_AddType7() is called
 * correctly.  With this defined, it is easier to make a mistake when
 * authoring the encoding of a protocol that will output not well formed
 * CBOR, but as long as the calling code is correct, it is safe to
 * disable these checks. Bounds checking that prevents security issues
 * in the code is still enforced. This define reduces the size of
 * encoding object code by about 150 bytes.
 */


/**
 * The size of the buffer to be passed to QCBOREncode_EncodeHead(). It
 * is one byte larger than sizeof(uint64_t) + 1, the actual maximum
 * size of the head of a CBOR data item because
 * QCBOREncode_EncodeHead() needs one extra byte to work.
 */
#define QCBOR_HEAD_BUFFER_SIZE  (sizeof(uint64_t) + 2)



/**
 * This enum is the bit flags for configuring the encoder for things
 * like the sorting of maps.
 */
enum QCBOREncodeConfig {
   /**
    * This causes maps to be sorted per RFC 8949 section 4.2.1 .
    * QCBOREncode_CloseMap() becomes equivalent to
    * QCBOREncode_CloseAndSortMap(). This causes map closing to run
    * much slower, but this is probably only of consequence in very
    * constrained environments sorting large maps.
    *
    * Note that map sorting causese about 30% more code from the QCBOR
    * library to be linked. Any call to QCBOREncode_Config(), even if
    * sorting is not selected, will cause the sorting code to be
    * linked.  See QCBOREncode_ConfigReduced() to avoid this.
    */
   QCBOR_ENCODE_CONFIG_SORT = 0x01,

   /** By default QCBOR will error with @ref QCBOR_ERR_NOT_ALLOWED
    * when trying to encode a double or float NaN that has a payload
    * because NaN payloads are not very interoperable. With this set,
    * NaN payloads can be encoded.
    */
   QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD = 0x02,

   /**
    * This unifies the integer and floating-point number space such
    * that there is only one way to encode any particular value. For
    * example, 0 is always encoded as a type 0 positive integer, never
    * as a 0.0 as a float or double. This unification never loses
    * precision. For example, 1.000001 would not be reduced to the
    * integer 1.
    *
    * This specification for this reduction comes from dCBOR. It is
    * part of a deterministic encoding that that covers integer and
    * float numbers.  This reduction doesn't cover other number
    * representations like big numbers and big floats.
    *
    * See @ref QCBOR_ENCODE_CONFIG_DCBOR.
    */
   QCBOR_ENCODE_CONFIG_FLOAT_REDUCTION = 0x04,

   /** With this set, attempts to encode indefinite length text and
    * byte strings, arrays and maps will error out. */
   QCBOR_ENCODE_CONFIG_DISALLOW_INDEFINITE_LENGTHS = 0x08,

   /** This disallows non-preferred floating number encoding,
    * QCBOREncode_AddFloatNoPreferred() and
    * QCBOREncode_AddDoubleNoPreferred().  It is not possible to disable
    * preferred serialization of type 0 and type 1 integers in QCBOR. */
   QCBOR_ENCODE_CONFIG_DISALLOW_NON_PREFERRED_NUMBERS = 0x10,

   /**
    * This enforces a simple rule in dCBOR allows only the simple
    * values true, false and null.  With this set, any other simple
    * value will error out. See @ref QCBOR_ENCODE_CONFIG_DCBOR.
    */
   QCBOR_ENCODE_CONFIG_ONLY_DCBOR_SIMPLE = 0x20,

   /** Preferred serialization requires number reduction of big
    * numbers to type 0 and 1 integers. With this set an error will be
    * set when trying to encode non-preferred big numbers with
    * QCBOREncode_AddTBigNumberNoPreferred() or
    * QCBOREncode_AddTBigNumberRaw(). */
   QCBOR_ENCODE_CONFIG_ONLY_PREFERRED_BIG_NUMBERS = 0x40, // TODO: test this one


   /**
    * Setting this mode will cause QCBOR to return an error if an
    * attempt is made to use one of the methods that produce
    * non-preferred serialization. It doesn't change anything else as
    * QCBOR produces preferred serialization by default.
    *
    * The non-preferred methods are:
    * QCBOREncode_AddFloatNoPreferred(),
    * QCBOREncode_AddDoubleNoPreferred(),
    * QCBOREncode_OpenArrayIndefiniteLength(),
    * QCBOREncode_CloseArrayIndefiniteLength(),
    * QCBOREncode_OpenMapIndefiniteLength(),
    * QCBOREncode_CloseMapIndefiniteLength(), plus those derived from
    * the above listed.
    *
    * This mode is just a user guard to prevent accidentally calling
    * something that produces non-preferred serialization. It doesn't
    * do anything but causes errors to occur on attempts to call the
    * above listed functions. This does nothing if the library is
    * compiled QCBOR_DISABLE_ENCODE_USAGE_GUARDS.
    *
    * See @ref Serialization. It is usually not necessary to set this
    * mode, but there is usually no disadvantage to setting
    * it. Preferred serialization is defined in RFC 8949, section 4.1.
    */
   QCBOR_ENCODE_CONFIG_PREFERRED =
       QCBOR_ENCODE_CONFIG_DISALLOW_INDEFINITE_LENGTHS |
       QCBOR_ENCODE_CONFIG_DISALLOW_NON_PREFERRED_NUMBERS |
       QCBOR_ENCODE_CONFIG_ONLY_PREFERRED_BIG_NUMBERS,

   /**
    * This causes QCBOR to produce CBOR Deterministic Encoding (CDE).
    * With CDE, two distant unrelated CBOR encoders will produce
    * exactly the same encoded CBOR for a given input.
    *
    * In addition to doing everything
    * @ref QCBOR_ENCODE_CONFIG_PREFERRED does (including exclusion of
    * indefinite lengths), this causes maps to be sorted. The map is
    * sorted automatically when QCBOREncode_CloseMap() is called. See
    * @ref QCBOR_ENCODE_CONFIG_SORT.
    *
    * See @ref Serialization. It is usually not necessary to set this
    * mode as determinism is very rarely needed. However it will
    * usually work with most protocols. CDE is defined in
    * draft-ietf-cbor-cde and/or RFC 8949 section 4.2.
    */
   QCBOR_ENCODE_CONFIG_CDE = QCBOR_ENCODE_CONFIG_PREFERRED |
                             QCBOR_ENCODE_CONFIG_SORT,

   /**
    * See draft-mcnally-deterministic-cbor.
    *
    * This is a superset of CDE. This function does everything
    * QCBOREncode_SerializationCDE() does. Also it is a super set of
    * preferred serialization and does everything
    * QCBOREncode_SerializationPreferred() does.
    *
    * The main feature of dCBOR is that there is only one way to
    * serialize a particular numeric value. This changes the behavior
    * of functions that add floating-point numbers.  If the
    * floating-point number is whole, it will be encoded as an
    * integer, not a floating-point number.  0.000 will be encoded as
    * 0x00. Precision is never lost in this conversion.
    *
    * dCBOR also disallows NaN payloads. QCBOR will allow NaN payloads
    * if you pass a NaN to one of the floating-point encoding
    * functions.  This mode forces all NaNs to the half-precision
    * queit NaN.
    *
    * TODO: confirm and test NaN payload behavior dCBOR reduces all
    * NaN payloads to half-precision quiet NaN
    *
    * dCBOR disallows use of any simple type other than true, false
    * and NULL. In particular it disallows use of "undef" produced by
    * QCBOREncode_AddUndef().
    *
    * See @ref Serialization. Set this mode only if the protocol you
    * are implementing requires dCBOR. This mode is usually not
    * compatible with protocols that don't use dCBOR. dCBOR is defined
    * in draft-mcnally-deterministic-cbor.
    */
   QCBOR_ENCODE_CONFIG_DCBOR = QCBOR_ENCODE_CONFIG_CDE |
                               QCBOR_ENCODE_CONFIG_FLOAT_REDUCTION |
                               QCBOR_ENCODE_CONFIG_ONLY_DCBOR_SIMPLE
};




/**
 * QCBOREncodeContext is the data type that holds context for all the
 * encoding functions. It is less than 200 bytes, so it can go on the
 * stack. The contents are opaque, and the caller should not access
 * internal members.  A context may be re used serially as long as it is
 * re initialized.
 */
typedef struct _QCBOREncodeContext QCBOREncodeContext;


/**
 * Initialize the encoder.
 *
 * @param[in,out]  pCtx     The encoder context to initialize.
 * @param[in]      Storage  The buffer into which the encoded result
 *                          will be written.
 *
 * Call this once at the start of an encoding of some CBOR. Then call
 * the many functions like QCBOREncode_AddInt64() and
 * QCBOREncode_AddText() to add the different data items. Finally,
 * call QCBOREncode_Finish() to get the pointer and length of the
 * encoded result.
 *
 * The primary purpose of this function is to give the pointer and
 * length of the output buffer into which the encoded CBOR will be
 * written. This is done with a @ref UsefulBuf structure, which is
 * just a pointer and length (it is equivalent to two parameters, one
 * a pointer and one a length, but a little prettier).
 *
 * The output buffer can be allocated any way (malloc, stack,
 * static). It is just some memory that QCBOR writes to. The length
 * must be the length of the allocated buffer. QCBOR will never write
 * past that length, but might write up to that length. If the buffer
 * is too small, encoding will go into an error state and not write
 * anything further.
 *
 * If allocating on the stack, the convenience macro
 * UsefulBuf_MAKE_STACK_UB() can be used, but its use is not required.
 *
 * Since there is no reallocation or such, the output buffer must be
 * correctly sized when passed in here. It is OK, but wasteful if it
 * is too large. One way to pick the size is to figure out the maximum
 * size that will ever be needed and hard code a buffer of that size.
 *
 * Another way to do it is to have QCBOR calculate it for you. To do
 * this, pass @ref SizeCalculateUsefulBuf for @c Storage.  Then call
 * all the functions to add the CBOR exactly as if encoding for
 * real. Finally, call QCBOREncode_FinishGetSize().  Once the length
 * is obtained, allocate a buffer of that size, call
 * QCBOREncode_Init() again with the real buffer. Call all the add
 * functions again and finally, QCBOREncode_Finish() to obtain the
 * final result. This uses twice the CPU time, but that is usually not
 * an issue.
 *
 * See QCBOREncode_Finish() for how the pointer and length for the
 * encoded CBOR is returned.
 *
 * For practical purposes QCBOR can't output encoded CBOR larger than
 * @c UINT32_MAX (4GB) even on 64-bit CPUs because the internal
 * offsets used to track the start of an array/map are 32 bits to
 * reduce the size of the encoding context.
 *
 * A @ref QCBOREncodeContext can be reused over and over as long as
 * QCBOREncode_Init() is called before each use.
 */
void
QCBOREncode_Init(QCBOREncodeContext *pCtx, UsefulBuf Storage);


/**
 * @brief Configure the encoder.
 *
 * @param[in] pCtx   The encoding context for mode set.
 * @param[in] uConfig  See @ref QCBOREncodeConfig.
 *
 * QCBOR usually as needed without configuration.
 *
 * QCBOR encodes with preferred serialization by default
 * but provides some explicit functions that don't. This
 * can configure QCBOR to error if they are used. This can
 * also be used to encode dCBOR.
 *
 * See @ref QCBOR_ENCODE_CONFIG_PREFERRED, @ref
 * QCBOR_ENCODE_CONFIG_DCBOR, @ref QCBOR_ENCODE_CONFIG_SORT
 * and such.
 *
 * Also see QCBOREncode_ConfigReduced() if you are concerned
 * about the amount of linked.
 */
static void
QCBOREncode_Config(QCBOREncodeContext *pCtx, enum QCBOREncodeConfig uConfig);


/**
 * @brief Configure the encoder, reduced object code.
 *
 * @param[in] pCtx   The encoding context for mode set.
 * @param[in] uConfig  Bit flags for configuration options.
 *
 * This is the same as QCBOREncode_Config() except it can't
 * configure anything to do with map sorting. That includes
 * both @ref CDE and @ref dCBOR. @ref QCBOR_ERR_NOT_ALLOWED
 * is returned if trying to configure map sorting.
 */
static void
QCBOREncode_ConfigReduced(QCBOREncodeContext *pCtx, enum QCBOREncodeConfig uConfig);




/**
 * @brief  Add a UTF-8 text string to the encoded output.
 *
 * @param[in] pCtx   The encoding context to add the text to.
 * @param[in] Text   Pointer and length of text to add.
 *
 * The text passed in must be unencoded UTF-8 according to
 * [RFC 3629](https://www.rfc-editor.org/rfc/rfc3629.html). There is
 * no @c NULL termination. The text is added as CBOR major type 3.
 *
 * If called with @c nBytesLen equal to 0, an empty string will be
 * added. When @c nBytesLen is 0, @c pBytes may be @c NULL.
 *
 * Note that the restriction of the buffer length to a @c uint32_t is
 * entirely intentional as this encoder is not capable of encoding
 * lengths greater. This limit to 4GB for a text string should not be
 * a problem.
 *
 * Text lines in Internet protocols (on the wire) are delimited by
 * either a CRLF or just an LF. Officially many protocols specify
 * CRLF, but implementations often work with either. CBOR type 3 text
 * can be either line ending, even a mixture of both.
 *
 * Operating systems usually have a line end convention. Windows uses
 * CRLF. Linux and MacOS use LF. Some applications on a given OS may
 * work with either and some may not.
 *
 * The majority of use cases and CBOR protocols using type 3 text will
 * work with either line ending. However, some use cases or protocols
 * may not work with either in which case translation to and/or from
 * the local line end convention, typically that of the OS, is
 * necessary.
 *
 * QCBOR does no line ending translation for type 3 text when encoding
 * and decoding.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 */
static void
QCBOREncode_AddText(QCBOREncodeContext *pCtx, UsefulBufC Text);

/** See QCBOREncode_AddText(). */
static void
QCBOREncode_AddTextToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC Text);

/** See QCBOREncode_AddText(). */
static void
QCBOREncode_AddTextToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, UsefulBufC Text);


/**
 * @brief  Add a UTF-8 text string to the encoded output.
 *
 * @param[in] pCtx      The encoding context to add the text to.
 * @param[in] szString  Null-terminated text to add.
 *
 * This works the same as QCBOREncode_AddText().
 */
static void
QCBOREncode_AddSZString(QCBOREncodeContext *pCtx, const char *szString);

/** See QCBOREncode_AddSZStringToMap(). */
static void
QCBOREncode_AddSZStringToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel, const char *szString);

/** See QCBOREncode_AddSZStringToMap(). */
static void
QCBOREncode_AddSZStringToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, const char *szString);


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

/** See QCBOREncode_AddBytesToMap(). */
static void
QCBOREncode_AddBytesToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC Bytes);

/** See QCBOREncode_AddBytesToMap(). */
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

/** See QCBOREncode_OpenBytesInMap(). */
static void
QCBOREncode_OpenBytesInMapSZ(QCBOREncodeContext *pCtx,
                             const char         *szLabel,
                             UsefulBuf          *pPlace);

/** See QCBOREncode_OpenBytesInMap(). */
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
 * @brief  Add a standard Boolean.
 *
 * @param[in] pCtx  The encoding context to add the Boolean to.
 * @param[in] b     true or false from @c <stdbool.h>.
 *
 * Adds a Boolean value as CBOR major type 7.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 */
static void
QCBOREncode_AddBool(QCBOREncodeContext *pCtx, bool b);

/** See QCBOREncode_AddBoolToMap(). */
static void
QCBOREncode_AddBoolToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel, bool b);

/** See QCBOREncode_AddBoolToMap(). */
static void
QCBOREncode_AddBoolToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, bool b);


/**
 * @brief  Add a NULL to the encoded output.
 *
 * @param[in] pCtx  The encoding context to add the NULL to.
 *
 * Adds the NULL value as CBOR major type 7.
 *
 * This NULL doesn't have any special meaning in CBOR such as a
 * terminating value for a string or an empty value.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 */
static void
QCBOREncode_AddNULL(QCBOREncodeContext *pCtx);

/** See QCBOREncode_AddNULL(). */
static void
QCBOREncode_AddNULLToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel);

/** See QCBOREncode_AddNULL(). */
static void
QCBOREncode_AddNULLToMapN(QCBOREncodeContext *pCtx, int64_t nLabel);


/**
 * @brief  Add an "undef" to the encoded output.
 *
 * @param[in] pCtx  The encoding context to add the "undef" to.
 *
 * Adds the undef value as CBOR major type 7.
 *
 * Note that this value will not translate to JSON.
 *
 * "undef" doesn't have any special meaning in CBOR such as a
 * terminating value for a string or an empty value.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 */
static void
QCBOREncode_AddUndef(QCBOREncodeContext *pCtx);

/** See QCBOREncode_AddUndef(). */
static void
QCBOREncode_AddUndefToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel);

/** See QCBOREncode_AddUndef(). */
static void
QCBOREncode_AddUndefToMapN(QCBOREncodeContext *pCtx, int64_t nLabel);


/**
 * @brief Add a simple value.
 *
 * @param[in] pCtx    The encode context.
 * @param[in] uNum   The simple value.
 *
 * QCBOREncode_AddBool(), QCBOREncode_AddUndef() and
 * QCBOREncode_AddNULL() are preferred to this for the simple values
 * defined in RFC 8949, but this can be used for them too.
 *
 * The main purpose of this is to add simple values beyond those in
 * defined RFC 8949. Note that simple values must be registered with
 * IANA. Those in the range of 0 to 19 must be standardized.  Those in
 * the range of 32 to 255 do not require a standard, but must be
 * publically specified. There is no range of values for proprietary
 * use. See
 * https://www.iana.org/assignments/cbor-simple-values/cbor-simple-values.xhtml
 */
static void
QCBOREncode_AddSimple(QCBOREncodeContext *pCtx, const uint8_t uNum);

/** See QCBOREncode_AddSimple(). */
static void
QCBOREncode_AddSimpleToMapSZ(QCBOREncodeContext *pCtx,
                             const char         *szLabel,
                             const uint8_t       uSimple);

/** See QCBOREncode_AddSimple(). */
static void
QCBOREncode_AddSimpleToMapN(QCBOREncodeContext *pCtx,
                            const int64_t       nLabel,
                            const uint8_t       uSimple);


/**
 * @brief  Indicates that the next items added are in an array.
 *
 * @param[in] pCtx The encoding context to open the array in.
 *
 * Arrays are the basic CBOR aggregate or structure type. Call this
 * function to start or open an array. Then call the various
 * @c QCBOREncode_AddXxx() functions to add the items that go into the
 * array. Then call QCBOREncode_CloseArray() when all items have been
 * added. The data items in the array can be of any type and can be of
 * mixed types.
 *
 * Nesting of arrays and maps is allowed and supported just by calling
 * QCBOREncode_OpenArray() again before calling
 * QCBOREncode_CloseArray().  While CBOR has no limit on nesting, this
 * implementation does in order to keep it smaller and simpler.  The
 * limit is @ref QCBOR_MAX_ARRAY_NESTING. This is the max number of
 * times this can be called without calling
 * QCBOREncode_CloseArray(). QCBOREncode_Finish() will return
 * @ref QCBOR_ERR_ARRAY_NESTING_TOO_DEEP when it is called as this
 * function just sets an error state and returns no value when this
 * occurs.
 *
 * If you try to add more than @ref QCBOR_MAX_ITEMS_IN_ARRAY items to
 * a single array or map, @ref QCBOR_ERR_ARRAY_TOO_LONG will be
 * returned when QCBOREncode_Finish() is called.
 *
 * An array itself must have a label if it is being added to a map.
 * Note that array elements do not have labels (but map elements do).
 *
 * An array itself may be tagged by calling QCBOREncode_AddTagNumber()
 * before this call.
 */
static void
QCBOREncode_OpenArray(QCBOREncodeContext *pCtx);

/** See QCBOREncode_OpenArray(). */
static void
QCBOREncode_OpenArrayInMapSZ(QCBOREncodeContext *pCtx, const char *szLabel);

/** See QCBOREncode_OpenArray(). */
static void
QCBOREncode_OpenArrayInMapN(QCBOREncodeContext *pCtx,  int64_t nLabel);


/**
 * @brief Close an open array.
 *
 * @param[in] pCtx The encoding context to close the array in.
 *
 * The closes an array opened by QCBOREncode_OpenArray(). It reduces
 * nesting level by one. All arrays (and maps) must be closed before
 * calling QCBOREncode_Finish().
 *
 * When an error occurs as a result of this call, the encoder records
 * the error and enters the error state. The error will be returned
 * when QCBOREncode_Finish() is called.
 *
 * If this has been called more times than QCBOREncode_OpenArray(), then
 * @ref QCBOR_ERR_TOO_MANY_CLOSES will be returned when QCBOREncode_Finish()
 * is called.
 *
 * If this is called and it is not an array that is currently open,
 * @ref QCBOR_ERR_CLOSE_MISMATCH will be returned when
 * QCBOREncode_Finish() is called.
 */
static void
QCBOREncode_CloseArray(QCBOREncodeContext *pCtx);




/**
 * @brief  Indicates that the next items added are in a map.
 *
 * @param[in] pCtx The encoding context to open the map in.
 *
 * See QCBOREncode_OpenArray() for more information, particularly
 * error handling.
 *
 * CBOR maps are an aggregate type where each item in the map consists
 * of a label and a value. They are similar to JSON objects.
 *
 * The value can be any CBOR type including another map.
 *
 * The label can also be any CBOR type, but in practice they are
 * typically, integers as this gives the most compact output. They
 * might also be text strings which gives readability and translation
 * to JSON.
 *
 * Every @c QCBOREncode_AddXxx() call has one version that ends with
 * @c InMap for adding items to maps with string labels and one that
 * ends with @c InMapN that is for adding with integer labels.
 *
 * RFC 8949 uses the term "key" instead of "label".
 *
 * If you wish to use map labels that are neither integer labels nor
 * text strings, then just call the QCBOREncode_AddXxx() function
 * explicitly to add the label. Then call it again to add the value.
 *
 * See the [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html)
 * for a lot more information on creating maps.
 */
static void
QCBOREncode_OpenMap(QCBOREncodeContext *pCtx);

/** See QCBOREncode_OpenMap(). */
static void
QCBOREncode_OpenMapInMapSZ(QCBOREncodeContext *pCtx, const char *szLabel);

/** See QCBOREncode_OpenMap(). */
static void
QCBOREncode_OpenMapInMapN(QCBOREncodeContext *pCtx, int64_t nLabel);


/**
 * @brief Close an open map.
 *
 * @param[in] pCtx The encoding context to close the map in.
 *
 * This closes a map opened by QCBOREncode_OpenMap(). It reduces
 * nesting level by one.
 *
 * When an error occurs as a result of this call, the encoder records
 * the error and enters the error state. The error will be returned
 * when QCBOREncode_Finish() is called.
 *
 * If this has been called more times than QCBOREncode_OpenMap(), then
 * @ref QCBOR_ERR_TOO_MANY_CLOSES will be returned when
 * QCBOREncode_Finish() is called.
 *
 * If this is called and it is not a map that is currently open,
 * @ref QCBOR_ERR_CLOSE_MISMATCH will be returned when
 * QCBOREncode_Finish() is called.
 */
static void
QCBOREncode_CloseMap(QCBOREncodeContext *pCtx);


/**
 * @brief Indicates that the next items added are in an indefinite length array.
 *
 * @param[in] pCtx The encoding context to open the array in.
 *
 * This is the same as QCBOREncode_OpenArray() except the array is
 * indefinite length.
 *
 * This must be closed with QCBOREncode_CloseArrayIndefiniteLength().
 */
static void
QCBOREncode_OpenArrayIndefiniteLength(QCBOREncodeContext *pCtx);

/** See QCBOREncode_OpenArrayIndefiniteLength(). */
static void
QCBOREncode_OpenArrayIndefiniteLengthInMapSZ(QCBOREncodeContext *pCtx,
                                             const char         *szLabel);

/** See QCBOREncode_OpenArrayIndefiniteLength(). */
static void
QCBOREncode_OpenArrayIndefiniteLengthInMapN(QCBOREncodeContext *pCtx,
                                            int64_t            nLabel);


/**
 * @brief Close an open indefinite length array.
 *
 * @param[in] pCtx The encoding context to close the array in.
 *
 * This is the same as QCBOREncode_CloseArray(), but the open array
 * that is being close must be of indefinite length.
 */
static void
QCBOREncode_CloseArrayIndefiniteLength(QCBOREncodeContext *pCtx);


/**
 * @brief Indicates that the next items added are in an indefinite length map.
 *
 * @param[in] pCtx The encoding context to open the map in.
 *
 * This is the same as QCBOREncode_OpenMap() except the array is
 * indefinite length.
 *
 * This must be closed with QCBOREncode_CloseMapIndefiniteLength().
 */
static void
QCBOREncode_OpenMapIndefiniteLength(QCBOREncodeContext *pCtx);

/** See QCBOREncode_OpenMapIndefiniteLength(). */
static void
QCBOREncode_OpenMapIndefiniteLengthInMapSZ(QCBOREncodeContext *pCtx,
                                           const char         *szLabel);

/** See QCBOREncode_OpenMapIndefiniteLength(). */
static void
QCBOREncode_OpenMapIndefiniteLengthInMapN(QCBOREncodeContext *pCtx,
                                         int64_t              nLabel);




/**
 * @brief Close an open indefinite length map.
 *
 * @param[in] pCtx The encoding context to close the map in.
 *
 * This is the same as QCBOREncode_CloseMap(), but the open map that
 * is being close must be of indefinite length.
 */
static void
QCBOREncode_CloseMapIndefiniteLength(QCBOREncodeContext *pCtx);


/**
 * @brief Close and sort an open map.
 *
 * @param[in] pCtx The encoding context to close the map in .
 *
 * This is the same as QCBOREncode_CloseMap() except it sorts the map
 * per RFC 8949 Section 4.2.1 and checks for duplicate map keys. This
 * sort is lexicographic of the CBOR-encoded map labels.
 *
 * This is more expensive than most things in the encoder. It uses
 * bubble sort which runs in n-squared time where @c n is the number
 * of map items. Sorting large maps on slow CPUs might be slow. This
 * is also increases the object code size of the encoder by about 30%
 * (500-1000 bytes).
 *
 * Bubble sort was selected so as to not need require configuration of
 * a buffer to track map item offsets. Bubble sort works well even
 * though map items are not all the same size because it always swaps
 * adjacent items.
 */
void
QCBOREncode_CloseAndSortMap(QCBOREncodeContext *pCtx);

/** See QCBOREncode_CloseAndSortMapIndef(). */
void
QCBOREncode_CloseAndSortMapIndef(QCBOREncodeContext *pCtx);


/**
 * @brief Indicate start of encoded CBOR to be wrapped in a bstr.
 *
 * @param[in] pCtx The encoding context to open the bstr-wrapped CBOR in.
 *
 * All added encoded items between this call and a call to
 * QCBOREncode_CloseBstrWrap2() will be wrapped in a bstr. They will
 * appear in the final output as a byte string.  That byte string will
 * contain encoded CBOR. This increases nesting level by one.
 *
 * The typical use case is for encoded CBOR that is to be
 * cryptographically hashed, as part of a
 * [RFC 9052, COSE](https://www.rfc-editor.org/rfc/rfc9052.html)
 * implementation. The
 * wrapping byte string is taken as input by the hash function (which
 * is why it is returned by QCBOREncode_CloseBstrWrap2()).  It is also
 * easy to recover on decoding with standard CBOR decoders.
 *
 * Using QCBOREncode_BstrWrap() and QCBOREncode_CloseBstrWrap2()
 * avoids having to encode the items first in one buffer (e.g., the
 * COSE payload) and then add that buffer as a bstr to another
 * encoding (e.g. the COSE to-be-signed bytes, the @c Sig_structure)
 * potentially halving the memory needed.
 *
 * CBOR by nature must be decoded item by item in order from the
 * start.  By wrapping some CBOR in a byte string, the decoding of
 * that wrapped CBOR can be skipped. This is another use of wrapping,
 * perhaps because the CBOR is large and deeply nested. Perhaps APIs
 * for handling one defined CBOR message that is being embedded in
 * another only take input as a byte string. Perhaps the desire is to
 * be able to decode the out layer even in the wrapped has errors.
 */
static void
QCBOREncode_BstrWrap(QCBOREncodeContext *pCtx);

/** See QCBOREncode_BstrWrap(). */
static void
QCBOREncode_BstrWrapInMapSZ(QCBOREncodeContext *pCtx, const char *szLabel);

/** See QCBOREncode_BstrWrap(). */
static void
QCBOREncode_BstrWrapInMapN(QCBOREncodeContext *pCtx, int64_t nLabel);


/**
 * @brief Close a wrapping bstr.
 *
 * @param[in] pCtx              The encoding context to close of bstr wrapping in.
 * @param[in] bIncludeCBORHead  Include the encoded CBOR head of the bstr
 *                              as well as the bytes in @c pWrappedCBOR.
 * @param[out] pWrappedCBOR     A @ref UsefulBufC containing wrapped bytes.
 *
 * The closes a wrapping bstr opened by QCBOREncode_BstrWrap(). It reduces
 * nesting level by one.
 *
 * A pointer and length of the enclosed encoded CBOR is returned in @c
 * *pWrappedCBOR if it is not @c NULL. The main purpose of this is so
 * this data can be hashed (e.g., with SHA-256) as part of a
 * [RFC 9052, COSE](https://www.rfc-editor.org/rfc/rfc9052.html)
 * implementation. **WARNING**, this pointer and length should be used
 * right away before any other calls to @c QCBOREncode_CloseXxx() as
 * they will move data around and the pointer and length will no
 * longer be to the correct encoded CBOR.
 *
 * When an error occurs as a result of this call, the encoder records
 * the error and enters the error state. The error will be returned
 * when QCBOREncode_Finish() is called.
 *
 * If this has been called more times than QCBOREncode_BstrWrap(),
 * then @ref QCBOR_ERR_TOO_MANY_CLOSES will be returned when
 * QCBOREncode_Finish() is called.
 *
 * If this is called and it is not a wrapping bstr that is currently
 * open, @ref QCBOR_ERR_CLOSE_MISMATCH will be returned when
 * QCBOREncode_Finish() is called.
 *
 * QCBOREncode_CloseBstrWrap() is a deprecated version of this function
 * that is equivalent to the call with @c bIncludeCBORHead @c true.
 */
void
QCBOREncode_CloseBstrWrap2(QCBOREncodeContext *pCtx, bool bIncludeCBORHead, UsefulBufC *pWrappedCBOR);

/** See QCBOREncode_CloseBstrWrap2(). */
static void
QCBOREncode_CloseBstrWrap(QCBOREncodeContext *pCtx, UsefulBufC *pWrappedCBOR);


/**
 * @brief Cancel byte string wrapping.
 *
 * @param[in] pCtx       The encoding context.
 *
 * This cancels QCBOREncode_BstrWrap() making the encoding as if it
 * were never called.
 *
 * WARNING: This does not work on QCBOREncode_BstrWrapInMapSZ()
 * or QCBOREncode_BstrWrapInMapN() and there is no error detection
 * of an attempt at their use.
 *
 * This only works if nothing has been added into the wrapped byte
 * string.  If something has been added, this sets the error
 * @ref QCBOR_ERR_CANNOT_CANCEL.
 */
void
QCBOREncode_CancelBstrWrap(QCBOREncodeContext *pCtx);


/**
 * @brief Add some already-encoded CBOR bytes.
 *
 * @param[in] pCtx     The encoding context to add the already-encode CBOR to.
 * @param[in] Encoded  The already-encoded CBOR to add to the context.
 *
 * The encoded CBOR being added must be fully conforming CBOR. It must
 * be complete with no arrays or maps that are incomplete. it is OK for the
 * raw CBOR added here to have indefinite lengths.
 *
 * The raw CBOR added here is not checked in anyway. If it is not
 * conforming or has open arrays or such, the final encoded CBOR
 * will probably be wrong or not what was intended.
 *
 * If the encoded CBOR being added here contains multiple items, they
 * must be enclosed in a map or array. At the top level the raw
 * CBOR must be a single data item.
 */
void
QCBOREncode_AddEncoded(QCBOREncodeContext *pCtx, UsefulBufC Encoded);


/** See QCBOREncode_AddEncoded(). */
static void
QCBOREncode_AddEncodedToMapSZ(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC Encoded);

/** See QCBOREncode_AddEncoded(). */
static void
QCBOREncode_AddEncodedToMapN(QCBOREncodeContext *pCtx, int64_t nLabel, UsefulBufC Encoded);


/**
 * @brief Get the encoded result.
 *
 * @param[in] pCtx           The context to finish encoding with.
 * @param[out] pEncodedCBOR  Structure in which the pointer and length of
 *                           the encoded CBOR is returned.
 *
 * @retval QCBOR_SUCCESS                     Encoded CBOR is returned.
 *
 * @retval QCBOR_ERR_TOO_MANY_CLOSES         Nesting error
 *
 * @retval QCBOR_ERR_CLOSE_MISMATCH          Nesting error
 *
 * @retval QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN Nesting error
 *
 * @retval QCBOR_ERR_BUFFER_TOO_LARGE        Encoded output buffer size
 *
 * @retval QCBOR_ERR_BUFFER_TOO_SMALL        Encoded output buffer size
 *
 * @retval QCBOR_ERR_ARRAY_NESTING_TOO_DEEP  Implementation limit
 *
 * @retval QCBOR_ERR_ARRAY_TOO_LONG          Implementation limit
 *
 * On success, the pointer and length of the encoded CBOR are returned
 * in @c *pEncodedCBOR. The pointer is the same pointer that was passed
 * in to QCBOREncode_Init(). Note that it is not const when passed to
 * QCBOREncode_Init(), but it is const when returned here.  The length
 * will be smaller than or equal to the length passed in when
 * QCBOREncode_Init() as this is the length of the actual result, not
 * the size of the buffer it was written to.
 *
 * If a @c NULL was passed for @c Storage.ptr when QCBOREncode_Init()
 * was called, @c NULL will be returned here, but the length will be
 * that of the CBOR that would have been encoded.
 *
 * Encoding errors primarily manifest here as most other encoding function
 * do no return an error. They just set the error state in the encode
 * context after which no encoding function does anything.
 *
 * Three types of errors manifest here. The first type are nesting
 * errors where the number of @c QCBOREncode_OpenXxx() calls do not
 * match the number @c QCBOREncode_CloseXxx() calls. The solution is to
 * fix the calling code.
 *
 * The second type of error is because the buffer given is either too
 * small or too large. The remedy is to give a correctly sized buffer.
 *
 * The third type are due to limits in this implementation.
 * @ref QCBOR_ERR_ARRAY_NESTING_TOO_DEEP can be worked around by
 * encoding the CBOR in two (or more) phases and adding the CBOR from
 * the first phase to the second with @c QCBOREncode_AddEncoded().
 *
 * If an error is returned, the buffer may have partially encoded
 * incorrect CBOR in it and it should not be used. Likewise, the length
 * may be incorrect and should not be used.
 *
 * Note that the error could have occurred in one of the many
 * @c QCBOREncode_AddXxx() calls long before QCBOREncode_Finish() was
 * called. This error handling reduces the CBOR implementation size
 * but makes debugging harder.
 *
 * This may be called multiple times. It will always return the
 * same. It can also be interleaved with calls to
 * QCBOREncode_FinishGetSize(). See QCBOREncode_SubString() for a
 * means to get the thus-far-encoded CBOR.
 *
 * QCBOREncode_GetErrorState() can be called to get the current
 * error state in order to abort encoding early as an optimization, but
 * calling it is is never required.
 */
QCBORError
QCBOREncode_Finish(QCBOREncodeContext *pCtx, UsefulBufC *pEncodedCBOR);


/**
 * @brief Get the encoded CBOR and error status.
 *
 * @param[in] pCtx          The context to finish encoding with.
 * @param[out] uEncodedLen  The length of the encoded or potentially
 *                          encoded CBOR in bytes.
 *
 * @return The same errors as QCBOREncode_Finish().
 *
 * This functions the same as QCBOREncode_Finish(), but only returns the
 * size of the encoded output.
 */
QCBORError
QCBOREncode_FinishGetSize(QCBOREncodeContext *pCtx, size_t *uEncodedLen);


/**
 * @brief Indicate whether the output storage buffer is NULL.
 *
 * @param[in] pCtx  The encoding context.
 *
 * @return 1 if the output buffer is @c NULL.
 *
 * As described in QCBOREncode_Init(), @c Storage.ptr may be give as @c NULL
 * for output size calculation. This returns 1 when that is the true, and 0 if not.
 */
static int
QCBOREncode_IsBufferNULL(QCBOREncodeContext *pCtx);


/**
 * @brief Retrieve the storage buffer passed in to QCBOREncode_Init().
 *
 * @param[in] pCtx  The encoding context.
 *
 * @return The output storage buffer passed to QCBOREncode_Init().
 *
 * This doesn't give any information about how much has been encoded
 * or the error state. It just returns the exact @ref UsefulOutBuf given
 * to QCBOREncode_Init().
 */
static UsefulBuf
QCBOREncode_RetrieveOutputStorage(QCBOREncodeContext *pCtx);


/**
 * @brief Get the encoding error state.
 *
 * @param[in] pCtx  The encoding context.
 *
 * @return One of @ref QCBORError. See return values from
 *         QCBOREncode_Finish()
 *
 * Normally encoding errors need only be handled at the end of
 * encoding when QCBOREncode_Finish() is called. This can be called to
 * get the error result before finish should there be a need to halt
 * encoding before QCBOREncode_Finish() is called.
 */
static QCBORError
QCBOREncode_GetErrorState(QCBOREncodeContext *pCtx);


/**
 * @brief Returns current end of encoded data.
 *
 * @param[in] pCtx  The encoding context.
 *
 * @return Byte offset of end of encoded data.
 *
 * The purpose of this is to enable cryptographic hashing over a
 * subpart of thus far CBOR-encoded data. Then perhaps a signature
 * over the hashed CBOR is added to the encoded output. There is
 * nothing specific to hashing or signing in this, so this can be used
 * for other too.
 *
 * Call this to get the offset of the start of the encoded
 * to-be-hashed CBOR items, then call QCBOREncode_SubString().
 * QCBOREncode_Tell() can also be called twice, first to get the
 * offset of the start and second for the offset of the end. Those
 * offsets can be applied to the output storage buffer.
 *
 * This will return successfully even if the encoder is in the error
 * state.
 *
 * WARNING: All definite-length arrays and maps opened before the
 * first call to QCBOREncode_Tell() must not be closed until the
 * substring is obtained and processed. Similarly, every
 * definite-length array or map opened after the first call to
 * QCBOREncode_Tell() must be closed before the substring is obtained
 * and processed.  The same applies for opened byte strings. There is
 * no detection of these errors. This occurs because QCBOR goes back
 * and inserts the lengths of definite-length arrays and maps when
 * they are closed. This insertion will make the offsets incorrect.
 */
static size_t
QCBOREncode_Tell(QCBOREncodeContext *pCtx);


/**
 * @brief Get a substring of encoded CBOR for cryptographic hash
 *
 * @param[in] pCtx  The encoding context.
 * @param[in] uStart  The start offset of substring.
 *
 * @return Pointer and length of of substring.
 *
 * @c uStart is obtained by calling QCBOREncode_Tell() before encoding
 * the first item in the substring. Then encode some data items. Then
 * call this. The substring returned contains the encoded data items.
 *
 * The substring may have deeply nested arrays and maps as long as any
 * opened after the call to QCBOREncode_Tell() are closed before this
 * is called.
 *
 * This will return @c NULLUsefulBufC if the encoder is in the error
 * state or if @c uStart is beyond the end of the thus-far encoded
 * data items.
 *
 * If @c uStart is 0, all the thus-far-encoded CBOR will be returned.
 * Unlike QCBOREncode_Finish(), this will succeed even if some arrays
 * and maps are not closed.
 *
 * See important usage WARNING in QCBOREncode_Tell()
 */
UsefulBufC
QCBOREncode_SubString(QCBOREncodeContext *pCtx, const size_t uStart);


/**
 * @brief Encode the head of a CBOR data item.
 *
 * @param Buffer       Buffer to output the encoded head to; must be
 *                     @ref QCBOR_HEAD_BUFFER_SIZE bytes in size.
 * @param uMajorType   One of CBOR_MAJOR_TYPE_XX.
 * @param uMinLen      The minimum number of bytes to encode uNumber. Almost
 *                     always this is 0 to use preferred
 *                     serialization. If this is 4, then even the
 *                     values 0xffff and smaller will be encoded in 4
 *                     bytes. This is used primarily when encoding a
 *                     float or double put into uNumber as the leading
 *                     zero bytes for them must be encoded.
 * @param uNumber      The numeric argument part of the CBOR head.
 * @return             Pointer and length of the encoded head or
 *                     @ref NULLUsefulBufC if the output buffer is too small.
 *
 * Callers do not to need to call this for normal CBOR encoding. Note
 * that it doesn't even take a @ref QCBOREncodeContext argument.
 *
 * This encodes the major type and argument part of a data item. The
 * argument is an integer that is usually either the value or the length
 * of the data item.
 *
 * This is exposed in the public interface to allow hashing of some CBOR
 * data types, bstr in particular, a chunk at a time so the full CBOR
 * doesn't have to be encoded in a contiguous buffer.
 *
 * For example, if you have a 100,000 byte binary blob in a buffer that
 * needs to be bstr encoded and then hashed. You could allocate a
 * 100,010 byte buffer and encode it normally. Alternatively, you can
 * encode the head in a 10 byte buffer with this function, hash that and
 * then hash the 100,000 bytes using the same hash context.
 */
UsefulBufC
QCBOREncode_EncodeHead(UsefulBuf Buffer,
                       uint8_t   uMajorType,
                       uint8_t   uMinLen,
                       uint64_t  uNumber);




/* ========================================================================= *
 *    BEGINNING OF DEPRECATED FUNCTION DECLARATIONS                          *
 *                                                                           *
 *    There is no plan to remove these in future versions.                   *
 *    They just have been replaced by something better.                      *
 * ========================================================================= */


/** @deprecated Use QCBOREncode_AddTextToMapSZ() instead. */
static void
QCBOREncode_AddTextToMap(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC Text);

/** @deprecated Use QCBOREncode_AddSZStringToMapSZ() instead. */
static void
QCBOREncode_AddSZStringToMap(QCBOREncodeContext *pCtx, const char *szLabel, const char *szString);

/** @deprecated Use QCBOREncode_AddBytesToMapSZ() instead. */
static void
QCBOREncode_AddBytesToMap(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC Bytes);

/** @deprecated Use QCBOREncode_AddBoolToMapSZ() instead. */
static void
QCBOREncode_AddBoolToMap(QCBOREncodeContext *pCtx, const char *szLabel, bool b);

/** @deprecated Use QCBOREncode_AddNULLToMapSZ() instead. */
static void
QCBOREncode_AddNULLToMap(QCBOREncodeContext *pCtx, const char *szLabel);

/** @deprecated Use QCBOREncode_AddUndefToMapSZ() instead. */
static void
QCBOREncode_AddUndefToMap(QCBOREncodeContext *pCtx, const char *szLabel);

/** @deprecated Use QCBOREncode_AddSimpleToMapSZ() instead. */
static void
QCBOREncode_AddSimpleToMap(QCBOREncodeContext *pCtx,
                           const char         *szLabel,
                           const uint8_t       uSimple);

/** @deprecated Use QCBOREncode_OpenArrayInMapSZ() instead. */
static void
QCBOREncode_OpenArrayInMap(QCBOREncodeContext *pCtx, const char *szLabel);

/** @deprecated Use QCBOREncode_OpenMapInMapSZ() instead. */
static void
QCBOREncode_OpenMapInMap(QCBOREncodeContext *pCtx, const char *szLabel);

/** @deprecated Use QCBOREncode_OpenArrayIndefiniteLengthInMapSZ() instead. */
static void
QCBOREncode_OpenArrayIndefiniteLengthInMap(QCBOREncodeContext *pCtx,
                                           const char         *szLabel);

/** @deprecated Use QCBOREncode_OpenMapIndefiniteLengthInMapSZ() instead. */
static void
QCBOREncode_OpenMapIndefiniteLengthInMap(QCBOREncodeContext *pCtx,
                                         const char         *szLabel);

/** @deprecated Use QCBOREncode_BstrWrapInMapSZ() instead. */
static void
QCBOREncode_BstrWrapInMap(QCBOREncodeContext *pCtx, const char *szLabel);

/** @deprecated Use QCBOREncode_AddEncodedToMapSZ() instead. */
static void
QCBOREncode_AddEncodedToMap(QCBOREncodeContext *pCtx, const char *szLabel, UsefulBufC Encoded);


/* ========================================================================= *
 *    END OF DEPRECATED FUNCTION DECLARATIONS                                *
 * ========================================================================= */




/* ========================================================================= *
 *    BEGINNING OF PRIVATE INLINE IMPLEMENTATION                             *
 * ========================================================================= */

/** @private See qcbor_main_encode.c */
void QCBOREncode_Private_AppendCBORHead(QCBOREncodeContext *pMe,
                                        const uint8_t       uMajorType,
                                        const uint64_t      uArgument,
                                        const uint8_t       uMinLen);

/** @private See qcbor_main_encode.c */
void
QCBOREncode_Private_AddBuffer(QCBOREncodeContext *pCtx,
                              uint8_t             uMajorType,
                              UsefulBufC          Bytes);

/** @private See qcbor_main_encode.c */
void
QCBOREncode_Private_OpenMapOrArray(QCBOREncodeContext *pCtx,
                                   uint8_t             uMajorType);

/** @private See qcbor_main_encode.c */
void
QCBOREncode_Private_OpenMapOrArrayIndefiniteLength(QCBOREncodeContext *pCtx,
                                                   uint8_t             uMajorType);

/** @private See qcbor_main_encode.c */
void
QCBOREncode_Private_CloseMapOrArray(QCBOREncodeContext *pCtx,
                                    uint8_t             uMajorType);

/** @private See qcbor_main_encode.c */
void
QCBOREncode_Private_CloseMapOrArrayIndefiniteLength(QCBOREncodeContext *pCtx,
                                                    uint8_t             uMajorType);

/** @private See qcbor_main_encode.c */
void
QCBOREncode_Private_CloseMapUnsorted(QCBOREncodeContext *pMe);

/** @private See qcbor_main_encode.c */
void
QCBOREncode_AddInt64(QCBOREncodeContext *pCtx, int64_t nNum);


/**
 * @brief  Semi-private method to add simple items and floating-point.
 * @private
 *
 * @param[in] pMe        The encoding context.
 * @param[in] uMinLen    Minimum encoding size for uNum. Usually 0.
 * @param[in] uArgument  The value to add.
 *
 * This is used to add simple types like true and false and float-point
 * values, both of which are type 7.
 *
 * Call QCBOREncode_AddBool(), QCBOREncode_AddNULL(),
 * QCBOREncode_AddUndef() QCBOREncode_AddDouble() instead of this.
 *
 * Error handling is the same as QCBOREncode_AddInt64().
 */
static inline void
QCBOREncode_Private_AddType7(QCBOREncodeContext *pMe,
                             const uint8_t       uMinLen,
                             const uint64_t      uArgument)
{
   QCBOREncode_Private_AppendCBORHead(pMe, CBOR_MAJOR_TYPE_SIMPLE, uArgument, uMinLen);
}




static inline void
QCBOREncode_Config(QCBOREncodeContext *pMe, enum QCBOREncodeConfig uConfig)
{
   /* The close function is made a function pointer as a way to avoid
    * linking the proportionately large chunk of code for sorting
    * maps unless explicitly requested. QCBOREncode_CloseAndSortMap()
    * doesn't get linked unless this function is called. */
   if(uConfig & QCBOR_ENCODE_CONFIG_SORT) {
      pMe->pfnCloseMap = QCBOREncode_CloseAndSortMap;
   } else {
      pMe->pfnCloseMap = QCBOREncode_Private_CloseMapUnsorted;
   }
   pMe->uConfigFlags = (int)uConfig;
}


static inline void
QCBOREncode_ConfigReduced(QCBOREncodeContext *pMe, enum QCBOREncodeConfig uConfig)
{
   if(uConfig & QCBOR_ENCODE_CONFIG_SORT) {
      pMe->uError = QCBOR_ERR_NOT_ALLOWED;
   } else {
      pMe->uConfigFlags = (int)uConfig;
   }
}



static inline void
QCBOREncode_AddText(QCBOREncodeContext *pMe, const UsefulBufC Text)
{
   QCBOREncode_Private_AddBuffer(pMe, CBOR_MAJOR_TYPE_TEXT_STRING, Text);
}

static inline void
QCBOREncode_AddTextToMapSZ(QCBOREncodeContext *pMe,
                           const char         *szLabel,
                           const UsefulBufC    Text)
{
   QCBOREncode_AddText(pMe, UsefulBuf_FromSZ(szLabel));
   QCBOREncode_AddText(pMe, Text);
}

static inline void
QCBOREncode_AddTextToMap(QCBOREncodeContext *pMe, const char *szLabel, UsefulBufC Text)
{
   QCBOREncode_AddTextToMapSZ(pMe, szLabel, Text);
}

static inline void
QCBOREncode_AddTextToMapN(QCBOREncodeContext *pMe,
                          const int64_t       nLabel,
                          const UsefulBufC    Text)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddText(pMe, Text);
}


inline static void
QCBOREncode_AddSZString(QCBOREncodeContext *pMe, const char *szString)
{
   QCBOREncode_AddText(pMe, UsefulBuf_FromSZ(szString));
}

static inline void
QCBOREncode_AddSZStringToMapSZ(QCBOREncodeContext *pMe,
                               const char         *szLabel,
                               const char         *szString)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddSZString(pMe, szString);
}

static inline void
QCBOREncode_AddSZStringToMap(QCBOREncodeContext *pMe, const char *szLabel, const char *szString)
{
   QCBOREncode_AddSZStringToMapSZ(pMe, szLabel, szString);
}

static inline void
QCBOREncode_AddSZStringToMapN(QCBOREncodeContext *pMe,
                              const int64_t       nLabel,
                              const char         *szString)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddSZString(pMe, szString);
}




static inline void
QCBOREncode_AddBytes(QCBOREncodeContext *pMe,
                     const UsefulBufC    Bytes)
{
   QCBOREncode_Private_AddBuffer(pMe, CBOR_MAJOR_TYPE_BYTE_STRING, Bytes);
}

static inline void
QCBOREncode_AddBytesToMapSZ(QCBOREncodeContext *pMe,
                            const char         *szLabel,
                            const UsefulBufC    Bytes)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddBytes(pMe, Bytes);
}

static inline void
QCBOREncode_AddBytesToMap(QCBOREncodeContext *pMe, const char *szLabel, UsefulBufC Bytes)
{
   QCBOREncode_AddBytesToMapSZ(pMe, szLabel, Bytes);
}

static inline void
QCBOREncode_AddBytesToMapN(QCBOREncodeContext *pMe,
                           const int64_t       nLabel,
                           const UsefulBufC    Bytes)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddBytes(pMe, Bytes);
}

static inline void
QCBOREncode_OpenBytesInMapSZ(QCBOREncodeContext *pMe,
                             const char         *szLabel,
                             UsefulBuf          *pPlace)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_OpenBytes(pMe, pPlace);
}

static inline void
QCBOREncode_OpenBytesInMapN(QCBOREncodeContext *pMe,
                            const int64_t       nLabel,
                            UsefulBuf          *pPlace)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_OpenBytes(pMe, pPlace);
}


static inline void
QCBOREncode_AddSimple(QCBOREncodeContext *pMe, const uint8_t uNum)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(pMe->uConfigFlags & QCBOR_ENCODE_CONFIG_ONLY_DCBOR_SIMPLE) {
      if(uNum < CBOR_SIMPLEV_FALSE || uNum > CBOR_SIMPLEV_NULL) {
         pMe->uError = QCBOR_ERR_NOT_PREFERRED;
         return;
      }
   }
   /* This check often is optimized out because uNum is known at compile time. */
   if(uNum >= CBOR_SIMPLEV_RESERVED_START && uNum <= CBOR_SIMPLEV_RESERVED_END) {
      pMe->uError = QCBOR_ERR_ENCODE_UNSUPPORTED;
      return;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   QCBOREncode_Private_AddType7(pMe, 0, uNum);
}

static inline void
QCBOREncode_AddSimpleToMapSZ(QCBOREncodeContext *pMe,
                             const char         *szLabel,
                             const uint8_t       uSimple)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddSimple(pMe, uSimple);
}

static inline void
QCBOREncode_AddSimpleToMap(QCBOREncodeContext *pMe,
                           const char         *szLabel,
                           const uint8_t       uSimple)
{
   QCBOREncode_AddSimpleToMapSZ(pMe, szLabel, uSimple);
}

static inline void
QCBOREncode_AddSimpleToMapN(QCBOREncodeContext *pMe,
                            const int64_t       nLabel,
                            const uint8_t       uSimple)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddSimple(pMe, uSimple);
}


static inline void
QCBOREncode_AddBool(QCBOREncodeContext *pMe, const bool b)
{
   uint8_t uSimple = CBOR_SIMPLEV_FALSE;
   if(b) {
      uSimple = CBOR_SIMPLEV_TRUE;
   }
   QCBOREncode_AddSimple(pMe, uSimple);
}

static inline void
QCBOREncode_AddBoolToMapSZ(QCBOREncodeContext *pMe, const char *szLabel, const bool b)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddBool(pMe, b);
}

static inline void
QCBOREncode_AddBoolToMap(QCBOREncodeContext *pMe, const char *szLabel, bool b)
{
   QCBOREncode_AddBoolToMapSZ(pMe, szLabel, b);
}

static inline void
QCBOREncode_AddBoolToMapN(QCBOREncodeContext *pMe, const int64_t nLabel, const bool b)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddBool(pMe, b);
}


static inline void
QCBOREncode_AddNULL(QCBOREncodeContext *pMe)
{
   QCBOREncode_AddSimple(pMe, CBOR_SIMPLEV_NULL);
}

static inline void
QCBOREncode_AddNULLToMapSZ(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddNULL(pMe);
}

static inline void
QCBOREncode_AddNULLToMap(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_AddNULLToMapSZ(pMe, szLabel);
}

static inline void
QCBOREncode_AddNULLToMapN(QCBOREncodeContext *pMe, const int64_t nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddNULL(pMe);
}


static inline void
QCBOREncode_AddUndef(QCBOREncodeContext *pMe)
{
   QCBOREncode_AddSimple(pMe, CBOR_SIMPLEV_UNDEF);
}

static inline void
QCBOREncode_AddUndefToMapSZ(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddUndef(pMe);
}

static inline void
QCBOREncode_AddUndefToMap(QCBOREncodeContext *pCtx, const char *szLabel)
{
   QCBOREncode_AddUndefToMapSZ(pCtx, szLabel);
}

static inline void
QCBOREncode_AddUndefToMapN(QCBOREncodeContext *pMe, const int64_t nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddUndef(pMe);
}


static inline void
QCBOREncode_OpenArray(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_OpenMapOrArray(pMe, CBOR_MAJOR_TYPE_ARRAY);
}

static inline void
QCBOREncode_OpenArrayInMapSZ(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_OpenArray(pMe);
}

static inline void
QCBOREncode_OpenArrayInMap(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_OpenArrayInMapSZ(pMe, szLabel);
}


static inline void
QCBOREncode_OpenArrayInMapN(QCBOREncodeContext *pMe,  const int64_t nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_OpenArray(pMe);
}


static inline void
QCBOREncode_CloseArray(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_CloseMapOrArray(pMe, CBOR_MAJOR_TYPE_ARRAY);
}


static inline void
QCBOREncode_OpenMap(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_OpenMapOrArray(pMe, CBOR_MAJOR_TYPE_MAP);
}

static inline void
QCBOREncode_OpenMapInMapSZ(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_OpenMap(pMe);
}

static inline void
QCBOREncode_OpenMapInMap(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_OpenMapInMapSZ(pMe, szLabel);
}

static inline void
QCBOREncode_OpenMapInMapN(QCBOREncodeContext *pMe, const int64_t nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_OpenMap(pMe);
}

static inline void
QCBOREncode_CloseMap(QCBOREncodeContext *pMe)
{
   (pMe->pfnCloseMap)(pMe);
}

static inline void
QCBOREncode_OpenArrayIndefiniteLength(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_OpenMapOrArrayIndefiniteLength(pMe, CBOR_MAJOR_NONE_TYPE_ARRAY_INDEFINITE_LEN);
}

static inline void
QCBOREncode_OpenArrayIndefiniteLengthInMapSZ(QCBOREncodeContext *pMe,
                                           const char         *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_OpenArrayIndefiniteLength(pMe);
}

static inline void
QCBOREncode_OpenArrayIndefiniteLengthInMap(QCBOREncodeContext *pMe,
                                           const char         *szLabel)
{
   QCBOREncode_OpenArrayIndefiniteLengthInMapSZ(pMe, szLabel);
}

static inline void
QCBOREncode_OpenArrayIndefiniteLengthInMapN(QCBOREncodeContext *pMe,
                                            const int64_t       nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_OpenArrayIndefiniteLength(pMe);
}

static inline void
QCBOREncode_CloseArrayIndefiniteLength(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_CloseMapOrArrayIndefiniteLength(pMe, CBOR_MAJOR_NONE_TYPE_ARRAY_INDEFINITE_LEN);
}


static inline void
QCBOREncode_OpenMapIndefiniteLength(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_OpenMapOrArrayIndefiniteLength(pMe, CBOR_MAJOR_NONE_TYPE_MAP_INDEFINITE_LEN);
}

static inline void
QCBOREncode_OpenMapIndefiniteLengthInMapSZ(QCBOREncodeContext *pMe,
                                           const char         *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_OpenMapIndefiniteLength(pMe);
}

static inline void
QCBOREncode_OpenMapIndefiniteLengthInMap(QCBOREncodeContext *pMe,
                                         const char         *szLabel)
{
   QCBOREncode_OpenMapIndefiniteLengthInMapSZ(pMe, szLabel);
}

static inline void
QCBOREncode_OpenMapIndefiniteLengthInMapN(QCBOREncodeContext *pMe,
                                          const int64_t       nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_OpenMapIndefiniteLength(pMe);
}

static inline void
QCBOREncode_CloseMapIndefiniteLength(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_CloseMapOrArrayIndefiniteLength(pMe, CBOR_MAJOR_NONE_TYPE_MAP_INDEFINITE_LEN);
}


static inline void
QCBOREncode_BstrWrap(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_OpenMapOrArray(pMe, CBOR_MAJOR_TYPE_BYTE_STRING);
}

static inline void
QCBOREncode_BstrWrapInMapSZ(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_BstrWrap(pMe);
}

static inline void /* Deprecated */
QCBOREncode_BstrWrapInMap(QCBOREncodeContext *pMe, const char *szLabel)
{
   QCBOREncode_BstrWrapInMapSZ(pMe, szLabel);
}

static inline void
QCBOREncode_BstrWrapInMapN(QCBOREncodeContext *pMe, const int64_t nLabel)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_BstrWrap(pMe);
}

static inline void
QCBOREncode_CloseBstrWrap(QCBOREncodeContext *pMe, UsefulBufC *pWrappedCBOR)
{
   QCBOREncode_CloseBstrWrap2(pMe, true, pWrappedCBOR);
}



static inline void
QCBOREncode_AddEncodedToMapSZ(QCBOREncodeContext *pMe,
                            const char         *szLabel,
                            const UsefulBufC    Encoded)
{
   QCBOREncode_AddSZString(pMe, szLabel);
   QCBOREncode_AddEncoded(pMe, Encoded);
}

static inline void /* Deprecated */
QCBOREncode_AddEncodedToMap(QCBOREncodeContext *pMe, const char *szLabel, UsefulBufC Encoded)
{
   QCBOREncode_AddEncodedToMapSZ(pMe, szLabel, Encoded);
}

static inline void
QCBOREncode_AddEncodedToMapN(QCBOREncodeContext *pMe,
                             const int64_t       nLabel,
                             const UsefulBufC    Encoded)
{
   QCBOREncode_AddInt64(pMe, nLabel);
   QCBOREncode_AddEncoded(pMe, Encoded);
}


static inline int
QCBOREncode_IsBufferNULL(QCBOREncodeContext *pMe)
{
   return UsefulOutBuf_IsBufferNULL(&(pMe->OutBuf));
}


static inline UsefulBuf
QCBOREncode_RetrieveOutputStorage(QCBOREncodeContext *pMe)
{
   return UsefulOutBuf_RetrieveOutputStorage(&(pMe->OutBuf));
}


static inline QCBORError
QCBOREncode_GetErrorState(QCBOREncodeContext *pMe)
{
   if(UsefulOutBuf_GetError(&(pMe->OutBuf))) {
      /* Items didn't fit in the buffer. This check catches this
       * condition for all the appends and inserts so checks aren't
       * needed when the appends and inserts are performed.  And of
       * course UsefulBuf will never overrun the input buffer given to
       * it. No complex analysis of the error handling in this file is
       * needed to know that is true. Just read the UsefulBuf code.
       */
      pMe->uError = QCBOR_ERR_BUFFER_TOO_SMALL;
      /* QCBOR_ERR_BUFFER_TOO_SMALL masks other errors, but that is
       * OK. Once the caller fixes this, they'll be unmasked.
       */
   }

   return (QCBORError)pMe->uError;
}


static inline size_t
QCBOREncode_Tell(QCBOREncodeContext *pMe)
{
   return UsefulOutBuf_GetEndPosition(&(pMe->OutBuf));
}


/* ======================================================================== *
 *    END OF PRIVATE INLINE IMPLEMENTATION                                  *
 * ======================================================================== */


#ifdef __cplusplus
}
#endif

#endif /* qcbor_encode_h */
