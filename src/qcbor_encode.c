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


#include "qcbor/qcbor_encode.h"
#include "ieee754.h"

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
#include <math.h> /* Only for NAN definition */
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */


/**
 * @file qcbor_encode.c
 *
 * The entire implementation of the QCBOR encoder.
 */


/*
 * == Nesting Tracking ==
 *
 * The following functions and data type QCBORTrackNesting implement
 * the nesting management for encoding.
 *
 * CBOR's two nesting types, arrays and maps, are tracked here. There
 * is a limit of QCBOR_MAX_ARRAY_NESTING to the number of arrays and
 * maps that can be nested in one encoding so the encoding context
 * stays small enough to fit on the stack.
 *
 * When an array/map is opened, pCurrentNesting points to the element
 * in pArrays that records the type, start position and accumulates a
 * count of the number of items added. When closed the start position
 * is used to go back and fill in the type and number of items in the
 * array/map.
 *
 * Encoded output can be a CBOR Sequence (RFC 8742) in which case
 * there is no top-level array or map. It starts out with a string,
 * integer or other non-aggregate type. It may have an array or map
 * other than at the start, in which case that nesting is tracked
 * here.
 *
 * QCBOR has a special feature to allow constructing byte string
 * wrapped CBOR directly into the output buffer, so no extra buffer is
 * needed for byte string wrapping.  This is implemented as nesting
 * with the type CBOR_MAJOR_TYPE_BYTE_STRING and is tracked here. Byte
 * string wrapped CBOR is used by COSE for data that is to be hashed.
 */
static void
Nesting_Init(QCBORTrackNesting *pNesting)
{
   /* Assumes pNesting has been zeroed. */
   pNesting->pCurrentNesting = &pNesting->pArrays[0];
   /* Implied CBOR array at the top nesting level. This is never
    * returned, but makes the item count work correctly.
    */
   pNesting->pCurrentNesting->uMajorType = CBOR_MAJOR_TYPE_ARRAY;
}

static uint8_t
Nesting_Increase(QCBORTrackNesting *pNesting,
                 const uint8_t      uMajorType,
                 const uint32_t     uPos)
{
   if(pNesting->pCurrentNesting == &pNesting->pArrays[QCBOR_MAX_ARRAY_NESTING]) {
      return QCBOR_ERR_ARRAY_NESTING_TOO_DEEP;
   } else {
      pNesting->pCurrentNesting++;
      pNesting->pCurrentNesting->uCount     = 0;
      pNesting->pCurrentNesting->uStart     = uPos;
      pNesting->pCurrentNesting->uMajorType = uMajorType;
      return QCBOR_SUCCESS;
   }
}

static void
Nesting_Decrease(QCBORTrackNesting *pNesting)
{
   if(pNesting->pCurrentNesting > &pNesting->pArrays[0]) {
      pNesting->pCurrentNesting--;
   }
}

static uint8_t
Nesting_Increment(QCBORTrackNesting *pNesting)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(pNesting->pCurrentNesting->uCount >= QCBOR_MAX_ITEMS_IN_ARRAY) {
      return QCBOR_ERR_ARRAY_TOO_LONG;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   pNesting->pCurrentNesting->uCount++;

   return QCBOR_SUCCESS;
}

static void
Nesting_Decrement(QCBORTrackNesting *pNesting)
{
   /* No error check for going below 0 here needed because this
    * is only used by QCBOREncode_CancelBstrWrap() and it checks
    * the nesting level before calling this. */
   pNesting->pCurrentNesting->uCount--;
}

static uint16_t
Nesting_GetCount(QCBORTrackNesting *pNesting)
{
   /* The nesting count recorded is always the actual number of
    * individual data items in the array or map. For arrays CBOR uses
    * the actual item count. For maps, CBOR uses the number of pairs.
    * This function returns the number needed for the CBOR encoding,
    * so it divides the number of items by two for maps to get the
    * number of pairs.
    */
   if(pNesting->pCurrentNesting->uMajorType == CBOR_MAJOR_TYPE_MAP) {
      /* Cast back to uint16_t after integer promotion from bit shift */
      return (uint16_t)(pNesting->pCurrentNesting->uCount >> 1);
   } else {
      return pNesting->pCurrentNesting->uCount;
   }
}

static uint32_t
Nesting_GetStartPos(QCBORTrackNesting *pNesting)
{
   return pNesting->pCurrentNesting->uStart;
}

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
static uint8_t
Nesting_GetMajorType(QCBORTrackNesting *pNesting)
{
   return pNesting->pCurrentNesting->uMajorType;
}

static bool
Nesting_IsInNest(QCBORTrackNesting *pNesting)
{
   return pNesting->pCurrentNesting == &pNesting->pArrays[0] ? false : true;
}
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */




/*
 * == Major CBOR Types ==
 *
 * Encoding of the major CBOR types is by these functions:
 *
 * CBOR Major Type  Public Function
 * 0                QCBOREncode_AddUInt64()
 * 0, 1             QCBOREncode_AddUInt64(), QCBOREncode_AddInt64()
 * 2, 3             QCBOREncode_AddBuffer()
 * 4, 5             QCBOREncode_OpenMapOrArray(), QCBOREncode_CloseMapOrArray(),
 *                  QCBOREncode_OpenMapOrArrayIndefiniteLength(),
 *                  QCBOREncode_CloseMapOrArrayIndefiniteLength()
 * 6                QCBOREncode_AddTagNumber()
 * 7                QCBOREncode_AddDouble(), QCBOREncode_AddFloat(),
 *                  QCBOREncode_AddDoubleNoPreferred(),
 *                  QCBOREncode_AddFloatNoPreferred(), QCBOREncode_AddType7()
 *
 * Additionally, encoding of decimal fractions and bigfloats is by
 * QCBOREncode_AddExponentAndMantissa() and byte strings that wrap
 * encoded CBOR are handled by QCBOREncode_OpenMapOrArray() and
 * QCBOREncode_CloseBstrWrap2().
 *
 *
 * == Error Tracking Plan ==
 *
 * Errors are tracked internally and not returned until
 * QCBOREncode_Finish() or QCBOREncode_GetErrorState() is called. The
 * CBOR errors are in me->uError.  UsefulOutBuf also tracks whether
 * the buffer is full or not in its context.  Once either of these
 * errors is set they are never cleared. Only QCBOREncode_Init()
 * resets them. Or said another way, they must never be cleared or
 * we'll tell the caller all is good when it is not.
 *
 * Only one error code is reported by QCBOREncode_Finish() even if
 * there are multiple errors. The last one set wins. The caller might
 * have to fix one error to reveal the next one they have to fix.
 * This is OK.
 *
 * The buffer full error tracked by UsefulBuf is only pulled out of
 * UsefulBuf in QCBOREncode_Finish() so it is the one that usually
 * wins.  UsefulBuf will never go off the end of the buffer even if it
 * is called again and again when full.
 *
 * QCBOR_DISABLE_ENCODE_USAGE_GUARDS disables about half of the error
 * checks here to reduce code size by about 150 bytes leaving only the
 * checks for size to avoid buffer overflow. If the calling code is
 * completely correct, checks are completely unnecessary.  For
 * example, there is no need to check that all the opens are matched
 * by a close.
 *
 * QCBOR_DISABLE_ENCODE_USAGE_GUARDS also disables the check for more
 * than QCBOR_MAX_ITEMS_IN_ARRAY in an array. Since
 * QCBOR_MAX_ITEMS_IN_ARRAY is very large (65,534) it is very unlikely
 * to be reached. If it is reached, the count will wrap around to zero
 * and CBOR that is not well formed will be produced, but there will
 * be no buffers overrun and new security issues in the code.
 *
 * The 8 errors returned here fall into three categories:
 *
 * Sizes
 *   QCBOR_ERR_BUFFER_TOO_LARGE        -- Encoded output exceeded UINT32_MAX
 *   QCBOR_ERR_BUFFER_TOO_SMALL        -- Output buffer too small
 *   QCBOR_ERR_ARRAY_NESTING_TOO_DEEP  -- Nesting > QCBOR_MAX_ARRAY_NESTING1
 *   QCBOR_ERR_ARRAY_TOO_LONG          -- Too many items added to an array/map [1]
 *
 * Nesting constructed incorrectly
 *   QCBOR_ERR_TOO_MANY_CLOSES         -- More close calls than opens [1]
 *   QCBOR_ERR_CLOSE_MISMATCH          -- Type of close does not match open [1]
 *   QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN -- Finish called without enough closes [1]
 *
 * Would generate not-well-formed CBOR
 *   QCBOR_ERR_ENCODE_UNSUPPORTED      -- Simple type between 24 and 31 [1]
 *
 * [1] indicated disabled by QCBOR_DISABLE_ENCODE_USAGE_GUARDS
 */


/* Forward declaration for reference in QCBOREncode_Init() */
static void
QCBOREncode_Private_CloseMapUnsorted(QCBOREncodeContext *pMe);


/*
 * Public function for initialization. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_Init(QCBOREncodeContext *pMe, UsefulBuf Storage)
{
   memset(pMe, 0, sizeof(QCBOREncodeContext));
   UsefulOutBuf_Init(&(pMe->OutBuf), Storage);
   Nesting_Init(&(pMe->nesting));
   pMe->pfnCloseMap = QCBOREncode_Private_CloseMapUnsorted;
}


/*
 * Public function to encode a CBOR head. See qcbor/qcbor_encode.h
 */
UsefulBufC
QCBOREncode_EncodeHead(UsefulBuf Buffer,
                       uint8_t   uMajorType,
                       uint8_t   uMinLen,
                       uint64_t  uArgument)
{
   /*
    * == Description of the CBOR Head ==
    *
    *    The head of a CBOR data item
    *  +---+-----+ +--------+ +--------+ +--------+      +--------+
    *  |M T|  A R G U M E N T . . .                               |
    *  +---+-----+ +--------+ +--------+ +--------+ ...  +--------+
    *
    * Every CBOR data item has a "head". It is made up of the "major
    * type" and the "argument".
    *
    * The major type indicates whether the data item is an integer,
    * string, array or such. It is encoded in 3 bits giving it a range
    * from 0 to 7.  0 indicates the major type is a positive integer,
    * 1 a negative integer, 2 a byte string and so on.
    *
    * These 3 bits are the first part of the "initial byte" in a data
    * item.  Every data item has an initial byte, and some only have
    * the initial byte.
    *
    * The argument is essentially a number between 0 and UINT64_MAX
    * (18446744073709551615). This number is interpreted to mean
    * different things for the different major types. For major type
    * 0, a positive integer, it is value of the data item. For major
    * type 2, a byte string, it is the length in bytes of the byte
    * string. For major type 4, an array, it is the number of data
    * items in the array.
    *
    * Special encoding is used so that the argument values less than
    * 24 can be encoded very compactly in the same byte as the major
    * type is encoded. When the lower 5 bits of the initial byte have
    * a value less than 24, then that is the value of the argument.
    *
    * If the lower 5 bits of the initial byte are less than 24, then
    * they are the value of the argument. This allows integer values 0
    * - 23 to be CBOR encoded in just one byte.
    *
    * When the value of lower 5 bits are 24, 25, 26, or 27 the
    * argument is encoded in 1, 2, 4 or 8 bytes following the initial
    * byte in network byte order (bit endian). The cases when it is
    * 28, 29 and 30 are reserved for future use. The value 31 is a
    * special indicator for indefinite length strings, arrays and
    * maps.
    *
    * The lower 5 bits are called the "additional information."
    *
    * Thus the CBOR head may be 1, 2, 3, 5 or 9 bytes long.
    *
    * It is legal in CBOR to encode the argument using any of these
    * lengths even if it could be encoded in a shorter length. For
    * example it is legal to encode a data item representing the
    * positive integer 0 in 9 bytes even though it could be encoded in
    * only 0. This is legal to allow for for very simple code or even
    * hardware-only implementations that just output a register
    * directly.
    *
    * CBOR defines preferred encoding as the encoding of the argument
    * in the smallest number of bytes needed to encode it.
    *
    * This function takes the major type and argument as inputs and
    * outputs the encoded CBOR head for them. It does conversion to
    * network byte order.  It implements CBOR preferred encoding,
    * outputting the shortest representation of the argument.
    *
    * == Endian Conversion ==
    *
    * This code does endian conversion without hton() or knowing the
    * endianness of the machine by using masks and shifts. This avoids
    * the dependency on hton() and the mess of figuring out how to
    * find the machine's endianness.
    *
    * This is a good efficient implementation on little-endian
    * machines.  A faster and smaller implementation is possible on
    * big-endian machines because CBOR/network byte order is
    * big-endian. However big-endian machines are uncommon.
    *
    * On x86, this is about 150 bytes instead of 500 bytes for the
    * original, more formal unoptimized code.
    *
    * This also does the CBOR preferred shortest encoding for integers
    * and is called to do endian conversion for floats.
    *
    * It works backwards from the least significant byte to the most
    * significant byte.
    *
    * == Floating Point ==
    *
    * When the major type is 7 and the 5 lower bits have the values
    * 25, 26 or 27, the argument is a floating-point number that is
    * half, single or double-precision. Note that it is not the
    * conversion from a floating-point value to an integer value like
    * converting 0x00 to 0.00, it is the interpretation of the bits in
    * the argument as an IEEE 754 float-point number.
    *
    * Floating-point numbers must be converted to network byte
    * order. That is accomplished here by exactly the same code that
    * converts integer arguments to network byte order.
    *
    * There is preferred encoding for floating-point numbers in CBOR,
    * but it is very different than for integers and it is not
    * implemented here.  Half-precision is preferred to
    * single-precision which is preferred to double-precision only if
    * the conversion can be performed without loss of precision. Zero
    * and infinity can always be converted to half-precision, without
    * loss but 3.141592653589 cannot.
    *
    * The way this function knows to not do preferred encoding on the
    * argument passed here when it is a floating point number is the
    * uMinLen parameter. It should be 2, 4 or 8 for half, single and
    * double precision floating point values. This prevents and the
    * incorrect removal of leading zeros when encoding arguments that
    * are floating-point numbers.
    *
    * == Use of Type int and Static Analyzers ==
    *
    * The type int is used here for several variables because of the
    * way integer promotion works in C for variables that are uint8_t
    * or uint16_t. The basic rule is that they will always be promoted
    * to int if they will fit. These integer variables here need only
    * hold values less than 255 so they will always fit into an int.
    *
    * Most of values stored are never negative, so one might think
    * that unsigned int would be more correct than int. However the C
    * integer promotion rules only promote to unsigned int if the
    * result won't fit into an int even if the promotion is for an
    * unsigned variable like uint8_t.
    *
    * By declaring these int, there are few implicit conversions and
    * fewer casts needed. Code size is reduced a little. It makes
    * static analyzers happier.
    *
    * Note also that declaring these uint8_t won't stop integer wrap
    * around if the code is wrong. It won't make the code more
    * correct.
    *
    * https://stackoverflow.com/questions/46073295/implicit-type-promotion-rules
    * https://stackoverflow.com/questions/589575/what-does-the-c-standard-state-the-size-of-int-long-type-to-be
    *
    * Code Reviewers: THIS FUNCTION DOES POINTER MATH
    */

   /* The buffer must have room for the largest CBOR HEAD + one
    * extra. The one extra is needed for this code to work as it does
    * a pre-decrement.
    */
    if(Buffer.len < QCBOR_HEAD_BUFFER_SIZE) {
        return NULLUsefulBufC;
    }

   /* Pointer to last valid byte in the buffer */
   uint8_t * const pBufferEnd = &((uint8_t *)Buffer.ptr)[QCBOR_HEAD_BUFFER_SIZE-1];

   /* Point to the last byte and work backwards */
   uint8_t *pByte = pBufferEnd;
   /* The 5 bits in the initial byte that are not the major type */
   int nAdditionalInfo;

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   if(uMajorType > QCBOR_INDEFINITE_LEN_TYPE_MODIFIER) {
      /* Special case for start & end of indefinite length */
      uMajorType  = uMajorType - QCBOR_INDEFINITE_LEN_TYPE_MODIFIER;
      /* This takes advantage of design of CBOR where additional info
       * is 31 for both opening and closing indefinite length
       * maps and arrays.
       */
       #if CBOR_SIMPLE_BREAK != LEN_IS_INDEFINITE
       #error additional info for opening array not the same as for closing
       #endif
      nAdditionalInfo = CBOR_SIMPLE_BREAK;

   } else
#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
      if (uArgument < CBOR_TWENTY_FOUR && uMinLen == 0) {
      /* Simple case where argument is < 24 */
      nAdditionalInfo = (int)uArgument;

   } else  {
      /* This encodes the argument in 1,2,4 or 8 bytes. The outer loop
       * runs once for 1 byte and 4 times for 8 bytes.  The inner loop
       * runs 1, 2 or 4 times depending on outer loop counter. This
       * works backwards shifting 8 bits off the argument being
       * encoded at a time until all bits from uArgument have been
       * encoded and the minimum encoding size is reached.  Minimum
       * encoding size is for floating-point numbers that have some
       * zero-value bytes that must be output.
       */
      static const uint8_t aIterate[] = {1,1,2,4};

      /* uMinLen passed in is unsigned, but goes negative in the loop
       * so it must be converted to a signed value.
       */
      int nMinLen = (int)uMinLen;
      int i;
      for(i = 0; uArgument || nMinLen > 0; i++) {
         const int nIterations = (int)aIterate[i];
         for(int j = 0; j < nIterations; j++) {
            *--pByte = (uint8_t)(uArgument & 0xff);
            uArgument = uArgument >> 8;
         }
         nMinLen -= nIterations;
      }

      nAdditionalInfo = LEN_IS_ONE_BYTE-1 + i;
   }

   /* This expression integer-promotes to type int. The code above in
    * function guarantees that nAdditionalInfo will never be larger
    * than 0x1f. The caller may pass in a too-large uMajor type. The
    * conversion to uint8_t will cause an integer wrap around and
    * incorrect CBOR will be generated, but no security issue will
    * occur.
    */
   const int nInitialByte = (uMajorType << 5) + nAdditionalInfo;
   *--pByte = (uint8_t)nInitialByte;

#ifdef EXTRA_ENCODE_HEAD_CHECK
   /* This is a sanity check that can be turned on to verify the
    * pointer math in this function is not going wrong. Turn it on and
    * run the whole test suite to perform the check.
    */
   if(pBufferEnd - pByte > 9 || pBufferEnd - pByte < 1 || pByte < (uint8_t *)buffer.ptr) {
      return NULLUsefulBufC;
   }
#endif /* EXTRA_ENCODE_HEAD_CHECK */

   /* Length will not go negative because the loops run for at most 8 decrements
    * of pByte, only one other decrement is made, and the array is sized
    * for this.
    */
   return (UsefulBufC){pByte, (size_t)(pBufferEnd - pByte)};
}


/**
 * @brief Increment item counter for maps and arrays.
 *
 * @param pMe          QCBOR encoding context.
 *
 * This is mostly a separate function to make code more readable and
 * to have fewer occurrences of #ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
 */
static void
QCBOREncode_Private_IncrementMapOrArrayCount(QCBOREncodeContext *pMe)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(pMe->uError == QCBOR_SUCCESS) {
      pMe->uError = Nesting_Increment(&(pMe->nesting));
   }
#else
   (void)Nesting_Increment(&(pMe->nesting));
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */
}


/**
 * @brief Append the CBOR head, the major type and argument
 *
 * @param pMe         Encoder context.
 * @param uMajorType  Major type to insert.
 * @param uArgument   The argument (an integer value or a length).
 * @param uMinLen     Minimum number of bytes for encoding the CBOR argument.
 *
 * This formats the CBOR "head" and appends it to the output.
 *
 * This also increments the array/map item counter in most cases.
 */
void
QCBOREncode_Private_AppendCBORHead(QCBOREncodeContext *pMe,
                                   const uint8_t       uMajorType,
                                   const uint64_t      uArgument,
                                   const uint8_t       uMinLen)
{
   /* A stack buffer large enough for a CBOR head */
   UsefulBuf_MAKE_STACK_UB  (pBufferForEncodedHead, QCBOR_HEAD_BUFFER_SIZE);

   UsefulBufC EncodedHead = QCBOREncode_EncodeHead(pBufferForEncodedHead,
                                                    uMajorType,
                                                    uMinLen,
                                                    uArgument);

   /* No check for EncodedHead == NULLUsefulBufC is performed here to
    * save object code. It is very clear that pBufferForEncodedHead is
    * the correct size. If EncodedHead == NULLUsefulBufC then
    * UsefulOutBuf_AppendUsefulBuf() will do nothing so there is no
    * security hole introduced.
    */

   UsefulOutBuf_AppendUsefulBuf(&(pMe->OutBuf), EncodedHead);

   if(!(uMajorType & QCBOR_INDEFINITE_LEN_TYPE_MODIFIER || uMajorType == CBOR_MAJOR_TYPE_TAG)) {
      /* Don't increment the map count for tag or break because that is
       * not needed. Don't do it for indefinite-length arrays and maps
       * because it is done elsewhere. This is never called for definite-length
       * arrays and maps.
       */
      QCBOREncode_Private_IncrementMapOrArrayCount(pMe);
   }
}


/*
 * Public function for adding signed integers. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_AddInt64(QCBOREncodeContext *pMe, const int64_t nNum)
{
   uint8_t  uMajorType;
   uint64_t uValue;

   if(nNum < 0) {
      /* In CBOR -1 encodes as 0x00 with major type negative int.
       * First add one as a signed integer because that will not
       * overflow. Then change the sign as needed for encoding (the
       * opposite order, changing the sign and subtracting, can cause
       * an overflow when encoding INT64_MIN). */
      int64_t nTmp = nNum + 1;
      uValue = (uint64_t)-nTmp;
      uMajorType = CBOR_MAJOR_TYPE_NEGATIVE_INT;
   } else {
      uValue = (uint64_t)nNum;
      uMajorType = CBOR_MAJOR_TYPE_POSITIVE_INT;
   }
   QCBOREncode_Private_AppendCBORHead(pMe, uMajorType, uValue, 0);
}


/**
 * @brief Semi-private method to add a buffer full of bytes to encoded output.
 *
 * @param[in] pMe       The encoding context to add the string to.
 * @param[in] uMajorType The CBOR major type of the bytes.
 * @param[in] Bytes      The bytes to add.
 *
 * Called by inline functions to add text and byte strings.
 *
 * (This used to support QCBOREncode_AddEncoded() and
 * QCBOREncode_AddBytesLenOnly(), but that was pulled out to make this
 * smaller. This is one of the most used methods and they are some of
 * the least used).
 */
void
QCBOREncode_Private_AddBuffer(QCBOREncodeContext *pMe,
                              const uint8_t       uMajorType,
                              const UsefulBufC    Bytes)
{
   QCBOREncode_Private_AppendCBORHead(pMe, uMajorType, Bytes.len, 0);
   UsefulOutBuf_AppendUsefulBuf(&(pMe->OutBuf), Bytes);
}


/*
 * Public function for adding raw encoded CBOR. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_AddEncoded(QCBOREncodeContext *pMe, const UsefulBufC Encoded)
{
   UsefulOutBuf_AppendUsefulBuf(&(pMe->OutBuf), Encoded);
   QCBOREncode_Private_IncrementMapOrArrayCount(pMe);
}


#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
/**
 * @brief Semi-private method to add a double using preferred encoding.
 *
 * @param[in] pMe   The encode context.
 * @param[in] dNum  The double to add.
 *
 * This converts the double to a float or half-precision if it can be done
 * without a loss of precision. See QCBOREncode_AddDouble().
 */
void
QCBOREncode_Private_AddPreferredDouble(QCBOREncodeContext *pMe, double dNum)
{
   IEEE754_union        FloatResult;
   bool                 bNoNaNPayload;
   struct IEEE754_ToInt IntResult;
   uint64_t             uNegValue;

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(IEEE754_DoubleHasNaNPayload(dNum) && !(pMe->uAllow & QCBOR_ENCODE_ALLOW_NAN_PAYLOAD)) {
      pMe->uError = QCBOR_ERR_NOT_ALLOWED;
      return;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   if(pMe->uMode == QCBOR_ENCODE_MODE_DCBOR) {
      IntResult = IEEE754_DoubleToInt(dNum);
      switch(IntResult.type) {
         case IEEE754_ToInt_IS_INT:
            QCBOREncode_AddInt64(pMe, IntResult.integer.is_signed);
            return;
         case IEEE754_ToInt_IS_UINT:
            QCBOREncode_AddUInt64(pMe, IntResult.integer.un_signed);
            return;
         case IEEE754_ToInt_IS_65BIT_NEG:
            {
               if(IntResult.integer.un_signed == 0) {
                  uNegValue = UINT64_MAX;
               } else {
                  uNegValue = IntResult.integer.un_signed-1;
               }
               QCBOREncode_AddNegativeUInt64(pMe, uNegValue);
            }
            return;
         case IEEE754_ToInt_NaN:
            dNum = NAN;
            bNoNaNPayload = true;
            break;
         case IEEE754_ToInt_NO_CONVERSION:
            bNoNaNPayload = true;
      }
   } else  {
      bNoNaNPayload = false;
   }

   FloatResult = IEEE754_DoubleToSmaller(dNum, true, bNoNaNPayload);

   QCBOREncode_Private_AddType7(pMe, (uint8_t)FloatResult.uSize, FloatResult.uValue);
}


/**
 * @brief Semi-private method to add a float using preferred encoding.
 *
 * @param[in] pMe   The encode context.
 * @param[in] fNum  The float to add.
 *
 * This converts the float to a half-precision if it can be done
 * without a loss of precision. See QCBOREncode_AddFloat().
 */
void
QCBOREncode_Private_AddPreferredFloat(QCBOREncodeContext *pMe, float fNum)
{
   IEEE754_union        FloatResult;
   bool                 bNoNaNPayload;
   struct IEEE754_ToInt IntResult;
   uint64_t             uNegValue;

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(IEEE754_SingleHasNaNPayload(fNum) && !(pMe->uAllow & QCBOR_ENCODE_ALLOW_NAN_PAYLOAD)) {
      pMe->uError = QCBOR_ERR_NOT_ALLOWED;
      return;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   if(pMe->uMode == QCBOR_ENCODE_MODE_DCBOR) {
      IntResult = IEEE754_SingleToInt(fNum);
      switch(IntResult.type) {
         case IEEE754_ToInt_IS_INT:
            QCBOREncode_AddInt64(pMe, IntResult.integer.is_signed);
            return;
         case IEEE754_ToInt_IS_UINT:
            QCBOREncode_AddUInt64(pMe, IntResult.integer.un_signed);
            return;
         case IEEE754_ToInt_IS_65BIT_NEG:
            {
               if(IntResult.integer.un_signed == 0) {
                  uNegValue = UINT64_MAX;
               } else {
                  uNegValue = IntResult.integer.un_signed-1;
               }
               QCBOREncode_AddNegativeUInt64(pMe, uNegValue);
            }
            return;
         case IEEE754_ToInt_NaN:
            fNum = NAN;
            bNoNaNPayload = true;
            break;
         case IEEE754_ToInt_NO_CONVERSION:
            bNoNaNPayload = true;
      }
   } else  {
      bNoNaNPayload = false;
   }

   FloatResult = IEEE754_SingleToHalf(fNum, bNoNaNPayload);

   QCBOREncode_Private_AddType7(pMe, (uint8_t)FloatResult.uSize, FloatResult.uValue);
}
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */




/**
 * @brief Convert a big number to unsigned integer.
 *
 * @param[in]  BigNumber  Big number to convert.
 *
 * @return Converted unsigned.
 *
 * The big number must be less than 8 bytes long.
 **/
static uint64_t
QCBOREncode_Private_BigNumberToUInt(const UsefulBufC BigNumber)
{
   uint64_t uInt;
   size_t   uIndex;

   uInt = 0;
   for(uIndex = 0; uIndex < BigNumber.len; uIndex++) {
      uInt = (uInt << 8) + UsefulBufC_NTH_BYTE(BigNumber, uIndex);
   }

   return uInt;
}


/**
 * @brief Is there a carry when you subtract 1 from the BigNumber.
 *
 * @param[in]  BigNumber  Big number to check for carry.
 *
 * @return If there is a carry, \c true.
 *
 * If this returns @c true, then @c BigNumber - 1 is
 * one byte shorter than @c BigNumber.
 **/
static bool
QCBOREncode_Private_BigNumberCarry(const UsefulBufC BigNumber)
{
   bool       bCarry;
   UsefulBufC SubBigNum;

   // Improvement: rework without recursion?

   if(BigNumber.len == 0) {
      return true; /* Subtracting one from zero-length string gives a carry */
   } else {
      SubBigNum = UsefulBuf_Tail(BigNumber, 1);
      bCarry = QCBOREncode_Private_BigNumberCarry(SubBigNum);
      if(UsefulBufC_NTH_BYTE(BigNumber, 0) == 0x00 && bCarry) {
         /* Subtracting one from 0 gives a carry */
         return true;
      } else {
         return false;
      }
   }
}


/*
 * @brief Output negative bignum bytes with subtraction of 1.
 *
 * @param[in] pMe              The decode context.
 * @param[in] uTagRequirement  Either @ref QCBOR_ENCODE_AS_TAG or
 *                             @ref QCBOR_ENCODE_AS_BORROWED.
 * @param[in] BigNumber        The negative big number.
 */
static void
QCBOREncode_Private_AddTNegativeBigNumber(QCBOREncodeContext *pMe,
                                          const uint8_t       uTagRequirement,
                                          const UsefulBufC    BigNumber)
{
   size_t     uLen;
   bool       bCarry;
   bool       bCopiedSomething;
   uint8_t    uByte;
   UsefulBufC SubString;
   UsefulBufC NextSubString;

   QCBOREncode_Private_BigNumberTag(pMe, uTagRequirement, true);

   /* This works on any length without the need of an additional buffer */

   /* This subtracts one, possibly making the string shorter by one
    * 0x01 -> 0x00
    * 0x01 0x00 -> 0xff
    * 0x00 0x01 0x00 -> 0x00 0xff
    * 0x02 0x00 -> 0x01 0xff
    * 0xff -> 0xfe
    * 0xff 0x00 -> 0xfe 0xff
    * 0x01 0x00 0x00 -> 0xff 0xff
    *
    * This outputs the big number a byte at a time to be able to operate on
    * a big number of any length without memory allocation.
    */

   /* Compute the length up front because it goes in the encoded head */
   bCarry = QCBOREncode_Private_BigNumberCarry(UsefulBuf_Tail(BigNumber, 1));
   uLen = BigNumber.len;
   if(bCarry && BigNumber.len > 1 && UsefulBufC_NTH_BYTE(BigNumber, 0) >= 1) {
      uLen--;
   }
   QCBOREncode_Private_AppendCBORHead(pMe, CBOR_MAJOR_TYPE_BYTE_STRING, uLen, 0);

   SubString = BigNumber;
   bCopiedSomething = false;
   while(SubString.len) {
      uByte = UsefulBufC_NTH_BYTE(SubString, 0);
      NextSubString = UsefulBuf_Tail(SubString, 1);
      bCarry = QCBOREncode_Private_BigNumberCarry(NextSubString);
      if(bCarry) {
         uByte--;
      }
      /* This avoids all but the last leading zero. See
       * QCBOREncode_Private_SkipLeadingZeros() */
      if(bCopiedSomething || NextSubString.len == 0 || uByte != 0) {
         UsefulOutBuf_AppendByte(&(pMe->OutBuf), uByte);
         bCopiedSomething = true;
      }
      SubString = NextSubString;
   }
}


/**
 * @brief Convert a negative big number to unsigned int if possible.
 *
 * @param[in] BigNumber  The negative big number.
 * @param[out] puInt     The converted negative big number.
 *
 * @return If conversion was possible, returns @c true.
 *
 * The parameters here are unsigned integers, but they always
 * represent negative numbers.
 *
 * Conversion is possible if the big number is greater than -(2^64).
 * Conversion include offset of 1 for encoding CBOR negative numbers.
 */
static bool
QCBOREncode_Private_NegativeBigNumberToUInt(const UsefulBufC BigNumber, uint64_t *puInt)
{
   bool bIs2exp64;

   static const uint8_t twoExp64[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

   bIs2exp64 = ! UsefulBuf_Compare(BigNumber, UsefulBuf_FROM_BYTE_ARRAY_LITERAL(twoExp64));

   if(BigNumber.len > 8 && !bIs2exp64) {
      return false;
   }

   /* Must convert to CBOR type 1, a negative integer */
   if(bIs2exp64) {
      /* 2^64 is a 9 byte big number. Since negative numbers are offset
       * by one in CBOR, it can be encoded as a type 1 negative. The
       * conversion below won't work because the uInt will overflow
       * before the subtraction of 1.
       */
      *puInt = UINT64_MAX;
   } else {
      *puInt = QCBOREncode_Private_BigNumberToUInt(BigNumber);
      (*puInt)--; /* CBOR's negative offset of 1 */
   }
   return true;
}


/**
 * @brief Remove leading zeros.
 *
 * @param[in] BigNumber  The negative big number.
 *
 * @return Big number with no leading zeros.
 *
 * If the big number is all zeros, this returns a big number
 * that is one zero rather than the empty string.
 *
 * 3.4.3 does not explicitly decoders MUST handle the empty string,
 * but does say decoders MUST handle leading zeros. So Postel's Law
 * is applied here and 0 is not encoded as an empty string.
 */
static UsefulBufC
QCBOREncode_Private_SkipLeadingZeros(const UsefulBufC BigNumber)
{
   UsefulBufC NLZ;
   NLZ = UsefulBuf_SkipLeading(BigNumber, 0x00);

   /* An all-zero string reduces to one 0, not an empty string. */
   if(NLZ.len == 0 && BigNumber.len > 0 && UsefulBufC_NTH_BYTE(BigNumber, 0) == 0x00) {
      NLZ.len++;
   }

   return NLZ;
}


/*
 * Public functions for adding a big number. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_AddTBigNumber(QCBOREncodeContext *pMe,
                          const uint8_t       uTagRequirement,
                          const bool          bNegative,
                          const UsefulBufC    BigNumber)
{
   uint64_t uInt;

   const UsefulBufC BigNumberNLZ = QCBOREncode_Private_SkipLeadingZeros(BigNumber);

   /* Preferred serialization requires reduction to type 0 and 1 integers */
   if(bNegative) {
      if(QCBOREncode_Private_NegativeBigNumberToUInt(BigNumberNLZ, &uInt)) {
         /* Might be a 65-bit negative; use special add method for such */
         QCBOREncode_AddNegativeUInt64(pMe, uInt);
      } else {
         QCBOREncode_Private_AddTNegativeBigNumber(pMe, uTagRequirement, BigNumberNLZ);
      }

   } else {
      if(BigNumberNLZ.len <= sizeof(uint64_t)) {
         QCBOREncode_AddUInt64(pMe, QCBOREncode_Private_BigNumberToUInt(BigNumberNLZ));
      } else {
         QCBOREncode_AddTBigNumberRaw(pMe, bNegative, uTagRequirement, BigNumberNLZ);
      }
   }
}


/*
 * Public functions for adding a big number. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_AddTBigNumberNoPreferred(QCBOREncodeContext *pMe,
                                     const uint8_t       uTagRequirement,
                                     const bool          bNegative,
                                     const UsefulBufC    BigNumber)
{
   const UsefulBufC BigNumberNLZ = QCBOREncode_Private_SkipLeadingZeros(BigNumber);

   if(bNegative) {
      QCBOREncode_Private_AddTNegativeBigNumber(pMe, uTagRequirement, BigNumberNLZ);
   } else {
      QCBOREncode_AddTBigNumberRaw(pMe, false, uTagRequirement, BigNumberNLZ);
   }
}


#ifndef QCBOR_DISABLE_EXP_AND_MANTISSA
/**
 * @brief  Semi-private method to add bigfloats and decimal fractions.
 *
 * @param[in] pMe               The encoding context to add the value to.
 * @param[in] uTagNumber               The type 6 tag indicating what this is to be.
 * @param[in] nMantissa          The @c int64_t mantissa if it is not a big number.
 * @param[in] nExponent          The exponent.
 *
 * This outputs either the @ref CBOR_TAG_DECIMAL_FRACTION or
 * @ref CBOR_TAG_BIGFLOAT tag. if @c uTag is @ref CBOR_TAG_INVALID64,
 * then this outputs the "borrowed" content format.
 *
 * The tag content output by this is an array with two members, the
 * exponent and then the mantissa. The mantissa can be either a big
 * number or an @c int64_t.
 *
 * This implementation cannot output an exponent further from 0 than
 * @c INT64_MAX.
 *
 * To output a mantissa that is between INT64_MAX and UINT64_MAX from 0,
 * it must be as a big number.
 *
 * Typically, QCBOREncode_AddDecimalFraction(), QCBOREncode_AddBigFloat(),
 * QCBOREncode_AddDecimalFractionBigNum() or QCBOREncode_AddBigFloatBigNum()
 * is called instead of this.
 */
void
QCBOREncode_Private_AddTExpIntMantissa(QCBOREncodeContext *pMe,
                                       const int           uTagRequirement,
                                       const uint64_t      uTagNumber,
                                       const int64_t       nExponent,
                                       const int64_t       nMantissa)
{
   /* This is for encoding either a big float or a decimal fraction,
    * both of which are an array of two items, an exponent and a
    * mantissa.  The difference between the two is that the exponent
    * is base-2 for big floats and base-10 for decimal fractions, but
    * that has no effect on the code here.
    */
   /* Separate from QCBOREncode_Private_AddTExpBigMantissa() because
    * linking QCBOREncode_AddTBigNumber() adds a lot because it
    * does preferred serialization of big numbers and the offset of 1
    * for CBOR negative numbers.
    */
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTagNumber(pMe, uTagNumber);
   }
   QCBOREncode_OpenArray(pMe);
   QCBOREncode_AddInt64(pMe, nExponent);
   QCBOREncode_AddInt64(pMe, nMantissa);
   QCBOREncode_CloseArray(pMe);
}

void
QCBOREncode_Private_AddTExpBigMantissa(QCBOREncodeContext *pMe,
                                       const int           uTagRequirement,
                                       const uint64_t      uTagNumber,
                                       const int64_t       nExponent,
                                       const UsefulBufC    BigNumMantissa,
                                       const bool          bBigNumIsNegative)
{
   /* This is for encoding either a big float or a decimal fraction,
    * both of which are an array of two items, an exponent and a
    * mantissa.  The difference between the two is that the exponent
    * is base-2 for big floats and base-10 for decimal fractions, but
    * that has no effect on the code here.
    */
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, uTagNumber);
   }
   QCBOREncode_OpenArray(pMe);
   QCBOREncode_AddInt64(pMe, nExponent);
   QCBOREncode_AddTBigNumber(pMe, QCBOR_ENCODE_AS_TAG, bBigNumIsNegative, BigNumMantissa);
   QCBOREncode_CloseArray(pMe);
}


void
QCBOREncode_Private_AddTExpBigMantissaRaw(QCBOREncodeContext *pMe,
                                          const int           uTagRequirement,
                                          const uint64_t      uTagNumber,
                                          const int64_t       nExponent,
                                          const UsefulBufC    BigNumMantissa,
                                          const bool          bBigNumIsNegative)
{
   /* This is for encoding either a big float or a decimal fraction,
    * both of which are an array of two items, an exponent and a
    * mantissa.  The difference between the two is that the exponent
    * is base-2 for big floats and base-10 for decimal fractions, but
    * that has no effect on the code here.
    */
   /* Separate from QCBOREncode_Private_AddTExpBigMantissa() because
    * linking QCBOREncode_AddTBigNumber() adds a lot because it
    * does preferred serialization of big numbers and the offset of 1
    * for CBOR negative numbers.
    */
   if(uTagRequirement == QCBOR_ENCODE_AS_TAG) {
      QCBOREncode_AddTag(pMe, uTagNumber);
   }
   QCBOREncode_OpenArray(pMe);
   QCBOREncode_AddInt64(pMe, nExponent);
   QCBOREncode_AddTBigNumberRaw(pMe, QCBOR_ENCODE_AS_TAG, bBigNumIsNegative, BigNumMantissa);
   QCBOREncode_CloseArray(pMe);
}

#endif /* ! QCBOR_DISABLE_EXP_AND_MANTISSA */


/**
 * @brief Semi-private method to open a map, array or bstr-wrapped CBOR
 *
 * @param[in] pMe        The context to add to.
 * @param[in] uMajorType  The major CBOR type to close
 *
 * Call QCBOREncode_OpenArray(), QCBOREncode_OpenMap() or
 * QCBOREncode_BstrWrap() instead of this.
 */
void
QCBOREncode_Private_OpenMapOrArray(QCBOREncodeContext *pMe,
                                   const uint8_t       uMajorType)
{
   /* Add one item to the nesting level we are in for the new map or array */
   QCBOREncode_Private_IncrementMapOrArrayCount(pMe);

   /* The offset where the length of an array or map will get written
    * is stored in a uint32_t, not a size_t to keep stack usage
    * smaller. This checks to be sure there is no wrap around when
    * recording the offset.  Note that on 64-bit machines CBOR larger
    * than 4GB can be encoded as long as no array/map offsets occur
    * past the 4GB mark, but the public interface says that the
    * maximum is 4GB to keep the discussion simpler.
    */
   size_t uEndPosition = UsefulOutBuf_GetEndPosition(&(pMe->OutBuf));

   /* QCBOR_MAX_ARRAY_OFFSET is slightly less than UINT32_MAX so this
    * code can run on a 32-bit machine and tests can pass on a 32-bit
    * machine. If it was exactly UINT32_MAX, then this code would not
    * compile or run on a 32-bit machine and an #ifdef or some machine
    * size detection would be needed reducing portability.
    */
   if(uEndPosition >= QCBOR_MAX_ARRAY_OFFSET) {
      pMe->uError = QCBOR_ERR_BUFFER_TOO_LARGE;

   } else {
      /* Increase nesting level because this is a map or array.  Cast
       * from size_t to uin32_t is safe because of check above.
       */
      pMe->uError = Nesting_Increase(&(pMe->nesting), uMajorType, (uint32_t)uEndPosition);
   }
}


#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
/**
 * @brief Semi-private method to open a map, array with indefinite length
 *
 * @param[in] pMe        The context to add to.
 * @param[in] uMajorType  The major CBOR type to close
 *
 * Call QCBOREncode_OpenArrayIndefiniteLength() or
 * QCBOREncode_OpenMapIndefiniteLength() instead of this.
 */
void
QCBOREncode_Private_OpenMapOrArrayIndefiniteLength(QCBOREncodeContext *pMe,
                                                   const uint8_t       uMajorType)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(pMe->uMode >= QCBOR_ENCODE_MODE_PREFERRED) {
      pMe->uError = QCBOR_ERR_NOT_PREFERRED;
      return;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */
   /* Insert the indefinite length marker (0x9f for arrays, 0xbf for maps) */
   QCBOREncode_Private_AppendCBORHead(pMe, uMajorType, 0, 0);

   /* Call the definite-length opener just to do the bookkeeping for
    * nesting.  It will record the position of the opening item in the
    * encoded output but this is not used when closing this open.
    */
   QCBOREncode_Private_OpenMapOrArray(pMe, uMajorType);
}
#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */


/**
 * @brief Check for errors when decreasing nesting.
 *
 * @param pMe          QCBOR encoding context.
 * @param uMajorType  The major type of the nesting.
 *
 * Check that there is no previous error, that there is actually some
 * nesting and that the major type of the opening of the nesting
 * matches the major type of the nesting being closed.
 *
 * This is called when closing maps, arrays, byte string wrapping and
 * open/close of byte strings.
 */
static bool
QCBOREncode_Private_CheckDecreaseNesting(QCBOREncodeContext *pMe,
                                         const uint8_t       uMajorType)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(pMe->uError != QCBOR_SUCCESS) {
      return true;
   }

   if(!Nesting_IsInNest(&(pMe->nesting))) {
      pMe->uError = QCBOR_ERR_TOO_MANY_CLOSES;
      return true;
   }

   if(Nesting_GetMajorType(&(pMe->nesting)) != uMajorType) {
      pMe->uError = QCBOR_ERR_CLOSE_MISMATCH;
      return true;
   }

#else /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */
   /* None of these checks are performed if the encode guards are
    * turned off as they all relate to correct calling.
    *
    * Turning off all these checks does not turn off any checking for
    * buffer overflows or pointer issues.
    */

   (void)uMajorType;
   (void)pMe;
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   return false;
}


/**
 * @brief Insert the CBOR head for a map, array or wrapped bstr.
 *
 * @param pMe         QCBOR encoding context.
 * @param uMajorType  One of CBOR_MAJOR_TYPE_XXXX.
 * @param uLen        The length of the data item.
 *
 * When an array, map or bstr was opened, nothing was done but note
 * the position. This function goes back to that position and inserts
 * the CBOR Head with the major type and length.
 */
static void
QCBOREncode_Private_CloseAggregate(QCBOREncodeContext *pMe,
                                   uint8_t             uMajorType,
                                   size_t              uLen)
{
   if(QCBOREncode_Private_CheckDecreaseNesting(pMe, uMajorType)) {
      return;
   }

   if(uMajorType == CBOR_MAJOR_NONE_TYPE_OPEN_BSTR) {
      uMajorType = CBOR_MAJOR_TYPE_BYTE_STRING;
   }

   /* A stack buffer large enough for a CBOR head (9 bytes) */
   UsefulBuf_MAKE_STACK_UB(pBufferForEncodedHead, QCBOR_HEAD_BUFFER_SIZE);

   UsefulBufC EncodedHead = QCBOREncode_EncodeHead(pBufferForEncodedHead,
                                                   uMajorType,
                                                   0,
                                                   uLen);

   /* No check for EncodedHead == NULLUsefulBufC is performed here to
    * save object code. It is very clear that pBufferForEncodedHead is
    * the correct size. If EncodedHead == NULLUsefulBufC then
    * UsefulOutBuf_InsertUsefulBuf() will do nothing so there is no
    * security hole introduced.
    */
   UsefulOutBuf_InsertUsefulBuf(&(pMe->OutBuf),
                                EncodedHead,
                                Nesting_GetStartPos(&(pMe->nesting)));

   Nesting_Decrease(&(pMe->nesting));
}


/**
 * @brief Semi-private method to close a map, array or bstr wrapped CBOR.
 *
 * @param[in] pMe           The context to add to.
 * @param[in] uMajorType     The major CBOR type to close.
 */
void
QCBOREncode_Private_CloseMapOrArray(QCBOREncodeContext *pMe,
                                    const uint8_t       uMajorType)
{
   QCBOREncode_Private_CloseAggregate(pMe, uMajorType, Nesting_GetCount(&(pMe->nesting)));
}


/**
 * @brief Private method to close a map without sorting.
 *
 * @param[in] pMe     The encode context with map to close.
 *
 * See QCBOREncode_SerializationCDE() implemention for explantion for why
 * this exists in this form.
 */
static void
QCBOREncode_Private_CloseMapUnsorted(QCBOREncodeContext *pMe)
{
   QCBOREncode_Private_CloseMapOrArray(pMe, CBOR_MAJOR_TYPE_MAP);
}


/**
 * @brief Decode a CBOR item head.
 *
 * @param[in]   pUInBuf           UsefulInputBuf to read from.
 * @param[out]  pnMajorType       Major type of decoded head.
 * @param[out]  puArgument        Argument of decoded head.
 * @param[out]  pnAdditionalInfo  Additional info from decoded head.
 *
 * @return SUCCESS if a head was decoded
 *         HIT_END if there were not enough bytes to decode a head
 *         UNSUPPORTED if the decoded item is not one that is supported
 *
 * This is copied from qcbor_decode.c rather than referenced.  This
 * makes the core decoder 60 bytes smaller because it gets inlined.
 * It would not get inlined if it was referenced. It is important to
 * make the core decoder as small as possible. The copy here does make
 * map sorting 200 bytes bigger, but map sorting is rarely used in
 * environments that need small object code. It would also make
 * qcbor_encode.c depend on qcbor_decode.c
 *
 * This is also super stable and tested. It implements the very
 * well-defined part of CBOR that will never change.  So this won't
 * change.
 */
static QCBORError
QCBOREncodePriv_DecodeHead(UsefulInputBuf *pUInBuf,
                           int            *pnMajorType,
                           uint64_t       *puArgument,
                           int            *pnAdditionalInfo)
{
   QCBORError uReturn;

   /* Get the initial byte that every CBOR data item has and break it
    * down. */
   const int nInitialByte    = (int)UsefulInputBuf_GetByte(pUInBuf);
   const int nTmpMajorType   = nInitialByte >> 5;
   const int nAdditionalInfo = nInitialByte & 0x1f;

   /* Where the argument accumulates */
   uint64_t uArgument;

   if(nAdditionalInfo >= LEN_IS_ONE_BYTE && nAdditionalInfo <= LEN_IS_EIGHT_BYTES) {
      /* Need to get 1,2,4 or 8 additional argument bytes. Map
       * LEN_IS_ONE_BYTE..LEN_IS_EIGHT_BYTES to actual length.
       */
      static const uint8_t aIterate[] = {1,2,4,8};

      /* Loop getting all the bytes in the argument */
      uArgument = 0;
      for(int i = aIterate[nAdditionalInfo - LEN_IS_ONE_BYTE]; i; i--) {
         /* This shift and add gives the endian conversion. */
         uArgument = (uArgument << 8) + UsefulInputBuf_GetByte(pUInBuf);
      }
   } else if(nAdditionalInfo >= ADDINFO_RESERVED1 && nAdditionalInfo <= ADDINFO_RESERVED3) {
      /* The reserved and thus-far unused additional info values */
      uReturn = QCBOR_ERR_UNSUPPORTED;
      goto Done;
   } else {
      /* Less than 24, additional info is argument or 31, an
       * indefinite-length.  No more bytes to get.
       */
      uArgument = (uint64_t)nAdditionalInfo;
   }

   if(UsefulInputBuf_GetError(pUInBuf)) {
      uReturn = QCBOR_ERR_HIT_END;
      goto Done;
   }

   /* All successful if arrived here. */
   uReturn           = QCBOR_SUCCESS;
   *pnMajorType      = nTmpMajorType;
   *puArgument       = uArgument;
   *pnAdditionalInfo = nAdditionalInfo;

Done:
   return uReturn;
}


/**
 * @brief Consume the next item from a UsefulInputBuf.
 *
 * @param[in] pInBuf  UsefulInputBuf from which to consume item.
 *
 * Recursive, but stack usage is light and encoding depth limit
 */
static QCBORError
QCBOR_Private_ConsumeNext(UsefulInputBuf *pInBuf)
{
   int      nMajor;
   uint64_t uArgument;
   int      nAdditional;
   uint16_t uItemCount;
   uint16_t uMul;
   uint16_t i;
   QCBORError uCBORError;

   uCBORError = QCBOREncodePriv_DecodeHead(pInBuf, &nMajor, &uArgument, &nAdditional);
   if(uCBORError != QCBOR_SUCCESS) {
      return uCBORError;
   }

   uMul = 1;

   switch(nMajor) {
      case CBOR_MAJOR_TYPE_POSITIVE_INT: /* Major type 0 */
      case CBOR_MAJOR_TYPE_NEGATIVE_INT: /* Major type 1 */
         break;

      case CBOR_MAJOR_TYPE_SIMPLE:
         return uArgument == CBOR_SIMPLE_BREAK ? 1 : 0;
         break;

      case CBOR_MAJOR_TYPE_BYTE_STRING:
      case CBOR_MAJOR_TYPE_TEXT_STRING:
         if(nAdditional == LEN_IS_INDEFINITE) {
            /* Segments of indefinite length */
            while(QCBOR_Private_ConsumeNext(pInBuf) == 0);
         }
         (void)UsefulInputBuf_GetBytes(pInBuf, uArgument);
         break;

      case CBOR_MAJOR_TYPE_TAG:
         QCBOR_Private_ConsumeNext(pInBuf);
         break;

      case CBOR_MAJOR_TYPE_MAP:
         uMul = 2;
         /* Fallthrough */
      case CBOR_MAJOR_TYPE_ARRAY:
         uItemCount = (uint16_t)uArgument * uMul;
         if(nAdditional == LEN_IS_INDEFINITE) {
            uItemCount = UINT16_MAX;
         }
         for(i = uItemCount; i > 0; i--) {
            if(QCBOR_Private_ConsumeNext(pInBuf)) {
               /* End of indefinite length */
               break;
            }
         }
         break;
   }

   return QCBOR_SUCCESS;
}


/**
 * @brief  Decoded next item to get its lengths.
 *
 * Decode the next item in map no matter what type it is. It works
 * recursively when an item is a map or array It returns offset just
 * past the item decoded or zero there are no more items in the output
 * buffer.
 *
 * This doesn't distinguish between end of the input and an error
 * because it is used to decode stuff we encoded into a buffer, not
 * stuff that came in from outside. We still want a check for safety
 * in case of bugs here, but it is OK to report end of input on error.
 */
struct ItemLens {
   uint32_t  uLabelLen;
   uint32_t  uItemLen;
};

static struct ItemLens
QCBOREncode_Private_DecodeNextInMap(QCBOREncodeContext *pMe, uint32_t uStart)
{
   UsefulInputBuf  InBuf;
   UsefulBufC      EncodedMapBytes;
   QCBORError      uCBORError;
   struct ItemLens Result;

   Result.uLabelLen = 0;
   Result.uItemLen  = 0;

   EncodedMapBytes = UsefulOutBuf_OutUBufOffset(&(pMe->OutBuf), uStart);
   if(UsefulBuf_IsNULLC(EncodedMapBytes)) {
      return Result;
   }

   UsefulInputBuf_Init(&InBuf, EncodedMapBytes);

   /* This is always used on maps, so consume two, the label and the value */
   uCBORError = QCBOR_Private_ConsumeNext(&InBuf);
   if(uCBORError) {
      return Result;
   }

   /* Cast is safe because this is QCBOR which limits sizes to UINT32_MAX */
   Result.uLabelLen = (uint32_t)UsefulInputBuf_Tell(&InBuf);

   uCBORError = QCBOR_Private_ConsumeNext(&InBuf);
   if(uCBORError) {
      Result.uLabelLen = 0;
      return Result;
   }

   Result.uItemLen = (uint32_t)UsefulInputBuf_Tell(&InBuf);

   /* Cast is safe because this is QCBOR which limits sizes to UINT32_MAX */
   return Result;
}


/**
 * @brief Sort items lexographically by encoded labels.
 *
 * @param[in] pMe     Encoding context.
 * @param[in] uStart  Offset in outbuf of first item for sorting.
 *
 * This reaches into the UsefulOutBuf in the encoding context and
 * sorts encoded CBOR items. The byte offset start of the items is at
 * @c uStart and it goes to the end of valid bytes in the
 * UsefulOutBuf.
 */
static void
QCBOREncode_Private_SortMap(QCBOREncodeContext *pMe, uint32_t uStart)
{
   bool            bSwapped;
   int             nComparison;
   uint32_t        uStart1;
   uint32_t        uStart2;
   struct ItemLens Lens1;
   struct ItemLens Lens2;


   if(pMe->uError != QCBOR_SUCCESS) {
      return;
   }

   /* Bubble sort because the sizes of all the items are not the
    * same. It works with adjacent pairs so the swap is not too
    * difficult even though sizes are different.
    *
    * While bubble sort is n-squared, it seems OK here because n will
    * usually be small and the comparison and swap functions aren't
    * too CPU intensive.
    *
    * Another approach would be to have an array of offsets to the
    * items. However this requires memory allocation and the swap
    * operation for quick sort or such is complicated because the item
    * sizes are not the same and overlap may occur in the bytes being
    * swapped.
    */
   do { /* Loop until nothing was swapped */
      Lens1 = QCBOREncode_Private_DecodeNextInMap(pMe, uStart);
      if(Lens1.uLabelLen == 0) {
         /* It's an empty map. Nothing to do. */
         break;
      }
      uStart1 = uStart;
      uStart2 = uStart1 + Lens1.uItemLen;
      bSwapped = false;

      while(1) {
         Lens2 = QCBOREncode_Private_DecodeNextInMap(pMe, uStart2);
         if(Lens2.uLabelLen == 0) {
            break;
         }

         nComparison = UsefulOutBuf_Compare(&(pMe->OutBuf),
                                            uStart1, Lens1.uLabelLen,
                                            uStart2, Lens2.uLabelLen);
         if(nComparison < 0) {
            UsefulOutBuf_Swap(&(pMe->OutBuf), uStart1, uStart2, uStart2 + Lens2.uItemLen);
            uStart1 = uStart1 + Lens2.uItemLen; /* item 2 now in position of item 1 */
            /* Lens1 is still valid as Lens1 for the next loop */
            bSwapped = true;
         } else if(nComparison > 0) {
            uStart1 = uStart2;
            Lens1   = Lens2;
         } else /* nComparison == 0 */ {
            pMe->uError = QCBOR_ERR_DUPLICATE_LABEL;
            return;
         }
         uStart2 = uStart2 + Lens2.uItemLen;
      }
   } while(bSwapped);
}


/*
 * Public functions for closing sorted maps. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_CloseAndSortMap(QCBOREncodeContext *pMe)
{
   uint32_t uStart;

   /* The Header for the map we are about to sort hasn't been
    * inserted yet, so uStart is the position of the first item
    * and the end out the UsefulOutBuf data is the end of the
    * items we are about to sort.
    */
   uStart = Nesting_GetStartPos(&(pMe->nesting));
   QCBOREncode_Private_SortMap(pMe, uStart);

   QCBOREncode_Private_CloseAggregate(pMe, CBOR_MAJOR_TYPE_MAP, Nesting_GetCount(&(pMe->nesting)));
}


#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
/*
 * Public functions for closing sorted maps. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_CloseAndSortMapIndef(QCBOREncodeContext *pMe)
{
   uint32_t uStart;

   uStart = Nesting_GetStartPos(&(pMe->nesting));
   QCBOREncode_Private_SortMap(pMe, uStart);

   QCBOREncode_Private_CloseMapOrArrayIndefiniteLength(pMe, CBOR_MAJOR_NONE_TYPE_MAP_INDEFINITE_LEN);
}
#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */


/*
 * Public function for closing bstr wrapping. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_CloseBstrWrap2(QCBOREncodeContext *pMe,
                           const bool          bIncludeCBORHead,
                           UsefulBufC         *pWrappedCBOR)
{
   const size_t uInsertPosition = Nesting_GetStartPos(&(pMe->nesting));
   const size_t uEndPosition    = UsefulOutBuf_GetEndPosition(&(pMe->OutBuf));

   /* This subtraction can't go negative because the UsefulOutBuf
    * always only grows and never shrinks. UsefulOutBut itself also
    * has defenses such that it won't write where it should not even
    * if given incorrect input lengths.
    */
   const size_t uBstrLen = uEndPosition - uInsertPosition;

   /* Actually insert */
   QCBOREncode_Private_CloseAggregate(pMe, CBOR_MAJOR_TYPE_BYTE_STRING, uBstrLen);

   if(pWrappedCBOR) {
      /* Return pointer and length to the enclosed encoded CBOR. The
       * intended use is for it to be hashed (e.g., SHA-256) in a COSE
       * implementation.  This must be used right away, as the pointer
       * and length go invalid on any subsequent calls to this
       * function because there might be calls to
       * InsertEncodedTypeAndNumber() that slides data to the right.
       */
      size_t uStartOfNew = uInsertPosition;
      if(!bIncludeCBORHead) {
         /* Skip over the CBOR head to just get the inserted bstr */
         const size_t uNewEndPosition = UsefulOutBuf_GetEndPosition(&(pMe->OutBuf));
         uStartOfNew += uNewEndPosition - uEndPosition;
      }
      const UsefulBufC PartialResult = UsefulOutBuf_OutUBuf(&(pMe->OutBuf));
      *pWrappedCBOR = UsefulBuf_Tail(PartialResult, uStartOfNew);
   }
}


/*
 * Public function for canceling a bstr wrap. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_CancelBstrWrap(QCBOREncodeContext *pMe)
{
   if(QCBOREncode_Private_CheckDecreaseNesting(pMe, CBOR_MAJOR_TYPE_BYTE_STRING)) {
      return;
   }

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   const size_t uCurrent = UsefulOutBuf_GetEndPosition(&(pMe->OutBuf));
   if(pMe->nesting.pCurrentNesting->uStart != uCurrent) {
      pMe->uError = QCBOR_ERR_CANNOT_CANCEL;
      return;
   }
   /* QCBOREncode_CancelBstrWrap() can't correctly undo
    * QCBOREncode_BstrWrapInMap() or QCBOREncode_BstrWrapInMapN(). It
    * can't undo the labels they add. It also doesn't catch the error
    * of using it this way.  QCBOREncode_CancelBstrWrap() is used
    * infrequently and the the result is incorrect CBOR, not a
    * security hole, so no extra code or state is added to handle this
    * condition.
    */
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   Nesting_Decrease(&(pMe->nesting));
   Nesting_Decrement(&(pMe->nesting));
}


/*
 * Public function for opening a byte string. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_OpenBytes(QCBOREncodeContext *pMe, UsefulBuf *pPlace)
{
   *pPlace = UsefulOutBuf_GetOutPlace(&(pMe->OutBuf));
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   uint8_t uMajorType = Nesting_GetMajorType(&(pMe->nesting));
   if(uMajorType == CBOR_MAJOR_NONE_TYPE_OPEN_BSTR) {
      /* It's OK to nest a byte string in any type but
       * another open byte string. */
      pMe->uError = QCBOR_ERR_OPEN_BYTE_STRING;
      return;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   QCBOREncode_Private_OpenMapOrArray(pMe, CBOR_MAJOR_NONE_TYPE_OPEN_BSTR);
}


/*
 * Public function for closing a byte string. See qcbor/qcbor_encode.h
 */
void
QCBOREncode_CloseBytes(QCBOREncodeContext *pMe, const size_t uAmount)
{
   UsefulOutBuf_Advance(&(pMe->OutBuf), uAmount);
   if(UsefulOutBuf_GetError(&(pMe->OutBuf))) {
      /* Advance too far. Normal off-end error handling in effect here. */
      return;
   }

   QCBOREncode_Private_CloseAggregate(pMe, CBOR_MAJOR_NONE_TYPE_OPEN_BSTR, uAmount);
}


#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
/**
 * @brief Semi-private method to close a map, array with indefinite length
 *
 * @param[in] pMe           The context to add to.
 * @param[in] uMajorType     The major CBOR type to close.
 *
 * Call QCBOREncode_CloseArrayIndefiniteLength() or
 * QCBOREncode_CloseMapIndefiniteLength() instead of this.
 */
void
QCBOREncode_Private_CloseMapOrArrayIndefiniteLength(QCBOREncodeContext *pMe,
                                                    const uint8_t       uMajorType)
{
   if(QCBOREncode_Private_CheckDecreaseNesting(pMe, uMajorType)) {
      return;
   }

   /* Append the break marker (0xff for both arrays and maps) */
   QCBOREncode_Private_AppendCBORHead(pMe, CBOR_MAJOR_NONE_TYPE_SIMPLE_BREAK, CBOR_SIMPLE_BREAK, 0);
   Nesting_Decrease(&(pMe->nesting));
}
#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */


/*
 * Public function to finish and get the encoded result. See qcbor/qcbor_encode.h
 */
QCBORError
QCBOREncode_Finish(QCBOREncodeContext *pMe, UsefulBufC *pEncodedCBOR)
{
   if(QCBOREncode_GetErrorState(pMe) != QCBOR_SUCCESS) {
      goto Done;
   }

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(Nesting_IsInNest(&(pMe->nesting))) {
      pMe->uError = QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN;
      goto Done;
   }
#endif /* ! QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   *pEncodedCBOR = UsefulOutBuf_OutUBuf(&(pMe->OutBuf));

Done:
   return pMe->uError;
}


/*
 * Public function to get size of the encoded result. See qcbor/qcbor_encode.h
 */
QCBORError
QCBOREncode_FinishGetSize(QCBOREncodeContext *pMe, size_t *puEncodedLen)
{
   UsefulBufC Enc;

   QCBORError nReturn = QCBOREncode_Finish(pMe, &Enc);

   if(nReturn == QCBOR_SUCCESS) {
      *puEncodedLen = Enc.len;
   }

   return nReturn;
}


/*
 * Public function to get substring of encoded-so-far. See qcbor/qcbor_encode.h
 */
UsefulBufC
QCBOREncode_SubString(QCBOREncodeContext *pMe, const size_t uStart)
{
   if(pMe->uError) {
      return NULLUsefulBufC;
   }

   /* An attempt was made to detect usage errors by comparing uStart
    * to offsets of open arrays and maps in pMe->nesting, but it is
    * not possible because there's not enough information in just
    * the offset. It's not possible to known if Tell() was called before
    * or after an Open(). To detect this error, the nesting level
    * would also need to be known. This is not frequently used, so
    * it is not worth adding this complexity.
    */

   const size_t uEnd = QCBOREncode_Tell(pMe);

   return UsefulOutBuf_SubString(&(pMe->OutBuf), uStart, uEnd - uStart);
}
