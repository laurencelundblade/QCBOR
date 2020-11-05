/*==============================================================================
 Copyright (c) 2016-2018, The Linux Foundation.
 Copyright (c) 2018-2020, Laurence Lundblade.
 All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.
    * Neither the name of The Linux Foundation nor the names of its
      contributors, nor the name "Laurence Lundblade" may be used to
      endorse or promote products derived from this software without
      specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 =============================================================================*/


#include "qcbor/qcbor_encode.h"
#include "ieee754.h"



/*
 Nesting -- This tracks the nesting of maps and arrays.

 The following functions and data type QCBORTrackNesting implement the
 nesting management for encoding.

 CBOR's two nesting types, arrays and maps, are tracked here. There is
 a limit of QCBOR_MAX_ARRAY_NESTING to the number of arrays and maps
 that can be nested in one encoding so the encoding context stays
 small enough to fit on the stack.

 When an array / map is opened, pCurrentNesting points to the element
 in pArrays that records the type, start position and accumulates a
 count of the number of items added. When closed the start position is
 used to go back and fill in the type and number of items in the array
 / map.

 Encoded output can be just items like ints and strings that are not
 part of any array / map. That is, the first thing encoded does not
 have to be an array or a map.

 QCBOR has a special feature to allow constructing bstr-wrapped CBOR
 directly into the output buffer, so an extra buffer for it is not
 needed.  This is implemented as nesting with type
 CBOR_MAJOR_TYPE_BYTE_STRING and uses this code. Bstr-wrapped CBOR is
 used by COSE for data that is to be hashed.
 */
inline static void Nesting_Init(QCBORTrackNesting *pNesting)
{
   // Assumes pNesting has been zeroed
   pNesting->pCurrentNesting = &pNesting->pArrays[0];
   // Implied CBOR array at the top nesting level. This is never returned,
   // but makes the item count work correctly.
   pNesting->pCurrentNesting->uMajorType = CBOR_MAJOR_TYPE_ARRAY;
}

inline static uint8_t Nesting_Increase(QCBORTrackNesting *pNesting,
                                          uint8_t uMajorType,
                                          uint32_t uPos)
{
   if(pNesting->pCurrentNesting == &pNesting->pArrays[QCBOR_MAX_ARRAY_NESTING]) {
      // Trying to open one too many
      return QCBOR_ERR_ARRAY_NESTING_TOO_DEEP;
   } else {
      pNesting->pCurrentNesting++;
      pNesting->pCurrentNesting->uCount     = 0;
      pNesting->pCurrentNesting->uStart     = uPos;
      pNesting->pCurrentNesting->uMajorType = uMajorType;
      return QCBOR_SUCCESS;
   }
}

inline static void Nesting_Decrease(QCBORTrackNesting *pNesting)
{
   pNesting->pCurrentNesting--;
}

inline static uint8_t Nesting_Increment(QCBORTrackNesting *pNesting)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(1 >= QCBOR_MAX_ITEMS_IN_ARRAY - pNesting->pCurrentNesting->uCount) {
      return QCBOR_ERR_ARRAY_TOO_LONG;
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   pNesting->pCurrentNesting->uCount++;

   return QCBOR_SUCCESS;
}

inline static uint16_t Nesting_GetCount(QCBORTrackNesting *pNesting)
{
   // The nesting count recorded is always the actual number of individiual
   // data items in the array or map. For arrays CBOR uses the actual item
   // count. For maps, CBOR uses the number of pairs.  This function returns
   // the number needed for the CBOR encoding, so it divides the number of
   // items by two for maps to get the number of pairs.  This implementation
   // takes advantage of the map major type being one larger the array major
   // type, hence uDivisor is either 1 or 2.

   if(pNesting->pCurrentNesting->uMajorType == CBOR_MAJOR_TYPE_MAP) {
      // Cast back to uint16_t after integer promotion for bit shift
      return (uint16_t)(pNesting->pCurrentNesting->uCount >> 1);
   } else {
      return pNesting->pCurrentNesting->uCount;
   }
}

inline static uint32_t Nesting_GetStartPos(QCBORTrackNesting *pNesting)
{
   return pNesting->pCurrentNesting->uStart;
}

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
inline static uint8_t Nesting_GetMajorType(QCBORTrackNesting *pNesting)
{
   return pNesting->pCurrentNesting->uMajorType;
}

inline static bool Nesting_IsInNest(QCBORTrackNesting *pNesting)
{
   return pNesting->pCurrentNesting == &pNesting->pArrays[0] ? false : true;
}
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */




/*
 Encoding of the major CBOR types is by these functions:

 CBOR Major Type    Public Function
 0                  QCBOREncode_AddUInt64()
 0, 1               QCBOREncode_AddUInt64(), QCBOREncode_AddInt64()
 2, 3               QCBOREncode_AddBuffer(), Also QCBOREncode_OpenMapOrArray(),
                    QCBOREncode_CloseMapOrArray()
 4, 5               QCBOREncode_OpenMapOrArray(), QCBOREncode_CloseMapOrArray(),
                    QCBOREncode_OpenMapOrArrayIndefiniteLength(),
                    QCBOREncode_CloseMapOrArrayIndefiniteLength()
 6                  QCBOREncode_AddTag()
 7                  QCBOREncode_AddDouble(), QCBOREncode_AddType7()

 Additionally, encoding of decimal fractions and bigfloats is by
 QCBOREncode_AddExponentAndMantissa()
*/

/*
 Error tracking plan -- Errors are tracked internally and not returned
 until QCBOREncode_Finish() or QCBOREncode_GetErrorState() is
 called. The CBOR errors are in me->uError.  UsefulOutBuf also tracks
 whether the buffer is full or not in its context.  Once either of
 these errors is set they are never cleared. Only QCBOREncode_Init()
 resets them. Or said another way, they must never be cleared or we'll
 tell the caller all is good when it is not.

 Only one error code is reported by QCBOREncode_Finish() even if there
 are multiple errors. The last one set wins. The caller might have to
 fix one error to reveal the next one they have to fix.  This is OK.

 The buffer full error tracked by UsefulBuf is only pulled out of
 UsefulBuf in QCBOREncode_Finish() so it is the one that usually wins.
 UsefulBuf will never go off the end of the buffer even if it is
 called again and again when full.

 QCBOR_DISABLE_ENCODE_USAGE_GUARDS disables about half of the error
 checks here to reduce code size by about 150 bytes leaving only the
 checks for size to avoid buffer overflow. If the calling code is
 completely correct, checks are completely unnecessary.  For example,
 there is no need to check that all the opens are matched by a close.

 QCBOR_DISABLE_ENCODE_USAGE_GUARDS also disables the check for more
 than QCBOR_MAX_ITEMS_IN_ARRAY in an array. Since
 QCBOR_MAX_ITEMS_IN_ARRAY is very large (65,535) it is very unlikely
 to be reached. If it is reached, the count will wrap around to zero
 and CBOR that is not well formed will be produced, but there will be
 no buffers overrun and new security issues in the code.

 The 8 errors returned here fall into three categories:

 Sizes
   QCBOR_ERR_BUFFER_TOO_LARGE        -- Encoded output exceeded UINT32_MAX
   QCBOR_ERR_BUFFER_TOO_SMALL        -- Output buffer too small
   QCBOR_ERR_ARRAY_NESTING_TOO_DEEP  -- Nesting > QCBOR_MAX_ARRAY_NESTING1
   QCBOR_ERR_ARRAY_TOO_LONG          -- Too many items added to an array/map [1]

 Nesting constructed incorrectly
   QCBOR_ERR_TOO_MANY_CLOSES         -- More close calls than opens [1]
   QCBOR_ERR_CLOSE_MISMATCH          -- Type of close does not match open [1]
   QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN -- Finish called without enough closes [1]

 Would generate not-well-formed CBOR
   QCBOR_ERR_ENCODE_UNSUPPORTED      -- Simple type between 24 and 31 [1]

 [1] indicated disabled by QCBOR_DISABLE_ENCODE_USAGE_GUARDS
 */


/*
 Public function for initialization. See qcbor/qcbor_encode.h
 */
void QCBOREncode_Init(QCBOREncodeContext *me, UsefulBuf Storage)
{
   memset(me, 0, sizeof(QCBOREncodeContext));
   UsefulOutBuf_Init(&(me->OutBuf), Storage);
   Nesting_Init(&(me->nesting));
}


/*
 Public function to encode a CBOR head. See qcbor/qcbor_encode.h
 */
UsefulBufC QCBOREncode_EncodeHead(UsefulBuf buffer,
                                  uint8_t   uMajorType,
                                  uint8_t   uMinLen,
                                  uint64_t  uArgument)
{
   /**
    All CBOR data items have a type and an "argument". The argument is
    either the value of the item for integer types, the length of the
    content for string, byte, array and map types, a tag for major type
    6, and has several uses for major type 7.

    This function encodes the type and the argument. There are several
    encodings for the argument depending on how large it is and how it is
    used.

    Every encoding of the type and argument has at least one byte, the
    "initial byte".

    The top three bits of the initial byte are the major type for the
    CBOR data item.  The eight major types defined by the standard are
    defined as CBOR_MAJOR_TYPE_xxxx in qcbor/qcbor_common.h.

    The remaining five bits, known as "additional information", and
    possibly more bytes encode the argument. If the argument is less than
    24, then it is encoded entirely in the five bits. This is neat
    because it allows you to encode an entire CBOR data item in 1 byte
    for many values and types (integers 0-23, true, false, and tags).

    If the argument is larger than 24, then it is encoded in 1,2,4 or 8
    additional bytes, with the number of these bytes indicated by the
    values of the 5 bits 24, 25, 25 and 27.

    It is possible to encode a particular argument in many ways with this
    representation.  This implementation always uses the smallest
    possible representation. This conforms with CBOR preferred encoding.

    This function inserts them into the output buffer at the specified
    position. AppendEncodedTypeAndNumber() appends to the end.

    This function takes care of converting to network byte order.

    This function is also used to insert floats and doubles. Before this
    function is called the float or double must be copied into a
    uint64_t. That is how they are passed in. They are then converted to
    network byte order correctly. The uMinLen parameter makes sure that
    even if all the digits of a half, float or double are 0 it is still
    correctly encoded in 2, 4 or 8 bytes.
    */
   /*
    This code does endian conversion without hton or knowing the
    endianness of the machine using masks and shifts. This avoids the
    dependency on hton and the mess of figuring out how to find the
    machine's endianness.

    This is a good efficient implementation on little-endian machines.
    A faster and small implementation is possible on big-endian
    machines because CBOR/network byte order is big endian. However
    big endian machines are uncommon.

    On x86, it is about 200 bytes instead of 500 bytes for the more
    formal unoptimized code.

    This also does the CBOR preferred shortest encoding for integers
    and is called to do endian conversion for floats.

    It works backwards from the LSB to the MSB as needed.

    Code Reviewers: THIS FUNCTION DOES POINTER MATH
    */
   /*
    The type int is used here for several variables because of the way
    integer promotion works in C for integer variables that are
    uint8_t or uint16_t. The basic rule is that they will always be
    promoted to int if they will fit. All of these integer variables
    need only hold values less than 255 or are promoted from uint8_t,
    so they will always fit into an int. Note that promotion is only
    to unsigned int if the value won't fit into an int even if the
    promotion is for an unsigned like uint8_t.

    By declaring them int, there are few implicit conversions and fewer
    casts needed. Code size is reduced a little. It also makes static
    analyzers happier.

    Note also that declaring them uint8_t won't stop integer wrap
    around if the code is wrong. It won't make the code more correct.

    https://stackoverflow.com/questions/46073295/implicit-type-promotion-rules
    https://stackoverflow.com/questions/589575/what-does-the-c-standard-state-the-size-of-int-long-type-to-be
    */

   // Buffer must have room for the largest CBOR HEAD + one extra as the
   // one extra is needed for this code to work as it does a pre-decrement.
    if(buffer.len < QCBOR_HEAD_BUFFER_SIZE) {
        return NULLUsefulBufC;
    }

   // Pointer to last valid byte in the buffer
   uint8_t * const pBufferEnd = &((uint8_t *)buffer.ptr)[QCBOR_HEAD_BUFFER_SIZE-1];

   // Point to the last byte and work backwards
   uint8_t *pByte = pBufferEnd;
   // The 5 bits in the initial byte that are not the major type
   int nAdditionalInfo;

   if(uMajorType > QCBOR_INDEFINITE_LEN_TYPE_MODIFIER) {
      // Special case for start & end of indefinite length
      uMajorType  = uMajorType - QCBOR_INDEFINITE_LEN_TYPE_MODIFIER;
      // Take advantage of design of CBOR where additional info
      // is 31 for both opening and closing indefinite length
      // maps and arrays.
#if CBOR_SIMPLE_BREAK != LEN_IS_INDEFINITE
#error additional info for opening array not the same as for closing
#endif
      nAdditionalInfo = CBOR_SIMPLE_BREAK;
   } else if (uArgument < CBOR_TWENTY_FOUR && uMinLen == 0) {
      // Simple case where argument is < 24
      nAdditionalInfo = (int)uArgument;
   } else  {
      /*
       Encode argument in 1,2,4 or 8 bytes. Outer loop
       runs once for 1 byte and 4 times for 8 bytes.
       Inner loop runs 1, 2 or 4 times depending on
       outer loop counter. This works backwards taking
       8 bits off the argument being encoded at a time
       until all bits from uNumber have been encoded
       and the minimum encoding size is reached.
       Minimum encoding size is for floating point
       numbers with zero bytes.
       */
      static const uint8_t aIterate[] = {1,1,2,4};

      // The parameter passed in is unsigned, but goes negative in the loop
      // so it must be converted to a signed value.
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
      // Additional info is the encoding of the number of additional
      // bytes to encode argument.
      nAdditionalInfo = LEN_IS_ONE_BYTE-1 + i;
   }

   /*
    This expression integer-promotes to type int. The code above in
    function guarantees that nAdditionalInfo will never be larger than
    0x1f. The caller may pass in a too-large uMajor type. The
    conversion to unint8_t will cause an integer wrap around and
    incorrect CBOR will be generated, but no security issue will
    occur.
    */
   *--pByte = (uint8_t)((uMajorType << 5) + nAdditionalInfo);

#ifdef EXTRA_ENCODE_HEAD_CHECK
   /* This is a sanity check that can be turned on to verify the pointer
    * math in this function is not going wrong. Turn it on and run the
    * whole test suite to perform the check.
    */
   if(pBufferEnd - pByte > 9 || pBufferEnd - pByte < 1 || pByte < (uint8_t *)buffer.ptr) {
      return NULLUsefulBufC;
   }
#endif

   // Length will not go negative because the loops run for at most 8 decrements
   // of pByte, only one other decrement is made, and the array is sized
   // for this.
   return (UsefulBufC){pByte, (size_t)(pBufferEnd - pByte)};
}


/**
 @brief Append the CBOR head, the major type and argument

 @param me          Encoder context.
 @param uMajorType  Major type to insert.
 @param uArgument   The argument (an integer value or a length).
 @param uMinLen     The minimum number of bytes for encoding the CBOR argument.

 This formats the CBOR "head" and appends it to the output.
 */
static void AppendCBORHead(QCBOREncodeContext *me, uint8_t uMajorType,  uint64_t uArgument, uint8_t uMinLen)
{
   // A stack buffer large enough for a CBOR head
   UsefulBuf_MAKE_STACK_UB  (pBufferForEncodedHead, QCBOR_HEAD_BUFFER_SIZE);

   UsefulBufC EncodedHead = QCBOREncode_EncodeHead(pBufferForEncodedHead,
                                                    uMajorType,
                                                    uMinLen,
                                                    uArgument);

   /* No check for EncodedHead == NULLUsefulBufC is performed here to
    * save object code. It is very clear that pBufferForEncodedHead
    * is the correct size. If EncodedHead == NULLUsefulBufC then
    * UsefulOutBuf_AppendUsefulBuf() will do nothing so there is
    * no security hole introduced.
    */

   UsefulOutBuf_AppendUsefulBuf(&(me->OutBuf), EncodedHead);
}


/**
 @brief Insert the CBOR head for a map, array or wrapped bstr

 @param me          QCBOR encoding context.
 @param uMajorType  One of CBOR_MAJOR_TYPE_XXXX.
 @param uLen        The length of the data item.

 When an array, map or bstr was opened, nothing was done but note
 the position. This function goes back to that position and inserts
 the CBOR Head with the major type and length.
 */
static void InsertCBORHead(QCBOREncodeContext *me, uint8_t uMajorType, size_t uLen)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(me->uError == QCBOR_SUCCESS) {
      if(!Nesting_IsInNest(&(me->nesting))) {
         me->uError = QCBOR_ERR_TOO_MANY_CLOSES;
         return;
      } else if(Nesting_GetMajorType(&(me->nesting)) != uMajorType) {
         me->uError = QCBOR_ERR_CLOSE_MISMATCH;
         return;
      }
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   // A stack buffer large enough for a CBOR head
   UsefulBuf_MAKE_STACK_UB(pBufferForEncodedHead, QCBOR_HEAD_BUFFER_SIZE);

   UsefulBufC EncodedHead = QCBOREncode_EncodeHead(pBufferForEncodedHead,
                                                   uMajorType,
                                                   0,
                                                   uLen);

   /* No check for EncodedHead == NULLUsefulBufC is performed here to
    * save object code. It is very clear that pBufferForEncodedHead
    * is the correct size. If EncodedHead == NULLUsefulBufC then
    * UsefulOutBuf_InsertUsefulBuf() will do nothing so there is
    * no security whole introduced.
    */
   UsefulOutBuf_InsertUsefulBuf(&(me->OutBuf),
                                EncodedHead,
                                Nesting_GetStartPos(&(me->nesting)));

   Nesting_Decrease(&(me->nesting));
}


/*
 Increment the count of items in a map or array. This is mostly
 a separate function to have fewer occurance of
 #ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
 */
static inline void IncrementMapOrArrayCount(QCBOREncodeContext *pMe)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(pMe->uError == QCBOR_SUCCESS) {
      pMe->uError = Nesting_Increment(&(pMe->nesting));
   }
#else
   (void)Nesting_Increment(&(pMe->nesting));
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */
}


/*
 Public functions for adding integers. See qcbor/qcbor_encode.h
 */
void QCBOREncode_AddUInt64(QCBOREncodeContext *me, uint64_t uValue)
{
   AppendCBORHead(me, CBOR_MAJOR_TYPE_POSITIVE_INT, uValue, 0);

   IncrementMapOrArrayCount(me);
}


/*
 Public functions for adding unsigned. See qcbor/qcbor_encode.h
 */
void QCBOREncode_AddInt64(QCBOREncodeContext *me, int64_t nNum)
{
   uint8_t      uMajorType;
   uint64_t     uValue;

   if(nNum < 0) {
      // In CBOR -1 encodes as 0x00 with major type negative int.
      uValue = (uint64_t)(-nNum - 1);
      uMajorType = CBOR_MAJOR_TYPE_NEGATIVE_INT;
   } else {
      uValue = (uint64_t)nNum;
      uMajorType = CBOR_MAJOR_TYPE_POSITIVE_INT;
   }
   AppendCBORHead(me, uMajorType, uValue, 0);

   IncrementMapOrArrayCount(me);
}


/*
 Semi-private function. It is exposed to user of the interface, but
 they will usually call one of the inline wrappers rather than this.

 See qcbor/qcbor_encode.h

 Does the work of adding actual strings bytes to the CBOR output (as
 opposed to numbers and opening / closing aggregate types).

 There are four use cases:
   CBOR_MAJOR_TYPE_BYTE_STRING -- Byte strings
   CBOR_MAJOR_TYPE_TEXT_STRING -- Text strings
   CBOR_MAJOR_NONE_TYPE_RAW -- Already-encoded CBOR
   CBOR_MAJOR_NONE_TYPE_BSTR_LEN_ONLY -- Special case

 The first two add the type and length plus the actual bytes. The
 third just adds the bytes as the type and length are presumed to be
 in the bytes. The fourth just adds the type and length for the very
 special case of QCBOREncode_AddBytesLenOnly().
 */
void QCBOREncode_AddBuffer(QCBOREncodeContext *me, uint8_t uMajorType, UsefulBufC Bytes)
{
   // If it is not Raw CBOR, add the type and the length
   if(uMajorType != CBOR_MAJOR_NONE_TYPE_RAW) {
      uint8_t uRealMajorType = uMajorType;
      if(uRealMajorType == CBOR_MAJOR_NONE_TYPE_BSTR_LEN_ONLY) {
         uRealMajorType = CBOR_MAJOR_TYPE_BYTE_STRING;
      }
      AppendCBORHead(me, uRealMajorType, Bytes.len, 0);
   }

   if(uMajorType != CBOR_MAJOR_NONE_TYPE_BSTR_LEN_ONLY) {
      // Actually add the bytes
      UsefulOutBuf_AppendUsefulBuf(&(me->OutBuf), Bytes);
   }

   IncrementMapOrArrayCount(me);
}


/*
 Public functions for adding a tag. See qcbor/qcbor_encode.h
 */
void QCBOREncode_AddTag(QCBOREncodeContext *me, uint64_t uTag)
{
   AppendCBORHead(me, CBOR_MAJOR_TYPE_OPTIONAL, uTag, 0);
}


/*
 Semi-private function. It is exposed to user of the interface,
 but they will usually call one of the inline wrappers rather than this.

 See header qcbor/qcbor_encode.h
 */
void QCBOREncode_AddType7(QCBOREncodeContext *me, uint8_t uMinLen, uint64_t uNum)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(me->uError == QCBOR_SUCCESS) {
      if(uNum >= CBOR_SIMPLEV_RESERVED_START && uNum <= CBOR_SIMPLEV_RESERVED_END) {
         me->uError = QCBOR_ERR_ENCODE_UNSUPPORTED;
         return;
      }
   }
#endif /* QCBOR_DISABLE_ENCODE_USAGE_GUARDS */

   // AppendHead() does endian swapping for the float / double
   AppendCBORHead(me, CBOR_MAJOR_TYPE_SIMPLE, uNum, uMinLen);
   
   IncrementMapOrArrayCount(me);
}


/*
 Public functions for adding a double. See qcbor/qcbor_encode.h
*/
void QCBOREncode_AddDoubleNoPreferred(QCBOREncodeContext *me, double dNum)
{
   QCBOREncode_AddType7(me,
                        sizeof(uint64_t),
                        UsefulBufUtil_CopyDoubleToUint64(dNum));
}


/*
 Public functions for adding a double. See qcbor/qcbor_encode.h
 */
void QCBOREncode_AddDouble(QCBOREncodeContext *me, double dNum)
{
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
   const IEEE754_union uNum = IEEE754_DoubleToSmallest(dNum);

   QCBOREncode_AddType7(me, uNum.uSize, uNum.uValue);
#else
   QCBOREncode_AddDoubleNoPreferred(me, dNum);
#endif
}


/*
 Public functions for adding a float. See qcbor/qcbor_encode.h
*/
void QCBOREncode_AddFloatNoPreferred(QCBOREncodeContext *me, float fNum)
{
   QCBOREncode_AddType7(me,
                        sizeof(uint32_t),
                        UsefulBufUtil_CopyFloatToUint32(fNum));
}


/*
 Public functions for adding a float. See qcbor/qcbor_encode.h
 */
void QCBOREncode_AddFloat(QCBOREncodeContext *me, float fNum)
{
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
   const IEEE754_union uNum = IEEE754_FloatToSmallest(fNum);

   QCBOREncode_AddType7(me, uNum.uSize, uNum.uValue);
#else
   QCBOREncode_AddFloatNoPreferred(me, fNum);
#endif
}


#ifndef QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
/*
 Semi-public function. It is exposed to the user of the interface, but
 one of the inline wrappers will usually be called rather than this.

 See qcbor/qcbor_encode.h

 Improvement: create another version of this that only
 takes a big number mantissa and converts the output to
 a type 0 or 1 integer when mantissa is small enough.
 */
void QCBOREncode_AddExponentAndMantissa(QCBOREncodeContext *pMe,
                                        uint64_t            uTag,
                                        UsefulBufC          BigNumMantissa,
                                        bool                bBigNumIsNegative,
                                        int64_t             nMantissa,
                                        int64_t             nExponent)
{
   /*
    This is for encoding either a big float or a decimal fraction,
    both of which are an array of two items, an exponent and a
    mantissa.  The difference between the two is that the exponent is
    base-2 for big floats and base-10 for decimal fractions, but that
    has no effect on the code here.
    */
   if(uTag != CBOR_TAG_INVALID64) {
      QCBOREncode_AddTag(pMe, uTag);
   }
   QCBOREncode_OpenArray(pMe);
   QCBOREncode_AddInt64(pMe, nExponent);
   if(!UsefulBuf_IsNULLC(BigNumMantissa)) {
      if(bBigNumIsNegative) {
         QCBOREncode_AddNegativeBignum(pMe, BigNumMantissa);
      } else {
         QCBOREncode_AddPositiveBignum(pMe, BigNumMantissa);
      }
   } else {
      QCBOREncode_AddInt64(pMe, nMantissa);
   }
   QCBOREncode_CloseArray(pMe);
}
#endif /* QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA */


/*
 Semi-public function. It is exposed to user of the interface,
 but they will usually call one of the inline wrappers rather than this.

 See qcbor/qcbor_encode.h
*/
void QCBOREncode_OpenMapOrArray(QCBOREncodeContext *me, uint8_t uMajorType)
{
   // Add one item to the nesting level we are in for the new map or array
   IncrementMapOrArrayCount(me);

   /*
    The offset where the length of an array or map will get written
    is stored in a uint32_t, not a size_t to keep stack usage
    smaller. This checks to be sure there is no wrap around when
    recording the offset.  Note that on 64-bit machines CBOR larger
    than 4GB can be encoded as long as no array / map offsets occur
    past the 4GB mark, but the public interface says that the
    maximum is 4GB to keep the discussion simpler.
   */
   size_t uEndPosition = UsefulOutBuf_GetEndPosition(&(me->OutBuf));

   /*
    QCBOR_MAX_ARRAY_OFFSET is slightly less than UINT32_MAX so this
    code can run on a 32-bit machine and tests can pass on a 32-bit
    machine. If it was exactly UINT32_MAX, then this code would not
    compile or run on a 32-bit machine and an #ifdef or some
    machine size detection would be needed reducing portability.
   */
   if(uEndPosition >= QCBOR_MAX_ARRAY_OFFSET) {
      me->uError = QCBOR_ERR_BUFFER_TOO_LARGE;

   } else {
      // Increase nesting level because this is a map or array.  Cast
      // from size_t to uin32_t is safe because of check above
      me->uError = Nesting_Increase(&(me->nesting), uMajorType, (uint32_t)uEndPosition);
   }
}


/*
 Semi-public function. It is exposed to user of the interface,
 but they will usually call one of the inline wrappers rather than this.

 See qcbor/qcbor_encode.h
*/
void QCBOREncode_OpenMapOrArrayIndefiniteLength(QCBOREncodeContext *me, uint8_t uMajorType)
{
   // Insert the indefinite length marker (0x9f for arrays, 0xbf for maps)
   AppendCBORHead(me, uMajorType, 0, 0);
   // Call the definite-length opener just to do the bookkeeping for
   // nesting.  It will record the position of the opening item in
   // the encoded output but this is not used when closing this open.
   QCBOREncode_OpenMapOrArray(me, uMajorType);
}


/*
 Public functions for closing arrays and maps. See qcbor/qcbor_encode.h
 */
void QCBOREncode_CloseMapOrArray(QCBOREncodeContext *me, uint8_t uMajorType)
{
   InsertCBORHead(me, uMajorType, Nesting_GetCount(&(me->nesting)));
}


/*
 Public functions for closing bstr wrapping. See qcbor/qcbor_encode.h
 */
void QCBOREncode_CloseBstrWrap2(QCBOREncodeContext *me, bool bIncludeCBORHead, UsefulBufC *pWrappedCBOR)
{
   const size_t uInsertPosition = Nesting_GetStartPos(&(me->nesting));
   const size_t uEndPosition    = UsefulOutBuf_GetEndPosition(&(me->OutBuf));

   // This can't go negative because the UsefulOutBuf always only grows
   // and never shrinks. UsefulOutBut itself also has defenses such that
   // it won't write where it should not even if given hostile input lengths.
   const size_t uBstrLen = uEndPosition - uInsertPosition;

   // Actually insert
   InsertCBORHead(me, CBOR_MAJOR_TYPE_BYTE_STRING, uBstrLen);

   if(pWrappedCBOR) {
      /*
       Return pointer and length to the enclosed encoded CBOR. The
       intended use is for it to be hashed (e.g., SHA-256) in a COSE
       implementation.  This must be used right away, as the pointer
       and length go invalid on any subsequent calls to this function
       because there might be calls to InsertEncodedTypeAndNumber()
       that slides data to the right.
       */
      size_t uStartOfNew = uInsertPosition;
      if(!bIncludeCBORHead) {
         // Skip over the CBOR head to just get the inserted bstr
         const size_t uNewEndPosition = UsefulOutBuf_GetEndPosition(&(me->OutBuf));
         uStartOfNew += uNewEndPosition - uEndPosition;
      }
      const UsefulBufC PartialResult = UsefulOutBuf_OutUBuf(&(me->OutBuf));
      *pWrappedCBOR = UsefulBuf_Tail(PartialResult, uStartOfNew);
   }
}


/*
 Public functions for closing arrays and maps. See qcbor/qcbor_encode.h
 */
void QCBOREncode_CloseMapOrArrayIndefiniteLength(QCBOREncodeContext *me, uint8_t uMajorType)
{
#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(me->uError == QCBOR_SUCCESS) {
      if(!Nesting_IsInNest(&(me->nesting))) {
         me->uError = QCBOR_ERR_TOO_MANY_CLOSES;
         return;
      } else if(Nesting_GetMajorType(&(me->nesting)) != uMajorType) {
         me->uError = QCBOR_ERR_CLOSE_MISMATCH;
         return;
      }
   }
#else
   (void) uMajorType;
#endif

   // Append the break marker (0xff for both arrays and maps)
   AppendCBORHead(me, CBOR_MAJOR_NONE_TYPE_SIMPLE_BREAK, CBOR_SIMPLE_BREAK, 0);
   Nesting_Decrease(&(me->nesting));
}


/*
 Public functions to finish and get the encoded result. See qcbor/qcbor_encode.h
 */
QCBORError QCBOREncode_Finish(QCBOREncodeContext *me, UsefulBufC *pEncodedCBOR)
{
   QCBORError uReturn = QCBOREncode_GetErrorState(me);

   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }

#ifndef QCBOR_DISABLE_ENCODE_USAGE_GUARDS
   if(Nesting_IsInNest(&(me->nesting))) {
      uReturn = QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN;
      goto Done;
   }
#endif

   *pEncodedCBOR = UsefulOutBuf_OutUBuf(&(me->OutBuf));

Done:
   return uReturn;
}


/*
 Public functions to finish and get the encoded result. See qcbor/qcbor_encode.h
 */
QCBORError QCBOREncode_FinishGetSize(QCBOREncodeContext *me, size_t *puEncodedLen)
{
   UsefulBufC Enc;

   QCBORError nReturn = QCBOREncode_Finish(me, &Enc);

   if(nReturn == QCBOR_SUCCESS) {
      *puEncodedLen = Enc.len;
   }

   return nReturn;
}
