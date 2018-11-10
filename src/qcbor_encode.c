/*==============================================================================
 Copyright (c) 2016-2018, The Linux Foundation.
 Copyright (c) 2018, Laurence Lundblade.
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
 ==============================================================================*/

/*===================================================================================
 FILE:  qcbor_encode.c
 
 DESCRIPTION:  This file contains the implementation of QCBOR.
 
 EDIT HISTORY FOR FILE:
 
 This section contains comments describing changes made to the module.
 Notice that changes are listed in reverse chronological order.
 
 when               who             what, where, why
 --------           ----            ---------------------------------------------------
 02/05/18           llundbla        Works on CPUs which require integer alignment. 
                                    Requires new version of UsefulBuf.
 07/05/17           llundbla        Add bstr wrapping of maps/arrays for COSE
 03/01/17           llundbla        More data types
 11/13/16           llundbla        Integrate most TZ changes back into github version.
 09/30/16           gkanike         Porting to TZ.
 03/15/16           llundbla        Initial Version.
 
 =====================================================================================*/

#include "qcbor.h"
#include "ieee754.h"


/*...... This is a ruler that is 80 characters long...........................*/


/*
 CBOR's two nesting types, arrays and maps, are tracked here. There is a
 limit of QCBOR_MAX_ARRAY_NESTING to the number of arrays and maps
 that can be nested in one encoding so the encoding context stays
 small enough to fit on the stack.
 
 When an array / map is opened, pCurrentNesting points to the element
 in pArrays that records the type, start position and accumluates a
 count of the number of items added. When closed the start position is
 used to go back and fill in the type and number of items in the array
 / map.
 
 Encoded output be just items like ints and strings that are
 not part of any array / map. That is, the first thing encoded
 does not have to be an array or a map.
 */
inline static void Nesting_Init(QCBORTrackNesting *pNesting)
{
   // assumes pNesting has been zeroed
   pNesting->pCurrentNesting = &pNesting->pArrays[0];
   // Implied CBOR array at the top nesting level. This is never returned,
   // but makes the item count work correctly.
   pNesting->pCurrentNesting->uMajorType = CBOR_MAJOR_TYPE_ARRAY;
}

inline static QCBORError Nesting_Increase(QCBORTrackNesting *pNesting, uint8_t uMajorType, uint32_t uPos)
{
   QCBORError nReturn = QCBOR_SUCCESS;
   
   if(pNesting->pCurrentNesting == &pNesting->pArrays[QCBOR_MAX_ARRAY_NESTING]) {
      // trying to open one too many
      nReturn = QCBOR_ERR_ARRAY_NESTING_TOO_DEEP;
   } else {
      pNesting->pCurrentNesting++;
      pNesting->pCurrentNesting->uCount     = 0;
      pNesting->pCurrentNesting->uStart     = uPos;
      pNesting->pCurrentNesting->uMajorType = uMajorType;
   }
   return nReturn;
}

inline static void Nesting_Decrease(QCBORTrackNesting *pNesting)
{
   pNesting->pCurrentNesting--;
}

inline static QCBORError Nesting_Increment(QCBORTrackNesting *pNesting, uint16_t uAmount)
{
   if(uAmount >= QCBOR_MAX_ITEMS_IN_ARRAY - pNesting->pCurrentNesting->uCount) {
      return QCBOR_ERR_ARRAY_TOO_LONG;
   }
      
   pNesting->pCurrentNesting->uCount += uAmount;
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
   // type, hence the subtraction returns either 1 or 2.
   return pNesting->pCurrentNesting->uCount / (pNesting->pCurrentNesting->uMajorType - CBOR_MAJOR_TYPE_ARRAY+1);
}

inline static uint32_t Nesting_GetStartPos(QCBORTrackNesting *pNesting)
{
   return pNesting->pCurrentNesting->uStart;
}

inline static uint8_t Nesting_GetMajorType(QCBORTrackNesting *pNesting)
{
   return pNesting->pCurrentNesting->uMajorType;
}

inline static int Nesting_IsInNest(QCBORTrackNesting *pNesting)
{
   return pNesting->pCurrentNesting == &pNesting->pArrays[0] ? 0 : 1;
}




/*
 Error tracking plan -- Errors are tracked internally and not returned
 until Finish is called. The CBOR errors are in me->uError.
 UsefulOutBuf also tracks whether the the buffer is full or not in its
 context.  Once either of these errors is set they are never
 cleared. Only Init() resets them. Or said another way, they must
 never be cleared or we'll tell the caller all is good when it is not.
 
 Only one error code is reported by Finish() even if there are
 multiple errors. The last one set wins. The caller might have to fix
 one error to reveal the next one they have to fix.  This is OK.
 
 The buffer full error tracked by UsefulBuf is only pulled out of
 UsefulBuf in Finish() so it is the one that usually wins.  UsefulBuf
 will never go off the end of the buffer even if it is called again
 and again when full.
 
 It is really tempting to not check for overflow on the count in the
 number of items in an array. It would save a lot of code, it is
 extremely unlikely that any one will every put 65,000 items in an
 array, and the only bad thing that would happen is the CBOR would be
 bogus.  Once we prove that is the only consequence, then we can make
 the change.
 
 Since this does not parse any input, you could in theory remove all
 error checks in this code if you knew the caller called it
 correctly. Maybe someday CDDL or some such language will be able to
 generate the code to call this and the calling code would always be
 correct. This could also automatically size some of the data
 structures like array/map nesting resulting in some good memory
 savings.
 */




/*
 Public function for initialization. See header qcbor.h
 */
void QCBOREncode_Init(QCBOREncodeContext *me, UsefulBuf Storage)
{
   memset(me, 0, sizeof(QCBOREncodeContext));
   if(Storage.len > UINT32_MAX) {
      me->uError = QCBOR_ERR_BUFFER_TOO_LARGE;
   } else {
      UsefulOutBuf_Init(&(me->OutBuf), Storage);
      Nesting_Init(&(me->nesting));
   }
}




/* 
 All CBOR data items have a type and a number. The number is either
 the value of the item for integer types, the length of the content
 for string, byte, array and map types, a tag for major type 6, and
 has serveral uses for major type 7.
 
 This function encodes the type and the number. There are several
 encodings for the number depending on how large it is and how it is
 used.
 
 Every encoding of the type and number has at least one byte, the 
 "initial byte".
 
 The top three bits of the initial byte are the major type for the
 CBOR data item.  The eight major types defined by the standard are
 defined as CBOR_MAJOR_TYPE_xxxx in qcbor.h.
 
 The remaining five bits, known as "additional information", and
 possibly more bytes encode the number. If the number is less than 24,
 then it is encoded entirely in the five bits. This is neat because it
 allows you to encode an entire CBOR data item in 1 byte for many
 values and types (integers 0-23, true, false, and tags).
 
 If the number is larger than 24, then it is encoded in 1,2,4 or 8
 additional bytes, with the number of these bytes indicated by the
 values of the 5 bits 24, 25, 25 and 27.
 
 It is possible to encode a particular number in many ways with this
 representation.  This implementation always uses the smallest
 possible representation. This is also the suggestion made in the RFC
 for cannonical CBOR.
 
 This function inserts them into the output buffer at the specified
 position.  AppendEncodedTypeAndNumber() appends to the end.
 
 This function takes care of converting to network byte order. 
 
 This function is also used to insert floats and doubles. Before this
 function is called the float or double must be copied into a
 uint64_t. That is how they are passed in. They are then converted to
 network byte order correctly. The uMinLen param makes sure that even
 if all the digits of a float or double are 0 it is still correctly
 encoded in 4 or 8 bytes.
 
 */
static void InsertEncodedTypeAndNumber(QCBOREncodeContext *me, uint8_t uMajorType, size_t uMinLen, uint64_t uNumber, size_t uPos)
{
   // No need to worry about integer overflow here because a) uMajorType is
   // always generated internally, not by the caller, b) this is for CBOR
   // _generation_, not parsing c) a mistake will result in bad CBOR generation,
   // not a security vulnerability.
   uMajorType <<= 5;
   
   if(uNumber > 0xffffffff || uMinLen >= 8) {
      UsefulOutBuf_InsertByte(&(me->OutBuf), uMajorType + LEN_IS_EIGHT_BYTES, uPos);
      UsefulOutBuf_InsertUint64(&(me->OutBuf), (uint64_t)uNumber, uPos+1);
      
   } else if(uNumber > 0xffff || uMinLen >= 4) {
      UsefulOutBuf_InsertByte(&(me->OutBuf), uMajorType + LEN_IS_FOUR_BYTES, uPos);
      UsefulOutBuf_InsertUint32(&(me->OutBuf), (uint32_t)uNumber, uPos+1);
      
   } else if (uNumber > 0xff || uMinLen>= 2) {
      // Between 0 and 65535
      UsefulOutBuf_InsertByte(&(me->OutBuf), uMajorType + LEN_IS_TWO_BYTES, uPos);
      UsefulOutBuf_InsertUint16(&(me->OutBuf), (uint16_t)uNumber, uPos+1);
      
   } else if(uNumber >= 24) {
      // Between 0 and 255, but only between 24 and 255 is ever encoded here
      UsefulOutBuf_InsertByte(&(me->OutBuf), uMajorType + LEN_IS_ONE_BYTE, uPos);
      UsefulOutBuf_InsertByte(&(me->OutBuf), (uint8_t)uNumber, uPos+1);

   } else {
      // Between 0 and 23
      UsefulOutBuf_InsertByte(&(me->OutBuf), uMajorType + (uint8_t)uNumber, uPos);
   }
}


/*
 Append the type and number info to the end of the buffer.
 
 See InsertEncodedTypeAndNumber() function above for details
*/
inline static void AppendEncodedTypeAndNumber(QCBOREncodeContext *me, uint8_t uMajorType, uint64_t uNumber)
{
   // An append is an insert at the end.
   InsertEncodedTypeAndNumber(me, uMajorType, 0, uNumber, UsefulOutBuf_GetEndPosition(&(me->OutBuf)));
}




/*
 Internal function for adding positive and negative integers of all different sizes
 */
void InsertInt64(QCBOREncodeContext *me, int64_t nNum, size_t uPos)
{
   uint8_t      uMajorType;
   uint64_t     uValue;
   
   if(nNum < 0) {
      uValue = (uint64_t)(-nNum - 1); // This is the way negative ints work in CBOR. -1 encodes as 0x00 with major type negative int.
      uMajorType = CBOR_MAJOR_TYPE_NEGATIVE_INT;
   } else {
      uValue = (uint64_t)nNum;
      uMajorType = CBOR_MAJOR_TYPE_POSITIVE_INT;
   }
   
   InsertEncodedTypeAndNumber(me, uMajorType, 0, uValue, uPos);
   me->uError = Nesting_Increment(&(me->nesting), 1);
}


/*
 Does the work of adding some bytes to the CBOR output. Works for a
 byte and text strings, which are the same in in CBOR though they have
 different major types.  This is also used to insert raw
 pre-encoded CBOR.
 */
static void AddBufferInternal(QCBOREncodeContext *me, UsefulBufC Bytes, uint8_t uMajorType, size_t uPos)
{
   if(Bytes.len >= UINT32_MAX) {
      // This implementation doesn't allow buffers larger than UINT32_MAX.
      // This is primarily because QCBORTrackNesting.pArrays[].uStart is
      // an uint32 rather than size_t to keep the stack usage down. Also
      // it is entirely impractical to create tokens bigger than 4GB in
      // contiguous RAM
      me->uError = QCBOR_ERR_BUFFER_TOO_LARGE;
      
   } else {
      if(!me->uError) {
         // If it is not Raw CBOR, add the type and the length
         if(uMajorType != CBOR_MAJOR_NONE_TYPE_RAW) {
            const size_t uPosBeforeInsert = UsefulOutBuf_GetEndPosition(&(me->OutBuf));
            InsertEncodedTypeAndNumber(me, uMajorType, 0, Bytes.len, uPos);
            // The increment in uPos is to account for bytes added for
            // type and number so the buffer being added goes to the
            // right place
            uPos += UsefulOutBuf_GetEndPosition(&(me->OutBuf)) - uPosBeforeInsert;
         }
         
         // Actually add the bytes
         UsefulOutBuf_InsertUsefulBuf(&(me->OutBuf), Bytes, uPos);
         
         // Update the array counting if there is any nesting at all
         me->uError = Nesting_Increment(&(me->nesting), 1);
      }
   }
}


/*
 Add an optional label. It will go in front of a real data item.
 */
static void AddLabel(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel)
{
   size_t uPos = UsefulOutBuf_GetEndPosition(&(me->OutBuf));
   if(Nesting_GetMajorType(&(me->nesting)) == CBOR_MAJOR_NONE_TAG_LABEL_REORDER) {
      // Have to insert the label rather than just appen if a tag
      // has been added. This is so the tag ends up on the value, not
      // on the label.
      uPos = Nesting_GetStartPos(&(me->nesting));
      Nesting_Decrease(&(me->nesting));
   }

   if(szLabel) {
      const UsefulBufC SZText = UsefulBuf_FromSZ(szLabel);
      AddBufferInternal(me, SZText, CBOR_MAJOR_TYPE_TEXT_STRING, uPos);
   } else if (QCBOR_NO_INT_LABEL != nLabel) {
      InsertInt64(me, nLabel, uPos);
   }
}


/*
 Public Function
 */
void QCBOREncode_AddTag(QCBOREncodeContext *me, uint64_t uTag)
{
   uint8_t uNestingType = Nesting_GetMajorType(&(me->nesting));
   if(uNestingType == CBOR_MAJOR_TYPE_MAP || uNestingType == CBOR_MAJOR_TYPE_ARRAY) {
      // Remember where the first tag is for this item
      // So we can go back and insert the label in front of it.
      // Cast to uint32_t here OK as all inputs are limited to 4GB
      const uint32_t uPos = (uint32_t)UsefulOutBuf_GetEndPosition(&(me->OutBuf));
      me->uError = Nesting_Increase(&(me->nesting), CBOR_MAJOR_NONE_TAG_LABEL_REORDER, uPos);
   }

   AppendEncodedTypeAndNumber(me, CBOR_MAJOR_TYPE_OPTIONAL, uTag);
}


/*
 Semi-public interface. Called by inline functions to add text and byte strings
 and already-encoded CBOR. They are the real public interface, even though this
 is the main entry point. The code is structured like this to reduce code size.
 */
void QCBOREncode_AddBuffer_2(QCBOREncodeContext *me, uint8_t uMajorType, const char *szLabel, int64_t nLabel, UsefulBufC Bytes)
{
   AddLabel(me, szLabel, nLabel);
   if(!me->uError) {
      AddBufferInternal(me, Bytes, uMajorType, UsefulOutBuf_GetEndPosition(&(me->OutBuf)));
   }
}


/*
 Semi-public interfaced. Called by inline functions to open arrays, maps and
 bstr wrapped CBOR. They are the real public interface, even though this is the
 main entry point. This code is structured like this to reduce code size.
 */
void QCBOREncode_OpenMapOrArray_2(QCBOREncodeContext *me, uint8_t uMajorType, const char *szLabel, uint64_t nLabel)
{
   AddLabel(me, szLabel, nLabel);
   
   if(!me->uError) {
      // Add one item to the nesting level we are in for the new map or array
      me->uError = Nesting_Increment(&(me->nesting), 1);
      if(!me->uError) {
         // Increase nesting level because this is a map or array
         // Cast from size_t to uin32_t is safe because the UsefulOutBuf
         // size is limited to UINT32_MAX in QCBOR_Init().
         me->uError = Nesting_Increase(&(me->nesting), uMajorType, (uint32_t)UsefulOutBuf_GetEndPosition(&(me->OutBuf)));
      }
   }
}


/*
 Public functions for closing arrays and maps. See header qcbor.h
 */
void QCBOREncode_Close(QCBOREncodeContext *me, uint8_t uMajorType, UsefulBufC *pWrappedCBOR)
{
   if(!me->uError) {
      if(!Nesting_IsInNest(&(me->nesting))) {
         me->uError = QCBOR_ERR_TOO_MANY_CLOSES;
      } else if( Nesting_GetMajorType(&(me->nesting)) != uMajorType) {
         me->uError = QCBOR_ERR_CLOSE_MISMATCH; 
      } else {
         // When the array, map or bstr wrap was started, nothing was done
         // except note the position of the start of it. This code goes back
         // and inserts the actual CBOR array, map or bstr and its length.
         // That means all the data that is in the array, map or wrapped
         // needs to be slid to the right. This is done by UsefulOutBuf's
         // insert function that is called from inside
         // InsertEncodedTypeAndNumber()
         const size_t uInsertPosition         = Nesting_GetStartPos(&(me->nesting));
         const size_t uEndPosition            = UsefulOutBuf_GetEndPosition(&(me->OutBuf));
         // This can't go negative because the UsefulOutBuf always only grows
         // and never shrinks. UsefulOutBut itself also has defenses such that
         // it won't write were it should not even if given hostile input lengths
         const size_t uLenOfEncodedMapOrArray = uEndPosition - uInsertPosition;
         
         // Length is number of bytes for a bstr and number of items a for map & array
         const size_t uLength = uMajorType == CBOR_MAJOR_TYPE_BYTE_STRING ?
                                    uLenOfEncodedMapOrArray : Nesting_GetCount(&(me->nesting));
         
         // Actually insert
         InsertEncodedTypeAndNumber(me,
                                    uMajorType,       // major type bstr, array or map
                                    0,                // no minimum length for encoding
                                    uLength,          // either len of bstr or num items in array or map
                                    uInsertPosition); // position in out buffer
         
         // Return pointer and length to the enclosed encoded CBOR. The intended
         // use is for it to be hashed (e.g., SHA-256) in a COSE implementation.
         // This must be used right away, as the pointer and length go invalid
         // on any subsequent calls to this function because of the
         // InsertEncodedTypeAndNumber() call that slides data to the right.
         if(pWrappedCBOR) {
            UsefulBufC PartialResult = UsefulOutBuf_OutUBuf(&(me->OutBuf));
            size_t uBstrLen = UsefulOutBuf_GetEndPosition(&(me->OutBuf)) - uEndPosition;
            *pWrappedCBOR = UsefulBuf_Tail(PartialResult, uInsertPosition+uBstrLen);
         }
         Nesting_Decrease(&(me->nesting));
      }
   }
}


/*
 Public functions for adding integers. See header qcbor.h
 */
void QCBOREncode_AddUInt64_2(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uNum)
{
   AddLabel(me, szLabel, nLabel);
   if(!me->uError) {
      AppendEncodedTypeAndNumber(me, CBOR_MAJOR_TYPE_POSITIVE_INT, uNum);
      me->uError = Nesting_Increment(&(me->nesting), 1);
   }
}


/*
 Public functions for adding integers. See header qcbor.h
 */
void QCBOREncode_AddInt64_2(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, int64_t nNum)
{
   AddLabel(me, szLabel, nLabel);
   if(!me->uError) {
      // Cast is OK here because the output buffer is limited to 4GB in Init().
      InsertInt64(me, nNum, (uint32_t)UsefulOutBuf_GetEndPosition(&(me->OutBuf)));
   }
}


/*
 Semi-public interfaced. Called by inline functions to add simple and float
 types. They are the real public interface, even though this is the
 main entry point. This code is structured like this to reduce code size.
 
 Common code for adding floats and doubles and simple types like true and false
 
 One way to look at simple values is that they are:
  - type 7
  - an additional integer from 0 to 255
     - additional integer 0-19 are unassigned and could be used in an update to CBOR
     - additional integers 20, 21, 22 and 23 are false, true, null and undef
     - additional integer 24 is not available
     - when the additional value is 25, 26, or 27 there is additionally a half, float or double in following bytes
     - additional integers 28, 29 and 30 are unassigned / reserved
     - additional integer 31 is a "break"
     - additional integers 32-255 are unassigned and could be used in an update to CBOR
 */
void QCBOREncode_AddType7_2(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, size_t uSize, uint64_t uNum)
{
   AddLabel(me, szLabel, nLabel);
   if(!me->uError) {
      // This function call takes care of endian swapping for the float / double
      InsertEncodedTypeAndNumber(me,
                                 CBOR_MAJOR_TYPE_SIMPLE,  // The major type for
                                                          // floats and doubles
                                 uSize,                   // min size / tells
                                                          // encoder to do it right
                                 uNum,                    // Bytes of the floating
                                                          // point number as a uint
                                 UsefulOutBuf_GetEndPosition(&(me->OutBuf))); // end position for append
      
      me->uError = Nesting_Increment(&(me->nesting), 1);
   }
}


void QCBOREncode_AddDouble_2(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, double dNum)
{
   const IEEE754_union uNum = IEEE754_DoubleToSmallest(dNum);
   
   QCBOREncode_AddType7_2(me, szLabel, nLabel, uNum.uSize, uNum.uValue);
}




/*
 Public functions to finish and get the encoded result. See header qcbor.h
 */
QCBORError QCBOREncode_Finish(QCBOREncodeContext *me, UsefulBufC *pEncodedCBOR)
{
   if(me->uError)
      goto Done;
   
   if (Nesting_IsInNest(&(me->nesting))) {
      me->uError = QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN;
      goto Done;
   }
   
   if(UsefulOutBuf_GetError(&(me->OutBuf))) {
      // Stuff didn't fit in the buffer.
      // This check catches this condition for all the appends and inserts
      // so checks aren't needed when the appends and inserts are performed.
      // And of course UsefulBuf will never overrun the input buffer given
      // to it. No complex analysis of the error handling in this file is
      // needed to know that is true. Just read the UsefulBuf code.
      me->uError = QCBOR_ERR_BUFFER_TOO_SMALL;
      goto Done;
   }

   *pEncodedCBOR = UsefulOutBuf_OutUBuf(&(me->OutBuf));
   
Done:
   return me->uError;
}


QCBORError QCBOREncode_FinishGetSize(QCBOREncodeContext *me, size_t *puEncodedLen)
{
   UsefulBufC Enc;
   
   QCBORError nReturn = QCBOREncode_Finish(me, &Enc);
   
   if(nReturn == QCBOR_SUCCESS) {
      *puEncodedLen = Enc.len;
   }
   
   return nReturn;
}


