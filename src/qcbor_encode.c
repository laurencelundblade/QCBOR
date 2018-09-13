/*==============================================================================
Copyright (c) 2016-2018, The Linux Foundation. All rights reserved.

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
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

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
#include <stdint.h>

#ifdef QSEE
#include "stringl.h"
#endif

/*...... This is a ruler that is 80 characters long...........................*/


// Used internally in the impementation here
// Must not conflict with any of the official CBOR types
#define CBOR_MAJOR_NONE_TYPE_RAW  9





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

inline static int Nesting_Increase(QCBORTrackNesting *pNesting, uint8_t uMajorType, uint32_t uPos, bool bBstWrap)
{
   int nReturn = QCBOR_SUCCESS;
   
   if(pNesting->pCurrentNesting == &pNesting->pArrays[QCBOR_MAX_ARRAY_NESTING]) {
      // trying to open one too many
      nReturn = QCBOR_ERR_ARRAY_NESTING_TOO_DEEP;
   } else {
      pNesting->pCurrentNesting++;
      pNesting->pCurrentNesting->uCount     = 0;
      pNesting->pCurrentNesting->uStart     = uPos;
      pNesting->pCurrentNesting->uMajorType = uMajorType;
      pNesting->pCurrentNesting->bBstrWrap  = bBstWrap;
   }
   return nReturn;
}

inline static void Nesting_Decrease(QCBORTrackNesting *pNesting)
{
   pNesting->pCurrentNesting--;
}

inline static int Nesting_Increment(QCBORTrackNesting *pNesting, uint16_t uAmount)
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

inline static bool Nesting_IsBstrWrapped(QCBORTrackNesting *pNesting)
{
   return pNesting->pCurrentNesting->bBstrWrap;
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
 correct. This could also make automatically size some of the data
 structures like array/map nesting resulting in some good memory
 savings.
 */




/*
 Public function for initialization. See header qcbor.h
 */
void QCBOREncode_Init(QCBOREncodeContext *me, void *pBuf, size_t uBufLen)
{
   memset(me, 0, sizeof(QCBOREncodeContext));
   if(uBufLen > UINT32_MAX) {
      me->uError = QCBOR_ERR_BUFFER_TOO_LARGE;
   } else {
      UsefulOutBuf_Init(&(me->OutBuf), pBuf, uBufLen);
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
      
   } else if (uNumber > 0xff) {
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


static void AddBytesInternal(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uTag, UsefulBufC Bytes, uint8_t uMajorType, uint16_t uItems);


/*
 Add an optional label and optional tag. It will go in front of a real data item.
 */
static void AddLabelAndOptionalTag(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uTag)
{
   if(szLabel) {
      UsefulBufC SZText = {szLabel, strlen(szLabel)};
      AddBytesInternal(me, NULL, nLabel, CBOR_TAG_NONE, SZText, CBOR_MAJOR_TYPE_TEXT_STRING, 0);
   } else if (QCBOR_NO_INT_LABEL != nLabel) {
      // Add an integer label. This is just adding an integer at this point
      // This will result in a call right back to here, but the call won't do anything
      // because of the params NULL, QCBOR_NO_INT_LABEL and CBOR_TAG_NONE
      QCBOREncode_AddInt64_3(me, NULL, QCBOR_NO_INT_LABEL, CBOR_TAG_NONE, nLabel);
   }
   if(uTag != CBOR_TAG_NONE) {
      AppendEncodedTypeAndNumber(me, CBOR_MAJOR_TYPE_OPTIONAL, uTag);
   }
}


/*
 Does the work of adding some bytes to the CBOR output. Works for a
 byte and text strings, which are the same in in CBOR though they have
 different major types.  This is also used to insert raw or
 pre-formatted CBOR.
 */
static void AddBytesInternal(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uTag, UsefulBufC Bytes, uint8_t uMajorType, uint16_t uItems)
{
   if(Bytes.len >= UINT32_MAX) {
      // This implementation doesn't allow buffers larger than UINT32_MAX. This is
      // primarily because QCBORTrackNesting.pArrays[].uStart is an uint32 rather
      // than size_t to keep the stack usage down. Also it is entirely impractical
      // to create tokens bigger than 4GB in contiguous RAM
      me->uError = QCBOR_ERR_BUFFER_TOO_LARGE;
      
   } else {
      
      AddLabelAndOptionalTag(me, szLabel, nLabel, uTag);
      
      if(!me->uError) {

         // If it is not Raw CBOR, add the type and the length
         if(uMajorType != CBOR_MAJOR_NONE_TYPE_RAW) {
            AppendEncodedTypeAndNumber(me, uMajorType, Bytes.len);
         }
         
         // Actually add the bytes
         UsefulOutBuf_AppendUsefulBuf(&(me->OutBuf), Bytes);
         
         // Update the array counting if there is any nesting at all
         me->uError = Nesting_Increment(&(me->nesting), uMajorType == CBOR_MAJOR_NONE_TYPE_RAW ? uItems : 1);
      }
   }
}




/*
 Public functions for adding strings and raw encoded CBOR. See header qcbor.h
 */
void QCBOREncode_AddBytes_3(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uTag, UsefulBufC Bytes)
{
   AddBytesInternal(me, szLabel, nLabel, uTag, Bytes, CBOR_MAJOR_TYPE_BYTE_STRING, 0);
}

void QCBOREncode_AddText_3(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uTag, UsefulBufC Bytes)
{
   AddBytesInternal(me, szLabel, nLabel, uTag, Bytes, CBOR_MAJOR_TYPE_TEXT_STRING, 0);
}

void QCBOREncode_AddRaw(QCBOREncodeContext *me, EncodedCBORC Raw)
{
   AddBytesInternal(me, NULL, QCBOR_NO_INT_LABEL, CBOR_TAG_NONE, Raw.Bytes, CBOR_MAJOR_NONE_TYPE_RAW, Raw.uItems);
}




/*
 Internal function common to opening an array or a map
 
 QCBOR_MAX_ARRAY_NESTING is the number of times Open can be called
 successfully.  Call it one more time gives an error.
 
 */
static void OpenMapOrArrayInternal(QCBOREncodeContext *me, uint8_t uMajorType, const char *szLabel, uint64_t nLabel, uint64_t uTag, bool bBstrWrap)
{
   AddLabelAndOptionalTag(me, szLabel, nLabel, uTag);
   
   if(!me->uError) {
      // Add one item to the nesting level we are in for the new map or array
      me->uError = Nesting_Increment(&(me->nesting), 1);
      if(!me->uError) {
         // Increase nesting level because this is a map or array
         // Cast from size_t to uin32_t is safe because the UsefulOutBuf
         // size is limited to UINT32_MAX in QCBOR_Init().
         me->uError = Nesting_Increase(&(me->nesting),
                                       uMajorType, (uint32_t)UsefulOutBuf_GetEndPosition(&(me->OutBuf)),
                                       bBstrWrap);
      }
   }
}


/*
 Public functions for opening / closing arrays and maps. See header qcbor.h
 */
void QCBOREncode_OpenArray_3(QCBOREncodeContext *me, const char *szLabel, uint64_t nLabel, uint64_t uTag, bool bBstrWrap)
{
   OpenMapOrArrayInternal(me, CBOR_MAJOR_TYPE_ARRAY, szLabel, nLabel, uTag, bBstrWrap);
}

void QCBOREncode_OpenMap_3(QCBOREncodeContext *me, const char *szLabel, uint64_t nLabel, uint64_t uTag, uint8_t bBstrWrap)
{
   OpenMapOrArrayInternal(me, CBOR_MAJOR_TYPE_MAP, szLabel, nLabel, uTag, bBstrWrap);
}

void QCBOREncode_CloseArray(QCBOREncodeContext *me)
{
   if(!Nesting_IsInNest(&(me->nesting))) {
      me->uError = QCBOR_ERR_TOO_MANY_CLOSES;
      
   } else {
      // When the array was opened, nothing was done except note the position
      // of the start of the array. This code goes back and inserts the type
      // (array or map) and length. That means all the data in the array or map
      // and any nested arrays or maps have to be slid right. This is done
      // by UsefulOutBuf's insert function that is called from inside
      // InsertEncodedTypeAndNumber()
      
      const uint32_t uInsertPosition = Nesting_GetStartPos(&(me->nesting));
      
      InsertEncodedTypeAndNumber(me,
                                 Nesting_GetMajorType(&(me->nesting)),  // the major type (array or map)
                                 0,                                     // no minimum length for encoding
                                 Nesting_GetCount(&(me->nesting)),      // number of items in array or map
                                 uInsertPosition);                      // position in output buffer
      
      if(Nesting_IsBstrWrapped(&(me->nesting))) {
         // This map or array is to be wrapped in a byte string. This is typically because
         // the data is to be hashed or cryprographically signed. This is what COSE
         // signing does.
         
         // Cast from size_t to uin32_t is safe because the UsefulOutBuf
         // size is limited to UINT32_MAX in QCBOR_Init().
         uint32_t uLenOfEncodedMapOrArray = (uint32_t)UsefulOutBuf_GetEndPosition(&(me->OutBuf)) - uInsertPosition;
 
         // Insert the bstring wrapping
         InsertEncodedTypeAndNumber(me,
                                    CBOR_MAJOR_TYPE_BYTE_STRING,  // major type bstring
                                    0,                            // no minimum length for encoding
                                    uLenOfEncodedMapOrArray,      // length of the map
                                    uInsertPosition);             // position in out buffer
      }
      
      Nesting_Decrease(&(me->nesting));
   }
}




/*
 Internal function for adding positive and negative integers of all different sizes
 */
static void AddUInt64Internal(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uTag, uint8_t uMajorType, uint64_t n)
{
   AddLabelAndOptionalTag(me, szLabel, nLabel, uTag);
   if(!me->uError) {
      AppendEncodedTypeAndNumber(me, uMajorType, n);
      me->uError = Nesting_Increment(&(me->nesting), 1);
   }
}


/*
 Public functions for adding integers. See header qcbor.h
 */
void QCBOREncode_AddUInt64_3(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uTag, uint64_t uNum)
{
   AddUInt64Internal(me, szLabel, nLabel, uTag, CBOR_MAJOR_TYPE_POSITIVE_INT, uNum);
}

void QCBOREncode_AddInt64_3(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uTag, int64_t nNum)
{
   uint8_t      uMajorType;
   uint64_t     uValue;
   
   // Handle CBOR's particular format for positive and negative integers
   if(nNum < 0) {
      uValue = (uint64_t)(-nNum - 1); // This is the way negative ints work in CBOR. -1 encodes as 0x00 with major type negative int.
      uMajorType = CBOR_MAJOR_TYPE_NEGATIVE_INT;
   } else {
      uValue = (uint64_t)nNum;
      uMajorType = CBOR_MAJOR_TYPE_POSITIVE_INT;
   }
   AddUInt64Internal(me, szLabel, nLabel, uTag, uMajorType, uValue);
}




/*
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
static void AddSimpleInternal(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uTag, size_t uSize, uint64_t uNum)
{
   AddLabelAndOptionalTag(me, szLabel, nLabel,  uTag);
   if(!me->uError) {
      // This function call takes care of endian swapping for the float / double
      InsertEncodedTypeAndNumber(me,
                                 CBOR_MAJOR_TYPE_SIMPLE,  // The major type for floats and doubles
                                 uSize,                   // min size / tells encoder to do it right
                                 uNum,                    // Bytes of the floating point number as a uint
                                 UsefulOutBuf_GetEndPosition(&(me->OutBuf))); // end position for append
      
      me->uError = Nesting_Increment(&(me->nesting), 1);
   }
}


/*
 Public function for adding simple values. See header qcbor.h
 */
void QCBOREncode_AddRawSimple_3(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uTag, uint8_t uSimple)
{
   AddSimpleInternal(me, szLabel, nLabel, uTag, 0, uSimple);
}


/*
 Public function for adding simple values. See header qcbor.h
 */
void QCBOREncode_AddSimple_3(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uTag, uint8_t uSimple)
{
   if(uSimple < CBOR_SIMPLEV_FALSE || uSimple > CBOR_SIMPLEV_UNDEF) {
      me->uError = QCBOR_ERR_BAD_SIMPLE;
   } else {
      QCBOREncode_AddRawSimple_3(me, szLabel, nLabel, uTag, uSimple);
   }
}


/*
 Public functions for floating point numbers. See header qcbor.h
 */
void QCBOREncode_AddFloat_3(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uTag, float fNum)
{
   // Convert the *type* of the data from a float to a uint so the
   // standard integer encoding can work.  This takes advantage
   // of CBOR's indicator for a float being the same as for a 4
   // byte integer too.
   const float *pfNum  = &fNum;
   const uint32_t uNum = *(uint32_t *)pfNum;
      
   AddSimpleInternal(me, szLabel, nLabel, uTag, sizeof(float), uNum);
}

void QCBOREncode_AddDouble_3(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, uint64_t uTag, double dNum)
{
   // see how it is done for floats above
   const double *pdNum = &dNum;
   const uint64_t uNum = *(uint64_t *)pdNum;
   
   AddSimpleInternal(me, szLabel, nLabel, uTag, sizeof(double), uNum);
}




/*
 Public functions to finish and get the encoded result. See header qcbor.h
 */
int QCBOREncode_Finish2(QCBOREncodeContext *me, EncodedCBOR *pEncodedCBOR)
{
   if(me->uError)
      goto Done;
   
   if (Nesting_IsInNest(&(me->nesting))) {
      me->uError = QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN;
      goto Done;
   }
   
   if(UsefulOutBuf_GetError(&(me->OutBuf))) {
      // Stuff didn't fit in the buffer.
      // This check catches this condition for all the appends and inserts so checks aren't needed
      // when the appends and inserts are performed.  And of course UsefulBuf will never
      // overrun the input buffer given to it. No complex analysis of the error handling
      // in this file is needed to know that is true. Just read the UsefulBuf code.
      me->uError = QCBOR_ERR_BUFFER_TOO_SMALL;
      goto Done;
   }
   
   UsefulOutBuf_OutUBuf(&(me->OutBuf), &(pEncodedCBOR->Bytes));
   pEncodedCBOR->uItems = Nesting_GetCount(&(me->nesting));
   
Done:
   return me->uError;
}

int QCBOREncode_Finish(QCBOREncodeContext *me, size_t *puEncodedLen)
{
   EncodedCBOR Enc;
   
   int nReturn = QCBOREncode_Finish2(me, &Enc);
   
   if(nReturn == QCBOR_SUCCESS) {
      *puEncodedLen = Enc.Bytes.len;
   }
   
   return nReturn;
}


