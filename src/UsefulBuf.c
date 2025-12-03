/*==============================================================================
 * Copyright (c) 2016-2018, The Linux Foundation.
 * Copyright (c) 2018-2025, Laurence Lundblade.
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



/*=============================================================================
 FILE:  UsefulBuf.c

 DESCRIPTION:  General purpose input and output buffers

 EDIT HISTORY FOR FILE:

 This section contains comments describing changes made to the module.
 Notice that changes are listed in reverse chronological order.

 when        who          what, where, why
 --------    ----         ---------------------------------------------------
 11/30/2025  llundblade   Add streaming mode.
 02/21/2025  llundblade   Improve magic number to detect lack of initialization.
 02/21/2025  llundblade   Bug fixes to UsefulOutBuf_Compare().
 02/21/2025  llundblade   Rename to UsefulOutBuf_OutSubString().
 08/08/2024  llundblade   Add UsefulOutBuf_SubString().
 21/05/2024  llundblade   Comment formatting and some code tidiness.
 1/7/2024    llundblade   Add UsefulInputBuf_Compare().
 28/02/2022  llundblade   Rearrange UsefulOutBuf_Compare().
 19/11/2023  llundblade   Add UsefulOutBuf_GetOutput().
 19/11/2023  llundblade   Add UsefulOutBuf_Swap().
 19/11/2023  llundblade   Add UsefulOutBuf_Compare().
 19/12/2022  llundblade   Don't pass NULL to memmove when adding empty data.
 4/11/2022   llundblade   Add GetOutPlace and Advance to UsefulOutBuf
 3/6/2021    mcr/llundblade  Fix warnings related to --Wcast-qual
 01/28/2020  llundblade   Refine integer signedness to quiet static analysis.
 01/08/2020  llundblade   Documentation corrections & improved code formatting.
 11/08/2019  llundblade   Re check pointer math and update comments
 3/6/2019    llundblade   Add UsefulBuf_IsValue()
 09/07/17    llundbla     Fix critical bug in UsefulBuf_Find() -- a read off
                          the end of memory when the bytes to find is longer
                          than the bytes to search.
 06/27/17    llundbla     Fix UsefulBuf_Compare() bug. Only affected comparison
                          for < or > for unequal length buffers.  Added
                          UsefulBuf_Set() function.
 05/30/17    llundbla     Functions for NULL UsefulBufs and const / unconst
 11/13/16    llundbla     Initial Version.

 ============================================================================*/

#include "UsefulBuf.h"

/* used to catch use of uninitialized or corrupted UsefulOutBuf */
#define USEFUL_OUT_BUF_MAGIC  (0x0B0F)


/*
 * Public function -- see UsefulBuf.h
 */
UsefulBufC UsefulBuf_CopyOffset(UsefulBuf Dest, size_t uOffset, const UsefulBufC Src)
{
   /* Do this with subtraction so it doesn't give an erroneous
    * result if uOffset + Src.len overflows. Right side is equivalent to
    * uOffset + Src.len > Dest.len
    */
   if(uOffset > Dest.len || Src.len > Dest.len - uOffset) {
      return NULLUsefulBufC;
   }

   memcpy((uint8_t *)Dest.ptr + uOffset, Src.ptr, Src.len);

   return (UsefulBufC){Dest.ptr, Src.len + uOffset};
}


/*
 * Public function -- see UsefulBuf.h
 */
int UsefulBuf_Compare(const UsefulBufC UB1, const UsefulBufC UB2)
{
   /* Use comparisons rather than subtracting lengths to
    * return an int instead of a size_t
    */
   if(UB1.len < UB2.len) {
      return -1;
   } else if (UB1.len > UB2.len) {
      return 1;
   } /* else UB1.len == UB2.len */

   return memcmp(UB1.ptr, UB2.ptr, UB1.len);
}


/*
 * Public function -- see UsefulBuf.h
 */
size_t UsefulBuf_IsValue(const UsefulBufC UB, uint8_t uValue)
{
   if(UsefulBuf_IsNULLOrEmptyC(UB)) {
      /* Not a match */
      return 0;
   }

   const uint8_t * const pEnd = (const uint8_t *)UB.ptr + UB.len;
   for(const uint8_t *p = UB.ptr; p < pEnd; p++) {
      if(*p != uValue) {
         /* Byte didn't match */
         /* Cast from signed to unsigned. Safe because the loop increments.*/
         return (size_t)(p - (const uint8_t *)UB.ptr);
      }
   }

   /* Success. All bytes matched */
   return SIZE_MAX;
}


/*
 * Public function -- see UsefulBuf.h
 */
size_t UsefulBuf_FindBytes(UsefulBufC BytesToSearch, UsefulBufC BytesToFind)
{
   if(BytesToSearch.len < BytesToFind.len) {
      return SIZE_MAX;
   }

   for(size_t uPos = 0; uPos <= BytesToSearch.len - BytesToFind.len; uPos++) {
      UsefulBufC SearchNext;

      SearchNext.ptr = ((const uint8_t *)BytesToSearch.ptr) + uPos;
      SearchNext.len = BytesToFind.len;
      if(!UsefulBuf_Compare(SearchNext, BytesToFind)) {
         return uPos;
      }
   }

   return SIZE_MAX;
}


/*
 * Public function -- see UsefulBuf.h
 */
UsefulBufC
UsefulBuf_SkipLeading(UsefulBufC String, uint8_t uByte)
{
   for(;String.len; String.len--) {
      if(*(const uint8_t *)String.ptr != uByte) {
         break;
      }
      String.ptr = (const uint8_t *)String.ptr + 1;
   }

   return String;
}



/*
 * Public function -- see UsefulBuf.h
 *
 * Code Reviewers: THIS FUNCTION DOES POINTER MATH
 */
void UsefulOutBuf_Init(UsefulOutBuf *pMe, UsefulBuf Storage)
{
    pMe->magic  = USEFUL_OUT_BUF_MAGIC;
#ifndef USEFULBUF_DISABLE_STREAMING
   pMe->pfFlush = NULL;
#endif /* ! USEFULBUF_DISABLE_STREAMING */
    UsefulOutBuf_Reset(pMe);
    pMe->UB     = Storage;

#if 0
   /* This check is off by default.
    *
    * The following check fails on ThreadX
    *
    * Sanity check on the pointer and size to be sure we are not
    * passed a buffer that goes off the end of the address space.
    * Given this test, we know that all unsigned lengths less than
    * me->size are valid and won't wrap in any pointer additions
    * based off of pStorage in the rest of this code.
    */
    const uintptr_t ptrM = UINTPTR_MAX - Storage.len;
    if(Storage.ptr && (uintptr_t)Storage.ptr > ptrM) /* Check #0 */
        me->err = 1;
#endif
}


/*
 * Public function -- see UsefulBuf.h
 *
 * The core of UsefulOutBuf -- put some bytes in the buffer without writing off
 *                             the end of it.
 *
 * Code Reviewers: THIS FUNCTION DOES POINTER MATH
 *
 * This function inserts the source buffer, NewData, into the destination
 * buffer, me->UB.ptr.
 *
 * Destination is represented as:
 *   me->UB.ptr -- start of the buffer
 *   me->UB.len -- size of the buffer UB.ptr
 *   me->data_len -- length of value data in UB
 *
 * Source is data:
 *   NewData.ptr -- start of source buffer
 *   NewData.len -- length of source buffer
 *
 * Insertion point:
 *   uInsertionPos.
 *
 * Steps:
 *
 * 0. Corruption checks on UsefulOutBuf
 *
 * 1. Figure out if the new data will fit or not
 *
 * 2. Is insertion position in the range of valid data?
 *
 * 3. If insertion point is not at the end, slide data to the right of the
 *    insertion point to the right
 *
 * 4. Put the new data in at the insertion position.
 *
 */
void UsefulOutBuf_InsertUsefulBuf(UsefulOutBuf *pMe, UsefulBufC NewData, size_t uInsertionPos)
{
   if(pMe->err) {
      /* Already in error state. */
      return;
   }

   /* 0. Sanity check the UsefulOutBuf structure
    * A "counter measure". If magic number is not the right number it
    * probably means pMe was not initialized or it was corrupted. Attackers
    * can defeat this, but it is a hurdle and does good with very
    * little code.
    */
   if(pMe->magic != USEFUL_OUT_BUF_MAGIC) {
      /* Magic number is wrong due to uninitalization or corruption */
      pMe->err = UsefulBufErr_BadState;
      return;
   }

#ifndef USEFULBUF_DISABLE_STREAMING
   if(pMe->pfFlush != NULL) {
      /* Can't do inserts in streaming mode */
      pMe->err = UsefulBufErr_IsStreaming;
      return;
   }
#endif /* ! USEFULBUF_DISABLE_STREAMING */

   /* Make sure valid data is less than buffer size. This would only occur
    * if there was corruption of me, but it is also part of the checks to
    * be sure there is no pointer arithmatic under/overflow.
    */
   if(pMe->data_len > pMe->UB.len) {  /* Check #1 */
      /* Offset of valid data is off the end of the UsefulOutBuf due to
       * uninitialization or corruption. */
      pMe->err = UsefulBufErr_BadState;
      return;
   }

   /* 1. Will it fit?
    * WillItFit() is the same as: NewData.len <= (me->UB.len - me->data_len)
    * Check #1 makes sure subtraction in RoomLeft will not wrap around
    */
   if(! UsefulOutBuf_WillItFit(pMe, NewData.len)) { /* Check #2 */
      /* The new data will not fit into the the buffer. */
      pMe->err = UsefulBuffErr_Full;
      return;
   }

   /* 2. Check the Insertion Position
    * This, with Check #1, also confirms that uInsertionPos <= me->data_len and
    * that uInsertionPos + pMe->UB.ptr will not wrap around the end of the
    * address space.
    */
   if(uInsertionPos > pMe->data_len) { /* Check #3 */
      /* Off the end of the valid data in the buffer. */
      pMe->err = UsefulBuffErr_InsertPoint;
      return;
   }


   if ( ! UsefulOutBuf_IsBufferNULL(pMe)) {
      uint8_t *pSourceOfMove      = ((uint8_t *)pMe->UB.ptr) + uInsertionPos; /* PtrMath #1 */
      size_t   uNumBytesToMove    = pMe->data_len - uInsertionPos; /* PtrMath #2 */
      uint8_t *pDestinationOfMove = pSourceOfMove + NewData.len; /* PtrMath #3*/

      /* 3. Slide existing data to the right */
      /* To know memmove won't go off end of destination, see PtrMath #4.
       * Use memove because it handles overlapping buffers
       */
      memmove(pDestinationOfMove, pSourceOfMove, uNumBytesToMove);

      /* 4. Put the new data in */
      uint8_t *pInsertionPoint = pSourceOfMove;
      /* To know memmove won't go off end of destination, see PtrMath #5 */
      if(NewData.ptr != NULL) {
         memmove(pInsertionPoint, NewData.ptr, NewData.len);
      }
   }

   pMe->data_len += NewData.len;
}


/*
 * Rationale that describes why the above pointer math is safe
 *
 * PtrMath #1 will never wrap around over because
 *   Check #0 in UsefulOutBuf_Init that me->UB.ptr + me->UB.len doesn't wrap
 *   Check #1 makes sure me->data_len is less than me->UB.len
 *   Check #3 makes sure uInsertionPos is less than me->data_len
 *
 * PtrMath #2 will never wrap around under because
 *   Check #3 makes sure uInsertionPos is less than me->data_len
 *
 * PtrMath #3 will never wrap around over because
 *   PtrMath #1 is checked resulting in pSourceOfMove being between me->UB.ptr and me->UB.ptr + me->data_len
 *   Check #2 that NewData.len will fit in the unused space left in me->UB
 *
 * PtrMath #4 will never wrap under because
 *   Calculation for extent or memmove is uRoomInDestination  = me->UB.len - (uInsertionPos + NewData.len)
 *   Check #3 makes sure uInsertionPos is less than me->data_len
 *   Check #3 allows Check #2 to be refactored as NewData.Len > (me->size - uInsertionPos)
 *   This algebraically rearranges to me->size > uInsertionPos + NewData.len
 *
 * PtrMath #5 will never wrap under because
 *   Calculation for extent of memove is uRoomInDestination = me->UB.len - uInsertionPos;
 *   Check #1 makes sure me->data_len is less than me->size
 *   Check #3 makes sure uInsertionPos is less than me->data_len
 *
 * PtrMath #10 will never wrap negative because
 *    Check #10.
 *
 * PtrMath #11 will exceed NewData.len because:
 *   Check #11
 *
 * PtrMath #12 will never exceed UB.len because:
 *   Check #12 (effectively the same as #1)
 *
 * PtrMath #13
 *   The destination of move is validated by check #12
 *   The source of the move is validated by check #11
 *   The length of the move is validated by
 *     - uAmountToAppend is never greater than uRoomLeft because of Check #10, making sure it is never off end of UB.ptr
 *     - uAmountToAppend is never greater than NewData.Len because of check #11 making sure it is never off the end of NewData.ptr
 *
 * PtrMath #14
 *   Check #10
 *   Check #11
 *
 * PtrMath #15
 *   uRoomLeft is always < UB.len because of call to RoomLeft()
 *   uAmountToAppend is always less than uRoomLeft because of #10
 */


/*
 * Public function for advancing data length. See qcbor/UsefulBuf.h
 */
void UsefulOutBuf_Advance(UsefulOutBuf *pMe, size_t uAmount)
{
   /* This function is a trimmed down version of
    * UsefulOutBuf_InsertUsefulBuf(). This could be combined with the
    * code in UsefulOutBuf_InsertUsefulBuf(), but that would make
    * UsefulOutBuf_InsertUsefulBuf() bigger and this will be very
    * rarely used.
    */

   if(pMe->err) {
      /* Already in error state. */
      return;
   }

   /* 0. Sanity check the UsefulOutBuf structure
    *
    * A "counter measure". If magic number is not the right number it
    * probably means me was not initialized or it was
    * corrupted. Attackers can defeat this, but it is a hurdle and
    * does good with very little code.
    */
   if(pMe->magic != USEFUL_OUT_BUF_MAGIC) {
      /* Magic number is wrong due to uninitalization or corrption */
      pMe->err = UsefulBufErr_BadState;
      return;
   }

   /* Make sure valid data is less than buffer size. This would only
    * occur if there was corruption of me, but it is also part of the
    * checks to be sure there is no pointer arithmatic
    * under/overflow.
    */
   if(pMe->data_len > pMe->UB.len) {  /* Check #1 */
      /* Offset of valid data is off the end of the UsefulOutBuf due
       * to uninitialization or corruption. */
      pMe->err = UsefulBufErr_BadState;
      return;
   }

   /* 1. Will it fit?
    *
    * WillItFit() is the same as: NewData.len <= (me->UB.len -
    * me->data_len) Check #1 makes sure subtraction in RoomLeft will
    * not wrap around
    */
   if(! UsefulOutBuf_WillItFit(pMe, uAmount)) { /* Check #2 */
      /* The new data will not fit into the the buffer. */
      pMe->err = UsefulBuffErr_Full;
      return;
   }

   pMe->data_len += uAmount;
}


#ifndef USEFULBUF_DISABLE_STREAMING

/*
 * Public function -- see UsefulBuf.h
 */
void
UsefulOutBuf_AppendUsefulBuf(UsefulOutBuf *pMe, UsefulBufC NewData)
{
   size_t       uNewDataCurrentOffset;
   size_t       uAmountToAppend;
   size_t       uRoomLeft;
   const void  *pNewDataCopyStart;
   void        *pAppendPosition;

   if(pMe->err) {
      /* Already in error state. */
      return;
   }

   /* 0. Sanity check the UsefulOutBuf structure
    *
    * A "counter measure". If magic number is not the right number it
    * probably means pMe was not initialized or it was
    * corrupted. Attackers can defeat this, but it is a hurdle and
    * does good with very little code.
    */
   if(pMe->magic != USEFUL_OUT_BUF_MAGIC) {
      pMe->err = UsefulBufErr_BadState;
      return;  /* Magic number is wrong due to uninitalization or corrption */
   }


   /* Loop because the bytes to append might be more than the buffer can hold */
   for(uNewDataCurrentOffset = 0; uNewDataCurrentOffset < NewData.len;) { /* Check #11 */
      uRoomLeft = UsefulOutBuf_RoomLeft(pMe);

      if((NewData.len - uNewDataCurrentOffset) <= uRoomLeft) { /* Check #10 */
         /* All the new data will fit in space remaining in buffer */
         uAmountToAppend = (NewData.len - uNewDataCurrentOffset); /* PtrMath #10 */
      } else {
         /* The new data won't fit in the buffer */
         if(pMe->pfFlush != NULL) {
            /* In streaming mode, just copy what will fit. */
            uAmountToAppend = uRoomLeft;
         } else {
            /* Non-streaming mode this is an error */
            pMe->err = UsefulBuffErr_Full;
            return;
         }
      }
      pNewDataCopyStart = (const uint8_t *)NewData.ptr + uNewDataCurrentOffset; /* PtrMath #11 */

      if( ! UsefulOutBuf_IsBufferNULL(pMe) && NewData.ptr != NULL) {
         if(pMe->data_len > pMe->UB.len) { /* Check #12 */
            /* This check is strictly not necessary as the rest of the
             * checks and correctness of pointer math will result in
             * this never happening, but it is inexpensive and provides
             * a nice secondary defense against corruption of pMe. */
            pMe->err = UsefulBufErr_BadState;
            /* Offset of valid data is off the end of the UsefulOutBuf due
             * to uninitialization or corruption. */
            return;
         }
         pAppendPosition = (uint8_t *)pMe->UB.ptr + pMe->data_len; /* PtrMath #12 */

         /* could use memcpy here, but afraid it is a banned function for some */
         /* PtrMath #13 */
         memmove(pAppendPosition, pNewDataCopyStart, uAmountToAppend);
      }

      pMe->data_len         += uAmountToAppend; /* PtrMath #14 */
      uNewDataCurrentOffset += uAmountToAppend; /* PtrMath #5 */

      if(pMe->pfFlush != NULL && pMe->data_len == pMe->UB.len) {
         UsefulOutBuf_Flush(pMe);
         if(pMe->err) {
            return;
         }
      }
   }
}


/*
 * Public function -- see UsefulBuf.h
 */
void
UsefulOutBuf_Flush(UsefulOutBuf *pMe)
{
   UsefulBufC BytesToFlush;
   int        nFlushErr;

   if(pMe->err) {
      return;
   }

   if(pMe->pfFlush == NULL) {
      return;
   }

   BytesToFlush = (UsefulBufC){pMe->UB.ptr, pMe->data_len};
   nFlushErr = (*pMe->pfFlush)(pMe->pFlushCtx, BytesToFlush);
   if(nFlushErr) {
      pMe->err = UsefulBufErr_FlushWrite;
   } else {
      pMe->data_len = 0;
   }
}


/*
 * Public function -- see UsefulBuf.h
 */
void
UsefulOutBuf_AppendDirect(UsefulOutBuf *pMe, UsefulBufC Bytes)
{
   int        nFlushErr;

   UsefulOutBuf_Flush(pMe);
   if(pMe->err == 0) {
      if(pMe->pfFlush == NULL) {
         pMe->err = UsefulBufErr_NotStreaming;
         return;
      }

      nFlushErr = (*pMe->pfFlush)(pMe->pFlushCtx, Bytes);
      if(nFlushErr) {
         pMe->err = UsefulBufErr_FlushWrite;
      }
   }
}

#endif /* ! USEFULBUF_DISABLE_STREAMING */





/*
 * Public function -- see UsefulBuf.h
 */
// TODO: inline and rearrange (one check of pMe->err) to make QCBOR_Finish much smaller?
UsefulBufC UsefulOutBuf_OutUBuf(UsefulOutBuf *pMe)
{
   if(pMe->magic != USEFUL_OUT_BUF_MAGIC) {
      pMe->err = UsefulBufErr_BadState;
   }

   if(pMe->err) {
      return NULLUsefulBufC;
   }

   return (UsefulBufC){pMe->UB.ptr, pMe->data_len};
}


/*
 * Public function -- see UsefulBuf.h
 *
 * Copy out the data accumulated in to the output buffer.
 */
UsefulBufC UsefulOutBuf_CopyOut(UsefulOutBuf *pMe, UsefulBuf pDest)
{
   const UsefulBufC Tmp = UsefulOutBuf_OutUBuf(pMe);
   if(UsefulBuf_IsNULLC(Tmp)) {
      return NULLUsefulBufC;
   }
   return UsefulBuf_Copy(pDest, Tmp);
}


/*
 * Public function -- see UsefulBuf.h
 *
 * Code Reviewers: THIS FUNCTION DOES POINTER MATH
 */
UsefulBufC UsefulOutBuf_OutSubString(UsefulOutBuf *pMe,
                                     const size_t  uStart,
                                     const size_t  uLen)
{
   const UsefulBufC Tmp = UsefulOutBuf_OutUBuf(pMe);

   if(UsefulBuf_IsNULLC(Tmp)) {
      return NULLUsefulBufC;
   }

   if(uStart > Tmp.len) {
      return NULLUsefulBufC;
   }

   if(Tmp.len - uStart < uLen) {
      return NULLUsefulBufC;
   }

   UsefulBufC SubString;
   SubString.ptr = (const uint8_t *)Tmp.ptr + uStart;
   SubString.len = uLen;

   return SubString;
}


/*
 * Public function -- see UsefulBuf.h
 *
 * The core of UsefulInputBuf -- consume bytes without going off end of buffer.
 *
 * Code Reviewers: THIS FUNCTION DOES POINTER MATH
 */
const void * UsefulInputBuf_GetBytes(UsefulInputBuf *pMe, size_t uAmount)
{
   /* Already in error state. Do nothing. */
   if(pMe->err) {
      return NULL;
   }

   if(!UsefulInputBuf_BytesAvailable(pMe, uAmount)) {
      /* Number of bytes asked for is more than available */
      pMe->err = 1;
      return NULL;
   }

   /* This is going to succeed */
   const void * const result = ((const uint8_t *)pMe->UB.ptr) + pMe->cursor;
   /* Won't overflow because of check using UsefulInputBuf_BytesAvailable() */
   pMe->cursor += uAmount;
   return result;
}


/*
 * Public function -- see UsefulBuf.h
 *
 * Code Reviewers: THIS FUNCTION DOES POINTER MATH
 */
int
UsefulInputBuf_Compare(UsefulInputBuf *pUInBuf,
                       const size_t    uOffset1,
                       const size_t    uLen1,
                       const size_t    uOffset2,
                       const size_t    uLen2)
{
   UsefulBufC UB1;
   UsefulBufC UB2;

   const size_t uInputSize = UsefulInputBuf_GetBufferLength(pUInBuf);

   /* Careful length check that works even if uLen1 + uOffset1 > SIZE_MAX */
   if(uOffset1 > uInputSize || uLen1 > uInputSize - uOffset1) {
      return 1;
   }
   UB1.ptr = (const uint8_t *)pUInBuf->UB.ptr + uOffset1;
   UB1.len = uLen1;

   /* Careful length check that works even if uLen2 + uOffset2 > SIZE_MAX */
   if(uOffset2 > uInputSize || uLen2 > uInputSize - uOffset2) {
      return -1;
   }
   UB2.ptr = (const uint8_t *)pUInBuf->UB.ptr + uOffset2;
   UB2.len = uLen2;

   return UsefulBuf_Compare(UB1, UB2);
}


/*
 * Public function -- see UsefulBuf.h
 *
 * Code Reviewers: THIS FUNCTION DOES POINTER MATH
 */
int UsefulOutBuf_Compare(UsefulOutBuf *pMe,
                         const size_t uStart1, const size_t uLen1,
                         const size_t uStart2, const size_t uLen2)
{
   const uint8_t *pBase;
   const uint8_t *pEnd;
   const uint8_t *p1;
   const uint8_t *p2;
   const uint8_t *p1Start;
   const uint8_t *p2Start;
   const uint8_t *p1End;
   const uint8_t *p2End;
   int            uComparison;
   size_t         uComparedLen1;
   size_t         uComparedLen2;

   pBase   = pMe->UB.ptr;
   pEnd    = (const uint8_t *)pBase + pMe->data_len;
   p1Start = pBase + uStart1;
   p2Start = pBase + uStart2;
   p1End   = p1Start + uLen1;
   p2End   = p2Start + uLen2;

   uComparison = 0;
   for(p1 = p1Start, p2 = p2Start;
       p1 < pEnd && p2 < pEnd && p1 < p1End && p2 < p2End;
       p1++, p2++) {
      uComparison = *p2 - *p1;
      if(uComparison != 0) {
         break;
      }
   }

   /* Loop might have terminated because strings were off
    * the end of the buffer. Compute actual lengths compared.
    */
   uComparedLen1 = uLen1;
   if(p1 >= pEnd) {
      uComparedLen1 = (size_t)(p1 - p1Start);
   }
   uComparedLen2 = uLen2;
   if(p2 >= pEnd) {
      uComparedLen2 = (size_t)(p2 - p2Start);
   }

   if(uComparison == 0) {
      /* All bytes were equal, now check the lengths */
      if(uComparedLen2 > uComparedLen1) {
         /* string 1 is a substring of string 2 */
         uComparison = 1;
      } else if(uComparedLen1 > uComparedLen2) {
         /* string 2 is a substring of string 1 */
         uComparison = -1;
      } else {
         /* do nothing, uComparison already is 0 */
      }
   }

   return uComparison;
}



/**
 * @brief Reverse order of bytes in a buffer.
 *
 * This reverses bytes starting at pStart, up to, but not including
 * the byte at pEnd
 */
static void
UsefulOutBuf_Private_ReverseBytes(uint8_t *pStart, uint8_t *pEnd)
{
   uint8_t uTmp;

   while(pStart < pEnd) {
      pEnd--;
      uTmp    = *pStart;
      *pStart = *pEnd;
      *pEnd   = uTmp;
      pStart++;
   }
}


/*
 * Public function -- see UsefulBuf.h
 *
 * Code Reviewers: THIS FUNCTION DOES POINTER MATH
 */
void UsefulOutBuf_Swap(UsefulOutBuf *pMe, size_t uStartOffset, size_t uPivotOffset, size_t uEndOffset)
{
   uint8_t *pBase;

   if(uStartOffset > pMe->data_len || uPivotOffset > pMe->data_len || uEndOffset > pMe->data_len) {
      return;
   }

   if(uStartOffset > uPivotOffset || uStartOffset > uEndOffset || uPivotOffset > uEndOffset) {
      return;
   }

   /* This is the "reverse" algorithm to swap two memory regions */
   pBase = pMe->UB.ptr;
   UsefulOutBuf_Private_ReverseBytes(pBase + uStartOffset, pBase + uPivotOffset);
   UsefulOutBuf_Private_ReverseBytes(pBase + uPivotOffset, pBase + uEndOffset);
   UsefulOutBuf_Private_ReverseBytes(pBase + uStartOffset, pBase + uEndOffset);
}


/*
 * Public function -- see UsefulBuf.h
 */
UsefulBufC
UsefulOutBuf_OutUBufOffset(UsefulOutBuf *pMe, size_t uOffset)
{
   UsefulBufC ReturnValue;

   ReturnValue = UsefulOutBuf_OutUBuf(pMe);

   if(UsefulBuf_IsNULLC(ReturnValue)) {
      return NULLUsefulBufC;
   }

   if(uOffset >= ReturnValue.len) {
      return NULLUsefulBufC;
   }

   ReturnValue.ptr = (const uint8_t *)ReturnValue.ptr + uOffset;
   ReturnValue.len -= uOffset;

   return ReturnValue;
}
