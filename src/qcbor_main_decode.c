/* ===========================================================================
 * qcbor_main_decode.h -- The main CBOR decoder.
 *
 * Copyright (c) 2016-2018, The Linux Foundation.
 * Copyright (c) 2018-2025, Laurence Lundblade.
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

#include "qcbor/qcbor_main_decode.h"
#include "ieee754.h" /* Does not use math.h */
#include "decode_nesting.h"

#include "qcbor/qcbor_tag_decode.h"


#if (defined(__GNUC__) && !defined(__clang__))
/*
 * This is how the -Wmaybe-uninitialized compiler warning is
 * handled. It can’t be ignored because some version of gcc enable it
 * with -Wall which is a common and useful gcc warning option. It also
 * can’t be ignored because it is the goal of QCBOR to compile clean
 * out of the box in all environments.
 *
 * The big problem with -Wmaybe-uninitialized is that it generates
 * false positives. It complains things are uninitialized when they
 * are not. This is because it is not a thorough static analyzer. This
 * is why “maybe” is in its name. The problem is it is just not
 * thorough enough to understand all the code (and someone saw fit to
 * put it in gcc and worse to enable it with -Wall).
 *
 * One solution would be to change the code so -Wmaybe-uninitialized
 * doesn’t get confused, for example adding an unnecessary extra
 * initialization to zero. (If variables were truly uninitialized, the
 * correct path is to understand the code thoroughly and set them to
 * the correct value at the correct time; in essence this is already
 * done; -Wmaybe-uninitialized just can’t tell). This path is not
 * taken because it makes the code bigger and is kind of the tail
 * wagging the dog.
 *
 * The solution here is to just use a pragma to disable it for the
 * whole file. Disabling it for each line makes the code fairly ugly
 * requiring #pragma to push, pop and ignore. Another reason is the
 * warnings issues vary by version of gcc and which optimization
 * optimizations are selected. Another reason is that compilers other
 * than gcc don’t have -Wmaybe-uninitialized.
 *
 * One may ask how to be sure these warnings are false positives and
 * not real issues. 1) The code has been read carefully to check. 2)
 * Testing is pretty thorough. 3) This code has been run through
 * thorough high-quality static analyzers.
 *
 * In particularly, most of the warnings are about
 * Item.Item->uDataType being uninitialized. QCBORDecode_GetNext()
 * *always* sets this value and test case confirm
 * this. -Wmaybe-uninitialized just can't tell.
 *
 * https://stackoverflow.com/questions/5080848/disable-gcc-may-be-used-uninitialized-on-a-particular-variable
 */
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif


/* Embed a version string in the library */
const char libqcborVersionDecode[] = QCBOR_VERSION_STRING;


static bool
QCBORItem_IsMapOrArray(const QCBORItem Item)
{
   const uint8_t uDataType = Item.uDataType;
   return uDataType == QCBOR_TYPE_MAP ||
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
          uDataType == QCBOR_TYPE_MAP_AS_ARRAY ||
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */
          uDataType == QCBOR_TYPE_ARRAY;
}

/* This must be called on a map or array */
static bool
QCBORItem_IsEmptyDefiniteLengthMapOrArray(const QCBORItem Item)
{
   /* This check is disabled because this is always called on map or array
   if(!QCBORItem_IsMapOrArray(Item)){
      return false;
   } */


   if(Item.val.uCount != 0) {
      return false;
   }
   return true;
}

/* This must be called on a map or array */
static bool
QCBORItem_IsIndefiniteLengthMapOrArray(const QCBORItem Item)
{
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
   /* This check is disabled because this is always called on map or array
   if(!QCBORItem_IsMapOrArray(Item)){
      return false;
   } */

   if(Item.val.uCount != QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH) {
      return false;
   }
   return true;
#else /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
   (void)Item;
   return false;
#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
}




#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
/*===========================================================================
   QCBORStringAllocate -- STRING ALLOCATOR INVOCATION

   The following four functions are pretty wrappers for invocation of
   the string allocator supplied by the caller.

  ===========================================================================*/

static void
StringAllocator_Free(const QCBORInternalAllocator *pMe, const void *pMem)
{
   /* This cast to uintptr_t suppresses the "-Wcast-qual" warnings.
    * This is the one place where the const needs to be cast away so const can
    * be use in the rest of the code.
    */
   (pMe->pfAllocator)(pMe->pAllocateCxt, (void *)(uintptr_t)pMem, 0);
}

// StringAllocator_Reallocate called with pMem NULL is
// equal to StringAllocator_Allocate()
static UsefulBuf
StringAllocator_Reallocate(const QCBORInternalAllocator *pMe,
                           const void *pMem,
                           size_t uSize)
{
   /* See comment in StringAllocator_Free() */
   return (pMe->pfAllocator)(pMe->pAllocateCxt, (void *)(uintptr_t)pMem, uSize);
}

static UsefulBuf
StringAllocator_Allocate(const QCBORInternalAllocator *pMe, size_t uSize)
{
   return (pMe->pfAllocator)(pMe->pAllocateCxt, NULL, uSize);
}

static void
StringAllocator_Destruct(const QCBORInternalAllocator *pMe)
{
   /* See comment in StringAllocator_Free() */
   if(pMe->pfAllocator) {
      (pMe->pfAllocator)(pMe->pAllocateCxt, NULL, 0);
   }
}
#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */




/*===========================================================================
 QCBORDecode -- The main implementation of CBOR decoding

 See qcbor/qcbor_main_decode.h for definition of the object
 used here: QCBORDecodeContext
  ===========================================================================*/

/* Public function; see qcbor_main_decode.h */
void
QCBORDecode_Init(QCBORDecodeContext *pMe,
                 UsefulBufC          EncodedCBOR,
                 QCBORDecodeMode     uConfigFlags)
{
   memset(pMe, 0, sizeof(QCBORDecodeContext));
   UsefulInputBuf_Init(&(pMe->InBuf), EncodedCBOR);
   /* Don't bother with error check on decode mode. If a bad value is
    * passed it will just act as if the default normal mode of 0 was set.
    */
   pMe->uDecodeMode = (uint32_t)uConfigFlags;
   DecodeNesting_Init(&(pMe->nesting));

   /* Inialize me->auMappedTagNumbers to CBOR_TAG_INVALID16. See
    * QCBORDecode_Private_GetNextTagNumber() and
    * QCBORDecode_Private_MapTagNumber(). */
   memset(pMe->auMappedTagNumbers, 0xff, sizeof(pMe->auMappedTagNumbers));

   pMe->uTagNumberCheckOffset = SIZE_MAX;
}




/*
 * Decoding items is done in six layers, one calling the next one
 * down. If a layer has no work to do for a particular item, it
 * returns quickly.
 *
 * 1. QCBORDecode_Private_GetNextTagContent - The top layer processes
 * tagged data items, turning them into the local C representation.
 * For the most simple it is just associating a QCBOR_TYPE with the
 * data. For the complex ones that an aggregate of data items, there
 * is some further decoding and some limited recursion.
 *
 * 2. QCBORDecode_Private_GetNextMapOrArray - This manages the
 * beginnings and ends of maps and arrays. It tracks descending into
 * and ascending out of maps/arrays. It processes breaks that
 * terminate indefinite-length maps and arrays.
 *
 * 3. QCBORDecode_Private_GetNextMapEntry - This handles the combining
 * of two items, the label and the data, that make up a map entry.  It
 * only does work on maps. It combines the label and data items into
 * one labeled item.
 *
 * 4. QCBORDecode_Private_GetNextTagNumber - This decodes type 6 tag
 * numbers. It turns the tag numbers into bit flags associated with
 * the data item. No actual decoding of the contents of the tag is
 * performed here.
 *
 * 5. QCBORDecode_Private_GetNextFullString - This assembles the
 * sub-items that make up an indefinite-length string into one string
 * item. It uses the string allocator to create contiguous space for
 * the item. It processes all breaks that are part of
 * indefinite-length strings.
 *
 * 6. QCBOR_Private_DecodeAtomicDataItem - This decodes the atomic
 * data items in CBOR. Each atomic data item has a "major type", an
 * integer "argument" and optionally some content. For text and byte
 * strings, the content is the bytes that make up the string. These
 * are the smallest data items that are considered to be well-formed.
 * The content may also be other data items in the case of aggregate
 * types. They are not handled in this layer.
 *
 * This uses about 350 bytes of stack. This number comes from
 * instrumenting (printf address of stack variables) the code on x86
 * compiled for size optimization.
 */


/*
 * Note about use of int and unsigned variables.
 *
 * See http://www.unix.org/whitepapers/64bit.html for reasons int is
 * used carefully here, and in particular why it isn't used in the
 * public interface.  Also see
 * https://stackoverflow.com/questions/17489857/why-is-int-typically-32-bit-on-64-bit-compilers
 *
 * Int is used for values that need 16-bits or less and would be
 * subject to integer promotion and result in complaining from static
 * analyzers.
 */


/**
 * @brief Decode the CBOR head, the type and argument.
 *
 * @param[in] pUInBuf            The input buffer to read from.
 * @param[in] uConfigFlags   Decode mode flags.
 * @param[out] pnMajorType       The decoded major type.
 * @param[out] puArgument        The decoded argument.
 * @param[out] pnAdditionalInfo  The decoded Lower 5 bits of initial byte.
 *
 * @retval QCBOR_ERR_UNSUPPORTED Encountered unsupported/reserved features
 * @retval QCBOR_ERR_HIT_END Unexpected end of input
 *
 * This decodes the CBOR "head" that every CBOR data item has. See
 * longer description in QCBOREncode_EncodeHead().
 *
 * This does the network to host byte order conversion. The conversion
 * here also provides the conversion for floats in addition to that
 * for lengths, tags and integer values.
 *
 * The int type is preferred to uint8_t for some variables as this
 * avoids integer promotions, can reduce code size and makes static
 * analyzers happier.
 */
static QCBORError
QCBOR_Private_DecodeHead(UsefulInputBuf  *pUInBuf,
                         QCBORDecodeMode  uConfigFlags,
                         int             *pnMajorType,
                         uint64_t        *puArgument,
                         int             *pnAdditionalInfo)
{
   QCBORError uReturn;
   uint64_t   uArgument;

   /* Get and break down initial byte that every CBOR data item has */
   const int nInitialByte    = (int)UsefulInputBuf_GetByte(pUInBuf);
   const int nTmpMajorType   = nInitialByte >> 5;
   const int nAdditionalInfo = nInitialByte & 0x1f;

   if(nAdditionalInfo >= LEN_IS_ONE_BYTE && nAdditionalInfo <= LEN_IS_EIGHT_BYTES) {
      /* Need to get 1,2,4 or 8 additional argument bytes. Map
       * LEN_IS_ONE_BYTE..LEN_IS_EIGHT_BYTES to actual length.
       */
      static const uint8_t aIterate[] = {1,2,4,8};

      /* Loop getting all the bytes in the argument */
      uArgument = 0;
      for(int i = aIterate[nAdditionalInfo - LEN_IS_ONE_BYTE]; i; i--) {
         /* This shift-and-add gives the endian conversion. */
         uArgument = (uArgument << 8) + UsefulInputBuf_GetByte(pUInBuf);
      }

#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
      /* If requested, check that argument is in preferred form */
      if(uConfigFlags & QCBOR_DECODE_ONLY_PREFERRED_NUMBERS) {
         uint64_t uMinArgument;

         if(nAdditionalInfo == LEN_IS_ONE_BYTE) {
            if(uArgument < 24) {
               uReturn = QCBOR_ERR_PREFERRED_CONFORMANCE;
               goto Done;
            }
         } else {
            if(nTmpMajorType != CBOR_MAJOR_TYPE_SIMPLE) {
               /* Check only if not a floating-point number */
               int nArgLen = aIterate[nAdditionalInfo - LEN_IS_ONE_BYTE - 1];
               uMinArgument = UINT64_MAX >> ((int)sizeof(uint64_t) - nArgLen) * 8;
               if(uArgument <= uMinArgument) {
                  uReturn = QCBOR_ERR_PREFERRED_CONFORMANCE;
                  goto Done;
               }
            }
         }
      }
#else
       (void)uConfigFlags;
#endif /* ! QCBOR_DISABLE_DECODE_CONFORMANCE */

   } else if(nAdditionalInfo >= ADDINFO_RESERVED1 && nAdditionalInfo <= ADDINFO_RESERVED3) {
      /* The reserved and thus-far unused additional info values */
      uReturn = QCBOR_ERR_UNSUPPORTED;
      goto Done;
   } else {
#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
      if(uConfigFlags & QCBOR_DECODE_NO_INDEF_LENGTH && nAdditionalInfo == LEN_IS_INDEFINITE) {
         uReturn = QCBOR_ERR_PREFERRED_CONFORMANCE;
         goto Done;
      }
#endif /* ! QCBOR_DISABLE_DECODE_CONFORMANCE */

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
 * @brief Decode integer types, major types 0 and 1.
 *
 * @param[in] nMajorType       The CBOR major type (0 or 1).
 * @param[in] uArgument        The argument from the head.
 * @param[in] nAdditionalInfo  So it can be error-checked.
 * @param[out] pDecodedItem    The filled in decoded item.
 *
 * @retval QCBOR_ERR_INT_OVERFLOW  Too-large negative encountered.
 * @retval QCBOR_ERR_BAD_INT       nAdditionalInfo indicated indefinte.
 *
 * Must only be called when major type is 0 or 1.
 *
 * CBOR doesn't explicitly specify two's compliment for integers but
 * all CPUs use it these days and the test vectors in the RFC are
 * so. All integers in encoded CBOR are unsigned and the CBOR major
 * type indicates positive or negative.  CBOR can express positive
 * integers up to 2^64 - 1 negative integers down to -2^64.  Note that
 * negative numbers can be one more
 * away from zero than positive because there is no negative zero.
 *
 * The "65-bit negs" are values CBOR can encode that can't fit
 * into an int64_t or uint64_t. They decoded as a special type
 * QCBOR_TYPE_65BIT_NEG_INT. Not that this type does NOT
 * take into account the offset of one for CBOR negative integers.
 * It must be applied to get the correct value. Applying this offset
 * would overflow a uint64_t.
 */
static QCBORError
QCBOR_Private_DecodeInteger(const int      nMajorType,
                            const uint64_t uArgument,
                            const int      nAdditionalInfo,
                            QCBORItem     *pDecodedItem)
{
   QCBORError uReturn = QCBOR_SUCCESS;

   if(nAdditionalInfo == LEN_IS_INDEFINITE) {
      uReturn = QCBOR_ERR_BAD_INT;
      goto Done;
   }

   if(nMajorType == CBOR_MAJOR_TYPE_POSITIVE_INT) {
      if(uArgument <= INT64_MAX) {
         pDecodedItem->val.int64 = (int64_t)uArgument;
         pDecodedItem->uDataType = QCBOR_TYPE_INT64;

      } else {
         pDecodedItem->val.uint64 = uArgument;
         pDecodedItem->uDataType  = QCBOR_TYPE_UINT64;
      }

   } else {
      if(uArgument <= INT64_MAX) {
         /* INT64_MIN is one further away from 0 than INT64_MAX
          * so the -1 here doesn't overflow. */
         pDecodedItem->val.int64 = (-(int64_t)uArgument) - 1;
         pDecodedItem->uDataType = QCBOR_TYPE_INT64;

      } else {
         pDecodedItem->val.uint64 = uArgument;
         pDecodedItem->uDataType  = QCBOR_TYPE_65BIT_NEG_INT;
      }
   }

Done:
   return uReturn;
}


/**
 * @brief Decode text and byte strings
 *
 * @param[in] pMe              Decoder context.
 * @param[in] bAllocate        Whether to allocate and copy string.
 * @param[in] nMajorType       Whether it is a byte or text string.
 * @param[in] uStrLen          The length of the string.
 * @param[in] nAdditionalInfo  Whether it is an indefinite-length string.
 * @param[out] pDecodedItem    The filled-in decoded item.
 *
 * @retval QCBOR_ERR_HIT_END          Unexpected end of input.
 * @retval QCBOR_ERR_STRING_ALLOCATE  Out of memory.
 * @retval QCBOR_ERR_STRING_TOO_LONG  String longer than SIZE_MAX - 4.
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR  Allocation requested, but no allocator
 *
 * This reads @c uStrlen bytes from the input and fills in @c
 * pDecodedItem. If @c bAllocate is true, then memory for the string
 * is allocated.
 */
static QCBORError
QCBOR_Private_DecodeString(QCBORDecodeContext  *pMe,
                           const bool           bAllocate,
                           const int            nMajorType,
                           const uint64_t       uStrLen,
                           const int            nAdditionalInfo,
                           QCBORItem           *pDecodedItem)
{
   QCBORError uReturn = QCBOR_SUCCESS;

   /* ---- Figure out the major type ---- */
   #if CBOR_MAJOR_TYPE_BYTE_STRING + 4 != QCBOR_TYPE_BYTE_STRING
   #error QCBOR_TYPE_BYTE_STRING not lined up with major type
   #endif

   #if CBOR_MAJOR_TYPE_TEXT_STRING + 4 != QCBOR_TYPE_TEXT_STRING
   #error QCBOR_TYPE_TEXT_STRING not lined up with major type
   #endif
   pDecodedItem->uDataType = (uint8_t)(nMajorType + 4);

   if(nAdditionalInfo == LEN_IS_INDEFINITE) {
      /* --- Just the head of an indefinite-length string --- */
      pDecodedItem->val.string = (UsefulBufC){NULL, QCBOR_STRING_LENGTH_INDEFINITE};

   } else {
      /* --- A definite-length string --- */
      /* --- (which might be a chunk of an indefinte-length string) --- */

      /* CBOR lengths can be 64 bits, but size_t is not 64 bits on all
       * CPUs.  This check makes the casts to size_t below safe.
       *
       * The max is 4 bytes less than the largest sizeof() so this can be
       * tested by putting a SIZE_MAX length in the CBOR test input (no
       * one will care the limit on strings is 4 bytes shorter).
       */
      if(uStrLen > SIZE_MAX-4) {
         uReturn = QCBOR_ERR_STRING_TOO_LONG;
         goto Done;
      }

      const UsefulBufC Bytes = UsefulInputBuf_GetUsefulBuf(&(pMe->InBuf),
                                                           (size_t)uStrLen);
      if(UsefulBuf_IsNULLC(Bytes)) {
         /* Failed to get the bytes for this string item */
         uReturn = QCBOR_ERR_HIT_END;
         goto Done;
      }

      if(bAllocate) {
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
         /* --- Put string in allocated memory --- */

         /* Note that this is not where allocation to coalesce
          * indefinite-length strings is done. This is for when the
          * caller has requested all strings be allocated. Disabling
          * indefinite length strings also disables this allocate-all
          * option.
          */

         if(pMe->StringAllocator.pfAllocator == NULL) {
            uReturn = QCBOR_ERR_NO_STRING_ALLOCATOR;
            goto Done;
         }
         UsefulBuf NewMem = StringAllocator_Allocate(&(pMe->StringAllocator),
                                                     (size_t)uStrLen);
         if(UsefulBuf_IsNULL(NewMem)) {
            uReturn = QCBOR_ERR_STRING_ALLOCATE;
            goto Done;
         }
         pDecodedItem->val.string = UsefulBuf_Copy(NewMem, Bytes);
         pDecodedItem->uDataAlloc = 1;
#else /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
         uReturn = QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED;
#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
      } else {
         /* --- Normal case with no string allocator --- */
         pDecodedItem->val.string = Bytes;
      }
   }

Done:
   return uReturn;
}


/**
 * @brief Decode array or map.
 *
 * @param[in] uConfigFlags            Decoder mode.
 * @param[in] nMajorType       Whether it is a byte or text string.
 * @param[in] uItemCount       The length of the string.
 * @param[in] nAdditionalInfo  Whether it is an indefinite-length.
 * @param[out] pDecodedItem    The filled-in decoded item.
 *
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED Indefinites disabled.
 * @retval QCBOR_ERR_ARRAY_DECODE_TOO_LONG     Too many items in array/map.
 *
 * Not much to do for arrays and maps. Just the type item count (but a
 * little messy because of ifdefs for indefinite-lengths and
 * map-as-array decoding).
 *
 * This also does the bulk of the work for @ref
 * QCBOR_DECODE_MODE_MAP_AS_ARRAY, a special mode to handle
 * arbitrarily complex map labels. This ifdefs out with
 * QCBOR_DISABLE_NON_INTEGER_LABELS.
 */
static QCBORError
QCBOR_Private_DecodeArrayOrMap(const QCBORDecodeMode  uConfigFlags,
                               const int              nMajorType,
                               uint64_t               uItemCount,
                               const int              nAdditionalInfo,
                               QCBORItem             *pDecodedItem)
{
   QCBORError uReturn;

   /* ------ Sort out the data type ------ */
   #if QCBOR_TYPE_ARRAY != CBOR_MAJOR_TYPE_ARRAY
   #error QCBOR_TYPE_ARRAY value not lined up with major type
   #endif

   #if QCBOR_TYPE_MAP != CBOR_MAJOR_TYPE_MAP
   #error QCBOR_TYPE_MAP value not lined up with major type
   #endif
   pDecodedItem->uDataType = (uint8_t)nMajorType;
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   if((uConfigFlags & QCBOR_DECODE_MODE_MAP_AS_ARRAY) && nMajorType == QCBOR_TYPE_MAP) {
      pDecodedItem->uDataType = QCBOR_TYPE_MAP_AS_ARRAY;
   }
#else
   (void)uConfigFlags;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */

   uReturn = QCBOR_SUCCESS;

   if(nAdditionalInfo == LEN_IS_INDEFINITE) {
      /* ------ Indefinite-length array/map ----- */
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
      pDecodedItem->val.uCount = QCBOR_COUNT_INDICATES_INDEFINITE_LENGTH;
#else /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
      uReturn = QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED;
#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
   } else {
      /* ----- Definite-length array/map ----- */
      if(uItemCount > (nMajorType == QCBOR_TYPE_MAP ? QCBOR_MAX_ITEMS_IN_MAP : QCBOR_MAX_ITEMS_IN_ARRAY)) {
         uReturn = QCBOR_ERR_ARRAY_DECODE_TOO_LONG;

      } else {
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
         if((uConfigFlags & QCBOR_DECODE_MODE_MAP_AS_ARRAY) && nMajorType == QCBOR_TYPE_MAP) {
            /* ------ Map as array ------ */
            uItemCount *= 2;
         }
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */

         /* cast OK because of check above */
         pDecodedItem->val.uCount = (uint16_t)uItemCount;
      }
   }

   return uReturn;
}


/**
 * @brief Decode a tag number.
 *
 * @param[in] uTagNumber       The length of the string.
 * @param[in] nAdditionalInfo  So this can be error-checked.
 * @param[out] pDecodedItem    The filled-in decoded item.
 *
 * @retval QCBOR_ERR_BAD_INT        nAdditionalInfo is LEN_IS_INDEFINITE.
 * @retval QCBOR_ERR_TAGS_DISABLED  QCBOR_DISABLE_TAGS is defined.
 *
 * Not much to do for tags, but fill in pDecodedItem and check for
 * error in nAdditionalInfo.
 */
static QCBORError
QCBOR_Private_DecodeTagNumber(const uint64_t uTagNumber,
                              const int      nAdditionalInfo,
                              QCBORItem     *pDecodedItem)
{
#ifndef QCBOR_DISABLE_TAGS
   if(nAdditionalInfo == LEN_IS_INDEFINITE) {
      return QCBOR_ERR_BAD_INT;
   } else {
      pDecodedItem->val.uTagNumber = uTagNumber;
      pDecodedItem->uDataType = QCBOR_TYPE_TAG_NUMBER;
      return QCBOR_SUCCESS;
   }
#else /* ! QCBOR_DISABLE_TAGS */
   (void)nAdditionalInfo;
   (void)uTagNumber;
   (void)pDecodedItem;
   return QCBOR_ERR_TAGS_DISABLED;
#endif /* ! QCBOR_DISABLE_TAGS */
}


#ifndef USEFULBUF_DISABLE_ALL_FLOAT

#if !defined(QCBOR_DISABLE_DECODE_CONFORMANCE) && !defined(QCBOR_DISABLE_PREFERRED_FLOAT)

static QCBORError
QCBORDecode_Private_HalfConformance(const double d, const QCBORDecodeMode uConfigFlags)
{
   struct IEEE754_ToInt ToInt;

   /* Only need to check for conversion to integer because
    * half-precision is always preferred serialization. Don't
    * need special checker for half-precision because whole
    * numbers always convert perfectly from half to double.
    *
    * This catches half-precision with NaN payload too.
    *
    * The only thing allowed here is a double/half-precision that
    * can't be converted to anything but a double.
    */
   if(uConfigFlags & QCBOR_DECODE_ONLY_REDUCED_FLOATS) {
      ToInt = IEEE754_DoubleToInt(d);
      if(ToInt.type != QCBOR_TYPE_DOUBLE) {
         return QCBOR_ERR_DCBOR_CONFORMANCE;
      }
   }

   return QCBOR_SUCCESS;
}


static QCBORError
QCBORDecode_Private_SingleConformance(const uint32_t uSingle, const QCBORDecodeMode uconfigFlags)
{
   struct IEEE754_ToInt ToInt;
   IEEE754_union        ToSmaller;

   if(uconfigFlags & QCBOR_DECODE_ONLY_REDUCED_FLOATS) {
      /* See if it could have been encoded as an integer */
      ToInt = IEEE754_SingleToInt(uSingle);
      if(ToInt.type == IEEE754_ToInt_IS_INT || ToInt.type == IEEE754_ToInt_IS_UINT) {
         return QCBOR_ERR_DCBOR_CONFORMANCE;
      }

      /* Make sure there is no NaN payload */
      if(IEEE754_SingleHasNaNPayload(uSingle)) {
         return QCBOR_ERR_DCBOR_CONFORMANCE;
      }
   }

   /* See if it could have been encoded shorter */
   if(uconfigFlags & QCBOR_DECODE_ONLY_PREFERRED_NUMBERS) {
      ToSmaller = IEEE754_SingleToHalf(uSingle, true);
      if(ToSmaller.uSize != sizeof(float)) {
         return QCBOR_ERR_PREFERRED_CONFORMANCE;
      }
   }

   return QCBOR_SUCCESS;
}


static QCBORError
QCBORDecode_Private_DoubleConformance(const double d, QCBORDecodeMode uConfigFlags)
{
   struct IEEE754_ToInt ToInt;
   IEEE754_union        ToSmaller;

   if(uConfigFlags & QCBOR_DECODE_ONLY_REDUCED_FLOATS) {
      /* See if it could have been encoded as an integer */
      ToInt = IEEE754_DoubleToInt(d);
      if(ToInt.type == IEEE754_ToInt_IS_INT || ToInt.type == IEEE754_ToInt_IS_UINT) {
         return QCBOR_ERR_DCBOR_CONFORMANCE;
      }
      /* Make sure there is no NaN payload */
      if(IEEE754_DoubleHasNaNPayload(d)) {
         return QCBOR_ERR_DCBOR_CONFORMANCE;
      }
   }

   /* See if it could have been encoded shorter */
   if(uConfigFlags & QCBOR_DECODE_ONLY_PREFERRED_NUMBERS) {
      ToSmaller = IEEE754_DoubleToSmaller(d, true, true);
      if(ToSmaller.uSize != sizeof(double)) {
         return QCBOR_ERR_PREFERRED_CONFORMANCE;
      }
   }

   return QCBOR_SUCCESS;
}
#else /* !QCBOR_DISABLE_DECODE_CONFORMANCE && !QCBOR_DISABLE_PREFERRED_FLOAT */

#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
static QCBORError
QCBORDecode_Private_HalfConformance(const double d, const QCBORDecodeMode uConfigFlags)
{
   (void)d;
   if(uConfigFlags & (QCBOR_DECODE_ONLY_REDUCED_FLOATS | QCBOR_DECODE_ONLY_PREFERRED_NUMBERS)) {
      return QCBOR_ERR_CANT_CHECK_FLOAT_CONFORMANCE;
   } else {
      return QCBOR_SUCCESS;
   }
}
#endif


static QCBORError
QCBORDecode_Private_SingleConformance(const uint32_t uSingle, const QCBORDecodeMode uConfigFlags)
{
   (void)uSingle;
   if(uConfigFlags & (QCBOR_DECODE_ONLY_REDUCED_FLOATS | QCBOR_DECODE_ONLY_PREFERRED_NUMBERS)) {
      return QCBOR_ERR_CANT_CHECK_FLOAT_CONFORMANCE;
   } else {
      return QCBOR_SUCCESS;
   }
}

static QCBORError
QCBORDecode_Private_DoubleConformance(const double d, const QCBORDecodeMode uConfigFlags)
{
   (void)d;
   if(uConfigFlags & (QCBOR_DECODE_ONLY_REDUCED_FLOATS | QCBOR_DECODE_ONLY_PREFERRED_NUMBERS)) {
      return QCBOR_ERR_CANT_CHECK_FLOAT_CONFORMANCE;
   } else {
      return QCBOR_SUCCESS;
   }
}
#endif /* !QCBOR_DISABLE_DECODE_CONFORMANCE && !QCBOR_DISABLE_PREFERRED_FLOAT */


/*
 * Decode a float
 */
static QCBORError
QCBOR_Private_DecodeFloat(const QCBORDecodeMode uConfigFlags,
                          const int             nAdditionalInfo,
                          const uint64_t        uArgument,
                          QCBORItem            *pDecodedItem)
{
   QCBORError uErr;
   uint32_t   uSingle;

   /* Set error code for when no case in the switch matches. This
    * never actually happens because, but the compiler and the code
    * coverage tool don't know this. */
   uErr = QCBOR_ERR_UNSUPPORTED;

   switch(nAdditionalInfo) {
      case HALF_PREC_FLOAT: /* 25 */
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         /* Half-precision is returned as a double. The cast to
          * uint16_t is safe because the encoded value was 16 bits. It
          * was widened to 64 bits to be passed in here. */
         pDecodedItem->val.dfnum = IEEE754_HalfToDouble((uint16_t)uArgument);
         pDecodedItem->uDataType = QCBOR_TYPE_DOUBLE;
         uErr = QCBORDecode_Private_HalfConformance(pDecodedItem->val.dfnum,
                                                    uConfigFlags);
         if(uErr != QCBOR_SUCCESS) {
            break;
         }
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         uErr = FLOAT_ERR_CODE_NO_PREF_FLOAT(QCBOR_SUCCESS);
         break;

      case SINGLE_PREC_FLOAT: /* 26 */
         /* The cast to uint32_t is safe because the encoded value was
          * 32 bits. It was widened to 64 bits to be passed in here. */
         uSingle = (uint32_t)uArgument;
#ifndef QCBOR_DISABLE_PREFERRED_FLOAT
         /* Single precision is normally returned as a double. Since
          * double is widely supported, there is no loss of precision,
          * it makes it easy for the caller and it can be converted
          * back to single with no loss of precision. */
         pDecodedItem->val.dfnum = IEEE754_SingleToDouble(uSingle);
         pDecodedItem->uDataType = QCBOR_TYPE_DOUBLE;
#else /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         /* QCBOR's SW float conversion is disabled */
         pDecodedItem->val.fnum  = UsefulBufUtil_CopyUint32ToFloat(uSingle);
         pDecodedItem->uDataType = QCBOR_TYPE_FLOAT;
#endif /* ! QCBOR_DISABLE_PREFERRED_FLOAT */
         uErr = QCBORDecode_Private_SingleConformance(uSingle, uConfigFlags);
         break;

      case DOUBLE_PREC_FLOAT: /* 27 */
         pDecodedItem->val.dfnum = UsefulBufUtil_CopyUint64ToDouble(uArgument);
         pDecodedItem->uDataType = QCBOR_TYPE_DOUBLE;
         uErr = QCBORDecode_Private_DoubleConformance(pDecodedItem->val.dfnum,
                                                      uConfigFlags);
         break;
   }

   return uErr;
}
#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT */



/* Make sure #define value line up as DecodeSimple counts on this. */
#if QCBOR_TYPE_FALSE != CBOR_SIMPLEV_FALSE
#error QCBOR_TYPE_FALSE macro value wrong
#endif

#if QCBOR_TYPE_TRUE != CBOR_SIMPLEV_TRUE
#error QCBOR_TYPE_TRUE macro value wrong
#endif

#if QCBOR_TYPE_NULL != CBOR_SIMPLEV_NULL
#error QCBOR_TYPE_NULL macro value wrong
#endif

#if QCBOR_TYPE_UNDEF != CBOR_SIMPLEV_UNDEF
#error QCBOR_TYPE_UNDEF macro value wrong
#endif

#if QCBOR_TYPE_BREAK != CBOR_SIMPLE_BREAK
#error QCBOR_TYPE_BREAK macro value wrong
#endif

#if QCBOR_TYPE_DOUBLE != DOUBLE_PREC_FLOAT
#error QCBOR_TYPE_DOUBLE macro value wrong
#endif

#if QCBOR_TYPE_FLOAT != SINGLE_PREC_FLOAT
#error QCBOR_TYPE_FLOAT macro value wrong
#endif

/**
 * @brief Decode major type 7 -- true, false, floating-point, break...
 *
 * @param[in] nAdditionalInfo   The lower five bits from the initial byte.
 * @param[in] uArgument         The argument from the head.
 * @param[out] pDecodedItem     The filled in decoded item.
 *
 * @retval QCBOR_ERR_PREFERRED_FLOAT_DISABLED Half-precision in input, but decode
 *                                           of half-precision disabled.
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED      Float-point in input, but all float
 *                                           decode is disabled.
 * @retval QCBOR_ERR_BAD_TYPE_7              Not-allowed representation of simple
 *                                           type in input.
 */
static QCBORError
QCBOR_Private_DecodeType7(const QCBORDecodeMode  uConfigFlags,
                          const int              nAdditionalInfo,
                          const uint64_t         uArgument,
                          QCBORItem             *pDecodedItem)
{
   QCBORError uReturn = QCBOR_SUCCESS;

   /* uAdditionalInfo is 5 bits from the initial byte. Compile time
    * checks above make sure uAdditionalInfo values line up with
    * uDataType values.  DecodeHead() never returns an AdditionalInfo
    * > 0x1f so cast is safe.
    */
   pDecodedItem->uDataType = (uint8_t)nAdditionalInfo;

   switch(nAdditionalInfo) {
      /* No check for ADDINFO_RESERVED1 - ADDINFO_RESERVED3 as they
       * are caught before this is called.
       */

      case HALF_PREC_FLOAT: /* 25 */
      case SINGLE_PREC_FLOAT: /* 26 */
      case DOUBLE_PREC_FLOAT: /* 27 */
#ifndef USEFULBUF_DISABLE_ALL_FLOAT
         uReturn = QCBOR_Private_DecodeFloat(uConfigFlags,
                                             nAdditionalInfo,
                                             uArgument,
                                             pDecodedItem);
#else
         uReturn = QCBOR_ERR_ALL_FLOAT_DISABLED;
#endif /* ! USEFULBUF_DISABLE_ALL_FLOAT */
         break;

      case CBOR_SIMPLEV_FALSE: /* 20 */
      case CBOR_SIMPLEV_TRUE:  /* 21 */
      case CBOR_SIMPLEV_NULL:  /* 22 */
      case CBOR_SIMPLEV_UNDEF: /* 23 */
      case CBOR_SIMPLE_BREAK:  /* 31 */
#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
         if((uConfigFlags & QCBOR_DECODE_DISALLOW_DCBOR_SIMPLES) &&
            nAdditionalInfo == CBOR_SIMPLEV_UNDEF) {
            uReturn = QCBOR_ERR_DCBOR_CONFORMANCE;
            goto Done;
         }
#endif /* ! QCBOR_DISABLE_DECODE_CONFORMANCE */
         break; /* nothing to do */

      case CBOR_SIMPLEV_ONEBYTE: /* 24 */
         if(uArgument <= CBOR_SIMPLE_BREAK) {
            /* This takes out f8 00 ... f8 1f which should be encoded
             * as e0 … f7 -- preferred serialization check for simple values.
             */
            uReturn = QCBOR_ERR_BAD_TYPE_7;
            goto Done;
         }
         /* FALLTHROUGH */

      default: /* 0-19 */
#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
         if((uConfigFlags & QCBOR_DECODE_DISALLOW_DCBOR_SIMPLES) &&
            (uArgument < CBOR_SIMPLEV_FALSE || uArgument > CBOR_SIMPLEV_NULL)) {
            uReturn = QCBOR_ERR_DCBOR_CONFORMANCE;
            goto Done;
         }
#endif /* ! QCBOR_DISABLE_DECODE_CONFORMANCE */

         pDecodedItem->uDataType = QCBOR_TYPE_UKNOWN_SIMPLE;
         /* QCBOR_Private_DecodeHead() will make uArgument equal to
          * nAdditionalInfo when nAdditionalInfo is < 24. This cast is
          * safe because the 2, 4 and 8 byte lengths of uNumber are in
          * the double/float cases above
          */
         pDecodedItem->val.uSimple = (uint8_t)uArgument;
         break;
   }

Done:
   return uReturn;
}


/**
 * @brief Decode a single primitive data item (decode layer 6).
 *
 * @param[in] pMe                Decoder context.
 * @param[in] bAllocateStrings   If true, use allocator for strings.
 * @param[out] pDecodedItem      The filled-in decoded item.
 *
 * @retval QCBOR_ERR_UNSUPPORTED             Encountered unsupported/reserved
 *                                           features
 * @retval QCBOR_ERR_HIT_END                 Unexpected end of input
 * @retval QCBOR_ERR_INT_OVERFLOW            Too-large negative encountered
 * @retval QCBOR_ERR_STRING_ALLOCATE         Out of memory.
 * @retval QCBOR_ERR_STRING_TOO_LONG         String longer than SIZE_MAX - 4.
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR     Allocation requested, but no allocator
 * @retval QCBOR_ERR_PREFERRED_FLOAT_DISABLED Half-precision in input, but decode
 *                                           of half-precision disabled
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED      Float-point in input, but all
 *                                           float decode is disabled.
 * @retval QCBOR_ERR_BAD_TYPE_7              Not-allowed representation of
 *                                           simple type in input.
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED  Indefinite length map/array
 *                                              in input, but indefinite
 *                                              lengths disabled.
 * @retval QCBOR_ERR_BAD_INT                 nAdditionalInfo indicated indefinte.
 * @retval QCBOR_ERR_ARRAY_DECODE_TOO_LONG   Too many items in array/map.
 * @retval QCBOR_ERR_TAGS_DISABLED           QCBOR_DISABLE_TAGS is defined.
 *
 * This decodes the most primitive/atomic data item. It does no
 * combining of data items.
 */
static QCBORError
QCBOR_Private_DecodeAtomicDataItem(QCBORDecodeContext  *pMe,
                                   const bool           bAllocateStrings,
                                   QCBORItem           *pDecodedItem)
{
   QCBORError uErr;
   int        nMajorType = 0;
   uint64_t   uArgument = 0;
   int        nAdditionalInfo = 0;

#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
   const QCBORDecodeMode uDecodeMode = pMe->uDecodeMode;
#else /* ! QCBOR_DISABLE_DECODE_CONFORMANCE */
    /* No decode conformance; this saves 100 bytes of object code */
    const QCBORDecodeMode uDecodeMode = 0;
#endif /* ! QCBOR_DISABLE_DECODE_CONFORMANCE */

   memset(pDecodedItem, 0, sizeof(QCBORItem));

   /* Decode the "head" that every CBOR item has into the major type,
    * argument and the additional info.
    */
   uErr = QCBOR_Private_DecodeHead(&(pMe->InBuf),
                                      uDecodeMode,
                                      &nMajorType,
                                      &uArgument,
                                      &nAdditionalInfo);

   if(uErr != QCBOR_SUCCESS) {
      return uErr;
   }

   /* Set error code for when no case in the switch matches. This
    * never actually happens because nMajorType is masked to 3 bits
    * before calling, but the compiler and the code coverage tools
    * don't know this. */
   uErr = QCBOR_ERR_UNSUPPORTED;

   /* All the functions below get inlined by the optimizer. This code
    * is easier to read with them all being similar functions, even if
    * some functions don't do much.
    */
   switch (nMajorType) {
      case CBOR_MAJOR_TYPE_POSITIVE_INT: /* Major type 0 */
      case CBOR_MAJOR_TYPE_NEGATIVE_INT: /* Major type 1 */
         uErr = QCBOR_Private_DecodeInteger(nMajorType, uArgument, nAdditionalInfo, pDecodedItem);
         break;

      case CBOR_MAJOR_TYPE_BYTE_STRING: /* Major type 2 */
      case CBOR_MAJOR_TYPE_TEXT_STRING: /* Major type 3 */
         uErr = QCBOR_Private_DecodeString(pMe, bAllocateStrings, nMajorType, uArgument, nAdditionalInfo, pDecodedItem);
         break;

      case CBOR_MAJOR_TYPE_ARRAY: /* Major type 4 */
      case CBOR_MAJOR_TYPE_MAP:   /* Major type 5 */
         uErr = QCBOR_Private_DecodeArrayOrMap(pMe->uDecodeMode, nMajorType, uArgument, nAdditionalInfo, pDecodedItem);
         break;

      case CBOR_MAJOR_TYPE_TAG: /* Major type 6, tag numbers */
         uErr = QCBOR_Private_DecodeTagNumber(uArgument, nAdditionalInfo, pDecodedItem);
         break;

      case CBOR_MAJOR_TYPE_SIMPLE: /* Major type 7: float, double, true, false, null... */
         uErr = QCBOR_Private_DecodeType7(uDecodeMode, nAdditionalInfo, uArgument, pDecodedItem);
         break;
   }
   return uErr;
}


/**
 * @brief Process indefinite-length strings (decode layer 5).
 *
 * @param[in] pMe   Decoder context
 * @param[out] pDecodedItem  The decoded item that work is done on.
 *
 * @retval QCBOR_ERR_UNSUPPORTED             Encountered unsupported/reserved
 *                                           features
 * @retval QCBOR_ERR_HIT_END                 Unexpected end of input
 * @retval QCBOR_ERR_INT_OVERFLOW            Too-large negative encountered
 * @retval QCBOR_ERR_STRING_ALLOCATE         Out of memory.
 * @retval QCBOR_ERR_STRING_TOO_LONG         String longer than SIZE_MAX - 4.
 * @retval QCBOR_ERR_PREFERRED_FLOAT_DISABLED Half-precision in input, but decode
 *                                           of half-precision disabled
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED      Float-point in input, but all
 *                                           float decode is disabled.
 * @retval QCBOR_ERR_BAD_TYPE_7              Not-allowed representation of
 *                                           simple type in input.
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED  Indefinite length map/array
 *                                              in input, but indefinite
 *                                              lengths disabled.
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR     Indefinite-length string in input,
 *                                           but no string allocator.
 * @retval QCBOR_ERR_INDEFINITE_STRING_CHUNK  Error in indefinite-length string.
 * @retval QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED  Indefinite-length string in
 *                                               input, but indefinite-length
 *                                               strings are disabled.
 *
 * If @c pDecodedItem is not an indefinite-length string, this does nothing.
 *
 * If it is, this loops getting the subsequent chunk data items that
 * make up the string.  The string allocator is used to make a
 * contiguous buffer for the chunks.  When this completes @c
 * pDecodedItem contains the put-together string.
 *
 * Code Reviewers: THIS FUNCTION DOES A LITTLE POINTER MATH
 */
static QCBORError
QCBORDecode_Private_GetNextFullString(QCBORDecodeContext *pMe,
                                      QCBORItem          *pDecodedItem)
{
   /* Aproximate stack usage
    *                                             64-bit      32-bit
    *   local vars                                    32          16
    *   2 UsefulBufs                                  32          16
    *   QCBORItem                                     56          52
    *   TOTAL                                        120          74
    */
   QCBORError uReturn;

   /* A note about string allocation -- Memory for strings is
    * allocated either because 1) indefinte-length string chunks are
    * being coalecsed or 2) caller has requested all strings be
    * allocated.  The first case is handed below here. The second case
    * is handled in DecodeString if the bAllocate is true. That
    * boolean originates here with pMe->bStringAllocateAll immediately
    * below. That is, QCBOR_Private_DecodeAtomicDataItem() is called
    * in two different contexts here 1) main-line processing which is
    * where definite-length strings need to be allocated if
    * bStringAllocateAll is true and 2) processing chunks of
    * indefinite-lengths strings in in which case there must be no
    * allocation.
    */


   uReturn = QCBOR_Private_DecodeAtomicDataItem(pMe,
                                                pMe->bStringAllocateAll,
                                                pDecodedItem);
   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }

   /* This is where out-of-place break is detected for the whole
    * decoding stack. Break is an error for everything that calls
    * QCBORDecode_Private_GetNextFullString(), so the check is
    * centralized here.
    */
   if(pDecodedItem->uDataType == QCBOR_TYPE_BREAK) {
      uReturn = QCBOR_ERR_BAD_BREAK;
      goto Done;
   }


   /* Skip out if not an indefinite-length string */
   const uint8_t uStringType = pDecodedItem->uDataType;
   if(uStringType != QCBOR_TYPE_BYTE_STRING &&
      uStringType != QCBOR_TYPE_TEXT_STRING) {
      goto Done;
   }
   if(pDecodedItem->val.string.len != QCBOR_STRING_LENGTH_INDEFINITE) {
      goto Done;
   }

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
   /* Can't decode indefinite-length strings without a string allocator */
   if(!pMe->StringAllocator.pfAllocator) {
      uReturn = QCBOR_ERR_NO_STRING_ALLOCATOR;
      goto Done;
   }

   /* Loop getting chunks of the indefinite-length string */
   UsefulBufC FullString = NULLUsefulBufC;

   for(;;) {
      /* Get QCBORItem for next chunk */
      QCBORItem StringChunkItem;
      /* Pass false to DecodeAtomicDataItem() because the individual
       * string chunks in an indefinite-length must not be
       * allocated. They are always copied into the allocated
       * contiguous buffer allocated here.
       */
      uReturn = QCBOR_Private_DecodeAtomicDataItem(pMe,
                                                   false,
                                                   &StringChunkItem);
      if(uReturn) {
         break;
      }

      /* Is item is the marker for end of the indefinite-length string? */
      if(StringChunkItem.uDataType == QCBOR_TYPE_BREAK) {
         /* String is complete */
         pDecodedItem->val.string = FullString;
         pDecodedItem->uDataAlloc = 1;
         break;
      }

      /* All chunks must be of the same type, the type of the item
       * that introduces the indefinite-length string. This also
       * catches errors where the chunk is not a string at all and an
       * indefinite-length string inside an indefinite-length string.
       */
      if(StringChunkItem.uDataType != uStringType ||
         StringChunkItem.val.string.len == QCBOR_STRING_LENGTH_INDEFINITE) {
         uReturn = QCBOR_ERR_INDEFINITE_STRING_CHUNK;
         break;
      }

      if (StringChunkItem.val.string.len > 0) {
         /* The first time throurgh FullString.ptr is NULL and this is
          * equivalent to StringAllocator_Allocate(). Subsequently it is
          * not NULL and a reallocation happens.
          */
         UsefulBuf NewMem = StringAllocator_Reallocate(&(pMe->StringAllocator),
                                                       FullString.ptr,
                                                       FullString.len + StringChunkItem.val.string.len);
         if(UsefulBuf_IsNULL(NewMem)) {
            uReturn = QCBOR_ERR_STRING_ALLOCATE;
            break;
         }

         /* Copy new string chunk to the end of accumulated string */
         FullString = UsefulBuf_CopyOffset(NewMem,
                                           FullString.len,
                                           StringChunkItem.val.string);
      }
   }

   if(uReturn != QCBOR_SUCCESS && !UsefulBuf_IsNULLC(FullString)) {
      /* Getting the item failed, clean up the allocated memory */
      StringAllocator_Free(&(pMe->StringAllocator), FullString.ptr);
   }
#else /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */
   uReturn = QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED;
#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */

Done:
   return uReturn;
}


#ifndef QCBOR_DISABLE_TAGS
/**
 * @brief This converts a tag number to a shorter mapped value for storage.
 *
 * @param[in] pMe                 The decode context.
 * @param[in] uUnMappedTag        The tag number to map
 * @param[out] puMappedTagNumber  The stored tag number.
 *
 * @return error code.
 *
 * The main point of mapping tag numbers is make QCBORItem
 * smaller. With this mapping storage of 4 tags takes up 8
 * bytes. Without, it would take up 32 bytes.
 *
 * This maps tag numbers greater than QCBOR_LAST_UNMAPPED_TAG.
 * QCBOR_LAST_UNMAPPED_TAG is a little smaller than MAX_UINT16.
 *
 * See also UnMapTagNumber() and @ref QCBORItem.
 */
static QCBORError
QCBORDecode_Private_MapTagNumber(QCBORDecodeContext *pMe,
                                 const uint64_t      uUnMappedTag,
                                 uint16_t           *puMappedTagNumber)
{
   size_t uTagMapIndex;

   if(uUnMappedTag > QCBOR_LAST_UNMAPPED_TAG) {
      /* Is there room in the tag map, or is it in it already? */
      for(uTagMapIndex = 0; uTagMapIndex < QCBOR_NUM_MAPPED_TAGS; uTagMapIndex++) {
         if(pMe->auMappedTagNumbers[uTagMapIndex] == CBOR_TAG_INVALID64) {
            break;
         }
         if(pMe->auMappedTagNumbers[uTagMapIndex] == uUnMappedTag) {
            break;
         }
      }
      if(uTagMapIndex >= QCBOR_NUM_MAPPED_TAGS) {
         return QCBOR_ERR_TOO_MANY_TAGS;
      }

      /* Covers the cases where tag is new and were it is already in the map */
      pMe->auMappedTagNumbers[uTagMapIndex] = uUnMappedTag;
      *puMappedTagNumber = (uint16_t)(uTagMapIndex + QCBOR_LAST_UNMAPPED_TAG + 1);

   } else {
      *puMappedTagNumber = (uint16_t)uUnMappedTag;
   }

   return QCBOR_SUCCESS;
}


/**
 * @brief This converts a mapped tag number to the actual tag number.
 *
 * @param[in] pMe               The decode context.
 * @param[in] uMappedTagNumber  The stored tag number.
 *
 * @return The actual tag number is returned or
 *         @ref CBOR_TAG_INVALID64 on error.
 *
 * This is the reverse of MapTagNumber()
 */
uint64_t
QCBORDecode_Private_UnMapTagNumber(const QCBORDecodeContext *pMe,
                                   const uint16_t            uMappedTagNumber)
{
   if(uMappedTagNumber <= QCBOR_LAST_UNMAPPED_TAG) {
      return uMappedTagNumber;
   } else if(uMappedTagNumber == CBOR_TAG_INVALID16) {
      return CBOR_TAG_INVALID64;
   } else {
      /* This won't be negative because of code below in
       * MapTagNumber()
       */
      const size_t uIndex = uMappedTagNumber - (QCBOR_LAST_UNMAPPED_TAG + 1);
      return pMe->auMappedTagNumbers[uIndex];
   }
}


static const struct QCBORTagDecoderEntry *
QCBORDecode_Private_GetTagContentDecoder(const struct QCBORTagDecoderEntry *pTagContentTable,
                                         const uint64_t                     uTagNumber)
{
   const struct QCBORTagDecoderEntry *pTE;

   if(pTagContentTable == NULL) {
      return NULL;
   }

   for(pTE = pTagContentTable; pTE->uTagNumber != CBOR_TAG_INVALID64; pTE++) {
      if(pTE->uTagNumber == uTagNumber || pTE->uTagNumber == CBOR_TAG_ANY) {
         break;
      }
   }

   if(pTE->uTagNumber == CBOR_TAG_INVALID64) {
      return NULL;
   }

   return pTE;
}
#endif /* ! QCBOR_DISABLE_TAGS */


/**
 * @brief Aggregate all tags wrapping a data item (decode layer 4).
 *
 * @param[in] pMe            Decoder context
 * @param[out] pDecodedItem  The decoded item that work is done on.
 *
 * @retval QCBOR_ERR_UNSUPPORTED             Encountered unsupported/reserved
 *                                           features
 * @retval QCBOR_ERR_HIT_END                 Unexpected end of input
 * @retval QCBOR_ERR_INT_OVERFLOW            Too-large negative encountered
 * @retval QCBOR_ERR_STRING_ALLOCATE         Out of memory.
 * @retval QCBOR_ERR_STRING_TOO_LONG         String longer than SIZE_MAX - 4.
 * @retval QCBOR_ERR_PREFERRED_FLOAT_DISABLED Half-precision in input, but decode
 *                                           of half-precision disabled
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED      Float-point in input, but all
 *                                           float decode is disabled.
 * @retval QCBOR_ERR_BAD_TYPE_7              Not-allowed representation of
 *                                           simple type in input.
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED  Indefinite length map/array
 *                                              in input, but indefinite
 *                                              lengths disabled.
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR     Indefinite-length string in input,
 *                                           but no string allocator.
 * @retval QCBOR_ERR_INDEFINITE_STRING_CHUNK  Error in indefinite-length string.
 * @retval QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED  Indefinite-length string in
 *                                               input, but indefinite-length
 *                                               strings are disabled.
 * @retval QCBOR_ERR_TOO_MANY_TAGS           Too many tag numbers on item.
 *
 * This loops getting atomic data items until one is not a tag
 * number.  Usually this is largely pass-through because most
 * item are not tag numbers.
 */
static QCBORError
QCBORDecode_Private_GetNextTagNumber(QCBORDecodeContext *pMe,
                                     QCBORItem          *pDecodedItem)
{
#ifndef QCBOR_DISABLE_TAGS
   size_t      uIndex;
   QCBORError  uErr;
   uint16_t    uMappedTagNumber;
   QCBORError  uReturn;

   /* Accummulate the tag numbers from multiple items here and then
    * copy them into the last item, the non-tag-number item.
    */
   QCBORMappedTagNumbers  auTagNumbers;;

   /* Initialize to CBOR_TAG_INVALID16 */
   #if CBOR_TAG_INVALID16 != 0xffff
   /* Be sure the memset is initializing to CBOR_TAG_INVALID16 */
   #err CBOR_TAG_INVALID16 tag not defined as expected
   #endif
   memset(auTagNumbers, 0xff, sizeof(auTagNumbers));

   /* Loop fetching data items until the item fetched is not a tag number */
   uReturn = QCBOR_SUCCESS;
   for(uIndex = 0; ; uIndex++) {
      uErr = QCBORDecode_Private_GetNextFullString(pMe, pDecodedItem);
      if(uErr != QCBOR_SUCCESS) {
         uReturn = uErr;
         break;
      }

      if(pDecodedItem->uDataType != QCBOR_TYPE_TAG_NUMBER) {
         /* Successful exit from loop; maybe got some tags, maybe not */
         memcpy(pDecodedItem->auTagNumbers, auTagNumbers, sizeof(auTagNumbers));
         break;
      }

      if(uIndex >= QCBOR_MAX_TAGS_PER_ITEM) {
         /* No room in the item's tag number array */
         uReturn = QCBOR_ERR_TOO_MANY_TAGS;
         /* Continue on to get all tag numbers wrapping this item even
          * though it is erroring out in the end. This allows decoding
          * to continue. This is a QCBOR resource limit error, not a
          * problem with being well-formed CBOR.
          */
         continue;
      }

      /* Map the tag number */
      uMappedTagNumber = 0;
      uReturn = QCBORDecode_Private_MapTagNumber(pMe,
                                                 pDecodedItem->val.uTagNumber,
                                                 &uMappedTagNumber);
      /* Continue even on error so as to consume all tag numbers
       * wrapping this data item so decoding can go on. If
       * QCBORDecode_Private_MapTagNumber() errors once it will
       * continue to error.
       */

      auTagNumbers[uIndex] = uMappedTagNumber;
   }

   return uReturn;

#else /* ! QCBOR_DISABLE_TAGS */

   return QCBORDecode_Private_GetNextFullString(pMe, pDecodedItem);

#endif /* ! QCBOR_DISABLE_TAGS */
}


/**
 * @brief Combine a map entry label and value into one item (decode layer 3).
 *
 * @param[in] pMe            Decoder context
 * @param[out] pDecodedItem  The decoded item that work is done on.
 *
 * @retval QCBOR_ERR_UNSUPPORTED             Encountered unsupported/reserved
 *                                           features
 * @retval QCBOR_ERR_HIT_END                 Unexpected end of input
 * @retval QCBOR_ERR_INT_OVERFLOW            Too-large negative encountered
 * @retval QCBOR_ERR_STRING_ALLOCATE         Out of memory.
 * @retval QCBOR_ERR_STRING_TOO_LONG         String longer than SIZE_MAX - 4.
 * @retval QCBOR_ERR_PREFERRED_FLOAT_DISABLED Half-precision in input, but decode
 *                                           of half-precision disabled
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED      Float-point in input, but all
 *                                           float decode is disabled.
 * @retval QCBOR_ERR_BAD_TYPE_7              Not-allowed representation of
 *                                           simple type in input.
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED  Indefinite length map/array
 *                                              in input, but indefinite
 *                                              lengths disabled.
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR     Indefinite-length string in input,
 *                                           but no string allocator.
 * @retval QCBOR_ERR_INDEFINITE_STRING_CHUNK  Error in indefinite-length string.
 * @retval QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED  Indefinite-length string in
 *                                               input, but indefinite-length
 *                                               strings are disabled.
 * @retval QCBOR_ERR_TOO_MANY_TAGS           Too many tag numbers on item.
 * @retval QCBOR_ERR_ARRAY_DECODE_TOO_LONG   Too many items in array.
 * @retval QCBOR_ERR_MAP_LABEL_TYPE          Map label not string or integer.
 *
 * If the current nesting level is a map, then this combines pairs of
 * items into one data item with a label and value.
 *
 * This is passthrough if the current nesting level is not a map.
 *
 * This also implements maps-as-array mode where a map is treated like
 * an array to allow caller to do their own label processing.
 */
static QCBORError
QCBORDecode_Private_GetNextMapEntry(QCBORDecodeContext *pMe,
                                    QCBORItem          *pDecodedItem,
                                    uint32_t           *puLabelEndOffset)
{
   QCBORItem  LabelItem;
   QCBORError uErr, uErr2;

   uErr = QCBORDecode_Private_GetNextTagNumber(pMe, pDecodedItem);
   if(QCBORDecode_IsUnrecoverableError(uErr)) {
      goto Done;
   }

   if(!DecodeNesting_IsCurrentTypeMap(&(pMe->nesting))) {
      /* Not decoding a map. Nothing to do. */
      /* When decoding maps-as-arrays, the type will be
       * QCBOR_TYPE_MAP_AS_ARRAY and this function will exit
       * here. This is now map processing for maps-as-arrays is not
       * done. */
      goto Done;
   }

   /* Decoding a map entry, so the item decoded above was the label */
   LabelItem = *pDecodedItem;

#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
   if(puLabelEndOffset != NULL) {
       /* Cast is OK because lengths are all 32-bit in QCBOR */
       *puLabelEndOffset = (uint32_t)UsefulInputBuf_Tell(&(pMe->InBuf));
    }
#else
   (void)puLabelEndOffset;
#endif /* ! QCBOR_DISABLE_DECODE_CONFORMANCE */

   /* Get the value of the map item */
   uErr2 = QCBORDecode_Private_GetNextTagNumber(pMe, pDecodedItem);
   if(QCBORDecode_IsUnrecoverableError(uErr2)) {
      uErr = uErr2;
      goto Done;
   }
   if(uErr2 != QCBOR_SUCCESS) {
      /* The recoverable error for the value overrides the recoverable
       * error for the label, if there was an error for the label */
      uErr = uErr2;
   }

   /* Combine the label item and value item into one */
   pDecodedItem->uLabelAlloc = LabelItem.uDataAlloc;
   pDecodedItem->uLabelType  = LabelItem.uDataType;

#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   if(pMe->uDecodeMode & QCBOR_DECODE_MODE_MAP_STRINGS_ONLY &&
      LabelItem.uDataType != QCBOR_TYPE_TEXT_STRING) {
      uErr = QCBOR_ERR_MAP_LABEL_TYPE;
      goto Done;
   }
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */

   switch(LabelItem.uDataType) {
      case QCBOR_TYPE_INT64:
         pDecodedItem->label.int64 = LabelItem.val.int64;
         break;

#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
      case QCBOR_TYPE_UINT64:
         pDecodedItem->label.uint64 = LabelItem.val.uint64;
         break;

      case QCBOR_TYPE_TEXT_STRING:
      case QCBOR_TYPE_BYTE_STRING:
         pDecodedItem->label.string = LabelItem.val.string;
         break;
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */

      default:
         /* It is possible to skip over labels that are non-aggregate
          * types like floats, but not to skip over labels that are
          * arrays or maps. We might eventually handle more label
          * types like floats as they are not too hard and we now
          * have QCBOR_DISABLE_NON_INTEGER_LABELS */
         if(!pMe->bAllowAllLabels || QCBORItem_IsMapOrArray(LabelItem)) {
            uErr = QCBOR_ERR_MAP_LABEL_TYPE;
            goto Done;
         }
   }

Done:
   return uErr;
}


#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
/**
 * @brief Peek and see if next data item is a break;
 *
 * @param[in]  pUIB            UsefulInputBuf to read from.
 * @param[out] pbNextIsBreak   Indicate if next was a break or not.
 *
 * @return  Any decoding error.
 *
 * See if next item is a CBOR break. If it is, it is consumed,
 * if not it is not consumed.
 *
 * @c pbNextIsBreak cannot be NULL. It is always set.
*/
static QCBORError
QCBOR_Private_NextIsBreak(QCBORDecodeContext *pMe, bool *pbNextIsBreak)
{
    QCBORError uReturn;
    QCBORItem  Peek;
    size_t     uPeek;

   *pbNextIsBreak = false;
   if(UsefulInputBuf_BytesUnconsumed(&(pMe->InBuf)) != 0) {
      uPeek = UsefulInputBuf_Tell(&(pMe->InBuf));
      uReturn = QCBOR_Private_DecodeAtomicDataItem(pMe, false, &Peek);
      if(uReturn != QCBOR_SUCCESS) {
         return uReturn;
      }
      if(Peek.uDataType != QCBOR_TYPE_BREAK) {
         /* It is not a break, rewind so it can be processed normally. */
         UsefulInputBuf_Seek(&(pMe->InBuf), uPeek);
      } else {
         *pbNextIsBreak = true;
      }
   }

   return QCBOR_SUCCESS;
}
#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */


/**
 * @brief Ascend up nesting levels if all items in arrays/maps have been consumed.
 *
 * @param[in] pMe       The decode context.
 * @param[in] bMarkEnd  If true mark end of maps/arrays with count of zero.
 * @param[out] pbBreak  Indicate if ascension was ended by a break. May be NULL.
 *                      Always set if not NULL.
 *
 * An item was just consumed, now figure out if it was the
 * end of an array/map map that can be closed out. That
 * may in turn close out the above array/map. This only closes
 * out arrays and maps, not any other sort of nesting.
 *
 * When ascending indefinite-length arrays and maps, this will
 * consume the break for the level above. This is a problem for the
 * implementation of QCBORDecode_GetArray() that must not return
 * that break. @c pbBreak is set to true to indicate that one byte
 * beyond was consumed.
 *
 * Improvement: this could reduced further if indef is disabled
 */
QCBORError
QCBORDecode_Private_NestLevelAscender(QCBORDecodeContext *pMe, bool bMarkEnd, bool *pbEndedByBreak)
{
   QCBORError uReturn;
   bool       bEndedByBreak;

   /* Loop ascending nesting levels as long as there is ascending to do */
   bEndedByBreak = false;

   while( ! DecodeNesting_IsCurrentAtTop(&(pMe->nesting))) {
      bEndedByBreak = false;

      if(DecodeNesting_IsCurrentBstrWrapped(&(pMe->nesting))) {
         /* Ascent for bstr-wrapped CBOR is always by explicit public API
          * call so no further ascending can happen. */
         break;
      }

      if(DecodeNesting_IsCurrentDefiniteLength(&(pMe->nesting))) {
         /* Level is a definite-length array/map */

         /* Decrement the item count the definite-length array/map */
         DecodeNesting_DecrementDefiniteLengthMapOrArrayCount(&(pMe->nesting));
         if(!DecodeNesting_IsEndOfDefiniteLengthMapOrArray(&(pMe->nesting))) {
             /* Didn't close out an array/map, so all work here is done */
             break;
          }
          /* All items in a definite-length array were consumed so it
           * is time to ascend one level. This happens below. */

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
      } else {
         /* Level is an indefinite-length array/map. */

         /* Check for break which is what ends indefinite-length arrays/maps */
         uReturn = QCBOR_Private_NextIsBreak(pMe, &bEndedByBreak);
         if(uReturn != QCBOR_SUCCESS) {
            goto Done;
         }

         if( ! bEndedByBreak) {
            /* Not a break so array/map does not close out. All work is done */
            break;
         }
         /* It was a break in an indefinite length map / array so
          * it is time to ascend one level. */

#endif /* ! QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */
      }

      /* All items in the array/map have been consumed. */
      /* But ascent in bounded mode is only by explicit call to
       * QCBORDecode_ExitBoundedMode(). */
      if(DecodeNesting_IsCurrentBounded(&(pMe->nesting))) {
         /* Set the count to zero for definite-length arrays to indicate
         * cursor is at end of bounded array/map */
         if(bMarkEnd) {
            /* Used for definite and indefinite to signal end */
            DecodeNesting_ZeroMapOrArrayCount(&(pMe->nesting));
         }
         break;
      }

      /* Finally, actually ascend one level. */
      DecodeNesting_Ascend(&(pMe->nesting));
   }

   uReturn = QCBOR_SUCCESS;

#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
Done:
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS */

   if(pbEndedByBreak != NULL) {
      *pbEndedByBreak = bEndedByBreak;
   }

   return uReturn;
}


/**
 * @brief Ascending & Descending out of nesting levels (decode layer 2).
 *
 * @param[in] pMe              Decoder context
 * @param[out] pbEndedByBreak  Indicate if ascension was ended by a break. May
 *                             be NULL. Always set if not NULL.
 * @param[out] pDecodedItem  The decoded item that work is done on.

 * @retval QCBOR_ERR_UNSUPPORTED             Encountered unsupported/reserved
 *                                           features
 * @retval QCBOR_ERR_HIT_END                 Unexpected end of input
 * @retval QCBOR_ERR_INT_OVERFLOW            Too-large negative encountered
 * @retval QCBOR_ERR_STRING_ALLOCATE         Out of memory.
 * @retval QCBOR_ERR_STRING_TOO_LONG         String longer than SIZE_MAX - 4.
 * @retval QCBOR_ERR_PREFERRED_FLOAT_DISABLED Half-precision in input, but decode
 *                                           of half-precision disabled
 * @retval QCBOR_ERR_ALL_FLOAT_DISABLED      Float-point in input, but all
 *                                           float decode is disabled.
 * @retval QCBOR_ERR_BAD_TYPE_7              Not-allowed representation of
 *                                           simple type in input.
 * @retval QCBOR_ERR_INDEF_LEN_ARRAYS_DISABLED  Indefinite length map/array
 *                                              in input, but indefinite
 *                                              lengths disabled.
 * @retval QCBOR_ERR_NO_STRING_ALLOCATOR     Indefinite-length string in input,
 *                                           but no string allocator.
 * @retval QCBOR_ERR_INDEFINITE_STRING_CHUNK  Error in indefinite-length string.
 * @retval QCBOR_ERR_INDEF_LEN_STRINGS_DISABLED  Indefinite-length string in
 *                                               input, but indefinite-length
 *                                               strings are disabled.
 * @retval QCBOR_ERR_TOO_MANY_TAGS           Too many tag numbers on item.
 * @retval QCBOR_ERR_ARRAY_DECODE_TOO_LONG   Too many items in array.
 * @retval QCBOR_ERR_MAP_LABEL_TYPE          Map label not string or integer.
 * @retval QCBOR_ERR_NO_MORE_ITEMS           Need more items for map or array.
 * @retval QCBOR_ERR_BAD_BREAK               Indefinite-length break in wrong
 *                                           place.
 * @retval QCBOR_ERR_ARRAY_DECODE_NESTING_TOO_DEEP  Nesting deeper than QCBOR
 *                                                  can handle.
 *
 * This handles the traversal descending into and asecnding out of
 * maps, arrays and bstr-wrapped CBOR. It figures out the ends of
 * definite- and indefinte-length maps and arrays by looking at the
 * item count or finding CBOR breaks.  It detects the ends of the
 * top-level sequence and of bstr-wrapped CBOR by byte count.
 */
QCBORError
QCBORDecode_Private_GetNextMapOrArray(QCBORDecodeContext *pMe,
                                      bool               *pbEndedByBreak,
                                      QCBORItem          *pDecodedItem,
                                      uint32_t           *puLabelEndOffset)
{
   QCBORError uReturn;
   /* ==== First: figure out if at the end of a traversal ==== */

   /* If out of bytes to consume, it is either the end of the
    * top-level sequence of some bstr-wrapped CBOR that was entered.
    *
    * In the case of bstr-wrapped CBOR, the length of the
    * UsefulInputBuf was set to that of the bstr-wrapped CBOR. When
    * the bstr-wrapped CBOR is exited, the length is set back to the
    * top-level's length or to the next highest bstr-wrapped CBOR.
   */
   if(UsefulInputBuf_BytesUnconsumed(&(pMe->InBuf)) == 0) {
      uReturn = QCBOR_ERR_NO_MORE_ITEMS;
      goto Done;
   }

   /* Check to see if at the end of a bounded definite-length map or
    * array. The check for a break ending indefinite-length array is
    * later in QCBORDecode_NestLevelAscender().
    */
   if(DecodeNesting_IsAtEndOfBoundedLevel(&(pMe->nesting))) {
      uReturn = QCBOR_ERR_NO_MORE_ITEMS;
      goto Done;
   }

   /* ==== Next: not at the end, so get another item ==== */
   uReturn = QCBORDecode_Private_GetNextMapEntry(pMe,
                                                 pDecodedItem,
                                                 puLabelEndOffset);
   if(QCBORDecode_IsUnrecoverableError(uReturn)) {
      /* Error is so bad that traversal is not possible. */
      goto Done;
   }

   /* Record the nesting level for this data item before processing
    * any of decrementing and descending.
    */
   pDecodedItem->uNestingLevel = DecodeNesting_GetCurrentLevel(&(pMe->nesting));


   /* ==== Next: Process the item for descent, ascent, decrement... ==== */
   if(QCBORItem_IsMapOrArray(*pDecodedItem)) {
      /* If the new item is a map or array, descend.
       *
       * Empty indefinite-length maps and arrays are descended into,
       * but then ascended out of in the next chunk of code.
       *
       * Maps and arrays do count as items in the map/array that
       * encloses them so a decrement needs to be done for them too,
       * but that is done only when all the items in them have been
       * processed, not when they are opened with the exception of an
       * empty map or array.
       */
      QCBORError uDescendErr;
      uDescendErr = DecodeNesting_DescendMapOrArray(&(pMe->nesting),
                                                    pDecodedItem->uDataType,
                                                    pDecodedItem->val.uCount);
      if(uDescendErr != QCBOR_SUCCESS) {
         /* This error is probably a traversal error and it overrides
          * the non-traversal error.
          */
         uReturn = uDescendErr;
         goto Done;
      }
   }

   if(!QCBORItem_IsMapOrArray(*pDecodedItem) ||
       QCBORItem_IsEmptyDefiniteLengthMapOrArray(*pDecodedItem) ||
       QCBORItem_IsIndefiniteLengthMapOrArray(*pDecodedItem)) {
      /* The following cases are handled here:
       *  - A non-aggregate item like an integer or string
       *  - An empty definite-length map or array
       *  - An indefinite-length map or array that might be empty or might not.
       *
       * QCBORDecode_NestLevelAscender() does the work of decrementing the count
       * for an definite-length map/array and break detection for an
       * indefinite-0length map/array. If the end of the map/array was
       * reached, then it ascends nesting levels, possibly all the way
       * to the top level.
       */
      QCBORError uAscendErr;
      uAscendErr = QCBORDecode_Private_NestLevelAscender(pMe, true, pbEndedByBreak);
      if(uAscendErr != QCBOR_SUCCESS) {
         /* This error is probably a traversal error and it overrides
          * the non-traversal error.
          */
         uReturn = uAscendErr;
         goto Done;
      }
   }

   /* ==== Last: tell the caller the nest level of the next item ==== */
   /* Tell the caller what level is next. This tells them what
    * maps/arrays were closed out and makes it possible for them to
    * reconstruct the tree with just the information returned in a
    * QCBORItem.
   */
   if(DecodeNesting_IsAtEndOfBoundedLevel(&(pMe->nesting))) {
      /* At end of a bounded map/array; uNextNestLevel 0 to indicate this */
      pDecodedItem->uNextNestLevel = 0;
   } else {
      pDecodedItem->uNextNestLevel = DecodeNesting_GetCurrentLevel(&(pMe->nesting));
   }

Done:
   return uReturn;
}


/**
 * @brief Invoke tag content decoder callbacks (decoding layer 1).
 *
 * @param[in] pMe            The decode context.
 * @param[out] pDecodedItem  The decoded item.
 *
 * @return Decoding error code.
 *
 * CBOR tag numbers for the item were decoded in GetNext_TaggedItem(),
 * but the whole tag was not decoded. Here, the whole tags (tag number
 * and tag content) are decoded. This is a
 * quick pass through for items that are not tags.
 * TODO: check above documentation
 * TODO: is this really layer 1 still?
 */
QCBORError
QCBORDecode_Private_GetNextTagContent(QCBORDecodeContext *pMe,
                                      QCBORItem          *pDecodedItem)
{
   QCBORError uErr;

   uErr = QCBORDecode_Private_GetNextMapOrArray(pMe, NULL, pDecodedItem, NULL);

#ifndef QCBOR_DISABLE_TAGS
   uint64_t   uTagNumber;
   int        nTagIndex;
   const struct QCBORTagDecoderEntry *pTagDecoder;

   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }

   /* Loop over tag numbers in reverse, those closest to content first */
   for(nTagIndex = QCBOR_MAX_TAGS_PER_ITEM-1; nTagIndex >= 0; nTagIndex--) {

      if(pDecodedItem->auTagNumbers[nTagIndex] == CBOR_TAG_INVALID16) {
         continue; /* Empty slot, skip to next */
      }

      /* See if there's a content decoder for it */
      uTagNumber  = QCBORDecode_Private_UnMapTagNumber(pMe, pDecodedItem->auTagNumbers[nTagIndex]);
      pTagDecoder = QCBORDecode_Private_GetTagContentDecoder(pMe->pTagDecoderTable, uTagNumber);
      if(pTagDecoder == NULL) {
         break; /* Successful exist -- a tag with no callback  */
      }

      /* Call the content decoder */
      uErr = pTagDecoder->pfContentDecoder(pMe,
                                           pMe->pTagDecodersContext,
                                           pTagDecoder->uTagNumber,
                                           pDecodedItem);
      if(uErr != QCBOR_SUCCESS) {
         break; /* Error exit from the loop */
      }

      /* Remove tag number from list since its content was decoded */
      pDecodedItem->auTagNumbers[nTagIndex] = CBOR_TAG_INVALID16;
   }

Done:
#endif /* ! QCBOR_DISABLE_TAGS */

   return uErr;
}


/**
 * @brief Consume an entire map or array including its contents.
 *
 * @param[in]  pMe              The decoder context.
 * @param[in]  pItemToConsume   The array/map whose contents are to be
 *                              consumed.
 * @param[out] pbEndedByBreak   Indicate if consumption was ended by a
 *                              break.  May be NULL. The indication is
 *                              only set if the result is true, so the
 *                              contents of this pointer should be set
 *                              to false before calling this.
 * @param[out] puNextNestLevel  The next nesting level after the item was
 *                              fully consumed.
 *
 * This may be called when @c pItemToConsume is not an array or
 * map. In that case, this is just a pass through for @c puNextNestLevel
 * since there is nothing to do.
 */
QCBORError
QCBORDecode_Private_ConsumeItem(QCBORDecodeContext *pMe,
                                const QCBORItem    *pItemToConsume,
                                bool               *pbEndedByBreak,
                                uint8_t            *puNextNestLevel)
{
   QCBORError uReturn;
   QCBORItem  Item;

   /* If it is a map or array, this will tell if it is empty. */
   const bool bIsEmpty = (pItemToConsume->uNextNestLevel <= pItemToConsume->uNestingLevel);

   if(QCBORItem_IsMapOrArray(*pItemToConsume) && !bIsEmpty) {
      /* There is only real work to do for non-empty maps and arrays */

      /* This works for definite- and indefinite-length maps and
       * arrays by using the nesting level
       */
      do {
         uReturn = QCBORDecode_Private_GetNextMapOrArray(pMe, pbEndedByBreak, &Item, NULL);
         if(QCBORDecode_IsUnrecoverableError(uReturn) ||
            uReturn == QCBOR_ERR_NO_MORE_ITEMS) {
            goto Done;
         }
      } while(Item.uNextNestLevel >= pItemToConsume->uNextNestLevel);

      *puNextNestLevel = Item.uNextNestLevel;

      uReturn = QCBOR_SUCCESS;

   } else {
      /* pItemToConsume is not a map or array. Just pass the nesting
       * level through. */
      *puNextNestLevel = pItemToConsume->uNextNestLevel;

      uReturn = QCBOR_SUCCESS;
   }

Done:
    return uReturn;
}


#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
/*
 * This consumes the next item. It returns the starting position of
 * the label and the length of the label. It also returns the nest
 * level of the item consumed.
 */
static QCBORError
QCBORDecode_Private_GetLabelAndConsume(QCBORDecodeContext *pMe,
                                       uint8_t            *puNestLevel,
                                       size_t             *puLabelStart,
                                       size_t             *puLabelLen)
{
   QCBORError uErr;
   QCBORItem  Item;
   uint8_t    uLevel;
   uint32_t   uLabelOffset;

   /* Get the label and consume it, should it be complex */
   *puLabelStart = UsefulInputBuf_Tell(&(pMe->InBuf));

   uErr = QCBORDecode_Private_GetNextMapOrArray(pMe, NULL, &Item, &uLabelOffset);
   if(uErr != QCBOR_SUCCESS) {
      goto Done;
   }
   *puLabelLen = uLabelOffset - *puLabelStart;
   *puNestLevel = Item.uNestingLevel;
   uErr = QCBORDecode_Private_ConsumeItem(pMe, &Item, NULL, &uLevel);

Done:
   return uErr;
}


/* Loop over items in a map until the end of the map looking for
 * duplicates. This starts at the current position in the map, not at
 * the beginning of the map.
 *
 * This saves and restores the traversal cursor and nest tracking so
 * they are the same on exit as they were on entry.
 */
static QCBORError
QCBORDecode_Private_CheckDups(QCBORDecodeContext *pMe,
                              const uint8_t       uNestLevel,
                              const size_t        uCompareLabelStart,
                              const size_t        uCompareLabelLen)
{
   QCBORError uErr;
   size_t     uLabelStart;
   size_t     uLabelLen;
   uint8_t    uLevel;
   int        nCompare;

   const QCBORDecodeNesting SaveNesting = pMe->nesting;
   const UsefulInputBuf     Save        = pMe->InBuf;

   do {
      uErr = QCBORDecode_Private_GetLabelAndConsume(pMe,
                                                    &uLevel,
                                                    &uLabelStart,
                                                    &uLabelLen);
      if(uErr != QCBOR_SUCCESS) {
         if(uErr == QCBOR_ERR_NO_MORE_ITEMS) {
            uErr = QCBOR_SUCCESS; /* Successful end */
         }
         break;
      }

      if(uLevel != uNestLevel) {
         break; /* Successful end of loop */
      }

      /* This check for dups works for labels that are preferred
       * serialization and are not maps. If the labels are not in
       * preferred serialization, then the check has to be more
       * complicated and is type-specific because it uses the decoded
       * value, not the encoded CBOR. It is further complicated for
       * maps because the order of items in a map that is a label
       * doesn't matter when checking that is is the duplicate of
       * another map that is a label. QCBOR so far only turns on this
       * dup checking as part of deterministic checking which requires preferred
       * serialization.  See 5.6 in RFC 8949.
       */
      nCompare = UsefulInputBuf_Compare(&(pMe->InBuf),
                                         uCompareLabelStart, uCompareLabelLen,
                                         uLabelStart, uLabelLen);
      if(nCompare == 0) {
         uErr = QCBOR_ERR_DUPLICATE_LABEL;
         break;
      }
   } while (1);

   pMe->nesting = SaveNesting;
   pMe->InBuf   = Save;

   return uErr;
}


/* This does sort order and duplicate detection on a map. The map and all
 * its members must be in preferred serialization so the comparisons
 * work correctly.
 */
static QCBORError
QCBORDecode_Private_CheckMap(QCBORDecodeContext *pMe, const QCBORItem *pMapToCheck)
{
   QCBORError uErr;
   uint8_t    uNestLevel;
   size_t     offset2, offset1, length2, length1;

   const QCBORDecodeNesting SaveNesting = pMe->nesting;
   const UsefulInputBuf Save = pMe->InBuf;
   pMe->bAllowAllLabels = 1;

   /* This loop runs over all the items in the map once, comparing
    * each adjacent pair for correct ordering. It also calls CheckDup
    * on each one which also runs over the remaining items in the map
    * checking for duplicates. So duplicate checking runs in n^2.
    */

   offset2 = SIZE_MAX;
   length2 = SIZE_MAX; // To avoid uninitialized warning
   while(1) {
      uErr = QCBORDecode_Private_GetLabelAndConsume(pMe,
                                                    &uNestLevel,
                                                    &offset1,
                                                    &length1);
      if(uErr != QCBOR_SUCCESS) {
         break;
      }

      if(uNestLevel < pMapToCheck->uNextNestLevel) {
         break; /* Successful exit from loop */
      }

      if(offset2 != SIZE_MAX) {
         /* Check that the labels are ordered. Check is not done the
          * first time through the loop when offset2 is unset. Since
          * this does comparison of the items in encoded form they
          * must be preferred serialization encoded. See RFC 8949
          * 4.2.1.
          */
         if(UsefulInputBuf_Compare(&(pMe->InBuf), offset2, length2, offset1, length1) > 0) {
            uErr = QCBOR_ERR_UNSORTED;
            break;
         }
      }

      uErr = QCBORDecode_Private_CheckDups(pMe,
                                           pMapToCheck->uNextNestLevel,
                                           offset1,
                                           length1);
      if(uErr != QCBOR_SUCCESS) {
         break;
      }

      offset2 = offset1;
      length2 = length1;
   }

   pMe->bAllowAllLabels = 0;
   pMe->nesting = SaveNesting;
   pMe->InBuf = Save;

   return uErr;
}
#endif /* ! QCBOR_DISABLE_DECODE_CONFORMANCE */

QCBORError
QCBORDecode_Private_GetItemChecks(QCBORDecodeContext *pMe,
                                  QCBORError          uErr,
                                  const size_t        uOffset,
                                  QCBORItem          *pDecodedItem)
{
   (void)pMe; /* Avoid warning for next two ifndefs */
   (void)uOffset;

#ifndef QCBOR_DISABLE_DECODE_CONFORMANCE
   if(uErr == QCBOR_SUCCESS &&
      pMe->uDecodeMode & QCBOR_DECODE_ONLY_SORTED_MAPS &&
      pDecodedItem->uDataType == QCBOR_TYPE_MAP) {
      /* Traverse map checking sort order and for duplicates */
      uErr = QCBORDecode_Private_CheckMap(pMe, pDecodedItem);
   }
#endif /* ! QCBOR_DISABLE_CONFORMANCE */

#ifndef QCBOR_DISABLE_TAGS
   if(uErr == QCBOR_SUCCESS &&
      !(pMe->uDecodeMode & QCBOR_DECODE_ALLOW_UNPROCESSED_TAG_NUMBERS) &&
      pDecodedItem->auTagNumbers[0] != CBOR_TAG_INVALID16) {
      /* Not QCBOR v1 mode; there are tag numbers -- check they were consumed */
      if(uOffset != pMe->uTagNumberCheckOffset ||
         pMe->uTagNumberIndex != QCBOR_ALL_TAGS_PROCESSED) {
         uErr = QCBOR_ERR_UNPROCESSED_TAG_NUMBER;
      }
   }
#endif /* ! QCBOR_DISABLE_TAGS */

   if(uErr != QCBOR_SUCCESS) {
      pDecodedItem->uDataType  = QCBOR_TYPE_NONE;
      pDecodedItem->uLabelType = QCBOR_TYPE_NONE;
   }

   return uErr;
}



/* Public function; see qcbor_main_decode.h */
QCBORError
QCBORDecode_GetNext(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   QCBORError uErr;
   size_t     uOffset;

   uOffset = UsefulInputBuf_Tell(&(pMe->InBuf));
   uErr = QCBORDecode_Private_GetNextTagContent(pMe, pDecodedItem);
   uErr = QCBORDecode_Private_GetItemChecks(pMe, uErr, uOffset, pDecodedItem);
   return uErr;
}


/* Public function; see qcbor_main_decode.h */
QCBORError
QCBORDecode_PeekNext(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   const QCBORDecodeNesting SaveNesting = pMe->nesting;
   const UsefulInputBuf Save = pMe->InBuf;

   QCBORError uErr = QCBORDecode_GetNext(pMe, pDecodedItem);

   pMe->nesting = SaveNesting;
   pMe->InBuf = Save;

   return uErr;
}


/* Public function; see qcbor_main_decode.h */
void
QCBORDecode_VPeekNext(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      pDecodedItem->uDataType  = QCBOR_TYPE_NONE;
      pDecodedItem->uLabelType = QCBOR_TYPE_NONE;
      return;
   }

   pMe->uLastError = (uint8_t)QCBORDecode_PeekNext(pMe, pDecodedItem);
}


/* Public function; see qcbor_main_decode.h */
void
QCBORDecode_VGetNext(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   if(pMe->uLastError != QCBOR_SUCCESS) {
      pDecodedItem->uDataType  = QCBOR_TYPE_NONE;
      pDecodedItem->uLabelType = QCBOR_TYPE_NONE;
      return;
   }

   pMe->uLastError = (uint8_t)QCBORDecode_GetNext(pMe, pDecodedItem);
   QCBORDecode_Private_SaveTagNumbers(pMe, pDecodedItem);
}


/* Public function; see qcbor_main_decode.h */
QCBORError
QCBORDecode_PartialFinish(QCBORDecodeContext *pMe, size_t *puConsumed)
{
   if(puConsumed != NULL) {
      *puConsumed = pMe->InBuf.cursor;
   }

   QCBORError uReturn = pMe->uLastError;

   if(uReturn != QCBOR_SUCCESS) {
      goto Done;
   }

   /* Error out if all the maps/arrays are not closed out */
   if(!DecodeNesting_IsCurrentAtTop(&(pMe->nesting))) {
      uReturn = QCBOR_ERR_ARRAY_OR_MAP_UNCONSUMED;
      goto Done;
   }

   /* Error out if not all the bytes are consumed */
   if(UsefulInputBuf_BytesUnconsumed(&(pMe->InBuf))) {
      uReturn = QCBOR_ERR_EXTRA_BYTES;
   }

Done:
   return uReturn;
}


/* Public function; see qcbor_main_decode.h */
QCBORError
QCBORDecode_Finish(QCBORDecodeContext *pMe)
{
#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
   /* Call the destructor for the string allocator if there is one.
    * Always called, even if there are errors; always have to clean up.
    */
   StringAllocator_Destruct(&(pMe->StringAllocator));
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */

   return QCBORDecode_PartialFinish(pMe, NULL);
}


/* Public function; see qcbor_main_decode.h */
void
QCBORDecode_VGetNextConsume(QCBORDecodeContext *pMe, QCBORItem *pDecodedItem)
{
   QCBORError uErr;

   QCBORDecode_VGetNext(pMe, pDecodedItem);
   if(pMe->uLastError != QCBOR_SUCCESS) {
      return;
   }
   uErr = QCBORDecode_Private_ConsumeItem(pMe,
                                          pDecodedItem,
                                          NULL,
                                         &pDecodedItem->uNextNestLevel);

   pMe->uLastError = (uint8_t)uErr;
}


/* Public function; see qcbor_main_decode.h */
QCBORError
QCBORDecode_EndCheck(QCBORDecodeContext *pMe)
{
   size_t     uCursorOffset;
   QCBORError uErr;

   uErr = QCBORDecode_GetError(pMe);
   if(uErr != QCBOR_SUCCESS) {
      return uErr;
   }

   uCursorOffset = UsefulInputBuf_Tell(&(pMe->InBuf));

   if(uCursorOffset == UsefulInputBuf_GetBufferLength(&(pMe->InBuf))) {
      return QCBOR_ERR_NO_MORE_ITEMS;
   }

   return QCBOR_SUCCESS;
}


/**
 * @brief Semi-private. Get pointer, length and item for an array or map.
 *
 * @param[in] pMe            The decode context.
 * @param[in] uType          CBOR major type, either array/map.
 * @param[out] pItem         The item for the array/map.
 * @param[out] pEncodedCBOR  Pointer and length of the encoded map or array.
 *
 * The next item to be decoded must be a map or array as specified by @c uType.
 *
 * @c pItem will be filled in with the label and tags of the array or map
 * in addition to @c pEncodedCBOR giving the pointer and length of the
 * encoded CBOR.
 *
 * When this is complete, the traversal cursor is at the end of the array or
 * map that was retrieved.
 */
void
QCBORDecode_Private_GetArrayOrMap(QCBORDecodeContext *pMe,
                                  const uint8_t       uType,
                                  QCBORItem          *pItem,
                                  UsefulBufC         *pEncodedCBOR)
{
   QCBORError uErr;
   uint8_t    uNestLevel;
   size_t     uStartingCursor;
   size_t     uStartOfReturned;
   size_t     uEndOfReturned;
   size_t     uTempSaveCursor;
   bool       bInMap;
   QCBORItem  LabelItem;
   bool       bEndedByBreak;

   bEndedByBreak = false;
   uStartingCursor = UsefulInputBuf_Tell(&(pMe->InBuf));
   bInMap = DecodeNesting_IsCurrentTypeMap(&(pMe->nesting));
   uErr = QCBORDecode_Private_GetNextMapOrArray(pMe, NULL, pItem, NULL);
   if(uErr != QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)uErr;
      return;
   }

   uint8_t uItemDataType = pItem->uDataType;
#ifndef QCBOR_DISABLE_NON_INTEGER_LABELS
   if(uItemDataType == QCBOR_TYPE_MAP_AS_ARRAY) {
      uItemDataType = QCBOR_TYPE_ARRAY;
   }
#endif /* ! QCBOR_DISABLE_NON_INTEGER_LABELS */

   if(uItemDataType != uType) {
      pMe->uLastError = QCBOR_ERR_UNEXPECTED_TYPE;
      return;
   }

   if(bInMap) {
      /* If the item is in a map, the start of the array/map
       * itself, not the label, must be found. Do this by
       * rewinding to the starting position and fetching
       * just the label data item. QCBORDecode_Private_GetNextTagNumber()
       * doesn't do any of the array/map item counting or nesting
       * level tracking. Used here it will just fetech the label
       * data item.
       *
       * Have to save the cursor and put it back to the position
       * after the full item once the label as been fetched by
       * itself.
       */
      uTempSaveCursor = UsefulInputBuf_Tell(&(pMe->InBuf));
      UsefulInputBuf_Seek(&(pMe->InBuf), uStartingCursor);

      /* Item has been fetched once so safe to ignore error */
      (void)QCBORDecode_Private_GetNextTagNumber(pMe, &LabelItem);

      uStartOfReturned = UsefulInputBuf_Tell(&(pMe->InBuf));
      UsefulInputBuf_Seek(&(pMe->InBuf), uTempSaveCursor);
   } else {
      uStartOfReturned = uStartingCursor;
   }

   /* Consume the entire array/map to find the end */
   uErr = QCBORDecode_Private_ConsumeItem(pMe, pItem, &bEndedByBreak, &uNestLevel);
   if(uErr != QCBOR_SUCCESS) {
      pMe->uLastError = (uint8_t)uErr;
      goto Done;
   }

   /* Fill in returned values */
   uEndOfReturned = UsefulInputBuf_Tell(&(pMe->InBuf));
   if(bEndedByBreak) {
      /* When ascending nesting levels, a break for the level above
       * was consumed. That break is not a part of what is consumed here. */
      uEndOfReturned--;
   }

   pEncodedCBOR->ptr = UsefulInputBuf_OffsetToPointer(&(pMe->InBuf), uStartOfReturned);
   pEncodedCBOR->len = uEndOfReturned - uStartOfReturned;

Done:
   return;
}



#ifndef QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS

/* ===========================================================================
   MemPool -- BUILT-IN SIMPLE STRING ALLOCATOR

   This implements a simple sting allocator for indefinite-length
   strings that can be enabled by calling QCBORDecode_SetMemPool(). It
   implements the function type QCBORStringAllocate and allows easy
   use of it.

   This particular allocator is built-in for convenience. The caller
   can implement their own.  All of this following code will get
   dead-stripped if QCBORDecode_SetMemPool() is not called.

   This is a very primitive memory allocator. It does not track
   individual allocations, only a high-water mark. A free or
   reallocation must be of the last chunk allocated.

   The size of the pool and offset to free memory are packed into the
   first 8 bytes of the memory pool so we don't have to keep them in
   the decode context. Since the address of the pool may not be
   aligned, they have to be packed and unpacked as if they were
   serialized data of the wire or such.

   The sizes packed in are uint32_t to be the same on all CPU types
   and simplify the code.
   ========================================================================== */


static int
MemPool_Unpack(const void *pMem, uint32_t *puPoolSize, uint32_t *puFreeOffset)
{
   // Use of UsefulInputBuf is overkill, but it is convenient.
   UsefulInputBuf UIB;

   // Just assume the size here. It was checked during SetUp so
   // the assumption is safe.
   UsefulInputBuf_Init(&UIB, (UsefulBufC){pMem,QCBOR_DECODE_MIN_MEM_POOL_SIZE});
   *puPoolSize     = UsefulInputBuf_GetUint32(&UIB);
   *puFreeOffset   = UsefulInputBuf_GetUint32(&UIB);
   return UsefulInputBuf_GetError(&UIB);
}


static int
MemPool_Pack(UsefulBuf Pool, uint32_t uFreeOffset)
{
   // Use of UsefulOutBuf is overkill, but convenient. The
   // length check performed here is useful.
   UsefulOutBuf UOB;

   UsefulOutBuf_Init(&UOB, Pool);
   UsefulOutBuf_AppendUint32(&UOB, (uint32_t)Pool.len); // size of pool
   UsefulOutBuf_AppendUint32(&UOB, uFreeOffset); // first free position
   return (int)UsefulOutBuf_GetError(&UOB);
}


/*
 Internal function for an allocation, reallocation free and destuct.

 Having only one function rather than one each per mode saves space in
 QCBORDecodeContext.

 Code Reviewers: THIS FUNCTION DOES POINTER MATH
 */
static UsefulBuf
MemPool_Function(void *pPool, void *pMem, size_t uNewSize)
{
   UsefulBuf ReturnValue = NULLUsefulBuf;

   uint32_t uPoolSize;
   uint32_t uFreeOffset;

   if(uNewSize > UINT32_MAX) {
      // This allocator is only good up to 4GB.  This check should
      // optimize out if sizeof(size_t) == sizeof(uint32_t)
      goto Done;
   }
   const uint32_t uNewSize32 = (uint32_t)uNewSize;

   if(MemPool_Unpack(pPool, &uPoolSize, &uFreeOffset)) {
      goto Done;
   }

   if(uNewSize) {
      if(pMem) {
         // REALLOCATION MODE
         // Calculate pointer to the end of the memory pool.  It is
         // assumed that pPool + uPoolSize won't wrap around by
         // assuming the caller won't pass a pool buffer in that is
         // not in legitimate memory space.
         const void *pPoolEnd = (uint8_t *)pPool + uPoolSize;

         // Check that the pointer for reallocation is in the range of the
         // pool. This also makes sure that pointer math further down
         // doesn't wrap under or over.
         if(pMem >= pPool && pMem < pPoolEnd) {
            // Offset to start of chunk for reallocation. This won't
            // wrap under because of check that pMem >= pPool.  Cast
            // is safe because the pool is always less than UINT32_MAX
            // because of check in QCBORDecode_SetMemPool().
            const uint32_t uMemOffset = (uint32_t)((uint8_t *)pMem - (uint8_t *)pPool);

            // Check to see if the allocation will fit. uPoolSize -
            // uMemOffset will not wrap under because of check that
            // pMem is in the range of the uPoolSize by check above.
            if(uNewSize <= uPoolSize - uMemOffset) {
               ReturnValue.ptr = pMem;
               ReturnValue.len = uNewSize;

               // Addition won't wrap around over because uNewSize was
               // checked to be sure it is less than the pool size.
               uFreeOffset = uMemOffset + uNewSize32;
            }
         }
      } else {
         // ALLOCATION MODE
         // uPoolSize - uFreeOffset will not underflow because this
         // pool implementation makes sure uFreeOffset is always
         // smaller than uPoolSize through this check here and
         // reallocation case.
         if(uNewSize <= uPoolSize - uFreeOffset) {
            ReturnValue.len = uNewSize;
            ReturnValue.ptr = (uint8_t *)pPool + uFreeOffset;
            uFreeOffset    += (uint32_t)uNewSize;
         }
      }
   } else {
      if(pMem) {
         // FREE MODE
         // Cast is safe because of limit on pool size in
         // QCBORDecode_SetMemPool()
         uFreeOffset = (uint32_t)((uint8_t *)pMem - (uint8_t *)pPool);
      } else {
         // DESTRUCT MODE
         // Nothing to do for this allocator
      }
   }

   UsefulBuf Pool = {pPool, uPoolSize};
   MemPool_Pack(Pool, uFreeOffset);

Done:
   return ReturnValue;
}


/* Public function; see qcbor_main_decode.h */
QCBORError
QCBORDecode_SetMemPool(QCBORDecodeContext *pMe,
                       UsefulBuf           Pool,
                       bool                bAllStrings)
{
   // The pool size and free mem offset are packed into the beginning
   // of the pool memory. This compile time check makes sure the
   // constant in the header is correct.  This check should optimize
   // down to nothing.
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant
#endif
   if(QCBOR_DECODE_MIN_MEM_POOL_SIZE < 2 * sizeof(uint32_t)) {
      return QCBOR_ERR_MEM_POOL_SIZE;
   }
#ifdef _MSC_VER
#pragma warning(pop)
#endif

   // The pool size and free offset packed in to the beginning of pool
   // memory are only 32-bits. This check will optimize out on 32-bit
   // machines.
   if(Pool.len > UINT32_MAX) {
      return QCBOR_ERR_MEM_POOL_SIZE;
   }

   // This checks that the pool buffer given is big enough.
   if(MemPool_Pack(Pool, QCBOR_DECODE_MIN_MEM_POOL_SIZE)) {
      return QCBOR_ERR_MEM_POOL_SIZE;
   }

   QCBORDecode_SetUpAllocator(pMe, MemPool_Function, Pool.ptr, bAllStrings);

   return QCBOR_SUCCESS;
}
#endif /* QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS */





/* Public function; see qcbor_main_decode.h */
void
QCBORDecode_CompatibilityV1(QCBORDecodeContext *pMe)
{
   pMe->uDecodeMode |= QCBOR_DECODE_ALLOW_UNPROCESSED_TAG_NUMBERS;
#ifndef QCBOR_DISABLE_TAGS
   QCBORDecode_InstallTagDecoders(pMe, QCBORDecode_TagDecoderTablev1, NULL);
#endif /* ! QCBOR_DISABLE_TAGS */
}


// Improvement: add methods for wrapped CBOR, a simple alternate
// to EnterBstrWrapped

