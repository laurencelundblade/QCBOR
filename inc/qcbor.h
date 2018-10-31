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

/*==============================================================================
 Modifications beyond the version released on CAF are under the MIT license:
 
 Copyright 2018 Laurence Lundblade
 
 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the
 "Software"), to deal in the Software without restriction, including
 without limitation the rights to use, copy, modify, merge, publish,
 distribute, sublicense, and/or sell copies of the Software, and to
 permit persons to whom the Software is furnished to do so, subject to
 the following conditions:
 
 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 ==============================================================================*/


/*===================================================================================
 FILE:  qcbor.h
 
 DESCRIPTION:  This is the full public API and data structures for QCBOR
 
 EDIT HISTORY FOR FILE:
 
 This section contains comments describing changes made to the module.
 Notice that changes are listed in reverse chronological order.
 
 when               who             what, where, why
 --------           ----            ---------------------------------------------------
 07/05/17           llundbla        Add bstr wrapping of maps/arrays for COSE
 03/01/17           llundbla        More data types; decoding improvements and fixes
 11/13/16           llundbla        Integrate most TZ changes back into github version.
 09/30/16           gkanike         Porting to TZ.
 03/15/16           llundbla        Initial Version.
 
 =====================================================================================*/

#ifndef __QCBOR__qcbor__
#define __QCBOR__qcbor__

/*...... This is a ruler that is 80 characters long...........................*/

/* ===========================================================================
   BEGINNING OF PRIVATE PART OF THIS FILE

   Caller of QCBOR should not reference any of the details below up until
   the start of the public part.
   =========================================================================== */

/*
 Standard integer types are used in the interface to be precise about
 sizes to be better at preventing underflow/overflow errors.
 */
#include <stdint.h>
#include <stdbool.h>
#include "UsefulBuf.h"


/*
 The maxium nesting of arrays and maps when encoding or decoding. 
 (Further down in the file there is a definition that refers to this 
 that is public. This is done this way so there can be a nice
 separation of public and private parts in this file.
*/
#define QCBOR_MAX_ARRAY_NESTING1 10 // Do not increase this over 255


/*  
 PRIVATE DATA STRUCTURE 
 
 Holds the data for tracking array and map nesting during encoding. Pairs up with
 the Nesting_xxx functions to make an "object" to handle nesting encoding.
 
 uStart is a uint32_t instead of a size_t to keep the size of this
 struct down so it can be on the stack without any concern.  It would be about
 double if size_t was used instead.
 
 64-bit machine: 10 * (4 + 2 + 1 + 1) + 8 = 88 bytes
 32-bit machine: 10 * (4 + 2 + 1 + 1) + 4 = 84 bytes
*/
typedef struct __QCBORTrackNesting {
   // PRIVATE DATA STRUCTURE
   struct {
      // See function OpenArrayInternal() for detailed comments on how this works
      uint32_t  uStart;     // uStart is the byte position where the array starts
      uint16_t  uCount;     // Number of items in the arrary or map; counts items in a map, not pairs of items 
      uint8_t   uMajorType; // Indicates if item is a map or an array
   } pArrays[QCBOR_MAX_ARRAY_NESTING1+1], // stored state for the nesting levels
   *pCurrentNesting; // the current nesting level
} QCBORTrackNesting;


/*  
 PRIVATE DATA STRUCTURE 
 
 Context / data object for encoding some CBOR. Used by all encode functions to 
 form a public "object" that does the job of encdoing.
 
 64-bit machine: 27 + 1 (+ 4 padding) + 88 = 32+88 = 120 bytes
 32-bit machine: 15 + 1 + 84 = 90 bytes
*/
struct _QCBOREncodeContext {
   // PRIVATE DATA STRUCTURE
   UsefulOutBuf      OutBuf;  // Pointer to output buffer, its length and position in it
   uint8_t           uError;  // Error state
   QCBORTrackNesting nesting; // Keep track of array and map nesting
};


/*
 PRIVATE DATA STRUCTURE
 
 Holds the data for array and map nesting for decoding work. This structure
 and the DecodeNesting_xxx functions form an "object" that does the work
 for arrays and maps.
 
 Size approximation (varies with CPU/compiler):
   64-bit machine: 4 * 10 + 8 + 4 padding =  56
   32-bit machine: 4 * 10 + 4 = 44
 */
typedef struct __QCBORDecodeNesting  {
  // PRIVATE DATA STRUCTURE
   struct {
      uint16_t uCount;  
      uint8_t  uMajorType;
   } pMapsAndArrays[QCBOR_MAX_ARRAY_NESTING1+1],
   *pCurrent;
} QCBORDecodeNesting;


/* 
 PRIVATE DATA STRUCTURE

 The decode context. This data structure plus the public QCBORDecode_xxx
 functions form an "object" that does CBOR decoding.

 Size approximation (varies with CPU/compiler):
   64-bit machine: 32 + 1 + 1 + 6 bytes padding + 56 + 8 = 104 bytes
   32-bit machine: 16 + 1 + 1 + 2 bytes padding + 44 + 4 = 68 bytes
 */
struct _QCBORDecodeContext {
   // PRIVATE DATA STRUCTURE   
   UsefulInputBuf InBuf;
   
   uint8_t        uDecodeMode;
   uint8_t        bStringAllocateAll;
   
   QCBORDecodeNesting nesting;
   
   // This is NULL or points to a QCBORStringAllocator. It is void
   // here because _QCBORDecodeContext is defined early in the
   // private part of this file and QCBORStringAllocat is defined
   // later in the public part of this file.
   void *pStringAllocator;
};

// Used internally in the impementation here
// Must not conflict with any of the official CBOR types
#define CBOR_MAJOR_NONE_TYPE_RAW  9
#define CBOR_MAJOR_NONE_TAG_LABEL_REORDER 10

/* ===========================================================================
   END OF PRIVATE PART OF THIS FILE

   BEGINNING OF PUBLIC PART OF THIS FILE
   =========================================================================== */



/* ===========================================================================
   BEGINNING OF CONSTANTS THAT COME FROM THE CBOR STANDARD, RFC 7049
 
   It is not necessary to use these directly when encoding or decoding
   CBOR with this implementation.
   =========================================================================== */

/* Standard CBOR Major type for positive integers of various lengths */
#define CBOR_MAJOR_TYPE_POSITIVE_INT 0

/* Standard CBOR Major type for negative integer of various lengths */
#define CBOR_MAJOR_TYPE_NEGATIVE_INT 1

/* Standard CBOR Major type for an array of arbitrary 8-bit bytes. */
#define CBOR_MAJOR_TYPE_BYTE_STRING  2

/* Standard CBOR Major type for a UTF-8 string. Note this is true 8-bit UTF8
 with no encoding and no NULL termination */
#define CBOR_MAJOR_TYPE_TEXT_STRING  3

/* Standard CBOR Major type for an ordered array of other CBOR data items */
#define CBOR_MAJOR_TYPE_ARRAY        4

/* Standard CBOR Major type for CBOR MAP. Maps an array of pairs. The
 first item in the pair is the "label" (key, name or identfier) and the second
 item is the value.  */
#define CBOR_MAJOR_TYPE_MAP          5

/* Standard CBOR optional tagging. This tags things like dates and URLs */
#define CBOR_MAJOR_TYPE_OPTIONAL     6

/* Standard CBOR extra simple types like floats and the values true and false */
#define CBOR_MAJOR_TYPE_SIMPLE       7


/*
 These are special values for the AdditionalInfo bits that are part of the first byte.
 Mostly they encode the length of the data item.
 */
#define LEN_IS_ONE_BYTE    24
#define LEN_IS_TWO_BYTES   25
#define LEN_IS_FOUR_BYTES  26
#define LEN_IS_EIGHT_BYTES 27
#define ADDINFO_RESERVED1  28
#define ADDINFO_RESERVED2  29
#define ADDINFO_RESERVED3  30
#define LEN_IS_INDEFINITE  31


/*
 24 is a special number for CBOR. Integers and lengths
 less than it are encoded in the same byte as the major type
 */
#define CBOR_TWENTY_FOUR   24


/*
 Tags that are used with CBOR_MAJOR_TYPE_OPTIONAL. These are
 the ones defined in the CBOR spec.
 */
/** See QCBOREncode_AddDateString() below */
#define CBOR_TAG_DATE_STRING    0
/** See QCBOREncode_AddDateEpoch_2() */
#define CBOR_TAG_DATE_EPOCH     1
#define CBOR_TAG_POS_BIGNUM     2
#define CBOR_TAG_NEG_BIGNUM     3
#define CBOR_TAG_FRACTION       4
#define CBOR_TAG_BIGFLOAT       5
/* The data in byte string should be converted in base 64 URL when encoding in JSON or similar text-based representations */
#define CBOR_TAG_ENC_AS_B64URL 21
/* The data in byte string should be encoded in base 64 when encoding in JSON */
#define CBOR_TAG_ENC_AS_B64    22
/* The data in byte string should be encoded in base 16 when encoding in JSON */
#define CBOR_TAG_ENC_AS_B16    23
#define CBOR_TAG_CBOR          24
/** The data in the string is a URIs, as defined in RFC3986 */
#define CBOR_TAG_URI           32
/** The data in the string is a base 64'd URL */
#define CBOR_TAG_B64URL        33
/** The data in the string is base 64'd */
#define CBOR_TAG_B64           34
/** regular expressions in Perl Compatible Regular Expressions (PCRE) / JavaScript syntax ECMA262. */
#define CBOR_TAG_REGEX         35
/** MIME messages (including all headers), as defined in RFC2045 */
#define CBOR_TAG_MIME          36
/** Binary UUID */
#define CBOR_TAG_BIN_UUID      37
/** The data is CBOR data */
#define CBOR_TAG_CBOR_MAGIC 55799
#define CBOR_TAG_NONE  UINT64_MAX


/*
 Values for the 5 bits for items of major type 7
 */
#define CBOR_SIMPLEV_FALSE   20
#define CBOR_SIMPLEV_TRUE    21
#define CBOR_SIMPLEV_NULL    22
#define CBOR_SIMPLEV_UNDEF   23
#define CBOR_SIMPLEV_ONEBYTE 24
#define HALF_PREC_FLOAT      25
#define SINGLE_PREC_FLOAT    26
#define DOUBLE_PREC_FLOAT    27
#define CBOR_SIMPLE_BREAK    31



/* ===========================================================================
 
 END OF CONSTANTS THAT COME FROM THE CBOR STANDARD, RFC 7049
 
 BEGINNING OF PUBLIC INTERFACE FOR QCBOR ENCODER / DECODER
 
 =========================================================================== */

/**
 
 @file qcbor.h
 
 Q C B O R   E n c o d e / D e c o d e
 
 This implements CBOR -- Concise Binary Ojbect Representation as defined
 in RFC 7049. More info is at http://cbor.io.  This is a near-complete
 implementation of the specification. Limitations are listed further down.
 
 CBOR is intentinonally designed to be translatable to JSON, but not
 all CBOR can convert to JSON. See RFC 7049 for more info on how to
 construct CBOR that is the most JSON friendly.
 
 The memory model for encoding and decoding is that encoded CBOR
 must be in a contigious buffer in memory.  During encoding the
 caller must supply an output buffer and if the encoding would go
 off the end of the buffer an error is returned.  During decoding
 the caller supplies the encoded CBOR in a contiguous buffer
 and the decoder returns pointers and lengths into that buffer
 for strings.
 
 This implementation does not use malloc. All data structures
 passed in/out of the APIs can fit on the stack.
 
 Decoding of indefinite length strings is a special case that requires
 a "string allocator" to allocate memory into which the segments of
 the string are coalesced. Without this, decoding will error out if
 an indefinite length string is encountered (indefinite length maps
 and arrays do not require the string allocator). A simple string
 allocator called MemPool is built-in and will work if supplied with
 a block of memory to allocate. The string allocator can optionally
 use malloc() or some other custom scheme.
 
 Here are some terms and definitions:
 
 - "Item", "Data Item": An integer or string or such. The basic "thing" that
 CBOR is about. An array is an item itself that contains some items.
 
 - "Array": An ordered sequence of items, the same as JSON.
 
 - "Map": A collection of label/value pairs. Each pair is a data
 item. A JSON "object" is the same as a CBOR "map".
 
 - "Label": The data item in a pair in a map that names or identifies the
 pair, not the value. This implementation refers to it as a "label".
 JSON refers to it as the "name". The CBOR RFC refers to it this as a "key".
 This implementation chooses label instead because key is too easily confused
 with a cryptographic key. The COSE standard, which uses CBOR, has also
 choosen to use the term "label" rather than "key" for this same reason.
 
 - "Tag": Optional info that can be added before each data item. This is always
 CBOR major type 6.
 
 - "Initial Byte": The first byte of an encoded item. Encoding and decoding of
 this byte is taken care of by the implementation.
 
 - "Additional Info": In addition to the major type, all data items have some
 other info. This is usually the length of the data, but can be several
 other things. Encoding and decoding of this is taken care of by the
 implementation.
 
 CBOR has two mechanisms for tagging and labeling the primitive data
 values like integers and strings. For example an integter that
 represents someone's birthday in epoch seconds since Jan 1, 1970
 could be encoded like this:
 
 - First it is CBOR_MAJOR_TYPE_POSITIVE_INT, the primitive positive
 integer.
 - Next it has a "tag" CBOR_TAG_DATE_EPOCH indicating the integer
 represents a date in the form of the number of seconds since
 Jan 1, 1970.
 - Last it has a string "label" like "BirthDate" indicating
 the meaning of the data.
 
 The encoded binary looks like this:
   a1                      # Map of 1 item
      69                   # Indicates text string of 9 bytes
        426972746844617465 # The text "BirthDate"
     c1                    # Tags next int as epoch date
        1a                 # Indicates 4 byte integer
            580d4172       # unsigned integer date 1477263730
 
 Implementors using this API will primarily work with labels. Generally
 tags are only needed for making up new data types. This implementation
 covers most of the data types defined in the RFC using tags. However,
 it does allow for the creation of news tags if necessary.
 
 This implementation explicitly supports labels that are text strings
 and integers. Text strings translate nicely into JSON objects and
 are very readable.  Integer labels are much less readable, but
 can be very compact. If they are in the range of -23 to
 23 they take up only one byte.
 
 CBOR allows a label to be any type of data including an array or 
 a map. It is possible to use this API to construct and
 parse such labels, but it is not explicitly supported.
 
 
 A common encoding usage mode is to invoke the encoding twice. First
 with no output buffer to compute the length of the needed output
 buffer. Then the correct sized output buffer is allocated. Last the
 encoder is invoked again, this time with the output buffer.
 
 The double invocation is not required if the max output buffer size
 can be predicted. This is usually possible for simple CBOR structures.
 If the double invocation is implemented it can be
 in a loop or function as in the example code so that the code doesn't
 have to actually be written twice, saving code size.
 
 If a buffer too small to hold the encoded output is given, the error
 QCBOR_ERR_BUFFER_TOO_SMALL will be returned. Data will never be
 written off the end of the output buffer no matter which functions
 here are called or what parameters are passed to them.
 
 The error handling is simple. The only possible errors are trying to
 encode structures that are too large or too complex. There are no
 internal malloc calls so there will be no failures for out of memory.
 Only the final call, QCBOREncode_Finish(), returns an error code.
 Once an error happens, the encoder goes into an error state and calls
 to it will do nothing so the encoding can just go on. An error
 check is not needed after every data item is added.
 
 Encoding generally proceeds by calling QCBOREncode_Init(), calling
 lots of "Add" functions and calling QCBOREncode_Finish(). There
 are many "Add" functions for various data types. The input
 buffers need only to be valid during the "Add" calls. The 
 data is copied into the output buf during the "Add" call.
 
 TODO: remote discussion of tags
 There are several "Add" functions / macros for each type. The one
 with named ending in "_2", for example QCBOREncode_AddInt64_3(),
 takes parameters for labels and tags and is the most powerful.
 Generally it is better to use the macros that only take the
 parameters necessary. For example, QCBOREncode_AddInt64(),
 only takes the integer value to add with no labels and tags.
 
 The simplest aggregate type is an array, which is a simple ordered
 set of items without labels the same as JSON arrays. Call 
 QCBOREncode_OpenArray() to open a new array, then "Add" to
 put items in the array and then QCBOREncode_CloseArray(). Nesting
 to a limit is allowed.  All opens must be matched by closes or an
 encoding error will be returned.
 
 The other aggregate is a map which does use labels.  For convenience
 there are macros for adding each type to a map, one with a string
 label, the other with an integer label. (Part of the goal of this
 design is to make the code implementing a CBOR protocol easy to
 read).
 
 Note that when you nest arrays or maps in a map, the nested
 array or map has a label.
 
 As mentioned callers of this API will generally not need tags
 and thus not need the "_3" functions, but they are available
 if need be. There is an IANA registry for new tags that are
 for broad use and standardization as per RFC 7049. It is also 
 allowed for protocols to make up new tags in the range above 256.
 Note that even arrays and maps can be tagged.
 
 Tags in CBOR are a bit open-ended in particular allowing
 multiple tags per item, and the ability to tag deeply nested maps
 and arrays. Partly this is good as it allows them to be used 
 in lots of ways, but also makes a general purpose decoder 
 like this more difficult.
 
 This implementation only supports one tag per data item
 during encoding and decoding.
  
 Summary Limits of this implementation:
 - The entire encoded CBOR must fit into contiguous memory.
 - Max size of encoded / decoded CBOR data is UINT32_MAX (4GB).
 - Max array / map nesting level when encoding / decoding is
   QCBOR_MAX_ARRAY_NESTING (this is typically 10).
 - Max items in an array or map when encoding / decoding is
   QCBOR_MAX_ITEMS_IN_ARRAY (typicall 65,536).
 - Does not support encoding indefinite lengths (decoding is supported).
 - Does not directly support some tagged types: decimal fractions, big floats
 - Does not directly support labels in maps other than text strings and ints.
 - Does not directly support int labels > INT64_MAX
 - Epoch dates limited to INT64_MAX (+/- 292 billion years)
 - Only one tag per data item is supported for tag values > 62
 - Tags on labels are ignored
 
 This implementation is intended to run on 32 and 64-bit CPUs. It
 will probably work on 16-bit CPUs but less efficiently.
 
 The public interface uses size_t for all lengths. Internally the
 implementation uses 32-bit lengths by design to use less memory and
 fit structures on the stack. This limits the encoded
 CBOR it can work with to size UINT32_MAX (4GB) which should be
 enough.
 
 This implementation assume two's compliment integer
 machines. Stdint.h also requires this. It of course would be easy to
 fix this implementation for another integer representation, but all
 modern machines seem to be two's compliment.
 
 */


/**
 The maximum number of items in a single array or map when encoding of decoding.
*/
#define QCBOR_MAX_ITEMS_IN_ARRAY (UINT16_MAX) // This value is 65,535 a lot of items for an array

/** 
 The maxium nesting of arrays and maps when encoding or decoding. The
 error QCBOR_ERR_ARRAY_NESTING_TOO_DEEP will be returned on encoding
 of decoding if it is exceeded
*/
#define QCBOR_MAX_ARRAY_NESTING  QCBOR_MAX_ARRAY_NESTING1




/** The encode or decode completely correctly. */
#define QCBOR_SUCCESS                     0

/** The buffer provided for the encoded output when doing encoding was
 too small and the encoded output will not fit. */
#define QCBOR_ERR_BUFFER_TOO_SMALL        1

/**  During encoding or decoding, the array or map nesting was deeper than this
 implementation can handle. Note that in the interest of code size and
 memory use, this implementation has a hard limit on array nesting. The
 limit is defined as the constant QCBOR_MAX_ARRAY_NESTING. */
#define QCBOR_ERR_ARRAY_NESTING_TOO_DEEP  2

/**  During decoding the array or map had too many items in it. This limit is quite
 high at 65,535. */
#define QCBOR_ERR_ARRAY_TOO_LONG          3

/**  During encoding, more arrays or maps were closed than opened. This is a
 coding error on the part of the caller of the encoder. */
#define QCBOR_ERR_TOO_MANY_CLOSES         4

/**  During decoding, some CBOR construct was encountered that this decoder
 doesn't support. */
#define QCBOR_ERR_UNSUPPORTED             5

/**  During decoding, hit the end of the given data to decode. For example,
 a byte string of 100 bytes was expected, but the end of the input
 was hit before finding those 100 bytes.  Corrupted CBOR
 input will often result in this error. */
#define QCBOR_ERR_HIT_END                 6

/** The length of the input buffer was too large. This might happen
 on a 64-bit machine when a buffer larger than INT32_MAX is passed */
#define QCBOR_ERR_BUFFER_TOO_LARGE        7

/** The simple value added for encoding (e.g. passed to QCBOR_AddSimple) was not valid */
#define QCBOR_ERR_INVALID_SIMPLE          8

/** During parsing, the integer received was larger than can be handled. This is
 most likely a large negative number as CBOR can represent large negative integers
 that C cannot */
#define QCBOR_ERR_INT_OVERFLOW            9

/** During parsing, the label for a map entry is bad. An array is used as a map label,
 in mode to accept strings only as labels and it is not a string... */
#define QCBOR_ERR_MAP_LABEL_TYPE          10

/** The number of array or map opens was not matched by the number of closes */
#define QCBOR_ERR_ARRAY_OR_MAP_STILL_OPEN 11

/** The simple value is not between CBOR_SIMPLEV_FALSE and CBOR_SIMPLEV_UNDEF */
#define QCBOR_ERR_BAD_SIMPLE              12 // todo combine with 8?

/** Date greater than +- 292 billion years from Jan 1 1970 encountered during parsing */
#define QCBOR_ERR_DATE_OVERFLOW           13

/** The CBOR is not valid (a simple type is encoded wrong)  */
#define QCBOR_ERR_INVALID_CBOR            14

/** Optional tagging that doesn't make sense (an int is tagged as a date string) or can't be handled. */
#define QCBOR_ERR_BAD_OPT_TAG             15

/** Returned by QCBORDecode_Finish() if all the inputs bytes have not been consumed */
#define QCBOR_ERR_EXTRA_BYTES             16

/** Closing something different than is open */
#define QCBOR_ERR_CLOSE_MISMATCH          17

/** Unable to decode an indefinitely length string because no string allocator was configured */
#define QCBOR_ERR_NO_STRING_ALLOCATOR     18

/** One of the segments in an indefinite length string is of the wrong type */
#define QCBOR_ERR_INDEFINITE_STRING_SEG   19

/** Error allocating space for a string, usually for an indefinite length string */
#define QCBOR_ERR_STRING_ALLOC            20

/** The a break occurred outside an indefinite length item */
#define QCBOR_ERR_BAD_BREAK               21


/** See QCBORDecode_Init() */
#define QCBOR_DECODE_MODE_NORMAL            0
/** See QCBORDecode_Init() */
#define QCBOR_DECODE_MODE_MAP_STRINGS_ONLY  1
/** See QCBORDecode_Init() */
#define QCBOR_DECODE_MODE_MAP_AS_ARRAY      2





/* Do not renumber these. Code depends on some of these values. */
/** Type for an integer that decoded either between INT64_MIN and INT32_MIN or INT32_MAX and INT64_MAX; val.int64 */
#define QCBOR_TYPE_INT64          2
/** Type for an integer that decoded to a more than INT64_MAX and UINT64_MAX; val.uint64 */
#define QCBOR_TYPE_UINT64         3
/** Type for an array. The number of items in the array is in val.uCount. */
#define QCBOR_TYPE_ARRAY          4
/** Type for a map; number of items in map is in val.uCount */ // todo note how map decoding works
#define QCBOR_TYPE_MAP            5
/** Type for a buffer full of bytes. Data is in val.string. */
#define QCBOR_TYPE_BYTE_STRING    6
/** Type for a UTF-8 string. It is not NULL terminated. Data is in val.string.  */
#define QCBOR_TYPE_TEXT_STRING    7
/** Type for a floating point number. Data is in val.float. */
#define QCBOR_TYPE_FLOAT         26
/** Type for a double floating point number. Data is in val.double. */
#define QCBOR_TYPE_DOUBLE        27
/** Type for a postive big number. Data is in val.bignum, a pointer and a length. */
#define QCBOR_TYPE_POSBIGNUM     9
/** Type for a negative big number. Data is in val.bignum, a pointer and a length. */
#define QCBOR_TYPE_NEGBIGNUM     10
/** Type for RFC xxxx date string, possibly with time zone.Data is in val.dateString */
#define QCBOR_TYPE_DATE_STRING   11
/** Type for integer seconds since Jan 1970 + floating point fraction. Data is in val.epochDate */
#define QCBOR_TYPE_DATE_EPOCH    12
/** A simple type that this CBOR implementation doesn't know about; Type is in val.uSimple. */
#define QCBOR_TYPE_UKNOWN_SIMPLE 13
/** Type for the simple value false; nothing more; nothing in val union. */
#define QCBOR_TYPE_FALSE         20
/** Type for the simple value true; nothing more; nothing in val union. */
#define QCBOR_TYPE_TRUE          21
/** Type for the simple value null; nothing more; nothing in val union. */
#define QCBOR_TYPE_NULL          22
/** Type for the simple value undef; nothing more; nothing in val union. */
#define QCBOR_TYPE_UNDEF         23

#define QCBOR_TYPE_BREAK         31 // Used internally; never returned

#define QCBOR_TYPE_OPTTAG       254 // Used internally; never returned



/*
 Approx Size of this:
   8 + 8 + 1 + 1 + 1 + (1 padding) + (4 padding on 64-bit machine) = 24 for first part (20 on a 32-bit machine)
   16 bytes for the val union
   16 bytes for label union
   total = 56 bytes (52 bytes on 32-bit machine)
 */

/**
 QCBORItem holds the type, value and other info for a decoded item returned by GetNextItem().
 */
typedef struct _QCBORItem {
   uint8_t  uDataType;     /** Tells what element of the val union to use. One of QCBOR_TYPE_XXXX */
   uint8_t  uNestingLevel; /** How deep the nesting from arrays and maps are. 0 is the top level with no arrays or maps entered */
   uint8_t  uLabelType;    /** Tells what element of the label union to use */
   uint8_t  uDataAlloc;    /** 1 if allocated with string allocator, 0 if not. See xxx TODO: more work; also exceeds padding size on 32-bit machine*/
   uint8_t  uLabelAlloc;   /** Like uDataAlloc, but for label */
   uint8_t  uNextNestLevel; /** If not equal to uNestingLevel, this item closed out at least one map/array */
   
   union {
      int64_t     int64;      /** The value for uDataType QCBOR_TYPE_INT64 */
      uint64_t    uint64;     /** The value for uDataType QCBOR_TYPE_UINT64 */

      UsefulBufC  string;     /** The value for uDataType QCBOR_TYPE_BYTE_STRING and QCBOR_TYPE_TEXT_STRING */
      uint16_t    uCount;     /** The "value" for uDataType QCBOR_TYPE_ARRAY or QCBOR_TYPE_MAP -- the number of items in the array or map */ // TODO: indefinite len arrays
      float       fnum;       /** The value for uDataType QCBOR_TYPE_FLOAT */
      double      dfnum;      /** The value for uDataType QCBOR_TYPE_DOUBLE */
      struct {
         int64_t  nSeconds;
         double   fSecondsFraction;
      } epochDate;            /** The value for uDataType QCBOR_TYPE_DATE_EPOCH */
      UsefulBufC  dateString; /** The value for uDataType QCBOR_TYPE_DATE_STRING */
      UsefulBufC  bigNum;     /** The value for uDataType QCBOR_TYPE_BIGNUM */
      uint8_t     uSimple;    /** The integer value for unknown simple types */
      
   } val;  /** The union holding the item's value. Select union member based on uDataType */
   
   union {
      UsefulBufC  string;  /** The label for uLabelType QCBOR_TYPE_BYTE_STRING and QCBOR_TYPE_TEXT_STRING */
      int64_t     int64;   /** The label for uLabelType for QCBOR_TYPE_INT64 */
      uint64_t    uint64;  /** The label for uLabelType for QCBOR_TYPE_UINT64 */
   } label; /** Union holding the different label types selected based on uLabelType */
   
   uint64_t uTag;     /** Any tag value that is greater than 63.  If there is more than one, then only the last one is recorded */
   uint64_t uTagBits; /** Bits corresponding to tag values less than 63 as defined in RFC 7049, section 2.4 */
   
} QCBORItem;


/**
  This is a set of functions and pointer context (in object-oriented parlance,
 an "object") used to allocate memory for coalescing the segments of an indefinite
 length string into one.
 
 The fAllocate function works as an initial allocator and a reallocator to
 expand the string for each new segment. When it is an initial allocator
 pOldMem is NULL.
 
 The fFree function is called to clean up an individual allocation when an error occurs.
 
 The fDesctructor function is called when QCBORDecode_Finish is called.
 
 Any memory allocated with this will be marked by setting uXXXAlloc in the
 QCBORItem structure so the caller knows they have to free it.
 
 fAllocate is only ever called to increase the single most recent
 allocation made, making implementation of a memory pool very simple.
 
 fFree is also only called on the single most recent allocation.
 */
typedef struct {
   void       *pAllocaterContext;
   UsefulBuf (*fAllocate)(void *pAllocaterContext, void *pOldMem, size_t uNewSize);
   void      (*fFree)(void *pAllocaterContext, void *pMem);
   void      (*fDestructor)(void *pAllocaterContext);
} QCBORStringAllocator;


/** See the descriptions for CBOR_SIMPLEV_FALSE, CBOR_TAG_DATE_EPOCH... for
    the meaning of the individual tags.  The values here are bit flags
    associated with each tag.  These flags are set in uTagsBits in QCBORItem */
#define QCBOR_TAGFLAG_DATE_STRING    (0x01LL << CBOR_TAG_DATE_STRING)
#define QCBOR_TAGFLAG_DATE_EPOCH     (0x01LL << CBOR_TAG_DATE_EPOCH)
#define QCBOR_TAGFLAG_POS_BIGNUM     (0x01LL << CBOR_TAG_POS_BIGNUM)
#define QCBOR_TAGFLAG_NEG_BIGNUM     (0x01LL << CBOR_TAG_NEG_BIGNUM)
#define QCBOR_TAGFLAG_FRACTION       (0x01LL << CBOR_TAG_FRACTION)
#define QCBOR_TAGFLAG_BIGFLOAT       (0x01LL << CBOR_TAG_BIGFLOAT)
#define QCBOR_TAGFLAG_ENC_AS_B64URL  (0x01LL << CBOR_TAG_ENC_AS_B64URL)
#define QCBOR_TAGFLAG_ENC_AS_B64     (0x01LL << CBOR_TAG_ENC_AS_B64)
#define QCBOR_TAGFLAG_ENC_AS_B16     (0x01LL << CBOR_TAG_ENC_AS_B16)
#define QCBOR_TAGFLAG_CBOR           (0x01LL << CBOR_TAG_CBOR)
#define QCBOR_TAGFLAG_URI            (0x01LL << CBOR_TAG_URI)
#define QCBOR_TAGFLAG_B64URL         (0x01LL << CBOR_TAG_B64URL)
#define QCBOR_TAGFLAG_B64            (0x01LL << CBOR_TAG_B64)
#define QCBOR_TAGFLAG_REGEX          (0x01LL << CBOR_TAG_REGEX)
#define QCBOR_TAGFLAG_MIME           (0x01LL << CBOR_TAG_MIME)
#define QCBOR_TAGFLAG_CBOR_MAGIC     (0x01ULL << 63)


/**
 Constant passed for paramenter nLabel to indicate that no integer
 label should be added for this item. This also means that you can
 never use INT64_MAX as an integer label.
 */
#define QCBOR_NO_INT_LABEL           INT64_MAX

/**
 QCBOREncodeContext is the data type that holds context for all the
 encoding functions. It is a little over 100 bytes so it can go on 
 the stack. The contents are opaque and the caller should not access
 any internal items.  A context may be re used serially as long as
 it is re initialized.
 */
typedef struct _QCBOREncodeContext QCBOREncodeContext;


/**
 
 Initialize the the encoder to prepare to encode some CBOR.
 
 @param[in,out]  pCtx    The encoder context to initialize.
 @param[in]      Storage The buffer into which this encoded result will be placed.
 
 Call this once at the start of an encoding of a CBOR structure. Then
 call the various QCBOREncode_AddXXX() functions to add the data
 items. Then call QCBOREncode_Finish().
 
 The maximum output buffer is UINT32_MAX (4GB). This is not a practical
 limit in any way and reduces the memory needed by the implementation.
 The error QCBOR_ERR_BUFFER_TOO_LARGE will be returned by QCBOR_Finish()
 if a larger buffer length is passed in.
  
 If this is called with pBuf as NULL and uBufLen a large value like
 UINT32_MAX, all the QCBOREncode_AddXXXX() functions and
 QCBORE_Encode_Finish() can still be called. No data will be encoded,
 but the length of what would be encoded will be calculated. The
 length of the encoded structure will be handed back in the call to
 QCBOREncode_Finish(). You can then allocate a buffer of that size
 and call all the encoding again, this time to fill in the buffer.
 
 A QCBORContext can be reused over and over as long as
 QCBOREncode_Init() is called.
 
 */

void QCBOREncode_Init(QCBOREncodeContext *pCtx, UsefulBuf Storage);

/* TODO: add documentation
 */
void QCBOREncode_AddTag(QCBOREncodeContext *pCtx,uint64_t uTag);


/**
 
 @brief  Add a 64-bit integer to the encoded output
 
 @param[in] pCtx      The encoding context to add the integer to.
 @param[in] szLabel   The string map label for this integer value.
 @param[in] nLabel    The integer map label for this integer value.
 @param[in] nNum      The integer to add.
 
 The functions and macros with a "U" add unsigned integers and those
 without add signed. The main reason to use the unsigned versions is
 when the integers are in the range of MAX_INT to MAX_UINT, values
 that can be expressed by a uint64_t, but not an int64_t.
 
 This function figures out the size and the sign and encodes in the
 correct minimal CBOR. Specifically it will select CBOR major type 0 or 1
 based on sign and will encode to 1, 2, 4 or 8 bytes depending on the
 value of the integer. Values less than 24 effectively encode to one
 byte because they are encoded in with the CBOR major type.  This is
 a neat and efficient characteristic of CBOR that can be taken
 advantage of when designing CBOR-based protocols. If integers like
 tags can be kept between -23 and 23 they will be encoded in one byte
 including the major type.
 
 If you pass a smaller int, say an int16_t or a small value, say 100,
 the encoding will still be CBOR's most compact that can represent the
 value.  For example CBOR always encodes the value 0 as one byte,
 0x00. The representation as 0x00 includes identfication of the type
 as an integer too as the major type for an integer is 0. See RFC 7049
 Appendix A for more examples of CBOR encoding. This compact encoding
 is also cannonical CBOR as per section 3.9 in RFC 7049.
 
 There are no functions to add int16_t or int32_t because they are
 not necessary because this always encodes to the smallest number
 of bytes based on the value (If this code is running on a 32-bit
 machine having way to add 32-bit integers would reduce code size some).
 
 If the encoding context is in an error state, this will do
 nothing. If this causes an error such as going off the end of the
 buffer an internal error flag will be set and the error will be
 returned when QCBOREncode_Finish() is called.
 
 */

void QCBOREncode_AddInt64_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, int64_t nNum);
void QCBOREncode_AddUInt64_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, uint64_t uNum);

#define QCBOREncode_AddUInt64(pCtx, uNum) \
      QCBOREncode_AddUInt64_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (uNum))

#define QCBOREncode_AddUInt64ToMap(pCtx, szLabel, uNum) \
      QCBOREncode_AddUInt64_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (uNum))

#define QCBOREncode_AddUInt64ToMapN(pCtx, nLabel, uNum) \
      QCBOREncode_AddUInt64_2((pCtx), NULL, (nLabel), (uNum))

#define QCBOREncode_AddInt64(pCtx, nNum) \
      QCBOREncode_AddInt64_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (nNum))

#define QCBOREncode_AddInt64ToMap(pCtx, szLabel, nNum) \
      QCBOREncode_AddInt64_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (nNum))

#define QCBOREncode_AddInt64ToMapN(pCtx, nLabel, nNum) \
      QCBOREncode_AddInt64_2((pCtx), NULL, (nLabel), (nNum))




/**
 
 @brief  Add a float or double value to the encoded output
 
 @param[in] pCtx      The encoding context to add the float to.
 @param[in] szLabel   The string map label for this integer value.
 @param[in] nLabel    The integer map label for this integer value.
 @param[in] fNum       The float to add.
 
 This works the same as QCBOREncode_AddInt64_2() except it is for floats and doubles.
 
 */
void QCBOREncode_AddFloat_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, float fNum);
void QCBOREncode_AddDouble_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, double dNum);

#define QCBOREncode_AddFloat(pCtx, fNum) \
      QCBOREncode_AddFloat_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (fNum))

#define QCBOREncode_AddFloatToMap(pCtx, szLabel, fNum) \
      QCBOREncode_AddFloat_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (fNum))

#define QCBOREncode_AddFloatToMapN(pCtx, nLabel, fNum) \
      QCBOREncode_AddFloat_2((pCtx), NULL, (nLabel), (fNum))

#define QCBOREncode_AddDouble(pCtx, dNum) \
      QCBOREncode_AddDouble_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (dNum))

#define QCBOREncode_AddDoubleToMap(pCtx, szLabel, dNum) \
      QCBOREncode_AddDouble_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (dNum))

#define QCBOREncode_AddDoubleToMapN(pCtx, nLabel, dNum) \
      QCBOREncode_AddDouble_2((pCtx), NULL, (nLabel), (dNum))

/*
 @brief  Add a half-precision floating point number to the encoded output
 
 @param[in] pCtx      The encoding context to add the float to.
 @param[in] szLabel   The string map label for this integer value.
 @param[in] nLabel    The integer map label for this integer value.
 @param[in] uTag      A CBOR type 6 tag
 @param[in] fNum      The float to add.
 
 This will truncate the precision of the single precision float to half-precision.
 Numbers whose absolute value is larger than 65504 will be encoded as infinity as this is the largest number
 half-precision can encode. Numbers whose absolute value is less than 5.96E−8 will be
 encoded as 0. Single precision floats smaller than 6.10E−5 will be converted
 half-precision subnormal numbers.
 
 Infinity and NaN are handled correctly. NaN payloads are partially carried.
 
 Half-precision floating point number take up 2 bytes, half that of single-precision.
 
 This works the same as QCBOREncode_AddInt64_2() except it is for half-precision floats.

 */

void QCBOREncode_AddFloatAsHalf_2(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, float fNum);

#define QCBOREncode_AddFloatAsHalf(pCtx, fNum) \
      QCBOREncode_AddFloatAsHalf_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (fNum))

#define QCBOREncode_AddFloatAsHalfToMap(pCtx, szLabel, fNum) \
      QCBOREncode_AddFloatAsHalf_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (fNum))

#define QCBOREncode_AddFloatAsHalfToMapN(pCtx, nLabel, fNum) \
      QCBOREncode_AddFloatAsHalf_2((pCtx), NULL, (nLabel), (fNum))


/*
 @brief  Add a dynamically sized floating point number to the encoded output
 
 @param[in] pCtx      The encoding context to add the float to.
 @param[in] szLabel   The string map label for this integer value.
 @param[in] nLabel    The integer map label for this integer value.
 @param[in] uTag      A CBOR type 6 tag
 @param[in] fNum      The float to add.
 
 This will selectively encode the single-precision floating point number as either
 single-precision or half-precision. It will always encode infinity, NaN and 0
 has half precision. If no precision will be lost in the conversion to half-precision
 then it will be performed, otherwise it will not be performed.
 
 This reduces the size of encoded messages a lot, maybe even half if most values are
 0, infinity or NaN.
 
 Half-precision floating point numbers take up 2 bytes, half that of single-precision.
 
 These will always be decoded into a float as standard C doesn't have a widely used
 standard representation for half-precision floats yet.
 
 This works the same as QCBOREncode_AddInt64_2() except it is for single and half-precision floats.
 
 */

void QCBOREncode_AddFloatAsSmallest_2(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, float fNum);

#define QCBOREncode_AddFloatAsSmallest(pCtx, fNum) \
      QCBOREncode_AddFloatAsSmallest_2((pCtx), NULL, QCBOR_NO_INT_LABEL, CBOR_TAG_NONE, (fNum))

#define QCBOREncode_AddFloatAsSmallestToMap(pCtx, szLabel, fNum) \
      QCBOREncode_AddFloatAsSmallest_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (fNum))

#define QCBOREncode_AddFloatAsSmallestToMapN(pCtx, nLabel, fNum) \
      QCBOREncode_AddFloatAsSmallest_2((pCtx), NULL, (nLabel), (fNum))


/*
 @brief  Add a dynamically sized floating point number to the encoded output
 
 @param[in] pCtx      The encoding context to add the float to.
 @param[in] szLabel   The string map label for this integer value.
 @param[in] nLabel    The integer map label for this integer value.
 @param[in] uTag      A CBOR type 6 tag
 @param[in] dNum      The float to add.
 
 This will selectively encode the double-precision floating point number as either
 double-precision, single-precision or half-precision. It will always encode infinity, NaN and 0
 has half precision. If no precision will be lost in the conversion to half-precision
 then it will be converted and encoded. If not and no precision will be lost in
 conversion to single-precision, then it will be converted and encoded. If not, then
 no conversion is performed and it sent as a double.
 
 Half-precision floating point numbers take up 2 bytes, half that of single-precision,
 one quarter of double-preceision
 
 This reduces the size of encoded messages a lot, maybe even by four if a most of values are
 0, infinity or NaN.
 
 On decode, these will always be represented has float or double. Half-precision values
 will decode as float as standard C doesn't have a widely used
 standard representation for half-precision floats yet. The designer of the protocol
 using this approach can / should assume that floats received actually have the precision
 of double. They should probably cast the float received to double.
 
 This works the same as QCBOREncode_AddInt64_2() except it is for floating point types.
 
 */

void QCBOREncode_AddDoubleAsSmallest_2(QCBOREncodeContext *me, const char *szLabel, int64_t nLabel, double dNum);

#define QCBOREncode_AddDoubleAsSmallest(pCtx, dNum) \
      QCBOREncode_AddDoubleAsSmallest_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (dNum))

#define QCBOREncode_AddDoubleAsSmallestToMap(pCtx, szLabel, dNum) \
      QCBOREncode_AddDoubleAsSmallest_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (dNum))

#define QCBOREncode_AddDoubleAsSmallestToMapN(pCtx, nLabel, dNum) \
      QCBOREncode_AddDoubleAsSmallest_2((pCtx), NULL, (nLabel), (dNum))



/**
 
 @brief  Add an epoch-based date
 
 @param[in] pCtx     The encoding context to add the simple value to.
 @param[in] szLabel  The string map label for this integer value.
 @param[in] nLabel   The integer map label for this integer value.
 @param[in] date     Number of seconds since 1970-01-01T00:00Z in UTC time.
 
 As per RFC 7049 this is similar to UNIX/Linux/POSIX dates. This is
 the most compact way to specify a date and time in CBOR. Note that this
 is always UTC and does not include the time zone.  Use
 QCBOREncode_AddDateString() if you want to include the time zone.
 
 The integer encoding rules apply here so the date will be encoded in a
 minimal number of 1, 2 4 or 8 bytes. Until about the year 2106 these
 dates should encode in 6 bytes -- one byte for the tag, one byte for the type
 and 4 bytes for the integer.
 
 If you care about leap-seconds and that level of accuracy, make sure the
 system you are running this code on does it correctly. This code just takes
 the value passed in.
 
 This implementation cannot encode fractional seconds using float or double
 even though that is allowed by CBOR, but you can encode them if you
 want to by calling QCBOREncode_AddFloat_2() or QCBOREncode_AddDouble_2()
 with the right parameters.
 
 Error handling is the same as QCBOREncode_AddInt64_2().
 */

static inline void QCBOREncode_AddDateEpoch_2(QCBOREncodeContext *pCtx, const char *szLabel, uint64_t nLabel, int64_t date)
{
   QCBOREncode_AddTag(pCtx, CBOR_TAG_DATE_EPOCH);
   QCBOREncode_AddInt64_2(pCtx, szLabel, nLabel, date);
}

#define QCBOREncode_AddDateEpoch(pCtx, date) \
      QCBOREncode_AddDateEpoch_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (date))

#define QCBOREncode_AddDateEpochToMap(pCtx, szLabel, date) \
      QCBOREncode_AddDateEpoch_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (date))

#define QCBOREncode_AddDateEpochToMapN(pCtx, nLabel, date) \
      QCBOREncode_AddDateEpoch_2((pCtx), NULL, (nLabel), (date))


// TODO: document this
void QCBOREncode_AddBytes_2(QCBOREncodeContext *me, uint8_t uMajorType, const char *szLabel, int64_t nLabel, UsefulBufC Bytes);


/**
 
 @brief Add a byte string to the encoded output.
 
 @param[in] pCtx      The context to initialize.
 @param[in] szLabel   The string map label for this integer value.
 @param[in] nLabel    The integer map label for this integer value.
 @param[in] uTag      Optional CBOR data tag or CBOR_TAG_NONE.
 @param[in] Bytes     Pointer and length of the input data.
 
 Simply adds the bytes to the encoded output and CBOR major type 2.
 
 If called with Bytes.len equal to 0, an empty string will be
 added. When Bytes.len is 0, Bytes.ptr may be NULL.
 
 */

#define QCBOREncode_AddBytes(pCtx, Bytes) \
      QCBOREncode_AddBytes_2((pCtx), CBOR_MAJOR_TYPE_BYTE_STRING, NULL, QCBOR_NO_INT_LABEL, Bytes)

#define QCBOREncode_AddBytesToMap(pCtx, szLabel, Bytes) \
      QCBOREncode_AddBytes_2((pCtx), CBOR_MAJOR_TYPE_BYTE_STRING, (szLabel), QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddBytesToMapN(pCtx, nLabel, Bytes) \
      QCBOREncode_AddBytes_2((pCtx), CBOR_MAJOR_TYPE_BYTE_STRING, NULL, (nLabel), (Bytes))



static inline void QCBOREncode_AddBinaryUUID_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, UsefulBufC Bytes)
{
   QCBOREncode_AddTag(pCtx, CBOR_TAG_BIN_UUID);
   QCBOREncode_AddBytes_2(pCtx, CBOR_MAJOR_TYPE_BYTE_STRING, szLabel, nLabel, Bytes);
}


#define QCBOREncode_AddBinaryUUID(pCtx, Bytes) \
      QCBOREncode_AddBinaryUUID_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddBinaryUUIDToMap(pCtx, szLabel, Bytes) \
      QCBOREncode_AddBinaryUUID_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddBinaryUUIDToMapN(pCtx, nLabel, Bytes) \
      QCBOREncode_AddBinaryUUID_2((pCtx), NULL, (nLabel), (Bytes))


static inline void QCBOREncode_AddPositiveBignum_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, UsefulBufC Bytes)
{
   QCBOREncode_AddTag(pCtx, CBOR_TAG_POS_BIGNUM);
   QCBOREncode_AddBytes_2(pCtx, CBOR_MAJOR_TYPE_BYTE_STRING, szLabel, nLabel, Bytes);
}

#define QCBOREncode_AddPositiveBignum(pCtx, Bytes) \
      QCBOREncode_AddPositiveBignum_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddPositiveBignumToMap(pCtx, szLabel, Bytes) \
      QCBOREncode_AddPositiveBignum_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddPositiveBignumToMapN(pCtx, nLabel, Bytes) \
      QCBOREncode_AddPositiveBignum_2((pCtx), NULL, (nLabel), (Bytes))


static inline void QCBOREncode_AddNegativeBignum_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, UsefulBufC Bytes)
{
   QCBOREncode_AddTag(pCtx, CBOR_TAG_NEG_BIGNUM);
   QCBOREncode_AddBytes_2(pCtx, CBOR_MAJOR_TYPE_BYTE_STRING, szLabel, nLabel, Bytes);
}

#define QCBOREncode_AddNegativeBignum(pCtx, Bytes) \
      QCBOREncode_AddNegativeBignum_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddNegativeBignumToMap(pCtx, szLabel, Bytes) \
      QCBOREncode_AddNegativeBignum_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddNegativeBignumToMapN(pCtx, nLabel, Bytes) \
      QCBOREncode_AddNegativeBignum_2((pCtx), NULL, (nLabel), (Bytes))



/**
 
 @brief  Add a UTF-8 text string to the encoded output
 
 @param[in] pCtx     The context to initialize.
 @param[in] szLabel  The string map label for this integer value.
 @param[in] nLabel   The integer map label for this integer value.
 @param[in] uTag     Optional CBOR data tag or CBOR_TAG_NONE.
 @param[in] Bytes    Pointer and length of text to add.
 
 The text passed in must be unencoded UTF-8 according to RFC
 3629. There is no NULL termination.
 
 If called with nBytesLen equal to 0, an empty string will be
 added. When nBytesLen is 0, pBytes may be NULL.
 
 
 Note that the restriction of the buffer length to an uint32_t is
 entirely intentional as this encoder is not capable of encoding
 lengths greater. This limit to 4GB for a text string should not be a
 problem.
 
 Error handling is the same as QCBOREncode_AddInt64_2().
 
 */

// TODO: AddText_2? 
#define QCBOREncode_AddText(pCtx, Bytes) \
      QCBOREncode_AddBytes_2((pCtx), CBOR_MAJOR_TYPE_TEXT_STRING, NULL, QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddTextToMap(pCtx, szLabel, Bytes) \
      QCBOREncode_AddBytes_2((pCtx), CBOR_MAJOR_TYPE_TEXT_STRING, (szLabel), QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddTextToMapN(pCtx, nLabel, Bytes) \
      QCBOREncode_AddBytes_2((pCtx), CBOR_MAJOR_TYPE_TEXT_STRING, NULL, (nLabel),  (Bytes))


inline static void QCBOREncode_AddSZString_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, const char *szString)
{
   QCBOREncode_AddBytes_2(pCtx, CBOR_MAJOR_TYPE_TEXT_STRING, szLabel, nLabel,UsefulBuf_FromSZ(szString));
}

#define QCBOREncode_AddSZString(pCtx, szString) \
      QCBOREncode_AddSZString_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (szString))

#define QCBOREncode_AddSZStringToMap(pCtx, szLabel, szString) \
      QCBOREncode_AddSZString_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (szString))

#define QCBOREncode_AddSZStringToMapN(pCtx, nLabel, szString) \
      QCBOREncode_AddSZString_2((pCtx), NULL, (nLabel), (szString))




static inline void QCBOREncode_AddURI_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, UsefulBufC Bytes)
{
   QCBOREncode_AddTag(pCtx, CBOR_TAG_URI);
   QCBOREncode_AddBytes_2(pCtx, CBOR_MAJOR_TYPE_TEXT_STRING, szLabel, nLabel, Bytes);
}

#define QCBOREncode_AddURI(pCtx, Bytes) \
      QCBOREncode_AddURI_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddURIToMap(pCtx, szLabel, Bytes) \
      QCBOREncode_AddURI_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddURIToMapN(pCtx, nLabel, Bytes) \
      QCBOREncode_AddURI_2((pCtx), NULL, (nLabel), (Bytes))


static inline void QCBOREncode_AddB64Text_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, UsefulBufC Bytes)
{
   QCBOREncode_AddTag(pCtx, CBOR_TAG_B64);
   QCBOREncode_AddBytes_2(pCtx, CBOR_MAJOR_TYPE_TEXT_STRING, szLabel, nLabel, Bytes);
}

#define QCBOREncode_AddB64Text(pCtx, Bytes) \
      QCBOREncode_AddB64Text_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddB64TextToMap(pCtx, szLabel, Bytes) \
      QCBOREncode_AddB64Text_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddB64TextToMapN(pCtx, nLabel, Bytes) \
      QCBOREncode_AddB64Text_2((pCtx), NULL, (nLabel), (Bytes))



static inline void QCBOREncode_AddB64URLText_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, UsefulBufC Bytes)
{
   QCBOREncode_AddTag(pCtx, CBOR_TAG_B64URL);
   QCBOREncode_AddBytes_2(pCtx, CBOR_MAJOR_TYPE_TEXT_STRING, szLabel, nLabel, Bytes);
}

#define QCBOREncode_AddB64URLText(pCtx, Bytes) \
      QCBOREncode_AddB64URLText_2((pCtx), NULL, QCBOR_NO_INT_LABEL, CBOR_TAG_B64URL, (Bytes))

#define QCBOREncode_AddB64URLTextToMap(pCtx, szLabel, Bytes) \
      QCBOREncode_AddB64URLText_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, CBOR_TAG_B64URL, (Bytes))

#define QCBOREncode_AddB64URLTextToMapN(pCtx, nLabel, Bytes) \
      QCBOREncode_AddB64URLText_2((pCtx), NULL, (nLabel), CBOR_TAG_B64URL, (Bytes))



static inline void QCBOREncode_AddRegex_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, UsefulBufC Bytes)
{
   QCBOREncode_AddTag(pCtx, CBOR_TAG_REGEX);
   QCBOREncode_AddBytes_2(pCtx, CBOR_MAJOR_TYPE_TEXT_STRING, szLabel, nLabel, Bytes);
}

#define QCBOREncode_AddRegex(pCtx, Bytes) \
      QCBOREncode_AddRegex_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddRegexToMap(pCtx, szLabel, Bytes) \
      QCBOREncode_AddRegex_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddRegexToMapN(pCtx, nLabel, Bytes) \
      QCBOREncode_AddRegex_2((pCtx), NULL, (nLabel), (Bytes))



static inline void QCBOREncode_AddMIMEData_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, UsefulBufC Bytes)
{
   QCBOREncode_AddTag(pCtx, CBOR_TAG_MIME);
   QCBOREncode_AddBytes_2(pCtx, CBOR_MAJOR_TYPE_TEXT_STRING, szLabel, nLabel, Bytes);
}

#define QCBOREncode_AddMIMEData(pCtx, Bytes) \
      QCBOREncode_AddMIMEData_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddMIMEDataToMap(pCtx, szLabel, Bytes) \
      QCBOREncode_AddMIMEData_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (Bytes))

#define QCBOREncode_AddMIMEDataToMapN(pCtx, nLabel, Bytes) \
      QCBOREncode_AddMIMEData_2((pCtx), NULL, (nLabel), (Bytes))



/**
 
 @brief  Add an RFC 3339 date string
 
 @param[in] pCtx      The encoding context to add the simple value to.
 @param[in] szDate    Null-terminated string with date to add
 @param[in] szLabel   A string label for the bytes to add. NULL if no label.
 @param[in] nLabel    The integer map label for this integer value.
 
 None.
 
 The string szDate should be in the form of RFC 3339 as refined by section
 3.3 in RFC 4287. This is as described in section 2.4.1 in RFC 7049.
 
 Note that this function doesn't validate the format of the date string
 at all. If you add an incorrect format date string, the generated
 CBOR will be incorrect and the receiver may not be able to handle it.
 
 Error handling is the same as QCBOREncode_AddInt64_2().
 
 */
static inline void QCBOREncode_AddDateString_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, const char *szDate)
{
   QCBOREncode_AddTag(pCtx, CBOR_TAG_DATE_STRING);
   QCBOREncode_AddSZString_2(pCtx, szLabel, nLabel, szDate);
}

#define QCBOREncode_AddDateString(pCtx, szDate) \
      QCBOREncode_AddDateString_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (szDate))

#define QCBOREncode_AddDateStringToMap(pCtx, szLabel, szDate)  \
      QCBOREncode_AddDateString_2(pCtx, szLabel, QCBOR_NO_INT_LABEL, (szDate))

#define QCBOREncode_AddDateStringToMapN(pCtx, nLabel, szDate)  \
      QCBOREncode_AddDateString_2(pCtx, NULL, (nLabel), (szDate))




/**
 
 @brief  Add true, false, null and undef
 
 @param[in] pCtx      The encoding context to add the simple value to.
 @param[in] szLabel   A string label for the bytes to add. NULL if no label.
 @param[in] nLabel    The integer map label for this integer value.
 @param[in] uSimple   One of CBOR_SIMPLEV_FALSE through _UNDEF

 CBOR defines encoding for special values "true", "false", "null" and "undef". This
 function can add these values.
 
 Error handling is the same as QCBOREncode_AddInt64_2().
 */
void QCBOREncode_AddSimple_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, uint8_t uSimple);


#define QCBOREncode_AddSimple(pCtx, uSimple) \
      QCBOREncode_AddSimple_2((pCtx), NULL,  QCBOR_NO_INT_LABEL, (uSimple))

#define QCBOREncode_AddSimpleToMap(pCtx, szLabel, uSimple) \
      QCBOREncode_AddSimple_2((pCtx), (szLabel),  QCBOR_NO_INT_LABEL, (uSimple))

#define QCBOREncode_AddSimpleToMapN(pCtx, nLabel, uSimple) \
      QCBOREncode_AddSimple_2((pCtx), NULL, (nLabel), (uSimple))




/**
 
 @brief  Add a standard boolean
 
 @param[in] pCtx      The encoding context to add the simple value to.
 @param[in] szLabel   A string label for the bytes to add. NULL if no label.
 @param[in] nLabel    The integer map label for this integer value.
 @param[in] b      true or false from stdbool. Anything will result in an error.
 
 Error handling is the same as QCBOREncode_AddInt64_2().
 */


inline static void QCBOREncode_AddBool_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, bool b)
{
   uint8_t uSimple = CBOR_SIMPLE_BREAK; // CBOR_SIMPLE_BREAK is invalid here. The point is to cause an error later
   if(b == true || b == false)
      uSimple = CBOR_SIMPLEV_FALSE + b;;
   QCBOREncode_AddSimple_2(pCtx, szLabel, nLabel, uSimple);
}

#define QCBOREncode_AddBool(pCtx, bool) \
   QCBOREncode_AddBool_2((pCtx), NULL,  QCBOR_NO_INT_LABEL, (bool))

#define QCBOREncode_AddBoolToMap(pCtx, szLabel, bool) \
   QCBOREncode_AddBool_2((pCtx), (szLabel),  QCBOR_NO_INT_LABEL, (bool))

#define QCBOREncode_AddBoolToMapN(pCtx, nLabel, bool) \
   QCBOREncode_AddBool_2((pCtx), NULL, (nLabel), (bool))



// TODO: document this
void OpenMapOrArray_2(QCBOREncodeContext *me, uint8_t uMajorType, const char *szLabel, uint64_t nLabel);

/**
 
 @brief  Indicates that the next items added are in an array.
 
 @param[in] pCtx The encoding context to open the array in.
 @param[in] szLabel A NULL-terminated string label for the map. May be a NULL pointer.
 @param[in] nLabel An integer label for the whole map. QCBOR_NO_INT_LABEL for no integer label.
 
 Arrays are the basic CBOR aggregate or structure type. Call this
 function to start or open an array. The call the various AddXXX
 functions to add the items that go into the array. Then call
 QCBOREncode_CloseArray() when all items have been added.
 
 Nesting of arrays and maps is allowed and supported just by calling
 OpenArray again before calling CloseArray.  While CBOR has no limit
 on nesting, this implementation does in order to keep it smaller and
 simpler.  The limit is QCBOR_MAX_ARRAY_NESTING. This is the max
 number of times this can be called without calling
 QCBOREncode_CloseArray(). QCBOREncode_Finish() will return
 QCBOR_ERR_ARRAY_TOO_LONG when it is called as this function just sets
 an error state and returns no value when this occurs.
 
 If you try to add more than 32,767 items to an array or map, incorrect CBOR will
 be produced by this encoder.
 
 An array itself may have a label if it is being added to a map. Either the
 string array or integer label should be filled in, but not both. Note that
 array elements do not have labels (but map elements do).
 
 An array itself may be tagged.
 
 When constructing signed CBOR objects, maps or arrays, they are encoded
 normally and then wrapped as a byte string. The COSE standard for example
 does this. The wrapping is simply treating the encoded CBOR map
 as a byte string.
 
 The stated purpose of this wrapping is to prevent code relaying the signed data
 but not verifying it from tampering with the signed data thus making
 the signature unverifiable. It is also quite beneficial for the
 signature verification code. Standard CBOR parsers usually do not give
 access to partially parsed CBOR as would be need to check the signature
 of some CBOR. With this wrapping, standard CBOR parsers can be used
 to get to all the data needed for a signature verification.
 */

static inline void QCBOREncode_OpenArray_2(QCBOREncodeContext *pCtx, const char *szLabel, uint64_t nLabel)
{
   OpenMapOrArray_2(pCtx, CBOR_MAJOR_TYPE_ARRAY, szLabel, nLabel);
}

#define QCBOREncode_OpenArray(pCtx) \
      QCBOREncode_OpenArray_2((pCtx), NULL, QCBOR_NO_INT_LABEL)

#define QCBOREncode_OpenArrayInMap(pCtx, szLabel) \
      QCBOREncode_OpenArray_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL)

#define QCBOREncode_OpenArrayInMapN(pCtx, nLabel) \
      QCBOREncode_OpenArray_2((pCtx), NULL, (nLabel))


/**
 
 @brief  Indicates that the next items added are in a map.
 
 @param[in] pCtx The context to add to.
 @param[in] szLabel A NULL-terminated string label for the map. May be a NULL pointer.
 @param[in] nLabel An integer label for the whole map. QCBOR_NO_INT_LABEL for no integer label.
 
 See QCBOREncode_OpenArray() for more information.
 
 When adding items to maps, they must be added in pairs, the label and
 the value. This can be done making two calls to QCBOREncode_AddXXX
 one for the map label and one for the value.
 
 It can also be accomplished by calling one of the add functions that
 takes an additional NULL-terminated text string parameter that is the
 label.  This is useful for encoding CBOR you which to translate easily
 to JSON.
 
 Note that labels do not have to be strings. They can be integers or
 other. Small integers < 24 are a good choice for map labels when the
 size of the encoded data should be as small and simple as possible.

 See the RFC7049 for a lot more information on creating maps.
 
 */

static inline void QCBOREncode_OpenMap_2(QCBOREncodeContext *pCtx, const char *szLabel,  uint64_t nLabel)
{
   OpenMapOrArray_2(pCtx, CBOR_MAJOR_TYPE_MAP, szLabel, nLabel);
}


#define QCBOREncode_OpenMap(pCtx) \
      QCBOREncode_OpenMap_2((pCtx), NULL, QCBOR_NO_INT_LABEL)

#define QCBOREncode_OpenMapInMap(pCtx, szLabel) \
      QCBOREncode_OpenMap_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL)

#define QCBOREncode_OpenMapInMapN(pCtx, nLabel) \
      QCBOREncode_OpenMap_2((pCtx), NULL, (nLabel))


/**
 
 @brief Closes array, map or bstr wrapping
 
 @param[in] pCtx The context to add to.
 @param[in] uMajorType The major CBOR type to close
 @param[out] pWrappedCBOR UsefulBufC containing wrapped bytes
 
 This reduces the nesting level by one. Usually one of the macros
 below is called rather than calling this directly.
 
 If more Close's have been called than Open's the error state is
 entered, no value is returned and the error can be discovered when
 QCBOREncode_Finish() is called. The error will be
 QCBOR_ERR_TOO_MANY_CLOSES.
 
 If uMajorType doesn't match the type of what is open then
 QCBOR_ERR_CLOSE_MISMATCH will be returned when QCBOREncode_Finish()
 is called.
 
 A pointer and length of the enclosed encoded CBOR is returned in
 *pWrappedCBOR if it is not NULL. The main purpose of this is so this
 data can be hashed (e.g., with SHA-256) as part of a COSE (RFC 8152)
 implementation. **WARNING**, this pointer and length should be used
 right away before any other calls to QCBOREncode_xxxx() as they will
 move data around and the pointer and length will no longer be to the
 correct encoded CBOR.
 
 */
void QCBOREncode_Close(QCBOREncodeContext *pCtx, uint8_t uMajorType, UsefulBufC *pWrappedCBOR);

#define QCBOREncode_CloseBstrWrap(pCtx, pWrappedCBOR) \
    QCBOREncode_Close(pCtx, CBOR_MAJOR_TYPE_BYTE_STRING, pWrappedCBOR)

#define QCBOREncode_CloseArray(pCtx) \
    QCBOREncode_Close(pCtx, CBOR_MAJOR_TYPE_ARRAY, NULL)

#define QCBOREncode_CloseMap(pCtx) \
    QCBOREncode_Close(pCtx, CBOR_MAJOR_TYPE_MAP, NULL)


/**
 @brief Indicate start of encoded CBOR to be wrapped in a bstr
 
 @param[in] pCtx The context to add to.
 @param[in] szLabel A NULL-terminated string label for the map. May be a NULL pointer.
 @param[in] nLabel An integer label for the whole map. QCBOR_NO_INT_LABEL for no integer label.

 All added encoded items between this call and a call to
 QCBOREncode_CloseBstrWrap() will be wrapped in a bstr. They will
 appear in the final output as a byte string.  That byte string will
 contain encoded CBOR.
 
 The typical use case is for encoded CBOR that is to be
 cryptographically hashed, as part of a COSE (RFC 8152)
 implementation. This avoids having to encode the items first in one
 buffer (e.g., the COSE payload) and then add that buffer as a bstr to
 another encoding (e.g. the COSE to-be-signed bytes, the
 Sig_structure) potentially saving a lot of memory.

 */
static inline void QCBOREncode_OpenBstrWrap_2(QCBOREncodeContext *pCtx, const char *szLabel, uint64_t nLabel)
{
   OpenMapOrArray_2(pCtx, CBOR_MAJOR_TYPE_BYTE_STRING, szLabel, nLabel);
}

#define QCBOREncode_BstrWrap(pCtx) \
      QCBOREncode_OpenBstrWrap_2((pCtx), NULL, QCBOR_NO_INT_LABEL)

#define QCBOREncode_BstrWrapInMap(pCtx, szLabel) \
      QCBOREncode_OpenBstrWrap_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL)

#define QCBOREncode_BstrWrapMapN(pCtx, nLabel) \
      QCBOREncode_OpenBstrWrap_2((pCtx), NULL, (nLabel))



/**
 Add some already-encoded CBOR bytes
 
 @param[in] pCtx The context to add to.
 @param[in] szLabel A NULL-terminated string label for the map. May be a NULL pointer.
 @param[in] nLabel An integer label for the whole map. QCBOR_NO_INT_LABEL for no integer label.
 @param[in] Encoded The already-encoded CBOR to add to the context.
 
 The encoded CBOR being added must be fully conforming CBOR. It must
 be complete with no arrays or maps that are incomplete. While this
 encoder doesn't every produce indefinite lengths, it is OK for the
 raw CBOR added here to have indefinite lengths.
 
 The raw CBOR added here is not checked in anyway. If it is not
 conforming or has open arrays or such, the final encoded CBOR
 will probably be wrong or not what was intended.
 
 If the encoded CBOR being added here contains multiple items, they
 must be enclosed in a map or array. At the top level the raw
 CBOR must have a single item. 
 
 */

static inline void QCBOREncode_AddEncodedToMap_2(QCBOREncodeContext *pCtx, const char *szLabel, uint64_t nLabel, UsefulBufC Encoded)
{
   QCBOREncode_AddBytes_2(pCtx, CBOR_MAJOR_NONE_TYPE_RAW, szLabel, nLabel, Encoded);
}

#define QCBOREncode_AddEncodedToMapN(pCtx, nLabel, Encoded) \
      QCBOREncode_AddEncodedToMap_2((pCtx), NULL, (nLabel), Encoded)

#define QCBOREncode_AddEncoded(pCtx, Encoded) \
      QCBOREncode_AddEncodedToMap_2((pCtx), NULL, QCBOR_NO_INT_LABEL, (Encoded))

#define QCBOREncode_AddEncodedToMap(pCtx, szLabel, Encoded) \
      QCBOREncode_AddEncodedToMap_2((pCtx), (szLabel), QCBOR_NO_INT_LABEL, (Encoded))


/**
 
 @brief  Add a simple value
 
 @param[in] pCtx      The encoding context to add the simple value to.
 @param[in] szLabel   A string label for the bytes to add. NULL if no label.
 @param[in] nLabel    The integer map tag / label for this integer value.
 @param[in] uSimple   One of CBOR_SIMPLEV_xxx.
 
 There should be no need to use this function directly unless some
 extensions to the CBOR standard are created and put to use.  All the defined
 simple types are available via the macros for false...null
 below. Float and double are also simple types and have functions to
 add them above.
 
 Error handling is the same as QCBOREncode_AddInt64_2().
 */
void QCBOREncode_AddRawSimple_2(QCBOREncodeContext *pCtx, const char *szLabel, int64_t nLabel, uint8_t uSimple);



/**
 Get the encoded CBOR and error status.
 
 @param[in] pCtx  The context to finish encoding with.
 @param[out] uEncodedLen The length of the encoded or potentially encoded CBOR in bytes.
 
 @return
 One of the CBOR error codes.
 
 If this returns success QCBOR_SUCCESS the encoding was a success and
 the return length is correct and complete.
 
 If no buffer was passed to QCBOR_Init(), then only the length was
 computed. If a buffer was passed, then the encoded CBOR is in the
 buffer.
 
 If an error is returned, the buffer may have partially encoded
 incorrect CBOR in it and it should not be used. Likewise the length
 may be incorrect and should not be used.
 
 Note that the error could have occurred in one of the many
 QCBOR_AddXXX calls long before QCBOREncode_Finish() was called. This
 error handling reduces the CBOR implementation size, but makes
 debugging harder.
 
 */

int QCBOREncode_Finish(QCBOREncodeContext *pCtx, size_t *uEncodedLen);



/**
 Get the encoded result.
 
 @param[in] pCtx  The context to finish encoding with.
 @param[out] pEncodedCBOR  Pointer and length of encoded CBOR.
 
 @return
 One of the CBOR error codes.
 
 If this returns success QCBOR_SUCCESS the encoding was a success and
 the return length is correct and complete.
 
 If no buffer was passed to QCBOR_Init(), then only the length and
 number of items was computed. The length is in
 pEncodedCBOR->Bytes.len. The number of items is in
 pEncodedCBOR->nItems. pEncodedCBOR->Bytes.ptr is NULL. TODO: fix documentation
 
 If a buffer was passed, then pEncodedCBOR->Bytes.ptr is the same as
 the buffer passed to QCBOR_Init() and contains the encoded CBOR.
 
 If an error is returned, the buffer may have partially encoded
 incorrect CBOR in it and it should not be used. Likewise the length
 may be incorrect and should not be used.
 
 Note that the error could have occurred in one of the many
 QCBOR_AddXXX calls long before QCBOREncode_Finish() was called. This
 error handling reduces the CBOR implementation size, but makes
 debugging harder.
 
 */

int QCBOREncode_Finish2(QCBOREncodeContext *pCtx, UsefulBufC *pEncodedCBOR);






/**
 QCBORDecodeContext is the data type that holds context decoding the
 data items for some received CBOR.  It is about 50 bytes so it can go
 on the stack.  The contents are opaque and the caller should not
 access any internal items.  A context may be re used serially as long
 as it is re initialized.
 */

typedef struct _QCBORDecodeContext QCBORDecodeContext;


/**
 Initialize the CBOR decoder context.
 
 @param[in] pCtx The context to initialize.
 @param[in] EncodedCBOR The buffer with CBOR encoded bytes to be decoded.
 @param[in] nMode One of QCBOR_DECODE_MODE_xxx
 
 Initialize context for a pre-order traveral of the encoded CBOR tree.
 
 Three decoding modes are supported.  In normal mode, maps are decoded
 and strings and ints are accepted as map labels. If a label is other
 than these, the error QCBOR_ERR_MAP_LABEL_TYPE is returned by
 QCBORDecode_GetNext(). In strings-only mode, only text strings are
 accepted for map labels.  This lines up with CBOR that converts to
 JSON. The error QCBOR_ERR_MAP_LABEL_TYPE is returned by
 QCBORDecode_GetNext() if anything but a text string label is
 encountered. In array mode, the maps are treated as arrays. This will
 decode any type of label, but the caller must figure out all the map
 decoding.
 
 */

void QCBORDecode_Init(QCBORDecodeContext *pCtx, UsefulBufC EncodedCBOR, int8_t nMode);


/**
 Set up the MemPool string allocator for indefinite length strings.
 
 @param[in] pCtx The decode context to initialize.
 @param[in] MemPool The pointer and length of the memory pool.
 @param[in] bAllStrings true means to put even definite length strings in the pool.
 
 @return 0 if the MemPool was at least minimum size, 1 if too small.
 
 Indefinite length strings (text and byte) cannot be decoded unless there is
 a string allocator configured. MemPool is a simple built-in string allocator
 that allocates bytes from a block of memory handed to it by calling
 this function.
 
 The buffer must be large enough to hold some fixed overhead plus the
 space for all the strings allocated. The fixed overhead does vary
 per implementation, but can roughly be computed as the space for
 nine pointers, 72 bytes of a 64-bit CPU.  There is no overhead
 per string allocated
 
 This memory pool is used for all indefinite length strings that are text
 strings or byte strings, including strings used as labels.
 
 The pointers to strings in QCBORItem will point into the buffer passed set
 here. They do not need to be individually freed. Just discard the buffer
 when they are no longer needed.
 
 If bAllStrings is set then the size will be the overhead plus the space to
 hold **all** strings, definite and indefinite length, value or label. The
 advantage of this is that after the decode is complete, the original memory
 holding the encoded CBOR does not need to remain valid.
 
 */
int QCBORDecode_SetMemPool(QCBORDecodeContext *pCtx, UsefulBuf MemPool, bool bAllStrings);


/**
 @brief Sets up a custom string allocator for indefinite length strings
 
 @param[in] pCtx The decoder context to set up an allocator for
 @param[in] pAllocator The string allocator "object"
 
 See QCBORStringAllocator for the requirements of the string allocator.
 
 Typically this is used if the simple MemPool allocator isn't desired.
 
 A malloc based string allocator can be obtained by calling
 QCBORDecode_MakeMallocStringAllocator(). Pass its result to
 this function.
 */

void QCBORDecode_SetUpAllocator(QCBORDecodeContext *pCtx, const QCBORStringAllocator *pAllocator, bool bAllStrings);


/**
 @brief This returns a string allocator that uses malloc
 
 @return pointer to string allocator or NULL
 
 Call this to get the string allocator and then configure it into
 the decoder by calling QCBORDecode_SetUpAllocator().  If you
 don't call this, there will be no dependency on malloc
 in QCBOR. Some deployments of QCBOR might even exclude
 the implementation of this function if they don't have
 malloc() at all.
 
 If you do set up this malloc-based string allocator, then
 every string marked as allocated in a QCBORItem must
 freed.
 */

QCBORStringAllocator *QCBORDecode_MakeMallocStringAllocator(void);


/**
 Gets the next item (integer, byte string, array...) in pre order traversal of CBOR tree
 
 @param[in]  pCtx          The decoder context.
 @param[out] pDecodedItem  Holds the CBOR item just decoded.
 
 @return
 0 or error.
 
 pDecodedItem is filled in with the value parsed. Generally, the
 folloinwg data is returned in the structure.
 
 - The data type in uDataType which indicates which member of the val
   union the data is in. This decoder figure out the type based on the
   CBOR major type, the CBOR "additionalInfo", the CBOR optional tags
   and the value of the integer.
 
 - The value of the item, which might be an integer, a pointer and a
   length, the count of items in an array, a floating point number or
   other.
 
 - The nesting level for maps and arrays.
 
 - The label for an item in a map, which may be a text or byte string or an integer.
 
 - The CBOR optional tag or tags.
 
 See documentation on in the data type QCBORItem for all the details
 on what is returned.
 
 This function also handles arrays and maps. When first encountered a
 QCBORItem will be returned with major type CBOR_MAJOR_TYPE_ARRAY or
 CBOR_MAJOR_TYPE_ARRAY_MAP. QCBORItem.nCount will indicate the number
 if Items in the array or map.  Typically an implementation will call
 QCBORDecode_GetNext() in a for loop to fetch them all.
 
 Optional tags are integer tags that are prepended to the actual data
 item. That tell more about the data. For example it can indicate data
 is a date or a big number or a URL.
 
 Note that when traversing maps, the count is the number of pairs of
 items, so the for loop would decrement once for every two calls to
 QCBORDecode_GetNext().
 
 Nesting level 0 is the outside top-most nesting level. For example in
 a CBOR structure with two items, an integer and a byte string only,
 both would be at nesting level 0.  A CBOR structure with an array
 open, an integer and a byte string, would have the integer and byte
 string as nesting level 1.
 
 Here is an example of how the nesting level is reported with no arrays
 or maps at all
 
 @verbatim
 CBOR Structure           Nesting Level
 Integer                    0
 Byte String                0
 @endverbatim
 
 Here is an example of how the nesting level is reported with an a simple
 array and some top-level items.
 
 @verbatim
 Integer                    0
 Array (with 2 items)       0
 Byte String                1
 Byte string                1
 Integer                    0
 @endverbatim
 
 
 Here's a more complex example
 @verbatim
 
 Map with 2 items           0
 Text string                1
 Array with 3 integers      1
 integer                    2
 integer                    2
 integer                    2
 text string                1
 byte string                1
 @endverbatim
 
 In QCBORItem, uNextNestLevel is the nesting level for the next call
 to QCBORDecode_GetNext(). It indicates if any maps or arrays were closed
 out during the processing of the just-fecthed QCBORItem. This processing
 includes a look-ahead for any breaks that close out indefinite length
 arrays or maps. This value is needed to be able to understand the
 hierarchical structure. If uNextNestLevel is not equal to uNestLevel
 the end of the current map or array has been encountered. This
 works the same for both definite and indefinite length arrays.
 
 */

int QCBORDecode_GetNext(QCBORDecodeContext *pCtx, QCBORItem *pDecodedItem);


/**
 Check whether all the bytes have been decoded
 
 @param[in]  pCtx          The context to check
 
 @return QCBOR_ERR_EXTRA_BYTES or QCBOR_SUCCESS
 
 This tells you if all the bytes give to QCBORDecode_Init() have
 been consumed or not. In most cases all bytes should be consumed
 in a correct parse. 
 
 It is OK to call this multiple times during decoding and to call
 QCBORDecode_GetNext() after calling this. This only
 performs a check. It does not change the state of the decoder.
 */

int QCBORDecode_Finish(QCBORDecodeContext *pCtx);




/**
  Convert int64_t to smaller int's safely
 
 @param [in]  src    An int64_t
 @param [out] dest   A smaller sized int to convert to
  
 @return 0 on success -1 if not
 
 When decoding an integer the CBOR decoder will return the value as an
 int64_t unless the integer is in the range of INT64_MAX and
 UINT64_MAX. That is, unless the value is so large that it can only be
 represented as a uint64_t, it will be an int64_t.
 
 CBOR itself doesn't size the individual integers it carries at
 all. The only limits it puts on the major integer types is that they
 are 8 bytes or less in length. Then encoders like this one use the
 smallest number of 1, 2, 4 or 8 bytes to represent the integer based
 on its value. There is thus no notion that one data item in CBOR is
 an 1 byte integer and another is a 4 byte integer.
 
 The interface to this CBOR encoder only uses 64-bit integers. Some
 CBOR protocols or implementations of CBOR protocols may not want to
 work with something smaller than a 64-bit integer.  Perhaps an array
 of 1000 integers needs to be sent and none has a value larger than
 50,000 and are represented as uint16_t.
 
 The sending / encoding side is easy. Integers are temporarily widened
 to 64-bits as a parameter passing through QCBOREncode_AddInt64() and
 encoded in the smallest way possible for their value, possibly in
 less than an uint16_t.
 
 On the decoding side the integers will be returned at int64_t even if
 they are small and were represented by only 1 or 2 bytes in the
 encoded CBOR. The functions here will convert integers to a small
 representation with an overflow check.
 
 (The decoder could have support 8 different integer types and
 represented the integer with the smallest type automatically, but
 this would have made the decoder more complex and code calling the
 decoder more complex in most use cases.  In most use cases on 64-bit
 machines it is no burden to carry around even small integers as
 64-bit values)
 
 */

static inline int QCBOR_Int64ToInt32(int64_t src, int32_t *dest)
{
   if(src > INT32_MAX || src < INT32_MIN) {
      return -1;
   } else {
      *dest = (int32_t) src;
   }
   return 0;
}

static inline int QCBOR_Int64ToInt16(int64_t src, int16_t *dest)
{
   if(src > INT16_MAX || src < INT16_MIN) {
      return -1;
   } else {
      *dest = (int16_t) src;
   }
   return 0;
}

static inline int QCBOR_Int64ToInt8(int64_t src, int8_t *dest)
{
   if(src > INT8_MAX || src < INT8_MIN) {
      return -1;
   } else {
      *dest = (int8_t) src;
   }
   return 0;
}

static inline int QCBOR_Int64ToUInt32(int64_t src, uint32_t *dest)
{
   if(src > UINT32_MAX || src < 0) {
      return -1;
   } else {
      *dest = (uint32_t) src;
   }
   return 0;
}

static inline int QCBOR_Int64UToInt16(int64_t src, uint16_t *dest)
{
   if(src > UINT16_MAX || src < 0) {
      return -1;
   } else {
      *dest = (uint16_t) src;
   }
   return 0;
}

static inline int QCBOR_Int64ToUInt8(int64_t src, uint8_t *dest)
{
   if(src > UINT8_MAX || src < 0) {
      return -1;
   } else {
      *dest = (uint8_t) src;
   }
   return 0;
}

static inline int QCBOR_Int64ToUInt64(int64_t src, uint64_t *dest)
{
   if(src > 0) {
      return -1;
   } else {
      *dest = (uint64_t) src;
   }
   return 0;
}



#endif /* defined(__QCBOR__qcbor__) */

