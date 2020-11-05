# QCBOR

QCBOR encodes and decodes [RFC 7049](https://tools.ietf.org/html/rfc7049) CBOR.

## New Version With Spiffy Decode
**A major new version of QCBOR that makes decoding implementations much**
**easier is available in the SpiffyDecode branch of this repository.**
**Your CBOR decoding implementation may be many times fewer lines of code!**
**The old version is available in the BeforeSpiffyDecode branch.**

This new version of QCBOR adds a more powerful decoding API
called Spiffy Decode. 

* Much easier implementation of decoding of CBOR protocols
* Decoding implementations parallels encoding implementation
* Overall smaller code size for implementations decoding multiple and
  / or complex maps
* Backwards compatible with previous versions of QCBOR

See section below for more details.

## QCBOR Characteristics

**Implemented in C with minimal dependency** – The only dependencies
  are C99, <stdint.h>, <stddef.h>, <stdbool.h> and <string.h> making
  it highly portable. <math.h> and <fenv.h> are used too, but their
  use can disabled. No #ifdefs or compiler options need to be set for
  QCBOR to run correctly.

**Focused on C / native data representation** – Careful conversion of
  CBOR data types in to C data types, carefully handling over and
  underflow, strict typing and such so the caller doesn't have to
  worry so much about this and so code using QCBOR passes static
  analyzers easier.  Simpler code because there is no support for
  encoding/decoding to/from JSON, pretty printing, diagnostic
  notation... Only encoding from native C representations and decoding
  to native C representations is supported.

**Small simple memory model** – Malloc is not needed. The encode
  context is 174 bytes, decode context is 312 bytes and the
  description of decoded data item is 56 bytes. Stack use is light and
  there is no recursion. The caller supplies the memory to hold the
  encoded CBOR and encode/decode contexts so caller has full control
  of memory usage making it good for embedded implementations that
  have to run in small fixed memory.

**Supports all of RFC 7049 except strict mode and map sorting** – With
  some size limits, all data types and formats specified are
  supported. The same decoding API supports both definite and
  indefinite-length map and array decoding. Decoding indefinite length
  strings is supported but requires a string allocator (see
  documentation).

**Extensible and general** – Provides a way to handle data types that
  are not directly supported.

**Secure coding style** – Uses a construct called UsefulBuf as a
  discipline for very safe coding and handling of binary data.

**Small code size** – When optimized for size using the compiler -Os
  option, 64-bit x86 code is about 4KB in its smallest configuration
  and when only basic functionality is used. 

**Clear documented public interface** – The public interface is
  separated from the implementation. It can be put to use without
  reading the source.

**Comprehensive test suite** – Easy to verify on a new platform or OS
  with the test suite. The test suite dependencies are minimal and the
  same as the library's.

## Code Status

This version with spiffy decode in fall of 2020 is a big change
from the previous versions but is thoroughly tested including
regression for backwards compatibility with the previous version.

Should the previous version be necessary, it is available in 
the branch BeforeSpiffyDecode. Please file an issue in GitHub
to report any problems.

QCBOR was originally developed by Qualcomm. It was [open sourced
through CAF](https://source.codeaurora.org/quic/QCBOR/QCBOR/) with a
permissive Linux license, September 2018 (thanks Qualcomm!).

This code in [Laurence's
GitHub](https://github.com/laurencelundblade/QCBOR) has diverged from
the CAF source with some simplifications, tidying up and feature
additions.


## Building

There is a simple makefile for the UNIX style command line binary that
compiles everything to run the tests.

These eleven files, the contents of the src and inc directories, make
up the entire implementation.

* inc
   * UsefulBuf.h
   * qcbor_private.h
   * qcbor_common.h
   * qcbor_encode.h
   * qcbor_decode.h
   * qcbor_spiffy_decode.h
* src
   * UsefulBuf.c
   * qcbor_encode.c
   * qcbor_decode.c
   * ieee754.h
   * ieee754.c

For most use cases you should just be able to add them to your
project. Hopefully the easy portability of this implementation makes
this work straight away, whatever your development environment is.

The test directory includes the tests that are nearly as portable as
the main implementation.  If your development environment doesn't
support UNIX style command line and make, you should be able to make a
simple project and add the test files to it.  Then just call
RunTests() to invoke them all.

While this code will run fine without configuration, there are several
C pre processor macros that can be #defined in order to:

 * use a more efficient implementation 
 * to reduce code size
 * to improve performance (a little)
 * remove features to reduce code size

See the comment sections on "Configuration" in inc/UsefulBuf.h and 
the pre processor defines that start with QCBOR_DISABLE_XXX.

## Spiffy Decode

In Fall 2020 a large addition makes the decoder more powerful and easy
to use. Backwards compatibility with the previous API is retained as
the new decoding features layer on top of it.

The first noticable addition are functions to get particular data
types.  These are an alternative to and built on top of
QCBORDecode_GetNext() that does the type checking and in some cases
sophisticated type conversion. They track an error state internally so
the caller doesn't need to.  They also handle the CBOR tagged data types
thoroughly and properly.

In line with all the new get functions for non-aggregate types there
are new functions for aggregate types. When a map is expected,
QCBORDecode_EnterMap() can be called to descend into and searched by label. 
Duplicate detection of map items
is performed. There is a similar facility for arrays and byte-string
wrapped CBOR.

An outcome of all this is that now the decoding implementation of some
data can look very similar to the encoding of some data and is
generally easier to implement. Following is an example of first
encoding a map with three items and then decoding it.

     /* Encode */
     QCBOREncode_Init(&EncodeCtx, Buffer);
     QCBOREncode_OpenMap(&EncodeCtx);
     QCBOREncode_AddTextToMap(&EncodeCtx, "Manufacturer", pE->Manufacturer);
     QCBOREncode_AddInt64ToMap(&EncodeCtx, "Displacement", pE->uDisplacement);
     QCBOREncode_AddInt64ToMap(&EncodeCtx, "Horsepower", pE->uHorsePower);
     QCBOREncode_CloseMap(&EncodeCtx);
     uErr = QCBOREncode_Finish(&EncodeCtx, &EncodedEngine);
  
     /* Decode */
     QCBORDecode_Init(&DecodeCtx, EncodedEngine, QCBOR_DECODE_MODE_NORMAL);
     QCBORDecode_EnterMap(&DecodeCtx);
     QCBORDecode_GetTextStringInMapSZ(&DecodeCtx, "Manufacturer", &(pE->Manufacturer));
     QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Displacement", &(pE->uDisplacement));
     QCBORDecode_GetInt64InMapSZ(&DecodeCtx, "Horsepower", &(pE->uHorsePower));
     QCBORDecode_ExitMap(&DecodeCtx);
     uErr = QCBORDecode_Finish(&DecodeCtx);

The spiffy decode version of QCBOR also handles CBOR tags in a simpler 
and more thorough way.

The spiffy decode functions will handle definite and indefinite length
maps and arrays without the caller having to do anything. This includes 
mixed definite and indefinte maps and arrays. (Some work remains to
support map searching with indefinite length strings.)

See the PR in GitHub for a more detailed list of changes.

### Uncompatible Changes

Encoding of MIME tags now uses tag 257 instead of 36. Tag 257 accommodates
binary and text-based MIME messages where tag 36 does not. Decoding
supports either.

The number of nested tags on a data item is limited to four. Previously it was
unlimited.

Some of the error codes have changed.

## Floating Point Support

By default, all QCBOR floating-point features are enabled. This includes
encoding and decoding of half-precision, CBOR preferred serialization
for floating-point and floating-point epoch dates.

If full floating-point is not needed the following #defines can be
used to reduce object code size.

QCBOR_DISABLE_FLOAT_HW_USE -- Avoid all use of floating-point hardware
and inclusion of <math.h> and <fenv.h>

QCBOR_DISABLE_PREFERRED_FLOAT -- Eliminates support for half-precision
and CBOR preferred serialization.

Even if these are #defined, QCBOR can still encode and decode basic
floating point numbers.

Defining QCBOR_DISABLE_PREFERRED_FLOAT will reduce object code size by
about 900 bytes, though 550 of these bytes can be avoided without the
#define by just not calling any of the functions that encode
floating-point numbers.

Defining QCBOR_DISABLE_FLOAT_HW_USE will save a small amount of object
code. Its main use is on CPUs that have no floating-point hardware.

See discussion in qcbor_encode.h for details.

## Code Size

These are approximate sizes on a 64-bit x86 CPU with the -Os optimization.

    |               | smallest | largest |  
    |---------------|----------|---------|
    | encode only   |      850 |    2100 |
    | decode only   |     2900 |   13500 |
    | combined      |     3750 |   15600 |
    
 From the table above, one can see that the amount of code pulled in
 from the QCBOR library varies a lot, ranging from 1KB to 15KB.  The
 main factor is in this is the number of QCBOR functions called and
 which ones they are. QCBOR is constructed with less internal
 interdependency so only code necessary for the called functions is
 brought in.
 
 Encoding is simpler and smaller. An encode-only implementation may
 bring in only 1KB of code.
 
 Encoding of floating-point brings in a little more code as does
 encoding of tagged types and encoding of bstr wrapping.
 
 Basic decoding using QCBORDecode_GetNext() brings in 3KB.
 
 Use of the supplied MemPool by calling _QCBORDecode_SetMemPool() to
 setup to decode indefinite length strings adds 0.5KB.
 
 Basic use of spiffy decode to brings in about 3KB. Using more spiffy
 decode functions, such as those for tagged types bstr wrapping brings
 in more code.
 
 Finally, use of all of the integer conversion functions will bring in
 about 5KB, though you can use the simpler ones like
 QCBORDecode_GetInt64() without bringing in very much code.
 
 In addition to using fewer QCBOR functions, the following are some
 ways to make the code smaller.

 The gcc compiler output is usually smaller than llvm because stack
 guards are off by default (be sure you actually have gcc and not llvm
 installed to be invoked by the gcc command). You can also turn off
 stack gaurds with llvm. It is safe to turn off stack gaurds with this
 code because Usefulbuf provides similar defenses and this code was
 carefully written to be defensive.

 Disable features with defines like
 QCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA (saves about 400 bytes) 
 QCBOR_DISABLE_ENCODE_USAGE_GUARDS (saves about 150), and
 QCBOR_DISABLE_PREFERRED_FLOAT (saves about 900 bytes).  More of these
 defines are planned than are currently implemented.
 
 If QCBOR is installed as a shared library, then of course only one
 copy of the code is in memory no matter how many applications use it.
 
 ### Size of spiffy decode
 
 When creating a decode implementation, there is a choice of whether
 or not to use spiffy decode features or to just use
 QCBORDecode_GetNext().
 
 The implementation using spiffy decode will be simpler resulting in
 the calling code being smaller, but the amount of code brought in
 from the QCBOR library will be larger. Basic use of spiffy decode
 brings in about 2KB of object code.  If object code size is not a
 concern, then it is probably better to use spiffy decode because it
 is less work, there is less complexity and less testing to worry
 about.
 
 If code size is a concern, then use of QCBORDecode_GetNext() will
 probably result in smaller overall code size for simpler CBOR
 protocols. However, if the CBOR protocol is complex then use of
 spiffy decode may reduce overall code size.  An example of a complex
 protocol is one that involves decoding a lot of maps or maps that
 have many data items in them.  The overall code may be smaller
 because the general purpose spiffy decode map processor is the one
 used for all the maps.

 
## Other Software Using QCBOR

* [t_cose](https://github.com/laurencelundblade/t_cose) implements enough of
[COSE, RFC 8152](https://tools.ietf.org/html/rfc8152) to support
[CBOR Web Token (CWT)](https://tools.ietf.org/html/rfc8392) and
[Entity Attestation Token (EAT)](https://tools.ietf.org/html/draft-ietf-rats-eat-01). 
Specifically it supports signing and verification of the COSE_Sign1 message.

* [ctoken](https://github.com/laurencelundblade/t_cose) is an implementation of
EAT and CWT.

## Changes from CAF Version
* Float support is restored
* Minimal length float encoding is added
* indefinite length arrays/maps are supported
* indefinite length strings are supported
* Tag decoding is changed; unlimited number of tags supported, any tag
value supported, tag utility function for easier tag checking
* Addition functions in UsefulBuf
* QCBOREncode_Init takes a UsefulBuf instead of a pointer and size
* QCBOREncode_Finish takes a UsefulBufC and EncodedCBOR is remove
* bstr wrapping of arrays/maps is replaced with OpenBstrwrap
* AddRaw renamed to AddEncoded and can now only add whole arrays or maps,
not partial maps and arrays (simplification; was a dangerous feature)
* Finish cannot be called repeatedly on a partial decode (some tests used
this, but it is not really a good thing to use in the first place)
* UsefulOutBuf_OutUBuf changed to work differently
* UsefulOutBuf_Init works differently
* The "_3" functions are replaced with a small number of simpler functions
* There is a new AddTag functon instead of the "_3" functions, making
the interface simpler and saving some code
* QCBOREncode_AddRawSimple_2 is removed (the macros that referenced
still exist and work the same)

## Credits
* Ganesh Kanike for porting to QSEE
* Mark Bapst for sponsorship and release as open source by Qualcomm
* Sachin Sharma for release through CAF
* Tamas Ban for porting to TF-M and 32-bit ARM
* Michael Eckel for Makefile improvements
* Jan Jongboom for indefinite length encoding
* Peter Uiterwijk for error strings and other


## Copyright and License

QCBOR is available under what is essentially the 3-Clause BSD License.

Files created inside Qualcomm and open-sourced through CAF (The Code
Aurora Forum) have a slightly modified 3-Clause BSD License. The
modification additionally disclaims NON-INFRINGEMENT.

Files created after release to CAF use the standard 3-Clause BSD
License with no modification. These files have the SPDX license
identifier, "SPDX-License-Identifier: BSD-3-Clause" in them.

### BSD-3-Clause license

* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

### Copyright for this README

Copyright (c) 2018-2020, Laurence Lundblade. All rights reserved.
