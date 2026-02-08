


# Floating-Point

@anchor Floating-Point

## Floating-point Quick start

There are subtle issues for floating-point numbers that are discussed
in this section, but they aren't a factor for most that just want to
encode and decode IEEE 754 floating-point numbers, that of the C type
double.

All floating-point features are enabled by default.

To encode a floating-point value, use QCBOREncode_AddDouble().

To decode, use QCBORDecode_GetNext(), check whether the returned item
has type @ref QCBOR_TYPE_DOUBLE, and access the dfNum member of the
@ref QCBORItem.  Alternatively, call QCBORDecode_GetDouble().

Both `INFINITY` and `NAN` are supported.

QCBOR primarily uses the double type in its API because converting
from float to double never loses precision or range.

If, however, you are using QCBOR in an environment with no support for
float-point at all, compile QCBOR with USEFULBUF_DISABLE_ALL_FLOAT
macro defined. In this configuration, all support is removed including
the use of the types `double` and `float` in the interface.

Now, own to the more subtle issuses.


## Floating-point Serialization

CBOR floating-point encoding is perhaps the most compact way possible, especially
compared to JSON which uses text strings.
CBOR makes use of IEEE single and half-precision in encoding when their use doesn't reduce precision or range.
This is particularly great for values like 0.0, INFINITY, -INFINITY and NaN which encode in 3 bytes instead of 9 if they were encoded as a double.
(CBOR floating-point encodes with a type byte plus the IEEE 754 representation).

CBOR also allows any size IEEE representation to be used to encode any value.
For example, 0.0 can be encoded (serialized) with double, single or half-precision.

When there is no restriction on what IEEE size is used to encode a particular value it is called "general serialization" as described draft-cbor-serialization.
The format definitions that make up general serialization are those for major type 7 in RFC 8949.

The compact serialization is called "ordinary serialization".
It is a standard defined in draft-cbor-serializaiton.
It requires the use of the most compact IEEE representation that will preserve the precision and range of the value being encoded.
Except for NaN handling, it is the same compact encoding of floats that is part of "preferred serialization" defined in RFC 8949.

Since orindary serialization has only one way to encode every IEEE value represented by a double, it is also deterministic for floating-point values.
For example, it is permitted only to encode the value 0.0 as half-precision.

All of QCBOR's main methods for encoding float-point will do so using ordinary serialization.

All of QCBOR's methods of decoding floating-point are able to decode general serialization.

QCBOREncode_AddDoubleRaw() and QCBOREncode_AddFloatRaw() do not do ordinary serialization.
One reason to them is NaN payloads.
Another reason would be for a protocol or a receiver that deosn't support single or half-precision.

Some discussion of half-precision is warranted.
It is fully and formally defined and standardized in IEEE 754.
It is very useful in CBOR for the compactness it brings for very commonly encoded values like 0, 1.0, 2.0, 4.0,...
While It is not commonly supported in programming environments, most CBOR decoders to support it.
Sample code to do the conversion from half-precision to single/double precision is provided in RFC 8949.
It is performed with shifts and masks.
It doesn't need any special hardware for floating point or any special support from the compiler.
THus, CBOR's use of half-precision is interoperable and not a problem.

QCBOR normally accepts floating point with any serialization for any size.
For example if you call GetDouble() and the value is encoded with half-precision, it will succeed.
If you want to be sure the serialization is not general, QCBOR decoding provides an option to check that the input is serialized according to ordinary serialization.


## Overview of QCBOR's floating-point features

### Float Encoding

The main means for encoding is QCBOREncode_AddDouble().
It will produce ordinary serialization, the most compact form.
This wide spread practice and decodable by all but the most incapable CBOR libraries.

QCBOREncode_AddFloat() is also available, mostly to avoid a cast from float to double, should you use flaot in your code.
It also does ordinary serialization.

QCBOREncode_AddDoubleRaw() and QCBOREncode_AddFloatRaw() always output the IEEE 754 type they are named for.
They do no processing at all.

CBOR supports a tag (new data type) called a "big float".
There is no limit to the size of the mantissa and thus no limit to the precision it can encode.
The exponent is a 64-bit integer, which is not unimited, but is very large for an exponent.
QCBOR supports this with QCBOREncode_AddTBigFloat() for a 64-bit mantissa and QCBOREncode_AddTBigFloatBigMantissa() for an unlimited mantissa.
"bit floats" are a whole separate data type then regular floats in CBOR.
There is no number space unification or equivalence like there are for big numbers and integers.

TODO: dates?


### Float Decoding

Most commonly, floats are decoded with GetNext().
This decodes double, single and half-precision and return the value as a double.
GetDouble() works same way.

If the float to be decoded is a NaN with a payload, the double returned will include the payload bits.
TODO: describe how they are shifted.

GetNext() can decode big floats if the tag handler, QCBORDecode_ExpMantissaTagCB(), for it is installed.
They are returned in the structure QCBORExpAndMantissa.

QCBORDecode_GetTBigFloat() and QCBORDecode_GetTBigFloatBigMantissa() can also be used to decode a big number.

QCBOR supports a number of decode options that do conversions.

QCBORDecode_GetInt64Convert() and GetIntQCBORDecode_GetInt64ConvertAll() always return a 64-bit signed integer.
GetInt64Convert() supports the float types double, single and half-precision.
GetInt64ConvertAll() adds big float support.
This conversion does rounding to the nearest integer.
There are similar functions for unsigned integer.
Since the floating-point range is much larger than the 64-bit integer range, this conversion will often result in QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW.

QCBORDecode_GetDoubleConvert() and GetDoubleConvertAll() always returns a double.
It can convert the basic integer types to double.
It will loose precision for integers larger than 52 bits because a double has only 52 bits of precission whereas a integer can have 64.
GetDoubleConvertAll() adds conversion for big float and big numbers.

QCBORDecode_GetNumberConvertPrecisely() can return both floats and integers.
It can decode both floats and integers.
It returns integers when the value can be represented as such without a loss in conversion.
It never looses precision in a conversion.

There is no comprehensive conversion (yet) to big numbers or big floats, though that might be useful.

The conformace setting QCBOR_DECODE_ONLY_PREFERRED_NUMBERS affects floats in two ways.
First it will error out if the float was not encoded in shortest form.
Second, it will error out if a NaN with a payload is encountered.

The conformance setting QCBOR_DECODE_ONLY_REDUCED_FLOATS will result in a error integer values encoded as floats are encountered.
This is part of the dCBOR requirements.



## NaNs

NaNs have been a subtle, complicated and controversial issue in the design of CBOR.
See the appendix in draft-cbor-serialization for detailed background information.

The large majority of applications can just not use NaNs at all.
Their primary purpose is local use inside to represent the result of division by zero.
They are not usually transmitted in protocols.

One use for them in protocols is to indicate an absent value.
NULL can be used instead.
It also works in JSON, where NaN does not.

The simplest case of a NaN in a protocol is a queit NaN.
While NaN's with payloads carry extra bits, a quiet NaN does not.
All the serializations for CBOR and versions of QCBOR handle this just fine.
Just pass NAN to AddDouble().
GetDouble() returns a NAN.

All the complicatations arise when NaNs have payloads, when they carry extra bits.
The recommendation is to not make use of NaN payloads, but if you must, read on.

Because Nan's with payloads are so seldom and poorly supported in most CBOR libraries
and even in C compilers, you must enable there use for each instance of the encoder or decoder
by setting XXX and XXX.

To encode a NaN with a payload, first you must construct it.
The C language doesn't have library or languages facilities to do it, so you have to do it manually with shifts and masks.
This requires familiarity with the details of IEEE 754.

In QCBOR v2, call QCBORENcode_AddDoubleRaw() or QCBORENcode_AddFloatRaw() to encode the double or float you constructed with a NaN payload.
QCBORDecode_GetNext() and QCBORDEcode_GetDouble() will return NaNs with payloads.



NaN handling in QCBOR v1 is in accordance with RFC 8949, particularly preferred serialization.
In v2 it is in accordance with draft-cbor-serialization, particularly ordinary serialization.
The difference is solely in how NaNs with payloads, non-trivial NaNs are handled.



## Compile-Time Floating-Point Configuration

By default, all floating-point functions are enabled and available.
This sections describes how to partially or fully disable
floating-point features when needed.

Before detailing the library compile-time options, note
that for the most part floating point code won't be
linked unless it is called (assuming the compiler/linker
does dead stripping). QCBOR minimizes internal dependencies
so this is effective. During
encoding, no floating-point code is linked unless called; during
decoding, only a small amount is linked. It may not
be necessary to reconfigure the QCBOR library just for the
sake of code size reduction in statically linked, dead-stripped, applications.

### #define QCBOR_DISABLE_PREFERRED_FLOAT

Defining `QCBOR_DISABLE_PREFERRED_FLOAT` can reduce
object code by as much a 2.5KB. The effects are:

- No preferred serialization encoding of float-point numbers
- Half-precision decoding is disabled -- decoding attempts will fail
- Single-precision values are not converted to double during decoding
- dCBOR number processing via QCBORDecode_GetNumberConvertPrecisely() is unavailable
- Floating-point decode conformance checks for dCBOR and others are unavailable

This eliminates support of:

- encode/decode of half-precision
- shortest-form encoding of floats
- QCBORDecode_GetNumberConvertPrecisely()

This saves about 1KB of object code, though much of this can be saved
by not calling any functions to encode doubles or floats or
QCBORDecode_GetNumberConvertPrecisely()

With this defined, single and double-precision floating-point numbers
can still be encoded and decoded. Some conversion of floating-point to
and from integers, big numbers and such is also supported. Floating-point
dates are still supported.

### #define QCBOR_DISABLE_FLOAT_HW_USE

This removes dependency on:

- Floating-point hardware and instructions
- `<math.h>` and `<fenv.h>`
- The math library (libm, -lm)
- Compiler-supplied floating-point libraries

This does not remove use of the types double and float from
QCBOR, but limits use of them to representing values
to be encoded and decoded. Basic CBOR floating-point encoding
and decoding does not require floating-point hardware or
libraries.

QCBOR uses its own implementation of half-precision float-pointing
that doesn't depend on math libraries. It uses masks and shifts
instead. Thus, even with this define, half-precision encoding and
decoding works.


On CPUs without floating-point hardware, define
`QCBOR_DISABLE_FLOAT_HW_USE` to elimate the possibility of the compiler
adding large software emulation libraries.  On CPUs with
floating-point hardware, defining it can still save up to 1.5 KB of
object code. This removes the dependency on <math.h>.

When `QCBOR_DISABLE_FLOAT_HW_USE` is defined:

- Decode conversions involving floating-point are disabled
- Decoding of floating-point dates is not possible

If both `QCBOR_DISABLE_FLOAT_HW_USE` and `QCBOR_DISABLE_PREFERRED_FLOAT`
are defined:

- Single-precision and double-precision values can only be encoded/decoded
   as-is (no conversions between them).
   
When this is defined, the QCBOR functionality lost is minimal and only
for decoding:

* Decoding floating-point format dates are not handled
* There is no conversion between floats and integers when decoding. For
  example, QCBORDecode_GetUInt64ConvertAll() will be unable to convert
  to and from float-point.
* Floats will be unconverted to double when decoding.

No interfaces are disabled or removed with this define.  If input that
requires floating-point conversion or functions are called that
request floating-point conversion, an error code like
`QCBOR_ERR_HW_FLOAT_DISABLED` will be returned.

This saves only a small amount of object code. The primary purpose for
defining this is to remove dependency on floating point hardware and
libraries.


#### #define USEFULBUF_DISABLE_ALL_FLOAT

If `USEFULBUF_DISABLE_ALL_FLOAT` is defined, then floating-point
support is completely disabled:

- No double or float types are used anywhere
- Decoding functions return @ref QCBOR_ERR_ALL_FLOAT_DISABLED if a floating-point value is encountered
- Encoding functions for floating-point values are unavailable
 
#### Compiler options

Compilers support a number of options that control which float-point
related code is generated. For example, it is usually possible to give
options to the compiler to avoid all floating-point hardware and
instructions, to use software and replacement libraries instead. These
are usually bigger and slower, but these options may still be useful
in getting QCBOR to run in some environments in combination with
`QCBOR_DISABLE_FLOAT_HW_USE`.  In particular, `-mfloat-abi=soft`,
disables use of hardware instructions for the float and double types
in C for some architectures.
 

@anchor BigNumbers

# Big Numbers

## Basics

Big numbers are integers that can be as long and as large as desired,
limited only by the amount of memory allocated for them.

They are represented as a byte string plus an indication of sign. The
most significant byte is first (network byte order) both in the
encoded form and as input and output by QCBOR APIs.

CBOR has only one encoded representation of zero for integers, big
numbers included.  That means the whole negative number space is
offset by one. Since big numbers are encoded as a sign and some bytes,
the steps to encode a negative value are to take the absolute value
and then adjust by one. On encoding, the adjustment is to subtract one
from the absolute value, and on decoding to add one to the absolute
value.

Take -256 as an example. It is represented in memory with two bytes,
0x01 0x00, plus indication that it is negative, perhaps a boolean.
When it is CBOR-encoded it becomes 0xff plus an indication of the
sign.

Notice that the length changed. This is one place in the design of
CBOR where the bytes off the wire cannot be simply used as they
are. This has an effect on the big number encoding and decoding
APIs.

The tag numbers 2 and 3 indicate a big number. The tag content is a
byte string with the absolute value of the big number, offset by one
when negative. Tag number 2 indicates positive and 3 negative.

For example, 256 encoded as a positive big number is 0xc2 0x42 0x01
0x00 and -256 encodes as 0xc3 0x41 0xff (non-preferred; see preferred
example in next section).


## Preferred Serialization

The integer number space encodable by big numbers overlaps with the
number space encodable by regular integers, by CBOR type 0 and type 1,
the range from -(2^64) to (2^64)-1.

RFC 8949 big number preferred serialization requires that numbers in
the type 0 and 1 integer range must not be encoded as big
numbers. They must be encoded as type 0 and type 1 integers.

For example, 256 must be encoded as 0x19 0x01 0x00 and -256 as
0x38 0xff.

One purpose of this is to save some bytes, but typically only one byte
is saved. The more important reason for this is determinism.  There is
only one way to represent a particular value.

Technically speaking, this reduction of the big number space to the
integer space is not about serialization. It doesn't change the way
big numbers and integers are serialized by themselves.

Note, also that CBOR can encode what can be called "65-big negative
numbers", 64 bits of precision and one bit to indicate a negative
one. These can't be represented by 64-bit two's compliment signed
integers or 64-bit unsigned integers. While many programming
environments, like Ruby and Python that have big number support built
in will support these, some environments like C and the CPU
instructions do not. QCBOR big number decoding supports them with
explicit code to carry the negative number in as a uint64_t and a sign
indicator. Big number specific preferred serialization requires
encoding of 65-bit negative integers. Other than big numbers QCBOR
avoids 65-big negative integers.

## QCBOR APIs

The negative number offset of one and the reduction required by
big number preferred serialization have a large effect on the QCBOR
big number API.

QCBOREncode_AddTBigNumber() and QCBORDecode_GetTBigNumber() are the
most comprehensive and easiest to use APIs. They automatically take
care of the offset of one for negative numbers and big number
preferred serialization. Unlike most other decode APIs,
QCBORDecode_GetTBigNumber() requires an output buffer of sufficient
size.

If the protocol being implemented does not use preferred
serialization, then QCBOREncode_AddTBigNumberNoPreferred() and
QCBORDecode_GetTBigNumberNoPreferred() can be used. Only tags 2 and 3
will be output when encoding.  Type 0 and 1 integers will never be
output. Decoding will error if type 0 and type 1 integers are
encountered.

It is likely that any implementation for a protocol that uses big
numbers will link in a big number library.  When that's so, it can be
used to offset the negative numbers by one rather than the internal
implementation that QCBOR has. If both the offset by one and the
preferred serialization are side-stepped, the big numbers APIs become
simple pass throughs for encoding and decoding byte strings.  This
reduces the amount of object linked from the QCBOR library by about
1KB.

This is what QCBOREncode_AddTBigNumberRaw() and
QCBORDecode_GetTBigNumberRaw() do. Note that decoding doesn't require
an output buffer be supplied because the bytes off the wire can simply
be returned. When these are used, the big number library should be
used to add one to negative numbers before encoding and subtract one
from negative numbers after decoding.

Last, QCBORDecode_StringsTagCB(), @ref QCBOR_TYPE_POSBIGNUM,
@ref QCBOR_TYPE_NEGBIGNUM, and QCBORDecode_ProcessBigNumber() need to
be described. QCBOR's tag processing callbacks can be used to handle
big numbers by installing QCBORDecode_StringsTagCB() for tag numbers 2
and 3. This will result in positive and negative big numbers being
returned in a @ref QCBORItem as QCBOR types @ref QCBOR_TYPE_POSBIGNUM and
@ref QCBOR_TYPE_NEGBIGNUM. QCBORDecode_StringsTagCB() is very simple,
and not much object code. Neither the offset of one for negative
values nor preferred serialization number reduction is preformed. It is
equivalent to QCBORDecode_GetTBigNumberRaw().

QCBORDecode_ProcessBigNumber() may be used to fully process a
@ref QCBORItem that is expected to be a big number. It will perform the
negative offset and handle the preferred serialization number
reduction. QCBORDecode_ProcessBigNumber() is what is used internally
to implement QCBORDecode_GetTBigNumber() and links in a lot of
object code. Note that QCBORDecode_ProcessBigNumber() requires an
output buffer be supplied.

QCBORDecode_ProcessBigNumbernoPreferred() is the same as
QCBORDecode_ProcessBigNumber() but will error out if the @ref QCBORItem
contains anything but @ref QCBOR_TYPE_POSBIGNUM, @ref QCBOR_TYPE_NEGBIGNUM.
 
Note that if QCBORDecode_StringsTagCB() is installed,
QCBORDecode_GetTBigNumber(), QCBORDecode_GetTBigNumberNoPreferred()
and QCBORDecode_GetTBigNumberRaw() all still work as documented.

## "Borrowed" Big Number Tag Content

Like all other tag decoding functions in QCBOR, the big number tag
decoders can also work with borrowed tag content for big numbers. For
example, the value of a map item might be specified that it be decoded
as a big number even though there is no tag number indicating so.

The main thing to mention here is that without a tag number, there's
nothing in the encoded CBOR to indicate the sign. That must be
indicated some other way. For example, it might be that the map item
is defined to always be a positive big number.

On the encode side, that means the sign boolean is ignored when
QCBOREncode_AddTBigNumber() is called with @c uTagRequirement other
than @ref QCBOR_ENCODE_AS_TAG.

On the decode side, the sign boolean becomes an input parameter rather
than an output parameter so that QCBORDecode_GetTBigNumber() can know
whether to apply the offset of one in case the value is negative.

## Big Number Conversions

QCBOR provides a number of decode functions that can convert big
numbers to other representations like floating point. For example, see
QCBORDecode_GetDoubleConvertAll().

Note also that QCBORDecode_ProcessBigNumber() can convert integers to
big numbers. It will work even if the protocol item is never supposed
to be a big number. It will just happily convert any type 0 or type 1
CBOR integer to a big number.

## Backwards Compatibility with QCBOR v1

QCBOR v1 supports only the minimal pass through processing of big
numbers, not the offset of one for negative values or the big number
specific preferred serialization. The main functions in v1 are
QCBOREncode_AddTPositiveBignum(), QCBOREncode_AddTNegativeBignum() and
QCBORDecode_GetBignum(). These are equivalent to
QCBOREncode_AddTBigNumberRaw() and QCBORDecode_GetTBigNumberRaw().

Also, in v1 @ref CBOR_TAG_POS_BIGNUM and @ref CBOR_TAG_NEG_BIGNUM are
always processed into a @ref QCBORItem of type @ref
QCBOR_TYPE_POSBIGNUM and @ref QCBOR_TYPE_NEGBIGNUM by an equivalent of
QCBORDecode_StringsTagCB.

All the v1 methods for big numbers such as
QCBOREncode_AddTPositiveBignum() and QCBORDecode_GetBignum() are fully
supported in v2. When QCBORDecode_StringsTagCB() is installed for tags
2 and 3 such as by calling QCBORDecode_CompatibilityV1(), QCBOR v2 big
number behavior is 100% backwards compatible.
 
