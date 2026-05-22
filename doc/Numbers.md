

# Floating-Point

@anchor Floating-Point

## Floating-Point Quick start

There are subtle issues for floating-point numbers that are discussed
in this section, but they aren't a factor for most that just want to
encode and decode IEEE 754 floating-point numbers of the C type
double.

All floating-point features are enabled by default.

To encode a floating-point value, use QCBOREncode_AddDouble().

To decode, use QCBORDecode_VGetNext(), check whether the returned item
has type @ref QCBOR_TYPE_DOUBLE, and access the dfNum member of the
@ref QCBORItem.  Alternatively, call QCBORDecode_GetDouble().

Both `INFINITY` and `NAN` are supported.

QCBOR primarily uses the type `double` in its API because converting
from `float` to `double` never loses precision or range.

If, however, you are using QCBOR in an environment with no support for
floating-point at all, compile QCBOR with `USEFULBUF_DISABLE_ALL_FLOAT`
macro defined. In this configuration, all support is removed including
the use of the types `double` and `float` in the interface.

Now, own to the more subtle issuses.


## Floating-Point Serialization

CBOR floating-point encoding is perhaps the most compact way possible,
especially compared to JSON which uses text strings.  CBOR makes use
of IEEE single and half-precision in encoding when their use doesn't
reduce precision or range.  This is particularly great for values like
0.0, INFINITY, -INFINITY and NaN which encode in 3 bytes instead of 9
if they were encoded as a double.  (CBOR floating-point encodes with a
type byte plus the IEEE 754 representation).

CBOR also allows any size IEEE representation to be used to encode any
value.  For example, 0.0 can be encoded (serialized) with double,
single or half-precision.

When there is no restriction on what IEEE size is used to encode a
particular value it is called "general serialization" as described
draft-cbor-serialization.  The format definitions that make up general
serialization are those for major type 7 in RFC 8949.

The compact serialization is called "ordinary serialization".  It is a
standard defined in draft-cbor-serializaiton.  It requires the use of
the most compact IEEE representation that will preserve the precision
and range of the value being encoded.  Except for NaN handling, it is
the same compact encoding of floats that is part of "preferred
serialization" defined in RFC 8949.

Since orindary serialization has only one way to encode every IEEE
value represented by a double, it is also deterministic for
floating-point values.  For example, it is permitted only to encode
the value 0.0 as half-precision.

All of QCBOR's main methods for encoding float-point will do so using
ordinary serialization.

All of QCBOR's methods of decoding floating-point are able to decode
general serialization.

QCBOREncode_AddDoubleRaw() and QCBOREncode_AddFloatRaw() do not do
ordinary serialization.  One reason to them is NaN payloads.  Another
reason would be for a protocol or a receiver that deosn't support
single or half-precision.

Some discussion of half-precision is warranted.  It is fully and
formally defined and standardized in IEEE 754.  It is very useful in
CBOR for the compactness it brings for very commonly encoded values
like 0, 1.0, 2.0, 4.0,...  While It is not commonly supported in
programming environments, most CBOR decoders to support it.  Sample
code to do the conversion from half-precision to single/double
precision is provided in RFC 8949.  It is performed with shifts and
masks.  It doesn't need any special hardware for floating point or any
special support from the compiler.  THus, CBOR's use of half-precision
is interoperable and not a problem.

QCBOR normally accepts floating point with any serialization for any
size.  For example if you call GetDouble() and the value is encoded
with half-precision, it will succeed.  If you want to be sure the
serialization is not general, QCBOR decoding provides an option to
check that the input is serialized according to ordinary
serialization.


## Overview of QCBOR's Floating-Point Features

### Float Encoding

The main means for encoding is QCBOREncode_AddDouble().  It will
produce preferred-plus serialization, the most compact form.  This is wide
spread practice and decodable by all but the most incapable CBOR
libraries.

QCBOREncode_AddFloat() is also available, mostly to avoid a cast from
float to double, should you use float in your code.  It also does
preferred-plus serialization.

QCBOREncode_AddDoubleRaw() and QCBOREncode_AddFloatRaw() always output
the IEEE 754 type they are named for.  They do no processing at all.

CBOR supports a tag (new data type) called a "big float".  There is no
limit to the size of the mantissa and thus no limit to the precision
it can encode.  The exponent is a 64-bit integer, which is not
unimited, but is very large for an exponent.  QCBOR supports this with
QCBOREncode_AddTBigFloat() for a 64-bit mantissa and
QCBOREncode_AddTBigFloatBigMantissa() for an unlimited mantissa.  "bit
floats" are a whole separate data type then regular floats in CBOR.
There is no number space unification or equivalence like there are for
big numbers and integers.

TODO: dates?


@anchor Floating-Point-Decode

### Float Decoding

Most commonly, floats are decoded with QCBORDecode_VGetNext().  This
decodes double, single and half-precision and returns the value as a
double.  QCBORDecode_GetDouble() works same way. NaN and inifinity
are supported. See @ref NaNs.

QCBORDecode_VGetNext() can decode big floats if the tag handler,
QCBORDecode_ExpMantissaTagCB(), for it is installed.  They are
returned in the structure QCBORExpAndMantissa.

QCBORDecode_GetTBigFloat() and QCBORDecode_GetTBigFloatBigMantissa()
can also be used to decode a big number.

QCBOR supports a number of decode options that do conversions.

QCBORDecode_GetInt64Convert() and
GetIntQCBORDecode_GetInt64ConvertAll() always return a 64-bit signed
integer.  GetInt64Convert() supports the float types double, single
and half-precision.  GetInt64ConvertAll() adds big float support.
This conversion does rounding to the nearest integer.  There are
similar functions for unsigned integer.  Since the floating-point
range is much larger than the 64-bit integer range, this conversion
will often result in QCBOR_ERR_CONVERSION_UNDER_OVER_FLOW.

QCBORDecode_GetDoubleConvert() and GetDoubleConvertAll() always
returns a double.  It can convert the basic integer types to double.
It will loose precision for integers larger than 52 bits because a
double has only 52 bits of precission whereas a integer can have 64.
GetDoubleConvertAll() adds conversion for big float and big numbers.

QCBORDecode_GetNumberConvertPrecisely() can return both floats and
integers.  It can decode both floats and integers.  It returns
integers when the value can be represented as such without a loss in
conversion.  It never looses precision in a conversion.

There is no comprehensive conversion (yet) to big numbers or big
floats, though that might be useful.

The conformace setting QCBOR_DECODE_ONLY_PREFERRED_NUMBERS affects
floats in two ways.  First it will error out if the float was not
encoded in shortest form.  Second, it will error out if a NaN with a
payload is encountered.

The conformance setting QCBOR_DECODE_ONLY_REDUCED_FLOATS will result
in a error integer values encoded as floats are encountered.  This is
part of the dCBOR requirements.


@anchor NaNs

## NaNs

NaNs have been a subtle, complicated, and controversial issue in the
design of CBOR. For detailed background, see the appendix in
draft-cbor-serialization.

Most protocols don't use NaNs, and they can be generally ignored.  If
decoding a floating-point value yields NAN (see <math.h>), it can be
usually considered an error. That said, QCBOR provides good support
for NaNs.

The simplest case is a quiet NaN. Unlike NaNs with payloads, quiet
NaNs do not carry extra bits. All CBOR serialization types and all
versions of QCBOR support quiet NaNs, which are represented by the
constant NAN from <math.h>.

Complications arise with NaNs that include payloads (sometimes called
non-trivial NaNs). These carry extra bits and are not widely
supported.  The recommendation is not to make use of NaN payloads, but
if you must, read on.

Because NaNs with payloads are rarely used and inconsistently
supported across CBOR libraries and programming languages, QCBOR
discourages their use. Support must be explicitly enabled on a
per-instance basis by setting @ref QCBOR_ENCODE_CONFIG_ALLOW_NAN_PAYLOAD
and @ref QCBOR_DECODE_MODE_ALLOW_NAN_PAYLOADS.

To encode a NaN with a payload, you must first construct it manually.
The C language does not provide standard facilities for this, so it
requires bit-level manipulation using shifts and masks, along with a
solid understanding of IEEE 754 floating-point representation.

In QCBOR v2, use QCBOREncode_AddDoubleRaw() or
QCBOREncode_AddFloatRaw() to encode a float or double containing a NaN
payload. On decoding, QCBORDecode_VGetNext() and
QCBORDecode_GetDouble() will return NaNs with payloads if they have
been allowed.

NaN handling differs slightly between QCBOR versions. QCBOR v1 follows
RFC 8949, particularly its “preferred serialization” rules. QCBOR v2
follows draft-cbor-serialization, including “preferred-plus
serialization.” The distinction primarily affects how NaNs with
payloads are treated.

If you are thinking about NaN payloads, really, really don't.  Try
some meditation or medication. Join a cult. A cult is probably better
than NaN payloads. I've wasted part of my life on NaN payloads. You
should not.

### Protocol Design

It is my opinion that protocols should avoid NaNs.

Instead, use null to indicate that a value is absent or invalid.  This
approach is consistent with how missing or erroneous values are
represented for CBOR integers, and it aligns with JSON, which does not
support NaNs. If a protocol is intended to work across both CBOR and
JSON, null is the more portable and interoperable choice.

Even more so, protocols should avoid non-trivial NaNs. Other protocol
structures can easily be invented to do what they do. Non-trivial NaN
support is poor in most programming languages, unevenly supported in
CBOR libraries, and doesn't work in JSON.


## Compile-Time Floating-Point Configuration

By default, all floating-point functions are enabled and available.
This section describes how to partially or fully disable
floating-point features when needed.

Before detailing the library compile-time options, note that for the
most part, floating-point code won't be linked unless it is called
(assuming compiler/linker dead stripping). QCBOR minimizes internal
dependencies, so this is effective. During encoding, no floating-point
code is linked unless called; during decoding, only a small amount is
linked. It may not be necessary to reconfigure the QCBOR library just
for the sake of code size reduction in statically linked,
dead-stripped applications.

### `#define QCBOR_DISABLE_PREFERRED_FLOAT`

The main purpose of this is to reduce object code. It removes many
floating-point features:

- No preferred serialization encoding of float-point numbers
- Half-precision decoding is disabled -- decoding attempts will fail
- Single-precision values are not converted to double during decoding
- dCBOR number processing via QCBORDecode_GetNumberConvertPrecisely() is unavailable
- Floating-point decode conformance checks for dCBOR and other are unavailable

With this defined, single and double-precision floating-point numbers
can still be encoded and decoded. Some conversion of floating-point to
and from integers, big numbers and such is also
supported. Floating-point dates are still supported.

### `#define QCBOR_DISABLE_FLOAT_HW_USE`

The main purpose of this is to remove dependency for easier
portability when only basic floating-point support is needed. The
dependencies removed are:

- Floating-point hardware and instructions
- `<math.h>` and `<fenv.h>`
- The math library (libm, -lm)
- Compiler-supplied floating-point libraries

This does not remove use of the types `double` and `float` from QCBOR,
but limits use of them to representing values to be encoded and
decoded. Basic CBOR floating-point encoding and decoding does not
require floating-point hardware or libraries.

QCBOR uses its own implementation of half-precision float-pointing
that doesn't depend on math libraries. It uses masks and shifts
instead. Thus, even with this define, half-precision encoding and
decoding works.

When `QCBOR_DISABLE_FLOAT_HW_USE` is defined:

- When decoding, single-precision inputs will not be returned as double
- Number conversion functions like QCBORDecode_GetUInt64ConvertAll() will not work with floating-point 
- Decoding of floating-point dates is not possible

If both `QCBOR_DISABLE_FLOAT_HW_USE` and `QCBOR_DISABLE_PREFERRED_FLOAT`
are defined:

- Single-precision and double-precision values can only be encoded/decoded
   as-is (no conversions between them).

No interfaces are disabled or removed with this define.  If input that
requires floating-point conversion or functions are called that
request floating-point conversion, an error code like @ref
QCBOR_ERR_HW_FLOAT_DISABLED will be returned.


#### `#define USEFULBUF_DISABLE_ALL_FLOAT`

The main purpose of this is to completely elimate dependency
on floating-point:

- The type `double` and `float` are not used.
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

Academically speaking, this reduction of the big number space to the
integer space is not about serialization. It doesn't change the way
big numbers and integers are serialized by themselves.

Note, also that CBOR can encode what can be called "65-big negative
numbers", 64 bits of precision and one bit to indicate the number is negative.
 These can't be represented by 64-bit two's compliment signed
integers or 64-bit unsigned integers. While many programming
environments, like Ruby and Python that have big number support built
in will support these, some environments like C do not. Note also CPU
instructions do not support these directly. QCBOR big number decoding supports them with
explicit code to carry the negative number in as a uint64_t and a sign
indicator. Big number specific preferred serialization requires
encoding of 65-bit negative integers.

## QCBOR APIs

QCBOR supports big numbers in several ways. The big number decoding
APIs are more complex than others in QCBOR because applying the
offset-of-one for negative numbers can increase the size of the big
number, requiring an output buffer — the only place in all of CBOR
where this occurs.

QCBOREncode_AddTBigNumber() and QCBORDecode_GetTBigNumber() are the
most comprehensive and easiest-to-use APIs. They automatically apply
the offset-of-one for negative numbers and reduce to type 0 and 1 for
preferred serialization.

The Raw() APIs do little more than handle tag numbers, serving mostly
as inline wrappers around byte string handling. When using these, the
offset-of-one for negative numbers must be applied manually. This is
straightforward if values are passed to a big number math library, and
in that case the Raw() functions may be more efficient and produce
less object code than QCBORDecode_GetTBigNumber(). Note that
QCBORDecode_GetTBigNumber() requires an output buffer, whereas
QCBORDecode_GetTBigNumberRaw() does not.

QCBOREncode_AddTBigNumberNoPreferred() and
QCBORDecode_GetTBigNumberNoPreferred() apply the offset-of-one but
process the range from -(2^64) to (2^64)−1 as big numbers rather than
as type 0 and 1 integers.

QCBORDecode_VGetNext() can also decode big numbers, provided the tag
handling callback QCBORDecode_StringsTagCB() has been configured. It
returns a @ref QCBORItem of type @ref QCBOR_TYPE_POSBIGNUM or
@ref QCBOR_TYPE_NEGBIGNUM — analogous to
QCBORDecode_GetTBigNumberRaw() — without the offset-of-one
applied. QCBORDecode_StringsTagCB() is lightweight and contributes
little object code.

Items returned by QCBORDecode_VGetNext() can in turn be fully
processed with QCBORDecode_ProcessBigNumber(), which applies the
offset-of-one (and therefore requires an output buffer), recognizes
type 0 and 1 integers and converts them to big number representation,
and can verify conformance with preferred serialization. It does,
however, pull in a significant amount of object code. The reason big
number processing via QCBORDecode_VGetNext() is split into two steps —
unlike other tags — is precisely this output buffer requirement and
the object code cost of full processing.

Finally, many other QCBOR number-decoding APIs can decode and convert
big numbers. For example, QCBORDecode_GetDoubleConvertAll() can
convert big numbers to double-precision floats, and
QCBORDecode_GetTDecimalFractionBigMantissa() returns a decimal
fraction's mantissa as a big number. All of these handle the
offset-of-one and preferred serialization unless their name ends in
Raw().


### APIs Overview

The following tables list all the functions that encode and decode 
big numbers in some way or another.

The columns in the table are as follows:

<dl>
  <dt>Tag & Type</dt>
  <dd>Outputs / Checks the tag number and CBOR major type.</dd>
  
  <dt>Offset</dt>
  <dd>Handles the offset-of-1 for negative numbers. These decode functions 
  require an output buffer because the output size may increase. Decoding 
  ignores leading zeros and the empty string has the value 0.

  When big number conformace checking is on, 
  @ref QCBOR_DECODE_MODE_ONLY_PREFERRED_BIG_NUMBERS, decoding errors out
  on leading zeros or empty string.</dd>

  <dt>Integer Unification</dt>
  <dd>This is the preferred serialization unificaton of big numbers
  with type 0 and 1 integers. Values in the range of type 0 and 1 are encoded
  as type 0 and 1, not big numbers.

  When big number conformance checking is on,
  @ref QCBOR_DECODE_MODE_ONLY_PREFERRED_BIG_NUMBERS, decoding errors out if
  unification is not performed.e</dd>
  
  <dt>Size</dt>
  <dd>A rough characterization of size of the object code linked.</dd>
</dl>

The cell indicators are as follows:

<dl>
  <dt>X</dt>
  <dd>Directly handles unification with type 0 and 1</dd>
  <dt>x</dt>
  <dd>Type 0 and 1 are handled because of the tag definition, but because of
  preferred serialization requirement, conformance of big numbers is
  still checked.</dd>
</dl>

#### Encoding

| Function                                        | Tag & Type | Offset | Unification | Size  |
| :---------------------------------------------- | :--------: | :----: | :---------: | :---- |
| QCBOREncode_AddTBigNumber()                     |    X       |    X   |      X      | Large |
| QCBOREncode_AddTBigNumberNoPreferred()          |    X       |    X   |             | Large | TODO: 
| QCBOREncode_AddTBigNumberRaw()                  |    X       |        |             | Small |
| QCBOREncode_AddTDecimalFractionBigMantissa()    |    X       |    X   |      x      | Large |
| QCBOREncode_AddTDecimalFractionBigMantissaRaw() |    X       |        |      x      | Med   |
| QCBOREncode_AddTBigFloatBigMantissa()           |    X       |    X   |      x      | Large |
| QCBOREncode_AddTBigFloatBigMantissaRaw()        |    X       |        |      x      | Med   |

#### Decoding

| Function                                        | Tag & Type | Offset | Unification | Size  |
| :---------------------------------------------- | :--------: | :----: | :---------: | :---- |
| QCBORDecode_GetTBigNumber()                     |    X       |    X   |      X      | Large |
| QCBORDecode_ProcessBigNumber()                  |    X       |    X   |      X      | Large |
| QCBORDecode_GetTBigNumberRaw()                  |    X       |        |             | Small |
| QCBORDecode_StringsTagCB() / VGetNext()         |    X       |        |             | Small |
| QCBORDecode_GetInt64ConvertAll()                |    X       |    X   |      x      | Large |
| QCBORDecode_GetUInt64ConvertAll()               |    X       |    X   |      x      | Large |
| QCBORDecode_GetDoubleConvertAll()               |    X       |    X   |      x      | Large |
| QCBORDecode_GetTDecimalFractionBigMantissa()    |    X       |    X   |      x      | Large |
| QCBORDecode_GetTBigFloatBigMantissa()           |    X       |    X   |      x      | Large |
| QCBORDecode_GetTDecimalFractionBigMantissaRaw() |    X       |        |      x      | Large |
| QCBORDecode_GetTBigFloatBigMantissaRaw()        |    X       |        |      x      | Large |

TODO: measure code size accurately for the above functions

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

## Backwards Compatibility with QCBOR v1

QCBOR v1 supports only the minimal pass through processing of big
numbers, not the offset of one for negative values or the big number
specific preferred serialization. The main functions in v1 are
QCBOREncode_AddTPositiveBignum(), QCBOREncode_AddTNegativeBignum() and
QCBORDecode_GetBignum(). These are equivalent to
QCBOREncode_AddTBigNumberRaw() and QCBORDecode_GetTBigNumberRaw().

Also, in v1 @ref CBOR_TAG_POS_BIGNUM and @ref CBOR_TAG_NEG_BIGNUM are
always processed into a @ref QCBORItem of type @ref QCBOR_TYPE_POSBIGNUM
and @ref QCBOR_TYPE_NEGBIGNUM by an equivalent of QCBORDecode_StringsTagCB.

All the v1 methods for big numbers such as
QCBOREncode_AddTPositiveBignum() and QCBORDecode_GetBignum() are fully
supported in v2. When QCBORDecode_StringsTagCB() is installed for tags
2 and 3 such as by calling QCBORDecode_CompatibilityV1(), QCBOR v2 big
number behavior is 100% backwards compatible.
 
