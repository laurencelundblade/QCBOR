@page Serialization Serialization and Determinism

# Serialization

## Introduction

For most uses of QCBOR, serialization and determinism are not
something you need to think about. The main QCBOR encoding APIs
produce what is known as "preferred-plus" serialization. This is the
recommended serialization, and it is nearly identical to its
predecessor, preferred serialization, which is widely used throughout
the CBOR ecosystem. See
[draft-ietf-cbor-serialization](https://www.ietf.org/archive/id/draft-ietf-cbor-serialization-12.html).

By default, QCBOR fully decodes preferred-plus and deterministic serialization
with no configuration required.

QCBOR also has encoding APIs that produce serializations other than
preferred-plus, such as QCBOREncode_AddDoubleRaw() and
QCBOREncode_OpenArrayIndefiniteLength(). By default, calling these
does not cause an error. To be sure you don't call one by accident,
configure @ref QCBOR_ENCODE_CONFIG_PREFERRED_PLUS. With it set, any
encoding API call that would produce something other than
preferred-plus serialization results in an error.

All examples of encoded CBOR in this section are shown in hex.


## Serialization Variations

CBOR allows variation in serialization to accommodate use cases such
as constrained environments. This section describes each variation,
what it is good for and how QCBOR supports it.

The APIs listed are examples, not the full set that QCBOR provides
for each serialization option.

### Shortest-Length CBOR Argument

The CBOR argument is the integer in the head of every data item. It
holds the length of strings, arrays and maps, and the value of
simple values, tag numbers and integers.

With shortest-length encoding, values 0–23 are encoded in the
initial byte itself, 24–255 take 2 bytes, 256–65535 take 3 bytes,
values up to 2^32 - 1 take 5 bytes and larger values take 9 bytes.

Shortest length is preferred because it reduces size, but sometimes a
fixed length (e.g., always 64 bits) is better because the value can
be updated in place without moving the rest of the encoded output.

QCBOR always encodes the shortest form, no matter which API is used.
There are no APIs for the fixed-length form. QCBOR decodes arguments
of any length.

|                           | Shortest Form   | Fixed-Length Form                                         |
|---------------------------|-----------------|-----------------------------------------------------------|
| Encoding                  | Always used     | Not supported                                             |
| Decoding                  | Supported       | Supported                                                 |
| Example: integer 3        | 0x03            | 0x1803, 0x190003, 0x1a00000003, 0x1b0000000000000003      |
| Example: integer 1000000  | 0x1a000f4240    | 0x1b00000000000f4240                                      |
| Example: text "ABC"       | 0x63414243      | 0x7803414243, 0x790003414243                              |


### Shortest-Length Floating-Point

CBOR can reduce the encoded size of a floating-point value from
double precision to single or half precision when no precision is
lost. This is the normal behavior in QCBOR: QCBOREncode_AddDouble()
reduces to single or half precision, and QCBOREncode_AddFloat()
reduces to half precision, whenever the value is exactly
representable in the smaller size.

"Raw" functions are provided to encode floats with no reduction in
precision. They always output the size of the type passed in.

When decoding, all sizes are converted to the type returned by
the decoding API, so the same decode function works for both.

|                     | Shortest Form                                   | Raw Encoding                                          |
|---------------------|-------------------------------------------------|-------------------------------------------------------|
| Encoding            | QCBOREncode_AddDouble(), QCBOREncode_AddFloat() | QCBOREncode_AddDoubleRaw(), QCBOREncode_AddFloatRaw() |
| Decoding            | QCBORDecode_GetDouble()                         | QCBORDecode_GetDouble()                               |
| Example: -2.0       | 0xf9c000                                        | 0xfbc000000000000000 (double), 0xfac0000000 (float)   |
| Example: 100000.0   | 0xfa47c35000                                    | 0xfb40f86a0000000000                                  |
| Example: 0.1        | 0xfb3fb999999999999a (cannot be reduced)        | 0xfb3fb999999999999a                                  |
| Example: NaN        | 0xf97e00                                        | 0xfb7ff8000000000000 (double), 0xfa7fc00000 (float)   |


### Definite- and Indefinite-Length Strings

Text and byte strings can be encoded either as a single
definite-length string or as a series of string chunks. A
definite-length string is made up of a length followed by the bytes
of the string, so the length must be known when encoding starts.

An indefinite-length string has an opening indicator, a series of
string chunks (each a definite-length string) and a break that marks
the end. This allows encoding a string whose length is not known when
encoding starts.

Decoding indefinite-length strings requires a memory pool, set up
with QCBORDecode_SetMemPool(), so the chunks can be joined into one
contiguous string.

|                  | Definite-Length              | Indefinite-Length                                                                                          |
|------------------|------------------------------|------------------------------------------------------------------------------------------------------------|
| Encoding         | QCBOREncode_AddText()        | QCBOREncode_OpenIndefiniteLengthText(), QCBOREncode_AddIndefiniteLengthTextChunk(), QCBOREncode_CloseIndefiniteLengthText() |
| Decoding         | QCBORDecode_GetTextString()  | QCBORDecode_SetMemPool(), QCBORDecode_GetTextString()                                                      |
| Example: "ABC"   | 0x63414243                   | 0x7f6141624243ff (chunks "A" and "BC")                                                                     |


### Definite- and Indefinite-Length Arrays and Maps

For definite-length arrays and maps, the number of items must be
known at the start of encoding, either by being given up front or, as
QCBOR does, by going back and filling it in when the array or map is
closed. Indefinite-length arrays and maps instead end with a break,
so the number of items never needs to be known.

QCBOREncode_OpenFlowedMap() opens an indefinite-length map when
passed @c SIZE_MAX as the length. QCBOREncode_OpenMapIndefiniteLength()
does the same. Arrays have the corresponding functions.

QCBOR decodes indefinite-length arrays and maps the same way as
definite-length ones, with no extra setup.

|                  | Definite-Length                                 | Indefinite-Length                                                   |
|------------------|-------------------------------------------------|---------------------------------------------------------------------|
| Encoding         | QCBOREncode_OpenMap(), QCBOREncode_CloseMap()   | QCBOREncode_OpenFlowedMap() with @c SIZE_MAX, QCBOREncode_CloseFlowedMap() |
| Decoding         | QCBORDecode_EnterMap()                          | QCBORDecode_EnterMap()                                              |
| Example: [1, 2]  | 0x820102                                        | 0x9f0102ff                                                          |
| Example: {1: 2}  | 0xa10102                                        | 0xbf0102ff                                                          |


### Big Numbers

Preferred serialization of big numbers unifies the integer number
space of big numbers (tags 2 and 3) with that of major types 0 and 1.
That is, an integer that can be encoded with major type 0 or 1 is
never encoded as a big number. In this mode there is no distinction
between a big number and a major type 0 or 1 integer.

Without unification, a big number is always encoded as tag 2 or 3,
however small its value.

|                     | Unified with Integers         | Not Unified                                                         |
|---------------------|-------------------------------|---------------------------------------------------------------------|
| Encoding            | QCBOREncode_AddTBigNumber()   | QCBOREncode_AddTBigNumberNoPreferred(), QCBOREncode_AddTBigNumberRaw() |
| Decoding            | QCBORDecode_GetTBigNumber()   | QCBORDecode_GetTBigNumberNoPreferred(), QCBORDecode_GetTBigNumberRaw() |
| Example: 1          | 0x01                          | 0xc24101                                                            |
| Example: 2^64       | 0xc249010000000000000000      | 0xc249010000000000000000                                            |

Note that 2^64 is too large for major type 0, so it is a big number
in both forms.


## Deterministic Encoding

QCBOR implements the deterministic encoding defined in
draft-ietf-cbor-serialization. It is the same as section 4.2.1 of
RFC 8949, except that NaN payloads are not allowed.

Deterministic serialization can be used anywhere preferred-plus can
be used, but it is usually not necessary. In some cases (only some)
involving signing or hashing, it is absolutely necessary.

The only difference between preferred-plus and deterministic
serialization is that map entries are sorted by key. If no maps are
used, the two are the same. Configuring @ref QCBOR_ENCODE_CONFIG_SORT
causes maps to be sorted automatically. This makes closing a map
slower, but that is probably only noticeable with big maps on a very
slow CPU.

For example, the map {"b": 1, "a": 2} is encoded as follows:

|                        | Encoded CBOR        |
|------------------------|---------------------|
| Preferred-plus         | 0xa2616201616102    |
| Deterministic (sorted) | 0xa2616102616201    |

@ref QCBOR_ENCODE_CONFIG_DETERMINISTIC sorts maps and also causes an
error if any non-deterministic encoding API is called.

Decoding deterministic serialization is the same as decoding any
other serialization.


## Serialization Conformance Checking

QCBOR supports full serialization conformance checking during
decoding. The conformance mode is set by passing
@ref QCBOR_DECODE_MODE_PREFERRED_PLUS or
@ref QCBOR_DECODE_MODE_DETERMINISTIC to QCBORDecode_Init(). From then
on, decode as normal. An error occurs if the input CBOR is not
conformant.

Errors occur even for items that are only decoded in passing. For
example, when a map is searched by label, any non-conformant item in
the map (or in any map nested in it) causes an error.
