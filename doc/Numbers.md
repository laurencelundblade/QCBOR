
@file Numbers.md

@anchor BigNumbers

#  Big Numbers

## Basics

Big numbers are integers that can be as long and as large as desired, 
limited only by the amount of memory allocated for them.

They are represented as a byte string plus an indication of sign.
The most significant byte is first (network byte order).

CBOR has only one representation of zero for integers, big numbers included.
That means the whole negative number space is offset by one.
Since big numbers are encoded as a sign and some bytes, the steps
to encode a negative value are to take the absolute value and then 
adjust by one. On encoding, the adjustment is to subtract one
from the absolute value, and on decoding to add one to the absolute
value.

Take -256 as an example. It is represented in memory with two
bytes, 0x01, 0x00, plus some indication, perhaps a boolean, that 
it is negative. When it is CBOR-encoded it becomes 0xff
plus an indication of the sign.

Notice that the length changed. This is one place in the
design of CBOR where the bytes off the wire cannot be
simply used as they are. This has a big effect on the
big number encoding and decoding APIs.

The tag numbers 2 and 3 indicate a big number. The tag content
is a byte string with the absolute value of the big number,
offset by one when negative. Tag number 2 indicates positive
and 3 negative.

For example, 256 encoded as a positive big number is 0xc2, 0x42, 0x01, 0x00
and -256 encodes as 0xc3, 0x41, 0xff.


## Preferred Serialization

The integer number space encodable by big numbers overlaps
with the number space encodable by regular integers, by
CBOR type 0 and type 1, the range from -(2^64) to 
(2^64)-1.

RFC 8949 preferred serialization requires that numbers in
the type 0 and 1 integer range must not be encoded as
big numbers. They must be encoded as type 0 and type
1 integers.

For example, 256 must always be encoded as 0x19 0x01 0x00 and -256 as 0x38 0xff.

One purpose of this is to save some bytes, but typically only 
one byte is saved. The more important reason for this is determinism.
There is only one way to represent a particular value.

Technically speaking, this reduction of the big number space
to the integer space is not about serialization. It doesn't
change the way big numbers and integers are serialized by
themselves. See big number editorial comments below.

Note, also that CBOR can encode what can be called
"65-big negative numbers", 64 bits of precission and
one bit to indicate a negative one. These can't be represented
by 64-bit two's compliment signed integers or 64-bit 
unsigned integer. While many programming environments, particularly
those like Ruby and Python that have big number support built 
in will support these some very embedded environments may not.
QCBOR big number decoding suports them with explicit code to
carry the negative number in as a uint64_t and a sign indicator.
Preferred serialization requires encoding of 65-bit
negative integers. 
Other than big numbers QCBOR generally avoids 65-big negative
integers.

## QCBOR APIs

The negative number offset of one and the reduction required by
preferred serialization have a large effect on the QCBOR 
implementation and number-related APIs.

QCBOREncode_AddTBigNumber() and QCBORDecode_GetTBigNumber() 
TODO: improve writing
are the easiest in a way. The API input and output are exactly
the representations you would expect. They conform with
preferred serialization like most QCBOR APIs. Do note
that QCBORDecode_GetTBigNumber() requires that a buffer
be passed to receive the decoded big number. The caller 
has to anticipate the maximum size of this. This is unlike
just about every other decode API in QCBOR.

If the protocol being implemented does use preferred
serialization, then QCBOREncode_AddTBigNumberNoPreferred() and QCBORDecode_GetTBigNumberNoPreferred()
can be used. Only tags 2 and 3 will be output when encoding.
Type 0 and 1 integers will never be output. Decoding
will error if type 0 and type 1 integers are encountered.

It is likely that any implementation for a protocol that
uses big numbers will link in a big number library.
When that's it can be used to offset the negative numbers 
by one rather than the internal implementation that QCBOR
has. If both the offset by 1 and the preferred serialization
are side stepped, the big numbers APIs become extremely simple
pass throughs for encoding and decoding byte strings. 
This reduces the amount of object linked from the QCBOR
library by something like 1KB. The
only thing that is of interest is that the tag numbers
tell you the sign.

This is what QCBOREncode_AddTBigNumberRaw() and 
QCBORDecode_GetTBigNumberRaw() do. Note that decoding
doesn't require an output buffer be supplied because the
bytes off the wire can simply be returned. When
these are used, the big number library should be used
to add one to negative numbers before encoding
and subtract one from negative numbers after decoding.

Last, struct QCBORDecode_StringsTagCB() QCBOR_TYPE_POSBIGNUM, QCBOR_TYPE_NEGBIGNUM, and QCBORDecode_ProcessBigNumber()
need to be described. QCBOR's tag processing callbacks can
be used to handle big numbers by installing QCBORDecode_StringsTagCB()
for tag numbers 2 and 3. This will result in postive and negative
big numbers being returned in a QCBORItem as QCBOR types 
QCBOR_TYPE_POSBIGNUM and QCBOR_TYPE_NEGBIGNUM. QCBORDecode_StringsTagCB()
is very simple, and not much object code. Neither the offset
of one for negative values or preferred serializtion number
reduction is preformed. It is equivalent to QCBORDecode_GetTBigNumberRaw().

QCBORDecode_ProcessBigNumber() 
may be used to fully process a QCBORItem that is expected to
be a big number. It will perform the negative offset and handle
the preferred serialization number reduction. QCBORDecode_ProcessBigNumber()
is what is used internally to implemented QCBORDecode_GetTBigNumber() and
does link in a lot of object code. Note that QCBORDecode_ProcessBigNumber()
requires an output buffer be supplied.

QCBORDecode_ProcessBigNumbernoPreferred() is the same as QCBORDecode_ProcessBigNumber()
but will error out if the QCBORItem contains anything but
 QCBOR_TYPE_POSBIGNUM, QCBOR_TYPE_NEGBIGNUM.
 
Note that if  QCBORDecode_StringsTagCB() is installed, QCBORDecode_GetTBigNumber(),
QCBORDecode_GetTBigNumberNoPreferred() and QCBORDecode_GetTBigNumberRaw() all still work
as documented.

## "Borrowed" Big Number Tag Content

Like all other tag decoding functions in QCBOR, the big number
tag decoders can also work with borrowed tag content for big numbers. For example, the value of a map item might be specified that it be
decoded as a big number even though there is no tag number indicating
so.

The main thing to mention here is that without a tag number, there's
nothing in the encoded CBOR to indicate the sign. That must be indicated
some other way. For example, it might be that the map item is defined
that the big number is always positive.

On the encode side, that means the sign boolean is ignored when
QCBOREncode_AddTBigNumber() is called with uTagRequirement other than
@ref ENCODE_TAG.

On the decode side, the sign boolean becomes an input parameter rather
than an output parameter so that QCBORDecode_GetTBigNumber() can 
know whether to apply the offset of 1 in case the value is negative.

## Big Number Conversions

There's a number of decode functions that can convert big numbers to
other representations like floating point. See the various
conversion functions.

Note also that QCBORDecode_ProcessBigNumber() can convert integers 
to big numbers. It will work even if the protocol item is never
supposed to be a big number. It will just happily convert any
type 0 or type 1 CBOR integer to a big number.

## Backwards Compatibility with QCBOR v1



