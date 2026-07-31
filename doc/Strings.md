@page Strings  Byte and Text Strings

This section covers both text strings and byte strings, the encoding
of which mostly differs only in the major type. Both are treated as
opaque blobs of bytes. Text strings in CBOR are always UTF-8 Unicode,
but QCBOR still treats them like an opaque blob.

CBOR strings may be either definite-length or indefinite-length. A
definite-length string is encoded as the length, then the bytes in the
string.  An indefinite-length string is encoded as an opening item
that indicates it is an indefinite-length string, then a series of
definite-length strings, and finally a terminating "break".

Definite-length strings are generally preferred because they are
easier to decode -- a pointer and length into the encoded CBOR can
just be returned. Indefinite-length strings have to be reassembled in
an allocated buffer. Some decoders don't support them or, like QCBOR,
need special setup.

Indefinite-length strings, however, have a big advantage as they can
be used to stream a very long string, much larger than available
memory, on a constrained device.


# String Encoding

This is a tour of QCBOR's string encoding features, particularly
strings that don't fit in a single buffer.

## Encoding a simple string

In the very common simple case, the string is of known length and
exists in a single buffer. It also probably fits in the fixed-length
output buffer that holds the entire encoded output and doesn't create
a requirement for streaming or segmenting. Use these APIs:

- QCBOREncode_AddBytes()
- QCBOREncode_AddText()
- QCBOREncode_AddSZString()
    
If the encoder is in streaming mode, presumably for reasons other than
a simple string, you can gain efficiency from reduced copying with:
    
- QCBOREncode_AddStreamedBytes()
- QCBOREncode_AddStreamedText()

If you want to obtain a buffer to pass to some function so it can
write a definite-length string directly into the output buffer,
avoiding a temporary buffer, use:

- QCBOREncode_OpenBytes()
- QCBOREncode_OpenSizedBytes()

This is useful for having a signing operation write the signature
directly to the encoded output, or better yet for having an encryption
operation write the ciphertext directly to the encoded output.
    
## Encoding a string that is in segments

Here, the string exists in segments, not in a single buffer. Its
length may or may not be known when encoding starts. It is probably
constructed on the fly, one segment at a time — for example, the
output of block-by-block AES encryption. Segmenting might also be used
to avoid allocating big blocks of memory.

### String fits in the output buffer

In this case, even though the string is in segments, it fits in the
output buffer. Streaming is not needed. QCBOR can encode such a
segmented string as a definite-length string with these:

- QCBOREncode_OpenSizedBytes()
- QCBOREncode_OpenBytes()
 
QCBOR can also encode this as an indefinite-length string, but that is
generally not preferable because it is harder to decode and some
receivers can't. Use these APIs:

- QCBOREncode_OpenIndefiniteLengthBytes()
- QCBOREncode_OpenIndefiniteLengthText()

#### Byte string wrapping

Some protocols require subordinate chunks of encoded CBOR to be
wrapped in a byte string — for example, when signing encoded CBOR or
embedding one CBOR protocol in another. QCBOR has a special API for
this, where the byte string is opened analogously to opening an
array. Each item in the wrapped CBOR is encoded on the fly, similar to
adding items to an array:

- QCBOREncode_BstrWrap()

### Streaming -- the string doesn't fit in the output buffer

Sometimes the entire completed string does not fit in the output
buffer, and full streaming (see QCBOREncode_SetStream()) is
required. The string never exists contiguously in memory; it only
exists on the wire in the encoded output.

QCBOR supports indefinite lengths for this use case:

- QCBOREncode_OpenIndefiniteLengthBytes()

If the length is known in advance, a definite-length byte string can be
output in streaming mode with:

- QCBOREncode_OpenSizedBytes()

## Internal Encoding Efficiency

Most QCBOR string encoding is internally simple and efficient: the
CBOR head with the length is encoded, and then the bytes are
encoded. These APIs operate differently because they output
definite-length strings without knowing the string length until it is
complete:

- QCBOREncode_BstrWrap()
- QCBOREncode_OpenBytes()

When these "open" methods are called, QCBOR internally records the
byte offset for the CBOR head but doesn't output it. When their
corresponding "close" methods are called, they go back and insert the
head. This is less efficient because all the bytes in the string have
to be moved.


## What is not supported

Streaming definite-length strings when the length is not known is not
supported, because it is impossible to support.

The following are not supported, but could be:

- Writing indefinite-length strings directly to the output buffer in
  streaming mode.
- Writing definite-length segments directly to the output buffer in
  streaming mode (when the full length of the string is known at the
  start).
- Many text-string functions that exist for byte strings but have no
  text-string counterpart.
- Byte-string wrapping with indefinite lengths.
- Byte-string wrapping in streaming mode.

## String Map Labels

QCBOR has extensive direct support for text string map labels
via functions of the form QCBOREncode_AddXxxxToMapSZ. It's the
"SZ" at the end that indicates a text string label. These
functions all take a NULL-terminated string for convenience.
They are encoded as a definite-length string.

It is possible to use byte strings as map labels by making
two calls, one to encode the label and the other to encode
the data. For example to encode a an integer map item with
a byte string label call these two in sequence:

- QCBOREncode_AddBytes()
- QCBOREncode_AddInt64()

A map label of any type can be encoded this way. QCBOR only
supports QCBOREncode_AddXxxxToMap style functions for string 
and integer labels because they are most common and supporting
all label types would result in a large function fan out.


# String Decoding

QCBOR does no streaming decoding. Strings are always decoded into a
single contiguous buffer, so all strings must fit in memory.

## Definite-length strings

The string decode APIs simply return a @ref UsefulBufC (a pointer and
length):

- QCBORDecode_VGetNext()
- QCBORDecode_GetItemsInMap()
- QCBORDecode_GetByteString()
- QCBORDecode_GetTextString()

The first two APIs get items of any type, so you must check that the
item returned is the type of string expected. Normally, what is
returned is a pointer into the original encoded CBOR, but if a string
allocator is configured with QCBORDecode_SetMemPool() or
QCBORDecode_SetUpAllocator() and bAllStrings is true, strings are
copied into allocated buffers.

## Indefinite-length strings

The decode APIs for indefinite-length strings are exactly the same as
for definite-length strings. Indefinite-length strings are reassembled
into a single contiguous buffer. To do this, QCBOR needs to allocate
memory, so a memory allocation must be set up. See:

 - QCBORDecode_SetMemPool() 
 - QCBORDecode_SetUpAllocator()


## Byte-string wrapped CBOR

Byte-string wrapped CBOR can be decoded like any other byte string and
fed into another instance of the decoder. This works on
indefinite-length byte strings. It has the disadvantage of needing
another instance of the decoder (which costs about 400 bytes).

It can also be "opened" and the items inside decoded with the same
decoder instance, analogously to opening an array:

- QCBORDecode_EnterBstrWrapped()

Nested wrapping is supported. Entering ("opening") indefinite-length
wrapped byte strings is not supported.
