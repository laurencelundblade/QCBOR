@anchor Overview

# QCBOR Overview

This implements CBOR -- Concise Binary Object Representation as
defined in [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html).
More information is at http://cbor.io.  This is a near-complete
implementation of the specification.
[RFC 8742](https://www.rfc-editor.org/rfc/rfc8742.html) CBOR Sequences is
also supported. Limitations are listed further down.

See @ref Encoding for general discussion on encoding,
@ref BasicDecode for general discussion on the basic decode features
and @ref SpiffyDecode for general discussion on the easier-to-use
decoder functions.

CBOR is intentionally designed to be translatable to JSON, but not
all CBOR can convert to JSON. See RFC 8949 for more info on how to
construct CBOR that is the most JSON friendly.

The memory model for encoding and decoding is that encoded CBOR must
be in a contiguous buffer in memory.  During encoding the caller must
supply an output buffer and if the encoding would go off the end of
the buffer an error is returned.  During decoding the caller supplies
the encoded CBOR in a contiguous buffer and the decoder returns
pointers and lengths into that buffer for strings.

This implementation does not require malloc. All data structures
passed in/out of the APIs can fit on the stack.

Decoding of indefinite-length strings is a special case that requires
a "string allocator" to allocate memory into which the segments of
the string are coalesced. Without this, decoding will error out if an
indefinite-length string is encountered (indefinite-length maps and
arrays do not require the string allocator). A simple string
allocator called MemPool is built-in and will work if supplied with a
block of memory to allocate. The string allocator can optionally use
malloc() or some other custom scheme.

Here are some terms and definitions:

- "Item", "Data Item": An integer or string or such. The basic "thing" that
CBOR is about. An array is an item itself that contains some items.

- "Array": An ordered sequence of items, the same as JSON.

- "Map": A collection of label/value pairs. Each pair is a data
item. A JSON "object" is the same as a CBOR "map".

- "Label": The data item in a pair in a map that names or identifies
the pair, not the value. This implementation refers to it as a
"label".  JSON refers to it as the "name". The CBOR RFC refers to it
this as a "key".  This implementation chooses label instead because
key is too easily confused with a cryptographic key. The COSE
standard, which uses CBOR, has also chosen to use the term "label"
rather than "key" for this same reason.

- "Key": See "Label" above.

- "Tag": A data item that is an explicitly labeled new data
type made up of the tagging integer and the tag content.
See @ref CBORTags.

- "Initial Byte": The first byte of an encoded item. Encoding and
decoding of this byte is taken care of by the implementation.

- "Additional Info": In addition to the major type, all data items
have some other info. This is usually the length of the data but can
be several other things. Encoding and decoding of this is taken care
of by the implementation.

CBOR has two mechanisms for tagging and labeling the data values like
integers and strings. For example, an integer that represents
someone's birthday in epoch seconds since Jan 1, 1970 could be
encoded like this:

- First it is CBOR_MAJOR_TYPE_POSITIVE_INT (@ref QCBOR_TYPE_INT64),
the primitive positive integer.

- Next it has a "tag" @ref CBOR_TAG_DATE_EPOCH indicating the integer
represents a date in the form of the number of seconds since Jan 1,
1970.

- Last it has a string "label" like "BirthDate" indicating the
meaning of the data.

The encoded binary looks like this:

     a1                      # Map of 1 item
        69                   # Indicates text string of 9 bytes
          426972746844617465 # The text "BirthDate"
       c1                    # Tags next integer as epoch date
          1a                 # Indicates a 4-byte integer
              580d4172       # unsigned integer date 1477263730

Implementors using this API will primarily work with
labels. Generally, tags are only needed for making up new data
types. This implementation covers most of the data types defined in
the RFC using tags. It also, allows for the use of custom tags if
necessary.

This implementation explicitly supports labels that are text strings
and integers. Text strings translate nicely into JSON objects and are
very readable.  Integer labels are much less readable but can be very
compact. If they are in the range of 0 to 23, they take up only one
byte.

CBOR allows a label to be any type of data including an array or a
map. It is possible to use this API to construct and parse such
labels, but it is not explicitly supported.

@anchor Limitations

## Limitations

Summary limitations:
- The entire encoded CBOR must fit into contiguous memory.
- Max size of encoded CBOR data is a few bytes less than
  @c UINT32_MAX (4GB).
- Max array / map nesting level when encoding or decoding is
  @ref QCBOR_MAX_ARRAY_NESTING (this is typically 15).
- Max items in an array or map when encoding or decoding is
  @ref QCBOR_MAX_ITEMS_IN_ARRAY (typically 65,536).
- Does not directly support labels in maps other than text strings & integers.
- Traversal, duplicate and sort order checking errors out for labels that are arrays or maps.
- Does not directly support integer labels beyond whats fits in @c int64_t
  or @c uint64_t.
- Epoch dates limited to @c INT64_MAX (+/- 292 billion years).
- Exponents for bigfloats and decimal integers are limited to whats fits in
  @c int64_t.
- Tags on labels are ignored during decoding.
- The maximum tag nesting is @c QCBOR_MAX_TAGS_PER_ITEM (typically 4).
- Works only on 32- and 64-bit CPUs.
- QCBORDecode_EnterBstrWrapped() doesn't work on indefinite-length strings.

The public interface uses @c size_t for all lengths. Internally the
implementation uses 32-bit lengths by design to use less memory and
fit structures on the stack. This limits the encoded CBOR it can
work with to size @c UINT32_MAX (4GB).

This implementation requires two's compliment integers. While
C doesn't require two's compliment, <stdint.h> does. Other
parts of this implementation may also require two's compliment.
 
