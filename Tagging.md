#  Types and Tagging in CBOR

## New Types

CBOR provides a means for defining new data types that are either 
aggregates of the primitive types or the association of further sematics
to a primitive type. 

An aggregate is similar to a C structure. A bigfloat is an example. It
is an array of two data items, an exponent and a mantissa. 

An example of association of further semantics to a primitive type
is an epoch date, where the new data type is 
a primitive integer that is to be interpreted as a date.

## Explicit Tags

These new types can be explicitly tagged by preceding them
with a CBOR Item of major type 6. The tag data item is a positive
integer. 

For example the epoch date looks lie this:


A big float looks like this:


The data item tagged is known as the tag content. Most tags
require the content to be of a specific type or types. A few work
with content of any type.

There may be more than one explicit tag for a single tag content. When
this is done, they nest. The order of the explicit tags is significant. The explicit
tag closes to the content is applied first. That then becomes the 
content for the next closest tag.

If the content for a specific tag is not of the right type then
the encoded CBOR is invalid.

The explicit tag data item is not always required when the data type is used. In some situations
in some CBOR protocols, they may actually be prohibited.

## Standard Tags and the Tags Registry

Tags used in CBOR protocols should at least be registered in 
the IANA CBOR Tags Registry. A small number of tags (0-23),
are full IETF standards. Further, tags 24-255 require published
documentation, but are not full IETF standards. Beyond
tag 255, the tags are first come first served. 

There is no range for private use, so any tag used in a
CBOR protocol should be registered. The range of tag
values is very large to accommodate this.

It is common to use  data types from the registry in a CBOR protocol
without the explicit tag, so in a way the registry is a registry
of data types.

## When Explicit Tags are Required

In many CBOR protocols, the new type of a data item
can be known implicitly without any explicit type. In that
case the explicit tag is redundant. For example,
if a data item in a map is labled the "expiration date", 
it can be inferred that the type is a date.

All CBOR protocols that use registered data types
should explicitly say for each occurance whether
the explicit tag is required or not. If they say it is required,
it must always be present and it is a protocol decoding
error if not. Usually the tag is explicitly required because
it is not possible to infer the type from the context
of the protocol. 

If the protocol says the explicit tag is not required, it
is a decoding error if it is present.

That is tags are not optional in a protocol (even though they
were called "optional tags" in RFC 7049).

Part of the result of this is that unknown tags generally
can't be ignored during decoding. They are not like
email or HTTP headers.

The QCBOR encoding API for standard registered types
has an option to include the tag or not. Setting this
flag depends on the protocol definition and should only
be true if the protocol requires explicit tagging.

The QCBOR decoding APIs for standard registered types
has a tag requirements flag. If true it requires the tag
to be present and sets an error if it is absent. If false
an error is set if it is present.

During decoding, it will sometimes be necessary to 
peek-decode the data item with the generic PeekNext()
first to know its type, then call the appropriate GetXxxx(0
to actually dcode and consume it. When this is necessary
depends on the design and flow of the protocol.



