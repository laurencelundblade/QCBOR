
@anchor CBORTags

#  QCBOR-oriented Introduction to Tags

## New Types

CBOR allows for the definition of new data types beyond basic
primitives like integers and strings. These new types can either be
simple extensions of a primitive type with additional semantics or
more complex structures involving large aggregations.

The mechanism for identifying these new types is called tagging.
Tagging uses a simple unsigned integer to indicate that the following
CBOR item is a different type.

It's important to note that CBOR uses the word "tag" in an unusual
way. In CBOR, a "tag" refers to the combination of the tag number and
the tag content.  By the normal dictionary definition, a "tag" would
be just a tag number, not an aggregation of tag number and tag content
By analogy, if you attach a small label to an elephant's ear, the
"tag" in CBOR terms would be the combination of the label (tag number)
and the elephant (tag content).

QCBOR always uses the terms "tag number" to refer to the integer that
identifies the type, "tag content" to refer to the target of the
indicating integer and "tag" as the full combination of both.

The tag content is always a single data item. However, this item can
itself be a complex structure, such as a map or an array, which may
contain nested maps and arrays, allowing for arbitrarily complex tag
content.

Tag numbers can range up to UINT64_MAX, providing a large number of
possible tags. Some are defined by standards and registered in the
IANA CBOR Tag Registry, while a substantial range is available for
proprietary use.


@anchor AreTagsOptional
## Are Tags "Optional"?

The description of tags in
[RFC 7049](https://tools.ietf.org/html/rfc7049) and in some other
places can lead one to think they are optional prefixes that can be
ignored at times. This is not true.

As stated above, a tag is exactly a tag number and a single data item
that is the tag content. Its purpose in the encoded CBOR is to
indicate something is of a data type. Ignoring it would be like
ignoring a typedef or struct in C.

However, it is common in CBOR-based protocols to use the format,
semantics or definition of the tag content without it actually being a
*tag*. One can think of this as *borrowing* the tag content or implied
type information.

For example, [RFC 8392](https://tools.ietf.org/html/rfc8392) which
defines a CBOR Web Token, a CWT, says that the NumericDate field is
represented as a CBOR numeric date described as tag 1 in the CBOR
standard, but with the tag number 1 omitted from the encoding. A
NumericDate is thus not a tag. It just borrows the content format and
semantics from tag 1.

This borrowing of the content makes a lot of sense for data items that
are labeled members of a map where the type of the data can be easily
inferred by the label and the full use of a tag with a tag number
would be redundant.

There is another way that tags are "optional". RFC 8392 serves again
as an example. A CWT is officially defined as a COSE-secured map
containing a bunch of claims where each claim is a labeled data
item. This COSE-secured map-of-claims is the definition of a *CWT* and
stands on its own as the definition of a protocol message. One can say
that some protocol message is a *CWT* without ever mention the word
tag or the *CWT Tag*.

Then RFC 8392 goes on to define a *CWT Tag* as a tag with tag number
of 61 and tag content being a *CWT*. The content format definition
comes first and stands on it's own.

To recap, the tags defined in RFC 7049 such as the date formats define
the content type of the tag only in the context of the tag itself. To
use the content formats outside of the tag, the content format must be
borrowed.  By contrast some definitions first define the content
format in an independent way, then they define a tag to enclose that
particular content format. A CWT is of the later sort.

Finally, every CBOR protocol should explicitly spell out how it is
using each tag, borrowing tag content and such. If the protocol you
are trying to implement doesn't, ask the designer.  Generally,
protocols designs should not allow for some data item to optional be
either a tag or to be the borrowed tag content.  While allowing this
tag optionality is a form of Postel's law, "be liberal in what you
accept", current wisdom is somewhat the opposite.


## Types and Tags in QCBOR

TODO: bring in AddTagNumber() and GetTagNumber()

QCBOR explicitly supports all the tags standardized in
[RFC 8949](https://tools.ietf.org/html/rfc8949) for dates, big numbers and
such. It has specific APIs and data structures for encoding and
decoding them.

The encode APIs are in @ref inc/qcbor/qcbor_encode_tag.h "qcbor_encode_tag.h".
Their names start with
"QCBOREncode_AddT". Decoding can be done by installing the provided
callbacks, @ref QCBORDecode_TagDecoderTablev1, in which case they get
decoded by QCBORDecode_VGetNext() and appear in a @ref
QCBORItem. Alternative spiffy decode style functions from
@ref inc/qcbor/qcbor_decode_tag.h "qcbor_decode_tag.h" can be called.

These APIs and structures support both the full tag form and the
borrowed content form that is not a tag. An argument of type @ref xxx
and @ref QCBORDecodeTagReq is provided respectively to the tag encode
and decode functions to distinguish between full tags and borrowed
content.

Early versions of QCBOR did not support encoding borrowed content. The
old APIs for dates, big numbers and such are listed as deprecated, but
will continue to be supported. The encode side has functions like
QCBOREncode_AddDateEpoch() rather than
QCBOREncode_AddTDateEpoch(). The tag decode APIs always supported
borrowed content.

When decoding with QCBORDecode_GetNext(), the non-spiffy decode API,
the proper tag form is automatically recognized by the tag number and
decoded into @ref QCBORItem. This decoding API however cannot recognize
borrowed content format. The caller must tell QCBOR when borrowed
content format is expected.

The spiffy decode APIs for the particular tags are the way the caller
tells QCBOR to expect borrowed content format. These spiffy decode
APIs can also decode the proper tag as well. When asked to decode a
proper tag and the input CBOR is not, it is a decode validity
error. These APIs take an argument which says whether to expect the
proper tag or just the borrowed content. They can also be told to
allow either to "be liberal in what you accept", but this is not
recommended.


## Nested Tags

CBOR tags are an enclosing or encapsulating format. When one tag
encloses another, the enclosed tag is the content for the enclosing
tag.

Encoding nested tags is easy with QCBOREncode_AddTagNumber(). Just call it
several times before calling the functions to encode the tag content.

When QCBOR decodes tags it does so by first completely processing the
built-in tags that it knows how to process. It returns that processed
item.

If tags occur that QCBOR doesn't know how to process, it will return
the tag content as a @ref QCBORItem and list the tags that
encapsulate. The caller then has the information it needs to process
tag that QCBOR did not.

Nesting of tags is certainly used in CBOR protocols, but deep nesting
is less common so QCBOR has an implementation limit of 4 levels of tag
encapsulation on some tag content. (This can be increased by changing
QCBOR_MAX_TAGS_PER_ITEM, but it will increase stack memory use by
increasing the size of a QCBORItem).

QCBOR also saves memory by mapping the tag values larger than
UINT16_MAX, so the tags have to fetched through an accessor function.

When decoding with QCBORDecode_GetNext(), the encapsulating tags are
listed in the QCBORItem returned. When decoding with spiffy decoding
functions the tags encapsulating the last-decoded item are saved in
the decode context and have to be fetched with
QCBORDecode_GetNthTagOfLast().


## Tags for Encapsulated CBOR

Tag 24 and 63 deserve special mention. The content of these tags is a
byte string containing encoded CBOR. The content of tag 24 is a single
CBOR data item and the content of tag 63 is a CBOR sequence, more than
one data item. Said another way, with tag 24 you can have deeply
nested complex structures, but the if you do the one data item must be
either a map or an array or a tag that defined to be complex and
nested. With tag 63, the content can be a sequence of integers not
held together in a map or array. Tag 63 is defined in
[RFC 8742](https://tools.ietf.org/html/rfc8742).

The point of encapsulating CBOR this way is often so it can be
cryptographically signed. It works well with off-the-shelf encoders
and decoders to sign and verify CBOR this way because the decoder can
just get the byte string that it needs to hash in a normal way, then
feed the content back into another instance of the CBOR decoder.

It is also a way to break up complex CBOR structures so they can be
decoded in layers. Usually, with CBOR one error will render the whole
structure un-decodable because there is little redundancy in the
encoding. By nesting like this, an error in the wrapped CBOR will not
cause decoding error in the wrapping CBOR.

QCBOR can be asked to treat these two tags as nesting like maps and
arrays are nesting with the spiffy decode
QCBORDecode_EnterBstrWrapped() decoding function.  It is kind of like
entering an array with one item, but with the difference that the end
is defined by the end of the byte string not the end of the array.

These tags work like others in that they can be the proper tag or they
can be the borrowed content. The QCBOR API supports this as any other
tag.

Finally, the payload and protected headers of COSE are worth
mentioning here. Neither are officially tag 24 or 63 though they look
like it and QCBORs decode APIs can be used on them.

The protected headers are a CBOR byte string that always contains
encoded CBOR. It could have been described as tag 24 borrowed content.

The payload is always a byte string, but only sometimes contains
encoded CBOR. It never could have been defined as tag 24. When the
payload is known to contain CBOR, like the case of a CWT, then QCBOR's
QCBORDecode_EnterBstrWrapped() can be used to decode it.


## Tags that Can be Ignored

There are a few specially defined tags that can actually be
ignored. These are the following:

    21 Hint that content should be base64url encoded
    22 Hint that content should be base64 encoded
    23 Hint that content should be base16 encoded
    57799 Tag that serves as a CBOR magic number

The content format for all these tags is that it can be any valid
CBOR. Decoding of these tags doesn't have to check the content format.

Tag 55799 is not really for consumption by the CBOR decoder. Rather it
is for file format checkers and such.  The other tags are just hints
in how to process the content. They don't really create new data types
with new semantics.

Other than these four, just about every other tag defined thus far
requires the content to be of a specific type and results in a new
data type that a protocol decoder must understand.


## Standard Tags and the Tags Registry

Tags used in CBOR protocols should at least be registered in the
[IANA CBOR Tags Registry](https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml).
A small number of tags (0-23), must be full IETF standards. Tags
24-255 require published documentation. Beyond tag 255, the tags are
first come first served.  Any tag can be an IETF standard if the
authors chooses to take it through the process.

There is no range for private use, so any tag used in a CBOR protocol
should be registered. The range of tag values is very large to
accommodate this.

As described above, it is common to use data types from the registry
in a CBOR protocol without the explicit tag, to borrow the content, so
in a way the IANA registry is a registry of data types.


## See Also

See @ref Tags-Overview and @ref Tag-Usage.

