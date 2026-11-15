@page Serialization Serialization and Determinism

## Intro

For the most part the topics of serialization and determinism are
not of consequence to common use. The main APIs in CBOR use
what is known as "preferred-plus" serialization. It is the 
serialization that is recommended and it is widely used in the
CBOR ecosystem. See https://www.ietf.org/archive/id/draft-ietf-cbor-serialization-12.html

By default no error will occur
if you call one of the non-preferred APIs like QCBOREncode_AddDoubleRaw() or
QCBOREncode_OpenArrayIndefiniteLength(), but you can configure @ref QCBOR_ENCODE_CONFIG_PREFERRED_PLUS to be 
sure you don't call one by accident. With @ref QCBOR_ENCODE_CONFIG_PREFERRED_PLUS set, any encoding
API call that produces anything but preferred-plus serialization
will error.

By default the decoder will fully decode preferred-plus serialization
with no configuration required.

## Serialization variation

CBOR is designed to support serialization variation and QCBOR
supports this variation.


To be filled in...


## Serialization Conformance Checking

QCBOR supports full serialization conformance checking during decode.
The conformance mode is set by passing @ref QCBOR_DECODE_MODE_PREFERRED_PLUS 
or @ref QCBOR_DECODE_MODE_DETERMINISTIC to QCBORDecode_Init(). From
then on, decode normally. Errors will occur if the input
CBOR is not conformant. Note that errors will occur
even for items decoded in passing. For example when 
a map is being searched by label, every item in the map
(and subordinate maps) must be conformant. 
