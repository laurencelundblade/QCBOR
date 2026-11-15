@page Serialization Serialization and Determinism

## Intro

For the most part the topics of serialization and determinism are
not of consequence to common use. The main APIs in CBOR use
what is known as "preferred-plus" serialization. It is the 
serialization that is recommended and it is widely used in the
CBOR ecosystem.

By default (TODO: should this change?) no error will occur
if you call one of the non-preferred APIs like FloatNoPreferred() or
OpenIndefiniteLenArray(), but you can configured XXX to be 
sure you don't call one by accident. With XXX set, any encoding
API call that produces anything but preferred-plus serialization
will error.

By default the decoder will fully decode preferred-plus serialization
with no configuration required.

## Serialization variation

CBOR is designed to support serialization variation and QCBOR
supports this variation.




To be filled in...

