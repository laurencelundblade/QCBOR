
![QCBOR Logo](https://github.com/laurencelundblade/qdv/blob/master/logo.png?raw=true)

## QCBOR 2.0 Alpha

This is a QCBOR 2.0 alpha release. It is suitable for test and prototyping,
but not commerical use. The planned 2.0 changes are in, but they are
not fully tested or documented. The interface is also subject to change.

QCBOR 2.0 is compatible with 1.0 with one exception that can be overriden
with a call to QCBORDecode_Compatibilityv1().

Please file issues found with this release in GitHub.

### Major Changes

* Unexpected tag numbers are not silently ignored unless in v1 compatibility
mode. This is more correct decoding behavior.

* New API to explicitly decode tag numbers to make tag numbers easier to
work with.

* Plug-in API scheme for custom tag content processors.

* Streamed encoding mode -- encoded output doesn't have to fit in one buffer

* Indefinite-length string encoding

* Sort maps and check for duplicate labels when encoding.

* Encode modes for dCBOR, deterministic and preferred serialization.

* Decode modes that check for conformance with dCBOR, deterministic and preferred serialization.

* Full support for preferred serialization of big numbers, decimal fractions and big numbers.

* Full support for 65-bit negative integers.

* The decoding interface is split into four files (sources files are too).

### Compatibility with QCBOR v1

QCBOR v1 does not error out when a tag number occurs where it is not
expected. QCBOR v2 does. Tag numbers really do change the type of an
item, so it is more correct to error out.

For many protocols, the v2 behavior produces a more correct implementation,
so it is often better to not return to QCBOR v1 behavior.

Another difference is that the tag content decoders for big numbers,
big floats, URIs and such are not enabled by default. These are
what notices the things like the big number and big float tags,
decodes them and turns them into QCBOR types for big numbers and floats.

QCBORDecode_Compatibilityv1() disables the error out on unprocessed
tag numbers and installs the same tag content decoders that v1 had.

The tag number decoders can be installed with the retention of
erroring out on unprocessed tag numbers by calling
QCBORDecode_InstallTagDecoders(pMe, QCBORDecode_TagDecoderTablev1, NULL);

QCBOR v2 requires tag numbers to be consumed in one of three ways.
It may be consumed explicitly with QCBORDecode_VGetNextTagNumber().
It may be consumed by a tag content process or like QCBORDecode_DateEpochTagCB()
installed with QCBORDecode_InstallTagDecoders(). It may be
consumed with a spiffy decode function like QCBORDecode_GetTBigNumber().

## Manifesto

* Maximal set of CBOR features with mininum object code
* Implement everything in RFC 8949 and some other CBOR RFCs
* Very small object code for very simple protocols
* Rich feature set to support complex CBOR protocol stacks 
* Small simple memory use model without malloc()
* Clear, fully documented public interface
* Commercial quality test coverage and secure coding 
* Minimal dependency — C99 and a few standard library functions
* Works out of the box without configuration
* #ifdefs only optimize and disable features for constrained environments

## Standards

* [RFC8949](https://tools.ietf.org/html/rfc8949) The CBOR Standard. (Nearly everything
except full (complex) duplicate detection))
* [RFC7049](https://tools.ietf.org/html/rfc7049) The previous CBOR standard.
Replaced by RFC 8949.
* [RFC8742](https://tools.ietf.org/html/rfc8742) CBOR Sequences
* [RFC8943](https://tools.ietf.org/html/rfc8943) CBOR Dates
* [dCBOR](https://www.ietf.org/archive/id/draft-mcnally-deterministic-cbor-11.html) "dCBOR, deterministic encoding"

## Dependency
* C99 or C++11
* <stdint.h>, <stddef.h>, <stdbool.h> and <string.h>
* <math.h> and <fenv.h> but can be excluded

## Documentation

Full API documentation is at https://www.securitytheory.com/qcbor-docs/

## Comparison to TinyCBOR

TinyCBOR is a popular widely used implementation. Like QCBOR,
it is a solid, well-maintained commercial quality implementation. This
section is for folks trying to understand the difference in
the approach between QCBOR and TinyCBOR.

TinyCBOR's API is more minimalist and closer to the CBOR
encoding mechanics than QCBOR's. QCBOR's API is at a somewhat higher
level of abstraction.

QCBOR really does implement just about everything described in
RFC 8949.  TinyCBOR implements a smaller part of the standard.

No detailed code size comparison has been made, but in a spot check
that encodes and decodes a single integer shows QCBOR about 25%
larger.  QCBOR encoding is actually smaller, but QCBOR decoding is
larger. This includes the code to call the library, which is about the
same for both libraries, and the code linked from the libraries. QCBOR
is a bit more powerful, so you get value for the extra code brought
in, especially when decoding more complex protocols.

QCBOR tracks encoding and decoding errors internally so the caller
doesn't have to check the return code of every call to an encode or
decode function. In many cases the error check is only needed as the
last step or an encode or decode. TinyCBOR requires an error check on
each call.

QCBOR provides a substantial feature that allows searching for data
items in a map by label. It works for integer and text string labels
(and at some point byte-string labels). This includes detection of
items with duplicate labels. This makes the code for decoding CBOR
simpler, similar to the encoding code and easier to read. TinyCBOR
supports search by string, but no integer, nor duplicate detection.

QCBOR provides explicit support many of the registered CBOR tags. For
example, QCBOR supports big numbers and decimal fractions including
their conversion to floats, uint64_t and such.

Generally, QCBOR supports safe conversion of most CBOR number formats
into number formats supported in C. For example, a data item can be
fetched and converted to a C uint64_t whether the input CBOR is an
unsigned 64-bit integer, signed 64-bit integer, floating-point number,
big number, decimal fraction or a big float. The conversion is
performed with full proper error detection of overflow and underflow.

QCBOR has a special feature for decoding byte-string wrapped CBOR. It
treats this similar to entering an array with one item. This is
particularly use for CBOR protocols like COSE that make use of
byte-string wrapping.  The implementation of these protocols is
simpler and uses less memory.

QCBOR's test suite is written in the same portable C that QCBOR is
where TinyCBOR requires Qt for its test. QCBOR's test suite is
designed to be able to run on small embedded devices the same as
QCBOR.

## Code Status

This is the 2.0 alpha release. It has large changes and feature
additions. It's not ready for commericial use yet. The main short
coming is the need for more testing of the newer features. It will
go through alpha, then to beta and then to an official 2.0
commerical release sometimes in 2025.

The official QCBOR commercial quality release (as of this writing) is QCBOR 1.6. It
is very stable. Only small fixes and features additions have been
made to it over the last years.

QCBOR was originally developed by Qualcomm. It was [open sourced
through CAF](https://source.codeaurora.org/quic/QCBOR/QCBOR/) with a
permissive Linux license, September 2018 (thanks Qualcomm!).


## Other Software Using QCBOR

* [t_cose](https://github.com/laurencelundblade/t_cose) implements enough of
[COSE, RFC 8152](https://tools.ietf.org/html/rfc8152) to support
[CBOR Web Token (CWT)](https://tools.ietf.org/html/rfc8392) and
[Entity Attestation Token (EAT)](https://tools.ietf.org/html/draft-ietf-rats-eat-06).
Specifically it supports signing and verification of the COSE_Sign1 message.

* [ctoken](https://github.com/laurencelundblade/ctoken) is an implementation of
EAT and CWT.

## Credits
* Ganesh Kanike for porting to QSEE
* Mark Bapst for sponsorship and release as open source by Qualcomm
* Sachin Sharma for release through CAF
* Tamas Ban for porting to TF-M and 32-bit ARM
* Michael Eckel for Makefile improvements
* Jan Jongboom for indefinite length encoding
* Peter Uiterwijk for error strings and other
* Michael Richarson for CI set up and fixing some compiler warnings
* Máté Tóth-Pál for float-point disabling and other
* Dave Thaler for portability to Windows


### Copyright for this README

Copyright (c) 2018-2025, Laurence Lundblade. All rights reserved.
Copyright (c) 2021-2023, Arm Limited. All rights reserved.
