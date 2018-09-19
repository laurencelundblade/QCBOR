# QCBOR

QCBOR encodes and decodes [RFC 7049](https://tools.ietf.org/html/rfc7049) CBOR. 

## Characteristics

**Implemented in C with minimal dependecy** – Only dependencies are C99, stdint.h, stddef.h, stdbool.h and string.h making it highly portable. There are no #ifdefs.

**Focused on C / native data representation** – Simpler code because there is no support for encoding/decoding to/from JSON, pretty printing, diagnostic notation... Only encoding from native C representations and decoding to native C representations is supported.

**Small simple memory model** – Malloc is not used. The encode context is 128 bytes, decode context is 168 bytes and the description of decoded data item is 56 bytes. Stack use is very light and there is no recursion. The caller supplies the memory to hold the encoded CBOR and encode/decode contexts so caller has full control of memory usage and it is good for embedded implementations that have to run in small fixed memory. 

**Supports nearly all of RFC 7049** – Only minor, corner-case parts of RFC 7049 are not directly supported (canonicalization, decimal fractions, big floats) (indefinite length support is planned, but not ready yet).

**Extensible and General** – Provides a way to handle data types that are not directly supported.

**Secure Coding Style** – Uses a construct called UsefulBuf as a discipline for very safe coding the handling of binary data.

**Small Code Size** – When optimized for size using the compiler -Os option, x86 code is less than 5KB (~2KB encode, 2KB decode, 1KB common). 

**Clear documented public interface** – The public interface is separated from the implementation. It can be put to use without reading the source. 

## Code Status
This was originally developed by Qualcomm. It was [open sourced through CAF](https://source.codeaurora.org/quic/QCBOR/QCBOR/) with a permissive Linux license, September 2018 (thanks Qualcomm!).

This code in Laurence's GitHub has diverged some from the CAF source with some small simplifications and tidying up. 

The following modifications are planned as of September 2018:
* Floating point support
* Indefinite length support
* Improve design for handling multiple tags

These changes may result in some interface changes. 




