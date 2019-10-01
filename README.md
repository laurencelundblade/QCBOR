

#  t_cose

t_cose implements enough of COSE to support [CBOR Web Token, RFC 8392](https://tools.ietf.org/html/rfc8392)  
and [Entity Attestation Token (EAT)](https://tools.ietf.org/html/draft-ietf-rats-eat-01). 
This is the COSE_Sign1 part of [COSE, RFC 8152](https://tools.ietf.org/html/rfc8152). 

## Characteristics

**Implemented in C with minimal dependency** – There are three main 
dependencies: 1) [QCBOR](https://github.com/laurencelundblade/QCBOR), 2) A 
cryptographic library for ECDSA and SHA-2, 3)  C99, <stdint.h>, <stddef.h>,
<stdbool.h> and <string.h>.  It is intended to be highly portable to different HW, OS's and 
cryptographic libraries. No #ifdefs or compiler options  need to be set for it to run correctly.

**Crypto Library Integration Layer** – t_cose can work with different cryptographic
libraries via a simple integration layer. The integration layer is kept small and simple, 
just enough for the use cases, so that integration is simpler. An integration layer for 
Openssl is included (not complete yet).

**Secure coding style** – Uses a construct called UsefulBuf / q_useful_buf as a
discipline for very safe coding and handling of binary data.

**Small simple memory model** – Malloc is not needed. The signing
context is less than 100 bytes. Stack use is light and
there is no recursion. The caller supplies the memory to hold the
completed COSE_Sign1 and encode/decode contexts so caller has full control
of memory usage making it good for embedded implementations that
have to run in small fixed memory.

## Code Status

As of September 2019, the code is in reasonable working order, but needs some more 
test and refinement. The signing code is more thoroughly tested and fully featured than
the verification code. 

### The to-do list:
* Add lots of test cases for verification, particularly hostile input
* Lots of code clean up, formatting and documentation
* Resolve what to do with string algorithm IDs and integer content types in the verifier
* Makefile needs improvements

## Building and Dependencies

There is a simple makefile (probably too simple, but at least a starting point)

* [QCBOR](https://github.com/laurencelundblade/QCBOR) is required
* Some cryptographic library that supports ECDSA and at least SHA-256 is required
* * A porting layer for [OpenSSL](https://www.openssl.org) is included (soon).

## Memory Usage

### Code 

These are approximate numbers for 64-bit x86 code optimized for size

* Common to signing and verifying:  515
* Signing: 920 (742)
* Verify: 1596
* OpenSSL adaptor layer: 609
* Total: 3710
* Signing only total: 1813
* Verify only total: 2509

### Heap and stack
Malloc is not used.

Stack usage is less than 1KB for signing and for encryption.

The design is such that only one copy of the COSE_Sign1 need be in memory. It makes
use of special features in QCBOR to accomplish this.

The payload to sign must be in one contiguous buffer and be passed in. It can be allocated
however the caller wishes, even in ROM, since it is only read.

A buffer to hold the signed COSE result must be passed in. It must be about 100 bytes 
larger than the combined size of the payload and key id for ECDSA 256. It can be 
allocated however the caller wishes.

### Crypto library memory usage
In addition to the above memory usage, the crypto library will use some stack and / or
heap memory. This will vary quite a bit by crypto library. Some may use malloc. Some may
not. 

If only ECDSA is used, not RSA, in theory it is possible for the crypto library memory usage to be small
because the keys and signatures are relatively small, but this depends on the crypto library.

The standard OpenSSL library does use malloc.

### Mixed code style
QCBOR uses camelCase and t_cose follows 
[Arm's coding guidelines](https://git.trustedfirmware.org/trusted-firmware-m.git/tree/docs/coding_guide.rst)
resulting in code with mixed styles. For better or worse, an Arm-style version of UsefulBuf
is created and used and so there is a duplicate of UsefulBuf. The two are identical. They
just have different names.

## Limitations
* Doesn't handle string algorithm IDs. Only integer algorithm IDs are handled. This is OK because no string algorithm IDs have been allocated by IANA.
* No way to add the content type when creating a COSE_Sign1.
* No way to handle custom headers with signing or verifying. Only standard COSE headers are handled.
* Only ECDSA is supported so far (facilities are available to add others).

## Credit

* Tamas Ban for lots code review comments, design ideas and porting to ARM PSA.
* Rob Coombs, Shebu Varghese Kuriakose and other ARM folks for sponsorship

## Copyright and License

t_cose is available under the 3-Clause BSD License.
