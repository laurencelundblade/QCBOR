

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

As of October 2019, the code is in reasonable working order and the public interface is 
fairly stable. There is a crypto adaptaion layer for [OpenSSL](https://www.openssl.org).

### The to-do list:
* Add some more tests, particular test vectors from C_COSE or such
* General documentation clean up, spelling checks and formatting.

## Building and Dependencies

Except for the crypto library set up, t_cose is very portable and
should largely just work in any environment. It needs a few standard
libraries and [QCBOR](https://github.com/laurencelundblade/QCBOR)
(which is also very portable). Hence the rest of this section is about
crypto library set up.

### Currently Supported Libraries

Here's three crypto library configurations that are supported. Others
can be added with relative ease over time.

#### Test Crypto -- Makefile.test

This configuration should work instantly on any device and is useful
to do quite a large amount of testing with, but can't be put to full
commercial use. What it lacks is any integration with an ECDSA
implementation so it can't produce real ECDSA signatures. It does
however produce some fake signatures called "short-circuit
signatures" that are very useful for testing. See header
documentation for details on short-circuit sigs.

This configuration (and only this configuration) uses an bundled
SHA-256 implementation (SHA-256 is simple and easy to bundle, ECDSA is
not).

To use this, edit the makefile for the location of QCBOR and then just
do

    make -f Makefile.test

#### OpenSSL Crypto -- Makefile.ossl

This OpenSSL integration supports SHA-256, SHA-384 and SHA-512 with
ECDSA to support the COSE algorithms ES256, ES384 and ES512. It is a
full and tested integration with OpenSSL crypto.

To use this, edit the makefile for the location of QCBOR and OpenSSL
and do:

    make -f Makefile.ossl

The specific things that Makefile.ossl does is:
* #defines T_COSE_USE_OPENSSL_CRYPTO 
* Links the crypto_adapters/t_cose_openssl_crypto.o into libt_cose.a
* Links test/test/t_cose_make_openssl_test_key.o into the test binary

Note that the internally supplied b_con_hash is not used in this case
by virtue of the Makefile not linking to it.

#### PSA Crypto -- Makefile.psa

This makes use of crypto libraries supporting the PSA cryptographic
interface found in psa/crypto.h as a part of Arm's TF-M and perhaps
others.

This integration supports SHA-256, SHA-384 and SHA-512 with ECDSA to support
the COSE algorithms ES256, ES384 and ES512. It is a full implementation but
needs on-target testing.

To use this, edit the makefile for the location of CBOR and your
PSA-compatible cryptographic library and do:

    make -f Makefile.psa
    
The specific things that Makefile.ossl does is:
    * Links the crypto_adapters/t_cose_psa_crypto.o into libt_cose.a
    * Links test/test/t_cose_make_psa_test_key.o into the test binary
    * (No #defines needed, all adaptation is through the above object files)   

Note that the internally supplied b_con_hash is not used in this case
by virtue of the Makefile not linking to it.

### General Crypto Library Strategy

The functions that t_cose needs from the crypto library are all
defined in src/t_cose_crypto.h.  This is a porting or adaption
layer. There are no #ifdefs in the main t_cose code for different
crypto libraries. When it needs a crypto function it just calls the
interface defined in t_cose_crypto.h.

When integrating t_cose with a new cryptographic library, what is
necessary is to write some code, an "adaptor", that implements
t_cose_crypto.h using the new target cryptographic library. This can
be done without changes to any t_cose code for many cryptographic
libraries. See the interface documentation in t_cose_crypto.h for what
needs to be implemented.

That said, there is one case where t_cose source code needs to be
modified. This is for hash algorithm implementations that are linked
into and run inline with t_cose and that have a context structure. In
this case t_cose_crypto.h should be modified to use that context
structure. Use the OpenSSL configuration as an example.

To complete the set up for a new cryptographic library and test it, a
new test adaptation file is also needed. This file makes public key
pairs of the correct type for use with testing.  This file is usually
named test/t_cose_make_xxxx_test_key.c and is linked in with the test
app. The keys it makes are passed through t_cose untouched, through
the t_cose_crypto.h interface into the underlying crypto.

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

So far no support for RSA is available, but since the keys and signatures are much bigger,
it will up the memory usage a lot and may require use of malloc. 

The OpenSSL library does use malloc, even with ECDSA. Another implementation of ECDSA
might not use malloc, as the keys are small enough.

### Mixed code style
QCBOR uses camelCase and t_cose follows 
[Arm's coding guidelines](https://git.trustedfirmware.org/trusted-firmware-m.git/tree/docs/coding_guide.rst)
resulting in code with mixed styles. For better or worse, an Arm-style version of UsefulBuf
is created and used and so there is a duplicate of UsefulBuf. The two are identical. They
just have different names.

## Limitations
* The payload input and output and the signed structure input and output must be in 
contiguous memory.
* Doesn't handle COSE string algorithm IDs. Only COSE integer algorithm IDs are handled. 
Thus far no string algorithm IDs have been assigned by IANA.
* No way to add custom headers when creating signed messages or process them during 
verification.
* Only ECDSA is supported so far (facilities are available to add others).
* Does not handle CBOR indefinite length strings (indefinite length maps and arrays are handled).
* Counter signatures are not supported.

## Credit

* Tamas Ban for lots code review comments, design ideas and porting to ARM PSA.
* Rob Coombs, Shebu Varghese Kuriakose and other ARM folks for sponsorship.

## Copyright and License

t_cose is available under the 3-Clause BSD License.
