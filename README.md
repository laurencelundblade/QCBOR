THIS IS A DEV BRANCH FOR t_cose 2.0. It's purpose is to integrate several large changes
(multiple signers, MAC, encryption, and restartable crypto) together before
they merge into master to become t_cose 2.0. (Replace this message with
an introduction to t_cose 2.0 before the merge to master.

![t_cose](https://github.com/laurencelundblade/t_cose/blob/master/t-cose-logo.png?raw=true)


*t_cose* implements enough of COSE to support [CBOR Web Token, RFC 8392](https://tools.ietf.org/html/rfc8392)
and [Entity Attestation Token (EAT)](https://tools.ietf.org/html/draft-ietf-rats-eat-01).
This is the COSE_Sign1 part of [COSE, RFC 9052](https://tools.ietf.org/html/rfc9052).

**Implemented in C with minimal dependency** – There are three main
dependencies: 1) [QCBOR](https://github.com/laurencelundblade/QCBOR),
2) A cryptographic library for ECDSA and SHA-2, 3) C99, <stdint.h>,
<stddef.h>, <stdbool.h> and <string.h>.  It is  highly
portable to different HW, OS's and cryptographic libraries. Except for
some minor configuration for the cryptographic library, no #ifdefs or
compiler options need to be set for it to run correctly.

**Crypto Library Integration Layer** – Works with different cryptographic
libraries via a simple integration layer. The integration layer is kept small and simple,
just enough for the use cases, so that integration is simpler. Integration layers for
the OpenSSL and ARM Mbed TLS (PSA Cryptography API) cryptographic libraries
are included.

**Secure coding style** – Uses a construct called UsefulBuf / q_useful_buf as a
discipline for safe coding and handling of binary data.

**Small simple memory model** – Malloc is not needed. Besides the
cryptographic library and payload buffer, about 600 bytes of heap/stack is needed
for signing and 1500 bytes for verifying. The caller supplies the output buffer
and context structures so the caller has control over memory usage making it
useful for embedded implementations that have to run in small fixed memory.

## Documentation

[API documentation is here](https://laurencelundblade.github.io/t_cose/)


## Code Status

Status for t_cose 2.0 is very roughly this. COSE_Sign1 is working
except for decoding of protected parameters. COSE_Sign works for
a single signature.  COSE_Mac0 is generally working. COSE_Encrypt
and COSE_Encrypt0 are somewhat working. 

There is still lots of work to do on COSE_Sign, clean up on
COSE_Mac0 and some re design is exected for COSE_Encrypt.

RSA and Eddsa integration from main is still to be done.

Integration with the [OpenSSL](https://www.openssl.org) and [Arm Mbed
TLS](https://github.com/ARMmbed/mbedtls) cryptographic libraries is
fully supported for signing, but not COSE_Mac or COSE_Encrypt.


## Building and Dependencies

Except for the crypto library set up, t_cose is very portable and
should largely just work in any environment. It needs a few standard
libraries and [QCBOR](https://github.com/laurencelundblade/QCBOR)
(which is also very portable). Hence most of this section is about
crypto library set up.

### QCBOR

If QCBOR is installed in /usr/local, then the makefiles should find
it. If not then QCBOR may need to be downloaded. The makefiles can be
modified to reference it other than in /usr/local.

### Supported Cryptographic Libraries

Here's three crypto library configurations that are supported. Others
can be added with relative ease.

#### Test Crypto -- Makefile.test

This configuration should work instantly on any device and is useful
to do a large amount of testing with, but can't be put to full
commercial use. What it lacks is integration with an ECDSA
implementation so it can't produce real ECDSA signatures. It does
however produce fake signatures called "short-circuit
signatures" that are very useful for testing. See header
documentation for details on short-circuit sigs.

This configuration (and only this configuration) uses a bundled
SHA-256 implementation (SHA-256 is simple and easy to bundle, ECDSA is
not).

To build run:

    make -f Makefile.test

#### OpenSSL Crypto -- Makefile.ossl

This OpenSSL integration supports SHA-256, SHA-384 and SHA-512 with
ECDSA, EdDSA, or RSAPSS to support the COSE algorithms ES256, ES384 and
ES512, PS256, PS384 and PS512. It is a full and tested integration
with OpenSSL crypto.

If OpenSSL is installed in /usr/local or as a standar library, you can
probably just run make:

    make -f Makefile.ossl

The specific things that Makefile.ossl does is:
    * Links the crypto_adapters/t_cose_openssl_crypto.o into libt_cose.a
    * Links test/test/t_cose_make_openssl_test_key.o into the test binary
    * `#define T_COSE_USE_OPENSSL_CRYPTO`

t_cose is regularly tested against OpenSSL 1.1.1 and 3.0.

The crypto adaptor for OpenSSL is about twice the size of that for
Mbed TLS because the API doesn't line up well with the needs for COSE
(OpenSSL is ASN.1/DER oriented). Memory allocation is performed inside
OpenSSL and in the crypto adaptation layer. This makes the OpenSSL
crypto library less suitable for embedded use.

No deprecated or to-be-deprecated APIs are used.

There are several different sets of APIs in OpenSSL that can be used
to implement ECDSA and hashing. The ones chosen are the most official
and well-supported, however others might suit particular uses cases
better.  An older t_cose used some to-be-deprecated APIs and is a more
efficient than this one.  It is unfortunate that these APIs
(ECDSA_do_sign and ECDSA_do_verify) are slated for deprecation and
there is no supported alternative to those that work only with DER-encoded
signatures.

There are no known problems with the code and test coverage for the
adaptor is good. Not every single memory allocation failure has
test coverage, but the code should handle them all correctly.


#### PSA Crypto -- Makefile.psa

As of March 2022, t_cose works with the PSA 1.0 Crypto API as
implemented by Mbed TLS 2.x and 3.x.

This integration supports SHA-256, SHA-384 and SHA-512 with
ECDSA, EdDSA or RSAPSS to support the COSE algorithms ES256, ES384 and
ES512, PS256, PS384 and PS512.

If Mbed TLS is installed in /usr/local, you can probably just run
make:

    make -f Makefile.psa

If this doesn't work or you have Mbed TLS elsewhere edit the makefile.

The specific things that Makefile.psa does is:
    * Links the crypto_adapters/t_cose_psa_crypto.o into libt_cose.a
    * Links test/test/t_cose_make_psa_test_key.o into the test binary
    * `#define T_COSE_USE_PSA_CRYPTO`

This crypto adapter is small and simple. The adapter allocates no
memory and as far as I know it internally allocates no memory. It is a
good choice for embedded use.

It makes use of the 1.0 version of the PSA cryptographic API.  No
deprecated or to-be-deprecated functions are called (an older t_cose
used some to be deprecated APIs).

It is regularly tested against the latest version 2 and version 3 of
Mbed TLS, an implementation of the PSA crypto API.

Confidence in the adaptor code is high and reasonably well tested
because it is simple.


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

#### Unsupported Crypto

Not all crypto libraries will support all algorithms that t_cose can
make use of. For example, t_cose will likely be able to make use of PQ
(post-quantum) algorithms, but that not all libraries will support all
of these algorithms.

Algorithm variability is handled in two layers: 1) compilation and
linking in the t_cose crypto adaptor layer and 2) run-time indication
in the public API. That is, there is no variability in the t_cose
public API because of variation in algorithms available. When an
algorithm isn't available, it manifests by one of the standard public
APIs returning T_COSE_ERR_UNSUPPORTED_XXXX.

All algorithm identification in t_cose is by COSE integer algorithm
IDs.

To go into detail of how compilation and linking are handled, the
crypto adaptation layer should rely on #defines in the crypto library
headers to know what files it can include and what functions it can
call. Hopefully, the crypto libraries provide the necessary
#defines. t_cose should always compile and link successfully with any
crypto libraries it supports no matter the version or
configuration. For example, if a version of Mbed TLS that doesn't
support HPKE is used, it should still compile and link with no user
intervention. The user will find out that HPKE is missing when they
get a T_COSE_ERR_UNSUPPORTED_XXXX error from the public API.

If a crypto library doesn't provide #defines, then algorithms in it
that are made use of should be disabled by default.  To enable them,
the user will have to go to the trouble of explicitly #defining
something to enable it. This is so t_cose always compiles and links
correctly the first time without the user doing any configuration
work.

t_cose does assume some algorithms like SHA-2 will always be present
because they are widely supported and generally necessary.

If an implementation or test case wishes to query whether a particular
t_cose build supports a particular algorithm the public API
t_cose_is_algorithm_supported() is provided.

In the automated tests, cases that use specific algorithms that are
known to be not widely supported are enabled and disabled at runtime
by querying whether they are not supported through the runtime public
API. They are generally not handled by #ifdefs unless absolutely
necessary.

For continuous integration (CI), it is fine if not every test covers
every algorithm, but every algorithm should be covered by at least one
test. This may require configuring CI with some alternate versions of
crypto libraries.

### Omitting Algorithms to Reduce Code Size

Previously, t_cose had #defines like T_COSE_DISABLE_ES512 to omit
algorthms to reduce code size. A different strategy is used for t_cose
2.0 that takes advantage of the dynamic linking of the signing,
COSE_Signature and COSE_Recipient implementations.

For t_cose 2.0, the bulk of the crypto algorithms are called by the
implementations of the t_cose_signature and of t_cose_recipient.
These are not hard-linked to the rest of the t_cose. Assuming dead
stripping, paticular implementations for particular algorithms will
not be linked in unless they are explicitly called. The dead stripping
can take care of this through the t_cose_crypto layer, though some
adjustments may be necessary for it to be most effective.

For example, the ECDSA algorithm is only called from
t_cose_signature_sign_main and t_cose_signature_verify_main. If a
user of t_cose never calls these, for example, never calls
t_cose_signature_sign_main_init() it won't be linked and the
references to the of the algorithms won't be made.

For this to work well, the t_cose_crypto layer needs to have separate
functions for separate algorithms. This is something to be looked
into.


## Memory Usage

### Code

Here are code sizes on 64-bit x86 optimized for size

     |                           | smallest | largest |
     |---------------------------|----------|---------|
     | signing only              |     1500 |    2300 |
     | verification only         |     2500 |    3300 |
     | common to sign and verify |     (500)|    (800)|
     | combined                  |     3500 |    4800 |

Things that make the code smaller:
* PSA / Mbed crypto takes less code to interface with than OpenSSL
* gcc is usually smaller than llvm because stack guards are off by default
* Use only 256-bit crypto with the T_COSE_DISABLE_ESXXX options
* Disable short-circut sig debug facility T_COSE_DISABLE_SHORT_CIRCUIT_SIGN
* Disable the content type header T_COSE_DISABLE_CONTENT_TYPE
* Disable COSE_Sign structure support with T_COSE_DISABLE_COSE_SIGN
  (use only COSE_Sign1 signature structures if adequate).

#### Change in code size with spiffy decode

The encode size is as before.

Compared to the previous t_cose, the code size for decoding/verifying
is reduced by about 600 bytes. However, spiffy decode functions in
QCBOR are now required and they are about 2KB, so there is a net size
increase of 1.4KB. But use of spiffy decode will also make other parts
of the overall SW stack smaller, perhaps by a lot, so this will likely
break even. For example, EAT or CWT decoding will be reduced a lot
through use of spiffy decode.  Basically, the more CBOR maps a SW
stack has to handle, the more saving there will be from spiffy decode.


### Heap and stack

Malloc is not used.

Stack usage is variable depending on the key and hash size and the
stack usage by the cryptographic library that performs the hash and
public key crypto functions.  The maximum requirement is roughly
2KB. This is an estimate from examining the code, not an actual
measurement.

Since the keys, hash outputs and signatures are stored on the stack,
the stronger the security, the more stack is used. By default up to
512 bit EC is enabled. Disable 512 and 384 bit EC to reduce stack
usage by about 100 bytes.

Different cryptographic libraries may have very different stack usage
characteristics.  For example if one use malloc rather than the stack,
it will (hopefully) use less stack.  The guess estimate range of usage
by the cryptographic library is between 64 and 1024 bytes of stack.

Aside from the cryptographic library, the base stack use by t_cose is
500 bytes for signing and 1500 bytes for verification. With a large
cryptographic library, the total is about 1500 bytes for signing and
2000 bytes for verification (for verification, the crypto library
stack re uses stack used to decode header parameters so the increment
isn't so large).

The design is such that only one copy of the output, the COSE_Sign1,
need be in memory.  It makes use of special features in QCBOR that
allows contstuction of the output including the payload, using just
the single output buffer to accomplish this.

A buffer to hold the signed COSE result must be passed in. It must be
about 100 bytes larger than the combined size of the payload and key
id for ECDSA 256. It can be allocated as the caller wishes.

### Crypto library memory usage
In addition to the above memory usage, the crypto library will use
some stack and/or heap memory. This will vary quite a bit by crypto
library. Some may use malloc. Some may not.

The OpenSSL library does use malloc, even with ECDSA. Another
implementation of ECDSA might not use malloc, as the keys are small
enough.

### Mixed code style
QCBOR uses camelCase and t_cose follows
[Arm's coding guidelines](https://git.trustedfirmware.org/TF-M/trusted-firmware-m.git/tree/docs/contributing/coding_guide.rst)
resulting in code with mixed styles. For better or worse, an Arm-style version of UsefulBuf
is created and used and so there is a duplicate of UsefulBuf. The two are identical. They
just have different names.

## Limitations

* Most inputs and outputs must be in a continguous buffer. One
  exception to this is that CBOR payloads being signed can be
  constructed piecemeal into the output buffer and signed without
  using a separate buffer.
* Doesn't handle COSE string algorithm IDs. Only COSE integer
  algorithm IDs are handled.  Thus far no string algorithm IDs have
  been assigned by IANA.
* No way to add custom headers when creating signed messages or
  process them during verification.
* Does not handle CBOR indefinite length strings (indefinite length
  maps and arrays are handled).
* Counter signatures are not supported.

## Credit

* Paul Liétar for RSA PSS (PS256..PS512) and EdDSA
* Maik Riechert for cmake, CI and other.
* Ken Takayama for the bulk of the detached content implementation.
* Tamas Ban for lots code review comments, design ideas and porting to ARM PSA.
* Rob Coombs, Shebu Varghese Kuriakose and other ARM folks for sponsorship.
* Michael Eckel for makefile fixes.

## Copyright and License

t_cose is available under the 3-Clause BSD License.
