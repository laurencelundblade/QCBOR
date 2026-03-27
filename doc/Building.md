
@anchor Building
## Building

The QCBOR library source is solely in the `src` and `inc` directories. The
`inc` directory contains the public API. The other files and
directories contain tests, documentation, examples, and such.

QCBOR can be built using `make` with the `Makefile` or with `cmake`
using `CMakeLists.txt`.

QCBOR compiles and operates correctly without any build-time
configuration or setup. It is designed to be fully portable across the
majority of platforms.

A number of C preprocessor `#define` options are available. Their
primary purpose is to reduce object code size by disabling optional
features, with a small number also providing modest performance
improvements.  See the “Configuration” comments in inc/UsefulBuf.h, as
well as the preprocessor symbols beginning with `QCBOR_DISABLE_XXX`.

The test directory contains the test suite, which is nearly as
portable as QCBOR itself. If your development environment does not
support a UNIX-style command line, you can create a simple project and
add the test source files directly. Invoking RunTests() will execute
the full test suite.


### Building with CMake

A modern CMake configuration is provided in CMakeLists.txt that can
build, test, and install QCBOR. The installation includes CMake package
files for easy installation, use of the QCBOR library by CMake-based
and non-CMake-based dependents, and integration into a larger
CMake-based project.

Generally, no configuration is needed, but there are a few build
options:

| Option                   | Description
|:-------------------------|:----------------------------------------------------------------
| `-DBUILD_SHARED_LIBS=ON` | Builds shared lib instead of static.
| `-DBUILD_QCBOR_WARN=ON`  | Compiler warnings are off by default; this turns on the warnins used in QCBOR continuous integration.
| `-DBUILD_QCBOR_TEST=APP` | Builds the tests as an executable. Tests are off by default.
| `-DBUILD_QCBOR_TEST=LIB` | Builds the tests as a library.
| `-DQCBOR_DISABLE_XXX=ON` | Disables feature XXX to reduce code size. See descriptions below. The name of the CMake option is the same as the `#define`.

Building the QCBOR library:

```sh
cd <QCBOR_base_folder>
# Configure the project and generate build set up
cmake -S . -B <build_folder>
# Build the project
cmake --build <build_folder>
# Install in /usr/local
cmake --install <build_folder>
```

Building and running the QCBOR test app:

```sh
cd <QCBOR_base_folder>
# Configure the project and generate build set up
cmake -S . -B <build_folder> -DBUILD_QCBOR_TEST=APP
# Build the project
cmake --build <build_folder>
# Run the test app
<build_folder>/test/qcbortest
```

@anchor CodeSize
## Code Size

TODO: The sizes in this section need to be updated for QCBOR v2.

These are approximate sizes on a 64-bit x86 CPU with the -Os optimization.
All `QCBOR_DISABLE_XXX` are set and compiler stack frame checking is disabled
for smallest but not for largest. Smallest is the library functions for a
protocol with strings, integers, arrays, maps and Booleans, but not floats
and standard tag types.

|               | smallest  | largest |
|---------------|-----------|---------|
| encode only   |   TODO    |  TODO   |
| decode only   |   TODO    |  TODO   |
| combined      |   TODO    |  TODO   |

 From the table above, one can see that the amount of code pulled in
 from the QCBOR library varies a lot, ranging from 1KB to 15KB.  The
 main factor is the number of QCBOR functions called and
 which ones they are. QCBOR minimizes internal
 interdependency so only code necessary for the called functions is
 brought in.

 Encoding is simpler and smaller. An encode-only implementation may
 bring in only 1KB of code.

 Encoding of floating-point brings in a little more code as does
 encoding of tagged types and encoding of bstr wrapping.

 Basic decoding using QCBORDecode_GetNext() brings in 3KB.

 Use of the supplied MemPool by calling  QCBORDecode_SetMemPool() to
 setup to decode indefinite-length strings adds 0.5KB.

 Basic use of spiffy decode to brings in about 3KB. Using more spiffy
 decode functions, such as those for tagged types bstr wrapping brings
 in more code.

 Finally, use of all of the integer conversion functions will bring in
 about 5KB, though you can use the simpler ones like
 QCBORDecode_GetInt64() without bringing in very much code.

 In addition to using fewer QCBOR functions, the following are some
 ways to make the code smaller.

 The gcc compiler output is usually smaller than llvm because stack
 guards are off by default (be sure you actually have gcc and not llvm
 installed to be invoked by the gcc command). You can also turn off
 stack gaurds with llvm. It is safe to turn off stack gaurds with this
 code because Usefulbuf provides similar defenses and this code was
 carefully written to be defensive.

 If QCBOR is installed as a shared library, then of course only one
 copy of the code is in memory no matter how many applications use it.

### Disabling Features

The primary control over the amount of QCBOR code that is linked into
an application is in which functions are actually used. When linking
against a library, or when dead-code stripping is enabled, any code
that is not explicitly referenced will not be linked. For example,
never calling number conversion functions will result in less linked
code.

In addition to minimizing the set of QCBOR functions used, the
following preprocessor `#define` options can be set to further reduce
code size. For example, defining `QCBOR_DISABLE_NON_INTEGER_LABELS`
reduces the decoder size and can be set when building the library for
protocols that use only integer map labels.

The code-size reductions listed below are approximate. Actual savings
depend on factors such as the target CPU, compiler, compiler options,
build configuration, and the specific QCBOR functions used.


| `#define`                                 |  Saves |
| ------------------------------------------| -------|
| `QCBOR_DISABLE_ENCODE_USAGE_GUARDS`       |  TODO  |
| `QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS` |  TODO  |
| `QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS`  |  TODO  |
| `QCBOR_DISABLE_EXP_AND_MANTISSA`          |  TODO  |
| `QCBOR_DISABLE_PREFERRED_FLOAT`           |  TODO  |
| `QCBOR_DISABLE_FLOAT_HW_USE`              |  TODO  |
| `USEFULBUF_DISABLE_ALL_FLOAT`             |  TODO  |
| `QCBOR_DISABLE_TAGS`                      |  TODO  |
| `QCBOR_DISABLE_NON_INTEGER_LABELS`        |  TODO  |
| `QCBOR_DISABLE_DECODE_CONFORMANCE`        |  TODO  |
| `USEFULBUF_DISABLE_STREAMING`             |  TODO  |

`QCBOR_DISABLE_ENCODE_USAGE_GUARDS` affects encoding only. It doesn't
disable any encoding features, just extra error checking that helps
debugging.  Disable it when you are confident that an encoding
implementation is complete and correct.

Indefinite lengths are a feature of CBOR that makes encoding simpler
and the decoding more complex. They allow the encoder to not have to
know the length of a string, map, or array when they start encoding
it. Their main use is when encoding has to be done on a very
constrained device.  Conversely, when decoding on a very constrained
device, it is good to prohibit use of indefinite lengths so the
decoder can be smaller.

The QCBOR decode API processes both definite and indefinite lengths
with the same API, except that to decode indefinite-length strings, a
storage allocator must be configured.

To reduce the size of the decoder, define
`QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS`, particularly if you are not
configuring a storage allocator.

Further reduction can be acheived by defining
`QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS`, which will result in an error
when an indefinite-length map or array arrives for decoding.

`QCBOR_DISABLE_UNCOMMON_TAGS` is removed from QCBOR v2. It didn't save
very much, and you can get the same effect by not installing
the tag content handlers.

`QCBOR_DISABLE_EXP_AND_MANTISSA` disables the decoding of decimal
fractions and big floats.

The options for disabling floating-point are detailed in the section
on @ref Floating-Point. In short, `QCBOR_DISABLE_PREFERRED_FLOAT`
eliminates a lot of floating-point-related code, particularly
half-precision support, `QCBOR_DISABLE_FLOAT_HW_USE` eliminates
dependency on the math library and `<math.h>`, and
`USEFULBUF_DISABLE_ALL_FLOAT` eliminates all float-point dependency,
such that the types double and float aren't used.

@anchor QCBOR_DISABLE_TAGS

`QCBOR_DISABLE_TAGS` disables decoding of all CBOR tags. If the input
contains any tag, an unrecoverable error (@ref
QCBOR_ERR_TAGS_DISABLED) is raised.  When this option is enabled, the
decoder is suitable only for protocols that do not use CBOR tags.

Setting `QCBOR_DISABLE_TAGS` reduces the size of the decoder core —
particularly QCBORDecode_VGetNext() — by approximately 500 bytes.

“Borrowed” tag content formats (for example, an epoch-based date
encoded without the corresponding tag number) can still be
decoded. See @ref Disabling-Tag-Decoding for additional details.

`QCBOR_DISABLE_NON_INTEGER_LABELS` causes any label that doesn't fit
in an int64_t to result in a @ref QCBOR_ERR_MAP_LABEL_TYPE error.
This also disables `QCBOR_DECODE_MODE_MAP_AS_ARRAY` and
`QCBOR_DECODE_MODE_MAP_STRINGS_ONLY`. It is fairly common for
CBOR-based protocols to use only small integers as labels.

`QCBOR_DISABLE_DECODE_CONFORMANCE` removes the decode features that
the input conforms in a particular way, such as that it is
deterministic of dCBOR.

`USEFULBUF_DISABLE_STREAMING` removes the encode streaming features.


### Size of spiffy decode

When implementing a protocol decoder, you can choose between using the
spiffy decode features or using the lower-level API,
QCBORDecode_VGetNext() API.

Using spiffy decode generally results in a simpler implementation. The
calling code is smaller and easier to write, understand, and test. The
tradeoff is that more code from the QCBOR library is linked in: basic
use of spiffy decode adds approximately 2 KB of object code. If object
code size is not a concern, spiffy decode is usually the better choice
due to reduced development effort, lower complexity, and simpler
testing.

If code size is a concern, using QCBORDecode_VGetNext() will often
produce a smaller overall binary for simple CBOR protocols. However,
for more complex protocols, spiffy decode may actually reduce total
code size. This is especially true for protocols that decode many
maps, or maps with many entries, where the shared, general-purpose
spiffy decode map processing logic replaces repeated hand-written
decoding code.
