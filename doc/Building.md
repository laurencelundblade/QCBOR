
@anchor Building
## Building

The library is built solely from the src and inc directores. The inc directory
contains the public interface. The test app and such are in other
directories.

There is a basic makefile that will build the library and command
line test app. CMake is also available, please read
the "Building with CMake" section for more information.

QCBOR will compile and fully function without any build configuration
or set up. It is 100% portable.

There are a number of C preprocessor #defines that can be set.
Their primary purpose is to reduce library object code sizes
by disabling features.  A couple slightly improve performance.
See the comment sections on "Configuration" in inc/UsefulBuf.h and
the pre processor defines that start with QCBOR_DISABLE_XXX.

The test directory includes the tests that are nearly as portable as
the main implementation.  If your development environment doesn't
support UNIX style command line and make, you should be able to make a
simple project and add the test files to it.  Then just call
RunTests() to invoke them all.

### Building with CMake

CMake can also be used to build QCBOR and the test application. Having the root
`CMakeLists.txt` file, QCBOR can be easily integrated with your project's
existing CMake environment. The result of the build process is a static library,
to build a shared library instead you must add the
`-DBUILD_SHARED_LIBS=ON` option at the CMake configuration step.
The tests can be built into a simple command line application to run them as it
was mentioned before; or it can be built as a library to be integrated with your
development environment.
The `BUILD_QCBOR_TEST` CMake option can be used for building the tests, it can
have three values: `APP`, `LIB` or `OFF` (default, test are not included in the
build).

Building the QCBOR library:

```bash
cd <QCBOR_base_folder>
# Configuring the project and generating a native build system
cmake -S . -B <build_folder>
# Building the project
cmake --build <build_folder>
```

Building and running the QCBOR test app:
```bash
cd <QCBOR_base_folder>
# Configuring the project and generating a native build system
cmake -S . -B <build_folder> -DBUILD_QCBOR_TEST=APP
# Building the project
cmake --build <build_folder>
# Running the test app
.<build_folder>/test/qcbortest
```

To enable all the compiler warnings that are used in the QCBOR release process
you can use the `BUILD_QCBOR_WARN` option at the CMake configuration step:
```bash
cmake -S . -B <build_folder> -DBUILD_QCBOR_WARN=ON
```

### Floating Point Support & Configuration

By default, all QCBOR floating-point features are enabled:

* Encoding and decoding of basic float types, single and double-precision
* Encoding and decoding of half-precision with conversion to/from single
  and double-precision
* Preferred serialization of floating-point
* Floating point dates
* Methods that can convert big numbers, decimal fractions and other numbers
  to/from floating-point

If full floating-point is not needed, the following #defines can be
used to reduce object code size and dependency.

See discussion in qcbor_encode.h for other details.

#### #define QCBOR_DISABLE_FLOAT_HW_USE

This removes dependency on:

* Floating-point hardware and floating-point instructions
* `<math.h>` and `<fenv.h>`
* The math library (libm, -lm)

For most limited environments, this removes enough floating-point
dependencies to be able to compile and run QCBOR.

Note that this does not remove use of the types double and float from
QCBOR, but it limits QCBOR's use of them to converting the encoded
byte stream to them and copying them. Converting and copying them
usually don't require any hardware, libraries or includes. The C
compiler takes care of it on its own.

QCBOR uses its own implementation of half-precision float-pointing
that doesn't depend on math libraries. It uses masks and shifts
instead. Thus, even with this define, half-precision encoding and
decoding works.

When this is defined, the QCBOR functionality lost is minimal and only
for decoding:

* Decoding floating-point format dates are not handled
* There is no conversion between floats and integers when decoding. For
  example, QCBORDecode_GetUInt64ConvertAll() will be unable to convert
  to and from float-point.
* Floats will be unconverted to double when decoding.

No interfaces are disabled or removed with this define.  If input that
requires floating-point conversion or functions are called that
request floating-point conversion, an error code like
`QCBOR_ERR_HW_FLOAT_DISABLED` will be returned.

This saves only a small amount of object code. The primary purpose for
defining this is to remove dependency on floating point hardware and
libraries.


#### #define QCBOR_DISABLE_PREFERRED_FLOAT

This eliminates support of:
- encode/decode of half-precision
- shortest-form encoding of floats
- QCBORDecode_GetNumberConvertPrecisely()

This saves about 1KB of object code, though much of this can be saved
by not calling any functions to encode doubles or floats or
QCBORDecode_GetNumberConvertPrecisely()

With this defined, single and double-precision floating-point numbers
can still be encoded and decoded. Some conversion of floating-point to
and from integers, big numbers and such is also supported. Floating-point
dates are still supported.


#### #define USEFULBUF_DISABLE_ALL_FLOAT

This eliminates floating point support completely (along with related function
headers). This is useful if the compiler options deny the usage of floating
point operations completely, and the usage of a soft floating point ABI is not
possible.

#### Compiler options

Compilers support a number of options that control
which float-point related code is generated. For example,
it is usually possible to give options to the compiler to avoid all
floating-point hardware and instructions, to use software
and replacement libraries instead. These are usually
bigger and slower, but these options may still be useful
in getting QCBOR to run in some environments in
combination with `QCBOR_DISABLE_FLOAT_HW_USE`.
In particular, `-mfloat-abi=soft`, disables use of
 hardware instructions for the float and double
 types in C for some architectures.

#### CMake options

If you are using CMake, it can also be used to configure the floating-point
support. These options can be enabled by adding them to the CMake configuration
step and setting their value to 'ON' (True). The following table shows the
available options and the associated #defines.

    | CMake option                      | #define                       |
    |-----------------------------------|-------------------------------|
    | QCBOR_OPT_DISABLE_FLOAT_HW_USE    | QCBOR_DISABLE_FLOAT_HW_USE    |
    | QCBOR_OPT_DISABLE_FLOAT_PREFERRED | QCBOR_DISABLE_PREFERRED_FLOAT |
    | QCBOR_OPT_DISABLE_FLOAT_ALL       | USEFULBUF_DISABLE_ALL_FLOAT   |

@anchor CodeSize
## Code Size

These are approximate sizes on a 64-bit x86 CPU with the -Os optimization.
All QCBOR_DISABLE_XXX are set and compiler stack frame checking is disabled
for smallest but not for largest. Smallest is the library functions for a
protocol with strings, integers, arrays, maps and Booleans, but not floats
and standard tag types.

    |               | smallest | largest |
    |---------------|----------|---------|
    | encode only   |          |         |
    | decode only   |          |         |
    | combined      |          |         |

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

The main control over the amount of QCBOR code that gets linked
is through which QCBOR functions are used. Linking against a
library or dead stripping will eliminate all code not explicitly
called.

In addition to using fewer QCBOR functions, the following #defines
can be set to further reduce code size. For example,
QCBOR_DISABLE_ENCODE_USAGE_GUARDS will reduce the size
of many common encoding functions by performing less error
checking (but not compromising any code safety).

The amounts saved listed below are approximate. They depends on
the CPU, the compiler, configuration, which functions are
use and so on.


    | #define                                 | Saves |
    | ----------------------------------------| ------|
    | QCBOR_DISABLE_ENCODE_USAGE_GUARDS       |       |
    | QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS |       |
    | QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS  |       |
    | QCBOR_DISABLE_EXP_AND_MANTISSA          |       |
    | QCBOR_DISABLE_PREFERRED_FLOAT           |       |
    | QCBOR_DISABLE_FLOAT_HW_USE              |       |
    | QCBOR_DISABLE_TAGS                      |       |
    | QCBOR_DISABLE_NON_INTEGER_LABELS        |       |
    | USEFULBUF_DISABLE_ALL_FLOAT             |       |

QCBOR_DISABLE_ENCODE_USAGE_GUARDS affects encoding only.  It doesn't
disable any encoding features, just some error checking.  Disable it
when you are confident that an encoding implementation is complete and
correct.

Indefinite lengths are a feature of CBOR that makes encoding simpler
and the decoding more complex. They allow the encoder to not have to
know the length of a string, map or array when they start encoding
it. Their main use is when encoding has to be done on a very
constrained device.  Conversely when decoding on a very constrained
device, it is good to prohibit use of indefinite lengths so the
decoder can be smaller.

The QCBOR decode API processes both definite and indefinite lengths
with the same API, except to decode indefinite-length strings a
storage allocator must be configured.

To reduce the size of the decoder define
QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS particularly if you are not
configuring a storage allocator.

Further reduction can be by defining
QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS which will result in an error
when an indefinite-length map or array arrives for decoding.

QCBOR_DISABLE_UNCOMMON_TAGS is removed from QCBOR v2. It didn't save
very much and you can get the same effect by not installing
the tag content handlers.

QCBOR_DISABLE_EXP_AND_MANTISSA disables the decoding of decimal
fractions and big floats.

@anchor QCBOR_DISABLE_TAGS
QCBOR_DISABLE_TAGS disables all CBOR tag decoding. If the input has
a single tag, the unrecoverable error, @ref QCBOR_ERR_TAGS_DISABLED, occurs.
The decoder is suitable only for protocols that
have no tags. This reduces the size of the core of the decoder,
particularly QCBORDecode_VGetNext(), by a about 500 bytes.
"Borrowed" tag content formats (e.g. an epoch-based date
without the tag number), can still be processed. See @ref Disabilng-Tag-Decoding.

QCBOR_DISABLE_NON_INTEGER_LABELS causes any label that doesn't
fit in an int64_t to result in a QCBOR_ERR_MAP_LABEL_TYPE error.
This also disables QCBOR_DECODE_MODE_MAP_AS_ARRAY and
QCBOR_DECODE_MODE_MAP_STRINGS_ONLY. It is fairly common for CBOR-based
protocols to use only small integers as labels.

See the discussion above on floating-point.

 ### Size of spiffy decode

 When creating a decode implementation, there is a choice of whether
 or not to use spiffy decode features or to just use
 QCBORDecode_GetNext().

 The implementation using spiffy decode will be simpler resulting in
 the calling code being smaller, but the amount of code brought in
 from the QCBOR library will be larger. Basic use of spiffy decode
 brings in about 2KB of object code.  If object code size is not a
 concern, then it is probably better to use spiffy decode because it
 is less work, there is less complexity and less testing to worry
 about.

 If code size is a concern, then use of QCBORDecode_GetNext() will
 probably result in smaller overall code size for simpler CBOR
 protocols. However, if the CBOR protocol is complex then use of
 spiffy decode may reduce overall code size.  An example of a complex
 protocol is one that involves decoding a lot of maps or maps that
 have many data items in them.  The overall code may be smaller
 because the general purpose spiffy decode map processor is the one
 used for all the maps.
