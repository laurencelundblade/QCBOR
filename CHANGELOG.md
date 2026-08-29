# Changelog

All notable changes to QCBOR are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Going forward, CHANGELOG.md (this file) is the source of truth for change history
  - Text in GitHub release notes will be copied from here 
  - Some of the version history from GitHub releases has been copied in here
- QCBOR_VERSION_NUMBER allows > and < version number comparison

### Changed
- QCBOR_VERSION_STRING no longer has "libqcbor" at the start (comply with convention)- 
- Revised & moved qcbor.spec to be much more useful for downstream packagers
- CI now checks qcbor.spec
- Establish SOVERSION and ABI version management policy

### Fixed
- When QCBOR_NUM_MAPPED_TAGS is re configured to less than QCBOR_MAX_TAGS_PER_ITEM
  and the input has more than QCBOR_NUM_MAPPED_TAGS tag numbers above 
  QCBOR_LAST_UNMAPPED_TAG, the error is not reported and incorrect tag numbers are returned.


## [1.6.1] - 2025-03-03

### Changed
- Building with cmake is modernized:
  - Cmake-based install is supported
  - Package files are created for use by dependents
  - All configuration options are in the cmake cache
  - A couple of the cmake configuration symbols, QCBOR_OPT_DISABLE_XXX, for floating-point are renamed that may cause a small backward compatibility problem for build environments that turn off float features. This is not an API compatibility issue, just a build environment issue
 - CI internals factoring is improved
- Windows CI is improved

### Fixed
- Small bug fix to QCBORDecode_EnteryArray() -- pItem-> uDataType is set to QCBOR_TYPE_NONE on error.


## [1.6] - 2025-11-23

### Added
- "strings libqcbor.a" can be run to discover the library version (but use cpp macros if your code needs to be version conditional).

### Changed
- Better support for Windows/MSVC:
  - Continuous integration includes Windows/MSVC
  - Fix compiler errors and warnings in the test suite (not the library)
  - Address issues with type "long" which is 32-bits, not 64 in test suite (not the library)
- Fix compiler warnings raised by gcc.
- Remove use of strcpy(), a function often "banned" for security reasons.
- Floating point NaN payload handling: This is an obscure part of CBOR and floating-point. This change only applies to encoding using preferred serialization where floating-point values are reduced to be shorter. This change makes this comply to the (implied) behavior required in RFC 8949. In order to fix this in a uniform way across all CPUs, reliance on the HW floating-point instructions for conversion was replaced by a SW implementation of the conversion.  Warning: NaN payloads are a hotly debated topic in the IETF CBOR working group. The standard behavior for them may change. Don't rely on them unless you are up to speed on the debate.
- This also changes how #ifdef QCBOR_DISABLE_FLOAT_HW_USE and QCBOR_DISABLE_PREFERRED_FLOAT work. When decoding floating-point, singles are usually returned as doubles. Previously this was disabled (singles are returned as singles) by QCBOR_DISABLE_FLOAT_HW_USE. Now it is disabled by QCBOR_DISABLE_PREFERRED_FLOAT.

### Fixed
- QCBORDecode_EnterBstrWrapped() called on an empty string at the very end of the whole CBOR input would fail.
- Bug in QCBORDecode_GetArray() and QCBORDecode_GetMap(). It was previously fixed in 1.5.2 and reintroduced in 1.5.3.



