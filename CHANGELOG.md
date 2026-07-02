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
- QCBOR_VERSION_STRING no longer has "libqcbor" at the start (comply with convention)
- Removed recursion from negative big number encoding
- Expand test coverage of big number encoding
- Source code nits in qcbor_number_encode

### Fixed
- Fix encoding of negative big nums that are one non-zero byte followed by zeros.


## [2.0.0-alpha.6] - 2025-05-01

### Added
- New API to save and restore decoder state. In particular, to save a decoder state and then abandon some subsequent decoding.

### Changed

- Build and Configuration:
  - Modernize cmake configuration! Works with find_package() and cmake GUIS to select configuration options.
  - Better GitHub CI, particularly for Windows
  - The floating-point configuration documentation is much improved.
  - Better overall build instructions.
- Substantial refactoring of floating-point testing
- Decode conformance checking:
  - Errors reflect specific error, rather than decoder mode
  - Changed names of some of the conformance modes
- Preferred and deterministic serialization no longer allow NaN payloads in alignment with the upcoming draft-cbor-serialization. NaNs with payloads are no longer reduced to single or half-precision. The only way to output a NaN with a payload is QCBOREncode_DoubleRaw() or QCBOREncode_AddFloatRaw().
  
### Fixed
- Small bug fix to QCBORDecode_EnteryArray(). pItem-> uDataType now correctly set to QCBOR_TYPE_NONE on error.
- Fix major bug with QCBOR_DECODE_MODE_ONLY_SORTED_MAPS. It would always error. Expand related test coverage.
