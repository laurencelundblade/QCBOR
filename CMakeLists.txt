#-------------------------------------------------------------------------------
# Copyright (c) 2022-2023, Arm Limited. All rights reserved.
# Copyright (c) 2024-2026, Laurence Lundblade. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# See BSD-3-Clause license in README.md
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)

project(qcbor
    DESCRIPTION "QCBOR"
    LANGUAGES C
    VERSION 2.0.0
)

# =========================================================================
#    Configuration
# =========================================================================

set(BUILD_QCBOR_TEST  "OFF"  CACHE STRING "Build QCBOR test suite [OFF, LIB, APP]")

option(BUILD_QCBOR_WARN  "Compile with the warning flags used in the QCBOR release process" OFF)

# BUILD_SHARED_LIBS is a built-in global CMake flag
#    The shared library is not made by default because of platform
#    variability For example MacOS and Linux behave differently and some
#    IoT OS's don't support them at all.
option(BUILD_SHARED_LIBS  "Build shared libraries instead of static ones" OFF)

option(QCBOR_DISABLE_FLOAT_HW_USE              "Eliminate dependency on FP libraries, hardware and instructions" OFF)
option(QCBOR_DISABLE_PREFERRED_FLOAT           "Eliminate support for half-precision and CBOR preferred serialization" OFF)
option(USEFULBUF_DISABLE_ALL_FLOAT             "Eliminate floating-point support completely" OFF)
option(QCBOR_DISABLE_NON_INTEGER_LABELS        "Disable all label types except integers" OFF)
option(QCBOR_DISABLE_TAGS                      "Disable all tag encoding and decoding" OFF)
option(QCBOR_DISABLE_EXP_AND_MANTISSA          "Disable big float and decimal fraction tags" OFF)
option(QCBOR_DISABLE_ENCODE_USAGE_GUARDS       "Disable (safely) encoding usage error checking" OFF)
option(QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS "Disable encoding and decoding of indefinite-length strings" OFF)
option(QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS  "Disable encoding and decoding of indefinite-length arrays and maps" OFF)
option(QCBOR_DISABLE_DECODE_CONFORMANCE        "Exclude all decode conformance checking features" OFF)
option(USEFULBUF_DISABLE_STREAMING             "Exclude features for streaming encoding" OFF)

# This is backwards compatibility for float-related cmake options -- decided
# to just make the cmake option the same as the #define
if(DEFINED QCBOR_OPT_DISABLE_PREFERRED_FLOAT)
    set(QCBOR_DISABLE_PREFERRED_FLOAT ${QCBOR_OPT_DISABLE_PREFERRED_FLOAT} CACHE BOOL "xx" FORCE)
endif()

if(DEFINED QCBOR_OPT_DISABLE_ALL_FLOAT)
    set(USEFULBUF_DISABLE_ALL_FLOAT ${QCBOR_OPT_DISABLE_ALL_FLOAT} CACHE BOOL "xx" FORCE)
endif()

if(DEFINED QCBOR_OPT_DISABLE_FLOAT_HW_USE)
    set(QCBOR_DISABLE_FLOAT_HW_USE ${QCBOR_OPT_DISABLE_FLOAT_HW_USE} CACHE BOOL "xx" FORCE)
endif()


if (BUILD_QCBOR_WARN)
    # Compile options applying to all targets in current directory and below
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wcast-qual)
endif()


# =========================================================================
#    building qcbor library 
# =========================================================================

add_library(qcbor)

add_library(qcbor::qcbor ALIAS qcbor)

set_target_properties(
    qcbor PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        POSITION_INDEPENDENT_CODE ON
)

target_sources(qcbor
    PRIVATE
        src/qcbor_main_encode.c
        src/qcbor_number_encode.c
        src/ieee754.c
        src/qcbor_main_decode.c
        src/qcbor_spiffy_decode.c
        src/qcbor_tag_decode.c
        src/qcbor_number_decode.c
        src/qcbor_err_to_str.c
        src/UsefulBuf.c
)

target_compile_definitions(qcbor
    PUBLIC
        $<$<BOOL:${QCBOR_DISABLE_FLOAT_HW_USE}>:QCBOR_DISABLE_FLOAT_HW_USE>
        $<$<BOOL:${QCBOR_DISABLE_PREFERRED_FLOAT}>:QCBOR_DISABLE_PREFERRED_FLOAT>
        $<$<BOOL:${USEFULBUF_DISABLE_ALL_FLOAT}>:USEFULBUF_DISABLE_ALL_FLOAT>
        $<$<BOOL:${QCBOR_DISABLE_NON_INTEGER_LABELS}>:QCBOR_DISABLE_NON_INTEGER_LABELS>
        $<$<BOOL:${QCBOR_DISABLE_TAGS}>:QCBOR_DISABLE_TAGS>
        $<$<BOOL:${QCBOR_DISABLE_EXP_AND_MANTISSA}>:QCBOR_DISABLE_EXP_AND_MANTISSA>
        $<$<BOOL:${QCBOR_DISABLE_ENCODE_USAGE_GUARDS}>:QCBOR_DISABLE_ENCODE_USAGE_GUARDS>
        $<$<BOOL:${QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS}>:QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS>
        $<$<BOOL:${QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS}>:QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS>
        $<$<BOOL:${QCBOR_DISABLE_DECODE_CONFORMANCE}>:QCBOR_DISABLE_DECODE_CONFORMANCE>
        $<$<BOOL:${USEFULBUF_DISABLE_STREAMING}>:USEFULBUF_DISABLE_STREAMING>
)

if (BUILD_SHARED_LIBS AND NOT MSVC)
    target_compile_options(qcbor PRIVATE -Os)
endif()

# Portable handling of the math library, the only special library dependency QCBOR has
if (NOT (USEFULBUF_DISABLE_ALL_FLOAT OR QCBOR_DISABLE_FLOAT_HW_USE) )
    include(CheckSymbolExists)
    check_symbol_exists(pow "math.h" QCBOR_HAVE_MATH)
    if(NOT QCBOR_HAVE_MATH)
        target_link_libraries(qcbor PUBLIC m)
    endif()
endif()

target_include_directories(qcbor
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
        $<INSTALL_INTERFACE:include>
)


# =========================================================================
#    Make the test code
# =========================================================================

if (NOT BUILD_QCBOR_TEST STREQUAL "OFF")
    enable_testing()
    add_subdirectory(test)
endif()


# =========================================================================
#    install qcbor library 
# =========================================================================

include(GNUInstallDirs)

install(
    TARGETS qcbor
    EXPORT qcborTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    DIRECTORY inc/qcbor
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    EXPORT qcborTargets
    NAMESPACE qcbor::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qcbor
)


# =========================================================================
#    install cmake package info
# =========================================================================

include(CMakePackageConfigHelpers)

configure_package_config_file(
    cmake/qcborConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/qcborConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qcbor
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/qcborConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES
        ${CMAKE_CURRENT_BINARY_DIR}/qcborConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/qcborConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/qcbor
)

