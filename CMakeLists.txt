#-------------------------------------------------------------------------------
# Copyright (c) 2022-2023, Arm Limited. All rights reserved.
# Copyright (c) 2024-2026, Laurence Lundblade. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# See BSD-3-Clause license in README.md
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)

# Also update the QCBOR version in qcbor_common.h, qcbor.spec and CHANGELOG.md

project(qcbor
    DESCRIPTION "A CBOR encoder/decoder library"
    LANGUAGES C
    VERSION 1.7.0
)

include(GNUInstallDirs)


# SOVERSION gets incremented most releases. QCBOR uses a lot of inlined
# functions that depend on semi-private functions in the shared
# library. For example, QCBOREncode_AddText() depends on
# QCBOREncode_Private_AddBuffer(). SOVERSION must change when
# functions like QCBOREncode_Private_AddBuffer() change their API or
# minutely change their semantics. Generally, only leave this
# unchanged for small releases where it is obvious there is no ABI
# change.
#
# The range of SOVERSION for QCBOR 1.x is 1..19. The range for QCBOR
# 2.x.x is 20...
set(QCBOR_SOVERSION 2)


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
set(QCBOR_MAX_ARRAY_NESTING 35 CACHE STRING    "Set maximum array/map nesting allowed")
set(QCBOR_NUM_MAPPED_TAGS 4 CACHE STRING       "Set maximum distinct tag numbers greater than QCBOR_LAST_UNMAPPED_TAG (typically 65,530)")
set(QCBOR_MAX_TAGS_PER_ITEM 4 CACHE STRING     "Set maximum number of tag numbers that may be nested on a single CBOR item")

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
#    Generate qcbor_config.h
# =========================================================================

# The configuration selected above is recorded in a generated
# qcbor_config.h rather than passed as one -D per option. The
# generated file is installed as qcbor/qcbor_config.h, so code that
# uses the installed library always sees the configuration the library
# was built with and needs no compile definitions.
#
# Within this build tree the generated file is selected by the single
# compile definition QCBOR_CONFIG_FILE, set to the file's absolute path
# (see target_compile_definitions() below). The QCBOR headers do
# "#include QCBOR_CONFIG_FILE" when it is defined. An absolute path
# involves no include-path search, so the result is the same with every
# compiler. Relying on include-path order is not enough: MSVC searches
# the directories of parent include files before the /I paths, which
# can find the checked-in file first.
#
# The checked-in inc/qcbor/qcbor_config.h is the default for builds
# that don't use CMake. CMake builds don't read it or install it.

# To add an option, add the option() or set(... CACHE ...) above and
# then add its name to the matching list here.
set(QCBOR_CONFIG_DISABLES
    QCBOR_DISABLE_FLOAT_HW_USE
    QCBOR_DISABLE_PREFERRED_FLOAT
    USEFULBUF_DISABLE_ALL_FLOAT
    QCBOR_DISABLE_NON_INTEGER_LABELS
    QCBOR_DISABLE_TAGS
    QCBOR_DISABLE_EXP_AND_MANTISSA
    QCBOR_DISABLE_ENCODE_USAGE_GUARDS
    QCBOR_DISABLE_INDEFINITE_LENGTH_STRINGS
    QCBOR_DISABLE_INDEFINITE_LENGTH_ARRAYS
)

set(QCBOR_CONFIG_VALUES
    QCBOR_MAX_ARRAY_NESTING
    QCBOR_NUM_MAPPED_TAGS
    QCBOR_MAX_TAGS_PER_ITEM
)

set(QCBOR_GENERATED_INC_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
set(QCBOR_CONFIG_H ${QCBOR_GENERATED_INC_DIR}/qcbor/qcbor_config.h)

set(QCBOR_CONFIG_H_TEXT
"/* Generated by CMake from the QCBOR build configuration. Do not edit.
 * To change the configuration, re-run cmake with different options.
 */
#ifndef qcbor_config_h
#define qcbor_config_h

")

# Each disable is wrapped in #ifndef because a -D with no value on the
# command line defines the macro as 1. Without the #ifndef, code that
# still gives one of these as a -D gets a macro redefinition warning.
foreach(QCBOR_CONFIG_ITEM IN LISTS QCBOR_CONFIG_DISABLES)
    if(${QCBOR_CONFIG_ITEM})
        string(APPEND QCBOR_CONFIG_H_TEXT
            "#ifndef ${QCBOR_CONFIG_ITEM}\n#define ${QCBOR_CONFIG_ITEM}\n#endif\n\n")
    endif()
endforeach()

foreach(QCBOR_CONFIG_ITEM IN LISTS QCBOR_CONFIG_VALUES)
    string(APPEND QCBOR_CONFIG_H_TEXT "#define ${QCBOR_CONFIG_ITEM} ${${QCBOR_CONFIG_ITEM}}\n")
endforeach()

string(APPEND QCBOR_CONFIG_H_TEXT "\n#endif /* qcbor_config_h */\n")

# Only write the file when its content changes so that re-running cmake
# with the same configuration doesn't cause everything to recompile.
set(QCBOR_CONFIG_H_OLD_TEXT "")
if(EXISTS ${QCBOR_CONFIG_H})
    file(READ ${QCBOR_CONFIG_H} QCBOR_CONFIG_H_OLD_TEXT)
endif()
if(NOT QCBOR_CONFIG_H_TEXT STREQUAL QCBOR_CONFIG_H_OLD_TEXT)
    file(WRITE ${QCBOR_CONFIG_H} "${QCBOR_CONFIG_H_TEXT}")
endif()


# =========================================================================
#    building qcbor library 
# =========================================================================

add_library(qcbor)

add_library(qcbor::qcbor ALIAS qcbor)

set_target_properties(
    qcbor PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${QCBOR_SOVERSION}
        POSITION_INDEPENDENT_CODE ON
)

target_sources(qcbor
    PRIVATE
        src/qcbor_encode.c
        src/ieee754.c
        src/qcbor_decode.c
        src/qcbor_err_to_str.c
        src/UsefulBuf.c
)

# In some rare environments, this may unnecessarily link libm, but this
# config is far simpler than trying detect which lib supports the needed
# math functions and most targets do fine with -lm.
if(NOT (USEFULBUF_DISABLE_ALL_FLOAT OR QCBOR_DISABLE_FLOAT_HW_USE))
    if(NOT MSVC)
        target_link_libraries(qcbor PUBLIC m)
        set(QCBOR_PC_LIBS_PRIVATE "-lm")
    endif()
endif()

# Select the generated configuration for qcbor and for everything in
# this build tree that links to it: the tests and projects that use
# add_subdirectory() or FetchContent. It is BUILD_INTERFACE only; the
# installed package needs no definition because the generated file is
# installed as qcbor/qcbor_config.h.
target_compile_definitions(qcbor
    PUBLIC
        "$<BUILD_INTERFACE:QCBOR_CONFIG_FILE=\"${QCBOR_CONFIG_H}\">"
)

target_include_directories(qcbor
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
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


install(
    TARGETS qcbor
    EXPORT qcborTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# The generated qcbor_config.h is installed, not the checked-in one
install(
    DIRECTORY inc/qcbor
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PATTERN "qcbor_config.h" EXCLUDE
)

install(
    FILES ${QCBOR_CONFIG_H}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qcbor
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


# =========================================================================
#    install pkg-config file
# =========================================================================
configure_file(cmake/qcbor.pc.in cmake/qcbor.pc @ONLY)
install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/cmake/qcbor.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
