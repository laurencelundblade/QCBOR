#-------------------------------------------------------------------------------
# Copyright (c) 2022-2023, Arm Limited. All rights reserved.
# Copyright (c) 2024-2026, Laurence Lundblade. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# See BSD-3-Clause license in README.md
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)

# Validate value of BUILD_QCBOR_TEST config option
if (NOT (BUILD_QCBOR_TEST STREQUAL "LIB" OR BUILD_QCBOR_TEST STREQUAL "APP"))
    message(FATAL_ERROR "QCBOR | Invalid Config: BUILD_QCBOR_TEST=${BUILD_QCBOR_TEST}")
endif()

add_library(qcbor_test_lib STATIC)

target_sources(qcbor_test_lib
    PRIVATE
        float_tests.c
        half_to_double_from_rfc7049.c
        qcbor_decode_tests.c
        qcbor_encode_tests.c
        run_tests.c
        UsefulBuf_Tests.c
)

target_link_libraries(qcbor_test_lib
    PRIVATE
        qcbor
)

target_include_directories(qcbor
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_compile_definitions(qcbor_test_lib
    PRIVATE
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

# Portable handling of the math library, the only special library dependency QCBOR has
if (NOT (USEFULBUF_DISABLE_ALL_FLOAT OR QCBOR_DISABLE_FLOAT_HW_USE) )
    include(CheckSymbolExists)
    check_symbol_exists(ldexp "math.h" QCBOR_TEST_HAVE_MATH)
    if(NOT QCBOR_TEST_HAVE_MATH)
        target_link_libraries(qcbor_test_lib PUBLIC m)
    endif()
endif()


if (BUILD_QCBOR_TEST STREQUAL "APP")
    add_executable(qcbortest)

    target_sources(qcbortest
        PRIVATE
            ../cmd_line_main.c
            ../example.c
            ../tag-examples.c
            ../ub-example.c
    )

    target_link_libraries(qcbortest
        PRIVATE
            qcbor
            qcbor_test_lib
    )

    message(STATUS "Adding test qcbortest")
    add_test(
        NAME qcbortest
        COMMAND qcbortest
    )
endif()
