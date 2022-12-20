cmake_minimum_required(VERSION 3.15)

# Validate value of BUILD_QCBOR_TEST config option
if ((NOT BUILD_QCBOR_TEST STREQUAL "LIB") AND (NOT BUILD_QCBOR_TEST STREQUAL "APP"))
    message(FATAL_ERROR "QCBOR | Invalid Config: BUILD_QCBOR_TEST=${BUILD_QCBOR_TEST}")
endif()

add_library(qcbor_test STATIC)

target_sources(qcbor_test
    PRIVATE
        float_tests.c
        half_to_double_from_rfc7049.c
        qcbor_decode_tests.c
        qcbor_encode_tests.c
        run_tests.c
        UsefulBuf_Tests.c
)

target_include_directories(qcbor_test
    PUBLIC
        .
    PRIVATE
        ../inc
)

target_link_libraries(qcbor_test
    PRIVATE
        qcbor
        # The math library is needed for floating-point support.
        # To avoid need for it #define QCBOR_DISABLE_FLOAT_HW_USE
        m
)

if (BUILD_QCBOR_TEST STREQUAL "APP")
    add_executable(qcbortest)

    target_sources(qcbortest
        PRIVATE
            ../cmd_line_main.c
            ../example.c
            ../ub-example.c
    )

    target_include_directories(qcbortest
        PRIVATE
            ../
    )

    target_link_libraries(qcbortest
        PRIVATE
            qcbor
            qcbor_test
    )
endif()
