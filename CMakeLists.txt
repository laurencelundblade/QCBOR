cmake_minimum_required(VERSION 3.15)

project(qcbor
    DESCRIPTION "QCBOR"
    LANGUAGES C
    VERSION 1.1.0
)

set(BUILD_QCBOR_TEST  "OFF"  CACHE STRING "Build QCBOR test suite [OFF, LIB, APP]")
set(BUILD_QCBOR_WARN   OFF   CACHE BOOL   "Compile with the warning flags used in the QCBOR release process")
# BUILD_SHARED_LIBS is a built-in global CMake flag
#    The shared library is not made by default because of platform
#    variability For example MacOS and Linux behave differently and some
#    IoT OS's don't support them at all.
set(BUILD_SHARED_LIBS  OFF   CACHE BOOL   "Build shared libraries instead of static ones")

if (BUILD_QCBOR_WARN)
    # Compile options applying to all targets in current directory and below
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wcast-qual)
endif()

add_library(qcbor)

target_sources(qcbor
    PRIVATE
        src/ieee754.c
        src/qcbor_decode.c
        src/qcbor_encode.c
        src/qcbor_err_to_str.c
        src/UsefulBuf.c
)

target_include_directories(qcbor
    PUBLIC
        inc
    PRIVATE
        src
)

if (BUILD_SHARED_LIBS)
    target_compile_options(qcbor PRIVATE -Os -fPIC)
endif()

# The math library is needed for floating-point support.
# To avoid need for it #define QCBOR_DISABLE_FLOAT_HW_USE
target_link_libraries(qcbor PRIVATE m)

if (NOT BUILD_QCBOR_TEST STREQUAL "OFF")
    add_subdirectory(test)
endif()
