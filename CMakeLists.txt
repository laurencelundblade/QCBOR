cmake_minimum_required(VERSION 3.10.2)
project(qcbor
	DESCRIPTION "QCBOR"
	LANGUAGES C
	VERSION 1.0.0)

set(BUILD_TESTS ON CACHE BOOL "Build tests")

add_library(qcbor STATIC)

target_sources(qcbor
	PRIVATE
		src/ieee754.c
		src/qcbor_decode.c
		src/qcbor_encode.c
		src/qcbor_err_to_str.c
		src/UsefulBuf.c
) 

target_include_directories(qcbor PUBLIC inc)

if (BUILD_TESTS)
	add_library(qcbor_test STATIC EXCLUDE_FROM_ALL)

	target_sources(qcbor_test
		PRIVATE
			${QCBOR_PATH}/test/float_tests.c
			${QCBOR_PATH}/test/half_to_double_from_rfc7049.c
			${QCBOR_PATH}/test/qcbor_decode_tests.c
			${QCBOR_PATH}/test/qcbor_encode_tests.c
			${QCBOR_PATH}/test/run_tests.c
			${QCBOR_PATH}/test/UsefulBuf_Tests.c
	)

	target_include_directories(qcbor_test
		PUBLIC
			$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/test>
		PRIVATE
			$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/inc>
	)

	target_link_libraries(qcbor_test
		PRIVATE
			qcbor
	)
endif()

