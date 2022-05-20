cmake_minimum_required(VERSION 3.10.2)
project(qcbor
	DESCRIPTION "QCBOR"
	LANGUAGES C
	VERSION 1.0.0)

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
