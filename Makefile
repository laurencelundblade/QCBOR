# Makefile -- UNIX-style make for qcbor as a lib and command line test
#
# Copyright (c) 2018-2019, Laurence Lundblade. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# See BSD-3-Clause license in README.md
#


CFLAGS=-I inc -I test -Os -Wcast-align -Wall -Werror -pedantic-errors -Wextra -Wshadow -Wparentheses -xc -std=c99

QCBOR_OBJ=src/UsefulBuf.o src/qcbor_encode.o src/qcbor_decode.o src/ieee754.o

TEST_OBJ=test/UsefulBuf_Tests.o test/qcbor_encode_tests.o test/qcbor_decode_tests.o test/run_tests.o \
  test/float_tests.o test/half_to_double_from_rfc7049.o

qcbortest: libqcbor.a $(TEST_OBJ) cmd_line_main.o
	cc -o $@ $^  libqcbor.a

qcbormin: libqcbor.a min_use_main.o
	cc -dead_strip -o $@ $^ libqcbor.a

libqcbor.a: $(QCBOR_OBJ)
	ar -r $@ $^

src/UsefulBuf.o:	inc/UsefulBuf.h
src/qcbor_decode.o:	inc/UsefulBuf.h inc/qcbor.h src/ieee754.h
src/qcbor_encode.o:	inc/UsefulBuf.h inc/qcbor.h src/ieee754.h
src/iee754.o:	src/ieee754.h

test/run_tests.o:	test/UsefulBuf_Tests.h test/float_tests.h test/run_tests.h test/qcbor_encode_tests.h\
    test/qcbor_decode_tests.h
test/UsefulBuf_Tests.o:	test/UsefulBuf_Tests.h inc/qcbor.h inc/UsefulBuf.h
test/qcbor_encode_tests.o:	test/qcbor_encode_tests.h inc/qcbor.h inc/UsefulBuf.h
test/qcbor_decode_tests.o:	test/qcbor_decode_tests.h inc/qcbor.h inc/UsefulBuf.h
test/float_tests.o:	inc/qcbor.h inc/UsefulBuf.h test/float_tests.h test/half_to_double_from_rfc7049.h
test/half_to_double_from_rfc7049.o:	test/half_to_double_from_rfc7049.h

cmd_line_main.o:	test/run_tests.h inc/qcbor.h

min_use_main.o:		inc/qcbor.h inc/UsefulBuf.h

clean:
	rm -f $(QCBOR_OBJ) $(TEST_OBJ) libqcbor.a min_use_main.o cmd_line_main.o
