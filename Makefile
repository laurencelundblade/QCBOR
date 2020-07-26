# Makefile -- UNIX-style make for qcbor as a lib and command line test
#
# Copyright (c) 2018-2020, Laurence Lundblade. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
# See BSD-3-Clause license in README.md
#

CC=cc
#CC=/usr/local/bin/gcc-9

CFLAGS=-I inc -I test -Os -fPIC

# The following are used before a release of QCBOR help to make sure
# the code compiles and runs in the most strict environments, but not
# all compilers support them so they are not turned on.
#CFLAGS=-I inc -I test -Os -fpic -Wall -pedantic-errors -Wextra -Wshadow -Wparentheses -Wconversion -xc -std=c99


QCBOR_OBJ=src/UsefulBuf.o src/qcbor_encode.o src/qcbor_decode.o src/ieee754.o src/qcbor_err_to_str.o

TEST_OBJ=test/UsefulBuf_Tests.o test/qcbor_encode_tests.o \
    test/qcbor_decode_tests.o test/run_tests.o \
    test/float_tests.o test/half_to_double_from_rfc7049.o example.o

.PHONY: all so install uninstall clean

all: qcbortest libqcbor.a

so:	libqcbor.so

qcbortest: libqcbor.a $(TEST_OBJ) cmd_line_main.o
	$(CC) -o $@ $^  libqcbor.a

libqcbor.a: $(QCBOR_OBJ)
	ar -r $@ $^

# The shared library is not made by default because of platform
# variability For example MacOS and Linux behave differently and some
# IoT OS's don't support them at all.
libqcbor.so: $(QCBOR_OBJ)
	$(CC) -shared $^ $(CFLAGS) -o $@

PUBLIC_INTERFACE=inc/qcbor/UsefulBuf.h inc/qcbor/qcbor_private.h inc/qcbor/qcbor_common.h inc/qcbor/qcbor_encode.h inc/qcbor/qcbor_decode.h

src/UsefulBuf.o: inc/qcbor/UsefulBuf.h
src/qcbor_decode.o: inc/qcbor/UsefulBuf.h inc/qcbor/qcbor_private.h inc/qcbor/qcbor_common.h inc/qcbor/qcbor_encode.h src/ieee754.h
src/qcbor_encode.o: inc/qcbor/UsefulBuf.h inc/qcbor/qcbor_private.h inc/qcbor/qcbor_common.h inc/qcbor/qcbor_decode.h src/ieee754.h
src/iee754.o: src/ieee754.h
src/qcbor_err_to_str.o: inc/qcbor/qcbor_common.h

example.o:	$(PUBLIC_INTERFACE)

test/run_tests.o: test/UsefulBuf_Tests.h test/float_tests.h test/run_tests.h test/qcbor_encode_tests.h test/qcbor_decode_tests.h inc/qcbor/qcbor_private.h
test/UsefulBuf_Tests.o: test/UsefulBuf_Tests.h inc/qcbor/UsefulBuf.h
test/qcbor_encode_tests.o: test/qcbor_encode_tests.h $(PUBLIC_INTERFACE)
test/qcbor_decode_tests.o: test/qcbor_decode_tests.h $(PUBLIC_INTERFACE)
test/float_tests.o: test/float_tests.h test/half_to_double_from_rfc7049.h $(PUBLIC_INTERFACE)
test/half_to_double_from_rfc7049.o: test/half_to_double_from_rfc7049.h

cmd_line_main.o: test/run_tests.h $(PUBLIC_INTERFACE)


ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

install: libqcbor.a $(PUBLIC_INTERFACE)
	install -d $(DESTDIR)$(PREFIX)/lib/
	install -m 644 libqcbor.a $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/qcbor
	install -m 644 inc/qcbor/qcbor.h $(DESTDIR)$(PREFIX)/include/qcbor
	install -m 644 inc/qcbor/qcbor_private.h $(DESTDIR)$(PREFIX)/include/qcbor
	install -m 644 inc/qcbor/qcbor_common.h $(DESTDIR)$(PREFIX)/include/qcbor
	install -m 644 inc/qcbor/qcbor_decode.h $(DESTDIR)$(PREFIX)/include/qcbor
	install -m 644 inc/qcbor/qcbor_encode.h $(DESTDIR)$(PREFIX)/include/qcbor
	install -m 644 inc/qcbor/UsefulBuf.h $(DESTDIR)$(PREFIX)/include/qcbor

install_so: libqcbor.so
	install -m 755 libqcbor.so $(DESTDIR)$(PREFIX)/lib/libqcbor.so.1.0.0
	ln -sf libqcbor.so.1 $(DESTDIR)$(PREFIX)/lib/libqcbor.so
	ln -sf libqcbor.so.1.0.0 $(DESTDIR)$(PREFIX)/lib/libqcbor.so.1

uninstall: libqcbor.a $(PUBLIC_INTERFACE)
	$(RM) -d $(DESTDIR)$(PREFIX)/include/qcbor/*
	$(RM) -d $(DESTDIR)$(PREFIX)/include/qcbor/
	$(RM) $(addprefix $(DESTDIR)$(PREFIX)/lib/, \
		libqcbor.a libqcbor.so libqcbor.so.1 libqcbor.so.1.0.0)

clean:
	rm -f $(QCBOR_OBJ) $(TEST_OBJ) libqcbor.a cmd_line_main.o libqcbor.a libqcbor.so qcbormin qcbortest
