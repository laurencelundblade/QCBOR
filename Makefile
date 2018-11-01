# Copyright (c) 2018, Laurence Lundblade.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials provided
# with the distribution.
# * Neither the name of The Linux Foundation nor the names of its
# contributors, nor the name "Laurence Lundblade" may be used to
# endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


CFLAGS=-I inc -I test -Os -Wall -Werror -pedantic-errors -Wextra -Wshadow

QCBOR_OBJ=src/UsefulBuf.o src/qcbor_encode.o src/qcbor_decode.o src/ieee754.o 
QCBOR_OBJ2=$(QCBOR_OBJ) src/qcbor_decode_malloc.o

TEST_OBJ=test/UsefulBuf_Tests.o test/qcbor_encode_tests.o test/qcbor_decode_tests.o test/run_tests.o \
  test/float_tests.o test/half_to_double_from_rfc7049.o test/qcbor_decode_malloc_tests.o

CMD_LINE_OBJ=$(QCBOR_OBJ2) $(TEST_OBJ) cmd_line_main.o

qcbortest: $(CMD_LINE_OBJ)
	cc -o $@ $^ $(CFLAGS)

qcbormin: $(QCBOR_OBJ) min_use_main.c
	cc -dead_strip -o $@ $^ $(CFLAGS)

src/UsefulBuf.o:	inc/UsefulBuf.h
src/qcbor_decode.o:	inc/UsefulBuf.h inc/qcbor.h src/ieee754.h
src/qcbor_encode.o:	inc/UsefulBuf.h inc/qcbor.h src/ieee754.h
src/iee754.o:	src/ieee754.h 
src/qcbor_malloc_decode.o:	inc/qcbor.h

test/run_tests.o:	test/UsefulBuf_Tests.h test/float_tests.h test/run_tests.h test/qcbor_encode_tests.h\
    test/qcbor_decode_tests.h test/qcbor_decode_malloc_tests.h
test/UsefulBuf_Tests.o:	test/UsefulBuf_Tests.h inc/qcbor.h inc/UsefulBuf.h
test/qcbor_encode_tests.o:	test/qcbor_encode_tests.h inc/qcbor.h inc/UsefulBuf.h
test/qcbor_decode_tests.o:	test/qcbor_decode_tests.h inc/qcbor.h inc/UsefulBuf.h
test/float_tests.o:	inc/qcbor.h inc/UsefulBuf.h test/float_tests.h test/half_to_double_from_rfc7049.h
test/half_to_double_from_rfc7049.o:	test/half_to_double_from_rfc7049.h
test/qcbor_decode_malloc_test.o:	test/qcbor_decode_malloc_tests.h

cmd_line_main.o:	test/run_tests.h

min_use_main.o:		inc/qcbor.h inc/UsefulBuf.h

clean:
	rm $(CMD_LINE_OBJ)
