#  Copyright (c) 2018, Laurence Lundblade.
#  All rights reserved.
#  
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#     * The name "Laurence Lundblade" may not be used to
#       endorse or promote products derived from this software without
#       specific prior written permission.
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
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

CFLAGS=-I inc -I test -Os -Wall -Werror -pedantic-errors -Wextra -Wshadow -Wparentheses -xc -std=c99

QCBOR_OBJ=src/UsefulBuf.o src/qcbor_encode.o src/qcbor_decode.o src/ieee754.o 

TEST_OBJ=test/UsefulBuf_Tests.o test/qcbor_encode_tests.o test/qcbor_decode_tests.o test/run_tests.o \
  test/float_tests.o test/half_to_double_from_rfc7049.o 

qcbortest: libqcbor.a $(TEST_OBJ) cmd_line_main.o
	cc -o $@ $^  libqcbor.a

qcbormin: libqcbor.a min_use_main.o
	cc -dead_strip -o $@ $^ libqcbor.a

libqcbor.a: $(QCBOR_OBJ2)
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
	rm -f $(QCBOR_OBJ2) $(TEST_OBJ) libqcbor.a
