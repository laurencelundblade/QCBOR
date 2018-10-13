CFLAGS=-I inc -I test -Os -Wall -Werror -pedantic-errors -Wextra -Wshadow

QCBOR_OBJ=src/UsefulBuf.o src/qcbor_encode.o src/qcbor_decode.o src/ieee754.o

TEST_OBJ=test/UsefulBuf_Tests.o test/qcbor_encode_tests.o test/qcbor_decode_tests.o test/run_tests.o \
  test/float_tests.o test/half_to_double_from_rfc7049.o

CMD_LINE_OBJ=$(QCBOR_OBJ) $(TEST_OBJ) cmd_line_main.o

qcbortest: $(CMD_LINE_OBJ)
	cc -o $@ $^ $(CFLAGS)

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

cmd_line_main.o:	test/run_tests.h

clean:
	rm $(CMD_LINE_OBJ)
