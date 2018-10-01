CFLAGS=-I inc -I test -Os

QCBOR_OBJ=src/UsefulBuf.o src/qcbor_encode.o src/qcbor_decode.o src/ieee754.o

TEST_OBJ=test/basic_test.o test/bstrwrap_tests.o test/run_tests.o test/half_precision_test.o \
  test/half_to_double_from_rfc7049.o

CMD_LINE_OBJ=$(QCBOR_OBJ) $(TEST_OBJ) cmd_line_main.o

qcbortest: $(CMD_LINE_OBJ)
	cc -o $@ $^ $(CFLAGS)

src/UsefulBuf.o:	inc/UsefulBuf.h
src/qcbor_decode.o:	inc/UsefulBuf.h inc/qcbor.h src/ieee754.h
src/qcbor_encode.o:	inc/UsefulBuf.h inc/qcbor.h src/ieee754.h
src/iee754.o:	src/ieee754.h 

test/basic_test.o:	test/basic_test.h inc/qcbor.h inc/UsefulBuf.h
test/bstrwrap_tests.o:	test/bstrwrap_tests.h inc/qcbor.h inc/UsefulBuf.h
test/run_tests.o:	test/half_precision_test.h test/run_tests.h test/basic_test.h test/bstrwrap_tests.h
test/half_precision_test.o:	inc/qcbor.h test/half_precision_test.h test/half_to_double_from_rfc7049.h
test/half_to_double_from_rfc7049.o:	test/half_to_double_from_rfc7049.h

cmd_line_main.o:	test/run_tests.h

clean:
	rm $(CMD_LINE_OBJ)
