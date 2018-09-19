CFLAGS=-I inc -I test -Os

QCBOR_OBJ=src/UsefulBuf.o src/qcbor_encode.o src/qcbor_decode.o 
TEST_OBJ=test/basic_test.o
CMD_LINE_OBJ=$(QCBOR_OBJ) $(TEST_OBJ) cmd_line_main.o

qcbortest: $(CMD_LINE_OBJ)
	cc -o $@ $^ $(CFLAGS)

src/UsefulBuf.o:	inc/UsefulBuf.h
src/qcbor_decode.o:	inc/UsefulBuf.h inc/qcbor.h
src/qcbor_encode.o:	inc/UsefulBuf.h inc/qcbor.h
test/basic_test.o:	test/basic_test.h inc/qcbor.h inc/UsefulBuf.h
cmd_line_main.o:	test/basic_test.h

clean:
	rm $(CMD_LINE_OBJ)
