#gcc -o test test.c -lcrypto -lsimple_engine

LDFLAG=-lfmpkcs11
INC=-I./inc
TARGET=Create_Key_pair

all:$(TARGET)
$(TARGET):*.c
	gcc -o $(TARGET) *.c $(INC) $(LDFLAG)

clean:
	rm -rf $(TARGET)

