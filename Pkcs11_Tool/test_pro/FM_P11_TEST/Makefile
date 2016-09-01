CC=gcc



LDFLAGS = -lfmpkcs11  -lpthread
CFLAGS  += -Wno-format

SRC+=*.c
INC= -I./ -I./inc


TARGET=fm_p11_test

all:$(TARGET)
$(TARGET):$(SRC)
	@$(CC) -o $(TARGET)  $(SRC) $(INC) $(LDFLAGS) $(CFLAGS)

clean:
	@rm *.o $(TARGET) -f

