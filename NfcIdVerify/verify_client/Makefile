CC=g++
#CC=arm-none-linux-gnueabi-gcc

#LDFLAGS =-L./lib -Wl,-Bdynamic -lpthread -lrt -Wl,-Bstatic -levent -Wl,-Bdynamic

#CFLAGS= -fpermissive

INC= -I./


SRC= *.c
SRC+= *.cpp

#SRC+=src/*.cpp

TARGET = nfc_client


all:$(TARGET)
nfc_client:$(SRC)
	$(CC) -o nfc_client $(SRC) $(INC) $(LDFLAGS) $(CFLAGS)

clean:
	@rm *.o $(TARGET) -f

