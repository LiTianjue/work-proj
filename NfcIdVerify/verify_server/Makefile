CC=g++
#CC=arm-none-linux-gnueabi-gcc

LDFLAGS =-L./lib -Wl,-Bdynamic -lpthread -lrt -Wl,-Bstatic -levent -Wl,-Bdynamic -lmysqlclient

#CFLAGS= -fpermissive -g

INC= -I./ -I./inc
INC+= -I ./inc/sm


SRC= src/sm/*.c
# thread_pool
SRC+= src/threadpool.c
SRC+= *.cpp

#SRC+=src/*.cpp

TARGET = nfc_verify


all:$(TARGET)
nfc_verify:$(SRC)
	@$(CC) -o nfc_verify  $(SRC) $(INC) $(LDFLAGS) $(CFLAGS)

clean:
	@rm *.o $(TARGET) -f

