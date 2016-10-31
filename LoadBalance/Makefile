CC=gcc
#CFLAGS=-Wall -O3
CFLAGS= -O3


PREFIX=/usr
BIN_DIR = $(PREFIX)/bin

SRC_DIR = src
CFILES = $(wildcard $(SRC_DIR)/*.c)
OFILES = $(CFILES:%.c=%.o)

CFLAGS+=-I./inc


all : LoadBalance

LoadBalance: $(OFILES)
	$(CC) $(OFILES) -o LoadBalance $(CFLAGS)


%.o: $(SRC_DIR)/%.c
	$(CC) -c $(CFLAGS) $<


install: LoadBalance
	@echo "installing LoadBalance to '$(BIN_DIR)'"
	@install -d -m 755 $(BIN_DIR)
	@install -m 755 LoadBalance $(BIN_DIR)


clean:
	@echo "cleaning up"
	@rm -f LoadBalance
	@rm -f $(SRC_DIR)/*.o

uninstall:
	@echo "uninstalling"
	@rm $(BIN_DIR)/LoadBalance
