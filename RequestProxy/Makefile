CC=gcc
#CFLAGS=-Wall -O3
CFLAGS= -g 
LDFLAGS= -lm


PREFIX=/usr
BIN_DIR = $(PREFIX)/bin

SRC_DIR = src
CFILES = $(wildcard $(SRC_DIR)/*.c)
CFILES += $(wildcard $(SRC_DIR)/json/*.c)
OFILES = $(CFILES:%.c=%.o)

CFLAGS+=-I./inc


all : RequestProxy

RequestProxy: $(OFILES)
	$(CC) $(OFILES) -o RequestProxy $(CFLAGS) $(LDFLAGS)


%.o: $(SRC_DIR)/%.c
	$(CC) -c $(CFLAGS) $<


install: RequestProxy
	@echo "installing RequestProxy to '$(BIN_DIR)'"
	@install -d -m 755 $(BIN_DIR)
	@install -m 755 RequestProxy $(BIN_DIR)


clean:
	@echo "cleaning up"
	@rm -f RequestProxy
	@rm -f $(SRC_DIR)/*.o

uninstall:
	@echo "uninstalling"
	@rm $(BIN_DIR)/RequestProxy
