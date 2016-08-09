# maybe a config is required to cross platform


TARGET=libSm4Jni.so
SRC=*.c
JNI_CFLAGS= -I./jni

all: $(TARGET)

$(TARGET): $(SRC)
	gcc -shared -fPIC  $(SRC) -I. $(JNI_CFLAGS)  -o $(TARGET)

clean:
	@rm -f $(TARGET)

test:

