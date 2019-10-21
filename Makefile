CC=g++
CFLAGS=-Wall -Werror
LIBS=-lcrypto
all: encode checkCR
encode: main_encode.o encode.o
	$(CC) $(CFLAGS) $? -o $@ $(LIBS)
checkCR: main_CCR.o checkCopyright.o jsmn.o
	$(CC) $(CFLAGS) $? -o $@ $(LIBS)
.cpp.o:
	$(CC) $(CFLAGS) -c $*.cpp
clean:
	rm -rf *.o ans encode decode checkCR *_encode.mp4