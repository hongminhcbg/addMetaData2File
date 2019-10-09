CC=g++
CFLAGS=-Wall -Werror
LIBS=-lcrypto
all: ans encode checkCR
ans: main.o
	$(CC) $(CFLAGS) $? -o $@
encode: main_encode.o encode.o
	$(CC) $(CFLAGS) $? -o $@ $(LIBS)
checkCR: main_CCR.o checkCopyright.o jsmn.o
	$(CC) $(CFLAGS) $? -o $@ $(LIBS)
.cpp.o:
	$(CC) $(CFLAGS) -c $*.cpp
clean:
	rm -rf *.o ans encode decode checkCR *_encode.mp4