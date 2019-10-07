CC=g++
CFLAGS=-Wall -Werror
all: ans
ans: main.o
	$(CC) $(CFLAGS) $? -o $@
main.o: main.cpp
	$(CC) $(CFLAGS) -c $?
clean:
	rm -rf *.o ans
