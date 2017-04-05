CC=gcc
CFLAGS=-c -Wall
LIBFLAGS=-lpcap
OBJS=sniffer.o main.o

all: build

build:  $(OBJS)
	$(CC) lib/* -o bin/sniffer.bin $(LIBFLAGS)

main.o: src/main.c
	$(CC) $(CFLAGS) $^ -o lib/$@

sniffer.o: src/sniffer.c
	$(CC) $(CFLAGS) $^ -o lib/$@

clean:
	rm -vf bin/*
	rm -vf lib/*.o
