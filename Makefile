CC=gcc
CFLAGS=-c -Wall
LIBFLAGS=-lpcap
OBJS=sniffer.o main.o
ARGS=-i wlan0 -c 10 'ip'

all: build exec

build:  $(OBJS)
	$(CC) lib/* -o bin/sniffer.bin $(LIBFLAGS)

main.o: src/main.c
	$(CC) $(CFLAGS) $^ -o lib/$@

sniffer.o: src/sniffer.c
	$(CC) $(CFLAGS) $^ -o lib/$@

clean:
	rm -vf bin/*

cleanall:
	rm -vf bin/* lib/*.o

exec:
	bin/sniffer.bin $(ARGS)
