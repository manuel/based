CCFLAGS=-g -O0 -Wall
LDFLAGS=-levent

based: dict.o list.o pool.o based.o

clean:
	rm -f dict.o list.o pool.o based.o based *~
