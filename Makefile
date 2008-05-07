CCFLAGS=-g -O0
LDFLAGS=-levent

based: dict.o based.o

clean:
	rm -f dict.o based.o based *~
