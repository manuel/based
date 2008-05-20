CCFLAGS=-g
LDFLAGS=-levent -lgcrypt

based: dict.o list.o pool.o based.o

clean:
	rm -f dict.o list.o pool.o based.o based *~
