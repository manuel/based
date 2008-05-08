LDFLAGS=-levent

based: dict.o list.o pool.o util.o based.o

clean:
	rm -f dict.o list.o pool.o util.o based.o based *~
