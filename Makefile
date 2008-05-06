LDFLAGS=-levent

based: dict.o md5.o based.o

clean:
	rm -f dict.o md5.o based.o based *~
