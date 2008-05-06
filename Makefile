LDFLAGS=-levent

based: dict.o based.o

clean:
	rm -f based based.o dict.o
