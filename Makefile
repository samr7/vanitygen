LIBS=-lpcre -lcrypto -lm -lpthread
CFLAGS=-ggdb -O3 -Wall
OBJS=vanitygen.o oclvanitygen.o pattern.o
PROGS=vanitygen
TESTS=

all: $(PROGS)

vanitygen: vanitygen.o pattern.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

oclvanitygen: oclvanitygen.o pattern.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) -lOpenCL

clean:
	rm -f $(OBJS) $(PROGS) $(TESTS)
