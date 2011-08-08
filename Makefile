LIBS=-lpcre -lcrypto -lm -lpthread
CFLAGS=-ggdb -O3 -Wall
OBJS=vanitygen.o oclvanitygen.o pattern.o util.o
PROGS=vanitygen

all: $(PROGS)

vanitygen: vanitygen.o pattern.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

oclvanitygen: oclvanitygen.o pattern.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) -lOpenCL

clean:
	rm -f $(OBJS) $(PROGS) $(TESTS)
