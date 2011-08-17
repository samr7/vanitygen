LIBS=-lpcre -lcrypto -lm -lpthread
CFLAGS=-ggdb -O3 -Wall
OBJS=vanitygen.o oclvanitygen.o keyconv.o pattern.o util.o
PROGS=vanitygen keyconv

all: $(PROGS)

vanitygen: vanitygen.o pattern.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

oclvanitygen: oclvanitygen.o pattern.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) -lOpenCL

keyconv: keyconv.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

clean:
	rm -f $(OBJS) $(PROGS) $(TESTS)
