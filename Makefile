LIBS=-lpcre -lcrypto -lm -lpthread
CFLAGS=-ggdb -O3 -Wall
OBJS=vanitygen.o oclvanitygen.o oclbntest.o pattern.o util.o
PROGS=vanitygen oclvanitygen keytool
TESTS=oclhbntest

all: $(PROGS) $(TESTS)

vanitygen: vanitygen.o pattern.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

keytool: keytool.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

oclvanitygen: oclvanitygen.o pattern.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) -lOpenCL

oclhbntest.o: oclhbntest.c calc_addrs.cl
	$(CC) -c $< -o $@ $(CFLAGS) -m32

oclhbntest: oclhbntest.o
	$(CC) $^ -o $@ $(CFLAGS) -m32 libcrypto32.a -lz -ldl -lpthread

clean:
	rm -f $(OBJS) $(PROGS) $(TESTS)
