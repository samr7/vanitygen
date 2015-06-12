LIBS= -lpcre -lcrypto -lm -lpthread
OBJS=vanitygen.o oclvanitygen.o oclvanityminer.o oclengine.o keyconv.o pattern.o util.o
PROGS=vanitygen keyconv oclvanitygen oclvanityminer

PLATFORM=$(shell uname -s)
ifeq ($(PLATFORM),Darwin)
OPENCL_LIBS=-framework OpenCL
INCPATHS=-I$(shell brew --prefix)/include -I$(shell brew --prefix openssl)/include
LIBPATHS=-L$(shell brew --prefix)/lib -L$(shell brew --prefix openssl)/lib
CFLAGS=-ggdb -O3 -Wall -Qunused-arguments $(INCPATHS) $(LIBPATHS)
else
OPENCL_LIBS=-lOpenCL
CFLAGS=-ggdb -O3 -Wall
endif


most: vanitygen keyconv

all: $(PROGS)

vanitygen: vanitygen.o pattern.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

oclvanitygen: oclvanitygen.o oclengine.o pattern.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(OPENCL_LIBS)

oclvanityminer: oclvanityminer.o oclengine.o pattern.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(OPENCL_LIBS) -lcurl

keyconv: keyconv.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

clean:
	rm -f $(OBJS) $(PROGS) $(TESTS)
