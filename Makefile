CFLAGS		:=	-O4 -march=native -Wall
# CFLAGS		:=	-O3

SRCS		:=	vanitygen.c			\
				oclvanitygen.c		\
				oclvanityminer.c	\
				oclengine.c			\
				keyconv.c			\
				pattern.c			\
				util.c
OBJS		:=	$(SRCS:.c=.o)

UTIL_OBJS	:=	pattern.o util.o

PROGS		:=	vanitygen keyconv oclvanitygen oclvanityminer

LIBS		:=	-lpcre -lcrypto -lm -lpthread

PLATFORM	=	$(shell uname -s)
ifeq ($(PLATFORM),Darwin)
OPENCL_LIBS	:=	-framework OpenCL
else
OPENCL_LIBS	:=	-lOpenCL
endif

all:			$(PROGS)

vanitygen:		vanitygen.o $(UTIL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

keyconv:		keyconv.o util.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

oclvanitygen:	oclvanitygen.o oclengine.o $(UTIL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(OPENCL_LIBS)

oclvanityminer:	oclvanityminer.o oclengine.o $(UTIL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(OPENCL_LIBS) -lcurl

clean:
	rm -f $(OBJS) $(PROGS)
