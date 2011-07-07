LIBS=-lpcre -lcrypto -lm -lpthread
CFLAGS=-ggdb -O3 -Wall
OBJS=vanitygen.o

vanitygen: $(OBJS)
	$(CC) $(OBJS) -o $@ $(CFLAGS) $(LIBS)

clean:
	rm -f $(OBJS) vanitygen
