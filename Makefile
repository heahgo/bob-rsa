CC=gcc
CFLAGS=-g -Wall
OBJS=rsa-test.o rsa.o utilBN.o
TARGET=rsa-test

all: $(TARGET)

clean:
	rm -f $(TARGET)
 
$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) -lssl -lcrypto
	rm -f *.o
