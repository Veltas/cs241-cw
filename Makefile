BINARY = idsniff
OBJS   = $(patsubst %.c,%.o,$(wildcard *.c))

CC     = gcc
CFLAGS = -g -DDEBUG -Wall -W
LDLIBS = -lpcap -lpthread

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

.PHONY: clean
clean:
	rm -f *.o $(BINARY)
