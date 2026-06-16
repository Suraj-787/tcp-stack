CC = gcc
CFLAGS = -Wall -Wextra -g
SRCS = main.c tcp.c ip.c checksum.c utils.c
OBJS = $(SRCS:.c=.o)
TARGET = tcp_stack

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test_retransmit: tests/test_retransmit.o tcp.o ip.o checksum.o utils.o
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJS) $(TARGET) tests/test_retransmit.o test_retransmit

.PHONY: all clean
