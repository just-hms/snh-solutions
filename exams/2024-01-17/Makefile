CFLAGS=-no-pie -g -z noexecstack -fstack-protector -z relro -z now -O2 -fno-inline -Wno-free-nonheap-object
all: server

server: server.c malloc-2.7.2.c
	gcc $(CFLAGS) -o server server.c

.PHONY: clean
clean:
	rm -f server
