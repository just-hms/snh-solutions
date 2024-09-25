CFLAGS=-no-pie -g -z noexecstack -fno-stack-protector -z relro -z now -Wno-stringop-overflow -Wl,-rpath=. -Wl,-dynamic-linker=ld-linux.so
all: server

server: server.c
	gcc $(CFLAGS) -o server server.c

.PHONY: clean
clean:
	rm -f server
