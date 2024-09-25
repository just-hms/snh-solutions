CFLAGS=-g -fstack-protector -fcf-protection=none -z noexecstack -Wno-free-nonheap-object -DPWNDBG_COMPAT=1
LDFLAGS=-L. -Wl,-rpath,.,-dynamic-linker,./ld-linux-x86-64.so.2,--disable-new-dtags
LDLIBS=libc_nonshared.a
all: myheap0 myheap0b myheap1 myheap2 objects1 objects2 myheap1b myheap1c

malloc-2.7.2.so: malloc-2.7.2.c
	gcc $(CFLAGS) -shared -fpic $(LDFLAGS) -o malloc-2.7.2.so malloc-2.7.2.c $(LDLIBS)

malloc-2.7.2-execheap.so: malloc-2.7.2.c
	gcc $(CFLAGS) -shared -fpic $(LDFLAGS) -DMAKE_EXECUTABLE -o malloc-2.7.2-execheap.so malloc-2.7.2.c $(LDLIBS)

myheap0: myheap.c malloc-2.7.2-execheap.so
	gcc $(CFLAGS) -z norelro -no-pie -DHEAP0 -DPORT=4460 $(LDFLAGS) -o myheap0 myheap.c malloc-2.7.2-execheap.so $(LDLIBS)

myheap0b: myheap.c
	gcc $(CFLAGS) -z norelro -no-pie -DMAKE_EXECUTABLE -DHEAP0b -DPORT=4465 -o myheap0b myheap.c

myheap1: myheap.c malloc-2.7.2.so
	gcc $(CFLAGS) -no-pie -z norelro -DHEAP1 -DPORT=4461 $(LDFLAGS) -o myheap1 myheap.c malloc-2.7.2.so $(LDLIBS)

myheap1b: myheap.c malloc-2.7.2.so
	gcc $(CFLAGS) -no-pie -z relro -z now -DHEAP1B -DPORT=4466 $(LDFLAGS) -o myheap1b myheap.c malloc-2.7.2.so $(LDLIBS)
	
myheap1c: myheap.c malloc-2.7.2.c
	gcc $(CFLAGS) -no-pie -z relro -z now -DHEAP1C -DCHECK_DOUBLE_FREE -DPORT=4467 $(LDFLAGS) -o myheap1c myheap.c $(LDLIBS)

myheap2: myheap.c malloc-2.7.2.c
	gcc $(CFLAGS) -no-pie -z relro -z now -DHEAP2 -DPORT=4462 $(LDFLAGS) -o myheap2 myheap.c $(LDLIBS)

objects1: objects.cc malloc-2.7.2.c
	g++ $(CFLAGS) -no-pie -z relro -z now -DOBJECTS -DPORT=4463 $(LDFLAGS) -o objects1 objects.cc $(LDLIBS)

objects2: objects.cc malloc-2.7.2.c
	g++ $(CFLAGS) -pie -z relro -z now -DPORT=4464 -DOBJECTS $(LDFLAGS) -o objects2 objects.cc $(LDLIBS)

.PHONY: clean
clean:
	rm -f myheap? objects? myheap[0-2][a-z] malloc-2.7.2.so
