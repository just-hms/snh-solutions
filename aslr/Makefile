DISABLE=-fno-stack-protector -fcf-protection=none -z norelro -Wno-format-security -Wno-stringop-overflow

all: aslr0 aslr1 aslr2

aslr0: aslr.c
	gcc -g $(DISABLE) -no-pie -DASLR0 -DPORT=4440 -o aslr0 aslr.c

aslr1: aslr.c
	gcc -g $(DISABLE) -no-pie -DASLR1 -DPORT=4441 -o aslr1 aslr.c

aslr2: aslr.c
	gcc -g $(DISABLE) -pie    -DASLR2 -DPORT=4442 -o aslr2 aslr.c

.PHONY: clean
clean:
	rm -f aslr?
