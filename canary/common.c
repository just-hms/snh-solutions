#include <sys/mman.h>
#include <stdio.h>

#define BUFSZ 1024

int printflag()
{
	char buf[BUFSZ], *scan = buf;

	FILE *flag = fopen("flag.txt", "r");
	if (flag == NULL) {
		perror("flag.txt");
		return -1;
	}

	if (fgets(buf, BUFSZ, flag) == NULL) {
		perror("flag.txt");
		return -1;
	}

	printf("Here is the flag:\n");
	while (*scan)	
		printf("%c", *scan++);

	return 0;
}

extern void *etext, *end;
void __attribute__((constructor)) make_executable()
{
	unsigned long v = (unsigned long)&etext;
	unsigned long e = (unsigned long)&end;

	v &= ~0xFFF;
	e = ((e - 1) & ~0xFFF) + 4096;

	if (mprotect((void *)v, e - v, PROT_EXEC | PROT_READ | PROT_WRITE) < 0) {
		perror("mmap");
	}
}
