#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>

#define PWNDBG_COMPAT 1
#include "malloc-2.7.2.c"

#ifndef PORT
#define PORT 10000
#endif

#define KEYSZ	    8
#define MAXENTRIES 16
#define MAXVSZ	   120
#define SECRETSZ   37

struct entry {
	char *data;
	int  ksz;
	int  vsz;
};

int readsecret(char *dst, int sz);
struct entry *findempty();
struct entry *search(const char *key, int ksz);
int readsz(char *rest);
int readn(char *p, int n);
int writen(char *p, int n);

struct entry entries[MAXENTRIES];

void cleanup()
{
	int i;

	for (i = 0; i < MAXENTRIES; i++) {
		if (entries[i].data != NULL && entries[i].data[0] != ':') {
			free(entries[i].data);
			entries[i].data = NULL;
			entries[i].ksz = 0;
			entries[i].vsz = 0;
		}
	}
}

void child()
{
	char searchkey[KEYSZ];
	char cmd, sep;
	int i, ksz, vsz;
	struct entry *e;

	memset(entries, 0, sizeof(entries));

	entries[0].data = malloc(KEYSZ + SECRETSZ);
	memcpy(entries[0].data, ":secret0", KEYSZ);
	entries[0].ksz = KEYSZ;
	entries[0].vsz = SECRETSZ;
	readsecret(entries[0].data + KEYSZ, SECRETSZ);

	while (read(0, &cmd, 1) > 0) {
		switch (cmd) {
		case '\n':
			break;
		case 'n':
			e = findempty(entries);
			if (e == NULL)
				break;
			memset(e, 0, sizeof(struct entry));
			ksz = readsz(&sep);
			if (ksz <= 0 || ksz > KEYSZ)
				return;
			if (sep != ',')
				return;
			vsz = readsz(&sep);
			if (sep != '\n' || vsz < 0 || vsz > MAXVSZ)
				return;
			e->data = malloc(ksz + vsz);
			if (e->data == NULL)
				return;
			if (readn(searchkey, ksz) < 0)
				return;
			// v1.1: check for duplicate keys
			// double free
			if (search(searchkey, ksz) != NULL) {
				free(e->data);
				break;
			}
			memcpy(e->data, searchkey, ksz);
			
			if (readn(e->data + ksz, vsz) < 0)
				return;
			e->ksz = ksz;
			e->vsz = vsz;
			break;
		case 's':
			ksz = readsz(&sep);
			if (sep != '\n' || ksz <= 0 || ksz > KEYSZ)
				return;
			if (readn(searchkey, ksz) < 0)
				return;
			if (searchkey[0] == ':')
				return;
			e = search(searchkey, ksz);
			if (e == NULL)
				break;
			if (writen(e->data + ksz, e->vsz) < 0)
				return;
			break;
		case 'c':
			cleanup();
			break;
		}
	}
}

/* NO INTENTIONAL ERRORS STARTING FROM THIS POINT */
int readsecret(char *dst, int sz)
{
	int fd, i;
	char c;

	fd = open("flag.txt", O_RDONLY);
	if (fd < 0)
		return -1;

	for (i = 0; i < sz; i++) {
		if (read(fd, dst, 1) < 0)
			return -1;
		dst++;
	}
	close(fd);
}

struct entry *search(const char *key, int ksz)
{
	struct entry *e;

	for (e = entries; e != entries + MAXENTRIES; e++) {
		if (e->data != NULL && e->ksz == ksz &&
				memcmp(e->data, key, ksz) == 0)
			return e;
	}
	return NULL;
}

struct entry *findempty()
{
	struct entry *e;

	for (e = entries; e != entries + MAXENTRIES; e++) {
		if (e->data == NULL)
			return e;
	}
	return NULL;
}

int readsz(char *sep)
{
	int rv;
	char c;

	rv = 0;
	while (read(0, &c, 1) >= 0) {
		if (c < '0' || c > '9')
			break;
		rv = rv * 10 + (c - '0');
	}
	if (sep != NULL)
		*sep = c;
	return rv;
}

int readn(char *p, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (read(0, p, 1) <= 0)
			return -1;
		p++;
	}
	return 0;
}

int writen(char *p, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (write(1, p, 1) != 1)
			return -1;
		p++;
	}
	return 0;
}


void sigchld(int signo)
{
	int status;
	pid_t pid = waitpid(-1, &status, WNOHANG);
	if (pid > 0) {
		printf("child %ld: ", (long)pid);
		if (WIFEXITED(status)) {
			printf("exited with status: %d\n", WEXITSTATUS(status));
		} else {
			printf("%s\n", strsignal(WTERMSIG(status)));
		}
	}
}

int main()
{
	int lstn;
	int enable;
	struct sockaddr_in lstn_addr;
	char * volatile dummy;

	srand(time(NULL));

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	lstn = socket(AF_INET, SOCK_STREAM, 0);
	if (lstn < 0) {
		perror("socket");
		return 1;
	}
	enable = 1;
	if (setsockopt(lstn, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
		perror("setsockopt");
		return 1;
	}
	bzero(&lstn_addr, sizeof(lstn_addr));

	lstn_addr.sin_family = AF_INET;
	lstn_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	lstn_addr.sin_port = htons(PORT);

	if (bind(lstn, (struct sockaddr *)&lstn_addr, sizeof(lstn_addr)) < 0) {
		perror("bind");
		return 1;
	}

	if (listen(lstn, 10) < 0) {
		perror("listen");
		return 1;
	}
	printf("Listening on port %d\n", PORT);

	signal(SIGCHLD, sigchld);

	for (;;) {
		int con = accept(lstn, NULL, NULL);
		if (con < 0) {
			perror("accept");
			return 1;
		}

		switch (fork()) {
		case -1:
			perror("fork");
			return 1;
		case 0:
			printf("New connection, child %d\n", getpid());

			close(0);
			if (dup(con) < 0)
				goto error;
			close(1);
			if (dup(con) < 0)
				goto error;
			close(2);
			if (dup(con) < 0)
				goto error;
			dummy = malloc(128);
			child();
			free(dummy);
			exit(0);
			break;
		default:
			close(con);
			break;
		}
	}
	return 0;

error:
	fprintf(stderr, "dup() failed\n");
	exit(1);
}
