#include <linux/limits.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#define OBJECTS
#define PWNDBG_COMPAT
#include "malloc-2.7.2.c"

#ifndef PORT
#define PORT 10000
#endif

#define MAXLINE 1024
#define ARGSZ 0xf0
#define MAXOBJ 32

struct Obj {
	size_t offset;
	char arg[ARGSZ];
};

struct objentry {
	struct Obj *obj;
	unsigned int perms;
#define P_READ		(1U << 0)
#define P_WRITE 	(1U << 1)
};

struct objentry objects[MAXOBJ];

int findfree();
void EchoObj_init(struct Obj *obj);
void SecretObj_init(struct Obj *obj);
void do_newobj(const char *buf)
{
	int pos, num;
	char type;
	struct Obj *obj;

	pos = findfree();
	if (pos >= MAXOBJ) {
		fprintf(stderr, "full\n");
		return;
	}
	type = *buf++;
	if (type == '\0') {
		fprintf(stderr, "missing object type\n");
		return;
	}
	if ( (obj = malloc(sizeof(*obj))) == NULL) {
		fprintf(stderr, "out of memory\n");
		return;
	}
	switch (type) {
	case 'e':
		objects[pos].perms = P_READ|P_WRITE;
		EchoObj_init(obj);
		break;
	case 's':
		objects[pos].perms = 0;
		SecretObj_init(obj);
		break;
	default:
		fprintf(stderr, "invalid type\n");
		free(obj);
		return;
	}
	objects[pos].obj = obj;

	// moooolto strano
	printf("%d\t%p\n", pos, obj);
}


int Obj_write(struct Obj *obj, const char *a)
{
	size_t l = strlen(a);
	if (l > (ARGSZ - obj->offset))
		return 0;
	
	// moooolto strano, scrive '\0'
	strcpy(obj->arg + obj->offset, a);
	obj->offset += l + 1;
	return 1;
}

void Obj_read(struct Obj *obj)
{
	size_t i = 0;
	while (i < obj->offset) {
		size_t l = strlen(obj->arg + i);
		printf("%s\n", obj->arg + i);
		i += l + 1;
	}
}


// NO INTENTIONAL BUGS AFTER THIS POINT

void EchoObj_init(struct Obj *obj)
{
	memset(obj->arg, 0, ARGSZ);
	obj->offset = 0;
}

void SecretObj_init(struct Obj *obj)
{
	FILE *f;
	size_t n;

	strcpy(obj->arg, "- SECRET DATA -");
	obj->offset += 16;

	f = fopen("secret", "r");
	if (f == NULL) {
		fprintf(stderr, "error opening secret file\n");
		return;
	}
	n = fread(obj->arg + obj->offset, 1, ARGSZ - obj->offset, f);
	if (n < ARGSZ) {
		if (ferror(f)) {
			fprintf(stderr, "error reading secret file\n");
		} else {
			obj->arg[n] = '\0';
		}
	}
	fclose(f);
	obj->offset += n;
}

int findfree()
{
	struct objentry *e = NULL;
	int i = 0;
	for ( ; i < MAXOBJ; i++)
		if (!objects[i].obj)
			break;
	return i;
}

// expects buf to contain pos. If valid,
// sets *ppos and *pidx to pos.
// Returns a pointer to the first unparsed char, or
// NULL in case of error.
const char *parseref(const char *buf, int *ppos)
{
	char *rest;
	long pos;
	struct Obj *obj;

	if (*buf == '\0') {
		fprintf(stderr, "missing reference\n");
		return NULL;
	}
	errno = 0;
	pos = strtol(buf, &rest, 10);
	if (errno || pos < 0 || pos >= MAXOBJ) {
		fprintf(stderr, "reference out of range\n");
		return NULL;
	}
	if (rest == buf) {
		fprintf(stderr, "invalid input\n");
		return NULL;
	}
	buf = rest;
	obj = objects[pos].obj;
	if (obj == NULL) {
		fprintf(stderr, "invalid reference\n");
		return NULL;
	}
	*ppos = pos;
	return buf;
}

void do_setarg(const char *buf)
{
	int pos;
	struct Obj *obj;

	buf = parseref(buf, &pos);
	if (buf == NULL)
		return;
	if (*buf != '=') {
		fprintf(stderr, "missing arg\n");
		return;
	}
	buf++;
	if (!(objects[pos].perms & P_WRITE)) {
		fprintf(stderr, "permission denied\n");
		return;
	}
	obj = objects[pos].obj;
	if (!Obj_write(obj, buf)) {
		fprintf(stderr, "write error\n");
	}
}

void do_getarg(const char *buf)
{
	int pos;
	struct Obj *obj;

	buf = parseref(buf, &pos);
	if (buf == NULL)
		return;
	if (*buf != '\0') {
		fprintf(stderr, "invalid input\n");
		return;
	}
	if (!(objects[pos].perms & P_READ)) {
		fprintf(stderr, "permission denited\n");
		return;
	}
	Obj_read(objects[pos].obj);
}

void do_delobj(const char *buf)
{
	int pos;
	struct Obj *obj;

	buf = parseref(buf, &pos);
	if (buf == NULL)
		return;
	if (*buf != '\0') {
		fprintf(stderr, "invalid input\n");
		return;
	}

	free(objects[pos].obj);
	objects[pos].obj = NULL;
	objects[pos].perms = 0;
}

void child(int uid)
{
	char buf[MAXLINE], *n;

	printf("Secure remote object server v0.99\n");

	for (;;) {
		if (fgets(buf, MAXLINE, stdin) == NULL)
			break;
		n = index(buf, '\n');
		if (n != NULL)
			*n = '\0';
		switch (buf[0]) {
		case '\0':
			break;
		case 'n':
			do_newobj(buf + 1);
			break;
		case 's':
			do_setarg(buf + 1);
			break;
		case 'g':
			do_getarg(buf + 1);
			break;
		case 'd':
			do_delobj(buf + 1);
			break;
		default:
			fprintf(stderr, "invalid command\n");
			break;
		}
	}
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
			child(1);
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
