#include <linux/limits.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ctype.h>
#include <dirent.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#ifndef PORT
#define PORT 10000
#endif

#define MAXLINE 1024
#define DATALINESZ 8
#define MAXDATALINES 10

void drain();

void do_grep(char *buf)
{
	long id;
	char *rest;
	char tmp1[MAXLINE];
	char tmp2[MAXLINE];
	FILE *f;
	int rv;

	errno = 0;
	id = strtol(buf, &rest, 10);
	if (errno == EINVAL || buf[0] == '\0' || rest[0] != '\0') {
		fprintf(stderr, "invalid input\n");
		return;
	}
	if (errno == ERANGE || id <= 0) {
		fprintf(stderr, "id out of range\n");
		return;
	}
	if (snprintf(tmp1, MAXLINE, "keywords/%ld", id) >= MAXLINE) {
		fprintf(stderr, "internal error\n");
		return;
	}
	if ( (f = fopen(tmp1, "r")) == NULL ) {
		fprintf(stderr, "no such keyword\n");
		return;
	}
	if (fgets(tmp1, MAXLINE, f) == NULL) {
		fprintf(stderr, "internal error\n");
		return;
	}
	fclose(f);
	if (snprintf(tmp2, MAXLINE, "/usr/bin/grep '%s' userdata/*\n", tmp1) >= MAXLINE) {
		fprintf(stderr, "keyword too long\n");
		return;
	}
	if (system(tmp2))
		perror("system");
	
}

void do_keywords(char *buf)
{
	static long keyword_id = 0;
	char fname[MAXLINE];
	int i;
	FILE *f;

	keyword_id++;
	if (snprintf(fname, MAXLINE, "keywords/%ld", keyword_id) >= MAXLINE) {
		fprintf(stderr, "too many keywords\n");
		return;
	}
	for (i = 0; buf[i] != '\0'; i++) {
		if (!isalnum(buf[i])) {
			fprintf(stderr, "invalid character in keyword\n");
			return;
		}
	}	
	if (i < 1) {
		fprintf(stderr, "empty keyword\n");
		return;
	}
	if ( (f = fopen(fname, "w")) == NULL ) {
		perror(fname);
		return;
	}
	fputs(buf, f);
	printf("%ld\n", keyword_id);
	fclose(f);
}

void do_userdata(char *buf)
{
	char tmp[MAXLINE];
	char data[DATALINESZ + 1];
	FILE *f;
	int lines;

	if (snprintf(tmp, MAXLINE, "userdata/%s", buf) >= MAXLINE) {
		fprintf(stderr, "filename too long\n");
		return;
	}
	if ( (f = fopen(tmp, "w")) == NULL ) {
		perror(tmp);
		return;
	}
	for (lines = 0; lines < MAXDATALINES; lines++) {
		if (fgets(data, DATALINESZ + 1, stdin) == NULL) {
			if (feof(stdin))
				break;
			fprintf(stderr, "WARNING: input error\n");
			goto error;
		}
		if (strchr(data, '\n') == NULL) {
			fprintf(stderr, "WARNING: line too long\n");
			drain();
			goto error;
		}
		fputs(data, f);
	}
	if (lines >= MAXDATALINES) {
		fprintf(stderr, "WARNING: too many lines\n");
		goto error;
	}
	fclose(f);
	return;
error:
	fclose(f);
	remove(tmp);
}

// NO INTENTIONAL BUG AFTER THIS POINT

void drain()
{
	char tmp[MAXLINE];

	while (fgets(tmp, MAXLINE, stdin) && !strchr(tmp, '\n'))
		;
}

void child(int uid)
{
	char buf[MAXLINE], *n;

	printf("Secure remote grep server v0.00001\n");

	for (;;) {
		if (fgets(buf, MAXLINE, stdin) == NULL)
			break;
		n = index(buf, '\n');
		if (n != NULL) {
			*n = '\0';
		} else {
			fprintf(stderr, "line too long\n");
			drain();
			continue;
		}
		switch (buf[0]) {
		case '\0':
			break;
		case 'k':
			do_keywords(buf + 1);
			break;
		case 'g':
			do_grep(buf + 1);
			break;
		case 'u':
			do_userdata(buf + 1);
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
