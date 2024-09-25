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

#ifndef PORT
#define PORT 10000
#endif

#define MAX_ARG 8
#define MAX_CMD 56

struct cmd {
	void (*f)(struct cmd *c);
	char arg[MAX_ARG];
};

void echo(struct cmd *c)
{
	printf("%s\n", c->arg);
}

void grep(struct cmd *c)
{
	int i;
	char buf[MAX_CMD];
	for (i = 0; i < MAX_ARG; i++)
		if (!isalnum(c->arg[i]))
			return;
	snprintf(buf, MAX_CMD, "/bin/grep '%s' database", c->arg);
//	XXX this is too dangerous, find another way
//	system(buf);
}

int child()
{
	char r, *t;
	struct cmd c;

	while (read(0, &r, 1) > 0) {
		switch (r) {
		case 'e': // echo
			c.f = echo;
			break;
		case 'g': // grep
			c.f = grep;
			break;
		case 'q':
			return -1;
		default:
			continue;
		}
		read(0, c.arg, MAX_CMD);
		if (t = index(c.arg, '\n')) {
			*t = '\0';
		} else {
			return -2;
		}
		c.f(&c);
	}
	return 0;
}

// NO INTENTIONAL BUG AFTER THIS POINT
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
			asm volatile ("mov $42, %%r12" ::: "r12");
			printf("&printf: %p\n", printf);
			exit(child());
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
