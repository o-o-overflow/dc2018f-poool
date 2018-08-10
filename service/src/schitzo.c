#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <grp.h>

unsigned int h;

void cleanup()
{
	assert(setuid(h) == 0);
	exit(kill(-1, 9));
}

int main(int argc, char **argv)
{
	int r = open("/dev/urandom", 0);
	assert(r != -1);
	assert(read(r, &h, sizeof(h)) == sizeof(h));
	h = (h % 30000) + 10000;
	close(r);

	assert(signal(SIGALRM, cleanup) == 0);
	assert(argc >= 3);
	assert(getuid() == 0);
	assert(alarm(atoi(argv[1])) == 0);

	int child = fork();
	assert(child != -1);
	if (child)
	{
		wait(0);
		cleanup();
	}
	else
	{
		assert(setgroups(1, &h) == 0);
		assert(setgid(h) == 0);
		assert(setuid(h) == 0);
		execv(argv[2], argv+2);
	}
	return 1;
}
