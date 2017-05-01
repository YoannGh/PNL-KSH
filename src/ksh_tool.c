#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "ksh.h"

int main()
{	
	int fd;
	char *argp;

	argp = malloc(1024);

	fd = open("/dev/hello", O_RDWR);

	if (ioctl(fd, HELLO, argp) == -1) {
		puts("HELLO ioctl error");
	}
   	else {
		printf("%s\n", argp);
	}

	free(argp);
	
	close(fd);
	
	return 0;
}