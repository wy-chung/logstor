/*
Author: Wuyang Chung
e-mail: wuyang.chung1@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>
#include <sys/queue.h>

#include "logstor.h"

int
main(int argc, char *argv[])
{
	const char *media_file;

	if (argc == 2)
		media_file = argv[1];
	else
		media_file = DISK_FILE;

	logstor_init(media_file);

	return 0;
}

