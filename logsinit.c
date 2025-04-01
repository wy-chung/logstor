/*
Author: Wuyang Chung
e-mail: wy-chung@outlook.com
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

/**************************************
 *           Test function            *
 **************************************/

static int
main_logsinit(int argc, char *argv[])
{
	char *disk_file;

	if (argc == 2)
		disk_file = argv[1];
	else
		disk_file = DISK_FILE;

	logstor_superblock_init(disk_file);

	return 0;
}

int
main(int argc, char *argv[])
{
	return main_logsinit(argc, argv);
}
