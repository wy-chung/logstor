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

/**************************************
 *           Test function            *
 **************************************/

int
main(int argc, char *argv[])
{
	char *disk_file;
	int disk_fd;

	if (argc == 1 || *argv[1] == '\0')
		disk_file = DISK_FILE;
	else
		disk_file = argv[1];

	disk_fd = open(disk_file, O_RDWR);
	MY_ASSERT(disk_fd > 0);

	superblock_init_write(disk_fd);

	return 0;
}


