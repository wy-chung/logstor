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
	printf("%s ...\n", __FILE__);
	logstor_open();
	logstor_check();
	logstor_close();
	printf("%s done\n", __FILE__);
	return 0;
}

