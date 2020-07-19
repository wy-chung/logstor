/*
Author: Wuyang Chung
e-mail: wuyang.chung1@outlook.com
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
#if 1
	#define	RAND_SEED	time(NULL)
#else
	#define	RAND_SEED	0
#endif
double loop_ratio = 0.5; // loop_count / max_block;

uint16_t *ba_write_count;	// write count for each block
uint32_t *ba2i;	// stored value for ba
uint32_t *i2ba;	// ba for iteration i
uint32_t buf[SECTOR_SIZE/4];

static uint64_t rdtsc(void);

static void
test_write(int n, unsigned max_block)
{
	uint32_t ba;		// block address
	int	overwrite_count;
	uint64_t start_time;
	unsigned i;
	unsigned loop_count;
	unsigned data_write_count, other_write_count;
	unsigned fbuf_hit, fbuf_miss;

	// writing data to logstor
	loop_count = max_block * loop_ratio;
	overwrite_count = 0;
	printf("writing...\n");
	start_time = rdtsc();
	for (i = 0 ; i < loop_count ; ++i)
	{
		gdb_cond1 = i;
		if ( (i % 0x10000) == 0)
			printf("w%d %7d/%7d\n", n, i, loop_count);
#if 1
		ba = random() % max_block;	// get a random block address
#else
		ba = i;
#endif
		if (ba_write_count[ba] != 0) {
#if 1
			++overwrite_count;
#else
			continue;
#endif
		}
		++ba_write_count[ba];
		ba2i[ba] = i;
		i2ba[i] = ba;

		buf[4] = n;
		buf[5] = i;
		buf[6] = ba % 4;
		buf[7] = ba;
		buf[ba % 4] = i;
		buf[SECTOR_SIZE/4-4+(ba%4)] = i;
		logstor_write_test(ba, buf);
	}
	printf("elapse time %lu ticks\n", rdtsc() - start_time);
	printf("overwrite %d/%d\n", overwrite_count, loop_count);
	printf("\n");

	fbuf_hit = logstor_get_fbuf_hit();
	fbuf_miss = logstor_get_fbuf_miss();
	printf("file hit %f\n", (double)fbuf_hit / (fbuf_hit + fbuf_miss));

	data_write_count = logstor_get_data_write_count();
	other_write_count = logstor_get_other_write_count();
	printf("write data %u other %u write amplification %f \n",
	    data_write_count, other_write_count,
	    (double)(data_write_count + other_write_count) / data_write_count);
	printf("\n");


}

static void 
test_read(int n, unsigned max_block)
{
	uint64_t start_time;
	int	read_count;
	uint32_t i_max;
	uint32_t ba;		// block address
	uint32_t act;

	// reading data from logstor
	read_count = 0;
	printf("reading...\n");
	start_time = rdtsc();
	i_max = 0;
	for (ba = 0 ; ba < max_block; ba += 1) {
		if ( (ba % 0x10000) == 0)
			printf("r%d %7d/%7d\n", n, ba, max_block);
		if (ba_write_count[ba] > 0) {
			if (ba_write_count[ba] > i_max)
				i_max = ba_write_count[ba];
			logstor_read_test(ba, buf);
			++read_count;
			act = buf[5];
			if (ba2i[ba] != act) {
				printf("%s: ERROR miscompare: ba %u, exp_i %u, get_i %u\n",
				    __func__, ba, ba2i[ba], act);
				PANIC();
			} else {
				ASSERT(buf[ba%4] == act);
				ASSERT(buf[SECTOR_SIZE/4-4+(ba%4)] == act);
			}
		}
	}
	printf("elapse time %lu ticks\n", rdtsc()-start_time);
	printf("read_count %d i_max %u\n\n", read_count, i_max);
}

static void
test(int n, unsigned max_block)
{

	test_write(n, max_block);
	//logstor_check();
	test_read(n, max_block);
}

int
main(int argc, char *argv[])
{
	bool break_for_loop = false;
	int	i;
	unsigned max_block;
	char *disk_file = DISK_FILE;
	unsigned int seed;

	seed = RAND_SEED;
	srandom(seed);

	logstor_init(disk_file);
	max_block = superblock_init();

	ba_write_count = malloc(max_block * sizeof(*ba_write_count));
	ASSERT(ba_write_count != NULL);
	memset(ba_write_count, 0, max_block * sizeof(*ba_write_count));

	ba2i = malloc(max_block * sizeof(*ba2i));
	ASSERT(ba2i != NULL);
	memset(ba2i, 0, max_block * sizeof(*ba2i));

	i2ba = malloc(max_block * loop_ratio * sizeof(*i2ba));
	ASSERT(i2ba != NULL);
	memset(i2ba, 0, max_block * loop_ratio * sizeof(*i2ba));

	for (i = 0; i<20; i++) {
	//	gdb_cond0 = i;
		printf("### test %d\n", i);
		logstor_open();
		test(i, max_block);
		logstor_close();
		if (break_for_loop)
			break;
	}
	free(ba2i);
	free(ba_write_count);
	free(i2ba);
	logstor_fini();

	return 0;
}

static uint64_t rdtsc(void)
{
        uint32_t lo,hi;

        __asm__ __volatile__
        (
         "rdtsc":"=a"(lo),"=d"(hi)
        );
        return (uint64_t)hi<<32|lo;
}

