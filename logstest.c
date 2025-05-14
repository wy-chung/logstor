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
//#include <assert.h>
#include <time.h>
//#include <math.h>
#include <sys/queue.h>
#include <limits.h>

#include "logstor.h"

/**************************************
 *           Test function            *
 **************************************/
#if 0
	#define	RAND_SEED	time(NULL)
#else
	#define	RAND_SEED	0
#endif
#define TIME_SCALE 100000000
#define MUTIPLIER_TO_MAXBLOCK 10
double ratio_to_maxblock = 1.4; // the ratio to max_block;

typedef void arrays_alloc_f(unsigned max_block);

static arrays_alloc_f arrays_alloc;
static void arrays_free(void);

//static uint64_t rdtsc(void);
static void test(int n, unsigned max_block);
static void test_write(unsigned max_block);
static void test_read(unsigned max_block);
static void arrays_check(void);

static arrays_alloc_f *arrays_alloc_once = arrays_alloc;
static uint32_t *i2ba;	// ba for iteration i
static uint32_t *ba2i;	// stored value for ba
static uint32_t *ba2sa;	// stored value for ba
static uint8_t *ba_write_count;	// write count for each block

static unsigned loop_count;

static int
main_logstest(int argc, char *argv[])
{
	int	main_loop_count;
	unsigned max_block;

	srandom(RAND_SEED);
	max_block = logstor_init();

	//main_loop_count = MUTIPLIER_TO_MAXBLOCK/ratio_to_maxblock + 0.999;
	//loop_count = max_block * ratio_to_maxblock;

	//main_loop_count = 2;
	//loop_count = 1764943;
	main_loop_count = 16;
	loop_count = 176494;
	for (int i = 0; i < main_loop_count; i++) {
		printf("#### test %d ####\n", i);
		logstor_open(DISK_FILE);
		arrays_alloc_once(max_block);
#if defined(WYC)
		arrays_alloc();
		arrays_nop();
#endif
		test(i, max_block);
		logstor_close();
	}
	arrays_free();
	logstor_fini();

	return 0;
}

static void
test(int n, unsigned max_block)
{

	printf("writing %d...\n", n);
	test_write(max_block);
	arrays_check();
	printf("reading %d...\n", n);
	test_read(max_block);
	logstor_commit();
	fbuf_hash_check();
}

static void
test_write(unsigned max_block)
{
	uint32_t buf[SECTOR_SIZE/4];
	uint32_t ba, sa;

	// writing data to logstor
	int overwrite_count = 0;
	for (unsigned i = 0 ; i < loop_count ; ++i)
	{
		if ( (i % 0x10000) == 0)
			printf("w %7d/%7d\n", i, loop_count);

		ba = random() % max_block;	// get a random block address
		if (ba_write_count[ba] != 0) {
			++overwrite_count;
		}
		if (++ba_write_count[ba] == 0)		// wrap around
			ba_write_count[ba] = UCHAR_MAX;	// set to maximum value

		// set prev_i point to nothing
		unsigned pre_i = ba2i[ba];
		if (pre_i != -1)
			i2ba[pre_i] = -1;

		i2ba[i] = ba;
		ba2i[ba] = i;

		buf[ba % 4] = i;
		buf[4] = ba % 4;
		buf[5] = i;
		buf[6] = ba;
		buf[SECTOR_SIZE/4-4+(ba%4)] = i;
		sa = logstor_write_test(ba, buf);
		ba2sa[ba] = sa;
	}
	printf("overwrite %d/%d\n", overwrite_count, loop_count);
	printf("\n");

	unsigned fbuf_hit = logstor_get_fbuf_hit();
	unsigned fbuf_miss = logstor_get_fbuf_miss();
	printf("file hit %f\n", (double)fbuf_hit / (fbuf_hit + fbuf_miss));

	unsigned data_write_count = logstor_get_data_write_count();
	unsigned other_write_count = logstor_get_other_write_count();
	printf("write data %u other %u write amplification %f \n",
	    data_write_count, other_write_count,
	    (double)(data_write_count + other_write_count) / data_write_count);
	printf("\n");
}

static void 
test_read(unsigned max_block)
{
	uint32_t ba, sa;
	uint32_t i_exp, i_get;
	uint32_t buf[SECTOR_SIZE/4]; // [5]:i, [6]:ba

	// reading data from logstor
	int read_count = 0;
	uint32_t i_max = 0;
	for (ba = 0 ; ba < max_block; ba += 1) {
		if ( (ba % 0x10000) == 0)
			printf("r %7d/%7d\n", ba, max_block);
		if (ba_write_count[ba] > 0) {
			if (ba_write_count[ba] > i_max)
				i_max = ba_write_count[ba];
			sa = logstor_read_test(ba, buf);
			MY_ASSERT(sa == ba2sa[ba]);
			++read_count;
			i_exp = ba2i[ba];
			i_get = buf[5];
			if (i_exp != i_get) {
				printf("%s: ERROR miscompare: ba %u, i_exp %u, i_get %u ba_write_count %u\n",
				    __func__, ba, i_exp, i_get, ba_write_count[ba]);
				MY_PANIC();
			} else {
				MY_ASSERT(buf[ba%4] == i_get);
				MY_ASSERT(buf[SECTOR_SIZE/4-4+(ba%4)] == i_get);
			}
		}
		else {
			sa = logstor_read_test(ba, buf);
			MY_ASSERT(sa == 0/*SECTOR_NULL*/);
		}
	}
	printf("read_count %d i_max %u\n\n", read_count, i_max);
}

static void
arrays_check(void)
{
	unsigned i, i_exp;
	uint32_t ba;

	for (i = 0; i < loop_count; i++) {
		ba = i2ba[i];
		if (ba == -1)
			continue;
		i_exp = ba2i[ba];
		MY_ASSERT(i == i_exp);
	}
}

int main(int argc, char *argv[]) // main_logstest
{
	return main_logstest(argc, argv);
}

static void
arrays_nop(unsigned max_block)
{
}

static void
arrays_alloc(unsigned max_block)
{
	size_t size;

	size = loop_count * sizeof(*i2ba);
	i2ba = malloc(size);
	MY_ASSERT(i2ba != NULL);
	memset(i2ba, -1, size);

	size = max_block * sizeof(*ba2i);
	ba2i = malloc(size);
	MY_ASSERT(ba2i != NULL);
	memset(ba2i, -1, size);

	size = max_block * sizeof(*ba2sa);
	ba2sa = malloc(size);
	MY_ASSERT(ba2sa != NULL);
	bzero(ba2sa, size);

	size = max_block * sizeof(*ba_write_count);
	ba_write_count = malloc(size);
	MY_ASSERT(ba_write_count != NULL);
	bzero(ba_write_count, size);

	arrays_alloc_once = arrays_nop;	// don't do array alloc any more
}

static void arrays_free(void)
{
	free(ba_write_count);
	free(ba2sa);
	free(ba2i);
	free(i2ba);
}
//============================
#if 0
static uint64_t rdtsc(void)
{
        uint32_t lo,hi;

        __asm__ __volatile__
        (
         "rdtsc":"=a"(lo),"=d"(hi)
        );
        return (uint64_t)hi<<32|lo;
}
#endif
