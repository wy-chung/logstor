/*
Author: Wuyang Chung
e-mail: wy-chung@outlook.com
*/

#if __linux
typedef unsigned char	uint8_t;
typedef unsigned short	uint16_t;
typedef unsigned int	uint32_t;
typedef unsigned long	uint64_t;

//typedef char	int8_t;
typedef short	int16_t;
typedef int	int32_t;
typedef long	int64_t;
#endif

#define	MY_DEBUG

#if defined(MY_DEBUG)
void my_panic(const char * file, int line_num, const char *func);
void my_break(void);

#define MY_PANIC()	my_panic(__FILE__, __LINE__, __func__)
#define MY_ASSERT(x)	do if (!(x)) my_panic(__FILE__, __LINE__, __func__); while(0)
#define MY_BREAK(x)	do if ((x)) my_break(); while(0)
#else
#define MY_ASSERT(x)
#define MY_BREAK(x)
#define MY_PANIC()
#endif

#define	G_LOGSTOR_MAGIC	0x4C4F4753	// "LOGS": Log-Structured Storage
#define	G_LOGSTOR_VERSION	0

#define	SECTOR_SIZE	0x1000	// 4K

uint32_t logstor_disk_init(void);
void logstor_fini(void);
int  logstor_open(void);
void logstor_close(void);
uint32_t logstor_read(uint32_t ba, void *data);
uint32_t logstor_write(uint32_t ba, void *data);
void logstor_snapshot(void);
void logstor_rollback(void);
int logstor_delete(off_t offset, void *data, off_t length);
uint32_t logstor_get_block_cnt(void);
unsigned logstor_get_data_write_count(void);
unsigned logstor_get_other_write_count(void);
unsigned logstor_get_fbuf_hit(void);
unsigned logstor_get_fbuf_miss(void);
#if defined(MY_DEBUG)
void logstor_queue_check(void);
void logstor_hash_check(void);
#endif

extern uint32_t gdb_cond0;	// for debug
extern uint32_t gdb_cond1;	// for debug

#if defined(WYC)
typedef int	ssize_t;
typedef unsigned time_t;

void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
time_t time(time_t *t);
void srandom(unsigned int seed);
long int random(void);
int printf(const char *format, ...);
void assert(scalar expression);
#endif
