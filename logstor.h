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

#define DISK_FILE	"logstor.disk"
//#define DISK_FILE	"/dev/ada1"

#if defined(MY_DEBUG)
void my_debug(const char * file, int line_num, const char *func);
void my_break(void);

#define MY_ASSERT(x)	do if (!(x)) my_debug(__FILE__, __LINE__, __func__); while(0)
#define MY_BREAK(x)	do if ((x)) my_break(); while(0)
#define MY_PANIC()	my_debug(__FILE__, __LINE__, __func__)
#else
#define MY_ASSERT(x)
#define MY_BREAK(x)
#define MY_PANIC()
#endif

#define	SECTOR_SIZE	0x1000	// 4K

uint32_t logstor_disk_init(const char *disk_file);
uint32_t logstor_init(void);
void logstor_fini(void);
int  logstor_open(const char *disk_file);
void logstor_close(void);
uint32_t logstor_read(uint32_t ba, void *data);
uint32_t logstor_write(uint32_t ba, void *data);
void logstor_commit(void);
void logstor_revert(void);
int logstor_delete(off_t offset, void *data, off_t length);
uint32_t logstor_get_block_cnt(void);
unsigned logstor_get_data_write_count(void);
unsigned logstor_get_other_write_count(void);
unsigned logstor_get_fbuf_hit(void);
unsigned logstor_get_fbuf_miss(void);
#if defined(MY_DEBUG)
void fbuf_queue_check(void);
void fbuf_hash_check(void);
#endif

extern uint32_t gdb_cond0;	// for debug
extern uint32_t gdb_cond1;	// for debug

#if defined(WYC)
#define roundup2(x, y)	(((x)+((y)-1))&~((y)-1))
#define rounddown2(x, y) ((x)&~((y)-1))

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
