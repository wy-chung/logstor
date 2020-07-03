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
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <sys/queue.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#if __linux
#include <linux/fs.h>
#include <sys/ioctl.h>
#endif
#if __BSD_VISIBLE
#include <sys/disk.h>
#include "ggate.h"
#endif

#include "logstor.h"

_Static_assert(sizeof(uint8_t) == 1, "sizeof(uint8_t) != 1");
_Static_assert(sizeof(uint16_t) == 2, "sizeof(uint16_t) != 2");
_Static_assert(sizeof(uint32_t) == 4, "sizeof(uint32_t) != 4");
_Static_assert(sizeof(uint64_t) == 8, "sizeof(uint64_t) != 8");

#if defined(MY_DEBUG)
void my_break(const char * fname, int line_num, bool bl_panic)
{
	const char *type[] = {"break", "panic"};

	printf("*** %s *** %s %d\n", type[bl_panic], fname, line_num);
	perror("");
  #if defined(NO_GDB_DEBUG)
	if (bl_panic)
		exit(1);
  #endif
}
#endif

#define	SIG_LOGSTOR	0x4C4F4753	// "LOGS": Log-Structured Storage
#define	VER_MAJOR	0
#define	VER_MINOR	1

#define SEG_DATA_START	1	// the data segment starts here
#define SEG_SUM_OFF	(SECTORS_PER_SEG - 1) // segment summary offset in segment
#define	SEG_SIZE	0x400000		// 4M
#define	SECTORS_PER_SEG	(SEG_SIZE/SECTOR_SIZE) // 1024
#define SA2SEGA_SHIFT	10
#define BLOCKS_PER_SEG	(SEG_SIZE/SECTOR_SIZE - 1)
#define GC_WINDOW	4
#define GC_AGE_LIMIT	4

#define	META_BASE	0x40000000u	// metadata block start address
#define	META_INVALID	0		// invalid metadata address
#define	SECTOR_INVALID	0	// this sector address can not map to any block address
// the block address above META_BASE is reserved for metadata address
#define	BLOCK_INVALID	META_BASE	// invalid block address

#define	IS_META_ADDR(x)	((x) & META_BASE)
#define META_LEAF_DEPTH 2

#define RAM_DISK_SIZE		0x70000000 // 1.75G the maximum size for i386 FreeBSD 12
#define FILE_BUCKET_COUNT	12899

/*
  The file descriptor for the forward map files
*/
enum {
	FD_BASE,	// file descriptor for base map
	FD_ACTIVE,	// file descriptor for active map
	FD_DELTA,	// file descriptor for delta map
	FD_COUNT	// the number of file descriptors
};

struct _superblock {
	uint32_t	sig;		// signature
	uint8_t		ver_major;
	uint8_t		ver_minor;
	uint16_t	sb_gen;		// the generation number. Used for redo after system crash
	uint32_t	max_block_cnt;	// max number of blocks supported
	/*
	   The segments are treated as circular buffer
	 */
	int32_t	seg_cnt;	// total number of segments
	int32_t seg_free_cnt;	// number of free segments
	int32_t	seg_alloc_p;	// allocate this segment
	int32_t	seg_clean_p;	// clean this segment
	/*
	   The files for forward mapping file

	   Mapping is always updated in @fm_cur. When snapshot command is issued
	   @fm_cur is copied to @fm_delta and then cleaned.
	   Backup program then backs up the delta by reading @fm_delta.
	   After backup is finished, @fm_delta is merged into @fm_base and then cleaned.

	   If reduced to reboot restore usage, only @fm_cur and @fm_base are needed.
	   Each time a PC is rebooted @fm_cur is cleaned so all data are restored.

	   So the actual mapping is @fm_cur || @fm_delta || @fm_base.
	   The first mapping that is not empty is used.
	*/
	uint32_t ftab[FD_COUNT]; 	// the file table
	uint8_t seg_age[];
};

_Static_assert(sizeof(struct _superblock) < SECTOR_SIZE,
    "The size of the super block must be smaller than SECTOR_SIZE");

/*
  The last sector in a segment is the segment summary. It stores the reverse mapping table
*/
struct _seg_sum {
	uint32_t ss_rm[SECTORS_PER_SEG - 1];	// reverse map
	// reverse map SECTORS_PER_SEG - 1 is not used so we store something here
	struct {
		uint16_t ss_gen;  // sequence number. used for redo after system crash
		uint16_t ss_alloc_p; // allocate sector at this location
	};

	// below is not stored on disk
	struct _ss_soft {
		TAILQ_ENTRY(_seg_sum) queue;
		uint32_t seg_sa; // the sector sa of the segment containing this segment summary
		unsigned live_count;		
	} ss_soft;
};

_Static_assert(sizeof(struct _seg_sum) - sizeof(struct _ss_soft) == SECTOR_SIZE,
    "The size of segment summary must be equal to SECTOR_SIZE");

/*
  File data and its indirect blocks are also stored in the downstream disk.
  The sectors used to store the file data and its indirect blocks are called metadata.

  Each metadata block has a corresponding metadata address.
  Below is the format of the metadata address.

  The metadata address occupies a small part of buffer address space. For buffer address
  that is >= META_BASE, it is actually a metadata address.
*/
union meta_addr { // metadata address for file data and its indirect blocks
	uint32_t	uint32;
	struct {
		uint32_t index  :20;	// index for indirect block
		uint32_t depth	:2;	// depth of the node
		uint32_t fd	:2;	// file descriptor
		uint32_t resv0	:6;	// reserved
		uint32_t meta	:1;	// 1 for metadata address
		uint32_t resv1	:1;	// reserved
	};
};

_Static_assert(sizeof(union meta_addr) == 4, "The size of emta_addr must be 4");

/*
  Metadata is cached in memory. The access unit of metadata is block so each cache line
  stores a block of metadata
*/
struct _fbuf { // file buffer
	union {
		LIST_ENTRY(_fbuf) indir_queue; // for the indirect queue
		struct {
			struct _fbuf *next;
			struct _fbuf *prev;
		} cir_queue; // list entry for the circular queue
	};
	uint16_t ref_cnt;	// only used by active indirect block queue
	bool	on_cir_queue;	// on circular queue
	bool	accessed;	// only used by cache entries on circular queue
	bool	modified;	// the metadata is dirty
	
	LIST_ENTRY(_fbuf)	buffer_bucket_queue;// the pointer for bucket chain
	struct _fbuf	*parent;

	union meta_addr	ma;	// the metadata address
#if defined(MY_DEBUG)
	uint32_t	sa;	// the sector address of the @data
#endif
	// the metadata is cached here
	uint32_t	data[SECTOR_SIZE/sizeof(uint32_t)];	
};

/*
	logstor soft control
*/
struct g_logstor_softc {
	struct _seg_sum seg_sum_cold;// segment summary for the cold segment
	struct _seg_sum seg_sum_hot;// segment summary for the hot segment
	uint8_t *seg_age;
	
	TAILQ_HEAD(, _seg_sum) gc_ss_head;
	struct _seg_sum gc_ss[GC_WINDOW];
	unsigned char gc_disabled;
	uint32_t gc_low_water;
	uint32_t gc_high_water;
	
	int fbuf_count;
	int fbuf_modified_count;
	struct _fbuf *fbuf;
#if 0
	uint32_t *fbuf_accessed;
	uint32_t *fbuf_modified;
	uint32_t *fbuf_on_cir_queue;
#endif	
	// buffer hash queue
	LIST_HEAD(_fbuf_bucket, _fbuf)	fbuf_bucket[FILE_BUCKET_COUNT];
	
	struct _fbuf *cir_buffer_head;	// head of the circular queue
	LIST_HEAD(, _fbuf) indirect_head[META_LEAF_DEPTH]; // indirect queue
	
#if defined(MY_DEBUG)
	int cir_queue_cnt;
#endif

	// statistics
	unsigned data_write_count;	// data block write to disk
	unsigned other_write_count;	// other write to disk, such as metadata write and garbage collection
	unsigned fbuf_hit, fbuf_miss;	// statistics

	int disk_fd;
	char *ram_disk;
	void (*my_read) (uint32_t sa, void *buf, unsigned size);
	void (*my_write)(uint32_t sa, const void *buf, unsigned size);

	bool sb_modified;	// the super block is dirty
	uint32_t sb_sa; 	// superblock's sector address
	struct _superblock superblock;
};

uint32_t gdb_cond0;
uint32_t gdb_cond1;

static struct g_logstor_softc sc;

static int _logstor_read(unsigned ba, char *data, int size);
static int _logstor_write(uint32_t ba, char *data, int size, struct _seg_sum *seg_sum);
static uint32_t seg_alloc_get_sa(void);
static uint32_t seg_to_clean_get_sa(void);
static void file_mod_flush(void);
static void file_mod_init(void);
static void file_mod_fini(void);
static uint32_t file_read_4byte(uint8_t fh, uint32_t ba);
static void file_write_4byte(uint8_t fh, uint32_t ba, uint32_t sa);

static uint32_t fbuf_ma2sa(union meta_addr ma);
static void seg_sum_write(struct _seg_sum *seg_sum);
static int superblock_read(void);
static void superblock_write(void);
static void gc_check(void);
static void gc_seg_clean(struct _seg_sum *seg_sum);

static void disk_read (uint32_t sa, void *buf, unsigned size);
static void disk_write(uint32_t sa, const void *buf, unsigned size);
static void ram_read (uint32_t sa, void *buf, unsigned size);
static void ram_write(uint32_t sa, const void *buf, unsigned size);

static uint8_t *file_access(uint8_t fd, uint32_t offset, uint32_t *buf_off, bool bl_write);
static struct _fbuf *fbuf_get(union meta_addr ma);
static struct _fbuf *fbuf_read_and_hash(uint32_t sa, union meta_addr ma);
static struct _fbuf *fbuf_search(union meta_addr ma);
static void fbuf_flush(struct _fbuf *buf, struct _seg_sum *seg_sum);
static void fbuf_hash_insert(struct _fbuf *buf, unsigned key);

#if !__BSD_VISIBLE
static off_t
g_gate_mediasize(int fd)
{
	off_t mediasize;
	struct stat sb;
	int rc;

	rc = fstat(fd, &sb);
	ASSERT(rc != -1);

	if (S_ISCHR(sb.st_mode))
		ASSERT(ioctl(fd, BLKGETSIZE64, &mediasize) != -1);
	else if (S_ISREG(sb.st_mode))
		mediasize = sb.st_size;
	else
		PANIC(); // Unsupported file system object

	return (mediasize);
}
#endif

/*******************************
 *        logstor              *
 *******************************/

/*
Description:
    Initialize the downstream disk to LotStor
*/
uint32_t
superblock_init(void)
{
	int	i;
	uint32_t sector_cnt;
	struct _superblock *sb, *sb_out;
	off_t media_size;
	char buf[SECTOR_SIZE] __attribute__ ((aligned));

	if (sc.disk_fd > 0)
		media_size = g_gate_mediasize(sc.disk_fd);
	else
		media_size = RAM_DISK_SIZE;
		
	sector_cnt = media_size / SECTOR_SIZE;

	sb = &sc.superblock;
	sb->sig = SIG_LOGSTOR;
	sb->ver_major = VER_MAJOR;
	sb->ver_minor = VER_MINOR;

#if __BSD_VISIBLE
	sb->sb_gen = arc4random();
#else
	sb->sb_gen = random();
#endif
	sb->seg_cnt = sector_cnt / SECTORS_PER_SEG;
	ASSERT(sizeof(struct _superblock) + sb->seg_cnt < SECTOR_SIZE);
	sb->seg_free_cnt = sb->seg_cnt - SEG_DATA_START;

	// the physical disk must have at least the space for the metadata
	ASSERT(sb->seg_free_cnt * BLOCKS_PER_SEG >
	    (sector_cnt / (SECTOR_SIZE / 4)) * FD_COUNT);

	sb->max_block_cnt =
	    sb->seg_free_cnt * BLOCKS_PER_SEG -
	    (sector_cnt / (SECTOR_SIZE / 4)) * FD_COUNT;
	sb->max_block_cnt *= 0.9;
#if defined(MY_DEBUG)
	printf("%s: sector_cnt %u max_block_cnt %u\n",
	    __func__, sector_cnt, sb->max_block_cnt);
#endif
	/*
	    Initially SEG_DATA_START is cold segment and SEG_DATA_START + 1 is hot segment
	    The starting clean point should point to hot segment.
	*/
	sb->seg_alloc_p = SEG_DATA_START;	// the segment to allocate
	sb->seg_clean_p = SEG_DATA_START + 1;	// the segment to clean

	// the root sector address for the files
	for (i = 0; i < FD_COUNT; i++) {
		sb->ftab[i] = SECTOR_INVALID;	// not allocated yet
	}

	if (sc.seg_age == NULL) {
		sc.seg_age = malloc(sc.superblock.seg_cnt);
		ASSERT(sc.seg_age != NULL);
	}
	memset(sc.seg_age, 0, sb->seg_cnt);

	// write out super block
	sb_out = (struct _superblock *)buf;
	memcpy(sb_out, &sc.superblock, sizeof(sc.superblock));
	memcpy(sb_out->seg_age, sc.seg_age, sb->seg_cnt);
	sc.sb_sa = 0;
	sc.my_write(sc.sb_sa, sb_out, 1);
	sc.sb_modified = false;

	return sb->max_block_cnt;
}

void logstor_init(const char *disk_file)
{
	memset(&sc, 0, sizeof(sc));

	if (*disk_file == '\0') {
		sc.ram_disk = malloc(RAM_DISK_SIZE);
		ASSERT(sc.ram_disk != NULL);
		sc.disk_fd = -1;
		sc.my_read = ram_read;
		sc.my_write = ram_write;
	} else {
		sc.ram_disk = NULL;
#if 0// __BSD_VISIBLE
		sc.disk_fd = open(disk_file, O_RDWR | O_DIRECT | O_FSYNC);
#else
		sc.disk_fd = open(disk_file, O_RDWR);
#endif
		ASSERT(sc.disk_fd > 0);
		sc.my_read = disk_read;
		sc.my_write = disk_write;
	}
}

void
logstor_fini(void)
{
	free(sc.seg_age);
	free(sc.ram_disk);
	if (sc.disk_fd != -1) {
		close(sc.disk_fd);
#if defined(MY_DEBUG)
		sc.disk_fd = -1;
#endif
	}
}

int
logstor_open(void)
{

	if (superblock_read() != 0) {
		superblock_init();
	}
	sc.seg_sum_cold.ss_soft.seg_sa = seg_alloc_get_sa(); 
	sc.seg_sum_cold.ss_alloc_p = 0;

	sc.seg_sum_hot.ss_soft.seg_sa = seg_alloc_get_sa();
	sc.seg_sum_hot.ss_alloc_p = 0;

	sc.data_write_count = sc.other_write_count = 0;
	sc.gc_low_water = 8;
	sc.gc_high_water = sc.gc_low_water + 2;

	file_mod_init();
	gc_check();

	return 0;
}

void
logstor_close(void)
{

	file_mod_fini();

	seg_sum_write(&sc.seg_sum_cold);
	seg_sum_write(&sc.seg_sum_hot);

	superblock_write();
}

/*
Description:
  Read blocks from logstor

Parameters:
  @offset: disk offset
  @data: data buffer
  @length: data length
*/
int
logstor_read(off_t offset, void *data, off_t length)
{
	unsigned size;
	uint32_t ba;

	ASSERT((offset & (SECTOR_SIZE - 1)) == 0);
	ASSERT((length & (SECTOR_SIZE - 1)) == 0);
	ba = offset / SECTOR_SIZE;
	size = length / SECTOR_SIZE;

	return _logstor_read(ba, data, size);
}

/*
Description:
  Write blocks to logstor

Parameters:
  @offset: disk offset
  @data: data buffer
  @length: data length
*/
int
logstor_write(off_t offset, void *data, off_t length)
{
	uint32_t ba;	// block address
	int size;	// number of remaining sectors to process

	ASSERT((offset & (SECTOR_SIZE - 1)) == 0);
	ASSERT((length & (SECTOR_SIZE - 1)) == 0);
	ba = offset / SECTOR_SIZE;
	size = length / SECTOR_SIZE;

	return _logstor_write(ba, data, size, &sc.seg_sum_hot);
}

int logstor_delete(off_t offset, void *data, off_t length)
{
	uint32_t ba;	// block address
	int size;	// number of remaining sectors to process
	int i;

	ASSERT((offset & (SECTOR_SIZE - 1)) == 0);
	ASSERT((length & (SECTOR_SIZE - 1)) == 0);
	ba = offset / SECTOR_SIZE;
	size = length / SECTOR_SIZE;
	ASSERT(ba < sc.superblock.max_block_cnt);

	for (i = 0; i<size; i++) {
		file_write_4byte(FD_ACTIVE, ba + i, SECTOR_INVALID);
	}
	return (0);
}

int
logstor_read_test(uint32_t ba, char *data)
{
	return _logstor_read(ba, data, 1);
}

int
logstor_write_test(uint32_t ba, char *data)
{
	return _logstor_write(ba, data, 1, &sc.seg_sum_hot);
}

/*
Description:
  Read blocks from the logstor

Parameters:
  @ba: block address
  @data: data buffer
  @size: size in unit of block
*/
static int
_logstor_read(unsigned ba, char *data, int size)
{
	unsigned i, count;
	uint32_t start_sa, pre_sa, sa;	// sector address

	ASSERT(ba < sc.superblock.max_block_cnt);
	ASSERT(size >= 1);

	start_sa = pre_sa = file_read_4byte(FD_ACTIVE, ba);
	count = 1;
	for (i = 1; i < size; i++) {
		sa = file_read_4byte(FD_ACTIVE, ba + i);
		if (sa == pre_sa + 1) {
			count++;
			pre_sa = sa;
		} else {
			if (start_sa == SECTOR_INVALID)
				memset(data, 0, SECTOR_SIZE);
			else
				sc.my_read(start_sa, data, count);
			// set the values for the next write
			data += count * SECTOR_SIZE;
			start_sa = pre_sa = sa;
			count = 1;
		}
	}
	if (start_sa == SECTOR_INVALID)
		memset(data, 0, SECTOR_SIZE);
	else
		sc.my_read(start_sa, data, count);

	return 0;
}

/*
Description:
  Write blocks to logstor

Parameters:
  @ba: block address
  @data: data buffer
  @size: size in unit of block

*/
static int
_logstor_write(uint32_t ba, char *data, int size, struct _seg_sum *seg_sum)
{
	uint32_t sa;	// sector address
	int sec_remain;	// number of remaining sectors to process
	int sec_free;	// number of free sectors in current segment
	int i, count;

	ASSERT(ba < sc.superblock.max_block_cnt);
	ASSERT(seg_sum->ss_alloc_p < SEG_SUM_OFF);

	sec_remain = size;
	while (sec_remain > 0) {
		sec_free = SEG_SUM_OFF - seg_sum->ss_alloc_p;
		count = sec_remain <= sec_free? sec_remain: sec_free; // min(sec_remain, sec_free)
		sa = seg_sum->ss_soft.seg_sa + seg_sum->ss_alloc_p;
		ASSERT(sa + count < sc.superblock.seg_cnt * SECTORS_PER_SEG);
		sc.my_write(sa, data, count);
		data += count * SECTOR_SIZE;
		if (sc.gc_disabled) // if doing garbage collection
			sc.other_write_count += count;
		else
			sc.data_write_count += count;

		// record the reverse mapping immediately after the data have been written
		for (i = 0; i < count; i++)
			seg_sum->ss_rm[seg_sum->ss_alloc_p++] = ba + i;

		if (seg_sum->ss_alloc_p == SEG_SUM_OFF)
		{	// current segment is full
			seg_sum_write(seg_sum);
			gc_check();
		}
		// record the forward mapping later after the segment summary block is flushed
		for (i = 0; i < count; i++)
			file_write_4byte(FD_ACTIVE, ba++, sa++);

		sec_remain -= count;
	}

	return 0;
}

uint32_t
logstor_get_block_cnt(void)
{
	return sc.superblock.max_block_cnt;
}

unsigned
logstor_get_data_write_count(void)
{
	return sc.data_write_count;
}

unsigned
logstor_get_other_write_count(void)
{
	return sc.other_write_count;
}

unsigned
logstor_get_fbuf_hit(void)
{
	return sc.fbuf_hit;
}

unsigned
logstor_get_fbuf_miss(void)
{
	return sc.fbuf_miss;
}

static void
seg_sum_read(struct _seg_sum *seg_sum)
{
	uint32_t sa;

	sa = seg_sum->ss_soft.seg_sa + SEG_SUM_OFF;
	sc.my_read(sa, seg_sum, 1);
}

/*
  write out the segment summary
*/
static void
seg_sum_write(struct _seg_sum *seg_sum)
{
	uint32_t sa;

	sa = seg_sum->ss_soft.seg_sa + SEG_SUM_OFF;
	seg_sum->ss_gen = sc.superblock.sb_gen;
	// segment summary is at the end of a segment
	sc.my_write(sa, (void *)seg_sum, 1);
	sc.other_write_count++;

	sc.superblock.seg_free_cnt--;
	ASSERT(sc.superblock.seg_free_cnt > 0 &&
	    sc.superblock.seg_free_cnt < sc.superblock.seg_cnt);

	seg_sum->ss_soft.seg_sa = seg_alloc_get_sa();
	seg_sum->ss_alloc_p = 0;
}

static int
superblock_read(void)
{
	int	i;
	uint16_t sb_gen;
	struct _superblock *sb_in;
	char buf[2][SECTOR_SIZE] __attribute__ ((aligned));

	_Static_assert(sizeof(sb_gen) == sizeof(sc.superblock.sb_gen), "sb_gen");

	// get the superblock
	sc.my_read(0, buf[0], 1);
	memcpy(&sc.superblock, buf[0], sizeof(sc.superblock));
	if (sc.superblock.sig != SIG_LOGSTOR ||
	    sc.superblock.seg_alloc_p >= sc.superblock.seg_cnt ||
	    sc.superblock.seg_clean_p >= sc.superblock.seg_cnt)
		return EINVAL;

	sb_gen = sc.superblock.sb_gen;
	for (i = 1 ; i < SECTORS_PER_SEG; i++) {
		sc.my_read(i, buf[i%2], 1);
		memcpy(&sc.superblock, buf[i%2], sizeof(sc.superblock));
		if (sc.superblock.sig != SIG_LOGSTOR)
			break;
		if (sc.superblock.sb_gen != (uint16_t)(sb_gen + 1)) // IMPORTANT type cast
			break;
		sb_gen = sc.superblock.sb_gen;
	}
	sc.sb_sa = (i - 1);
	sb_in = (struct _superblock *)buf[(i-1)%2];
	memcpy(&sc.superblock, sb_in, sizeof(sc.superblock));
	sc.sb_modified = false;
	if (sc.superblock.sig != SIG_LOGSTOR ||
	    sc.superblock.seg_alloc_p >= sc.superblock.seg_cnt ||
	    sc.superblock.seg_clean_p >= sc.superblock.seg_cnt)
		return EINVAL;

	if (sc.seg_age == NULL) {
		sc.seg_age = malloc(sc.superblock.seg_cnt);
		ASSERT(sc.seg_age != NULL);
	}
	memcpy(sc.seg_age, sb_in->seg_age, sb_in->seg_cnt);

	return 0;
}

static void
superblock_write(void)
{
	struct _superblock *sb_out;
	char buf[SECTOR_SIZE];

	sc.superblock.sb_gen++;
	if (++sc.sb_sa == SECTORS_PER_SEG)
		sc.sb_sa = 0;
	sb_out = (struct _superblock *)buf;
	memcpy(sb_out, &sc.superblock, sizeof(sc.superblock));
	memcpy(sb_out->seg_age, sc.seg_age, sb_out->seg_cnt);
	
	sc.my_write(sc.sb_sa, sb_out, 1);
	sc.other_write_count++;
}

static void
disk_read(uint32_t sa, void *buf, unsigned size)
{
	ssize_t bc; // byte count

	ASSERT((sa < sc.superblock.seg_cnt * SECTORS_PER_SEG) ||
	    (sc.superblock.seg_cnt == 0 && sa < SECTORS_PER_SEG));	// reading the superblock
	bc = pread(sc.disk_fd, buf, size * SECTOR_SIZE, (off_t)sa * SECTOR_SIZE);
	ASSERT(bc == size * SECTOR_SIZE);
}

static void
disk_write(uint32_t sa, const void *buf, unsigned size)
{
	ssize_t bc; // byte count

	ASSERT(sa < sc.superblock.seg_cnt * SECTORS_PER_SEG);
	bc = pwrite(sc.disk_fd, buf, size * SECTOR_SIZE, (off_t)sa * SECTOR_SIZE);
	ASSERT(bc == size * SECTOR_SIZE);
}

static void
ram_read(uint32_t sa, void *buf, unsigned size)
{
	ASSERT((sa < sc.superblock.seg_cnt * SECTORS_PER_SEG) || 1);
	    //(sc.superblock.seg_cnt == 0 && sa < SECTORS_PER_SEG));	// reading the superblock
	memcpy(buf, sc.ram_disk + (off_t)sa * SECTOR_SIZE, size * SECTOR_SIZE);
}

static void
ram_write(uint32_t sa, const void *buf, unsigned size)
{
	ASSERT(sa < sc.superblock.seg_cnt * SECTORS_PER_SEG);
	memcpy(sc.ram_disk + (off_t)sa * SECTOR_SIZE , buf, size * SECTOR_SIZE);
}

static uint32_t
seg_alloc_get_sa(void)
{
	uint32_t sega;

	do {
		sega = sc.superblock.seg_alloc_p;
		if (++sc.superblock.seg_alloc_p == sc.superblock.seg_cnt)
			sc.superblock.seg_alloc_p = SEG_DATA_START;
		ASSERT(sc.superblock.seg_alloc_p < sc.superblock.seg_cnt);
	} while (sc.seg_age[sega] != 0);

	return sega * SECTORS_PER_SEG;	
}

static uint32_t
seg_to_clean_get_sa(void)
{
	uint32_t sega;
	uint32_t sega_hot, sega_cold;
	struct _seg_sum seg_sum;

	sega_hot = sc.seg_sum_hot.ss_soft.seg_sa >> SA2SEGA_SHIFT;
	sega_cold = sc.seg_sum_cold.ss_soft.seg_sa >> SA2SEGA_SHIFT;
again:
	sega = sc.superblock.seg_clean_p;
	if (++sc.superblock.seg_clean_p == sc.superblock.seg_cnt)
		sc.superblock.seg_clean_p = SEG_DATA_START;
	ASSERT(sc.superblock.seg_clean_p < sc.superblock.seg_cnt);

	if (sega == sega_hot)
		goto again;
	if (sega == sega_cold)
		goto again;

	if (sc.seg_age[sega] >= GC_AGE_LIMIT) {
		seg_sum.ss_soft.seg_sa = sega * SECTORS_PER_SEG;
		seg_sum_read(&seg_sum); 
		gc_seg_clean(&seg_sum);
		if (sc.superblock.seg_free_cnt > sc.gc_high_water)
			return SECTOR_INVALID;
		goto again;
	}

	return sega * SECTORS_PER_SEG;
}

/*********************
* Garbage collection *
**********************/

static void
gc_seg_clean(struct _seg_sum *seg_sum)
{
	uint32_t	ba, sa;
	uint32_t	seg_sa;		// the sector address of the cleaning segment
	int	i;
	struct _fbuf *fbuf;
	uint32_t buf[SECTOR_SIZE];

	seg_sa = seg_sum->ss_soft.seg_sa;
	for (i = 0; i < seg_sum->ss_alloc_p; i++) {
		ba = seg_sum->ss_rm[i];	// get the block address from reverse map
		ASSERT((ba & 0x80000000u) == 0);
		if (IS_META_ADDR(ba)) {
			sa = fbuf_ma2sa((union meta_addr)ba); 
			if (sa == seg_sa + i) { // live metadata
				fbuf = fbuf_get((union meta_addr)ba);
				if (!fbuf->modified) {
					// Set it as modified and the buf
					// will be flushed to disk eventually.
					fbuf->modified = true;
					sc.fbuf_modified_count++;
					if (!fbuf->accessed)
						fbuf_flush(fbuf, &sc.seg_sum_cold);
				}
			}
		} else {
			sa = file_read_4byte(FD_ACTIVE, ba); 
			if (sa == seg_sa + i) { // live data
				sc.my_read(seg_sa + i, buf, 1);
				_logstor_write(ba, buf, 1, &sc.seg_sum_cold);
			}
		}
	}
	sc.superblock.seg_free_cnt++;
	sc.seg_age[seg_sa >> SA2SEGA_SHIFT] = 0; // It's cleaned
	//gc_trim(seg_sa);
}

/*
  Input:  seg_sum->ss_soft.seg_sa
  Output: seg_sum->ss_soft.live_count
*/
static void
seg_live_count(struct _seg_sum *seg_sum)
{
	int	i;
	uint32_t ba;
	uint32_t seg_sa;
	unsigned live_count = 0;
	struct _fbuf *buf;

	seg_sum_read(seg_sum);
	seg_sa = seg_sum->ss_soft.seg_sa;
	for (i = 0; i < seg_sum->ss_alloc_p; i++)
	{
		ba = seg_sum->ss_rm[i];	// get the block address from reverse map
		if (IS_META_ADDR(ba)) {
			if (fbuf_ma2sa((union meta_addr)ba) == seg_sa + i) { // live metadata
				buf = fbuf_get((union meta_addr)ba);
				if (!buf->modified && !buf->accessed)
					live_count++;
			}
		} else {
			if (file_read_4byte(FD_ACTIVE, ba) == seg_sa + i) // live data
				live_count++;
		}
	}
	seg_sum->ss_soft.live_count = live_count;
}

static void
garbage_collection(void)
{
	struct _seg_sum *seg;
	struct _seg_sum *seg_hot, *seg_head;
	unsigned min, live_count;
	int sega;	// segment address
	uint32_t seg_sa;
	int	i;
	int same_head;

//printf("\n%s >>>\n", __func__);
	TAILQ_INIT(&sc.gc_ss_head);
	for (i = 0; i < GC_WINDOW; i++) {
		seg_sa = seg_to_clean_get_sa();
		if (seg_sa == SECTOR_INVALID)
			goto exit;
		seg = &sc.gc_ss[i];
		seg->ss_soft.seg_sa = seg_sa;
		seg_live_count(seg);
		TAILQ_INSERT_TAIL(&sc.gc_ss_head, seg, ss_soft.queue);
	}

	seg_head = &sc.gc_ss[0];
	same_head = 0;
	for (;;) {
		// find the hottest segment
		min = -1; // the maximum unsigned integer
		TAILQ_FOREACH(seg, &sc.gc_ss_head, ss_soft.queue) {
			live_count = seg->ss_soft.live_count;
			if (live_count < min) {
				min = live_count;
				seg_hot = seg;
			}
		}
		// clean the hottest segment and load next segment to clean
		TAILQ_REMOVE(&sc.gc_ss_head, seg_hot, ss_soft.queue);
		gc_seg_clean(seg_hot);
		if (sc.superblock.seg_free_cnt > sc.gc_high_water)
			goto exit;
		seg_sa = seg_to_clean_get_sa();
		if (seg_sa == SECTOR_INVALID)
			goto exit;
		seg_hot->ss_soft.seg_sa = seg_sa;
		seg_live_count(seg_hot);
		TAILQ_INSERT_TAIL(&sc.gc_ss_head, seg_hot, ss_soft.queue);

		// if the head has not been changed for some time, make it cold
		seg = TAILQ_FIRST(&sc.gc_ss_head);
		if (seg == seg_head)
			same_head++;
		if (same_head > GC_WINDOW/2) {
			TAILQ_REMOVE(&sc.gc_ss_head, seg, ss_soft.queue);
			sega = seg->ss_soft.seg_sa >> SA2SEGA_SHIFT;
			sc.seg_age[sega]++;
			// load the next segment summary
			seg_sa = seg_to_clean_get_sa();
			if (seg_sa == SECTOR_INVALID)
				goto exit;
			seg->ss_soft.seg_sa = seg_sa;
			seg_live_count(seg);
			TAILQ_INSERT_TAIL(&sc.gc_ss_head, seg, ss_soft.queue);

			seg_head = TAILQ_FIRST(&sc.gc_ss_head);
			same_head = 0;
		}
	}
exit:
	TAILQ_FOREACH(seg, &sc.gc_ss_head, ss_soft.queue) {
		seg_sa = seg->ss_soft.seg_sa;
		sega = seg_sa >> SA2SEGA_SHIFT;
		sc.seg_age[sega]++;
	}
//printf("%s <<<\n", __func__);
}

static inline void
gc_enable(void)
{
	ASSERT(sc.gc_disabled != 0);
	sc.gc_disabled--;
}

static inline void
gc_disable(void)
{
	ASSERT(sc.gc_disabled <= 2);
	sc.gc_disabled++;
}

static void
gc_check(void)
{
	if (sc.superblock.seg_free_cnt <= sc.gc_low_water && !sc.gc_disabled) {
		gc_disable();	// disable gargabe collection
		garbage_collection();
		gc_enable(); // enable gargabe collection
	} 
}

/*********************************************************
 * The file buffer and indirect block cache              *
 *   Cache the the block to sector address translation   *
 *********************************************************/

/*
  Initialize metadata file buffer
*/
static void
file_mod_init(void)
{
	unsigned i;

	sc.fbuf_hit = sc.fbuf_miss = 0;
	sc.fbuf_count = sc.superblock.max_block_cnt / (SECTOR_SIZE / 4)
	//    * 0.93; // change the percentage with caution
	    * 1.01; // change the percentage with caution
	sc.fbuf_modified_count = 0;
#if defined(MY_DEBUG)
	sc.cir_queue_cnt = sc.fbuf_count;
#endif

	for (i = 0; i < FILE_BUCKET_COUNT; i++)
		LIST_INIT(&sc.fbuf_bucket[i]);

	sc.fbuf = malloc(sizeof(*sc.fbuf) * sc.fbuf_count);
	ASSERT(sc.fbuf != NULL);
#if 0
	sc.fbuf_accessed = malloc(sc.fbuf_count/8);
	ASSERT(sc.fbuf_accessed != NULL);
	sc.fbuf_modified = malloc(sc.fbuf_count/8);
	ASSERT(sc.fbuf_modified != NULL);
	sc.fbuf_on_cir_queue = malloc(sc.fbuf_count/8);
	ASSERT(sc.fbuf_on_cir_queue != NULL);
#endif
	for (i = 0; i < sc.fbuf_count; i++) {
		sc.fbuf[i].cir_queue.prev = &sc.fbuf[i-1];
		sc.fbuf[i].cir_queue.next = &sc.fbuf[i+1];
		sc.fbuf[i].parent = NULL;
		sc.fbuf[i].on_cir_queue = true;
		sc.fbuf[i].accessed = false;
		sc.fbuf[i].modified = false;
		// to distribute the file buffer to buckets evenly 
		// use @i as the key when the tag is META_INVALID
		sc.fbuf[i].ma.uint32 = META_INVALID;
		fbuf_hash_insert(&sc.fbuf[i], i);
	}
	// fix the circular queue for the first and last buffer
	sc.fbuf[0].cir_queue.prev = &sc.fbuf[sc.fbuf_count-1];
	sc.fbuf[sc.fbuf_count-1].cir_queue.next = &sc.fbuf[0];
	sc.cir_buffer_head = &sc.fbuf[0]; // point to the circular queue

	for (i = 0; i < META_LEAF_DEPTH; i++)
		LIST_INIT(&sc.indirect_head[i]); // point to active indirect blocks with depth i
}

static void
file_mod_flush(void)
{
	struct _fbuf	*buf;
	int	i;
	unsigned count = 0;

//printf("%s: modified count before %d\n", __func__, sc.fbuf_modified_count);
	buf = sc.cir_buffer_head;
	do {
		ASSERT(buf->on_cir_queue);
		if (buf->modified) {
			fbuf_flush(buf, &sc.seg_sum_hot);
			count++;
		}
		buf = buf->cir_queue.next;
	} while (buf != sc.cir_buffer_head);
	
	// process active indirect blocks
	for (i = META_LEAF_DEPTH - 1; i >= 0; i--)
		LIST_FOREACH(buf, &sc.indirect_head[i], indir_queue) {
			ASSERT(buf->on_cir_queue == false);
			if (buf->modified) {
				fbuf_flush(buf, &sc.seg_sum_hot);
				count++;
			}
		}
//printf("%s: modified count after %d\n", __func__, sc.fbuf_modified_count);
//printf("%s: flushed count %u\n", __func__, count);
}

static void
file_mod_fini(void)
{
	file_mod_flush();
}

/*
Description:
 	Get the sector address of the corresponding @ba in @file

Parameters:
	@fd: file descriptor
	@ba: block address

Return:
	The sector address of the @ba
*/
static uint32_t
file_read_4byte(uint8_t fd, uint32_t ba)
{
	uint8_t	*fbd;	// point to file buffer data
	uint32_t	offset;	// the offset within the file buffer data

	ASSERT((ba & 0xc0000000u) == 0);
	fbd = file_access(fd, ba << 2, &offset, false);
	return *((uint32_t *)(fbd + offset));
}

/*
Description:
 	Set the mapping of @ba to @sa in @file

Parameters:
	@fd: file descriptor
	@ba: block address
	@sa: sector address
*/
static void
file_write_4byte(uint8_t fd, uint32_t ba, uint32_t sa)
{
	uint8_t	*fbd;	// point to file buffer data
	uint32_t	offset;	// the offset within the file buffer data

	ASSERT((ba & 0xc0000000u) == 0);
	fbd = file_access(fd, ba << 2, &offset, true);
	*((uint32_t *)(fbd + offset)) = sa;
}

/*
Description:
    The metadata is cached in memory. This function returns the address
    of the metadata in memory for the forward mapping of the block @ba

Parameters:
	@fd: file descriptor
	@ba: block address
	@offset: the offset within the file buffer data
	@bl_write: true for write access, false for read access

Return:
	the address of the file buffer data
*/
static uint8_t *
file_access(uint8_t fd, uint32_t offset, uint32_t *buf_off, bool bl_write)
{
	union meta_addr	ma;		// metadata address
	struct _fbuf	*buf;

	*buf_off = offset & 0xfffu;

	// convert to metadata address from (@fd, @offset)
	ma.uint32 = META_BASE + (offset >> 12); // also set .index, .depth and .fd to 0
	ma.depth = META_LEAF_DEPTH;
	ma.fd = fd;
	buf = fbuf_get(ma);
	buf->accessed = true;
	if (!buf->modified && bl_write) {
		buf->modified = true;
		sc.fbuf_modified_count++;
	}

	return (uint8_t *)buf->data;
}

static unsigned
ma_index_get(union meta_addr ma, unsigned depth)
{
	unsigned index;

	index = ma.uint32;
	switch (depth) {
	case 0:
		index >>= 10;
		break;
	case 1:
		break;
	default:
		PANIC();
	}
	return (index & 0x3ffu);
}

static void
ma_index_set(union meta_addr *ma, unsigned depth, unsigned index)
{

	ASSERT(depth < META_LEAF_DEPTH);
	ASSERT(index < 1024);

	switch (depth) {
	case 0:
		index <<= 10;
		ma->uint32 &= 0xfff003ffu;
		break;
	case 1:
		ma->uint32 &= 0xfffffc00u;
		break;
	default:
		PANIC();
	}
	ma->uint32 |= index;
}

static uint32_t
fbuf_ma2sa(union meta_addr ma)
{
	struct _fbuf *pbuf;
	int pindex;		//index in the parent indirect block
	union meta_addr pma;	// parent's metadata address
	uint32_t sa;

	pma = ma;
	switch (ma.depth)
	{
	case 0:
		sa = sc.superblock.ftab[ma.fd];
		break;
	case 1:
		pindex = ma_index_get(ma, 0);
		//ma_index_set(&ma, 0, 0);
		//ma_index_set(&ma, 1, 0);
		pma.index = 0; // optimization of the above 2 statements
		pma.depth = 0; // i.e. ma.depth - 1
		goto get_sa;
	case 2:
		pindex = ma_index_get(ma, 1);
		ma_index_set(&pma, 1, 0);
		pma.depth = 1; // i.e. ma.depth - 1
get_sa:
		pbuf = fbuf_get(pma);
		sa = pbuf->data[pindex];
		break;
	default:
		PANIC();
	}
	return sa;
}

static void
fbuf_hash_insert(struct _fbuf *buf, unsigned key)
{
	unsigned hash;
	struct _fbuf_bucket *bucket;

	hash = key % FILE_BUCKET_COUNT;
	bucket = &sc.fbuf_bucket[hash];
	LIST_INSERT_HEAD(bucket, buf, buffer_bucket_queue);
}

#if defined(MY_DEBUG)
static void
fbuf_queue_check(void)
{
	struct _fbuf *buf;
	unsigned i;
	unsigned total, indir_cnt[META_LEAF_DEPTH];

	buf = sc.cir_buffer_head;
	ASSERT(buf != NULL);
	total = 0;
	do  {
		++total;
		ASSERT(total <= sc.fbuf_count);
		ASSERT(buf->on_cir_queue);
		buf = buf->cir_queue.next;
	} while (buf != sc.cir_buffer_head);

	for (i = 0; i < META_LEAF_DEPTH; i++)
		indir_cnt[i] = 0;

	for (i = 0; i < META_LEAF_DEPTH ; ++i) {
		buf = LIST_FIRST(&sc.indirect_head[i]);
		while (buf != NULL) {
			++indir_cnt[0];
			ASSERT(indir_cnt[0] <= sc.fbuf_count);
			ASSERT(buf->on_cir_queue == false);
			ASSERT(buf->ma.depth == i);
			buf = LIST_NEXT(buf, indir_queue);
		}
	}

	for (i = 0; i < META_LEAF_DEPTH; i++)
		total += indir_cnt[i];
	
	ASSERT(total == sc.fbuf_count);
}
#endif

/*
    Circular queue insert before
*/
static void
fbuf_cir_queue_insert(struct _fbuf *buf)
{
	struct _fbuf *prev;

	prev = sc.cir_buffer_head->cir_queue.prev;
	sc.cir_buffer_head->cir_queue.prev = buf;
	buf->cir_queue.next = sc.cir_buffer_head;
	buf->cir_queue.prev = prev;
	prev->cir_queue.next = buf;
	buf->on_cir_queue = true;
#if defined(MY_DEBUG)
	sc.cir_queue_cnt++;
#endif
}

/*
    Circular queue remove
    Must have at least tow elements on the queue before remove
*/
static void
fbuf_cir_queue_remove(struct _fbuf *buf)
{
	struct _fbuf *prev;
	struct _fbuf *next;

	ASSERT(buf->on_cir_queue);
	ASSERT(sc.cir_buffer_head->cir_queue.next != sc.cir_buffer_head);
	ASSERT(sc.cir_buffer_head->cir_queue.prev != sc.cir_buffer_head);
	if (buf == sc.cir_buffer_head)
		sc.cir_buffer_head = sc.cir_buffer_head->cir_queue.next;
	prev = buf->cir_queue.prev;
	next = buf->cir_queue.next;
	prev->cir_queue.next = next;
	next->cir_queue.prev = prev;
	buf->on_cir_queue = false;
#if defined(MY_DEBUG)
	sc.cir_queue_cnt--;
#endif
}

/*
Description:
    Read or write the file buffer with metadata address @ma
*/
static struct _fbuf *
fbuf_get(union meta_addr ma)
{
	struct _fbuf *pbuf;	// parent buffer
	struct _fbuf *buf;
	union meta_addr	tma;	// temporary metadata address
	uint32_t sa;	// sector address where the metadata is stored
	unsigned i;
	unsigned index;

	ASSERT(IS_META_ADDR(ma.uint32));
	buf = fbuf_search(ma);
	if (buf != NULL) // cache hit
		return buf;

	// cache miss
	// get the root sector address of the file @ma.fd
	ASSERT(ma.fd < FD_COUNT);
	sa = sc.superblock.ftab[ma.fd];
	pbuf = NULL;	// parent for root is NULL
	tma.uint32 = META_BASE; // also set .index, .depth and .fd to 0
	tma.fd = ma.fd;
	// read the metadata from root to leaf node
	for (i = 0; ; ++i) {	// read the indirect blocks to block cache
		tma.depth = i;
		buf = fbuf_search(tma);
		if (buf == NULL) {
			buf = fbuf_read_and_hash(sa, tma);
			buf->parent = pbuf;
			/*
			  Theoretically the parent's reference count should be
			  incremented here. But if imcremented here, the parent
			  might be reclaimed in the call fbuf_read_and_hash, so
			  it is actually incremented in the previous loop to
			  prevent it from being reclaimed by fbuf_read_and_hash.
			*/
		} else {
			ASSERT(buf->parent == pbuf);
			ASSERT(buf->sa == sa);
			if (pbuf) {
				ASSERT(pbuf->ref_cnt != 1);
				/*
				  The reference count of the parent is always
				  incremented in the previous loop. In this case
				  we don't need to, so decremented it here to
				  compensate the increment in the previous loop.
				*/
				pbuf->ref_cnt--;
			}
		}
		if (i == ma.depth) // reach intended depth
			break;

		if (buf->on_cir_queue) {
			// move it to active indirect block queue
			fbuf_cir_queue_remove(buf);
			LIST_INSERT_HEAD(&sc.indirect_head[i], buf, indir_queue);
			buf->ref_cnt = 0;
		}
		/*
		  Increment the reference count of this buffer to prevent it
		  from being reclaimed by the call to function fbuf_read_and_hash.
		*/
		buf->ref_cnt++;

		index = ma_index_get(ma, i);// the offset of indirect block for next level
		ma_index_set(&tma, i, index);
		sa = buf->data[index];	// the sector address of the next level indirect block
		pbuf = buf;		// @buf is the parent of next level indirect block
	}
#if defined(MY_DEBUG)
	fbuf_queue_check();
#endif
	return buf;
}

/*
Description:
    Use the second chance algorithm to allocate a file buffer
*/
struct _fbuf *
fbuf_alloc(void)
{
	struct _fbuf *pbuf;	// parent buffer
	struct _fbuf *buf;

	buf = sc.cir_buffer_head;
	do {
		ASSERT(buf->on_cir_queue);
		if (!buf->accessed)
			break;
		buf->accessed = false;	// give this buffer a second chance
		buf = buf->cir_queue.next;
	} while (buf != sc.cir_buffer_head);
	sc.cir_buffer_head = buf->cir_queue.next;
	if (buf->modified)
		fbuf_flush(buf, &sc.seg_sum_hot);

	// set buf's parent to NULL
	pbuf = buf->parent;
	if (pbuf != NULL) {
		ASSERT(pbuf->on_cir_queue == false);
		buf->parent = NULL;
		pbuf->ref_cnt--;
		if (pbuf->ref_cnt == 0) {
			// move it from indirect queue to circular queue
			LIST_REMOVE(pbuf, indir_queue);
			fbuf_cir_queue_insert(pbuf);
			// set @accessed to false so that it will be reclaimed
			// next time by the second chance algorithm
			pbuf->accessed = false;
		}
	}
	return buf;
}

/*
Description:
    Allocate a file buffer, fill it with data at sector address @sa
    and insert it into hash queue with key @ma
*/
static struct _fbuf *
fbuf_read_and_hash(uint32_t sa, union meta_addr ma)
{
	struct _fbuf *buf;

	buf = fbuf_alloc();

	if (sa == SECTOR_INVALID)	// the metadata block does not exist
		memset(buf->data, 0, sizeof(buf->data));
	else {
		sc.my_read(sa, buf->data, 1);
		//sc.other_write_count++;
	}

	LIST_REMOVE(buf, buffer_bucket_queue);
	buf->ma = ma;
	fbuf_hash_insert(buf, ma.uint32);
#if defined(MY_DEBUG)
	buf->sa = sa;
#endif
	return buf;
}

static uint32_t
fbuf_write(struct _fbuf *buf, struct _seg_sum *seg_sum)
{
	uint32_t	sa;	// sector address

	// get the sector address where the block will be written
	ASSERT(seg_sum->ss_alloc_p < SEG_SUM_OFF);
	sa = seg_sum->ss_soft.seg_sa + seg_sum->ss_alloc_p;
	ASSERT(sa < sc.superblock.seg_cnt * SECTORS_PER_SEG - 1);

	sc.my_write(sa, buf->data, 1);
	buf->modified = false;
	sc.fbuf_modified_count--;
	sc.other_write_count++;

	// store the reverse mapping in segment summary
	seg_sum->ss_rm[seg_sum->ss_alloc_p++] = buf->ma.uint32;

	if (seg_sum->ss_alloc_p == SEG_SUM_OFF) { // current segment is full
		seg_sum_write(seg_sum);
		// Don't do garbage collection when writing out fbuf
	}
	return sa;
}

/*
Description:
    Write the dirty data in file buffer to disk
*/
static void
fbuf_flush(struct _fbuf *buf, struct _seg_sum *seg_sum)
{
	struct _fbuf *pbuf;	// buffer parent
	unsigned pindex; // the index in parent indirect block
	uint32_t sa;	// sector address

	ASSERT(buf->modified);
	ASSERT(IS_META_ADDR(buf->ma.uint32));
	/*
	  Must disable garbage collection until @sa is written out
	*/
	//gc_disable();
	sa = fbuf_write(buf, seg_sum);
#if defined(MY_DEBUG)
	buf->sa = sa;
#endif
	pbuf = buf->parent;
	if (pbuf) {
		ASSERT(buf->ma.depth != 0);
		ASSERT(pbuf->ma.depth == buf->ma.depth - 1);
		pindex = ma_index_get(buf->ma, buf->ma.depth - 1);
		pbuf->data[pindex] = sa;
		if (!pbuf->modified) {
			pbuf->modified = true;
			sc.fbuf_modified_count++;
		}
	} else {
		ASSERT(buf->ma.depth == 0);
		ASSERT(buf->ma.fd < FD_COUNT);
		// store the root sector address to the corresponding file table in super block
		sc.superblock.ftab[buf->ma.fd] = sa;
		sc.sb_modified = true;
	}
	//gc_enable();
	return;
}

/*
Description:
    Search the file buffer with the tag value of @ma. Return NULL if not found
*/
static struct
_fbuf *
fbuf_search(union meta_addr ma)
{
	unsigned	hash;	// hash value
	struct _fbuf_bucket	*bucket;
	struct _fbuf	*buf;

	hash = ma.uint32 % FILE_BUCKET_COUNT;
	bucket = &sc.fbuf_bucket[hash];
	LIST_FOREACH(buf, bucket, buffer_bucket_queue)
#if defined(WYC) //wyc make the code friendly to SI
;
#endif
		if (buf->ma.uint32 == ma.uint32) { // cache hit
			sc.fbuf_hit++;
			return buf;
		}
	sc.fbuf_miss++;
	return NULL;	// cache miss
}

#if 0
static uint32_t
logstor_sa2ba(uint32_t sa)
{
	uint32_t seg_sa;
	unsigned seg_off;

	seg_sa = sa & ~(SECTORS_PER_SEG - 1);
	seg_off = sa & (SECTORS_PER_SEG - 1);
	ASSERT(seg_off != SEG_SUM_OFF);
	if (seg_sa != sc.seg_sum_cache.ss_soft.ss_cached_sa) {
		sc.my_read(seg_sa + SEG_SUM_OFF, &sc.seg_sum_cache, 1);
		sc.seg_sum_cache.ss_soft.ss_cached_sa = seg_sa;
	}

	return (sc.seg_sum_cache.ss_rm[seg_off]);
}

/*
Description:
    Block address to sector address
*/
static uint32_t
logstor_ba2sa(uint32_t ba)
{
	uint32_t sa;

	if (IS_META_ADDR(ba))
		sa = fbuf_ma2sa((union meta_addr)ba);
	else {
		sa = file_read_4byte(FD_ACTIVE, ba);
	}

	return sa;
}

/*
Description:
  Check the integrity of the logstor
*/
void
logstor_check(void)
{
	uint32_t ba, sa, ba_exp;
	uint32_t max_block;
	uint32_t sa_min;

	printf("%s ...\n", __func__);
	file_mod_flush();
	if (sc.seg_sum_hot.ss_alloc_p != 0)
		seg_sum_write(&sc.seg_sum_hot);
	sa_min = -1;
	max_block = logstor_get_block_cnt();
	for (ba = 0; ba < max_block; ba++) {
		sa = logstor_ba2sa(ba);
		if (sa != SECTOR_INVALID) {
			ba_exp = logstor_sa2ba(sa);
			if (ba_exp != ba) {
				if (sa < sa_min)
					sa_min = sa;
				printf("ERROR %s: ba %u sa %u ba_exp %u\n",
				    __func__, ba, sa, ba_exp);
				PANIC();
			}
		}
	}
	printf("%s done. max_block %u\n\n", __func__, max_block);
}

static void
gc_trim(uint32_t sa)
{
	struct stat sb;
	off_t arg[2];

	if (fstat(sc.disk_fd, &sb) == -1)
		g_gate_xlog("fstat(): %s.", strerror(errno));
	if (S_ISCHR(sb.st_mode)) {
		arg[0] = sa * SECTOR_SIZE;
		arg[1] = SEG_SIZE;
		if (ioctl(sc.disk_fd, DIOCGDELETE, arg) == -1) {
			g_gate_xlog("Can't get media size: %s.",
			    strerror(errno));
		}
	}
}

/*********************************
 *  The merge sort for cache  *
 ********************************/
static struct cache_entry *merge_src;	// input source array
static struct cache_entry *merge_dst;	// output destination array
static uint8_t	merge_depth;	// recursive depth

void split_merge(unsigned begin, unsigned end);
void merge(unsigned begin, unsigned middle, unsigned end);

/*
Parameters:
  @src: source input array
  @dst: destination output array
  @n: number of elements in the array
*/void
merge_sort(struct cache_entry *src, struct cache_entry *dst, unsigned n)
{
	if (n < 1)
		return;

	merge_src = src;
	merge_dst = dst;
	merge_depth = 0;

	split_merge(0, n);

#if defined(MY_DEBUG)
	{
		unsigned i;

		/* make sure that it is sorted */
		for (i = 1; i < n ; ++i)
			ASSERT(dst[i].ba > dst[i-1].ba);
	}
#endif
}

/*
Description:
  The merge sort algorithm first splits the array into two smaller arrays.
  It then sorts two array and merge them into one array.
Parameters:
  @begin is inclusive;
  @end is exclusive (merge_src[end] is not in the set)
*/
void
split_merge(unsigned begin, unsigned end)
{
	unsigned	middle;

	merge_depth++;
	if(end - begin == 1) {	// only one element in the array
		if (merge_depth & 1) {	// depth is odd
			merge_dst[begin].ba = merge_src[begin].ba;
			merge_dst[begin].sa = merge_src[begin].sa;
		}
		goto end;
	}

	// recursively split runs into two halves until run size == 1,
	// then merge them and return back up the call chain
	middle = (end + begin) / 2;
	split_merge(begin,  middle);	// split / merge left  half
	split_merge(middle, end);	// split / merge right half
	merge(begin, middle, end);
end:
	merge_depth--;
}

/*
 Left source half is  [ begin:middle-1].
 Right source half is [middle:end-1   ].
 Result is            [ begin:end-1   ].
*/
void
merge(unsigned begin, unsigned middle, unsigned end)
{
	unsigned	i, j, k;
	struct cache_entry	*from;
	struct cache_entry	*to;

	if (merge_depth & 1) {	// depth is odd, from merge_src to merge_dst
		from = merge_src;
		to = merge_dst;
	} else {		// depth is even, from merge_dst to merge_src
		from = merge_dst;
		to = merge_src;
	}

	// While there are elements in the left or right runs
	i = begin;
	j = middle;
	for (k = begin; k < end; k++) {
		// If left run head exists and is <= existing right run head.
		if (i < middle && (j >= end || from[i].ba <= from[j].ba)) {
			to[k].ba  = from[i].ba;
			to[k].sa = from[i].sa;
			i = i + 1;
		} else {
			to[k].ba  = from[j].ba;
			to[k].ba  = from[j].ba;
			to[k].sa = from[j].sa;
			j = j + 1;
		}
	}
}
#endif

