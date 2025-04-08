/*
Author: Wuyang Chung
e-mail: wy-chung@outlook.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
//#include <assert.h>
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

#if defined(MY_DEBUG)
  #if defined(FBUF_DEBUG)
static void fbuf_mod_dump(void);
  #endif

void my_break(void) {}

void my_debug(const char * fname, int line_num, bool bl_panic)
{
	const char *type[] = {"break", "panic"};

	printf("*** %s *** %s %d\n", type[bl_panic], fname, line_num);
	perror("");
  #if defined(FBUF_DEBUG)
	fbuf_mod_dump();
  #endif
	my_break();
  	if (bl_panic)
  #if defined(EXIT_ON_PANIC)
		exit(1);
  #else
		;
  #endif
}
#endif

#define MAX_FBUF_COUNT  4096
//#define MAX_FBUF_COUNT  500 //wyctest
#define CLEAN_AGE_LIMIT	3
//#define CLEAN_WINDOW	4

#define	SIG_LOGSTOR	0x4C4F4753	// "LOGS": Log-Structured Storage
#define	VER_MAJOR	0
#define	VER_MINOR	1

#define SEG_DATA_START	1	// the data segment starts here
#define SEG_SUM_OFFSET	(SECTORS_PER_SEG - 1) // segment summary offset in segment
#define	SEG_SIZE	0x400000		// 4M
#define	SECTORS_PER_SEG	(SEG_SIZE/SECTOR_SIZE) // 1024
#define SA2SEGA_SHIFT	10
#define BLOCKS_PER_SEG	(SEG_SIZE/SECTOR_SIZE - 1)

#define	META_START	0xFF000000u	// metadata block start address
#define	META_INVALID	0		// invalid metadata address

#define	SECTOR_NULL	0	// this sector address can not map to any block address
#define SECTOR_DELETE	1	// delete marker for a block

#define	IS_META_ADDR(x)	((x) >= META_START)
#define META_LEAF_DEPTH 2

#define FILE_BUCKET_COUNT	4099

#define	FD_CUR	0
#define FD_COUNT	4	// max number of metadata files supported

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
	int32_t	sega_alloc;	// allocate this segment
	int32_t	sega_reclaim;	// clean this segment
	/*
	   The files for forward mapping file

	   Mapping is always updated in @FD_CUR. When snapshot command is issued
	   @FD_CUR is copied to @FD_DELTA and then cleaned.
	   Backup program then backs up the delta by reading @FD_DELTA.
	   After backup is finished, @FD_DELTA is merged into @FD_BASE and then cleaned.

	   If reduced to reboot restore usage, only @FD_CUR and @FD_BASE are needed.
	   Each time a PC is rebooted @FD_CUR is cleaned so all data are restored.

	   So the actual mapping is @FD_CUR || @FD_DELTA || @FD_BASE.
	   The first mapping that is not empty is used.
	*/
	uint32_t ftab[FD_COUNT]; 	// file handles table
	uint8_t sb_seg_age[];	// the starting address to store seg_age in superblock
};

#if !defined(WYC)
_Static_assert(sizeof(struct _superblock) < SECTOR_SIZE, "The size of the super block must be smaller than SECTOR_SIZE");
#endif

/*
  The last sector in a segment is the segment summary. It stores the reverse mapping table
*/
struct _seg_sum {
	uint32_t ss_rm[SECTORS_PER_SEG - 1];	// reverse map
	// reverse map SECTORS_PER_SEG - 1 is not used so we store something here
	uint16_t ss_gen;  // sequence number. used for redo after system crash
	uint16_t ss_alloc_p; // allocate sector at this location

	// below are not stored on disk
	uint32_t sega; // the segment address of the segment summary
	unsigned live_count;		
	//LIST_ENTRY(_seg_sum) queue;
};

_Static_assert(offsetof(struct _seg_sum, sega) == SECTOR_SIZE,
    "The size of segment summary must be equal to SECTOR_SIZE");

/*
  Forward map and its indirect blocks are also stored in the downstream disk.
  The sectors used to store the forward map and its indirect blocks are called metadata.

  Each metadata block has a corresponding metadata address.
  Below is the format of the metadata address.

  The metadata address occupies a small part of block address space. For block address
  that is >= META_START, it is actually a metadata address.
*/
union meta_addr { // metadata address for file data and its indirect blocks
	uint32_t	uint32;
	struct {
		uint32_t index  :20;	// index for indirect block
		uint32_t depth	:2;	// depth of the node
		uint32_t fd	:2;	// file descriptor
		uint32_t meta	:8;	// 0xFF for metadata address
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
	uint16_t ref_cnt;	// only used for fbufs on indirect queue
	bool	on_cir_queue;	// on circular queue
	bool	accessed;	// only used for fbufs on circular queue
	bool	modified;	// the fbuf is dirty
	
	LIST_ENTRY(_fbuf)	buffer_bucket_queue;// the pointer for bucket chain
	struct _fbuf	*parent;

	union meta_addr	ma;	// the metadata address
#if defined(MY_DEBUG)
	uint32_t	sa;	// the sector address of the @data
#endif
#if defined(FBUF_DEBUG)
	uint16_t	index;
	struct _fbuf 	*child[SECTOR_SIZE/sizeof(uint32_t)];
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
	
	//struct _seg_sum clean_candidate[CLEAN_WINDOW];
	//LIST_HEAD(, _seg_sum) cc_head; // clean candidate
	unsigned char cleaner_disabled;
	uint32_t clean_low_water;
	uint32_t clean_high_water;
	
	struct _fbuf *fbuf;
	int fbuf_count;
#if 0 // the accessed, modified and flag bits should be moved out of struct _fbuf
	unsigned *fbuf_accessed;
	unsigned *fbuf_modified;
	unsigned *fbuf_on_cir_queue;
#endif	
	// buffer hash queue
	LIST_HEAD(_fbuf_bucket, _fbuf)	fbuf_bucket[FILE_BUCKET_COUNT];
	
	struct _fbuf *fbuf_cir_head;	// head of the circular queue
	LIST_HEAD(, _fbuf) fbuf_ind_head[META_LEAF_DEPTH]; // indirect queue
	
#if defined(MY_DEBUG)
	int cir_queue_cnt;
#endif

	// statistics
	unsigned data_write_count;	// data block write to disk
	unsigned other_write_count;	// other write to disk, such as metadata write and segment cleaning
	unsigned fbuf_hit;
	unsigned fbuf_miss;

	bool sb_modified;	// the super block is dirty
	uint32_t sb_sa; 	// superblock's sector address
	/*
	  The macro RAM_DISK_SIZE is used for debug.
	  By using RAM as the storage device, the test can run way much faster.
	*/
#if !defined(RAM_DISK_SIZE)
	int disk_fd;
#endif
	uint8_t *seg_age;
	struct _superblock superblock;
};

#if defined(MY_DEBUG)
uint32_t sa_rw; // the sector address for _logstor_read_one/_logstor_write_one
#endif
uint32_t gdb_cond0;
uint32_t gdb_cond1;

#if defined(RAM_DISK_SIZE)
static char *ram_disk;
#endif
static struct g_logstor_softc sc;

static int _logstor_read(unsigned ba, char *data, int size);
static int _logstor_read_one(unsigned ba, char *data);
static int _logstor_write(uint32_t ba, char *data, int size, struct _seg_sum *seg_sum);
static int _logstor_write_one(uint32_t ba, char *data, struct _seg_sum *seg_sum, uint32_t *sa_out);

static void seg_alloc(struct _seg_sum *seg_sum);
static void seg_reclaim_init(struct _seg_sum *seg_sum);
static void seg_sum_write(struct _seg_sum *seg_sum);
static void seg_clean(struct _seg_sum *seg_sum);
static void seg_live_count(struct _seg_sum *seg_sum);
static void clean_check(void);
static void clean_metadata(uint32_t cur_sa, union meta_addr cur_ma);
static void clean_data(uint32_t cur_sa, uint32_t cur_ba);

static int superblock_init_read(void);
static void superblock_init_write(int fd);
static void superblock_write(void);

static uint32_t file_read_4byte(uint8_t fh, uint32_t ba);
static void file_write_4byte(uint8_t fh, uint32_t ba, uint32_t sa);
static struct _fbuf *file_access(uint8_t fd, uint32_t offset, uint32_t *buf_off, bool bl_write);

static void fbuf_mod_init(void);
static void fbuf_mod_fini(void);
static void fbuf_mod_flush(void);
static struct _fbuf *fbuf_get(union meta_addr ma);
static struct _fbuf *fbuf_read_and_hash(uint32_t sa, union meta_addr ma);
static struct _fbuf *fbuf_search(union meta_addr ma);
static bool fbuf_flush(struct _fbuf *buf);
static void fbuf_hash_insert(struct _fbuf *buf, unsigned key);

static union meta_addr ma2pma(union meta_addr ma, unsigned *pindex_out);
static uint32_t ma2sa(union meta_addr ma);

static void my_read (uint32_t sa, void *buf, unsigned size);
static void my_write(uint32_t sa, const void *buf, unsigned size);

#if defined(RAM_DISK_SIZE)
static off_t
get_mediasize(int fd)
{
	return RAM_DISK_SIZE;
}
#else
  #if __BSD_VISIBLE
static off_t
get_mediasize(int fd)
{
	off_t mediasize;
	struct stat sb;

	if (fstat(fd, &sb) == -1) {
		printf("fstat(): %s.", strerror(errno));
		exit(1);
	}
	if (S_ISCHR(sb.st_mode)) {
		if (ioctl(fd, DIOCGMEDIASIZE, &mediasize) == -1) {
			printf("Can't get media size: %s.", strerror(errno));
			exit(1);
		}
	} else if (S_ISREG(sb.st_mode)) {
		mediasize = sb.st_size;
	} else {
		printf("Unsupported file system object.");
		exit(1);
	}
	return (mediasize);
}
  #else
static off_t
get_mediasize(int fd)
{
	off_t mediasize;
	struct stat sb;
	int rc;

	rc = fstat(fd, &sb);
	MY_ASSERT(rc != -1);

	if (S_ISCHR(sb.st_mode))
		MY_ASSERT(ioctl(fd, BLKGETSIZE64, &mediasize) != -1);
	else if (S_ISREG(sb.st_mode))
		mediasize = sb.st_size;
	else
		MY_PANIC(); // Unsupported file system object

	return (mediasize);
}
  #endif
#endif
/*******************************
 *        logstor              *
 *******************************/

/*
Description:
    segment address to sector address
*/
static uint32_t
sega2sa(uint32_t sega)
{
	return sega << SA2SEGA_SHIFT;
}

void logstor_superblock_init(const char *disk_file)
{
	int disk_fd;

	disk_fd = open(disk_file, O_WRONLY);
	MY_ASSERT(disk_fd > 0);
	superblock_init_write(disk_fd);
}

void logstor_init(void)
{
	int disk_fd;

#if defined(RAM_DISK_SIZE)
	ram_disk = malloc(RAM_DISK_SIZE);
	MY_ASSERT(ram_disk != NULL);
	disk_fd = -1;
#else
	disk_fd = open(disk_file, O_WRONLY);
	MY_ASSERT(disk_fd > 0);
#endif
	superblock_init_write(disk_fd);
}

void
logstor_fini(void)
{
#if defined(RAM_DISK_SIZE)
	free(ram_disk);
#endif
}

int
logstor_open(const char *disk_file)
{
	int error;

	bzero(&sc, sizeof(sc));
#if !defined(RAM_DISK_SIZE)
  #if __BSD_VISIBLE
	sc.disk_fd = open(disk_file, O_RDWR | O_DIRECT | O_FSYNC);
  #else
	sc.disk_fd = open(disk_file, O_RDWR);
  #endif
	MY_ASSERT(sc.disk_fd > 0);
#endif
	error = superblock_init_read();
	MY_ASSERT(error == 0);
	// the order of the two statements below is important
	seg_alloc(&sc.seg_sum_cold);
	seg_alloc(&sc.seg_sum_hot);

	sc.data_write_count = sc.other_write_count = 0;
	sc.clean_low_water = 8;
	sc.clean_high_water = sc.clean_low_water + 4;

	fbuf_mod_init();
	//clean_check();

	return 0;
}

void
logstor_close(void)
{

	fbuf_mod_fini();

	seg_sum_write(&sc.seg_sum_cold);
	seg_sum_write(&sc.seg_sum_hot);

	superblock_write();
#if !defined(RAM_DISK_SIZE)
	free(sc.seg_age);
	close(sc.disk_fd);
#endif
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
	int error;

	MY_ASSERT((offset & (SECTOR_SIZE - 1)) == 0);
	MY_ASSERT((length & (SECTOR_SIZE - 1)) == 0);
	ba = offset / SECTOR_SIZE;
	size = length / SECTOR_SIZE;

	if (size == 1) {
		error = _logstor_read_one(ba, data);
	} else {
		error = _logstor_read(ba, data, size);
	}
	return error;
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
	int error;

	MY_ASSERT((offset & (SECTOR_SIZE - 1)) == 0);
	MY_ASSERT((length & (SECTOR_SIZE - 1)) == 0);
	ba = offset / SECTOR_SIZE;
	size = length / SECTOR_SIZE;

	if (size == 1) {
		error = _logstor_write_one(ba, data, &sc.seg_sum_hot, NULL);
	} else {
		error = _logstor_write(ba, data, size, &sc.seg_sum_hot);
	}
	return error;
}

// To enable TRIM, the following statement must be added
// in "case BIO_GETATTR" of g_gate_start() of g_gate.c
//	if (g_handleattr_int(pbp, "GEOM::candelete", 1))
//		return;
// and the command below must be executed before mounting the device
//	tunefs -t enabled /dev/ggate0
int logstor_delete(off_t offset, void *data, off_t length)
{
	uint32_t ba;	// block address
	int size;	// number of remaining sectors to process
	int i;

	MY_ASSERT((offset & (SECTOR_SIZE - 1)) == 0);
	MY_ASSERT((length & (SECTOR_SIZE - 1)) == 0);
	ba = offset / SECTOR_SIZE;
	size = length / SECTOR_SIZE;
	MY_ASSERT(ba < sc.superblock.max_block_cnt);

	if (size == 1) {
		file_write_4byte(FD_CUR, ba, SECTOR_DELETE);
	} else {
		for (i = 0; i<size; i++)
			file_write_4byte(FD_CUR, ba + i, SECTOR_DELETE);
	}
	// file_read_4byte/file_write_4byte might trigger fbuf_write and
	// clean check cannot be done in fbuf_write
	// so need to do a clean check here
	clean_check();

	return (0);
}

int
logstor_read_test(uint32_t ba, void *data)
{
	//wyctest return _logstor_read(ba, data, 1);
	return _logstor_read_one(ba, data);
}

int
logstor_write_test(uint32_t ba, void *data)
{
	//wyctest return _logstor_write(ba, data, 1, &sc.seg_sum_hot);
	return _logstor_write_one(ba, data, &sc.seg_sum_hot, NULL);
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

	MY_ASSERT(ba < sc.superblock.max_block_cnt);

	start_sa = pre_sa = file_read_4byte(FD_CUR, ba);
	count = 1;
	for (i = 1; i < size; i++) {
		sa = file_read_4byte(FD_CUR, ba + i);
		if (sa == pre_sa + 1) {
			count++;
			pre_sa = sa;
		} else {
			if (start_sa == SECTOR_NULL || start_sa == SECTOR_DELETE)
				bzero(data, SECTOR_SIZE);
			else {
				my_read(start_sa, data, count);
			}
			// set the values for the next write
			data += count * SECTOR_SIZE;
			start_sa = pre_sa = sa;
			count = 1;
		}
	}
	if (start_sa == SECTOR_NULL || start_sa == SECTOR_DELETE)
		bzero(data, SECTOR_SIZE);
	else {
		my_read(start_sa, data, count);
	}
	// file_read_4byte/file_write_4byte might trigger fbuf_write and
	// clean check cannot be done in fbuf_write
	// so need to do a clean check here
	clean_check();

	return 0;
}

static int
_logstor_read_one(unsigned ba, char *data)
{
	uint32_t start_sa;	// sector address

	MY_ASSERT(ba < sc.superblock.max_block_cnt);

	start_sa = file_read_4byte(FD_CUR, ba);
#if defined(MY_DEBUG)
	sa_rw = start_sa; //wyctest
#endif
	if (start_sa == SECTOR_NULL || start_sa == SECTOR_DELETE)
		bzero(data, SECTOR_SIZE);
	else {
		my_read(start_sa, data, 1);
	}
	// file_read_4byte/file_write_4byte might trigger fbuf_write and
	// clean check cannot be done in fbuf_write
	// so need to do a clean check here
	clean_check();

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

	MY_ASSERT(ba < sc.superblock.max_block_cnt);
	MY_ASSERT(seg_sum->ss_alloc_p < SEG_SUM_OFFSET);

	sec_remain = size;
	while (sec_remain > 0) {
		sec_free = SEG_SUM_OFFSET - seg_sum->ss_alloc_p;
		count = sec_remain <= sec_free? sec_remain: sec_free; // min(sec_remain, sec_free)
		sa = sega2sa(seg_sum->sega) + seg_sum->ss_alloc_p;
		MY_ASSERT(sa + count < sc.superblock.seg_cnt * SECTORS_PER_SEG);
		my_write(sa, data, count);
		data += count * SECTOR_SIZE;

		// record the reverse mapping immediately after the data have been written
		for (i = 0; i < count; i++)
			seg_sum->ss_rm[seg_sum->ss_alloc_p++] = ba + i;

		if (seg_sum->ss_alloc_p == SEG_SUM_OFFSET)
		{	// current segment is full
			seg_sum_write(seg_sum);
			seg_alloc(seg_sum);
			clean_check();
		}
		// record the forward mapping
		// the forward mapping must be recorded after
		// the segment summary block write
		// lock
		for (i = 0; i < count; i++)
			file_write_4byte(FD_CUR, ba++, sa++);
		// unlock

		sec_remain -= count;
	}

	return 0;
}

/*
Note:
  sa_out is not NULL only when called from clean_metadata

  write only data block
*/
static int
_logstor_write_one(uint32_t ba, char *data, struct _seg_sum *seg_sum, uint32_t *sa_out)
{
	MY_ASSERT(ba < sc.superblock.max_block_cnt);
	MY_ASSERT(seg_sum->ss_alloc_p < SEG_SUM_OFFSET);
#if 0
again:
	uint32_t seg_sa = sega2sa(seg_sum->sega) + seg_sum->ss_alloc_p;
	for (int i = seg_sum->ss_alloc_p; i < SEG_SUM_OFFSET; ++i)
	{
		uint32_t ba_rev = seg_sum->ss_rm[i]; // ba from the reverse map
		uint32_t sa_rev = file_read_4byte(FD_CUR, ba_rev);
		if (sa_rev != seg_sa + i) { // stale block
			my_write(seg_sa + i, data, 1);
			file_write_4byte(FD_CUR, ba, seg_sa + i);
			return 0;
		}
	}
#else
	uint32_t sa;	// sector address
	sa = sega2sa(seg_sum->sega) + seg_sum->ss_alloc_p;
  #if defined(MY_DEBUG)
	sa_rw = sa; //wyctest
  #endif
	MY_ASSERT(sa < sc.superblock.seg_cnt * SECTORS_PER_SEG);
	my_write(sa, data, 1);

	// record the reverse mapping
	seg_sum->ss_rm[seg_sum->ss_alloc_p++] = ba;

	if (seg_sum->ss_alloc_p == SEG_SUM_OFFSET)
	{	// current segment is full
		seg_sum_write(seg_sum);
		seg_alloc(seg_sum);
		clean_check();
	}
	if (IS_META_ADDR(ba)) {
		// the forwarding mapping is returned to the caller
		MY_ASSERT(sa_out != NULL);
		*sa_out = sa;
	} else {
		// record the forward mapping
		// the forward mapping must be recorded after
		// the segment summary block write
		MY_ASSERT(sa_out == NULL);
		file_write_4byte(FD_CUR, ba, sa);
	}
	return 0;
#endif
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
seg_sum_read(struct _seg_sum *seg_sum, uint32_t sega)
{
	uint32_t sa;

	seg_sum->sega = sega;
	sa = sega2sa(sega) + SEG_SUM_OFFSET;
	my_read(sa, seg_sum, 1);
}

/*
  write out the segment summary
*/
static void
seg_sum_write(struct _seg_sum *seg_sum)
{
	uint32_t sa;

	// segment summary is at the end of a segment
	sa = sega2sa(seg_sum->sega) + SEG_SUM_OFFSET;
	seg_sum->ss_gen = sc.superblock.sb_gen;
	my_write(sa, (void *)seg_sum, 1);
	sc.other_write_count++; // the write for the segment summary
}

/*
  Segment 0 is used to store superblock so there are SECTORS_PER_SEG sectors
  for storing superblock. Each time the superblock is synced, it is stored
  in the next sector. When it reachs the end of segment 0, it wraps around
  to sector 0.
*/
static int
superblock_init_read(void)
{
	int	i;
	uint16_t sb_gen;
	struct _superblock *sb_in;
	char buf[2][SECTOR_SIZE];

	_Static_assert(sizeof(sb_gen) == sizeof(sc.superblock.sb_gen), "sb_gen");

	// get the superblock
	sb_in = (struct _superblock *)buf[0];
#if defined(RAM_DISK_SIZE)
	memcpy(sb_in, ram_disk, SECTOR_SIZE);
#else
	MY_ASSERT(pread(sc.disk_fd, sb_in, SECTOR_SIZE, 0) == SECTOR_SIZE);
#endif
	if (sb_in->sig != SIG_LOGSTOR ||
	    sb_in->sega_alloc >= sb_in->seg_cnt ||
	    sb_in->sega_reclaim >= sb_in->seg_cnt)
		return EINVAL;

	sb_gen = sb_in->sb_gen;
	for (i = 1 ; i < SECTORS_PER_SEG; i++) {
		sb_in = (struct _superblock *)buf[i%2];
#if defined(RAM_DISK_SIZE)
		memcpy(sb_in, ram_disk + i * SECTOR_SIZE, SECTOR_SIZE);
#else
		MY_ASSERT(pread(sc.disk_fd, sb_in, SECTOR_SIZE, i * SECTOR_SIZE) == SECTOR_SIZE);
#endif
		if (sb_in->sig != SIG_LOGSTOR)
			break;
		if (sb_in->sb_gen != (uint16_t)(sb_gen + 1)) // IMPORTANT type cast
			break;
		sb_gen = sb_in->sb_gen;
	}
	sc.sb_sa = (i - 1);
	sb_in = (struct _superblock *)buf[(i-1)%2];
	if (sb_in->sega_alloc >= sb_in->seg_cnt ||
	    sb_in->sega_reclaim >= sb_in->seg_cnt)
		return EINVAL;

	sc.seg_age = malloc(sb_in->seg_cnt);
	MY_ASSERT(sc.seg_age != NULL);
	memcpy(sc.seg_age, sb_in->sb_seg_age, sb_in->seg_cnt);
	memcpy(&sc.superblock, sb_in, sizeof(sc.superblock));
	sc.sb_modified = false;

	return 0;
}

/*
Description:
    Write the initialized supeblock to the downstream disk
*/
static void
superblock_init_write(int fd)
{
	uint32_t sector_cnt;
	struct _superblock *sb_out;
	off_t media_size;
	char buf[SECTOR_SIZE] __attribute__ ((aligned));

	media_size = get_mediasize(fd);
	sector_cnt = media_size / SECTOR_SIZE;

	sb_out = (struct _superblock *)buf;
	sb_out->sig = SIG_LOGSTOR;
	sb_out->ver_major = VER_MAJOR;
	sb_out->ver_minor = VER_MINOR;

#if __BSD_VISIBLE
	sb_out->sb_gen = arc4random();
#else
	sb_out->sb_gen = random();
#endif	
	sb_out->seg_cnt = sector_cnt / SECTORS_PER_SEG;
	if (sizeof(struct _superblock) + sb_out->seg_cnt > SECTOR_SIZE) {
		printf("%s: size of superblock %d seg_cnt %d\n",
		    __func__, (int)sizeof(struct _superblock), (int)sb_out->seg_cnt);
		printf("    the size of the disk must be less than %lld\n",
		    (SECTOR_SIZE - sizeof(struct _superblock)) * (long long)SEG_SIZE);
		MY_PANIC();
	}
	sb_out->seg_free_cnt = sb_out->seg_cnt - SEG_DATA_START;

	// the physical disk must have at least the space for the metadata
	MY_ASSERT(sb_out->seg_free_cnt * BLOCKS_PER_SEG >
	    (sector_cnt / (SECTOR_SIZE / 4)) * FD_COUNT);

	sb_out->max_block_cnt =
	    sb_out->seg_free_cnt * BLOCKS_PER_SEG -
	    (sector_cnt / (SECTOR_SIZE / 4)) * FD_COUNT;
	sb_out->max_block_cnt *= 0.9;
#if defined(MY_DEBUG)
	printf("%s: sector_cnt %u max_block_cnt %u\n",
	    __func__, sector_cnt, sb_out->max_block_cnt);
#endif
	// the root sector address for the files
	for (int i = 0; i < FD_COUNT; i++) {
		sb_out->ftab[i] = SECTOR_NULL;	// SECTOR_NULL means not allocated yet
	}
	sb_out->sega_alloc = SEG_DATA_START;	// start allocate from here
	sb_out->sega_reclaim = SEG_DATA_START + 1;	// start reclaim from here
	bzero(sb_out->sb_seg_age, SECTOR_SIZE - sizeof(struct _superblock));

	// write out super block
#if defined(RAM_DISK_SIZE)
	memcpy(ram_disk, sb_out, SECTOR_SIZE);
#else
	MY_ASSERT(pwrite(fd, sb_out, SECTOR_SIZE, 0) == SECTOR_SIZE);
#endif

	// clear the rest of the supeblock's segment
	bzero(buf, SECTOR_SIZE);
	for (int i = 1; i < SECTORS_PER_SEG; i++) {
#if defined(RAM_DISK_SIZE)
		memcpy(ram_disk + i * SECTOR_SIZE, buf, SECTOR_SIZE);
#else
		MY_ASSERT(pwrite(fd, buf, SECTOR_SIZE, i * SECTOR_SIZE) == SECTOR_SIZE);
#endif
	}
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
	memcpy(sb_out->sb_seg_age, sc.seg_age, sb_out->seg_cnt);
	
	my_write(sc.sb_sa, sb_out, 1);
	sc.other_write_count++;
}

#if defined(RAM_DISK_SIZE)
static void
my_read(uint32_t sa, void *buf, unsigned size)
{
	MY_ASSERT(sa < sc.superblock.seg_cnt * SECTORS_PER_SEG);
	memcpy(buf, ram_disk + (off_t)sa * SECTOR_SIZE, size * SECTOR_SIZE);
}

static void
my_write(uint32_t sa, const void *buf, unsigned size)
{
	MY_ASSERT(sa < sc.superblock.seg_cnt * SECTORS_PER_SEG);
	memcpy(ram_disk + (off_t)sa * SECTOR_SIZE , buf, size * SECTOR_SIZE);
}
#else
static void
my_read(uint32_t sa, void *buf, unsigned size)
{
	ssize_t bc; // byte count

	MY_ASSERT(sa < sc.superblock.seg_cnt * SECTORS_PER_SEG);
	bc = pread(sc.disk_fd, buf, size * SECTOR_SIZE, (off_t)sa * SECTOR_SIZE);
	MY_ASSERT(bc == size * SECTOR_SIZE);
}

static void
my_write(uint32_t sa, const void *buf, unsigned size)
{
	ssize_t bc; // byte count

	MY_ASSERT(sa < sc.superblock.seg_cnt * SECTORS_PER_SEG);
	bc = pwrite(sc.disk_fd, buf, size * SECTOR_SIZE, (off_t)sa * SECTOR_SIZE);
	MY_ASSERT(bc == size * SECTOR_SIZE);
}
#endif

/*
Description:
  Allocate a segment for writing
  
Output:
  Store the segment address into @seg_sum->sega
  Initialize @seg_sum->sum.alloc_p to 0
*/
static void
seg_alloc(struct _seg_sum *seg_sum)
{
	uint32_t sega;
#if defined(MY_DEBUG)
	uint32_t sega_cold = sc.seg_sum_cold.sega;
	uint32_t sega_hot = sc.seg_sum_hot.sega;
#endif
again:
	sega = sc.superblock.sega_alloc;
	if (++sc.superblock.sega_alloc == sc.superblock.seg_cnt)
		sc.superblock.sega_alloc = SEG_DATA_START;
	MY_ASSERT(sc.superblock.sega_alloc < sc.superblock.seg_cnt);
	MY_ASSERT(sc.superblock.sega_alloc + 1 != sc.superblock.sega_reclaim);
	MY_ASSERT(sega != sega_hot);

	if (sc.seg_age[sega] != 0)	// this segment is not free
		goto again;

	MY_ASSERT(sega != sega_cold);
	sc.seg_age[sega] = 1;	
	seg_sum->sega = sega;
	seg_sum->ss_alloc_p = 0;

	sc.superblock.seg_free_cnt--;
	MY_ASSERT(sc.superblock.seg_free_cnt > 0 &&
	    sc.superblock.seg_free_cnt < sc.superblock.seg_cnt);
	
}

/*
Description:
  This function does the following things:
  1. Get the segment address of the segment to reclaim
  2. Read the contents of the segment summary of the reclaimed segment
  3. Count the live blocks in this segment
*/
static void
seg_reclaim_init(struct _seg_sum *seg_sum)
{
	uint32_t sega;
	uint32_t sega_cold = sc.seg_sum_cold.sega;
	uint32_t sega_hot = sc.seg_sum_hot.sega;

again:
	sega = sc.superblock.sega_reclaim;
	if (++sc.superblock.sega_reclaim == sc.superblock.seg_cnt)
		sc.superblock.sega_reclaim = SEG_DATA_START;
	MY_ASSERT(sc.superblock.sega_reclaim < sc.superblock.seg_cnt);
	MY_ASSERT(sega != sega_hot);
#if 0
	MY_ASSERT(sega != sega_cold);
#else
	if (sega == sega_cold)
		goto again;
#endif
	seg_sum_read(seg_sum, sega);
	seg_live_count(seg_sum);
	return;
}

/********************
* segment cleaning  *
*********************/

static void
clean_metadata(uint32_t cur_sa, union meta_addr cur_ma)
{
	struct _fbuf *buf, *pbuf;
	unsigned pindex;
	uint32_t mapped_sa, new_sa;
	union meta_addr pma;
	uint32_t sec_buf[SECTOR_SIZE/4];

	mapped_sa = ma2sa(cur_ma);
	if (cur_sa == mapped_sa) { // metadata might be live
		buf = fbuf_search(cur_ma);
		if (buf == NULL) {
			my_read(cur_sa, sec_buf, 1);
			_logstor_write_one(cur_ma.uint32, (char *)sec_buf,
			    &sc.seg_sum_cold, &new_sa);
			if (cur_ma.depth != 0) {
				pma = ma2pma(cur_ma, &pindex);
				pbuf = fbuf_get(pma);
				pbuf->data[pindex] = new_sa;
				if (!pbuf->modified) {
					pbuf->modified = true;
				}
			} else {
				sc.superblock.ftab[cur_ma.fd] = new_sa;
				sc.sb_modified = true;
			}
		} else if (!buf->modified) {
			// set modified to true so it will eventually be written out
			buf->modified = true;
		}
	}
}

static void
clean_data(uint32_t cur_sa, uint32_t cur_ba)
{
	uint32_t mapped_sa;
	uint32_t sec_buf[SECTOR_SIZE/4];

	mapped_sa = file_read_4byte(FD_CUR, cur_ba);
	if (cur_sa == mapped_sa) { // live data
		my_read(cur_sa, sec_buf, 1);
		_logstor_write_one(cur_ba, (char *)sec_buf, &sc.seg_sum_cold, NULL);
	}
}

/*
  Input:  seg_sum->seg_sa, segment's sector address
  Output: seg_sum->live_count
*/
static void
seg_live_count(struct _seg_sum *seg_sum)
{
	uint32_t cur_ba;
	uint32_t cur_sa, mapped_sa;
	uint32_t seg_sa;
	unsigned live_count = 0;
	struct _fbuf *buf;

	seg_sa = sega2sa(seg_sum->sega);
	for (int i = 0; i < seg_sum->ss_alloc_p; i++)
	{
		cur_sa = seg_sa + i;
		cur_ba = seg_sum->ss_rm[i];	// get the block address from reverse map
		if (IS_META_ADDR(cur_ba)) {
			mapped_sa = ma2sa((union meta_addr)cur_ba); 
			if (cur_sa == mapped_sa) { // metadata might be live
				buf = fbuf_search((union meta_addr)cur_ba);
				if (buf == NULL)
					live_count++;
			}
		} else {
			mapped_sa = file_read_4byte(FD_CUR, cur_ba); 
			if (cur_sa == mapped_sa) // live data
				live_count++;
		}
	}
	seg_sum->live_count = live_count;
}

static void
seg_clean(struct _seg_sum *seg_sum)
{
	uint32_t seg_sa;	// the sector address of the cleaning segment
	uint32_t cur_sa, cur_ba;
	uint32_t sega;
	int	i;

	seg_sa = sega2sa(seg_sum->sega);
	for (i = 0; i < seg_sum->ss_alloc_p; i++) {
		cur_sa = seg_sa + i;
		cur_ba = seg_sum->ss_rm[i];	// get the block address from reverse map
		if (IS_META_ADDR(cur_ba)) {
			clean_metadata(cur_sa, (union meta_addr)cur_ba);
		} else {
			clean_data(cur_sa, cur_ba);
		}
	}
	sega = seg_sum->sega;
	sc.seg_age[sega] = 0; // It's cleaned
	sc.superblock.seg_free_cnt++;
}

#if 1
static void
cleaner(void)
{
	struct _seg_sum seg;

	do {
		seg_reclaim_init(&seg);
		if (seg.live_count < (SECTORS_PER_SEG - 1) * 0.95)
			seg_clean(&seg);
		else if (sc.seg_age[seg.sega] > CLEAN_AGE_LIMIT)
			// For wearleveling, if it is old enough clean it.
			seg_clean(&seg);
		else
			sc.seg_age[seg.sega]++;
	} while (sc.superblock.seg_free_cnt < sc.clean_high_water);
	//NOTE: need to flush the metadata to disk before erase the reclaimed segments
}
#else
static void
cleaner(void)
{
	struct _seg_sum *seg, *seg_to_clean;
	unsigned live_count_min;
	int	i;

//printf("\n%s >>>\n", __func__);
	do {
		LIST_INIT(&sc.cc_head);
		for (i = 0; i < CLEAN_WINDOW; i++) {
			seg = &sc.clean_candidate[i];
			seg_reclaim_init(seg);
			LIST_INSERT_HEAD(&sc.cc_head, seg, queue);
		}
		for (i = 0; i < CLEAN_WINDOW; i++) {
			// find the segment with min live sectors and clean it
			live_count_min = -1; // the maximum unsigned integer
			LIST_FOREACH(seg, &sc.cc_head, queue) {
				if (sc.seg_age[seg->sega] > CLEAN_AGE_LIMIT) {
					// force to clean this segment
					seg_to_clean = seg;
					break;
				}
				if (seg->live_count < live_count_min) {
					live_count_min = seg->live_count;
					seg_to_clean = seg;
				}
			}
			seg_clean(seg_to_clean);

			// get the next segment and place it at the end of the queue
			seg_reclaim_init(seg_to_clean);
			LIST_REMOVE(seg_to_clean, queue);
			LIST_INSERT_HEAD(&sc.cc_head, seg_to_clean, queue);
		}
		LIST_FOREACH(seg, &sc.cc_head, queue) {
			if (seg->live_count < (SECTORS_PER_SEG - 1) * 0.96)
				seg_clean(seg);
			else
				sc.seg_age[seg->sega]++;
		}
	} while (sc.superblock.seg_free_cnt < sc.clean_high_water);
//printf("%s <<<\n", __func__);
}
#endif

static inline void
cleaner_enable(void)
{
	MY_ASSERT(sc.cleaner_disabled != 0);
	sc.cleaner_disabled--;
}

static inline void
cleaner_disable(void)
{
	MY_ASSERT(sc.cleaner_disabled <= 2);
	sc.cleaner_disabled++;
}

static void
clean_check(void)
{
	if (sc.superblock.seg_free_cnt <= sc.clean_low_water && !sc.cleaner_disabled) {
		cleaner_disable();	// disable gargabe collection
		cleaner();
		cleaner_enable(); // enable gargabe collection
	} 
}

/*********************************************************
 * The file buffer and indirect block cache              *
 *   Cache the the block to sector address translation   *
 *********************************************************/

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
	struct _fbuf *buf;
	uint32_t offset;	// the offset within the file buffer data

	MY_ASSERT((ba & 0xc0000000u) == 0); // the most significant 2-bits can not be used
	buf = file_access(fd, ba << 2, &offset, false);
	return *((uint32_t *)((uint8_t *)buf->data + offset));
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
	struct _fbuf *buf;
	uint32_t offset;	// the offset within the file buffer data

	MY_ASSERT((ba & 0xc0000000u) == 0); // the most significant 2-bits can not be used
	buf = file_access(fd, ba << 2, &offset, true);
	*((uint32_t *)((uint8_t*)buf->data + offset)) = sa;
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
static struct _fbuf *
file_access(uint8_t fd, uint32_t offset, uint32_t *buf_off, bool bl_write)
{
	union meta_addr	ma;		// metadata address
	struct _fbuf *buf;

	*buf_off = offset & 0xfffu;

	// convert to metadata address from (@fd, @offset)
	ma.uint32 = META_START + (offset >> 12); // also set .index, .depth and .fd to 0
	ma.depth = META_LEAF_DEPTH;
	ma.fd = fd;
	buf = fbuf_get(ma);
	buf->accessed = true;
	if (!buf->modified && bl_write) {
		buf->modified = true;
	}
	return buf;
}

/*
  Initialize metadata file buffer
*/
static void
fbuf_mod_init(void)
{

	sc.fbuf_hit = sc.fbuf_miss = 0;
	sc.fbuf_count = sc.superblock.max_block_cnt / (SECTOR_SIZE / 4);
	if (sc.fbuf_count > MAX_FBUF_COUNT)
		sc.fbuf_count = MAX_FBUF_COUNT;
	size_t fbuf_size = sizeof(*sc.fbuf) * sc.fbuf_count;
	sc.fbuf = malloc(fbuf_size);
	MY_ASSERT(sc.fbuf != NULL);

	for (int i = 0; i < FILE_BUCKET_COUNT; i++)
		LIST_INIT(&sc.fbuf_bucket[i]);
#if 0
	sc.fbuf_accessed = malloc(sc.fbuf_count/8);
	MY_ASSERT(sc.fbuf_accessed != NULL);
	sc.fbuf_modified = malloc(sc.fbuf_count/8);
	MY_ASSERT(sc.fbuf_modified != NULL);
	sc.fbuf_on_cir_queue = malloc(sc.fbuf_count/8);
	MY_ASSERT(sc.fbuf_on_cir_queue != NULL);
#endif
#if defined(MY_DEBUG)
	sc.cir_queue_cnt = sc.fbuf_count;
#endif
	for (int i = 0; i < sc.fbuf_count; i++) {
#if defined(FBUF_DEBUG)
		sc.fbuf[i].index = i;
#endif
		sc.fbuf[i].ma.uint32 = META_INVALID;
		sc.fbuf[i].cir_queue.prev = &sc.fbuf[i-1];
		sc.fbuf[i].cir_queue.next = &sc.fbuf[i+1];
		sc.fbuf[i].parent = NULL;
		sc.fbuf[i].on_cir_queue = true;
		sc.fbuf[i].accessed = false;
		sc.fbuf[i].modified = false;
		// to distribute the file buffer to buckets evenly 
		// use @i as the key when the tag is META_INVALID
		fbuf_hash_insert(&sc.fbuf[i], i);
	}
	// fix the circular queue for the first and last buffer
	sc.fbuf[0].cir_queue.prev = &sc.fbuf[sc.fbuf_count-1];
	sc.fbuf[sc.fbuf_count-1].cir_queue.next = &sc.fbuf[0];
	sc.fbuf_cir_head = &sc.fbuf[0]; // point to the circular queue

	for (int i = 0; i < META_LEAF_DEPTH; i++)
		LIST_INIT(&sc.fbuf_ind_head[i]); // point to active indirect blocks with depth i
}

static void
fbuf_mod_fini(void)
{
	fbuf_mod_flush();
	free(sc.fbuf);
}

static void
fbuf_mod_flush(void)
{
	struct _fbuf	*buf;
	int	i;
	unsigned count = 0;

	buf = sc.fbuf_cir_head;
	do {
		MY_ASSERT(buf->on_cir_queue);
		if (fbuf_flush(buf))
			count++;
		buf = buf->cir_queue.next;
	} while (buf != sc.fbuf_cir_head);
	
	// process active indirect blocks
	for (i = META_LEAF_DEPTH - 1; i >= 0; i--)
		LIST_FOREACH(buf, &sc.fbuf_ind_head[i], indir_queue) {
			MY_ASSERT(buf->on_cir_queue == false);
			if (fbuf_flush(buf))
				count++;
		}
//printf("%s: flushed count %u\n", __func__, count);
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
		MY_PANIC();
	}
	return (index & 0x3ffu);
}

static void
ma_index_set(union meta_addr *ma, unsigned depth, unsigned index)
{

	MY_ASSERT(depth < META_LEAF_DEPTH);
	MY_ASSERT(index < 1024);

	switch (depth) {
	case 0:
		index <<= 10;
		ma->uint32 &= 0xfff003ffu;
		break;
	case 1:
		ma->uint32 &= 0xfffffc00u;
		break;
	default:
		MY_PANIC();
	}
	ma->uint32 |= index;
}

/*
  to parent's metadata address

output:
  pindex_out: the index in parent's metadata

return:
  parent's metadata address
*/
static union meta_addr
ma2pma(union meta_addr ma, unsigned *pindex_out)
{

	switch (ma.depth)
	{
	case 1:
		*pindex_out = ma_index_get(ma, 0);
		//ma_index_set(&ma, 0, 0);
		//ma_index_set(&ma, 1, 0);
		ma.index = 0; // optimization of the above 2 statements
		ma.depth = 0; // i.e. ma.depth - 1
		break;
	case 2:
		*pindex_out = ma_index_get(ma, 1);
		ma_index_set(&ma, 1, 0);
		ma.depth = 1; // i.e. ma.depth - 1
		break;
	default:
		MY_PANIC();
		break;
	}
	return ma;
}

// metadata address to sector address
static uint32_t
ma2sa(union meta_addr ma)
{
	struct _fbuf *pbuf;
	unsigned pindex;	//index in the parent indirect block
	union meta_addr pma;	// parent's metadata address
	uint32_t sa;

	switch (ma.depth)
	{
	case 0:
		sa = sc.superblock.ftab[ma.fd];
		break;
	case 1:
	case 2:
		pma = ma2pma(ma, &pindex);
		pbuf = fbuf_get(pma);
		sa = pbuf->data[pindex];
		break;
	default:
		MY_PANIC();
		sa = 0;
		break;
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

	buf = sc.fbuf_cir_head;
	MY_ASSERT(buf != NULL);
	total = 0;
	do  {
		++total;
		MY_ASSERT(total <= sc.fbuf_count);
		MY_ASSERT(buf->on_cir_queue);
		buf = buf->cir_queue.next;
	} while (buf != sc.fbuf_cir_head);

	for (i = 0; i < META_LEAF_DEPTH; i++)
		indir_cnt[i] = 0;

	for (i = 0; i < META_LEAF_DEPTH ; ++i) {
		buf = LIST_FIRST(&sc.fbuf_ind_head[i]);
		while (buf != NULL) {
			++indir_cnt[0];
			MY_ASSERT(indir_cnt[0] <= sc.fbuf_count);
			MY_ASSERT(buf->on_cir_queue == false);
			MY_ASSERT(buf->ma.depth == i);
			buf = LIST_NEXT(buf, indir_queue);
		}
	}

	for (i = 0; i < META_LEAF_DEPTH; i++)
		total += indir_cnt[i];
	
	MY_ASSERT(total == sc.fbuf_count);
}
#endif

/*
    Circular queue insert before
*/
static void
fbuf_cir_queue_insert_tail(struct _fbuf *buf)
{
	struct _fbuf *prev;

	prev = sc.fbuf_cir_head->cir_queue.prev;
	sc.fbuf_cir_head->cir_queue.prev = buf;
	buf->cir_queue.next = sc.fbuf_cir_head;
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

	MY_ASSERT(buf->on_cir_queue);
	MY_ASSERT(sc.fbuf_cir_head->cir_queue.next != sc.fbuf_cir_head);
	MY_ASSERT(sc.fbuf_cir_head->cir_queue.prev != sc.fbuf_cir_head);
	if (buf == sc.fbuf_cir_head)
		sc.fbuf_cir_head = sc.fbuf_cir_head->cir_queue.next;
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

	MY_ASSERT(IS_META_ADDR(ma.uint32));
	buf = fbuf_search(ma);
	if (buf != NULL) // cache hit
		return buf;

	// cache miss
	// get the root sector address of the file @ma.fd
	MY_ASSERT(ma.fd < FD_COUNT);
	sa = sc.superblock.ftab[ma.fd];
	pbuf = NULL;	// parent for root is NULL
	tma.uint32 = META_START; // also set .index, .depth and .fd to 0
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
#if defined(FBUF_DEBUG)
			if (pbuf)
				pbuf->child[index] = buf;
#endif
		} else {
			MY_ASSERT(buf->parent == pbuf);
			MY_ASSERT(buf->sa == sa);
			if (pbuf) {
				MY_ASSERT(pbuf->ref_cnt != 1);
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
			LIST_INSERT_HEAD(&sc.fbuf_ind_head[i], buf, indir_queue);
			buf->ref_cnt = 0;
		}
		/*
		  Increment the reference count of this buffer to prevent it
		  from being reclaimed by the call to function fbuf_read_and_hash.
		*/
		buf->ref_cnt++;

		index = ma_index_get(ma, i);// the index to next level's indirect block
		sa = buf->data[index];	// the sector address of the next level indirect block
		ma_index_set(&tma, i, index); // set the next level's index for @tma
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
#if defined(FBUF_DEBUG)
	unsigned pindex;
#endif

	buf = sc.fbuf_cir_head;
	do {
		MY_ASSERT(buf->on_cir_queue);
		if (!buf->accessed)
			break;
		buf->accessed = false;	// give this buffer a second chance
		buf = buf->cir_queue.next;
	} while (buf != sc.fbuf_cir_head);
	sc.fbuf_cir_head = buf->cir_queue.next;

	LIST_REMOVE(buf, buffer_bucket_queue);
	fbuf_flush(buf);

	// set buf's parent to NULL
	pbuf = buf->parent;
	if (pbuf != NULL) {
		MY_ASSERT(pbuf->on_cir_queue == false);
		buf->parent = NULL;
		pbuf->ref_cnt--;
		if (pbuf->ref_cnt == 0) {
			// move it from indirect queue to circular queue
			LIST_REMOVE(pbuf, indir_queue);
			fbuf_cir_queue_insert_tail(pbuf);
			// set @accessed to false so that it will be reclaimed
			// next time by the second chance algorithm
			pbuf->accessed = false;
		}
#if defined(FBUF_DEBUG)
		pindex = ma_index_get(buf->ma, buf->ma.depth - 1);
		pbuf->child[pindex] = NULL;
#endif
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

	buf = fbuf_alloc();	// allocate a fbuf from circular queue

	if (sa == SECTOR_NULL)	// the metadata block does not exist
		bzero(buf->data, sizeof(buf->data));
	else {
		my_read(sa, buf->data, 1);
		//sc.other_write_count++;
	}

	buf->ma = ma;
	fbuf_hash_insert(buf, ma.uint32);
#if defined(MY_DEBUG)
	buf->sa = sa;
#endif

	return buf;
}

static void
fbuf_write(struct _fbuf *buf)
{
	struct _fbuf *pbuf;	// buffer parent
	unsigned pindex;	// the index in parent indirect block
	uint32_t sa;		// sector address
	struct _seg_sum *seg_hot = &sc.seg_sum_hot;

	// get the sector address where the block will be written
	MY_ASSERT(seg_hot->ss_alloc_p < SEG_SUM_OFFSET);
	sa = sega2sa(seg_hot->sega) + seg_hot->ss_alloc_p;
	MY_ASSERT(sa < sc.superblock.seg_cnt * SECTORS_PER_SEG - 1);

	my_write(sa, buf->data, 1);
#if defined(MY_DEBUG)
	buf->sa = sa;
#endif
	buf->modified = false;
	sc.other_write_count++;

	// store the forward mapping in parent indirect block
	pbuf = buf->parent;
	if (pbuf) {
		MY_ASSERT(buf->ma.depth != 0);
		MY_ASSERT(pbuf->ma.depth == buf->ma.depth - 1);
		pindex = ma_index_get(buf->ma, buf->ma.depth - 1);
		pbuf->data[pindex] = sa;
		if (!pbuf->modified) {
			pbuf->modified = true;
		}
	} else {
		MY_ASSERT(buf->ma.depth == 0);
		MY_ASSERT(buf->ma.fd < FD_COUNT);
		// store the root sector address to the corresponding file table in super block
		sc.superblock.ftab[buf->ma.fd] = sa;
		sc.sb_modified = true;
	}

	// store the reverse mapping in segment summary
	seg_hot->ss_rm[seg_hot->ss_alloc_p++] = buf->ma.uint32;

	if (seg_hot->ss_alloc_p == SEG_SUM_OFFSET) { // current segment is full
		seg_sum_write(seg_hot);
		seg_alloc(seg_hot);
		// Cannot do clean_check() here. It will cause recursive call.
	}
}

/*
Description:
    Write the dirty data in file buffer to disk
*/
static bool
fbuf_flush(struct _fbuf *buf)
{

	if (!buf->modified)
		return false;

	MY_ASSERT(IS_META_ADDR(buf->ma.uint32));
	fbuf_write(buf);
	return true;
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
	LIST_FOREACH(buf, bucket, buffer_bucket_queue) {
		if (buf->ma.uint32 == ma.uint32) { // cache hit
			sc.fbuf_hit++;
			return buf;
		}
	}
	sc.fbuf_miss++;
	return NULL;	// cache miss
}

#if defined(FBUF_DEBUG)
static void
fbuf_dump(struct _fbuf *buf, FILE *fh)
{
	int i;

	fprintf(fh, "sa %08u depth %d\n", buf->sa, buf->ma.depth);
	for (i = 0; i < SECTOR_SIZE/4;  i++)
		fprintf(fh, "[%04d] %08u\n", i, buf->data[i]);
	fprintf(fh, "======================\n");
}

static void
fbuf_mod_dump(void)
{
	FILE *fh;
	struct _fbuf *buf;
	int i;

	fh = fopen("fbuf.txt", "w");
	MY_ASSERT(fh != NULL);

	fbuf_mod_flush();
	fprintf(fh, "\n\n");
	for (i = 0; i < META_LEAF_DEPTH; i++) {
		fprintf(fh, "indir queue %d\n", i);
		LIST_FOREACH(buf, &sc.fbuf_ind_head[i], indir_queue) {
			MY_ASSERT(buf->on_cir_queue == false);
			fbuf_dump(buf, fh);
		}
	}
	buf = sc.fbuf_cir_head;
	do {
		fbuf_dump(buf, fh);
		buf = buf->cir_queue.next;
	} while (buf != sc.fbuf_cir_head);

	fclose(fh);
}
#endif
//===================================================
#if 0
static uint32_t
logstor_sa2ba(uint32_t sa)
{
	uint32_t seg_sa;
	unsigned seg_off;

	seg_sa = sa & ~(SECTORS_PER_SEG - 1);
	seg_off = sa & (SECTORS_PER_SEG - 1);
	MY_ASSERT(seg_off != SEG_SUM_OFFSET);
	if (seg_sa != sc.seg_sum_cache.ss_cached_sa) {
		my_read(seg_sa + SEG_SUM_OFFSET, &sc.seg_sum_cache, 1);
		sc.seg_sum_cache.ss_cached_sa = seg_sa;
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
		sa = ma2sa((union meta_addr)ba);
	else {
		sa = file_read_4byte(FD_CUR, ba);
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
	fbuf_mod_flush();
	if (sc.seg_sum_hot.ss_alloc_p != 0)
		seg_sum_write(&sc.seg_sum_hot);
	sa_min = -1;
	max_block = logstor_get_block_cnt();
	for (ba = 0; ba < max_block; ba++) {
		sa = logstor_ba2sa(ba);
		if (sa != SECTOR_NULL) {
			ba_exp = logstor_sa2ba(sa);
			if (ba_exp != ba) {
				if (sa < sa_min)
					sa_min = sa;
				printf("ERROR %s: ba %u sa %u ba_exp %u\n",
				    __func__, ba, sa, ba_exp);
				MY_PANIC();
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
			MY_ASSERT(dst[i].ba > dst[i-1].ba);
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

