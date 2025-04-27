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
void my_break(void) {}

void my_debug(const char * fname, int line_num, bool bl_panic)
{
	const char *type[] = {"break", "panic"};

	printf("*** %s *** %s %d\n", type[bl_panic], fname, line_num);
	perror("");
	my_break();
  	if (bl_panic)
  #if defined(EXIT_ON_PANIC)
		exit(1);
  #else
		;
  #endif
}
#endif

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define __predict_true(exp)     __builtin_expect((exp), 1)
#define __predict_false(exp)    __builtin_expect((exp), 0)
#define __unused		__attribute__((unused))

#define RAM_DISK_SIZE		0x180000000UL // 6G

#define	SIG_LOGSTOR	0x4C4F4753	// "LOGS": Log-Structured Storage
#define	VER_MAJOR	0
#define	VER_MINOR	1

#define SEG_DATA_START	1	// the data segment starts here
#define SEG_SUM_OFFSET	(SECTORS_PER_SEG - 1) // segment summary offset in segment
#define	SEG_SIZE	0x400000		// 4M
#define	SECTORS_PER_SEG	(SEG_SIZE/SECTOR_SIZE) // 1024
#define SA2SEGA_SHIFT	10
#define BLOCKS_PER_SEG	(SEG_SIZE/SECTOR_SIZE - 1)

#define BLOCK_INVALID	(((union meta_addr){.meta = 0xFF, .depth = 3}).uint32) // depth can never be 3
#define META_INVALID	((union meta_addr){.uint32 = 0})
#define	META_START	(((union meta_addr){.meta = 0xFF}).uint32)	// metadata block address start
#define META_LEAF_DEPTH 2
#define	IS_META_ADDR(x)	((x) >= META_START)

#define	SECTOR_NULL	0	// this sector address can not map to any block address
#define SECTOR_DEL	1	// delete marker for a block

//#define FBUF_MAX	500
#define FBUF_CLEAN_THRESHOLD	12
#define FBUF_MIN	(1032 + FBUF_CLEAN_THRESHOLD)
#define FBUF_MAX	(FBUF_MIN * 2)
#define FBUF_BUCKETS	1097	// this should be a prime number

#define	FD_CUR	1
#define FD_COUNT	4	// max number of metadata files supported
#define FD_INVALID	-1	// invalid file

struct _superblock {
	uint32_t sig;		// signature
	uint8_t  ver_major;
	uint8_t  ver_minor;
	uint16_t sb_gen;	// the generation number. Used for redo after system crash
	/*
	   The segments are treated as circular buffer
	 */
	uint32_t seg_cnt;	// total number of segments
	uint32_t seg_alloc;	// allocate this segment
	uint32_t sector_cnt_free;
	uint32_t block_cnt_max;	// max number of blocks supported
	/*
	   The files for forward mapping file

	   Normally mapping is written to %fd_cur. When commit command is issued
	   %fd_cur and %fd_snap are merged to %fd_snap_new and new mappings are temporarily
	   written to %fd_new.
	   After the commit command is complete, %fd_new will become %fd_cur
	   %fd_new_snap will become %fd_snap and the old %fd_cur and %fd_snap
	   will be deleted.

	   So the actual mapping in normal state is
	       %fd_cur || %fd_snap
	   and during commit it is
	       %fd_new_cur || %fd_cur || %fd_snap

	   The first mapping that is not empty is used.
	*/
	uint32_t fd_tab[FD_COUNT]; 	// file handles table
	uint8_t fd_cur;		// the file descriptor for current mapping
	uint8_t fd_snap;	// the file descriptor for snapshot mapping
	uint8_t fd_new;		// the file descriptor for new current mapping
	uint8_t fd_new_snap;	// the file descriptor for new snapshot mapping
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
	uint16_t ss_alloc; // allocate sector at this location
	uint16_t ss_gen;  // sequence number. used for redo after system crash
};

_Static_assert(sizeof(struct _seg_sum) == SECTOR_SIZE,
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
		uint32_t index1 :10;	// index for indirect block of depth 1
		uint32_t index0 :10;	// index for indirect block of depth 0
		uint32_t depth	:2;	// depth of the node
		uint32_t fd	:2;	// file descriptor
		uint32_t meta	:8;	// 0xFF for metadata address
	};
	struct {
		uint32_t index :20;	// index for indirect blocks
	};
};

_Static_assert(sizeof(union meta_addr) == 4, "The size of emta_addr must be 4");

enum {
	QUEUE_IND0,	// for level 0 indirect blocks
	QUEUE_IND1,	// for level 1 indirect blocks
	QUEUE_LEAF,	// only replace buffers from leaf nodes
	QUEUE_CLEAN,	// leaf node but also guaranteed clean
	QUEUE_CNT,
};
_Static_assert(QUEUE_IND0 == 0, "QUEUE_IND0 must be 0");
_Static_assert(QUEUE_IND1 == 1, "QUEUE_IND1 must be 1");

struct _fbuf_comm {
	struct _fbuf *queue_next;
	struct _fbuf *queue_prev;
	bool is_sentinel;
	bool accessed;	/* only used for fbufs on circular queue */
	bool modified;	/* the fbuf is dirty */
};

struct _fbuf_sentinel {
	struct _fbuf_comm fc;
};

/*
  Metadata is cached in memory. The access unit of metadata is block so each cache line
  stores a block of metadata
*/
struct _fbuf { // file buffer
	struct _fbuf_comm fc;
	uint16_t queue_which;
	uint16_t bucket_which;
	struct _fbuf *bucket_next;
	struct _fbuf *bucket_prev;
	unsigned child_ref_cnt; // number of children reference this fbuf
	struct _fbuf	*parent;

	union meta_addr	ma;	// the metadata address
	// the metadata is cached here
	uint32_t	data[SECTOR_SIZE/sizeof(uint32_t)];
#if defined(MY_DEBUG)
	uint32_t	sa;	// the sector address of the @data
#endif
#if defined(FBUF_DEBUG)
	uint16_t	index; // the array index for this fbuf
	struct _fbuf 	*child[SECTOR_SIZE/sizeof(uint32_t)];
#endif
};

/*
	logstor soft control
*/
struct g_logstor_softc {
	uint32_t seg_alloc_sa;
	struct _seg_sum seg_sum;// segment summary for the hot segment
	
	int fbuf_count;
	struct _fbuf *fbuf;
	struct _fbuf_queue {
		struct _fbuf_sentinel sentinel;	// head of the queues
		struct _fbuf *head; // always points to sentinel except for QUEUE_LEAF
		int	count;
	} fbuf_queue[QUEUE_CNT];

	// buffer hash queue
	struct {
		struct _fbuf_sentinel sentinel;	// head of the queues
#if defined(MY_DEBUG)
		int	count;
#endif
	} fbuf_bucket[FBUF_BUCKETS];
	
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
	struct _superblock superblock;
};

uint32_t gdb_cond0;
uint32_t gdb_cond1;

#if defined(RAM_DISK_SIZE)
static char *ram_disk;
#endif
static struct g_logstor_softc sc;

static uint32_t _logstor_read_one(unsigned ba, void *data);
static uint32_t _logstor_write_one(uint32_t ba, void *data);

static void seg_alloc(void);
static void seg_sum_write(void);

static void disk_init(int fd);
static int  superblock_read(void);
static void superblock_write(void);

static uint32_t file_read_4byte(uint8_t fh, uint32_t ba);
static void file_write_4byte(uint8_t fh, uint32_t ba, uint32_t sa);
static struct _fbuf *file_access_4byte(uint8_t fd, uint32_t offset, uint32_t *off_4byte);

static void fbuf_mod_init(void);
static void fbuf_mod_fini(void);
static void fbuf_mod_flush(void);
static void fbuf_flush(struct _fbuf *fbuf);
static void fbuf_write(struct _fbuf *fbuf);
static void fbuf_queue_init(int which);
static void fbuf_queue_insert_tail(int which, struct _fbuf *fbuf);
static void fbuf_queue_remove(struct _fbuf *fbuf);
static void fbuf_clean_queue_check(void);
static void fbuf_hash_init(int which);
static void fbuf_hash_insert_head(struct _fbuf *fbuf);
static void fbuf_hash_remove(struct _fbuf *fbuf);
static struct _fbuf *fbuf_search(union meta_addr ma);
static struct _fbuf *fbuf_get(union meta_addr ma);
static struct _fbuf *fbuf_alloc(void);

static union meta_addr ma2pma(union meta_addr ma, unsigned *pindex_out);
static uint32_t ma2sa(union meta_addr ma);

static void my_read (uint32_t sa, void *buf, unsigned size);
static void my_write(uint32_t sa, const void *buf, unsigned size);

static void logstor_check(void);
static void fbuf_queue_check(void);

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

// called by ggate or logsinit when disk is a file
// not used when disk is a ram disk
void logstor_disk_init(const char *disk_file)
{
	int disk_fd;

	disk_fd = open(disk_file, O_WRONLY);
	MY_ASSERT(disk_fd > 0);
	disk_init(disk_fd);
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
	disk_init(disk_fd);
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
	bzero(&sc, sizeof(sc));
#if !defined(RAM_DISK_SIZE)
  #if __BSD_VISIBLE
	sc.disk_fd = open(disk_file, O_RDWR | O_DIRECT | O_FSYNC);
  #else
	sc.disk_fd = open(disk_file, O_RDWR);
  #endif
	MY_ASSERT(sc.disk_fd > 0);
#endif
	int error __unused;

	error = superblock_read();
	MY_ASSERT(error == 0);

	// read the segment summary block
	sc.seg_alloc_sa = sega2sa(sc.superblock.seg_alloc);
	uint32_t sa = sc.seg_alloc_sa + SEG_SUM_OFFSET;
	my_read(sa, &sc.seg_sum, 1);
	sc.data_write_count = sc.other_write_count = 0;

	fbuf_mod_init();
	logstor_check();

	return 0;
}

void
logstor_close(void)
{

	fbuf_mod_fini();

	seg_sum_write();

	superblock_write();
#if !defined(RAM_DISK_SIZE)
	close(sc.disk_fd);
#endif
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
	MY_ASSERT(ba < sc.superblock.block_cnt_max);

	for (i = 0; i < size; i++)
		file_write_4byte(sc.superblock.fd_cur, ba + i, SECTOR_DEL);

	fbuf_clean_queue_check();
	return (0);
}

// using the second chance replace policy
struct _fbuf *
fbuf_get_replacement(void)
{
	struct _fbuf *fbuf;
	struct _fbuf_queue *fbuf_queue;
	struct _fbuf_sentinel *queue_sentinel;

	fbuf_queue = &sc.fbuf_queue[QUEUE_LEAF];
	queue_sentinel = &fbuf_queue->sentinel;
	fbuf = fbuf_queue->head;
again:
	while (true) {
		if (!fbuf->fc.accessed)
			break;
		fbuf->fc.accessed = false;	// give this buffer a second chance
		fbuf = fbuf->fc.queue_next;
	}
	if ((struct _fbuf_sentinel *)fbuf == queue_sentinel) {
		fbuf->fc.accessed = true;
		fbuf = fbuf->fc.queue_next;
		goto again;
	}
	fbuf_queue->head = fbuf->fc.queue_next;
	MY_ASSERT(fbuf->queue_which == QUEUE_LEAF);

	return fbuf;
}

static void
fbuf_clean_queue_check(void)
{
	struct _fbuf *fbuf;
	const int min_clean = 24;

	while (sc.fbuf_queue[QUEUE_CLEAN].count < min_clean) {
		fbuf = fbuf_get_replacement();
		MY_ASSERT(fbuf != NULL);
		MY_ASSERT(!fbuf->fc.is_sentinel);
		fbuf_queue_remove(fbuf);
		fbuf_queue_insert_tail(QUEUE_CLEAN, fbuf);
		if (fbuf->fc.modified)
			fbuf_write(fbuf);
	}
}

uint32_t
logstor_read_test(uint32_t ba, void *data)
{
	uint32_t sa = _logstor_read_one(ba, data);
	fbuf_clean_queue_check();
	return sa;
}

uint32_t
logstor_write_test(uint32_t ba, void *data)
{
	uint32_t sa = _logstor_write_one(ba, data);
	fbuf_clean_queue_check();
	return sa;
}

uint32_t
_logstor_read_one(unsigned ba, void *data)
{
	uint32_t sa;	// sector address

	MY_ASSERT(ba < sc.superblock.block_cnt_max);

	sa = file_read_4byte(sc.superblock.fd_cur, ba);
	if (sa == SECTOR_NULL || sa == SECTOR_DEL)
		bzero(data, SECTOR_SIZE);
	else {
		my_read(sa, data, 1);
	}
	return sa;
}

// is a sector with a reverse ba valid?
static bool
is_sec_valid(uint32_t sa, uint32_t ba_rev)
{
	uint32_t sa_rev; // the sector address for ba_rev

	if (IS_META_ADDR(ba_rev)) {
		sa_rev = ma2sa((union meta_addr)ba_rev);
		if (sa == sa_rev)
			return true;
	} else {
		sa_rev = file_read_4byte(sc.superblock.fd_cur, ba_rev);
		if (sa == sa_rev)
			return true;
		sa_rev = file_read_4byte(sc.superblock.fd_snap, ba_rev);
		if (sa == sa_rev)
			return true;
	}
	return false;
}

/*
Description:
  write data/metadata block to disk

Return:
  the sector address where the data is written
*/
static uint32_t
_logstor_write_one(uint32_t ba, void *data)
{
	//static uint8_t recursive;
	struct _seg_sum *seg_sum = &sc.seg_sum;

	//MY_BREAK(++recursive >= 3);
	MY_ASSERT(ba < sc.superblock.block_cnt_max || IS_META_ADDR(ba));
	MY_ASSERT(seg_sum->ss_alloc < SEG_SUM_OFFSET);
again:
	for (int i = seg_sum->ss_alloc; i < SEG_SUM_OFFSET; ++i)
	{
		uint32_t sa = sc.seg_alloc_sa + i;
		uint32_t ba_rev = seg_sum->ss_rm[i]; // ba from the reverse map
//MY_BREAK(sa == 118309);
		if (is_sec_valid(sa, ba_rev))
			continue;

		my_write(sa, data, 1);
		seg_sum->ss_rm[i] = ba;		// record reverse mapping
		seg_sum->ss_alloc = i + 1;	// advnace the alloc pointer
		if (seg_sum->ss_alloc == SEG_SUM_OFFSET) {
			seg_sum_write();
			seg_alloc();
		}
		if (!IS_META_ADDR(ba)) {
			// record the forward mapping for the %ba
			// the forward mapping must be recorded after
			// the segment summary block write
			file_write_4byte(sc.superblock.fd_cur, ba, sa);
		}
		//--recursive;
		return sa;
	}
	// no free sector in current segment
	seg_alloc();
	goto again;
}

uint32_t
logstor_get_block_cnt(void)
{
	return sc.superblock.block_cnt_max;
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
#if 0
static void
seg_sum_read(struct _seg_sum *seg_sum, uint32_t sega)
{
	uint32_t sa;

	seg_sum->sega = sega;
	sa = sega2sa(sega) + SEG_SUM_OFFSET;
	my_read(sa, seg_sum, 1);
}
#endif
/*
  write out the segment summary
*/
static void
seg_sum_write(void)
{
	uint32_t sa;

	// segment summary is at the end of a segment
	sa = sc.seg_alloc_sa + SEG_SUM_OFFSET;
	sc.seg_sum.ss_gen = sc.superblock.sb_gen;
	my_write(sa, (void *)&sc.seg_sum, 1);
	sc.other_write_count++; // the write for the segment summary
}

/*
Description:
    Write the initialized supeblock to the downstream disk
*/
static void
disk_init(int fd)
{
	int32_t seg_cnt;
	uint32_t sector_cnt;
	struct _superblock *sb;
	off_t media_size;
	char buf[SECTOR_SIZE] __attribute__ ((aligned));

	media_size = get_mediasize(fd);
	sector_cnt = media_size / SECTOR_SIZE;

	sb = (struct _superblock *)buf;
	sb->sig = SIG_LOGSTOR;
	sb->ver_major = VER_MAJOR;
	sb->ver_minor = VER_MINOR;
#if __BSD_VISIBLE
	sb->sb_gen = arc4random();
#else
	sb->sb_gen = random();
#endif	
	sb->fd_cur = FD_CUR;
	sb->fd_snap = FD_INVALID;
	sb->fd_new = FD_INVALID;
	sb->fd_new_snap = FD_INVALID;
	sb->seg_cnt = sector_cnt / SECTORS_PER_SEG;
	if (sizeof(struct _superblock) + sb->seg_cnt > SECTOR_SIZE) {
		printf("%s: size of superblock %d seg_cnt %d\n",
		    __func__, (int)sizeof(struct _superblock), (int)sb->seg_cnt);
		printf("    the size of the disk must be less than %lld\n",
		    (SECTOR_SIZE - sizeof(struct _superblock)) * (long long)SEG_SIZE);
		MY_PANIC();
	}
	seg_cnt = sb->seg_cnt;
	sb->block_cnt_max =
	    (seg_cnt - SEG_DATA_START) * BLOCKS_PER_SEG -
	    (sector_cnt / (SECTOR_SIZE / 4)) * FD_COUNT * 1.02;
#if defined(MY_DEBUG)
	printf("%s: sector_cnt %u block_cnt_max %u\n",
	    __func__, sector_cnt, sb->block_cnt_max);
#endif
	// the root sector address for the files
	for (int i = 0; i < FD_COUNT; i++) {
		sb->fd_tab[i] = SECTOR_NULL;	// SECTOR_NULL means not allocated yet
	}
	sb->seg_alloc = SEG_DATA_START;	// start allocate from here

	// write out super block
#if defined(RAM_DISK_SIZE)
	memcpy(ram_disk, sb, SECTOR_SIZE);
#else
	MY_ASSERT(pwrite(fd, sb, SECTOR_SIZE, 0) == SECTOR_SIZE);
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
	struct _seg_sum ss;
	for (int i = 0; i < SECTORS_PER_SEG - 1; ++i)
		ss.ss_rm[i] = BLOCK_INVALID;
	ss.ss_alloc = 0;
	sc.superblock.seg_cnt = seg_cnt; // to silence the assert fail in my_write
	// initialize all segment summary blocks
	for (int i = SEG_DATA_START; i < seg_cnt; ++i)
	{	uint32_t sa = sega2sa(i) + SEG_SUM_OFFSET;
		my_write(sa, &ss, 1);
	}
}

/*
  Segment 0 is used to store superblock so there are SECTORS_PER_SEG sectors
  for storing superblock. Each time the superblock is synced, it is stored
  in the next sector. When it reachs the end of segment 0, it wraps around
  to sector 0.
*/
static int
superblock_read(void)
{
	int	i;
	uint16_t sb_gen;
	struct _superblock *sb;
	char buf[2][SECTOR_SIZE];

	_Static_assert(sizeof(sb_gen) == sizeof(sc.superblock.sb_gen), "sb_gen");

	// get the superblock
	sb = (struct _superblock *)buf[0];
#if defined(RAM_DISK_SIZE)
	memcpy(sb, ram_disk, SECTOR_SIZE);
#else
	MY_ASSERT(pread(sc.disk_fd, sb, SECTOR_SIZE, 0) == SECTOR_SIZE);
#endif
	if (sb->sig != SIG_LOGSTOR ||
	    sb->seg_alloc >= sb->seg_cnt)
		return EINVAL;

	sb_gen = sb->sb_gen;
	for (i = 1 ; i < SECTORS_PER_SEG; i++) {
		sb = (struct _superblock *)buf[i%2];
#if defined(RAM_DISK_SIZE)
		memcpy(sb, ram_disk + i * SECTOR_SIZE, SECTOR_SIZE);
#else
		MY_ASSERT(pread(sc.disk_fd, sb, SECTOR_SIZE, i * SECTOR_SIZE) == SECTOR_SIZE);
#endif
		if (sb->sig != SIG_LOGSTOR)
			break;
		if (sb->sb_gen != (uint16_t)(sb_gen + 1)) // IMPORTANT type cast
			break;
		sb_gen = sb->sb_gen;
	}
	sc.sb_sa = (i - 1);
	sb = (struct _superblock *)buf[(i-1)%2];
	if (sb->seg_alloc >= sb->seg_cnt)
		return EINVAL;

	memcpy(&sc.superblock, sb, sizeof(sc.superblock));
	sc.sb_modified = false;

	return 0;
}

static void
superblock_write(void)
{
	struct _superblock *sb;
	char buf[SECTOR_SIZE];

	sc.superblock.sb_gen++;
	if (++sc.sb_sa == SECTORS_PER_SEG)
		sc.sb_sa = 0;
	sb = (struct _superblock *)buf;
	memcpy(sb, &sc.superblock, sizeof(sc.superblock));
	
	my_write(sc.sb_sa, sb, 1);
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
seg_alloc(void)
{
	MY_ASSERT(sc.superblock.seg_alloc < sc.superblock.seg_cnt);
	if (++sc.superblock.seg_alloc == sc.superblock.seg_cnt)
		sc.superblock.seg_alloc = SEG_DATA_START;
	sc.seg_alloc_sa = sega2sa(sc.superblock.seg_alloc);
	my_read(sc.seg_alloc_sa + SEG_SUM_OFFSET, &sc.seg_sum, 1);
	sc.seg_sum.ss_alloc = 0;
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
	struct _fbuf *fbuf;
	uint32_t off_4byte;	// the offset in 4 bytes within the file buffer data
	uint32_t sa;

	fbuf = file_access_4byte(fd, ba, &off_4byte);
	if (fbuf)
		sa = fbuf->data[off_4byte];
	else
		sa = SECTOR_NULL;
	return sa;
}

/*
Description:
 	Set the mapping of @ba to @sa in @file

Parameters:
	%fd: file descriptor
	%ba: block address
	%sa: sector address
*/
static void
file_write_4byte(uint8_t fd, uint32_t ba, uint32_t sa)
{
	struct _fbuf *fbuf;
	uint32_t off_4byte;	// the offset in 4 bytes within the file buffer data

	fbuf = file_access_4byte(fd, ba, &off_4byte);
	MY_ASSERT(fbuf != NULL);
	fbuf->fc.modified = true;
	fbuf->data[off_4byte] = sa;
}

/*
Description:
    The metadata is cached in memory. This function returns the address
    of the metadata in memory for the forward mapping of the block @ba

Parameters:
	%fd: file descriptor
	%ba: block address
	%off_4byte: the offset (in unit of 4 bytes) within the file buffer data

Return:
	the address of the file buffer data
*/
static struct _fbuf *
file_access_4byte(uint8_t fd, uint32_t ba, uint32_t *off_4byte)
{
	union meta_addr	ma;		// metadata address
	struct _fbuf *fbuf;

	MY_ASSERT(ba < META_START);
	if (fd >= FD_COUNT)
		return NULL;

	// the data stored in file for this ba is 4 bytes
	// we want to calculate ((ba * 4) & (SECTOR_SIZE - 1))/4
	// and it is reduced to the expression below
	*off_4byte = ba & (SECTOR_SIZE/4 - 1); // ((ba * 4) & (SECTOR_SIZE - 1))/4

	// convert (%fd, %ba) to metadata address
	ma.index = ba / (SECTOR_SIZE / 4); // (ba * 4) / SECTOR_SIZE
	ma.depth = META_LEAF_DEPTH;
	ma.fd = fd;
	ma.meta = 0xFF;	// for metadata address, bits 31:24 are all 1s
	fbuf = fbuf_get(ma);
	if (fbuf == NULL) {
		// no forwarding mapping for this %fd
		return NULL;
	}
	fbuf->fc.accessed = true;

	return fbuf;
}

static unsigned
ma_index_get(union meta_addr ma, unsigned depth)
{
	unsigned index;

	switch (depth) {
	case 0:
		index = ma.index0;
		break;
	case 1:
		index = ma.index1;
		break;
	default:
		MY_PANIC();
	}
	return (index);
}

static union meta_addr
ma_index_set(union meta_addr ma, unsigned depth, unsigned index)
{
	MY_ASSERT(index < 1024);

	switch (depth) {
	case 0:
		ma.index0 = index;
		break;
	case 1:
		ma.index1 = index;
		break;
	default:
		MY_PANIC();
	}
	return ma;
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
		*pindex_out = ma.index0;
		ma.index = 0;
		ma.depth = 0; // i.e. ma.depth - 1
		break;
	case 2:
		*pindex_out = ma.index1;
		ma.index1 = 0;
		ma.depth = 1; // i.e. ma.depth - 1
		break;
	default:
		ma = META_INVALID;
		break;
	}
	return ma;
}

// get the sector address where the metadata is stored on disk
static uint32_t
ma2sa(union meta_addr ma)
{
	struct _fbuf *pbuf;	// parent buffer
	union meta_addr pma;	// parent's metadata address
	unsigned pindex;	// index in the parent indirect block
	uint32_t sa;

	switch (ma.depth)
	{
	case 0:
		sa = sc.superblock.fd_tab[ma.fd];
		break;
	case 1:
	case 2:
		pma = ma2pma(ma, &pindex);
		pbuf = fbuf_get(pma);
		if (pbuf != NULL)
			sa = pbuf->data[pindex];
		else
			sa = SECTOR_NULL;
		break;
	case 3: // it is an invalid block/metadata address
		sa = SECTOR_NULL;
		break;
	}
	return sa;
}

/*
  Initialize metadata file buffer
*/
static void
fbuf_mod_init(void)
{
	int fbuf_count;

	//fbuf_count = sc.superblock.block_cnt_max / (SECTOR_SIZE / 4);
	fbuf_count = FBUF_MIN;
	if (fbuf_count < FBUF_MIN)
		fbuf_count = FBUF_MIN;
	if (fbuf_count > FBUF_MAX)
		fbuf_count = FBUF_MAX;
	sc.fbuf = malloc(fbuf_count * sizeof(*sc.fbuf));
	MY_ASSERT(sc.fbuf != NULL);

	for (int i = 0; i < FBUF_BUCKETS; ++i) {
		fbuf_hash_init(i);
	}
	for (int i = 0; i < QUEUE_CNT; ++i) {
		fbuf_queue_init(i);
	}
	// insert fbuf to both QUEUE_CLEAN and hash queue
	for (int i = 0; i < fbuf_count; ++i) {
		struct _fbuf *fbuf = &sc.fbuf[i];
		fbuf->fc.is_sentinel = false;
		fbuf->fc.accessed = false;
		fbuf->fc.modified = false;
		fbuf_queue_insert_tail(QUEUE_CLEAN, fbuf);
		// distribute fbuf evently to hash buckets
		fbuf->ma.uint32 = i;
		fbuf_hash_insert_head(fbuf);
		fbuf->child_ref_cnt = 0;
#if defined(FBUF_DEBUG)
		fbuf->index = i;
#endif
	}

#if defined(MY_DEBUG)
	sc.fbuf_count = fbuf_count;
#endif

	sc.fbuf_hit = sc.fbuf_miss = 0;
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
	struct _fbuf_sentinel	*queue_sentinel;
	struct _fbuf	*fbuf;
	int	i;

	for (i = META_LEAF_DEPTH; i >= 0; i--) {
		queue_sentinel = &sc.fbuf_queue[i].sentinel;
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			MY_ASSERT(fbuf->queue_which == i);
			fbuf_flush(fbuf);
			fbuf = fbuf->fc.queue_next;
		}
	}
}

static void
fbuf_queue_init(int which)
{
	struct _fbuf_queue *fbuf_queue;
	struct _fbuf *fbuf;

	MY_ASSERT(which < QUEUE_CNT);
	fbuf_queue = &sc.fbuf_queue[which];
	fbuf_queue->count = 0;
	fbuf_queue->head = (struct _fbuf *)&fbuf_queue->sentinel;
	fbuf = (struct _fbuf *)&fbuf_queue->sentinel;
	fbuf->fc.queue_next = fbuf;
	fbuf->fc.queue_prev = fbuf;
	fbuf->fc.is_sentinel = true;
	fbuf->fc.accessed = false;
	fbuf->fc.modified = false;
}

static void
fbuf_queue_insert_tail(int which, struct _fbuf *fbuf)
{
	struct _fbuf *prev;
	struct _fbuf *head;

	MY_ASSERT(which < QUEUE_CNT);
	fbuf->queue_which = which;
	head = sc.fbuf_queue[which].head;
	prev = head->fc.queue_prev;
	head->fc.queue_prev = fbuf;
	fbuf->fc.queue_next = head;
	fbuf->fc.queue_prev = prev;
	prev->fc.queue_next = fbuf;
	++sc.fbuf_queue[which].count;
}

static void
fbuf_queue_remove(struct _fbuf *fbuf)
{
	struct _fbuf *prev;
	struct _fbuf *next;
	int which = fbuf->queue_which;

	MY_ASSERT(fbuf != (struct _fbuf *)&sc.fbuf_queue[which].sentinel);
	prev = fbuf->fc.queue_prev;
	next = fbuf->fc.queue_next;
	prev->fc.queue_next = next;
	next->fc.queue_prev = prev;
	--sc.fbuf_queue[which].count;
}

static void
fbuf_hash_init(int which)
{
	struct _fbuf_sentinel *fbuf;

	MY_ASSERT(which < FBUF_BUCKETS);
#if defined(MY_DEBUG)
	sc.fbuf_bucket[which].count = 0;
#endif
	fbuf = &sc.fbuf_bucket[which].sentinel;
	fbuf->fc.queue_next = (struct _fbuf *)fbuf;
	fbuf->fc.queue_prev = (struct _fbuf *)fbuf;
	fbuf->fc.is_sentinel = true;
}

// insert to the head of the bucket
static void
fbuf_hash_insert_head(struct _fbuf *fbuf)
{
	unsigned which;
	struct _fbuf *next;
	struct _fbuf_sentinel *bucket_head;

	which = fbuf->ma.uint32 % FBUF_BUCKETS;
	fbuf->bucket_which = which;
#if defined(MY_DEBUG)
	sc.fbuf_bucket[which].count++;
#endif
	bucket_head = &sc.fbuf_bucket[which].sentinel;

	next = bucket_head->fc.queue_next;
	bucket_head->fc.queue_next = fbuf;
	fbuf->bucket_next = next;
	fbuf->bucket_prev = (struct _fbuf *)bucket_head;
	if (__predict_false(next->fc.is_sentinel))
		next->fc.queue_prev = fbuf;
	else
		next->bucket_prev = fbuf;
}

static void
fbuf_hash_remove(struct _fbuf *fbuf)
{
	int which;
	struct _fbuf *prev;
	struct _fbuf *next;

	which = fbuf->bucket_which;
	MY_ASSERT(which < FBUF_BUCKETS);
	MY_ASSERT(fbuf != (struct _fbuf *)&sc.fbuf_bucket[which].sentinel);
#if defined(MY_DEBUG)
	sc.fbuf_bucket[which].count--;
#endif
	prev = fbuf->bucket_prev;
	next = fbuf->bucket_next;
	if (__predict_false(prev->fc.is_sentinel))
		prev->fc.queue_next = next;
	else
		prev->bucket_next = next;
	if (__predict_false(next->fc.is_sentinel))
		next->fc.queue_prev = prev;
	else
		next->bucket_prev = prev;
}

/*
Description:
    Search the file buffer with the tag value of @ma. Return NULL if not found
*/
static struct _fbuf *
fbuf_search(union meta_addr ma)
{
	unsigned	hash;	// hash value
	struct _fbuf	*fbuf;
	struct _fbuf_sentinel	*bucket_sentinel;

	hash = ma.uint32 % FBUF_BUCKETS;
int bucket_count __unused = sc.fbuf_bucket[hash].count;
	bucket_sentinel = &sc.fbuf_bucket[hash].sentinel;
	fbuf = bucket_sentinel->fc.queue_next;
int loop_cnt = 0; // debug
	while (fbuf != (struct _fbuf *)bucket_sentinel) {
MY_BREAK(++loop_cnt > 4);
		if (fbuf->ma.uint32 == ma.uint32) { // cache hit
			sc.fbuf_hit++;
			if (fbuf->queue_which == QUEUE_CLEAN) {
				fbuf_queue_remove(fbuf);
				fbuf_queue_insert_tail(QUEUE_LEAF, fbuf);
			}
			return fbuf;
		}
		fbuf = fbuf->bucket_next;
	}
	sc.fbuf_miss++;
	return NULL;	// cache miss
}

/*
Description:
    Read or write the file buffer with metadata address @ma
*/
static struct _fbuf *
fbuf_get(union meta_addr ma)
{
	struct _fbuf *pbuf;	// parent buffer
	struct _fbuf *fbuf;
	union meta_addr	tma;	// temporary metadata address
	uint32_t sa;	// sector address where the metadata is stored
	unsigned index;

	MY_ASSERT(IS_META_ADDR(ma.uint32));
	fbuf = fbuf_search(ma);
	if (fbuf != NULL) // cache hit
		return fbuf;

	// cache miss
	// get the root sector address of the file @ma.fd
	sa = sc.superblock.fd_tab[ma.fd];
	if (sa == SECTOR_DEL)
		return NULL;

	pbuf = NULL;	// parent for root is NULL
	tma.uint32 = META_START; // set .meta to 0xFF and all others to 0
	tma.fd = ma.fd;
	// read the metadata from root to leaf node
	for (int i = 0; ; ++i) {
		tma.depth = i;
		fbuf = fbuf_search(tma);
		if (fbuf == NULL) {
			fbuf = fbuf_alloc();	// allocate a fbuf from clean queue
			fbuf->ma = tma;
			fbuf_hash_insert_head(fbuf);
			fbuf->parent = pbuf;
			if (pbuf) {
				if (pbuf->child_ref_cnt++ == 0 &&
				    pbuf->queue_which != pbuf->ma.depth) {
					fbuf_queue_remove(pbuf);
					fbuf_queue_insert_tail(pbuf->ma.depth, pbuf);
				}
				MY_ASSERT(pbuf->child_ref_cnt <= SECTOR_SIZE/4);
			}
			if (sa == SECTOR_NULL)	// the metadata block does not exist
				bzero(fbuf->data, sizeof(fbuf->data));
			else {
				my_read(sa, fbuf->data, 1);
				//sc.other_write_count++;
			}
#if defined(MY_DEBUG)
			fbuf->sa = sa;
#endif
#if defined(FBUF_DEBUG)
			if (pbuf)
				pbuf->child[index] = fbuf;
#endif
			if (i == ma.depth) {
				fbuf_queue_insert_tail(QUEUE_LEAF, fbuf);
				break;
			} else
				fbuf_queue_insert_tail(i, fbuf);

		} else {
			MY_ASSERT(fbuf->parent == pbuf);
#if defined(MY_DEBUG)
			MY_ASSERT(fbuf->sa == sa);
#endif
			if (i == ma.depth) // reach intended depth
				break;
		}
		index = ma_index_get(ma, i);// the index to next level's indirect block
		sa = fbuf->data[index];	// the sector address of the next level indirect block
		tma = ma_index_set(tma, i, index); // set the next level's index for @tma
		pbuf = fbuf;		// @fbuf is the parent of next level indirect block
	}
#if defined(MY_DEBUG)
	fbuf_queue_check();
#endif
	return fbuf;
}

static void
fbuf_write(struct _fbuf *fbuf)
{
	struct _fbuf *pbuf;	// buffer parent
	unsigned pindex;	// the index in parent indirect block
	uint32_t sa;		// sector address

	sa = _logstor_write_one(fbuf->ma.uint32, fbuf->data);
#if defined(MY_DEBUG)
	fbuf->sa = sa;
#endif
	fbuf->fc.modified = false;
	sc.other_write_count++;

	// update the sector address of this fbuf in its parent's fbuf
	pbuf = fbuf->parent;
	if (pbuf) {
		MY_ASSERT(fbuf->ma.depth != 0);
		MY_ASSERT(pbuf->ma.depth == fbuf->ma.depth - 1);
		pindex = ma_index_get(fbuf->ma, fbuf->ma.depth - 1);
		pbuf->data[pindex] = sa;
		pbuf->fc.modified = true;
	} else {
		MY_ASSERT(fbuf->ma.depth == 0);
		// store the root sector address to the corresponding file table in super block
		sc.superblock.fd_tab[fbuf->ma.fd] = sa;
		sc.sb_modified = true;
	}
}

/*
Description:
    Write the dirty data in file buffer to disk
*/
static void
fbuf_flush(struct _fbuf *fbuf)
{

	MY_ASSERT(IS_META_ADDR(fbuf->ma.uint32));

	if (!fbuf->fc.modified)
		return;

	fbuf_write(fbuf);
	return;
}

/*
Description:
    allocate a file buffer from free queue
*/
static struct _fbuf *
fbuf_alloc(void)
{
	struct _fbuf *fbuf, *pbuf;
	struct _fbuf_sentinel *queue_sentinel;

	queue_sentinel = &sc.fbuf_queue[QUEUE_CLEAN].sentinel;
	fbuf = queue_sentinel->fc.queue_next;
	MY_ASSERT(fbuf != (struct _fbuf *)queue_sentinel);
	MY_ASSERT(fbuf->queue_which == QUEUE_CLEAN);
	fbuf_queue_remove(fbuf);
	fbuf_hash_remove(fbuf);
	pbuf = fbuf->parent;
	if (pbuf && --pbuf->child_ref_cnt == 0) {
		fbuf_queue_remove(pbuf);
		fbuf_queue_insert_tail(QUEUE_LEAF, pbuf);
	}
	return fbuf;
}

#if defined(MY_DEBUG)
void
fbuf_hash_check(void)
{
	struct _fbuf *fbuf;
	struct _fbuf_sentinel *bucket_sentinel;

	for (int i = 0; i < FBUF_BUCKETS; ++i)
	{
		bucket_sentinel = &sc.fbuf_bucket[i].sentinel;
		fbuf = bucket_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)bucket_sentinel) {
			MY_ASSERT(fbuf->bucket_which == i);
			fbuf = fbuf->bucket_next;
		}
	}
}

static void
fbuf_queue_check(void)
{
	struct _fbuf *fbuf;
	struct _fbuf_sentinel *queue_sentinel;
	unsigned count[QUEUE_CNT];

	for (int i = 0; i < QUEUE_CNT ; ++i) {
		count[i] = 0;
		queue_sentinel = &sc.fbuf_queue[i].sentinel;
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			++count[i];
			MY_ASSERT(fbuf->queue_which == i);
			if (i < META_LEAF_DEPTH)
				MY_ASSERT(fbuf->ma.depth == i);
			fbuf = fbuf->fc.queue_next;
		}
		MY_ASSERT(sc.fbuf_queue[i].count == count[i]);
	}
	int total = 0;
	for (int i = 0; i < QUEUE_CNT; ++i)
		total += count[i];

	MY_ASSERT(total == sc.fbuf_count);
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
		sa = file_read_4byte(sc.superblock.fd_cur, ba);
	}
	fbuf_clean_queue_check();
	return sa;
}

static uint32_t
logstor_sa2ba(uint32_t sa)
{
	static uint32_t seg_sum_sa;
	static struct _seg_sum seg_sum;
	uint32_t seg_sa;
	unsigned seg_off;

	seg_sa = sa & ~(SECTORS_PER_SEG - 1);
	seg_off = sa & (SECTORS_PER_SEG - 1);
	MY_ASSERT(seg_off != SEG_SUM_OFFSET);
	if (seg_sa != seg_sum_sa) {
		my_read(seg_sa + SEG_SUM_OFFSET, &seg_sum, 1);
		seg_sum_sa = seg_sa;
	}
	return (seg_sum.ss_rm[seg_off]);
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
	sa_min = -1;
	max_block = logstor_get_block_cnt();
	for (ba = 0; ba < max_block; ba++) {
		sa = logstor_ba2sa(ba);
		if (sa != SECTOR_NULL && sa != SECTOR_DEL) {
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
#endif
//===================================================
#if 0
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

