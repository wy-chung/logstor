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

#include "logstor.h"

#define	LOGSTOR_MAGIC	0x4C4F4753	// "LOGS": Log-Structured Storage
#define	VER_MAJOR	0
#define	VER_MINOR	1

#define	SEG_SIZE	0x400000		// 4M
#define	SECTORS_PER_SEG	(SEG_SIZE/SECTOR_SIZE)	// 1024
#define BLOCKS_PER_SEG	(SECTORS_PER_SEG - 1)
#define SEG_SUM_OFFSET	(SECTORS_PER_SEG - 1)	// segment summary offset
#define SB_CNT	8	// number of superblock sectors
#define SEC_PER_SEG_SHIFT 10	// sectors per segment shift

/*
  The max file size is 1K*1K*4K=4G, each entry is 4 bytes
  so the max block number is 4G/4 = 1G
*/
#define BLOCK_MAX	0x40000000	// 1G
// the address [BLOCK_MAX..META_STAR) are invalid block/metadata address
#define BLOCK_INVALID	(BLOCK_MAX+1)
#define META_INVALID	(BLOCK_MAX+1)

enum {
	SECTOR_NULL,	// the metadata are all NULL
	SECTOR_DEL,	// the file does not exist or don't look the mapping further, it is NULL
	SECTOR_CACHE,	// the root sector of the file is still in the cache
};

#if defined(MY_DEBUG)
void my_break(void)
{
}

void my_panic(const char * file, int line, const char *func)
{
	printf("error: %s %d %s\n", file, line, func);
	perror("");
	my_break();
	exit(1);
}
#endif

//=================================
#define __predict_true(exp)     __builtin_expect((exp), 1)
#define __predict_false(exp)    __builtin_expect((exp), 0)
#define __unused		__attribute__((unused))

#define RAM_DISK_SIZE		0x180000000UL // 6G

#define	META_START	(((union meta_addr){.meta = 0xFF}).uint32)	// metadata block address start
#define	IS_META_ADDR(x)	((x) >= META_START)

#define FBUF_CLEAN_THRESHOLD	32
#define FBUF_MIN	1564
#define FBUF_MAX	(FBUF_MIN * 2)
// the last bucket is reserved for queuing fbufs that will not be searched
#define FBUF_BUCKET_LAST 953	// this should be a prime number
#define FBUF_BUCKET_CNT	(FBUF_BUCKET_LAST+1)

#define FD_COUNT	4		// max number of metadata files supported
#define FD_INVALID	FD_COUNT	// the valid file descriptor are 0 to 3

struct _superblock {
	uint32_t magic;
	uint8_t  ver_major;
	uint8_t  ver_minor;
	uint16_t sb_gen;	// the generation number. Used for redo after system crash
	/*
	   The segments are treated as circular buffer
	 */
	uint32_t seg_cnt;	// total number of segments
	uint32_t seg_allocp;	// allocate this segment
	uint32_t sector_cnt_free;
	// since the max meta file size is 4G (1K*1K*4K) and the entry size is 4
	// block_cnt_max must be < (4G/4)
	uint32_t block_cnt_max;	// max number of blocks supported
	/*
	   The files for forward mapping

	   New mapping is written to %fd_cur. When commit command is issued
	   %fd_cur is movied to %fd_prev, %fd_prev and %fd_snap are merged to %fd_snap_new
	   After the commit command is complete, %fd_snap_new is movied to %fd_snap
	   and %fd_prev is deleted.

	   So the actual mapping in normal state is
	       %fd_cur || %fd_snap
	   and during commit it is
	       %fd_cur || %fd_prev || %fd_snap

	   The first mapping that is not null is used.
	   To support trim command, the mapping marked as delete will stop
	   the checking for the next mapping file and return null immediately
	*/
	struct { // file handles
		uint32_t root;	// the root sector of the file
		uint32_t written;// number of blocks written to this virtual disk
	} fh[FD_COUNT];
	uint8_t fd_prev;	// the file descriptor for previous current mapping
	uint8_t fd_snap;	// the file descriptor for snapshot mapping
	uint8_t fd_cur;		// the file descriptor for current mapping
	uint8_t fd_snap_new;	// the file descriptor for new snapshot mapping
};

_Static_assert(sizeof(struct _superblock) < SECTOR_SIZE,
	"The size of the super block must be smaller than SECTOR_SIZE");

/*
  Forward map and its indirect blocks are also stored in the downstream disk.
  The sectors used to store the forward map and its indirect blocks are called metadata.

  Each metadata block has a corresponding metadata address.
  Below is the format of the metadata address.

  The metadata address occupies a small portion of block address space.
  For block address that is >= META_START, it is actually a metadata address.
*/
#define META_LEAF_DEPTH	2
#define IDX_BITS	10	// number of index bits
union meta_addr { // metadata address for file data and its indirect blocks
	uint32_t	uint32;
	struct {
		uint32_t index1 :IDX_BITS;	// index for indirect block of depth 1
		uint32_t index0 :IDX_BITS;	// index for indirect block of depth 0
		uint32_t depth	:2;	// depth of the node
		uint32_t fd	:2;	// file descriptor
		uint32_t meta	:8;	// 0xFF for metadata address
	};
	struct {
		uint32_t index :20;	// index for indirect blocks
	};
};

_Static_assert(sizeof(union meta_addr) == 4, "The size of emta_addr must be 4");

// when processing queues, we always process it from the leaf to root
// so leaf has lower queue number
enum {
	QUEUE_F0_CLEAN,	// floor 0, clean queue
	QUEUE_F0_DIRTY,	// floor 0, dirty queue
	QUEUE_F1,	// floor 1
	QUEUE_F2,	// floor 2
	QUEUE_CNT,
};

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
	struct _fbuf *bucket_next;
	struct _fbuf *bucket_prev;
	struct _fbuf *parent;
	uint16_t child_cnt; // number of children reference this fbuf

	union meta_addr	ma;	// the metadata address
	uint16_t queue_which;
#if defined(MY_DEBUG)
	uint16_t bucket_which;
	uint16_t index; // the array index for this fbuf
	uint16_t dbg_child_cnt;
	uint32_t sa;	// the sector address of the @data
	struct _fbuf 	*child[SECTOR_SIZE/sizeof(uint32_t)];
#endif
	// the metadata is cached here
	uint32_t	data[SECTOR_SIZE/sizeof(uint32_t)];
};

/*
  The last sector in a segment is the segment summary. It stores the reverse mapping table
*/
struct _seg_sum {
	uint32_t ss_rm[SECTORS_PER_SEG - 1];	// reverse map
	// reverse map SECTORS_PER_SEG - 1 is not used so we store something here
	uint32_t ss_allocp;	// the sector for allocation in the segment
	//uint32_t ss_gen;  // sequence number. used for redo after system crash
};

_Static_assert(sizeof(struct _seg_sum) == SECTOR_SIZE,
	"The size of segment summary must be equal to SECTOR_SIZE");

/*
	logstor soft control
*/
struct g_logstor_softc {
	bool (*is_sec_valid_fp)(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);
	uint32_t (*ba2sa_fp)(struct g_logstor_softc *sc, uint32_t ba);

	uint32_t seg_allocp_start;// the starting segment for _logstor_write
	uint32_t seg_allocp_sa;	// the sector address of the segment for allocation
	struct _seg_sum seg_sum;// segment summary for the current segment
	uint32_t sb_sa; 	// superblock's sector address
	bool sb_modified;	// is the super block modified
	bool ss_modified;	// is segment summary modified

	int fbuf_count;
	struct _fbuf *fbufs;	// an array of fbufs
	struct _fbuf *fbuf_allocp; // point to the fbuf candidate for replacement
	struct _fbuf_sentinel fbuf_queue[QUEUE_CNT];
	int fbuf_queue_len[QUEUE_CNT];

	// buffer hash queue
	struct _fbuf_sentinel fbuf_bucket[FBUF_BUCKET_CNT];
#if defined(MY_DEBUG)
	int fbuf_bucket_len[FBUF_BUCKET_CNT];
#endif
	// statistics
	unsigned data_write_count;	// data block write to disk
	unsigned other_write_count;	// other write to disk, such as metadata write and segment cleaning
	unsigned fbuf_hit;
	unsigned fbuf_miss;

	/*
	  The macro RAM_DISK_SIZE is used for debug.
	  By using RAM as the storage device, the test can run way much faster.
	*/
#if !defined(RAM_DISK_SIZE)
	int disk_fd;
#endif
	struct _superblock superblock;
};

static uint32_t disk_init(int fd);
static void my_read (struct g_logstor_softc *sc, void *buf, uint32_t sa);
static void my_write(struct g_logstor_softc *sc, const void *buf, uint32_t sa);

uint32_t gdb_cond0 = -1;
uint32_t gdb_cond1 = -1;

#if defined(RAM_DISK_SIZE)
static char *ram_disk;
 #if defined(MY_DEBUG)
// given a page number and see a 4k page. point to the same address as ram_disk
static union {
	uint32_t u32[1024];
	uint16_t u16[2048];
	uint8_t  u8[4096];
} *ram4k;
 #endif
#endif

#if defined(RAM_DISK_SIZE)
static inline off_t
get_mediasize(int fd)
{
	return RAM_DISK_SIZE;
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

/*
Description:
    segment address to sector address
*/
static inline uint32_t
sega2sa(uint32_t sega)
{
	return sega << SEC_PER_SEG_SHIFT;
}

/*
Description:
    Write the initialized supeblock to the downstream disk

Return:
    The max number of blocks for this disk
*/
static uint32_t
disk_init(int fd)
{
	int32_t seg_cnt;
	uint32_t sector_cnt;
	off_t media_size;
	struct _superblock *sb;
	struct _seg_sum *seg_sum;
	char buf[SECTOR_SIZE] __attribute__((aligned(4)));

	media_size = get_mediasize(fd);
	sector_cnt = media_size / SECTOR_SIZE;

	sb = (struct _superblock *)buf;
	sb->magic = LOGSTOR_MAGIC;
	sb->ver_major = VER_MAJOR;
	sb->ver_minor = VER_MINOR;
	sb->sb_gen = random();
	sb->seg_cnt = sector_cnt / SECTORS_PER_SEG;
	if (sizeof(struct _superblock) + sb->seg_cnt > SECTOR_SIZE) {
		printf("%s: size of superblock %d seg_cnt %d\n",
		    __func__, (int)sizeof(struct _superblock), (int)sb->seg_cnt);
		printf("    the size of the disk must be less than %lld\n",
		    (SECTOR_SIZE - sizeof(struct _superblock)) * (long long)SEG_SIZE);
		MY_PANIC();
	}
	seg_cnt = sb->seg_cnt;
	uint32_t max_block =
	    seg_cnt * BLOCKS_PER_SEG - SB_CNT -
	    (sector_cnt / (SECTOR_SIZE / 4)) * FD_COUNT * 4;
	MY_ASSERT(max_block < 0x40000000); // 1G
	sb->block_cnt_max = max_block;
#if defined(MY_DEBUG)
	printf("%s: sector_cnt %u block_cnt_max %u\n",
	    __func__, sector_cnt, sb->block_cnt_max);
#endif
	sb->seg_allocp = 0;	// start allocate from here

	sb->fd_cur = 0;			// current mapping is file 0
	sb->fd_snap = 1;
	sb->fd_prev = FD_INVALID;	// mapping does not exist
	sb->fd_snap_new = FD_INVALID;
	sb->fh[0].root = SECTOR_NULL;	// file 0 is all 0
	// the root sector address for the files 1, 2 and 3
	for (int i = 1; i < FD_COUNT; i++) {
		sb->fh[i].root = SECTOR_DEL;	// the file does not exit
	}

	// write out the first super block
	memset(buf + sizeof(*sb), 0, sizeof(buf) - sizeof(*sb));
#if defined(RAM_DISK_SIZE)
	memcpy(ram_disk, sb, SECTOR_SIZE);
#else
	MY_ASSERT(pwrite(fd, sb, SECTOR_SIZE, 0) == SECTOR_SIZE);
#endif

	// clear the rest of the supeblocks
	bzero(buf, SECTOR_SIZE);
	for (int i = 1; i < SB_CNT; i++) {
#if defined(RAM_DISK_SIZE)
		memcpy(ram_disk + i * SECTOR_SIZE, buf, SECTOR_SIZE);
#else
		MY_ASSERT(pwrite(fd, buf, SECTOR_SIZE, i * SECTOR_SIZE) == SECTOR_SIZE);
#endif
	}
	// initialize the segment summary block
	seg_sum = (struct _seg_sum *)buf;
	for (int i = 0; i < BLOCKS_PER_SEG; ++i)
		seg_sum->ss_rm[i] = BLOCK_INVALID;

	// write out the first segment summary block
	seg_sum->ss_allocp = SB_CNT;
	my_write(NULL, seg_sum, SEG_SUM_OFFSET);

	// write out the rest of the segment summary blocks
	seg_sum->ss_allocp = 0;
	for (int i = 1; i < seg_cnt; ++i) {
		uint32_t sa = sega2sa(i) + SEG_SUM_OFFSET;
		my_write(NULL, seg_sum, sa);
	}
	return max_block;
}

/*******************************
 *        logstor              *
 *******************************/
static uint32_t _logstor_read(struct g_logstor_softc *sc, uint32_t ba, void *data);
static uint32_t _logstor_write(struct g_logstor_softc *sc, uint32_t ba, void *data);

static void seg_alloc(struct g_logstor_softc *sc);
static void seg_sum_write(struct g_logstor_softc *sc);

static int  superblock_read(struct g_logstor_softc *sc);
static void superblock_write(struct g_logstor_softc *sc);

static struct _fbuf *file_access_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t offset, uint32_t *off_4byte);
static uint32_t file_read_4byte(struct g_logstor_softc *sc, uint8_t fh, uint32_t ba);
static void file_write_4byte(struct g_logstor_softc *sc, uint8_t fh, uint32_t ba, uint32_t sa);

static void fbuf_mod_init(struct g_logstor_softc *sc);
static void fbuf_mod_fini(struct g_logstor_softc *sc);
static void fbuf_queue_init(struct g_logstor_softc *sc, int which);
static void fbuf_queue_insert_tail(struct g_logstor_softc *sc, int which, struct _fbuf *fbuf);
static void fbuf_queue_remove(struct g_logstor_softc *sc, struct _fbuf *fbuf);
static struct _fbuf *fbuf_search(struct g_logstor_softc *sc, union meta_addr ma);
static void fbuf_hash_insert_head(struct g_logstor_softc *sc, struct _fbuf *fbuf);
static void fbuf_bucket_init(struct g_logstor_softc *sc, int which);
static void fbuf_bucket_insert_head(struct g_logstor_softc *sc, int which, struct _fbuf *fbuf);
static void fbuf_bucket_remove(struct _fbuf *fbuf);
static void fbuf_write(struct g_logstor_softc *sc, struct _fbuf *fbuf);
static struct _fbuf *fbuf_alloc(struct g_logstor_softc *sc, union meta_addr ma, int depth);
static struct _fbuf *fbuf_access(struct g_logstor_softc *sc, union meta_addr ma);
static void fbuf_cache_flush(struct g_logstor_softc *sc);
static void fbuf_cache_flush_and_invalidate_fd(struct g_logstor_softc *sc, int fd1, int fd2);
static void fbuf_clean_queue_check(struct g_logstor_softc *sc);

static union meta_addr ma2pma(union meta_addr ma, unsigned *pindex_out);
static uint32_t ma2sa(struct g_logstor_softc *sc, union meta_addr ma);

static uint32_t ba2sa_normal(struct g_logstor_softc *sc, uint32_t ba);
static uint32_t ba2sa_during_commit(struct g_logstor_softc *sc, uint32_t ba);
static bool is_sec_valid_normal(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);
static bool is_sec_valid_during_commit(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev);
#if defined(MY_DEBUG)
static void logstor_check(struct g_logstor_softc *sc);
#endif
static struct g_logstor_softc softc;

/*
Return the max number of blocks for this disk
*/
uint32_t logstor_disk_init(const char *disk_file)
{
	int disk_fd;

#if defined(RAM_DISK_SIZE)
	ram_disk = malloc(RAM_DISK_SIZE);
	MY_ASSERT(ram_disk != NULL);
 #if defined(MY_DEBUG)
	ram4k = (void *)ram_disk;
 #endif
	disk_fd = -1;
#else
	disk_fd = open(disk_file, O_WRONLY);
	MY_ASSERT(disk_fd > 0);
#endif
	return disk_init(disk_fd);
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
	struct g_logstor_softc *sc = &softc;

	bzero(sc, sizeof(*sc));
#if !defined(RAM_DISK_SIZE)
	sc->disk_fd = open(disk_file, O_RDWR);
	MY_ASSERT(sc->disk_fd > 0);
#endif
	int error __unused;

	error = superblock_read(sc);
	MY_ASSERT(error == 0);
	sc->sb_modified = false;

	// read the segment summary block
	sc->seg_allocp_sa = sega2sa(sc->superblock.seg_allocp);
	uint32_t sa = sc->seg_allocp_sa + SEG_SUM_OFFSET;
	my_read(sc, &sc->seg_sum, sa);
	MY_ASSERT(sc->seg_sum.ss_allocp < SEG_SUM_OFFSET);
	sc->ss_modified = false;

	fbuf_mod_init(sc);

	sc->data_write_count = sc->other_write_count = 0;
	sc->is_sec_valid_fp = is_sec_valid_normal;
	sc->ba2sa_fp = ba2sa_normal;
#if defined(MY_DEBUG)
	logstor_check(sc);
#endif
	return 0;
}

void
logstor_close(void)
{
	struct g_logstor_softc *sc = &softc;

	fbuf_mod_fini(sc);
	seg_sum_write(sc);
	superblock_write(sc);
#if !defined(RAM_DISK_SIZE)
	close(sc->disk_fd);
#endif
}

uint32_t
logstor_read(uint32_t ba, void *data)
{
	struct g_logstor_softc *sc = &softc;

	fbuf_clean_queue_check(sc);
	uint32_t sa = _logstor_read(sc, ba, data);
	return sa;
}

uint32_t
logstor_write(uint32_t ba, void *data)
{
	struct g_logstor_softc *sc = &softc;

	fbuf_clean_queue_check(sc);
	uint32_t sa = _logstor_write(sc, ba, data);
	return sa;
}

// To enable TRIM, the following statement must be added
// in "case BIO_GETATTR" of g_gate_start() of g_gate.c
//	if (g_handleattr_int(pbp, "GEOM::candelete", 1))
//		return;
// and the command below must be executed before mounting the device
//	tunefs -t enabled /dev/ggate0
int logstor_delete(off_t offset, void *data __unused, off_t length)
{
	struct g_logstor_softc *sc = &softc;
	uint32_t ba;	// block address
	int size;	// number of remaining sectors to process
	int i;

	MY_ASSERT((offset & (SECTOR_SIZE - 1)) == 0);
	MY_ASSERT((length & (SECTOR_SIZE - 1)) == 0);
	ba = offset / SECTOR_SIZE;
	size = length / SECTOR_SIZE;
	MY_ASSERT(ba < sc->superblock.block_cnt_max);

	for (i = 0; i < size; ++i) {
		fbuf_clean_queue_check(sc);
		file_write_4byte(sc, sc->superblock.fd_cur, ba + i, SECTOR_DEL);
	}

	return (0);
}

void
logstor_commit(void)
{
	struct g_logstor_softc *sc = &softc;

	// lock metadata
	// move fd_cur to fd_prev
	sc->superblock.fd_prev = sc->superblock.fd_cur;
	// create new files fd_cur and fd_snap_new
	// fc_cur is either 0 or 2 and fd_snap always follows fd_cur
	sc->superblock.fd_cur = sc->superblock.fd_cur ^ 2;
	sc->superblock.fd_snap_new = sc->superblock.fd_cur + 1;
	sc->superblock.fh[sc->superblock.fd_cur].root = SECTOR_NULL;
	sc->superblock.fh[sc->superblock.fd_snap_new].root = SECTOR_NULL;

	sc->is_sec_valid_fp = is_sec_valid_during_commit;
	sc->ba2sa_fp = ba2sa_during_commit;
	// unlock metadata

	uint32_t block_max = sc->superblock.block_cnt_max;
	for (int ba = 0; ba < block_max; ++ba) {
		uint32_t sa;

		fbuf_clean_queue_check(sc);
		sa = file_read_4byte(sc, sc->superblock.fd_prev, ba);
		if (sa == SECTOR_NULL)
			sa = file_read_4byte(sc, sc->superblock.fd_snap, ba);
		else if (sa == SECTOR_DEL)
			sa = SECTOR_NULL;

		if (sa != SECTOR_NULL)
			file_write_4byte(sc, sc->superblock.fd_snap_new, ba, sa);
	}

	// lock metadata
	int fd_prev = sc->superblock.fd_prev;
	int fd_snap = sc->superblock.fd_snap;
	fbuf_cache_flush_and_invalidate_fd(sc, fd_prev, fd_snap);
	sc->superblock.fh[fd_prev].root = SECTOR_DEL;
	sc->superblock.fh[fd_snap].root = SECTOR_DEL;
	// move fd_snap_new to fd_snap
	sc->superblock.fd_snap = sc->superblock.fd_snap_new;
	// delete fd_prev and fd_snap
	sc->superblock.fd_prev = FD_INVALID;
	sc->superblock.fd_snap_new = FD_INVALID;
	sc->sb_modified = true;

	seg_sum_write(sc);
	superblock_write(sc);

	sc->is_sec_valid_fp = is_sec_valid_normal;
	sc->ba2sa_fp = ba2sa_normal;
	//unlock metadata
}

void
logstor_revert(void)
{
	struct g_logstor_softc *sc = &softc;

	fbuf_cache_flush_and_invalidate_fd(sc, sc->superblock.fd_cur, FD_INVALID);
	sc->superblock.fh[sc->superblock.fd_cur].root = SECTOR_NULL;
}

uint32_t
_logstor_read(struct g_logstor_softc *sc, unsigned ba, void *data)
{
	uint32_t sa;	// sector address

	MY_ASSERT(ba < sc->superblock.block_cnt_max);

	sa = sc->ba2sa_fp(sc, ba);
#if defined(WYC)
	ba2sa_normal();
	ba2sa_during_commit();
#endif
	if (sa == SECTOR_NULL)
		bzero(data, SECTOR_SIZE);
	else {
		MY_ASSERT(sa >= SB_CNT);
		my_read(sc, data, sa);
	}
	return sa;
}

// The common part of is_sec_valid
static bool
is_sec_valid_comm(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev, uint8_t fd[], int fd_cnt)
{
	uint32_t sa_rev; // the sector address for ba_rev

	MY_ASSERT(ba_rev < BLOCK_MAX);
	for (int i = 0; i < fd_cnt; ++i) {
		sa_rev = file_read_4byte(sc, fd[i], ba_rev);
		if (sa == sa_rev)
			return true;
	}
	return false;
}
#define NUM_OF_ELEMS(x) (sizeof(x)/sizeof(x[0]))

// Is a sector with a reverse ba valid?
// This function is called normally
static bool
is_sec_valid_normal(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_snap,
	};

	return is_sec_valid_comm(sc, sa, ba_rev, fd, NUM_OF_ELEMS(fd));
}

// Is a sector with a reverse ba valid?
// This function is called during commit
static bool
is_sec_valid_during_commit(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_prev,
	    sc->superblock.fd_snap,
	};

	return is_sec_valid_comm(sc, sa, ba_rev, fd, NUM_OF_ELEMS(fd));
}

// Is a sector with a reverse ba valid?
static bool
is_sec_valid(struct g_logstor_softc *sc, uint32_t sa, uint32_t ba_rev)
{
#if defined(MY_DEBUG)
	union meta_addr ma_rev __unused;
	ma_rev.uint32 = ba_rev;
#endif
	if (ba_rev < BLOCK_MAX) {
		return sc->is_sec_valid_fp(sc, sa, ba_rev);
#if defined(WYC)
		is_sec_valid_normal();
		is_sec_valid_during_commit();
#endif
	} else if (IS_META_ADDR(ba_rev)) {
		uint32_t sa_rev = ma2sa(sc, (union meta_addr)ba_rev);
		return (sa == sa_rev);
	} else if (ba_rev == BLOCK_INVALID) {
		return false;
	} else {
		MY_PANIC();
		return false;
	}
}

/*
Description:
  write data/metadata block to disk

Return:
  the sector address where the data is written
*/
static uint32_t
_logstor_write(struct g_logstor_softc *sc, uint32_t ba, void *data)
{
	static bool is_called = false;
	int i;
	struct _seg_sum *seg_sum = &sc->seg_sum;
#if defined(MY_DEBUG)
	union meta_addr ma __unused;
	union meta_addr ma_rev __unused;

	ma.uint32 = ba;
#endif

	MY_ASSERT(ba < sc->superblock.block_cnt_max || IS_META_ADDR(ba));
	if (is_called) // recursive call is not allowed
		exit(1);
	is_called = true;

	// record the starting segment
	// if the search for free sector rolls over to the starting segment
	// it means that there is no free sector in this disk
	sc->seg_allocp_start = sc->superblock.seg_allocp;
again:
	for (i = seg_sum->ss_allocp; i < SEG_SUM_OFFSET; ++i)
	{
		uint32_t sa = sc->seg_allocp_sa + i;
		uint32_t ba_rev = seg_sum->ss_rm[i]; // ba from the reverse map
#if defined(MY_DEBUG)
		ma_rev.uint32 = ba_rev;
#endif
		if (is_sec_valid(sc, sa, ba_rev))
			continue;

		my_write(sc, data, sa);
		seg_sum->ss_rm[i] = ba;		// record reverse mapping
		sc->ss_modified = true;
		seg_sum->ss_allocp = i + 1;	// advnace the alloc pointer
		if (seg_sum->ss_allocp == SEG_SUM_OFFSET)
			seg_alloc(sc);

		if (IS_META_ADDR(ba))
			++sc->other_write_count;
		else {
			++sc->data_write_count;
			// record the forward mapping for the %ba
			// the forward mapping must be recorded after
			// the segment summary block write
			file_write_4byte(sc, sc->superblock.fd_cur, ba, sa);
		}
		is_called = false;
		return sa;
	}
	seg_alloc(sc);
	goto again;
}

static uint32_t
logstor_ba2sa_comm(struct g_logstor_softc *sc, uint32_t ba, uint8_t fd[], int fd_cnt)
{
	uint32_t sa;

	MY_ASSERT(ba < BLOCK_MAX);
	for (int i = 0; i < fd_cnt; ++i) {
		sa = file_read_4byte(sc, fd[i], ba);
		if (sa == SECTOR_DEL) { // don't need to check further
			sa = SECTOR_NULL;
			break;
		}
		if (sa != SECTOR_NULL)
			break;
	}
	return sa;
}

/*
Description:
    Block address to sector address translation in normal state
*/
static uint32_t
ba2sa_normal(struct g_logstor_softc *sc, uint32_t ba)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_snap,
	};

	return logstor_ba2sa_comm(sc, ba, fd, NUM_OF_ELEMS(fd));
}

/*
Description:
    Block address to sector address translation in commit state
*/
static uint32_t __unused
ba2sa_during_commit(struct g_logstor_softc *sc, uint32_t ba)
{
	uint8_t fd[] = {
	    sc->superblock.fd_cur,
	    sc->superblock.fd_prev,
	    sc->superblock.fd_snap,
	};

	return logstor_ba2sa_comm(sc, ba, fd, NUM_OF_ELEMS(fd));
}

uint32_t
logstor_get_block_cnt(void)
{
	struct g_logstor_softc *sc = &softc;

	return sc->superblock.block_cnt_max;
}

unsigned
logstor_get_data_write_count(void)
{
	struct g_logstor_softc *sc = &softc;

	return sc->data_write_count;
}

unsigned
logstor_get_other_write_count(void)
{
	struct g_logstor_softc *sc = &softc;

	return sc->other_write_count;
}

unsigned
logstor_get_fbuf_hit(void)
{
	struct g_logstor_softc *sc = &softc;

	return sc->fbuf_hit;
}

unsigned
logstor_get_fbuf_miss(void)
{
	struct g_logstor_softc *sc = &softc;

	return sc->fbuf_miss;
}

/*
  write out the segment summary
  segment summary is at the end of a segment
*/
static void
seg_sum_write(struct g_logstor_softc *sc)
{
	uint32_t sa;

	if (!sc->ss_modified)
		return;
	MY_ASSERT(sc->seg_sum.ss_allocp < SEG_SUM_OFFSET);
	sa = sc->seg_allocp_sa + SEG_SUM_OFFSET;
	my_write(sc, (void *)&sc->seg_sum, sa);
	sc->ss_modified = false;
	sc->other_write_count++; // the write for the segment summary
}

/*
  Segment 0 is used to store superblock so there are SECTORS_PER_SEG sectors
  for storing superblock. Each time the superblock is synced, it is stored
  in the next sector. When it reachs the end of segment 0, it wraps around
  to sector 0.
*/
static int
superblock_read(struct g_logstor_softc *sc)
{
	int	i;
	uint16_t sb_gen;
	struct _superblock *sb;
	char buf[2][SECTOR_SIZE];

	_Static_assert(sizeof(sb_gen) == sizeof(sc->superblock.sb_gen), "sb_gen");

	// get the superblock
	sb = (struct _superblock *)buf[0];
#if defined(RAM_DISK_SIZE)
	memcpy(sb, ram_disk, SECTOR_SIZE);
#else
	MY_ASSERT(pread(sc->disk_fd, sb, SECTOR_SIZE, 0) == SECTOR_SIZE);
#endif
	if (sb->magic != LOGSTOR_MAGIC ||
	    sb->seg_allocp >= sb->seg_cnt)
		return EINVAL;

	sb_gen = sb->sb_gen;
	for (i = 1 ; i < SB_CNT; i++) {
		sb = (struct _superblock *)buf[i%2];
#if defined(RAM_DISK_SIZE)
		memcpy(sb, ram_disk + i * SECTOR_SIZE, SECTOR_SIZE);
#else
		MY_ASSERT(pread(sc->disk_fd, sb, SECTOR_SIZE, i * SECTOR_SIZE) == SECTOR_SIZE);
#endif
		if (sb->magic != LOGSTOR_MAGIC)
			break;
		if (sb->sb_gen != (uint16_t)(sb_gen + 1)) // IMPORTANT type cast
			break;
		sb_gen = sb->sb_gen;
	}
	if (i == SECTORS_PER_SEG)
		return EINVAL;

	sc->sb_sa = (i - 1);
	sb = (struct _superblock *)buf[(i-1)%2]; // get the previous valid superblock
	if (sb->seg_allocp >= sb->seg_cnt)
		return EINVAL;

	for (i=0; i<FD_COUNT; ++i)
		MY_ASSERT(sb->fh[i].root != SECTOR_CACHE);
	memcpy(&sc->superblock, sb, sizeof(sc->superblock));

	return 0;
}

static void
superblock_write(struct g_logstor_softc *sc)
{
	size_t sb_size = sizeof(sc->superblock);
	char buf[SECTOR_SIZE];

	//if (!sc->sb_modified)
	//	return;

	for (int i = 0; i < 4; ++i) {
		MY_ASSERT(sc->superblock.fh[i].root != SECTOR_CACHE);
	}
	sc->superblock.sb_gen++;
	if (++sc->sb_sa == SB_CNT)
		sc->sb_sa = 0;
	memcpy(buf, &sc->superblock, sb_size);
	memset(buf + sb_size, 0, SECTOR_SIZE - sb_size);
	my_write(sc, buf, sc->sb_sa);
	sc->sb_modified = false;
	sc->other_write_count++;
}

#if defined(RAM_DISK_SIZE)
static void
my_read(struct g_logstor_softc *sc, void *buf, uint32_t sa)
{
//MY_BREAK(sa == );
	MY_ASSERT(sc == NULL || sa < sc->superblock.seg_cnt * SECTORS_PER_SEG);
	memcpy(buf, ram_disk + (off_t)sa * SECTOR_SIZE, SECTOR_SIZE);
}

static void
my_write(struct g_logstor_softc *sc, const void *buf, uint32_t sa)
{
//MY_BREAK(sa == );
	MY_ASSERT(sc == NULL || sa < sc->superblock.seg_cnt * SECTORS_PER_SEG);
	memcpy(ram_disk + (off_t)sa * SECTOR_SIZE , buf, SECTOR_SIZE);
}
#else
static void
my_read(struct g_logstor_softc *sc, void *buf, uint32_t sa)
{
	ssize_t bc; // byte count

	MY_ASSERT(sa < sc->superblock.seg_cnt * SECTORS_PER_SEG);
	bc = pread(sc->disk_fd, buf, SECTOR_SIZE, (off_t)sa * SECTOR_SIZE);
	MY_ASSERT(bc == SECTOR_SIZE);
}

static void
my_write(struct g_logstor_softc *sc, const void *buf, uint32_t sa)
{
	ssize_t bc; // byte count

	MY_ASSERT(sa < sc->superblock.seg_cnt * SECTORS_PER_SEG);
	bc = pwrite(sc->disk_fd, buf, SECTOR_SIZE, (off_t)sa * SECTOR_SIZE);
	MY_ASSERT(bc == SECTOR_SIZE);
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
seg_alloc(struct g_logstor_softc *sc)
{
	uint32_t ss_allocp;

	// write the previous segment summary to disk if it has been modified
	sc->seg_sum.ss_allocp = 0;	// the allocation starts from 0 in the next time
	seg_sum_write(sc);

	MY_ASSERT(sc->superblock.seg_allocp < sc->superblock.seg_cnt);
	if (++sc->superblock.seg_allocp == sc->superblock.seg_cnt) {
		sc->superblock.seg_allocp = 0;
		ss_allocp = SB_CNT; // the first SB_CNT sectors are superblock
	} else
		ss_allocp = 0;

	if (sc->superblock.seg_allocp == sc->seg_allocp_start)
		// has accessed all the segment summary blocks
		MY_PANIC();
	sc->seg_allocp_sa = sega2sa(sc->superblock.seg_allocp);
	my_read(sc, &sc->seg_sum, sc->seg_allocp_sa + SEG_SUM_OFFSET);
	sc->seg_sum.ss_allocp = ss_allocp;
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
file_read_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t ba)
{
	uint32_t off_4byte;	// the offset in 4 bytes within the file buffer data
	uint32_t sa;
	struct _fbuf *fbuf;

	MY_ASSERT(fd < FD_COUNT);

	// the initialized reverse map in the segment summary is BLOCK_MAX
	// so it is possible that a caller might pass a ba that is BLOCK_MAX
	if (ba >= BLOCK_MAX) {
		MY_ASSERT(ba == BLOCK_INVALID);
		return SECTOR_NULL;
	}
	// this file is all 0
	if (sc->superblock.fh[fd].root == SECTOR_NULL ||
	    sc->superblock.fh[fd].root == SECTOR_DEL)
		return SECTOR_NULL;

	fbuf = file_access_4byte(sc, fd, ba, &off_4byte);
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
file_write_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t ba, uint32_t sa)
{
	struct _fbuf *fbuf;
	uint32_t off_4byte;	// the offset in 4 bytes within the file buffer data

	MY_ASSERT(fd < FD_COUNT);
	MY_ASSERT(ba < BLOCK_MAX);
	MY_ASSERT(sc->superblock.fh[fd].root != SECTOR_DEL);

	fbuf = file_access_4byte(sc, fd, ba, &off_4byte);
	MY_ASSERT(fbuf != NULL);
	fbuf->data[off_4byte] = sa;
	if (!fbuf->fc.modified) {
		// move to QUEUE_F0_DIRTY
		MY_ASSERT(fbuf->queue_which == QUEUE_F0_CLEAN);
		fbuf->fc.modified = true;
		if (fbuf == sc->fbuf_allocp)
			sc->fbuf_allocp = fbuf->fc.queue_next;
		fbuf_queue_remove(sc, fbuf);
		fbuf_queue_insert_tail(sc, QUEUE_F0_DIRTY, fbuf);
	} else
		MY_ASSERT(fbuf->queue_which == QUEUE_F0_DIRTY);
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
file_access_4byte(struct g_logstor_softc *sc, uint8_t fd, uint32_t ba, uint32_t *off_4byte)
{
	union meta_addr	ma;		// metadata address
	struct _fbuf *fbuf;

	// the sector address stored in file for this ba is 4 bytes
	*off_4byte = ((ba * 4) & (SECTOR_SIZE - 1)) / 4;

	// convert (%fd, %ba) to metadata address
	ma.index = (ba * 4) / SECTOR_SIZE;
	ma.depth = META_LEAF_DEPTH;
	ma.fd = fd;
	ma.meta = 0xFF;	// for metadata address, bits 31:24 are all 1s
	fbuf = fbuf_access(sc, ma);
	return fbuf;
}

static inline unsigned
ma_index_get(union meta_addr ma, unsigned depth)
{
	switch (depth) {
	case 0:
		return ma.index0;
	case 1:
		return ma.index1;
	default:
		MY_PANIC();
		return 0;
	}
}

static union meta_addr
ma_index_set(union meta_addr ma, unsigned depth, unsigned index)
{
	MY_ASSERT(index < (2 << IDX_BITS));

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
		MY_PANIC();
		break;
	}
	return ma;
}

// get the sector address where the metadata is stored on disk
static uint32_t
ma2sa(struct g_logstor_softc *sc, union meta_addr ma)
{
	uint32_t sa;

	switch (ma.depth)
	{
	case 0:
		sa = sc->superblock.fh[ma.fd].root;
		break;
	case 1:
	case 2:
		if (sc->superblock.fh[ma.fd].root == SECTOR_NULL ||
		    sc->superblock.fh[ma.fd].root == SECTOR_DEL)
			sa = SECTOR_NULL;
		else {
			struct _fbuf *parent;	// parent buffer
			union meta_addr pma;	// parent's metadata address
			unsigned pindex;	// index in the parent indirect block

			pma = ma2pma(ma, &pindex);
			parent = fbuf_access(sc, pma);
			MY_ASSERT(parent != NULL);
			sa = parent->data[pindex];
		}
		break;
	case 3: // it is an invalid metadata address
		sa = SECTOR_NULL;
		break;
	}
	return sa;
}

/*
  Initialize metadata file buffer
*/
static void
fbuf_mod_init(struct g_logstor_softc *sc)
{
	int fbuf_count;
	int i;

	//fbuf_count = sc.superblock.block_cnt_max / (SECTOR_SIZE / 4);
	fbuf_count = FBUF_MIN;
	if (fbuf_count < FBUF_MIN)
		fbuf_count = FBUF_MIN;
	if (fbuf_count > FBUF_MAX)
		fbuf_count = FBUF_MAX;
	sc->fbuf_count = fbuf_count;
	sc->fbufs = malloc(fbuf_count * sizeof(*sc->fbufs));
	MY_ASSERT(sc->fbufs != NULL);

	for (i = 0; i < FBUF_BUCKET_CNT; ++i) {
		fbuf_bucket_init(sc, i);
	}
	for (i = 0; i < QUEUE_CNT; ++i) {
		fbuf_queue_init(sc, i);
	}
	// insert fbuf to both QUEUE_F0_CLEAN and hash queue
	for (i = 0; i < fbuf_count; ++i) {
		struct _fbuf *fbuf = &sc->fbufs[i];
#if defined(MY_DEBUG)
		fbuf->index = i;
#endif
		fbuf->fc.is_sentinel = false;
		fbuf->fc.accessed = false;
		fbuf->fc.modified = false;
		fbuf_queue_insert_tail(sc, QUEUE_F0_CLEAN, fbuf);
		// insert fbuf to the last fbuf bucket
		// this bucket is not used in hash search
		// init parent, child_cnt and ma before inserting into FBUF_BUCKET_LAST
		fbuf->parent = NULL;
		fbuf->child_cnt = 0;
		fbuf->ma.uint32 = META_INVALID; // ma must be invalid for fbuf in FBUF_BUCKET_LAST
		fbuf_bucket_insert_head(sc, FBUF_BUCKET_LAST, fbuf);
	}
	sc->fbuf_allocp = &sc->fbufs[0];;
	sc->fbuf_hit = sc->fbuf_miss = 0;
}

// there are 3 kinds of metadata in the system, the fbuf cache, segment summary block and superblock
static void
md_flush(struct g_logstor_softc *sc)
{
	fbuf_cache_flush(sc);
	seg_sum_write(sc);
	superblock_write(sc);
}

static void
fbuf_mod_fini(struct g_logstor_softc *sc)
{
	md_flush(sc);
	free(sc->fbufs);
}

static inline bool
is_queue_empty(struct _fbuf_sentinel *sentinel)
{
	if (sentinel->fc.queue_next == (struct _fbuf *)sentinel) {
		MY_ASSERT(sentinel->fc.queue_prev == (struct _fbuf *)sentinel);
		return true;
	}
	return false;
}

static void
fbuf_clean_queue_check(struct g_logstor_softc *sc)
{
	struct _fbuf_sentinel *queue_sentinel;
	struct _fbuf *fbuf;

	if (sc->fbuf_queue_len[QUEUE_F0_CLEAN] > FBUF_CLEAN_THRESHOLD)
		return;

	md_flush(sc);

	// move all internal nodes with child_cnt 0 to clean queue and last bucket
	for (int q = QUEUE_F1; q < QUEUE_CNT; ++q) {
		queue_sentinel = &sc->fbuf_queue[q];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			MY_ASSERT(fbuf->queue_which == q);
			struct _fbuf *next = fbuf->fc.queue_next;
			if (fbuf->child_cnt == 0) {
				fbuf_queue_remove(sc, fbuf);
				fbuf->fc.accessed = false; // so that it can be replaced faster
				fbuf_queue_insert_tail(sc, QUEUE_F0_CLEAN, fbuf);
				if (fbuf->parent) {
					MY_ASSERT(q != QUEUE_CNT-1);
					struct _fbuf *parent = fbuf->parent;
					fbuf->parent = NULL;
					--parent->child_cnt;
					MY_ASSERT(parent->child_cnt <= SECTOR_SIZE/4);
				}
				// move it to the last bucket so that it cannot be searched
				// fbufs on the last bucket will have the metadata address META_INVALID
				fbuf_bucket_remove(fbuf);
				fbuf->ma.uint32 = META_INVALID;
				fbuf_bucket_insert_head(sc, FBUF_BUCKET_LAST, fbuf);
			}
			fbuf = next;
		}
	}
}

// write back all the dirty fbufs to disk
static void
fbuf_cache_flush(struct g_logstor_softc *sc)
{
	struct _fbuf *fbuf;
	struct _fbuf *dirty_first, *dirty_last, *clean_first;
	struct _fbuf_sentinel *dirty_sentinel;
	struct _fbuf_sentinel *clean_sentinel;

	// write back all the modified nodes to disk
	for (int q = QUEUE_F0_DIRTY; q < QUEUE_CNT; ++q) {
		struct _fbuf_sentinel *queue_sentinel = &sc->fbuf_queue[q];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			MY_ASSERT(fbuf->queue_which == q);
			MY_ASSERT(IS_META_ADDR(fbuf->ma.uint32));
			// QUEUE_F0_DIRTY nodes are always dirty
			MY_ASSERT(q != QUEUE_F0_DIRTY || fbuf->fc.modified);
			if (__predict_true(fbuf->fc.modified))
				fbuf_write(sc, fbuf);
			fbuf = fbuf->fc.queue_next;
		}
	}
	// move all fbufs in the dirty leaf queue to clean leaf queue
	dirty_sentinel = &sc->fbuf_queue[QUEUE_F0_DIRTY];
	if (is_queue_empty(dirty_sentinel))
		return;
	// first, set queue_which to QUEUE_F0_CLEAN for all fbufs on dirty leaf queue
	fbuf = dirty_sentinel->fc.queue_next;
	while (fbuf != (struct _fbuf *)dirty_sentinel) {
		fbuf->queue_which = QUEUE_F0_CLEAN;
		fbuf = fbuf->fc.queue_next;
	}
	// second, insert dirty leaf queue to the head of clean leaf queue
	clean_sentinel = &sc->fbuf_queue[QUEUE_F0_CLEAN];
	dirty_first = dirty_sentinel->fc.queue_next;
	dirty_last = dirty_sentinel->fc.queue_prev;
	clean_first = clean_sentinel->fc.queue_next;
	clean_sentinel->fc.queue_next = dirty_first;
	dirty_first->fc.queue_prev = (struct _fbuf *)clean_sentinel;
	dirty_last->fc.queue_next = clean_first;
	clean_first->fc.queue_prev = dirty_last;
	sc->fbuf_queue_len[QUEUE_F0_CLEAN] += sc->fbuf_queue_len[QUEUE_F0_DIRTY];

	fbuf_queue_init(sc, QUEUE_F0_DIRTY);
}

// flush the cache and invalid fbufs with file descriptors fd1 or fd2
static void
fbuf_cache_flush_and_invalidate_fd(struct g_logstor_softc *sc, int fd1, int fd2)
{
	struct _fbuf *fbuf;

	md_flush(sc);

	for (int i = 0; i < sc->fbuf_count; ++i)
	{
		fbuf = &sc->fbufs[i];
		MY_ASSERT(!fbuf->fc.modified);
		if (fbuf->ma.uint32 == META_INVALID) {
			// the fbufs with metadata address META_INVALID are
			// linked in bucket FBUF_BUCKET_LAST
			MY_ASSERT(fbuf->bucket_which == FBUF_BUCKET_LAST);
			continue;
		}
		// move fbufs with fd equals to fd1 or fd2 to the last bucket
		if (fbuf->ma.fd == fd1 || fbuf->ma.fd == fd2) {
			MY_ASSERT(fbuf->bucket_which != FBUF_BUCKET_LAST);
			fbuf_bucket_remove(fbuf);
			// init parent, child_cnt and ma before inserting to bucket FBUF_BUCKET_LAST
			fbuf->parent = NULL;
			fbuf->child_cnt = 0;
			fbuf->ma.uint32 = META_INVALID;
			fbuf_bucket_insert_head(sc, FBUF_BUCKET_LAST, fbuf);
			fbuf->fc.accessed = false; // so it will be recycled sooner
			if (fbuf->queue_which != QUEUE_F0_CLEAN) {
				// it is an internal node, move it to QUEUE_F0_CLEAN
				MY_ASSERT(fbuf->queue_which != QUEUE_F0_DIRTY);
				fbuf_queue_remove(sc, fbuf);
				fbuf_queue_insert_tail(sc, QUEUE_F0_CLEAN, fbuf);
			}
		}
	}
}

static void
fbuf_queue_init(struct g_logstor_softc *sc, int which)
{
	struct _fbuf_sentinel *queue_head;

	MY_ASSERT(which < QUEUE_CNT);
	sc->fbuf_queue_len[which] = 0;
	queue_head = &sc->fbuf_queue[which];
	queue_head->fc.queue_next = (struct _fbuf *)queue_head;
	queue_head->fc.queue_prev = (struct _fbuf *)queue_head;
	queue_head->fc.is_sentinel = true;
	queue_head->fc.accessed = true;
	queue_head->fc.modified = false;
}

static void
fbuf_queue_insert_tail(struct g_logstor_softc *sc, int which, struct _fbuf *fbuf)
{
	struct _fbuf_sentinel *queue_head;
	struct _fbuf *prev;

	MY_ASSERT(which < QUEUE_CNT);
	MY_ASSERT(which != QUEUE_F0_CLEAN || !fbuf->fc.modified);
	fbuf->queue_which = which;
	queue_head = &sc->fbuf_queue[which];
	prev = queue_head->fc.queue_prev;
	MY_ASSERT(prev->fc.is_sentinel || prev->queue_which == which);
	queue_head->fc.queue_prev = fbuf;
	fbuf->fc.queue_next = (struct _fbuf *)queue_head;
	fbuf->fc.queue_prev = prev;
	prev->fc.queue_next = fbuf;
	++sc->fbuf_queue_len[which];
}

static void
fbuf_queue_remove(struct g_logstor_softc *sc, struct _fbuf *fbuf)
{
	struct _fbuf *prev;
	struct _fbuf *next;
	int which = fbuf->queue_which;

	MY_ASSERT(fbuf != (struct _fbuf *)&sc->fbuf_queue[which]);
	prev = fbuf->fc.queue_prev;
	next = fbuf->fc.queue_next;
	MY_ASSERT(prev->fc.is_sentinel || prev->queue_which == which);
	MY_ASSERT(next->fc.is_sentinel || next->queue_which == which);
	prev->fc.queue_next = next;
	next->fc.queue_prev = prev;
	--sc->fbuf_queue_len[which];
}

// insert to the head of the hashed bucket
static void
fbuf_hash_insert_head(struct g_logstor_softc *sc, struct _fbuf *fbuf)
{
	unsigned hash;

	// the bucket FBUF_BUCKET_LAST is reserved for storing unused fbufs
	// so %hash will be [0..FBUF_BUCKET_LAST)
	hash = fbuf->ma.uint32 % FBUF_BUCKET_LAST;
	fbuf_bucket_insert_head(sc, hash, fbuf);
}

static void
fbuf_bucket_init(struct g_logstor_softc *sc, int which)
{
	struct _fbuf_sentinel *bucket_head;

#if defined(MY_DEBUG)
	MY_ASSERT(which < FBUF_BUCKET_CNT);
	sc->fbuf_bucket_len[which] = 0;
#endif
	bucket_head = &sc->fbuf_bucket[which];
	bucket_head->fc.queue_next = (struct _fbuf *)bucket_head;
	bucket_head->fc.queue_prev = (struct _fbuf *)bucket_head;
	bucket_head->fc.is_sentinel = true;
}

static void
fbuf_bucket_insert_head(struct g_logstor_softc *sc, int which, struct _fbuf *fbuf)
{
	struct _fbuf_sentinel *bucket_head;
	struct _fbuf *next;

#if defined(MY_DEBUG)
	MY_ASSERT(which < FBUF_BUCKET_CNT);
	fbuf->bucket_which = which;
	++sc->fbuf_bucket_len[which];
#endif
	bucket_head = &sc->fbuf_bucket[which];
	next = bucket_head->fc.queue_next;
	bucket_head->fc.queue_next = fbuf;
	fbuf->bucket_next = next;
	fbuf->bucket_prev = (struct _fbuf *)bucket_head;
	if (next->fc.is_sentinel)
		next->fc.queue_prev = fbuf;
	else
		next->bucket_prev = fbuf;
}

static void
fbuf_bucket_remove(struct _fbuf *fbuf)
{
	struct _fbuf *prev;
	struct _fbuf *next;

	MY_ASSERT(!fbuf->fc.is_sentinel);
	prev = fbuf->bucket_prev;
	next = fbuf->bucket_next;
	if (prev->fc.is_sentinel)
		prev->fc.queue_next = next;
	else
		prev->bucket_next = next;
	if (next->fc.is_sentinel)
		next->fc.queue_prev = prev;
	else
		next->bucket_prev = prev;
}

/*
Description:
    Search the file buffer with the tag value of @ma. Return NULL if not found
*/
static struct _fbuf *
fbuf_search(struct g_logstor_softc *sc, union meta_addr ma)
{
	unsigned	hash;	// hash value
	struct _fbuf	*fbuf;
	struct _fbuf_sentinel	*bucket_sentinel;

	// the bucket FBUF_BUCKET_LAST is reserved for storing unused fbufs
	// so %hash will be [0..FBUF_BUCKET_LAST)
	hash = ma.uint32 % FBUF_BUCKET_LAST;
	bucket_sentinel = &sc->fbuf_bucket[hash];
	fbuf = bucket_sentinel->fc.queue_next;
	while (fbuf != (struct _fbuf *)bucket_sentinel) {
		if (fbuf->ma.uint32 == ma.uint32) { // cache hit
			++sc->fbuf_hit;
			return fbuf;
		}
		fbuf = fbuf->bucket_next;
	}
	++sc->fbuf_miss;
	return NULL;	// cache miss
}

// convert from depth to queue number
static const int d2q[] = {QUEUE_F2, QUEUE_F1, QUEUE_F0_DIRTY};

/*
Description:
  using the second chance replace policy to choose a fbuf in QUEUE_F0_CLEAN
*/
struct _fbuf *
fbuf_alloc(struct g_logstor_softc *sc, union meta_addr ma, int depth)
{
	struct _fbuf_sentinel *queue_sentinel;
	struct _fbuf *fbuf, *parent;

	MY_ASSERT(depth <= META_LEAF_DEPTH);
	queue_sentinel = &sc->fbuf_queue[QUEUE_F0_CLEAN];
	fbuf = sc->fbuf_allocp;
again:
	while (true) {
		if (!fbuf->fc.accessed)
			break;

		fbuf->fc.accessed = false;	// give this fbuf a second chance
		fbuf = fbuf->fc.queue_next;
	}
	if (fbuf == (struct _fbuf *)queue_sentinel) {
		fbuf->fc.accessed = true;
		fbuf = fbuf->fc.queue_next;
		MY_ASSERT(fbuf != (struct _fbuf *)queue_sentinel);
		goto again;
	}

	MY_ASSERT(!fbuf->fc.modified);
	MY_ASSERT(fbuf->child_cnt == 0);
	sc->fbuf_allocp = fbuf->fc.queue_next;
	if (depth != META_LEAF_DEPTH) {
		// for fbuf allocated for internal nodes insert it immediately
		// to its internal queue
		fbuf_queue_remove(sc, fbuf);
		fbuf_queue_insert_tail(sc, d2q[depth], fbuf);
	}
	fbuf_bucket_remove(fbuf);
	fbuf->ma = ma;
	fbuf_hash_insert_head(sc, fbuf);
	parent = fbuf->parent;
	if (parent) {
		// parent with child_cnt == 0 will stay in its queue
		// it will only be moved to QUEUE_F0_CLEAN in fbuf_clean_queue_check()
		--parent->child_cnt;
		MY_ASSERT(parent->child_cnt <= SECTOR_SIZE/4);
		MY_ASSERT(parent->queue_which == d2q[parent->ma.depth]);
	}
	return fbuf;
}

/*
Description:
    Read or write the file buffer with metadata address @ma
*/
static struct _fbuf *
fbuf_access(struct g_logstor_softc *sc, union meta_addr ma)
{
	uint32_t sa;	// sector address where the metadata is stored
	unsigned index;
	union meta_addr	ima;	// the intermediate metadata address
	struct _fbuf *parent;	// parent buffer
	struct _fbuf *fbuf;

	MY_ASSERT(IS_META_ADDR(ma.uint32));
	MY_ASSERT(ma.depth <= META_LEAF_DEPTH);

	// get the root sector address of the file %ma.fd
	sa = sc->superblock.fh[ma.fd].root;
	MY_ASSERT(sa != SECTOR_DEL);

	fbuf = fbuf_search(sc, ma);
	if (fbuf != NULL) // cache hit
		goto end;

	// cache miss
	parent = NULL;	// parent for root is NULL
	ima = (union meta_addr){.meta = 0xFF};	// set .meta to 0xFF and all others to 0
	ima.fd = ma.fd;
	// read the metadata from root to leaf node
	for (int i = 0; ; ++i) {
		ima.depth = i;
		fbuf = fbuf_search(sc, ima);
		if (fbuf == NULL) {
			fbuf = fbuf_alloc(sc, ima, i);	// allocate a fbuf from clean queue
			fbuf->parent = parent;
			if (parent) {
				// parent with child_cnt == 0 will stay in its queue
				// it will only be moved to QUEUE_F0_CLEAN in fbuf_clean_queue_check()
				++parent->child_cnt;
				MY_ASSERT(parent->child_cnt <= SECTOR_SIZE/4);
			} else {
				MY_ASSERT(i == 0);
			}
			if (sa == SECTOR_NULL) {
				bzero(fbuf->data, sizeof(fbuf->data));
				if (i == 0)
					sc->superblock.fh[ma.fd].root = SECTOR_CACHE;
			} else {
				MY_ASSERT(sa >= SECTORS_PER_SEG);
				my_read(sc, fbuf->data, sa);
			}
#if defined(MY_DEBUG)
			fbuf->sa = sa;
			if (parent)
				parent->child[index] = fbuf;
#endif
		} else {
			MY_ASSERT(fbuf->parent == parent);
			MY_ASSERT(fbuf->sa == sa ||
				(i == 0 && sa == SECTOR_CACHE));
		}
		if (i == ma.depth) // reach the intended depth
			break;

		parent = fbuf;		// %fbuf is the parent of next level indirect block
		index = ma_index_get(ma, i);// the index to next level's indirect block
		sa = parent->data[index];	// the sector address of the next level indirect block
		ima = ma_index_set(ima, i, index); // set the next level's index for @ima
	} // for
end:
	fbuf->fc.accessed = true;
	return fbuf;
}

static void
fbuf_write(struct g_logstor_softc *sc, struct _fbuf *fbuf)
{
	struct _fbuf *parent;	// buffer parent
	unsigned pindex;	// the index in parent indirect block
	uint32_t sa;		// sector address

	MY_ASSERT(fbuf->fc.modified);
	sa = _logstor_write(sc, fbuf->ma.uint32, fbuf->data);
#if defined(MY_DEBUG)
	fbuf->sa = sa;
#endif
	fbuf->fc.modified = false;

	// update the sector address of this fbuf in its parent's fbuf
	parent = fbuf->parent;
	if (parent) {
		MY_ASSERT(fbuf->ma.depth != 0);
		MY_ASSERT(parent->ma.depth == fbuf->ma.depth - 1);
		pindex = ma_index_get(fbuf->ma, fbuf->ma.depth - 1);
		parent->data[pindex] = sa;
		parent->fc.modified = true;
	} else {
		MY_ASSERT(fbuf->ma.depth == 0);
		// store the root sector address to the corresponding file table in super block
		sc->superblock.fh[fbuf->ma.fd].root = sa;
		sc->sb_modified = true;
	}
}

#if defined(MY_DEBUG)
void
logstor_hash_check(void)
{
	struct g_logstor_softc *sc = &softc;
	struct _fbuf *fbuf;
	struct _fbuf_sentinel *bucket_sentinel;
	int total = 0;

	for (int i = 0; i < FBUF_BUCKET_CNT; ++i)
	{
		bucket_sentinel = &sc->fbuf_bucket[i];
		fbuf = bucket_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)bucket_sentinel) {
			++total;
			MY_ASSERT(!fbuf->fc.is_sentinel);
			MY_ASSERT(fbuf->bucket_which == i);
			if (i == FBUF_BUCKET_LAST)
				MY_ASSERT(fbuf->ma.uint32 == META_INVALID);
			else
				MY_ASSERT(fbuf->ma.uint32 % FBUF_BUCKET_LAST == i);
			fbuf = fbuf->bucket_next;
		}
	}
	MY_ASSERT(total == sc->fbuf_count);
}

void
logstor_queue_check(void)
{
	struct g_logstor_softc *sc = &softc;
	struct _fbuf_sentinel *queue_sentinel;
	struct _fbuf *fbuf;
	unsigned count[QUEUE_CNT];

	// set debug child count of internal nodes to 0
	for (int q = QUEUE_F1; q < QUEUE_CNT; ++q) {
		queue_sentinel = &sc->fbuf_queue[q];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			MY_ASSERT(d2q[fbuf->ma.depth] == q);
			fbuf->dbg_child_cnt = 0; // set the child count to 0
			fbuf = fbuf->fc.queue_next;
		}
	}
	// check queue length and calculate the child count
	int root_cnt = 0;
	for (int q = 0; q < QUEUE_CNT ; ++q) {
		count[q] = 0;
		queue_sentinel = &sc->fbuf_queue[q];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			++count[q];
			MY_ASSERT(fbuf->queue_which == q);
			if (q == QUEUE_CNT-1) {
				MY_ASSERT(fbuf->parent == NULL);
				++root_cnt;
			} else
				MY_ASSERT(fbuf->ma.uint32 == META_INVALID || fbuf->parent != NULL);
			if (fbuf->parent)
				++fbuf->parent->dbg_child_cnt; // increment parent's debug child count

			fbuf = fbuf->fc.queue_next;
		}
		MY_ASSERT(sc->fbuf_queue_len[q] == count[q]);
	}
	// check that the debug child count of internal nodes is correct
	for (int q = QUEUE_F1; q < QUEUE_CNT; ++q) {
		queue_sentinel = &sc->fbuf_queue[q];
		fbuf = queue_sentinel->fc.queue_next;
		while (fbuf != (struct _fbuf *)queue_sentinel) {
			MY_ASSERT(fbuf->dbg_child_cnt == fbuf->child_cnt);
			fbuf = fbuf->fc.queue_next;
		}
	}
	int total = 0;
	for (int q = 0; q < QUEUE_CNT; ++q)
		total += count[q];

	MY_ASSERT(total == sc->fbuf_count);
}

static uint32_t
sa2ba(struct g_logstor_softc *sc, uint32_t sa)
{
	static uint32_t seg_sum_cache_sa;
	static struct _seg_sum seg_sum_cache;
	uint32_t seg_sa;
	unsigned seg_off;

	seg_sa = sa & ~(SECTORS_PER_SEG - 1);
	seg_off = sa & (SECTORS_PER_SEG - 1);
	MY_ASSERT(seg_sa != 0 || seg_off >= SB_CNT);
	MY_ASSERT(seg_off != SEG_SUM_OFFSET);
	if (seg_sa != seg_sum_cache_sa) {
		my_read(sc, &seg_sum_cache, seg_sa + SEG_SUM_OFFSET);
		seg_sum_cache_sa = seg_sa;
	}
	return (seg_sum_cache.ss_rm[seg_off]);
}

/*
Description:
  Check the integrity of the logstor
*/
void
logstor_check(struct g_logstor_softc *sc)
{
	uint32_t block_cnt;

	printf("%s ...\n", __func__);
	block_cnt = logstor_get_block_cnt();
	MY_ASSERT(block_cnt < BLOCK_MAX);
	for (uint32_t ba = 0; ba < block_cnt; ++ba) {
		uint32_t sa = sc->ba2sa_fp(sc, ba);
#if defined(WYC)
		ba2sa_normal();
		ba2sa_during_commit();
#endif
		if (sa != SECTOR_NULL) {
			uint32_t ba_exp = sa2ba(sc, sa);
			if (ba_exp != ba) {
				printf("ERROR %s: ba %u sa %u ba_exp %u\n",
				    __func__, ba, sa, ba_exp);
				MY_PANIC();
			}
		}
	}
	printf("%s done.\n\n", __func__);
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
#endif
