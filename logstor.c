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

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define __predict_true(exp)     __builtin_expect((exp), 1)
#define __predict_false(exp)    __builtin_expect((exp), 0)
#define __unused		__attribute__((unused))

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
#define	IS_META_ADDR(x)	((x) >= META_START)
#define META_LEAF_DEPTH 2

#define	SECTOR_NULL	0	// this sector address can not map to any block address
#define SECTOR_DELETE	1	// delete marker for a block

//#define FBUF_MAX	500
#define FBUF_MAX	512
#define FBUF_BUCKETS	509

#define	FD_CUR	1
#define FD_COUNT	4	// max number of metadata files supported
#define FD_INVALID	-1	// invalid file

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
	int32_t	sega_alloc;	// allocate this segment
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
	uint16_t ss_gen;  // sequence number. used for redo after system crash
	uint16_t ss_alloc; // allocate sector at this location

	// below are not stored on disk
	uint32_t sega; // the segment address of the segment summary
	//unsigned live_count;
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

/*
  Metadata is cached in memory. The access unit of metadata is block so each cache line
  stores a block of metadata
*/
struct _fbuf_sential {
	union meta_addr	ma;	// the metadata address
	struct {
		struct _fbuf *next;
		struct _fbuf *prev;
	} cir_queue; // list entry for the circular queue
	bool accessed;	// only used for fbufs on circular queue
	bool modified;	// the fbuf is dirty
	bool on_cir_queue;	// on circular queue
	bool on_free_queue;
};

struct _fbuf { // file buffer
	union meta_addr	ma;	// the metadata address
	union {
		struct {
			LIST_ENTRY(_fbuf) entry; // for the indirect queue
			unsigned ref_cnt;
		} indir_queue;
		struct {
			struct _fbuf *next;
			struct _fbuf *prev;
		} cir_queue; // list entry for the circular queue
		TAILQ_ENTRY(_fbuf) free_queue;
	};
	bool accessed;	// only used for fbufs on circular queue
	bool modified;	// the fbuf is dirty
	bool on_cir_queue;	// on circular queue
	bool on_free_queue;

	LIST_ENTRY(_fbuf)	buffer_bucket_queue;// the pointer for bucket chain
	struct _fbuf	*parent;

	// the metadata is cached here
	uint32_t	data[SECTOR_SIZE/sizeof(uint32_t)];
#if defined(MY_DEBUG)
	uint32_t	sa;	// the sector address of the @data
#endif
#if defined(FBUF_DEBUG)
	uint16_t	index;
	struct _fbuf 	*child[SECTOR_SIZE/sizeof(uint32_t)];
#endif
};

/*
	logstor soft control
*/
struct g_logstor_softc {
	struct _seg_sum seg_sum;// segment summary for the hot segment
	
	int fbuf_count;
	struct _fbuf *fbuf;
	struct _fbuf *fbuf_cir_head;	// head of the circular queue
	struct _fbuf_sential fbuf_cir_sential;	// head of the circular queue
#if 0 // the accessed, modified and flag bits should be moved out of struct _fbuf
	unsigned *fbuf_accessed;
	unsigned *fbuf_modified;
	unsigned *fbuf_on_cir_queue;
#endif	
	// buffer hash queue
	LIST_HEAD(_fbuf_bucket, _fbuf)	fbuf_bucket[FBUF_BUCKETS];
	
	LIST_HEAD(, _fbuf) fbuf_ind_head[META_LEAF_DEPTH]; // indirect queue
	TAILQ_HEAD(, _fbuf) fbuf_free_head;
	uint32_t	fbuf_free_cnt;
	
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
	struct _superblock superblock;
};

uint32_t gdb_cond0;
uint32_t gdb_cond1;

#if defined(RAM_DISK_SIZE)
static char *ram_disk;
#endif
static struct g_logstor_softc sc;

static int _logstor_read_one(unsigned ba, char *data);
static int _logstor_write_one(uint32_t ba, char *data, struct _seg_sum *seg_sum);

static void seg_alloc(void);
static void seg_sum_write(void);

static void disk_init(int fd);
static int  superblock_read(void);
static void superblock_write(void);

static uint32_t file_read_4byte(uint8_t fh, uint32_t ba);
static void file_write_4byte(uint8_t fh, uint32_t ba, uint32_t sa);
static struct _fbuf *file_access_4byte(uint8_t fd, uint32_t offset, uint32_t *buf_off, bool bl_write);

static void fbuf_mod_init(void);
static void fbuf_mod_fini(void);
static void fbuf_mod_flush(void);
static struct _fbuf *fbuf_get(union meta_addr ma);
static struct _fbuf *fbuf_alloc(void);
static struct _fbuf *fbuf_search(union meta_addr ma);
static void fbuf_flush(struct _fbuf *buf);
static void fbuf_hash_insert(struct _fbuf *buf);
static void fbuf_write(struct _fbuf *buf);
static void fbuf_cir_queue_remove(struct _fbuf *buf);
static void fbuf_cir_queue_insert(struct _fbuf *buf);

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
	// the order of the two statements below is important
	seg_alloc();

	sc.data_write_count = sc.other_write_count = 0;

	fbuf_mod_init();

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
	MY_ASSERT(ba < sc.superblock.max_block_cnt);

	if (size == 1) {
		file_write_4byte(sc.superblock.fd_cur, ba, SECTOR_DELETE);
	} else {
		for (i = 0; i<size; i++)
			file_write_4byte(sc.superblock.fd_cur, ba + i, SECTOR_DELETE);
	}

	return (0);
}

struct _fbuf *
fbuf_get_replacement(void)
{
	struct _fbuf *buf;

again:
	buf = sc.fbuf_cir_head;
	do {
		MY_ASSERT(buf->on_cir_queue);
		if (!buf->accessed)
			break;
		buf->accessed = false;	// give this buffer a second chance
		buf = buf->cir_queue.next;
	} while (buf != sc.fbuf_cir_head);

	if ((struct _fbuf_sential *)buf == &sc.fbuf_cir_sential) {
		buf = buf->cir_queue.next;
		goto again;
	}
	sc.fbuf_cir_head = buf->cir_queue.next;

	return buf;
}

static void
check_free_queue(void)
{
	struct _fbuf *buf;

	while (sc.fbuf_free_cnt < 4) {
		buf = fbuf_get_replacement();
		if (buf->modified) {
			fbuf_write(buf);
		}
		fbuf_cir_queue_remove(buf);
		TAILQ_INSERT_TAIL(&sc.fbuf_free_head, buf, free_queue);
		sc.fbuf_free_cnt++;
	}
}

int
logstor_read_test(uint32_t ba, void *data)
{
	_logstor_read_one(ba, data);
	check_free_queue();
	return 0;
}

int
logstor_write_test(uint32_t ba, void *data)
{
	_logstor_write_one(ba, data, &sc.seg_sum);
	check_free_queue();
	return 0;
}

static int
_logstor_read_one(unsigned ba, char *data)
{
	uint32_t sa;	// sector address

	MY_ASSERT(ba < sc.superblock.max_block_cnt);

	sa = file_read_4byte(sc.superblock.fd_cur, ba);
	if (sa == SECTOR_NULL || sa == SECTOR_DELETE)
		bzero(data, SECTOR_SIZE);
	else {
		my_read(sa, data, 1);
	}
	return 0;
}

// is a sector with a reverse ba valid?
static bool
is_sec_valid(uint32_t sa, uint32_t ba_rev)
{
	uint32_t sa_rev; // the sector address for ba_rev

	if (IS_META_ADDR(ba_rev)) {
		sa_rev = ma2sa((union meta_addr)ba_rev);
	} else {
		sa_rev = file_read_4byte(sc.superblock.fd_cur, ba_rev);
	}
	if (sa == sa_rev)
		return true;

	return false;
}

/*
Description:
  write one data block

Return:
  the sector address where the data is written
*/
static int
_logstor_write_one(uint32_t ba, char *data, struct _seg_sum *seg_sum)
{
	static uint8_t recursive;

	MY_BREAK(++recursive >= 3);
	MY_ASSERT(IS_META_ADDR(ba) || ba < sc.superblock.max_block_cnt);
	MY_ASSERT(seg_sum->ss_alloc < SEG_SUM_OFFSET);
#if 1
again:
	uint32_t seg_sa = sega2sa(seg_sum->sega);
	for (int i = seg_sum->ss_alloc; i < SEG_SUM_OFFSET; ++i)
	{
		uint32_t ba_rev; // ba from the reverse map
		uint32_t sa = seg_sa + i;

		ba_rev = seg_sum->ss_rm[i];
		if (is_sec_valid(sa, ba_rev))
			continue;
		my_write(sa, data, 1);
		seg_sum->ss_rm[i] = ba; // record reverse mapping
		seg_sum->ss_alloc = i + 1;
		if (seg_sum->ss_alloc == SEG_SUM_OFFSET) {
			seg_sum_write();
			seg_alloc();
		}
		if (!IS_META_ADDR(ba)) {
			// record the forward mapping
			// the forward mapping must be recorded after
			// the segment summary block write
			file_write_4byte(sc.superblock.fd_cur, ba, sa);
		}
		--recursive;
		return sa;
	}
	// no free sector in current segment
	seg_alloc();
	goto again;
#else
	uint32_t sa;	// sector address
	sa = sega2sa(seg_sum->sega) + seg_sum->ss_alloc;
	MY_ASSERT(sa < sc.superblock.seg_cnt * SECTORS_PER_SEG);
	my_write(sa, data, 1);

	// record the reverse mapping
	seg_sum->ss_rm[seg_sum->ss_alloc++] = ba;

	if (seg_sum->ss_alloc == SEG_SUM_OFFSET)
	{	// current segment is full
		seg_sum_write(seg_sum);
		seg_alloc(seg_sum);
	}
	if (!IS_META_ADDR(ba)) {
		// record the forward mapping
		// the forward mapping must be recorded after
		// the segment summary block write
		file_write_4byte(sc.superblock.fd_cur, ba, sa);
	}
	return sa;
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
Description:
    Write the initialized supeblock to the downstream disk
*/
static void
disk_init(int fd)
{
	int32_t seg_free_cnt;
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
	sb_out->fd_cur = FD_CUR;
	sb_out->fd_snap = FD_INVALID;
	sb_out->fd_new = FD_INVALID;
	sb_out->fd_new_snap = FD_INVALID;
	sb_out->seg_cnt = sector_cnt / SECTORS_PER_SEG;
	if (sizeof(struct _superblock) + sb_out->seg_cnt > SECTOR_SIZE) {
		printf("%s: size of superblock %d seg_cnt %d\n",
		    __func__, (int)sizeof(struct _superblock), (int)sb_out->seg_cnt);
		printf("    the size of the disk must be less than %lld\n",
		    (SECTOR_SIZE - sizeof(struct _superblock)) * (long long)SEG_SIZE);
		MY_PANIC();
	}
	seg_free_cnt = sb_out->seg_cnt - SEG_DATA_START;

	// the physical disk must have at least the space for the metadata
	MY_ASSERT(seg_free_cnt * BLOCKS_PER_SEG >
	    (sector_cnt / (SECTOR_SIZE / 4)) * FD_COUNT);

	sb_out->max_block_cnt =
	    seg_free_cnt * BLOCKS_PER_SEG -
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
	struct _seg_sum ss;
	for (int i = 0; i < SECTORS_PER_SEG - 1; ++i)
		ss.ss_rm[i] = BLOCK_INVALID;
	ss.ss_alloc = 0;
	// initialize all segment summary blocks
	for (int i = SEG_DATA_START; i < sb_out->seg_cnt; ++i)
	{
		my_write(sega2sa(i) + SEG_SUM_OFFSET, &ss, 1);
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
	    sb_in->sega_alloc >= sb_in->seg_cnt)
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
	if (sb_in->sega_alloc >= sb_in->seg_cnt)
		return EINVAL;

	memcpy(&sc.superblock, sb_in, sizeof(sc.superblock));
	sc.sb_modified = false;

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
seg_alloc(void)
{
	uint32_t sega;

	sega = sc.superblock.sega_alloc;
	if (++sc.superblock.sega_alloc == sc.superblock.seg_cnt)
		sc.superblock.sega_alloc = SEG_DATA_START;
	MY_ASSERT(sc.superblock.sega_alloc < sc.superblock.seg_cnt);
	my_read(sega2sa(sega), &sc.seg_sum, 1);
	sc.seg_sum.sega = sega;
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
	struct _fbuf *buf;
	uint32_t offset;	// the offset within the file buffer data

	if (((union meta_addr)ba).depth == 3) // invalid block address
		return SECTOR_NULL;
	MY_ASSERT(ba < META_START);
	buf = file_access_4byte(fd, ba, &offset, false);
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

	MY_ASSERT(ba < META_START);
	buf = file_access_4byte(fd, ba, &offset, true);
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
file_access_4byte(uint8_t fd, uint32_t ba, uint32_t *buf_off, bool bl_write)
{
	union meta_addr	ma;		// metadata address
	struct _fbuf *buf;

	// the data stored in file for this ba is 4 bytes
	*buf_off = (ba * 4) & (SECTOR_SIZE - 1);	// the buffer is 4 KiB

	// convert to metadata address from (@fd, @ba)
	ma.index = ba / (SECTOR_SIZE / 4); // (ba * 4) / SECTOR_SIZE
	ma.depth = META_LEAF_DEPTH;
	ma.fd = fd;
	ma.meta = 0xFF;	// for metadata address, bits 31:24 are all 1s
	buf = fbuf_get(ma);
	buf->accessed = true;
	if (__predict_false(!buf->modified) && bl_write) {
		buf->modified = true;
	}
	return buf;
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
		MY_PANIC();
		break;
	}
	return ma;
}

// metadata address to sector address
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
		sa = sc.superblock.ftab[ma.fd];
		break;
	case 1:
	case 2:
		pma = ma2pma(ma, &pindex);
		pbuf = fbuf_get(pma);
		sa = pbuf->data[pindex];
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

	sc.fbuf_hit = sc.fbuf_miss = 0;
	sc.fbuf_count = sc.superblock.max_block_cnt / (SECTOR_SIZE / 4);
	if (sc.fbuf_count > FBUF_MAX)
		sc.fbuf_count = FBUF_MAX;
	size_t fbuf_size = sizeof(*sc.fbuf) * sc.fbuf_count;
	sc.fbuf = malloc(fbuf_size);
	MY_ASSERT(sc.fbuf != NULL);

	for (int i = 0; i < FBUF_BUCKETS; i++)
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
	TAILQ_INIT(&sc.fbuf_free_head);
	for (int i = 0; i < sc.fbuf_count; i++) {
		struct _fbuf *fbuf = &sc.fbuf[i];
#if defined(FBUF_DEBUG)
		fbuf->index = i;
#endif
		fbuf->parent = NULL;
		TAILQ_INSERT_TAIL(&sc.fbuf_free_head, &fbuf[i], free_queue);
		fbuf->on_free_queue = true;
		fbuf->on_cir_queue = false;
		fbuf->accessed = false;
		fbuf->modified = false;
	}
	sc.fbuf_free_cnt = sc.fbuf_count;
	sc.fbuf_cir_sential.ma = META_INVALID;
	sc.fbuf_cir_sential.cir_queue.next = (struct _fbuf *)&sc.fbuf_cir_sential;
	sc.fbuf_cir_sential.cir_queue.prev = (struct _fbuf *)&sc.fbuf_cir_sential;
	sc.fbuf_cir_sential.accessed = false;
	sc.fbuf_cir_sential.modified = false;
	sc.fbuf_cir_sential.on_cir_queue = true;
	sc.fbuf_cir_head = (struct _fbuf *)&sc.fbuf_cir_sential;

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

	buf = sc.fbuf_cir_head->cir_queue.next;
	while (buf != (struct _fbuf *)&sc.fbuf_cir_head) {
		MY_ASSERT(buf->on_cir_queue);
		fbuf_flush(buf);
		buf = buf->cir_queue.next;
	}

	// process active indirect blocks
	for (i = META_LEAF_DEPTH - 1; i >= 0; i--)
		LIST_FOREACH(buf, &sc.fbuf_ind_head[i], indir_queue.entry) {
			MY_ASSERT(buf->on_cir_queue == false);
			fbuf_flush(buf);
		}
}

static void
fbuf_hash_insert(struct _fbuf *buf)
{
	unsigned hash;
	struct _fbuf_bucket *bucket;

	hash = buf->ma.uint32 % FBUF_BUCKETS;
	bucket = &sc.fbuf_bucket[hash];
	LIST_INSERT_HEAD(bucket, buf, buffer_bucket_queue);
}

#if defined(MY_DEBUG)
static void
fbuf_queue_check(void)
{
	struct _fbuf *buf;
	unsigned total, indir_cnt[META_LEAF_DEPTH];

	buf = sc.fbuf_cir_head->cir_queue.next;
	total = 0;
	while (buf != (struct _fbuf *)&sc.fbuf_cir_head) {
		++total;
		MY_ASSERT(total <= sc.fbuf_count);
		MY_ASSERT(buf->on_cir_queue);
		buf = buf->cir_queue.next;
	}

	for (int i = 0; i < META_LEAF_DEPTH; i++)
		indir_cnt[i] = 0;

	for (int i = 0; i < META_LEAF_DEPTH ; ++i) {
		buf = LIST_FIRST(&sc.fbuf_ind_head[i]);
		while (buf != NULL) {
			++indir_cnt[0];
			MY_ASSERT(indir_cnt[0] <= sc.fbuf_count);
			MY_ASSERT(buf->on_cir_queue == false);
			MY_ASSERT(buf->ma.depth == i);
			buf = LIST_NEXT(buf, indir_queue.entry);
		}
	}

	for (int i = 0; i < META_LEAF_DEPTH; i++)
		total += indir_cnt[i];
	
	MY_ASSERT(total + sc.fbuf_free_cnt == sc.fbuf_count);
}
#endif

/*
    Circular queue insert before
*/
static void
fbuf_cir_queue_insert(struct _fbuf *buf)
{
	struct _fbuf *prev;

	prev = sc.fbuf_cir_head->cir_queue.prev;
	sc.fbuf_cir_head->cir_queue.prev = buf;
	buf->cir_queue.next = (struct _fbuf *)&sc.fbuf_cir_head;
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

	MY_ASSERT(buf != (struct _fbuf *)&sc.fbuf_cir_sential);
	MY_ASSERT(buf->on_cir_queue);
	MY_ASSERT(buf->ma.uint32 != META_INVALID.uint32);
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
	tma.uint32 = META_START; // set .meta to 0xFF and all others to 0
	tma.fd = ma.fd;
	// read the metadata from root to leaf node
	for (int i = 0; ; ++i) {
		tma.depth = i;
		buf = fbuf_search(tma);
		if (buf == NULL) {
			buf = fbuf_alloc();	// allocate a fbuf from free queue
			fbuf_cir_queue_insert(buf);
			buf->ma = tma;
			fbuf_hash_insert(buf);
			buf->parent = pbuf;
			/*
			  Theoretically the parent's reference count should be
			  incremented here. But if imcremented here, the parent
			  might be reclaimed in the call fbuf_alloc, so
			  it is actually incremented in the previous loop to
			  prevent it from being reclaimed by fbuf_alloc.
			*/
			if (sa == SECTOR_NULL)	// the metadata block does not exist
				bzero(buf->data, sizeof(buf->data));
			else {
				my_read(sa, buf->data, 1);
				//sc.other_write_count++;
			}
#if defined(MY_DEBUG)
			buf->sa = sa;
#endif
#if defined(FBUF_DEBUG)
			if (pbuf)
				pbuf->child[index] = buf;
#endif
		} else {
			MY_ASSERT(buf->parent == pbuf);
			MY_ASSERT(buf->sa == sa);
			if (pbuf) {
				MY_ASSERT(pbuf->indir_queue.ref_cnt != 1);
				/*
				  The reference count of the parent is always
				  incremented in the previous loop. In this case
				  we don't need to, so decremented it here to
				  compensate the increment in the previous loop.
				*/
				pbuf->indir_queue.ref_cnt--;
			}
		}
		if (i == ma.depth) // reach intended depth
			break;

		if (buf->on_cir_queue) {
			// move it to active indirect block queue
			fbuf_cir_queue_remove(buf);
			LIST_INSERT_HEAD(&sc.fbuf_ind_head[i], buf, indir_queue.entry);
			buf->indir_queue.ref_cnt = 0;
		}
		/*
		  Increment the reference count of this buffer to prevent it
		  from being reclaimed by the call to function fbuf_alloc.
		*/
		buf->indir_queue.ref_cnt++;

		index = ma_index_get(ma, i);// the index to next level's indirect block
		sa = buf->data[index];	// the sector address of the next level indirect block
		tma = ma_index_set(tma, i, index); // set the next level's index for @tma
		pbuf = buf;		// @buf is the parent of next level indirect block
	}
#if defined(MY_DEBUG)
	fbuf_queue_check();
#endif
	return buf;
}

static void
fbuf_write(struct _fbuf *buf)
{
	struct _fbuf *pbuf;	// buffer parent
	unsigned pindex;	// the index in parent indirect block
	uint32_t sa;		// sector address
	struct _seg_sum *seg_hot = &sc.seg_sum;

	sa = _logstor_write_one(buf->ma.uint32, (char *)buf->data, seg_hot);
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
		if (__predict_false(!pbuf->modified)) {
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
	seg_hot->ss_rm[seg_hot->ss_alloc++] = buf->ma.uint32;

	if (seg_hot->ss_alloc == SEG_SUM_OFFSET) { // current segment is full
		seg_sum_write(seg_hot);
		seg_alloc();
	}
}

/*
Description:
    Write the dirty data in file buffer to disk
*/
static void
fbuf_flush(struct _fbuf *buf)
{

	if (!buf->modified)
		return;

	MY_ASSERT(IS_META_ADDR(buf->ma.uint32));
	fbuf_write(buf);
	return;
}

/*
Description:
    Use the second chance algorithm to allocate a file buffer
*/
static struct _fbuf *
fbuf_alloc(void)
{
	struct _fbuf *fbuf;

	fbuf = TAILQ_FIRST(&sc.fbuf_free_head);
	MY_ASSERT(fbuf != NULL);
	TAILQ_REMOVE(&sc.fbuf_free_head, fbuf, free_queue);
	sc.fbuf_free_cnt--;
	return fbuf;
}

/*
Description:
    Search the file buffer with the tag value of @ma. Return NULL if not found
*/
static struct _fbuf *
fbuf_search(union meta_addr ma)
{
	unsigned	hash;	// hash value
	struct _fbuf_bucket	*bucket;
	struct _fbuf	*buf;

	hash = ma.uint32 % FBUF_BUCKETS;
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
		LIST_FOREACH(buf, &sc.fbuf_ind_head[i], indir_queue.entry) {
			MY_ASSERT(buf->on_cir_queue == false);
			fbuf_dump(buf, fh);
		}
	}
	buf = sc.fbuf_cir_head->cir_queue.next;
	while (buf != (struct _fbuf *)&sc.fbuf_cir_head) {
		fbuf_dump(buf, fh);
		buf = buf->cir_queue.next;
	}

	fclose(fh);
}
#endif // FBUF_DEBUG
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
		sa = file_read_4byte(sc.superblock.fd_cur, ba);
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
	if (sc.seg_sum.ss_alloc != 0)
		seg_sum_write(&sc.seg_sum);
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

