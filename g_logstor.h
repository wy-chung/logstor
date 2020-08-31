/*-
 * Copyright (c) 2004-2006 Pawel Jakub Dawidek <pjd@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef	_G_LOGSTOR_H_
#define	_G_LOGSTOR_H_

#define	G_LOGSTOR_CLASS_NAME	"LOGSTOR"
#define	G_LOGSTOR_VERSION	4
#define	G_LOGSTOR_PREFIX	"logstor/"
/*
 * Special flag to instruct glogstor to passthrough the underlying provider's
 * physical path
 */
#define G_LOGSTOR_PHYSPATH_PASSTHROUGH "\255"

#ifdef _KERNEL
#define	G_LOGSTOR_DEBUG(lvl, ...)	do {				\
	if (g_logstor_debug >= (lvl)) {					\
		printf("GEOM_LOGSTOR");					\
		if (g_logstor_debug > 0)				\
			printf("[%u]", lvl);				\
		printf(": ");						\
		printf(__VA_ARGS__);					\
		printf("\n");						\
	}								\
} while (0)
#define	G_LOGSTOR_LOGREQ(bp, ...)	G_LOGSTOR_LOGREQLVL(2, bp, __VA_ARGS__)
#define G_LOGSTOR_LOGREQLVL(lvl, bp, ...) do {				\
	if (g_logstor_debug >= (lvl)) {					\
		printf("GEOM_LOGSTOR[%d]: ", (lvl));			\
		printf(__VA_ARGS__);					\
		printf(" ");						\
		g_print_bio(bp);					\
		printf("\n");						\
	}								\
} while (0)

#define	MY_DEBUG

#if defined(MY_DEBUG)
void my_debug(const char * fname, int line_num);
void my_break(void);

#define MY_ASSERT(x)	do if (!(x)) my_debug(__func__, __LINE__); while(0)
#define MY_PANIC()	my_debug(__FILE__, __LINE__)
#else
#define MY_ASSERT(x)
#define MY_PANIC()
#endif

#define	SECTOR_SIZE	0x1000		// 4K

struct g_logstor_softc;

uint32_t superblock_init(struct g_logstor_softc *sc, off_t media_size);
void logstor_init(void);
void logstor_fini(struct g_logstor_softc *sc);
int  logstor_open(struct g_logstor_softc *sc, struct g_consumer *cp);
void logstor_close(struct g_logstor_softc *sc);
int logstor_read  (struct g_logstor_softc *sc, struct bio *bp);
int logstor_write (struct g_logstor_softc *sc, struct bio *bp);
int logstor_delete(struct g_logstor_softc *sc, struct bio *bp);
uint32_t logstor_get_block_cnt(struct g_logstor_softc *sc);
//void logstor_check(void);
unsigned logstor_get_data_write_count(struct g_logstor_softc *sc);
unsigned logstor_get_other_write_count(struct g_logstor_softc *sc);
unsigned logstor_get_fbuf_hit(struct g_logstor_softc *sc);
unsigned logstor_get_fbuf_miss(struct g_logstor_softc *sc);

#endif	/* _KERNEL */

#endif	/* _G_LOGSTOR_H_ */
