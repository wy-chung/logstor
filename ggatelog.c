/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2004 Pawel Jakub Dawidek <pjd@FreeBSD.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#if __BSD_VISIBLE
#include <stdbool.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <assert.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/bio.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syslog.h>

#include <geom/gate/g_gate.h>
#include "ggate.h"
#include "logstor.h"


static enum {
    LOG_UNSET,
    LOG_CREATE,
    LOG_DESTROY,
    LOG_LIST,
    LOG_RESCUE
} log_action = LOG_UNSET;

static const char *log_path = NULL;
static int log_unit = G_GATE_UNIT_AUTO;
static unsigned log_flags = 0;
static int log_force = 0;
static unsigned log_sectorsize = 0;
static unsigned log_timeout = G_GATE_TIMEOUT;

static void
log_usage(void)
{

	fprintf(stderr, "usage: %s create [-v] [-o <ro|wo|rw>] "
	    "[-s sectorsize] [-t timeout] [-u unit] <path>\n", getprogname());
	fprintf(stderr, "       %s rescue [-v] [-o <ro|wo|rw>] <-u unit> "
	    "<path>\n", getprogname());
	fprintf(stderr, "       %s destroy [-f] <-u unit>\n", getprogname());
	fprintf(stderr, "       %s list [-v] [-u unit]\n", getprogname());
	exit(EXIT_FAILURE);
}

static int
g_gatelog_openflags(unsigned ggflags)
{

	if ((ggflags & G_GATE_FLAG_READONLY) != 0)
		return (O_RDONLY);
	else if ((ggflags & G_GATE_FLAG_WRITEONLY) != 0)
		return (O_WRONLY);
	return (O_RDWR);
}

static void
g_gatelog_serve(void)
{
	struct g_gate_ctl_io ggio;
	size_t bsize;

	if (g_gate_verbose == 0) {
		if (daemon(0, 0) == -1) {
			g_gate_destroy(log_unit, 1);
			err(EXIT_FAILURE, "Cannot daemonize");
		}
	}
	g_gate_log(LOG_DEBUG, "Worker created: %u.", getpid());
	ggio.gctl_version = G_GATE_VERSION;
	ggio.gctl_unit = log_unit;
	bsize = log_sectorsize;
	ggio.gctl_data = malloc(bsize);
	for (;;) {
		int error;
once_again:
		ggio.gctl_length = bsize;
		ggio.gctl_error = 0;
		g_gate_ioctl(G_GATE_CMD_START, &ggio);
		error = ggio.gctl_error;
		switch (error) {
		case 0:
			break;
		case ECANCELED:
			/* Exit gracefully. */
			free(ggio.gctl_data);
			g_gate_close_device();
			logstor_close();
			logstor_fini();
			my_break();
			exit(EXIT_SUCCESS);
		case ENOMEM:
			/* Buffer too small. */
			assert(ggio.gctl_cmd == BIO_DELETE ||
			    ggio.gctl_cmd == BIO_WRITE);
			ggio.gctl_data = realloc(ggio.gctl_data,
			    ggio.gctl_length);
			if (ggio.gctl_data != NULL) {
				bsize = ggio.gctl_length;
				goto once_again;
			}
			/* FALLTHROUGH */
		case ENXIO:
		default:
			g_gate_xlog("ioctl(/dev/%s): %s.", G_GATE_CTL_NAME,
			    strerror(error));
		}

		error = 0;
		switch (ggio.gctl_cmd) {
		case BIO_READ:
			if ((size_t)ggio.gctl_length > bsize) {
				ggio.gctl_data = realloc(ggio.gctl_data,
				    ggio.gctl_length);
				if (ggio.gctl_data != NULL)
					bsize = ggio.gctl_length;
				else
					error = ENOMEM;
			}
			if (error)
				break;
			error = logstor_read(ggio.gctl_offset, ggio.gctl_data, ggio.gctl_length);
#if 0
			if (error == 0) {
				if (pread(fd, ggio.gctl_data, ggio.gctl_length,
				    ggio.gctl_offset) == -1) {
					error = errno;
				}
			}
#endif
			break;
		case BIO_DELETE:
			// To enable BIO_DELETE, the following statement must be added
			// in "case BIO_GETATTR" of g_gate_start() of g_gate.c
			//	if (g_handleattr_int(pbp, "GEOM::candelete", 1))
			//		return;
			// and the command below must be executed before mount the device
			//	tunefs -t enabled /dev/ggate0
			error = logstor_delete(ggio.gctl_offset, ggio.gctl_data, ggio.gctl_length);
			break;
		case BIO_WRITE:
			error = logstor_write(ggio.gctl_offset, ggio.gctl_data, ggio.gctl_length);
#if 0
			if (pwrite(fd, ggio.gctl_data, ggio.gctl_length,
			    ggio.gctl_offset) == -1) {
				error = errno;
			}
#endif
			break;
		default:
			error = EOPNOTSUPP;
		}

		ggio.gctl_error = error;
		g_gate_ioctl(G_GATE_CMD_DONE, &ggio);
	}
}

static void
g_gatelog_create(void)
{
	struct g_gate_ctl_create ggioc;

	logstor_init();
	logstor_open(log_path);

	memset(&ggioc, 0, sizeof(ggioc));
	ggioc.gctl_version = G_GATE_VERSION;
	ggioc.gctl_unit = log_unit;
	ggioc.gctl_mediasize = (off_t)logstor_get_block_cnt() * SECTOR_SIZE;
	//if (log_sectorsize == 0)
		//log_sectorsize = g_gate_sectorsize(fd);
	log_sectorsize = SECTOR_SIZE;
	ggioc.gctl_sectorsize = log_sectorsize;
	ggioc.gctl_timeout = log_timeout;
	ggioc.gctl_flags = log_flags;
	ggioc.gctl_maxcount = 0;
	strlcpy(ggioc.gctl_info, log_path, sizeof(ggioc.gctl_info));
	g_gate_ioctl(G_GATE_CMD_CREATE, &ggioc);
	if (log_unit == -1)
		printf("%s%u\n", G_GATE_PROVIDER_NAME, ggioc.gctl_unit);
	log_unit = ggioc.gctl_unit;
	g_gatelog_serve();
}

static void
g_gatelog_rescue(void)
{
	struct g_gate_ctl_cancel ggioc;

	logstor_init();
	logstor_open(log_path);

	ggioc.gctl_version = G_GATE_VERSION;
	ggioc.gctl_unit = log_unit;
	ggioc.gctl_seq = 0;
	g_gate_ioctl(G_GATE_CMD_CANCEL, &ggioc);

	g_gatelog_serve();
}

int
main(int argc, char *argv[])
{

	if (argc < 2)
		log_usage();
	if (strcasecmp(argv[1], "create") == 0)
		log_action = LOG_CREATE;
	else if (strcasecmp(argv[1], "rescue") == 0)
		log_action = LOG_RESCUE;
	else if (strcasecmp(argv[1], "destroy") == 0)
		log_action = LOG_DESTROY;
	else if (strcasecmp(argv[1], "list") == 0)
		log_action = LOG_LIST;
	else
		log_usage();
	argc -= 1;
	argv += 1;

	log_flags = 0; // rw
	log_sectorsize = SECTOR_SIZE;
	g_gate_verbose = 0;
	for (;;) {
		int ch;

		ch = getopt(argc, argv, "ft:u:v");
		if (ch == -1)
			break;
		switch (ch) {
		case 'f': // Forcibly destroy ggate provider
			if (log_action != LOG_DESTROY)
				log_usage();
			log_force = 1;
			break;
		case 'o':
			if (log_action != LOG_CREATE && log_action != LOG_RESCUE)
				log_usage();
			if (strcasecmp("ro", optarg) == 0)
				log_flags = G_GATE_FLAG_READONLY;
			else if (strcasecmp("wo", optarg) == 0)
				log_flags = G_GATE_FLAG_WRITEONLY;
			else if (strcasecmp("rw", optarg) == 0)
				log_flags = 0;
			else {
				errx(EXIT_FAILURE,
				    "Invalid argument for '-o' option.");
			}
			break;
		case 's': // Sector size
			if (log_action != LOG_CREATE)
				log_usage();
			errno = 0;
			log_sectorsize = strtoul(optarg, NULL, 10);
			if (log_sectorsize == 0 && errno != 0)
				errx(EXIT_FAILURE, "Invalid sectorsize.");
			break;
		case 't': // timeout
			if (log_action != LOG_CREATE)
				log_usage();
			errno = 0;
			log_timeout = strtoul(optarg, NULL, 10);
			if (log_timeout == 0 && errno != 0)
				errx(EXIT_FAILURE, "Invalid timeout.");
			break;
		case 'u':
			errno = 0;
			log_unit = strtol(optarg, NULL, 10);
			if (log_unit == 0 && errno != 0)
				errx(EXIT_FAILURE, "Invalid unit number.");
			break;
		case 'v':
			if (log_action == LOG_DESTROY)
				log_usage();
			g_gate_verbose++;
			break;
		default:
			log_usage();
		}
	}
	argc -= optind;
	argv += optind;

	log_path = NULL;
	if (argc == 0)
		log_path = ""; //DISK_FILE;
	else if (argc == 1)
		log_path = argv[0];
	else
		log_usage();

	switch (log_action) {
	case LOG_CREATE:
		g_gate_load_module();
		g_gate_open_device();
		//if (log_path == NULL)
		//	log_usage();
		g_gatelog_create();
		break;
	case LOG_RESCUE:
		if (log_unit == -1) {
			fprintf(stderr, "Required unit number.\n");
			log_usage();
		}
		g_gate_open_device();
		if (log_path == NULL)
			log_usage();
		g_gatelog_rescue();
		break;
	case LOG_DESTROY:
		if (log_unit == -1) {
			fprintf(stderr, "Required unit number.\n");
			log_usage();
		}
		g_gate_verbose = 1;
		g_gate_open_device();
		g_gate_destroy(log_unit, log_force);
		break;
	case LOG_LIST:
		g_gate_list(log_unit, g_gate_verbose);
		break;
	case LOG_UNSET:
	default:
		log_usage();
	}
	g_gate_close_device();
	exit(EXIT_SUCCESS);
}
