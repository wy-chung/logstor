# $FreeBSD$

#.PATH: ${.CURDIR:H}/shared

PROG=	ggatelog
MAN=
SRCS=	ggatelog.c ggate.c logstor.c

CFLAGS+= -DLIBGEOM
CFLAGS+= -I${.CURDIR:H}
CFLAGS+= -DEXIT_ON_PANIC
CFLAGS+= -O0

LIBADD=	geom util

#NO_WERROR= yes

.include <bsd.prog.mk>
