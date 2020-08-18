# $FreeBSD$

.PATH: ${SRCTOP}/sys/geom/logstor

KMOD=	geom_logstor
SRCS=	g_logstor.c

CFLAGS+= -g -O0

.include <bsd.kmod.mk>
