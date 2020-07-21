# $FreeBSD$

.PATH: ${SRCTOP}/sys/geom/logstor

KMOD=	geom_logstor
SRCS=	g_logstor.c

.include <bsd.kmod.mk>
