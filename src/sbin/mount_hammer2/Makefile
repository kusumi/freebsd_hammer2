.include <bsd.own.mk>

PROG=	mount_hammer2
SRCS=	mount_hammer2.c getmntopts.c
MAN=	mount_hammer2.8

WARNS=	5

SRCTOP?=	/usr/src # XXX

CFLAGS+=	-I${SRCTOP}/sbin/mount
CFLAGS+=	-I../../sys

.PATH:		${SRCTOP}/sbin/mount

.include <bsd.prog.mk>
