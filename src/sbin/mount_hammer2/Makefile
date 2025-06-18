.include <bsd.own.mk>

PROG=	mount_hammer2
SRCS=	mount_hammer2.c mntopts.c
MAN=	mount_hammer2.8

.PATH:	../../lib/libutil

WARNS=	5

CFLAGS+=	-I../../sys
CFLAGS+=	-I../../lib/libutil

.include <bsd.prog.mk>
