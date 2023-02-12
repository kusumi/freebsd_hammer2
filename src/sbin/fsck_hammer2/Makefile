PROG=	fsck_hammer2
SRCS=	fsck_hammer2.c test.c ondisk.c subs.c xxhash.c gsb_crc32.c
MAN=	fsck_hammer2.8

.PATH:	../hammer2 ../../sys/fs/hammer2/xxhash ../../sys/libkern

WARNS?=	3

CFLAGS+=	-I../../sys
CFLAGS+=	-I../hammer2

LIBADD=		md

.include <bsd.prog.mk>
