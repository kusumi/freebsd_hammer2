PROG=	newfs_hammer2
SRCS=	newfs_hammer2.c mkfs_hammer2.c ondisk.c subs.c xxhash.c gsb_crc32.c
MAN=	newfs_hammer2.8

.PATH:	../hammer2 ../../sys/fs/hammer2/xxhash ../../sys/libkern

WARNS?=	3

CFLAGS+=	-I../../sys
CFLAGS+=	-I../hammer2

.include <bsd.prog.mk>
