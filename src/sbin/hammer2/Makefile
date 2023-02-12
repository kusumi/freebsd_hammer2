PROG=	hammer2
SRCS=	cmd_debug.c cmd_pfs.c cmd_stat.c cmd_volume.c main.c ondisk.c \
	print_inode.c subs.c xxhash.c gsb_crc32.c
MAN=	hammer2.8

.PATH:	../../sys/fs/hammer2/xxhash ../../sys/libkern

WARNS?=	3

CFLAGS+=	-I../../sys

LIBADD=		md

.include <bsd.prog.mk>
