KMOD=	hammer2
SRCS=	vnode_if.h \
	hammer2_admin.c hammer2_chain.c hammer2_cluster.c hammer2_inode.c \
	hammer2_io.c hammer2_ioctl.c hammer2_lz4.c hammer2_ondisk.c \
	hammer2_strategy.c hammer2_subr.c hammer2_vfsops.c hammer2_vnops.c \
	hammer2_xops.c xxhash/xxhash.c icrc32.c

.PATH:	../../libkern

#CFLAGS+=	-DINVARIANTS -DINVARIANT_SUPPORT

WARNS=	5

.include <bsd.kmod.mk>
