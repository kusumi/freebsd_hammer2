/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2022 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _FS_HAMMER2_OS_H_
#define _FS_HAMMER2_OS_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/sx.h>
#include <sys/malloc.h>
#include <sys/buf.h>
#include <sys/vnode.h>

#include <vm/uma.h>

#include <machine/atomic.h>

#include "hammer2_compat.h"

/* See FreeBSD src 7e1d3eefd410ca0fbae5a217422821244c3eeee4 */
#define FREEBSD_NDINIT_ARGUMENT 1400043

/* See FreeBSD src 2bfd8992c7c7301166c74931ad63d4755bb4a6c7 */
/* 1400006 is the first version with this commit. */
#define FREEBSD_CLUSTERW_STRUCTURE 1400006

/* See FreeBSD src b214fcceacad6b842545150664bd2695c1c2b34f */
#define FREEBSD_READDIR_COOKIES_64 1400045

#ifdef INVARIANTS
#include <sys/kdb.h>
#define print_backtrace()	kdb_backtrace()
#else
#define print_backtrace()	do {} while (0)
#endif

#ifdef INVARIANTS
#define HFMT	"%s(%s|%d): "
#define HARGS	__func__, \
    curproc ? curproc->p_comm : "-", \
    curthread ? curthread->td_tid : -1
#else
#define HFMT	"%s: "
#define HARGS	__func__
#endif

#define hprintf(X, ...)	printf(HFMT X, HARGS, ## __VA_ARGS__)
#define hpanic(X, ...)	panic(HFMT X, HARGS, ## __VA_ARGS__)

#ifdef INVARIANTS
#define debug_hprintf	hprintf
#else
#define debug_hprintf(X, ...)	do {} while (0)
#endif

/* hammer2_lk is lockmgr(9) in DragonFly. */
typedef struct sx hammer2_lk_t;

static __inline void
hammer2_lk_init(hammer2_lk_t *p, const char *s)
{
	sx_init(p, s);
}

static __inline void
hammer2_lk_ex(hammer2_lk_t *p)
{
	sx_xlock(p);
}

static __inline void
hammer2_lk_unlock(hammer2_lk_t *p)
{
	sx_unlock(p);
}

static __inline void
hammer2_lk_destroy(hammer2_lk_t *p)
{
	sx_destroy(p);
}

static __inline void
hammer2_lk_assert_ex(hammer2_lk_t *p)
{
	sx_assert(p, SA_XLOCKED);
}

static __inline void
hammer2_lk_assert_unlocked(hammer2_lk_t *p)
{
	sx_assert(p, SA_UNLOCKED);
}

typedef int hammer2_lkc_t;

static __inline void
hammer2_lkc_init(hammer2_lkc_t *c __unused, const char *s __unused)
{
}

static __inline void
hammer2_lkc_destroy(hammer2_lkc_t *c __unused)
{
}

static __inline void
hammer2_lkc_sleep(hammer2_lkc_t *c, hammer2_lk_t *p, const char *s)
{
	sx_sleep(c, p, 0, s, 0);
}

static __inline void
hammer2_lkc_wakeup(hammer2_lkc_t *c)
{
	wakeup(c);
}

/*
 * Mutex and spinlock shims.
 * Normal synchronous non-abortable locks can be substituted for spinlocks.
 * FreeBSD HAMMER2 currently uses sx(9) for both mtx and spinlock.
 */
struct sx_wrapper {
	struct sx lock;
	int refs;
};
typedef struct sx_wrapper hammer2_mtx_t;

static __inline void
hammer2_mtx_init(hammer2_mtx_t *p, const char *s)
{
	bzero(p, sizeof(*p));
	sx_init(&p->lock, s);
}

static __inline void
hammer2_mtx_init_recurse(hammer2_mtx_t *p, const char *s)
{
	bzero(p, sizeof(*p));
	sx_init_flags(&p->lock, s, SX_RECURSE);
}

static __inline void
hammer2_mtx_ex(hammer2_mtx_t *p)
{
	sx_xlock(&p->lock);
	p->refs++;
}

static __inline void
hammer2_mtx_sh(hammer2_mtx_t *p)
{
	sx_slock(&p->lock);
	p->refs++;
}

static __inline void
hammer2_mtx_unlock(hammer2_mtx_t *p)
{
	p->refs--;
	sx_unlock(&p->lock);
}

static __inline int
hammer2_mtx_refs(hammer2_mtx_t *p)
{
	return (p->refs);
}

static __inline void
hammer2_mtx_destroy(hammer2_mtx_t *p)
{
	sx_destroy(&p->lock);
}

static __inline void
hammer2_mtx_sleep(hammer2_lkc_t *c, hammer2_mtx_t *p, const char *s)
{
	sx_sleep(c, &p->lock, 0, s, 0);
}

static __inline void
hammer2_mtx_wakeup(hammer2_lkc_t *c)
{
	wakeup(c);
}

/* Non-zero if exclusively locked by the calling thread. */
static __inline int
hammer2_mtx_owned(hammer2_mtx_t *p)
{
	return (sx_xlocked(&p->lock));
}

static __inline void
hammer2_mtx_assert_ex(hammer2_mtx_t *p)
{
	sx_assert(&p->lock, SA_XLOCKED);
}

static __inline void
hammer2_mtx_assert_sh(hammer2_mtx_t *p)
{
	sx_assert(&p->lock, SA_SLOCKED);
}

static __inline void
hammer2_mtx_assert_locked(hammer2_mtx_t *p)
{
	sx_assert(&p->lock, SA_LOCKED);
}

static __inline void
hammer2_mtx_assert_unlocked(hammer2_mtx_t *p)
{
	sx_assert(&p->lock, SA_UNLOCKED);
}

static __inline int
hammer2_mtx_ex_try(hammer2_mtx_t *p)
{
	if (sx_try_xlock(&p->lock)) {
		p->refs++;
		return (0);
	} else {
		return (1);
	}
}

static __inline int
hammer2_mtx_sh_try(hammer2_mtx_t *p)
{
	if (sx_try_slock(&p->lock)) {
		p->refs++;
		return (0);
	} else {
		return (1);
	}
}

static __inline int
hammer2_mtx_upgrade_try(hammer2_mtx_t *p)
{
	/* sx_try_upgrade() panics with INVARIANTS if already ex-locked. */
	if (hammer2_mtx_owned(p))
		return (0);

	if (sx_try_upgrade(&p->lock))
		return (0);
	else
		return (1);
}

static __inline int
hammer2_mtx_temp_release(hammer2_mtx_t *p)
{
	int x;

	x = hammer2_mtx_owned(p);
	hammer2_mtx_unlock(p);

	return (x);
}

static __inline void
hammer2_mtx_temp_restore(hammer2_mtx_t *p, int x)
{
	if (x)
		hammer2_mtx_ex(p);
	else
		hammer2_mtx_sh(p);
}

typedef struct sx hammer2_spin_t;

static __inline void
hammer2_spin_init(hammer2_spin_t *p, const char *s)
{
	sx_init(p, s);
}

static __inline void
hammer2_spin_ex(hammer2_spin_t *p)
{
	sx_xlock(p);
}

static __inline void
hammer2_spin_sh(hammer2_spin_t *p)
{
	sx_slock(p);
}

static __inline void
hammer2_spin_unex(hammer2_spin_t *p)
{
	sx_xunlock(p);
}

static __inline void
hammer2_spin_unsh(hammer2_spin_t *p)
{
	sx_sunlock(p);
}

static __inline void
hammer2_spin_destroy(hammer2_spin_t *p)
{
	sx_destroy(p);
}

static __inline void
hammer2_spin_assert_ex(hammer2_spin_t *p)
{
	sx_assert(p, SA_XLOCKED);
}

static __inline void
hammer2_spin_assert_sh(hammer2_spin_t *p)
{
	sx_assert(p, SA_SLOCKED);
}

static __inline void
hammer2_spin_assert_locked(hammer2_spin_t *p)
{
	sx_assert(p, SA_LOCKED);
}

static __inline void
hammer2_spin_assert_unlocked(hammer2_spin_t *p)
{
	sx_assert(p, SA_UNLOCKED);
}

MALLOC_DECLARE(M_HAMMER2);
MALLOC_DECLARE(M_HAMMER2_LZ4);
extern uma_zone_t hammer2_zone_inode;
extern uma_zone_t hammer2_zone_xops;
extern uma_zone_t hammer2_zone_rbuf;
extern uma_zone_t hammer2_zone_wbuf;

extern int malloc_leak_m_hammer2;
extern int malloc_leak_m_hammer2_lz4;
extern int malloc_leak_m_temp;

#ifdef HAMMER2_MALLOC
static __inline void
adjust_malloc_leak(int delta, struct malloc_type *type)
{
	int *lp;

	if (type == M_HAMMER2)
		lp = &malloc_leak_m_hammer2;
	else if (type == M_HAMMER2_LZ4)
		lp = &malloc_leak_m_hammer2_lz4;
	else if (type == M_TEMP)
		lp = &malloc_leak_m_temp;
	else
		hpanic("bad malloc type");
	atomic_add_int(lp, delta);
}

static __inline void *
hmalloc(size_t size, struct malloc_type *type, int flags)
{
	void *addr;

	flags &= ~M_WAITOK;
	flags |= M_NOWAIT;

	addr = malloc(size, type, flags);
	KASSERTMSG(addr, "size %ld flags %x malloc_leak %d,%d,%d",
	    (long)size, flags,
	    malloc_leak_m_hammer2,
	    malloc_leak_m_hammer2_lz4,
	    malloc_leak_m_temp);
	if (addr) {
		KKASSERT(size > 0);
		adjust_malloc_leak(size, type);
	}

	return (addr);
}

static __inline void *
hrealloc(void *addr, size_t size, struct malloc_type *type, int flags)
{
	flags &= ~M_WAITOK;
	flags |= M_NOWAIT;

	addr = realloc(addr, size, type, flags);
	KASSERTMSG(addr, "size %ld flags %x malloc_leak %d,%d,%d",
	    (long)size, flags,
	    malloc_leak_m_hammer2,
	    malloc_leak_m_hammer2_lz4,
	    malloc_leak_m_temp);
	if (addr) {
		KKASSERT(size > 0);
		adjust_malloc_leak(size, type);
	}

	return (addr);
}

/* OpenBSD style free(9) with 3 arguments */
static __inline void
hfree(void *addr, struct malloc_type *type, size_t freedsize)
{
	if (addr) {
		KKASSERT(freedsize > 0);
		adjust_malloc_leak(-(int)freedsize, type);
	}
	free(addr, type);
}

static __inline char *
hstrdup(const char *str)
{
	size_t len;
	char *copy;

	len = strlen(str) + 1;
	copy = hmalloc(len, M_TEMP, M_NOWAIT);
	if (copy == NULL)
		return (NULL);
	bcopy(str, copy, len);

	return (copy);
}

static __inline void
hstrfree(char *str)
{
	hfree(str, M_TEMP, strlen(str) + 1);
}
#else
static __inline void
adjust_malloc_leak(int delta __unused, struct malloc_type *type __unused)
{
}
#define hmalloc(size, type, flags)		malloc(size, type, flags)
#define hrealloc(addr, size, type, flags)	realloc(addr, size, type, flags)
#define hfree(addr, type, freedsize)		free(addr, type)
#define hstrdup(str)				strdup(str, M_TEMP)
#define hstrfree(str)				free(str, M_TEMP)
#endif

extern struct vop_vector hammer2_vnodeops;
extern struct vop_vector hammer2_fifoops;

/* cluster_write() interface has changed in FreeBSD 14.x. */
#if __FreeBSD_version >= FREEBSD_CLUSTERW_STRUCTURE
static void __inline
cluster_write_vn(struct vnode *vp, struct vn_clusterw *vnc, struct buf *bp,
    u_quad_t filesize, int seqcount, int gbflags)
{
	cluster_write(vp, vnc, bp, filesize, seqcount, gbflags);
}
#else
struct vn_clusterw {
};

static void __inline
cluster_init_vn(struct vn_clusterw *vnc __unused)
{
}

static void __inline
cluster_write_vn(struct vnode *vp, struct vn_clusterw *vnc __unused,
    struct buf *bp, u_quad_t filesize, int seqcount, int gbflags)
{
	cluster_write(vp, bp, filesize, seqcount, gbflags);
}
#endif

#endif /* !_FS_HAMMER2_OS_H_ */
