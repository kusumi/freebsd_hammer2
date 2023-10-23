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
#include <sys/lock.h>
#include <sys/sx.h>

/* printf(9) variants for HAMMER2 */
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
#define debug_hprintf(X, ...)	do { } while (0)
#endif

/* hammer2_lk is lockmgr(9) in DragonFly. */
typedef struct lock hammer2_lk_t;

#define hammer2_lk_init(p, s)		lockinit(p, PVFS, s, 0, 0)
#define hammer2_lk_ex(p)		lockmgr(p, LK_EXCLUSIVE, NULL)
#define hammer2_lk_unlock(p)		lockmgr(p, LK_RELEASE, NULL)
#define hammer2_lk_destroy(p)		lockdestroy(p)

/*
 * Mutex and spinlock shims.
 * Normal synchronous non-abortable locks can be substituted for spinlocks.
 * FreeBSD HAMMER2 currently uses sx(9) for both mtx and spinlock.
 */
typedef struct sx hammer2_mtx_t;

/* Zero on success. */
#define hammer2_mtx_init(p, s)		sx_init(p, s)
#define hammer2_mtx_init_recurse(p, s)	sx_init_flags(p, s, SX_RECURSE)
#define hammer2_mtx_ex(p)		sx_xlock(p)
#define hammer2_mtx_ex_try(p)		(!sx_try_xlock(p))
#define hammer2_mtx_sh(p)		sx_slock(p)
#define hammer2_mtx_sh_try(p)		(!sx_try_slock(p))
#define hammer2_mtx_unlock(p)		sx_unlock(p)
#define hammer2_mtx_destroy(p)		sx_destroy(p)
#define hammer2_mtx_sleep(c, p, s)	sx_sleep(c, p, 0, s, 0)
#define hammer2_mtx_wakeup(c)		wakeup(c)

/* sx_try_upgrade panics on INVARIANTS if already exclusively locked. */
#define hammer2_mtx_upgrade_try(p)	(!sx_try_upgrade(p))

/* Non-zero if exclusively locked by the calling thread. */
#define hammer2_mtx_owned(p)		sx_xlocked(p)

#define hammer2_mtx_assert_locked(p)	sx_assert(p, SA_LOCKED)
#define hammer2_mtx_assert_unlocked(p)	sx_assert(p, SA_UNLOCKED)
#define hammer2_mtx_assert_ex(p)	sx_assert(p, SA_XLOCKED)
#define hammer2_mtx_assert_sh(p)	sx_assert(p, SA_SLOCKED)

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

/* Zero on success. */
#define hammer2_spin_init(p, s)		sx_init(p, s)
#define hammer2_spin_ex(p)		sx_xlock(p)
#define hammer2_spin_sh(p)		sx_slock(p)
#define hammer2_spin_unex(p)		sx_xunlock(p)
#define hammer2_spin_unsh(p)		sx_sunlock(p)
#define hammer2_spin_destroy(p)		sx_destroy(p)

#define hammer2_spin_assert_locked(p)	sx_assert(p, SA_LOCKED)
#define hammer2_spin_assert_unlocked(p)	sx_assert(p, SA_UNLOCKED)
#define hammer2_spin_assert_ex(p)	sx_assert(p, SA_XLOCKED)
#define hammer2_spin_assert_sh(p)	sx_assert(p, SA_SLOCKED)

#endif /* !_FS_HAMMER2_OS_H_ */
