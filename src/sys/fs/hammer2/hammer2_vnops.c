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

#include "hammer2.h"

#include <sys/limits.h>
#include <sys/dirent.h>
#include <sys/fcntl.h>
#include <sys/namei.h>
#include <sys/uio.h>
#include <sys/unistd.h>
#include <sys/priv.h>
#include <sys/vmmeter.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vnode_pager.h>

static void hammer2_truncate_file(hammer2_inode_t *, hammer2_key_t);
static void hammer2_extend_file(hammer2_inode_t *, hammer2_key_t, int);

static int
hammer2_inactive(struct vop_inactive_args *ap)
{
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	/* degenerate case */
	if (ip->meta.mode == 0) {
		/*
		 * If we are done with the inode, reclaim it
		 * so that it can be reused immediately.
		 */
		vrecycle(vp);
		return (0);
	}

	/*
	 * Aquire the inode lock to interlock against vp updates via
	 * the inode path and file deletions and such (which can be
	 * namespace-only operations that might not hold the vnode).
	 */
	hammer2_inode_lock(ip, 0);
	if (ip->flags & HAMMER2_INODE_ISUNLINKED) {
		/*
		 * If the inode has been unlinked we can throw away all
		 * buffers (dirty or not) and clean the file out.
		 *
		 * Because vrecycle() calls are not guaranteed, try to
		 * dispose of the inode as much as possible right here.
		 */
		vtruncbuf(vp, 0, hammer2_get_logical());

		/* Delete the file on-media. */
		if ((ip->flags & HAMMER2_INODE_DELETING) == 0) {
			atomic_set_int(&ip->flags, HAMMER2_INODE_DELETING);
			hammer2_inode_delayed_sideq(ip);
		}
		hammer2_inode_unlock(ip);

		/* Recycle immediately if possible. */
		vrecycle(vp);
	} else {
		hammer2_inode_unlock(ip);
	}

	return (0);
}

static int
hammer2_reclaim(struct vop_reclaim_args *ap)
{
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	if (ip == NULL)
		return (0);

	/* The inode lock is required to disconnect it. */
	hammer2_inode_lock(ip, 0);

	vfs_hash_remove(vp);

	vp->v_data = NULL;
	ip->vp = NULL;

	/*
	 * Delete the file on-media.  This should have been handled by the
	 * inactivation.  The operation is likely still queued on the inode
	 * though so only complain if the stars don't align.
	 */
	if ((ip->flags & (HAMMER2_INODE_ISUNLINKED | HAMMER2_INODE_DELETING)) ==
	    HAMMER2_INODE_ISUNLINKED) {
		atomic_set_int(&ip->flags, HAMMER2_INODE_DELETING);
		hammer2_inode_delayed_sideq(ip);
		hprintf("inum %016llx unlinked but not disposed\n",
		    (long long)ip->meta.inum);
	}
	hammer2_inode_unlock(ip);

	/*
	 * Modified inodes will already be on SIDEQ or SYNCQ, no further
	 * action is needed.
	 *
	 * We cannot safely synchronize the inode from inside the reclaim
	 * due to potentially deep locks held as-of when the reclaim occurs.
	 * Interactions and potential deadlocks abound.  We also can't do it
	 * here without desynchronizing from the related directory entrie(s).
	 */
	hammer2_inode_drop(ip); /* vp ref */

	/*
	 * XXX handle background sync when ip dirty, kernel will no longer
	 * notify us regarding this inode because there is no longer a
	 * vnode attached to it.
	 */
	return (0);
}

/*
 * Currently this function synchronizes the front-end inode state to the
 * backend chain topology, then flushes the inode's chain and sub-topology
 * to backend media.  This function does not flush the root topology down to
 * the inode.
 */
static int
hammer2_fsync(struct vop_fsync_args *ap)
{
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);
	int error1 = 0, error2;

	hammer2_trans_init(ip->pmp, 0);

	/*
	 * Flush dirty buffers in the file's logical buffer cache.
	 * It is best to wait for the strategy code to commit the
	 * buffers to the device's backing buffer cache before
	 * then trying to flush the inode.
	 *
	 * This should be quick, but certain inode modifications cached
	 * entirely in the hammer2_inode structure may not trigger a
	 * buffer read until the flush so the fsync can wind up also
	 * doing scattered reads.
	 */
	vop_stdfsync(ap);

	/* Flush any inode changes. */
	hammer2_inode_lock(ip, 0);
	if (ip->flags & (HAMMER2_INODE_RESIZED|HAMMER2_INODE_MODIFIED))
		error1 = hammer2_inode_chain_sync(ip);

	/*
	 * Flush dirty chains related to the inode.
	 *
	 * NOTE! We are not in a flush transaction.  The inode remains on
	 *	 the sideq so the filesystem syncer can synchronize it to
	 *	 the volume root.
	 */
	error2 = hammer2_inode_chain_flush(ip, HAMMER2_XOP_INODE_STOP);
	if (error2)
		error1 = error2;

	hammer2_inode_unlock(ip);
	hammer2_trans_done(ip->pmp, 0);

	return (error1);
}

static int
hammer2_access(struct vop_access_args *ap)
{
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	/*
	 * Disallow write attempts on read-only file systems;
	 * unless the file is a socket, fifo, or a block or
	 * character device resident on the file system.
	 */
	if (ap->a_accmode & VWRITE) {
		switch (vp->v_type) {
		case VDIR:
		case VLNK:
		case VREG:
			if (vp->v_mount->mnt_flag & MNT_RDONLY)
				return (EROFS);
		default:
			break;
		}
	}

	/* If immutable bit set, nobody gets to write it. */
	if ((ap->a_accmode & VWRITE) && (ip->meta.uflags & SF_IMMUTABLE))
		return (EPERM);

	return (vaccess(vp->v_type, (mode_t)ip->meta.mode,
	    hammer2_to_unix_xid(&ip->meta.uid),
	    hammer2_to_unix_xid(&ip->meta.gid),
	    ap->a_accmode, ap->a_cred));
}

static int
hammer2_getattr(struct vop_getattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	hammer2_inode_t *ip = VTOI(vp);
	hammer2_pfs_t *pmp = ip->pmp;

	vap->va_fsid = pmp->mp->mnt_stat.f_fsid.val[0];
	vap->va_fileid = ip->meta.inum;
	vap->va_mode = ip->meta.mode & ~S_IFMT;
	vap->va_nlink = ip->meta.nlinks;
	vap->va_uid = hammer2_to_unix_xid(&ip->meta.uid);
	vap->va_gid = hammer2_to_unix_xid(&ip->meta.gid);
	vap->va_rdev = NODEV;
	vap->va_size = ip->meta.size;
	vap->va_flags = ip->meta.uflags;
	hammer2_time_to_timespec(ip->meta.ctime, &vap->va_ctime);
	hammer2_time_to_timespec(ip->meta.mtime, &vap->va_mtime);
#ifdef HAMMER2_ATIME
	hammer2_time_to_timespec(ip->meta.atime, &vap->va_atime);
#else
	hammer2_time_to_timespec(ip->meta.mtime, &vap->va_atime); /* return mtime */
#endif
	hammer2_time_to_timespec(ip->meta.btime, &vap->va_birthtime);
	vap->va_gen = 1;
	vap->va_blocksize = vp->v_mount->mnt_stat.f_iosize;
	if (ip->meta.type == HAMMER2_OBJTYPE_DIRECTORY) {
		/*
		 * Can't really calculate directory use sans the files under
		 * it, just assume one block for now.
		 */
		vap->va_bytes = HAMMER2_INODE_BYTES;
	} else {
		vap->va_bytes = hammer2_inode_data_count(ip);
	}
	vap->va_type = hammer2_get_vtype(ip->meta.type);
	vap->va_filerev = 0;

	return (0);
}

static int
hammer2_chown(struct vnode *vp, uid_t uid, gid_t gid, struct ucred *cred,
    struct thread *td)
{
	hammer2_inode_t *ip = VTOI(vp);
	struct uuid uuid_uid, uuid_gid;
	uid_t ouid, ogid;
	uint64_t ctime;
	uint32_t imode;
	int error;

	hammer2_mtx_assert_ex(&ip->lock);

	ouid = hammer2_to_unix_xid(&ip->meta.uid);
	ogid = hammer2_to_unix_xid(&ip->meta.gid);

	if (uid == (uid_t)VNOVAL)
		uid = ouid;
	if (gid == (gid_t)VNOVAL)
		gid = ogid;
	/*
	 * To modify the ownership of a file, must possess VADMIN
	 * for that file.
	 */
	error = VOP_ACCESS(vp, VADMIN, cred, td);
	if (error)
		return (error);
	/*
	 * To change the owner of a file, or change the group of a file
	 * to a group of which we are not a member, the caller must
	 * have privilege.
	 */
	if (uid != ouid || (gid != ogid && !groupmember(gid, cred))) {
		error = priv_check_cred(cred, PRIV_VFS_CHOWN);
		if (error)
			return (error);
	}
	imode = ip->meta.mode;
	if ((imode & (S_ISUID | S_ISGID)) && (ouid != uid || ogid != gid))
		if (priv_check_cred(cred, PRIV_VFS_RETAINSUGID) != 0)
			imode &= ~(S_ISUID | S_ISGID);

	hammer2_guid_to_uuid(&uuid_uid, uid);
	hammer2_guid_to_uuid(&uuid_gid, gid);
	if (bcmp(&uuid_uid, &ip->meta.uid, sizeof(uuid_uid)) ||
	    bcmp(&uuid_gid, &ip->meta.gid, sizeof(uuid_gid)) ||
	    ip->meta.mode != imode) {
		hammer2_update_time(&ctime);
		hammer2_inode_modify(ip);
		hammer2_spin_ex(&ip->cluster_spin);
		ip->meta.uid = uuid_uid;
		ip->meta.gid = uuid_gid;
		ip->meta.mode = imode;
		ip->meta.ctime = ctime;
		hammer2_spin_unex(&ip->cluster_spin);
	}

	return (0);
}

static int
hammer2_chmod(struct vnode *vp, mode_t mode, struct ucred *cred, struct thread *td)
{
	hammer2_inode_t *ip = VTOI(vp);
	uint64_t ctime;
	uint32_t imode;
	int error;

	hammer2_mtx_assert_ex(&ip->lock);

	/*
	 * To modify the permissions on a file, must possess VADMIN
	 * for that file.
	 */
	error = VOP_ACCESS(vp, VADMIN, cred, td);
	if (error)
		return (error);
	/*
	 * Privileged processes may set the sticky bit on non-directories,
	 * as well as set the setgid bit on a file with a group that the
	 * process is not a member of.
	 */
	if (vp->v_type != VDIR && (mode & S_ISTXT)) {
		error = priv_check_cred(cred, PRIV_VFS_STICKYFILE);
		if (error)
			return (EFTYPE);
	}
	if (!groupmember(hammer2_to_unix_xid(&ip->meta.gid), cred) &&
	    (mode & S_ISGID)) {
		error = priv_check_cred(cred, PRIV_VFS_SETGID);
		if (error)
			return (error);
	}

	imode = ip->meta.mode;
	imode &= ~ALLPERMS;
	imode |= (mode & ALLPERMS);
	if (ip->meta.mode != imode) {
		hammer2_update_time(&ctime);
		hammer2_inode_modify(ip);
		hammer2_spin_ex(&ip->cluster_spin);
		ip->meta.mode = imode;
		ip->meta.ctime = ctime;
		hammer2_spin_unex(&ip->cluster_spin);
	}

	return (0);
}

static int
hammer2_setattr(struct vop_setattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;
	struct ucred *cred = ap->a_cred;
	struct thread *td = curthread;
	hammer2_inode_t *ip = VTOI(vp);
	uint64_t ctime;
	int error = 0;

	/*
	 * Normally disallow setattr if there is no space, unless we
	 * are in emergency mode (might be needed to chflags -R noschg
	 * files prior to removal).
	 */
	if ((ip->pmp->flags & HAMMER2_PMPF_EMERG) == 0 &&
	    hammer2_vfs_enospace(ip, 0, cred) > 1)
		return (ENOSPC);

	/* Check for unsettable attributes. */
	if (vap->va_type != VNON ||
	    vap->va_nlink != (nlink_t)VNOVAL ||
	    vap->va_fsid != (dev_t)VNOVAL ||
	    vap->va_fileid != (ino_t)VNOVAL ||
	    vap->va_blocksize != (long)VNOVAL ||
	    vap->va_rdev != (dev_t)VNOVAL ||
	    vap->va_bytes != (u_quad_t)VNOVAL ||
	    vap->va_gen != (u_long)VNOVAL)
		return (EINVAL);

	hammer2_trans_init(ip->pmp, 0);
	hammer2_inode_lock(ip, 0);

	if (vap->va_flags != (u_long)VNOVAL) {
		if (vap->va_flags & ~(SF_APPEND | SF_IMMUTABLE | SF_NOUNLINK |
		    UF_APPEND | UF_IMMUTABLE | UF_NOUNLINK | UF_NODUMP)) {
			error = EOPNOTSUPP;
			goto done;
		}
		if (ip->pmp->rdonly) {
			error = EROFS;
			goto done;
		}
		/*
		 * Callers may only modify the file flags on objects they
		 * have VADMIN rights for.
		 */
		error = VOP_ACCESS(vp, VADMIN, cred, td);
		if (error)
			goto done;
		/*
		 * Unprivileged processes and privileged processes in
		 * jail() are not permitted to unset system flags, or
		 * modify flags if any system flags are set.
		 * Privileged non-jail processes may not modify system flags
		 * if securelevel > 0 and any existing system flags are set.
		 */
		if (!priv_check_cred(cred, PRIV_VFS_SYSFLAGS)) {
			if (ip->meta.uflags &
			    (SF_NOUNLINK | SF_IMMUTABLE | SF_APPEND)) {
				error = securelevel_gt(cred, 0);
				if (error)
					goto done;
			}
		} else {
			if (ip->meta.uflags &
			    (SF_NOUNLINK | SF_IMMUTABLE | SF_APPEND) ||
			    ((vap->va_flags ^ ip->meta.uflags) & SF_SETTABLE)) {
				error = EPERM;
				goto done;
			}
		}
		if (ip->meta.uflags != vap->va_flags) {
			hammer2_update_time(&ctime);
			hammer2_inode_modify(ip);
			hammer2_spin_ex(&ip->cluster_spin);
			ip->meta.uflags = vap->va_flags;
			ip->meta.ctime = ctime;
			hammer2_spin_unex(&ip->cluster_spin);
		}
		if (ip->meta.uflags & (IMMUTABLE | APPEND))
			goto done;
	}
	if (ip->meta.uflags & (IMMUTABLE | APPEND)) {
		error = EPERM;
		goto done;
	}

	/* Go through the fields and update iff not VNOVAL. */
	if (vap->va_uid != (uid_t)VNOVAL || vap->va_gid != (gid_t)VNOVAL) {
		if (ip->pmp->rdonly) {
			error = EROFS;
			goto done;
		}
		error = hammer2_chown(vp, vap->va_uid, vap->va_gid, cred, td);
		if (error)
			goto done;
	}

	if (vap->va_size != (u_quad_t)VNOVAL && ip->meta.size != vap->va_size) {
		/*
		 * Disallow write attempts on read-only file systems;
		 * unless the file is a socket, fifo, or a block or
		 * character device resident on the file system.
		 */
		switch (vp->v_type) {
		case VDIR:
			error = EISDIR;
			goto done;
		case VLNK:
		case VREG:
			if (ip->pmp->rdonly) {
				error = EROFS;
				goto done;
			}
			if (vap->va_size == ip->meta.size)
				break;
			if (vap->va_size < ip->meta.size) {
				hammer2_mtx_ex(&ip->truncate_lock);
				hammer2_truncate_file(ip, vap->va_size);
				hammer2_mtx_unlock(&ip->truncate_lock);
			} else {
				hammer2_extend_file(ip, vap->va_size, 0);
			}
			hammer2_update_time(&ctime);
			hammer2_inode_modify(ip);
			ip->meta.ctime = ctime;
			ip->meta.mtime = ctime;
			break;
		default:
			error = EINVAL;
			goto done;
		}
	}

	if (vap->va_atime.tv_sec != (time_t)VNOVAL ||
	    vap->va_mtime.tv_sec != (time_t)VNOVAL ||
	    vap->va_birthtime.tv_sec != (time_t)VNOVAL) {
		if (ip->pmp->rdonly) {
			error = EROFS;
			goto done;
		}
		/*
		 * From utimes(2):
		 * If times is NULL, ... The caller must be the owner of
		 * the file, have permission to write the file, or be the
		 * super-user.
		 * If times is non-NULL, ... The caller must be the owner of
		 * the file or be the super-user.
		 */
		if ((error = VOP_ACCESS(vp, VADMIN, cred, td)) &&
		    ((vap->va_vaflags & VA_UTIMES_NULL) == 0 ||
		    (error = VOP_ACCESS(vp, VWRITE, cred, td))))
			goto done;
		hammer2_inode_modify(ip);
		if (vap->va_atime.tv_sec != (time_t)VNOVAL)
			ip->meta.atime =
			    hammer2_timespec_to_time(&vap->va_atime);
		if (vap->va_mtime.tv_sec != (time_t)VNOVAL)
			ip->meta.mtime =
			    hammer2_timespec_to_time(&vap->va_mtime);
		if (vap->va_birthtime.tv_sec != (time_t)VNOVAL)
			ip->meta.btime =
			    hammer2_timespec_to_time(&vap->va_birthtime);
	}

	if (vap->va_mode != (mode_t)VNOVAL) {
		if (ip->pmp->rdonly) {
			error = EROFS;
			goto done;
		}
		error = hammer2_chmod(vp, vap->va_mode, cred, td);
		if (error)
			goto done;
	}
	KKASSERT(error == 0);
done:
	/*
	 * If a truncation occurred we must call chain_sync() now in order
	 * to trim the related data chains, otherwise a later expansion can
	 * cause havoc.
	 *
	 * If an extend occured that changed the DIRECTDATA state, we must
	 * call inode_chain_sync now in order to prepare the inode's indirect
	 * block table.
	 *
	 * WARNING! This means we are making an adjustment to the inode's
	 * chain outside of sync/fsync, and not just to inode->meta, which
	 * may result in some consistency issues if a crash were to occur
	 * at just the wrong time.
	 */
	if (ip->flags & HAMMER2_INODE_RESIZED)
		hammer2_inode_chain_sync(ip);

	hammer2_inode_unlock(ip);
	hammer2_trans_done(ip->pmp, HAMMER2_TRANS_SIDEQ);

	return (error);
}

static int
hammer2_write_dirent(struct uio *uio, ino_t d_fileno, uint8_t d_type,
    uint16_t d_namlen, const char *d_name, int *errorp)
{
	struct dirent dirent;
	size_t reclen;

	reclen = _GENERIC_DIRLEN(d_namlen);
	if (reclen > uio->uio_resid)
		return (1); /* uio has no space left, end this readdir */

	dirent.d_fileno = d_fileno;
	dirent.d_off = uio->uio_offset + reclen;
	dirent.d_reclen = reclen;
	dirent.d_type = d_type;
	dirent.d_namlen = d_namlen;
	bcopy(d_name, dirent.d_name, d_namlen);
	dirent_terminate(&dirent);

	*errorp = uiomove(&dirent, reclen, uio);

	return (0); /* uio has space left */
}

static int
hammer2_readdir(struct vop_readdir_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	hammer2_xop_readdir_t *xop;
	hammer2_inode_t *ip = VTOI(vp);
	const hammer2_inode_data_t *ripdata;
	hammer2_blockref_t bref;
	hammer2_tid_t inum;
	off_t saveoff = uio->uio_offset;
	off_t *cookies;
	int ncookies, r, dtype;
	int cookie_index = 0, eofflag = 0, error = 0;
	uint16_t namlen;
	const char *dname;

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	/* Setup cookies directory entry cookies if requested. */
	if (ap->a_ncookies) {
		ncookies = uio->uio_resid / 16 + 1;
		if (ncookies > 1024)
			ncookies = 1024;
		cookies = hmalloc(ncookies * sizeof(off_t), M_TEMP, M_WAITOK);
	} else {
		ncookies = -1;
		cookies = NULL;
	}

	hammer2_inode_lock(ip, HAMMER2_RESOLVE_SHARED);

	/*
	 * Handle artificial entries.  To ensure that only positive 64 bit
	 * quantities are returned to userland we always strip off bit 63.
	 * The hash code is designed such that codes 0x0000-0x7FFF are not
	 * used, allowing us to use these codes for articial entries.
	 *
	 * Entry 0 is used for '.' and entry 1 is used for '..'.  Do not
	 * allow '..' to cross the mount point into (e.g.) the super-root.
	 */
	if (saveoff == 0) {
		inum = ip->meta.inum & HAMMER2_DIRHASH_USERMSK;
		r = hammer2_write_dirent(uio, inum, DT_DIR, 1, ".", &error);
		if (r)
			goto done;
		if (cookies)
			cookies[cookie_index] = saveoff;
		++saveoff;
		++cookie_index;
		if (cookie_index == ncookies)
			goto done;
	}
	if (error)
		goto done;

	if (saveoff == 1) {
		inum = ip->meta.inum & HAMMER2_DIRHASH_USERMSK;
		if (ip != ip->pmp->iroot)
			inum = ip->meta.iparent & HAMMER2_DIRHASH_USERMSK;
		r = hammer2_write_dirent(uio, inum, DT_DIR, 2, "..", &error);
		if (r)
			goto done;
		if (cookies)
			cookies[cookie_index] = saveoff;
		++saveoff;
		++cookie_index;
		if (cookie_index == ncookies)
			goto done;
	}
	if (error)
		goto done;

	/* Use XOP for remaining entries. */
	xop = hammer2_xop_alloc(ip, 0);
	xop->lkey = saveoff | HAMMER2_DIRHASH_VISIBLE;
	hammer2_xop_start(&xop->head, &hammer2_readdir_desc);

	for (;;) {
		error = hammer2_xop_collect(&xop->head, 0);
		error = hammer2_error_to_errno(error);
		if (error)
			break;
		if (cookie_index == ncookies)
			break;
		hammer2_cluster_bref(&xop->head.cluster, &bref);

		if (bref.type == HAMMER2_BREF_TYPE_INODE) {
			ripdata = &hammer2_xop_gdata(&xop->head)->ipdata;
			dtype = hammer2_get_dtype(ripdata->meta.type);
			saveoff = bref.key & HAMMER2_DIRHASH_USERMSK;
			r = hammer2_write_dirent(uio,
			    ripdata->meta.inum & HAMMER2_DIRHASH_USERMSK,
			    dtype, ripdata->meta.name_len, ripdata->filename,
			    &error);
			hammer2_xop_pdata(&xop->head);
			if (r)
				break;
			if (cookies)
				cookies[cookie_index] = saveoff;
			++cookie_index;
		} else if (bref.type == HAMMER2_BREF_TYPE_DIRENT) {
			dtype = hammer2_get_dtype(bref.embed.dirent.type);
			saveoff = bref.key & HAMMER2_DIRHASH_USERMSK;
			namlen = bref.embed.dirent.namlen;
			if (namlen <= sizeof(bref.check.buf))
				dname = bref.check.buf;
			else
				dname = hammer2_xop_gdata(&xop->head)->buf;
			r = hammer2_write_dirent(uio, bref.embed.dirent.inum,
			    dtype, namlen, dname, &error);
			if (namlen > sizeof(bref.check.buf))
				hammer2_xop_pdata(&xop->head);
			if (r)
				break;
			if (cookies)
				cookies[cookie_index] = saveoff;
			++cookie_index;
		} else {
			/* XXX chain error */
			hprintf("bad blockref type %d\n", bref.type);
		}
	}
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
	if (error == ENOENT) {
		error = 0;
		eofflag = 1;
		saveoff = (hammer2_key_t)-1;
	} else {
		saveoff = bref.key & HAMMER2_DIRHASH_USERMSK;
	}
done:
	hammer2_inode_unlock(ip);

	if (ap->a_eofflag)
		*ap->a_eofflag = eofflag;
	/*
	 * XXX uio_offset value of 0x7fffffffffffffff known to not work with
	 * some user space libraries on 32 bit platforms.
	 */
	uio->uio_offset = saveoff & ~HAMMER2_DIRHASH_VISIBLE;

	if (error && cookie_index == 0) {
		if (cookies) {
			hfree(cookies, M_TEMP, ncookies * sizeof(off_t));
			*ap->a_ncookies = 0;
			*ap->a_cookies = NULL;
		}
	} else {
		if (cookies) {
			*ap->a_ncookies = cookie_index;
#if __FreeBSD_version >= FREEBSD_READDIR_COOKIES_64
			*ap->a_cookies = cookies;
#else
			KKASSERT(0);
#endif
		}
	}

	return (error);
}

/*
 * Perform read operations on a file or symlink given an unlocked
 * inode and uio.
 *
 * The passed ip is not locked.
 */
static int
hammer2_read_file(hammer2_inode_t *ip, struct uio *uio, int ioflag)
{
	struct vnode *vp = ip->vp;
	struct buf *bp;
	hammer2_off_t isize;
	hammer2_key_t lbase;
	daddr_t lbn;
	size_t n;
	int lblksize, loff, seqcount = 0, error = 0;

	KKASSERT(uio->uio_rw == UIO_READ);
	KKASSERT(uio->uio_offset >= 0);
	KKASSERT(uio->uio_resid >= 0);

	if (ioflag)
		seqcount = ioflag >> IO_SEQSHIFT;

	/*
	 * UIO read loop.
	 *
	 * WARNING! Assumes that the kernel interlocks size changes at the
	 *	    vnode level.
	 */
	hammer2_mtx_sh(&ip->lock);
	hammer2_mtx_sh(&ip->truncate_lock);
	isize = ip->meta.size;
	hammer2_mtx_unlock(&ip->lock);

	while (uio->uio_resid > 0 && (hammer2_off_t)uio->uio_offset < isize) {
		lblksize = hammer2_calc_logical(ip, uio->uio_offset, &lbase,
		    NULL);
		KKASSERT(lblksize <= MAXBSIZE);
		lbn = lbase / lblksize;

		if ((vp->v_mount->mnt_flag & MNT_NOCLUSTERR) == 0)
			error = cluster_read(vp, isize, lbn, lblksize, NOCRED,
			    uio->uio_resid, seqcount, 0, &bp);
		else
			error = bread(vp, lbn, lblksize, NOCRED, &bp);
		KKASSERT(error == 0 || bp == NULL);
		if (error)
			break;

		loff = (int)(uio->uio_offset - lbase);
		n = lblksize - loff;
		if (n > uio->uio_resid)
			n = uio->uio_resid;
		if (n > isize - uio->uio_offset)
			n = (int)(isize - uio->uio_offset);
		error = uiomove(bp->b_data + loff, n, uio);
		if (error) {
			vfs_bio_brelse(bp, ioflag);
			break;
		}
		vfs_bio_brelse(bp, ioflag);
	}
	/* XXX atime not updated */
	hammer2_mtx_unlock(&ip->truncate_lock);

	return (error);
}

static int
hammer2_readlink(struct vop_readlink_args *ap)
{
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	if (vp->v_type != VLNK)
		return (EINVAL);

	return (hammer2_read_file(ip, ap->a_uio, 0));
}

static int
hammer2_read(struct vop_read_args *ap)
{
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	if (vp->v_type == VDIR)
		return (EISDIR);
	if (vp->v_type != VREG)
		return (EINVAL);

	return (hammer2_read_file(ip, ap->a_uio, ap->a_ioflag));
}

/*
 * Write to the file represented by the inode via the logical buffer cache.
 * The inode may represent a regular file or a symlink.
 *
 * The inode must not be locked.
 */
static int
hammer2_write_file(hammer2_inode_t *ip, struct uio *uio, int ioflag,
    struct ucred *cred)
{
	struct vnode *vp = ip->vp;
	struct buf *bp;
	hammer2_key_t old_eof, new_eof, lbase;
	daddr_t lbn;
	size_t n;
	ssize_t resid = uio->uio_resid;
	uint64_t mtime;
	int lblksize, loff, trivial, endofblk;
	int modified = 0, /*seqcount = 0,*/ error = 0;

	KKASSERT(uio->uio_rw == UIO_WRITE);
	KKASSERT(uio->uio_offset >= 0);
	KKASSERT(uio->uio_resid >= 0);

	/*
	if (ioflag)
		seqcount = ioflag >> IO_SEQSHIFT;
	*/

	error = vn_rlimit_fsize(vp, uio, uio->uio_td);
	if (error)
		return (error);

	/*
	 * Setup if append.
	 *
	 * WARNING! Assumes that the kernel interlocks size changes at the
	 *	    vnode level.
	 */
	hammer2_mtx_ex(&ip->lock);
	hammer2_mtx_sh(&ip->truncate_lock);
	if (ioflag & IO_APPEND)
		uio->uio_offset = ip->meta.size;
	if ((ip->meta.uflags & APPEND) &&
	    uio->uio_offset != (off_t)ip->meta.size) {
		hammer2_mtx_unlock(&ip->truncate_lock);
		hammer2_mtx_unlock(&ip->lock);
		return (EPERM);
	}
	old_eof = ip->meta.size;

	/*
	 * Extend the file if necessary.  If the write fails at some point
	 * we will truncate it back down to cover as much as we were able
	 * to write.
	 *
	 * Doing this now makes it easier to calculate buffer sizes in
	 * the loop.
	 */
	if (uio->uio_offset + uio->uio_resid > old_eof) {
		new_eof = uio->uio_offset + uio->uio_resid;
		modified = 1;
		hammer2_extend_file(ip, new_eof, 1);
	} else {
		new_eof = old_eof;
	}
	hammer2_mtx_unlock(&ip->lock);

	/* UIO write loop. */
	while (uio->uio_resid > 0) {
		/*
		 * This nominally tells us how much we can cluster and
		 * what the logical buffer size needs to be.  Currently
		 * we don't try to cluster the write and just handle one
		 * block at a time.
		 */
		lblksize = hammer2_calc_logical(ip, uio->uio_offset, &lbase,
		    NULL);
		KKASSERT(lblksize <= MAXBSIZE);
		lbn = lbase / lblksize;
		loff = (int)(uio->uio_offset - lbase);

		/*
		 * Calculate bytes to copy this transfer and whether the
		 * copy completely covers the buffer or not.
		 */
		trivial = 0;
		n = lblksize - loff;
		if (n > uio->uio_resid) {
			n = uio->uio_resid;
			if (((hammer2_key_t)loff == lbase) &&
			    (uio->uio_offset + n == new_eof))
				trivial = 1;
			endofblk = 0;
		} else {
			if (loff == 0)
				trivial = 1;
			endofblk = 1;
		}
		if (lbase >= new_eof)
			trivial = 1;

		/* Get the buffer. */
		if (uio->uio_segflg == UIO_NOCOPY) {
			/*
			 * Issuing a write with the same data backing the
			 * buffer.  Instantiate the buffer to collect the
			 * backing vm pages, then read-in any missing bits.
			 *
			 * This case is used by vop_stdputpages().
			 */
			bp = getblk(vp, lbn, lblksize, 0, 0, 0);
			if ((bp->b_flags & B_CACHE) == 0) {
				bqrelse(bp);
				error = bread(vp, lbn, lblksize, NOCRED, &bp);
			}
		} else if (trivial) {
			/*
			 * Even though we are entirely overwriting the buffer
			 * we may still have to zero it out to avoid a
			 * mmap/write visibility issue.
			 */
			bp = getblk(vp, lbn, lblksize, 0, 0, 0);
			if ((bp->b_flags & B_CACHE) == 0)
				vfs_bio_clrbuf(bp);
		} else {
			/*
			 * Partial overwrite, read in any missing bits then
			 * replace the portion being written.
			 *
			 * (The strategy code will detect zero-fill physical
			 * blocks for this case).
			 */
			error = bread(vp, lbn, lblksize, NOCRED, &bp);
		}
		if (error)
			break;

		if ((ioflag & (IO_SYNC | IO_INVAL)) == (IO_SYNC | IO_INVAL))
			bp->b_flags |= B_NOCACHE;

		/* Ok, copy the data in. */
		error = uiomove(bp->b_data + loff, n, uio);
		modified = 1;
		if (error && (bp->b_flags & B_CACHE) == 0)
			vfs_bio_clrbuf(bp);
		vfs_bio_set_flags(bp, ioflag);

		/*
		 * WARNING: Pageout daemon will issue UIO_NOCOPY writes
		 *	    with IO_SYNC or IO_ASYNC set.  These writes
		 *	    must be handled as the pageout daemon expects.
		 *
		 * NOTE!    H2 relies on cluster_write() here because it
		 *	    cannot preallocate disk blocks at the logical
		 *	    level due to not knowing what the compression
		 *	    size will be at this time.
		 *
		 *	    We must use cluster_write() here and we depend
		 *	    on the write-behind feature to flush buffers
		 *	    appropriately.  If we let the buffer daemons do
		 *	    it the block allocations will be all over the
		 *	    map.
		 */
		if (ioflag & IO_SYNC) {
			(void)bwrite(bp);
		} else if ((ioflag & IO_DIRECT) && endofblk) {
			/* bp->b_flags |= B_CLUSTEROK; */
			bawrite(bp);
		} else if ((ioflag & IO_ASYNC) || vm_page_count_severe() ||
		    buf_dirty_count_severe()) {
			/* bp->b_flags |= B_CLUSTEROK; */
			bawrite(bp);
		} else if (vp->v_mount->mnt_flag & MNT_NOCLUSTERW) {
			bdwrite(bp);
		} else {
#if 0
			bp->b_flags |= B_CLUSTEROK;
			if (hammer2_dedup_enable == 0) /* XXX2 */
				cluster_write_vn(vp, &ip->clusterw, bp, new_eof,
				    seqcount, 0);
			else
				bdwrite(bp);
#else
			bdwrite(bp);
#endif
		}
	}

	/*
	 * Cleanup.  If we extended the file EOF but failed to write through
	 * the entire write is a failure and we have to back-up.
	 */
	if (error && new_eof != old_eof) {
		hammer2_mtx_unlock(&ip->truncate_lock);
		hammer2_mtx_ex(&ip->lock); /* note lock order */
		hammer2_mtx_ex(&ip->truncate_lock); /* note lock order */
		hammer2_truncate_file(ip, old_eof);
		if (ip->flags & HAMMER2_INODE_MODIFIED) {
			/*
			 * If we successfully wrote any data, and we are not the superuser
			 * we clear the setuid and setgid bits as a precaution against
			 * tampering.
			 */
			if ((ip->meta.mode & (S_ISUID | S_ISGID)) &&
			    resid > uio->uio_resid && cred)
				if (priv_check_cred(cred, PRIV_VFS_RETAINSUGID))
					ip->meta.mode &= ~(S_ISUID | S_ISGID);
			hammer2_inode_chain_sync(ip);
		}
		hammer2_mtx_unlock(&ip->lock);
	} else if (modified) {
		hammer2_update_time(&mtime);
		hammer2_mtx_ex(&ip->lock);
		hammer2_inode_modify(ip);
		/*
		 * If we successfully wrote any data, and we are not the superuser
		 * we clear the setuid and setgid bits as a precaution against
		 * tampering.
		 */
		if ((ip->meta.mode & (S_ISUID | S_ISGID)) &&
		    resid > uio->uio_resid && cred)
			if (priv_check_cred(cred, PRIV_VFS_RETAINSUGID))
				ip->meta.mode &= ~(S_ISUID | S_ISGID);
		ip->meta.mtime = mtime;
		hammer2_mtx_unlock(&ip->lock);
	}
	hammer2_trans_assert_strategy(ip->pmp);
	hammer2_mtx_unlock(&ip->truncate_lock);

	return (error);
}

static int
hammer2_write(struct vop_write_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	hammer2_inode_t *ip = VTOI(vp);
	int error, ioflag = ap->a_ioflag;

	if (vp->v_type != VREG)
		return (EINVAL);

	if (ip->pmp->rdonly || (ip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);

	switch (hammer2_vfs_enospace(ip, uio->uio_resid, ap->a_cred)) {
	case 2:
		return (ENOSPC);
	case 1:
		ioflag |= IO_DIRECT; /* semi-synchronous */
		break;
	default:
		break;
	}

	/*
	 * The transaction interlocks against flush initiations
	 * (note: but will run concurrently with the actual flush).
	 *
	 * To avoid deadlocking against the VM system, we must flag any
	 * transaction related to the buffer cache or other direct
	 * VM page manipulation.
	 */
	if (uio->uio_segflg == UIO_NOCOPY)
		hammer2_trans_init(ip->pmp, HAMMER2_TRANS_BUFCACHE);
	else
		hammer2_trans_init(ip->pmp, 0);
	error = hammer2_write_file(ip, uio, ioflag, ap->a_cred);
	if (uio->uio_segflg == UIO_NOCOPY)
		hammer2_trans_done(ip->pmp,
		    HAMMER2_TRANS_BUFCACHE | HAMMER2_TRANS_SIDEQ);
	else
		hammer2_trans_done(ip->pmp, HAMMER2_TRANS_SIDEQ);

	return (error);
}

/*
 * Truncate the size of a file.  The inode must be locked.
 *
 * We must unconditionally set HAMMER2_INODE_RESIZED to properly
 * ensure that any on-media data beyond the new file EOF has been destroyed.
 *
 * WARNING: nvtruncbuf() can only be safely called without the inode lock
 *	    held due to the way our write thread works.  If the truncation
 *	    occurs in the middle of a buffer, nvtruncbuf() is responsible
 *	    for dirtying that buffer and zeroing out trailing bytes.
 *
 * WARNING! Assumes that the kernel interlocks size changes at the
 *	    vnode level.
 *
 * WARNING! Caller assumes responsibility for removing dead blocks
 *	    if INODE_RESIZED is set.
 */
static void
hammer2_truncate_file(hammer2_inode_t *ip, hammer2_key_t nsize)
{
	hammer2_mtx_assert_locked(&ip->lock);

	hammer2_mtx_unlock(&ip->lock);
	if (ip->vp)
		vtruncbuf(ip->vp, nsize, hammer2_get_logical());
	hammer2_mtx_ex(&ip->lock);
	KKASSERT((ip->flags & HAMMER2_INODE_RESIZED) == 0);
	ip->osize = ip->meta.size;
	ip->meta.size = nsize;
	atomic_set_int(&ip->flags, HAMMER2_INODE_RESIZED);
	hammer2_inode_modify(ip);
	cluster_init_vn(&ip->clusterw);
}

/*
 * Extend the size of a file.  The inode must be locked.
 *
 * Even though the file size is changing, we do not have to set the
 * INODE_RESIZED bit unless the file size crosses the EMBEDDED_BYTES
 * boundary.  When this occurs a hammer2_inode_chain_sync() is required
 * to prepare the inode cluster's indirect block table, otherwise
 * async execution of the strategy code will implode on us.
 *
 * WARNING! Assumes that the kernel interlocks size changes at the
 *	    vnode level.
 *
 * WARNING! Caller assumes responsibility for transitioning out
 *	    of the inode DIRECTDATA mode if INODE_RESIZED is set.
 */
static void
hammer2_extend_file(hammer2_inode_t *ip, hammer2_key_t nsize, int writing)
{
	hammer2_key_t osize;
	struct buf *bp;
	int error;

	hammer2_mtx_assert_locked(&ip->lock);

	KKASSERT((ip->flags & HAMMER2_INODE_RESIZED) == 0);
	osize = ip->meta.size;

	hammer2_inode_modify(ip);
	ip->osize = osize;
	ip->meta.size = nsize;

	/*
	 * We must issue a chain_sync() when the DIRECTDATA state changes
	 * to prevent confusion between the flush code and the in-memory
	 * state.  This is not perfect because we are doing it outside of
	 * a sync/fsync operation, so it might not be fully synchronized
	 * with the meta-data topology flush.
	 *
	 * We must retain and re-dirty the buffer cache buffer containing
	 * the direct data so it can be written to a real block.  It should
	 * not be possible for a bread error to occur since the original data
	 * is extracted from the inode structure directly.
	 */
	if (osize <= HAMMER2_EMBEDDED_BYTES && nsize > HAMMER2_EMBEDDED_BYTES) {
		if (osize) {
			error = bread(ip->vp, 0, hammer2_get_logical(), NOCRED,
			    &bp);
			atomic_set_int(&ip->flags, HAMMER2_INODE_RESIZED);
			hammer2_inode_chain_sync(ip);
			if (error == 0)
				bdwrite(bp);
		} else {
			atomic_set_int(&ip->flags, HAMMER2_INODE_RESIZED);
			hammer2_inode_chain_sync(ip);
		}
	}
	hammer2_mtx_unlock(&ip->lock);
	if (ip->vp)
		vnode_pager_setsize(ip->vp, nsize);
	hammer2_mtx_ex(&ip->lock);
	if (!writing)
		cluster_init_vn(&ip->clusterw);
}

static int
hammer2_bmap_impl(struct vop_bmap_args *ap)
{
	hammer2_xop_bmap_t *xop;
	hammer2_inode_t *ip = VTOI(ap->a_vp);
	hammer2_dev_t *hmp = ip->pmp->pfs_hmps[0];
	int error;

	if (ap->a_bop != NULL)
		*ap->a_bop = &hmp->devvp->v_bufobj;
	if (ap->a_bnp == NULL)
		return (0);
	if (ap->a_runp != NULL)
		*ap->a_runp = 0; /* unsupported */
	if (ap->a_runb != NULL)
		*ap->a_runb = 0; /* unsupported */

	xop = hammer2_xop_alloc(ip, 0);
	xop->lbn = ap->a_bn;
	hammer2_xop_start(&xop->head, &hammer2_bmap_desc);
	error = hammer2_xop_collect(&xop->head, 0);
	error = hammer2_error_to_errno(error);
	if (error) {
		if (error == ENOENT)
			error = 0; /* sparse */
		*ap->a_bnp = -1;
	} else {
		KKASSERT(xop->offset != HAMMER2_OFF_MASK);
		*ap->a_bnp = xop->offset / DEV_BSIZE; /* XXX radix bits */
	}
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);

	return (error);
}

/*
 * HAMMER2 needs to force VFS to invoke logical vnode strategy
 * (not device vnode strategy).
 */
static int
hammer2_bmap(struct vop_bmap_args *ap)
{
	hammer2_inode_t *ip = VTOI(ap->a_vp);

	/*
	 * XXX struct vop_bmap_args in FreeBSD doesn't have ap->a_cmd to
	 * distinct VOP_BMAP for seek from others.
	 */
	if (ip->in_seek)
		return (hammer2_bmap_impl(ap));

	if (ap->a_bop != NULL)
		*ap->a_bop = &ap->a_vp->v_bufobj;
	if (ap->a_bnp != NULL)
		*ap->a_bnp = ap->a_bn;
	if (ap->a_runp != NULL)
		*ap->a_runp = 0;
	if (ap->a_runb != NULL)
		*ap->a_runb = 0;

	return (0);
}

static int
hammer2_nresolve(struct vop_cachedlookup_args *ap)
{
	struct componentname *cnp = ap->a_cnp;
	struct vnode *vp, *dvp = ap->a_dvp;
	struct ucred *cred = cnp->cn_cred;
	hammer2_xop_nresolve_t *xop;
	hammer2_inode_t *ip, *dip = VTOI(dvp);
	int nameiop, ltype, error;

	KKASSERT(ap->a_vpp);
	*ap->a_vpp = NULL;

	nameiop = cnp->cn_nameiop;

	/* FreeBSD needs "." and ".." handling. */
	if (cnp->cn_flags & ISDOTDOT) {
		if ((cnp->cn_flags & ISLASTCN) && nameiop == RENAME)
			return (EINVAL);
		error = vn_vget_ino(dvp, dip->meta.iparent, cnp->cn_lkflags, &vp);
		if (VN_IS_DOOMED(dvp)) {
			if (error == 0)
				vput(vp);
			error = ENOENT;
		}
		if (error) {
			vput(vp);
			return (error);
		}
		*ap->a_vpp = vp;
		if (cnp->cn_flags & MAKEENTRY)
			cache_enter(dvp, vp, cnp);
		return (0);
	} else if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') {
		if ((cnp->cn_flags & ISLASTCN) && nameiop == RENAME)
			return (EISDIR);
		VREF(dvp); /* we want ourself, ie "." */
		/*
		 * When we lookup "." we still can be asked to lock it
		 * differently.
		 */
		ltype = cnp->cn_lkflags & LK_TYPE_MASK;
		if (ltype != VOP_ISLOCKED(dvp)) {
			if (ltype == LK_EXCLUSIVE)
				vn_lock(dvp, LK_UPGRADE | LK_RETRY);
			else /* if (ltype == LK_SHARED) */
				vn_lock(dvp, LK_DOWNGRADE | LK_RETRY);
		}
		*ap->a_vpp = dvp;
		if (cnp->cn_flags & MAKEENTRY)
			cache_enter(dvp, dvp, cnp);
		return (0);
	}

	hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);
	xop = hammer2_xop_alloc(dip, 0);
	hammer2_xop_setname(&xop->head, cnp->cn_nameptr, cnp->cn_namelen);
	hammer2_xop_start(&xop->head, &hammer2_nresolve_desc);
	error = hammer2_xop_collect(&xop->head, 0);
	error = hammer2_error_to_errno(error);
	if (error)
		ip = NULL;
	else
		ip = hammer2_inode_get(dip->pmp, &xop->head, -1, -1);
	hammer2_inode_unlock(dip);

	if (ip) {
		error = hammer2_igetv(ip, LK_EXCLUSIVE, &vp);
		if (error == 0) {
			if (nameiop == DELETE && (cnp->cn_flags & ISLASTCN)) {
				if (cnp->cn_flags & LOCKPARENT)
					ASSERT_VOP_ELOCKED(dvp, __FUNCTION__);
				error = VOP_ACCESS(dvp, VWRITE, cred,
				    curthread);
				if (error) {
					vput(vp);
					hammer2_inode_unlock(ip);
					goto out;
				}
				/*
				 * If directory is "sticky", then user must own
				 * the directory, or the file in it, else she
				 * may not delete it (unless she's root). This
				 * implements append-only directories.
				 */
				if ((dip->meta.mode & S_ISVTX) &&
				    cred->cr_uid != 0 &&
				    cred->cr_uid != hammer2_to_unix_xid(&dip->meta.uid) &&
				    hammer2_to_unix_xid(&ip->meta.uid) != cred->cr_uid) {
					error = EPERM;
					vput(vp);
					hammer2_inode_unlock(ip);
					goto out;
				}
				*ap->a_vpp = vp;
			} else if (nameiop == RENAME &&
			    (cnp->cn_flags & ISLASTCN)) {
				error = VOP_ACCESS(dvp, VWRITE, cred,
				    curthread);
				if (error) {
					vput(vp);
					hammer2_inode_unlock(ip);
					goto out;
				}
				*ap->a_vpp = vp;
			} else {
				*ap->a_vpp = vp;
				if (cnp->cn_flags & MAKEENTRY)
					cache_enter(dvp, vp, cnp);
			}
		}
		hammer2_inode_unlock(ip);
	} else {
		if ((nameiop == CREATE || nameiop == RENAME) &&
		    (cnp->cn_flags & ISLASTCN)) {
			error = VOP_ACCESS(dvp, VWRITE, cred, curthread);
			if (error)
				goto out;
			error = EJUSTRETURN;
		} else {
			if (cnp->cn_flags & MAKEENTRY)
				cache_enter(dvp, NULL, cnp);
			error = ENOENT;
		}
	}
out:
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);

	return (error);
}

static int
hammer2_mknod(struct vop_mknod_args *ap)
{
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp;
	hammer2_inode_t *dip = VTOI(dvp), *nip;
	hammer2_tid_t inum;
	uint64_t mtime;
	int error;

	if (dip->pmp->rdonly || (dip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);

	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	/*
	 * Create the device inode and then create the directory entry.
	 * dip must be locked before nip to avoid deadlock.
	 */
	hammer2_trans_init(dip->pmp, 0);
	inum = hammer2_trans_newinum(dip->pmp);

	hammer2_inode_lock(dip, 0);
	nip = hammer2_inode_create_normal(dip, ap->a_vap, cnp->cn_cred, inum,
	    &error);
	if (error)
		error = hammer2_error_to_errno(error);
	else
		error = hammer2_dirent_create(dip, cnp->cn_nameptr,
		    cnp->cn_namelen, nip->meta.inum, nip->meta.type);
	if (error) {
		if (nip) {
			hammer2_inode_unlink_finisher(nip, NULL);
			hammer2_inode_unlock(nip);
			nip = NULL;
		}
		*ap->a_vpp = NULL;
	} else {
		/*
		 * inode_depend() must occur before the igetv() because
		 * the igetv() can temporarily release the inode lock.
		 */
		hammer2_inode_depend(dip, nip); /* before igetv */
		error = hammer2_igetv(nip, LK_EXCLUSIVE, &vp);
		if (error == 0) {
			*ap->a_vpp = vp;
			hammer2_inode_vhold(nip);
		}
		hammer2_inode_unlock(nip);
	}

	/*
	 * Update dip's mtime.
	 * We can use a shared inode lock and allow the meta.mtime update
	 * SMP race.  hammer2_inode_modify() is MPSAFE w/a shared lock.
	 */
	if (error == 0) {
		/*hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);*/
		hammer2_update_time(&mtime);
		hammer2_inode_modify(dip);
		dip->meta.mtime = mtime;
		dip->meta.ctime = mtime;
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);
	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	return (error);
}

static int
hammer2_mkdir(struct vop_mkdir_args *ap)
{
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp;
	hammer2_inode_t *dip = VTOI(dvp), *nip;
	hammer2_tid_t inum;
	uint64_t mtime;
	int error;

	if (dip->pmp->rdonly || (dip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);

	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	/*
	 * Create the directory inode and then create the directory entry.
	 * dip must be locked before nip to avoid deadlock.
	 */
	hammer2_trans_init(dip->pmp, 0);
	inum = hammer2_trans_newinum(dip->pmp);

	hammer2_inode_lock(dip, 0);
	nip = hammer2_inode_create_normal(dip, ap->a_vap, cnp->cn_cred, inum,
	    &error);
	if (error)
		error = hammer2_error_to_errno(error);
	else
		error = hammer2_dirent_create(dip, cnp->cn_nameptr,
		    cnp->cn_namelen, nip->meta.inum, nip->meta.type);
	if (error) {
		if (nip) {
			hammer2_inode_unlink_finisher(nip, NULL);
			hammer2_inode_unlock(nip);
			nip = NULL;
		}
		*ap->a_vpp = NULL;
	} else {
		/*
		 * inode_depend() must occur before the igetv() because
		 * the igetv() can temporarily release the inode lock.
		 */
		hammer2_inode_depend(dip, nip); /* before igetv */
		error = hammer2_igetv(nip, LK_EXCLUSIVE, &vp);
		if (error == 0) {
			*ap->a_vpp = vp;
			hammer2_inode_vhold(nip);
		}
		hammer2_inode_unlock(nip);
	}

	/*
	 * Update dip's mtime.
	 * We can use a shared inode lock and allow the meta.mtime update
	 * SMP race.  hammer2_inode_modify() is MPSAFE w/a shared lock.
	 */
	if (error == 0) {
		/*hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);*/
		hammer2_update_time(&mtime);
		hammer2_inode_modify(dip);
		dip->meta.mtime = mtime;
		dip->meta.ctime = mtime;
		if (dip->meta.nlinks != 1)
			++dip->meta.nlinks;
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);
	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	return (error);
}

static int
hammer2_create(struct vop_create_args *ap)
{
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp;
	hammer2_inode_t *dip = VTOI(dvp), *nip;
	hammer2_tid_t inum;
	uint64_t mtime;
	int error;

	if (dip->pmp->rdonly || (dip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);

	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	/*
	 * Create the regular file inode and then create the directory entry.
	 * dip must be locked before nip to avoid deadlock.
	 */
	hammer2_trans_init(dip->pmp, 0);
	inum = hammer2_trans_newinum(dip->pmp);

	hammer2_inode_lock(dip, 0);
	nip = hammer2_inode_create_normal(dip, ap->a_vap, cnp->cn_cred, inum,
	    &error);
	if (error)
		error = hammer2_error_to_errno(error);
	else
		error = hammer2_dirent_create(dip, cnp->cn_nameptr,
		    cnp->cn_namelen, nip->meta.inum, nip->meta.type);
	if (error) {
		if (nip) {
			hammer2_inode_unlink_finisher(nip, NULL);
			hammer2_inode_unlock(nip);
			nip = NULL;
		}
		*ap->a_vpp = NULL;
	} else {
		/*
		 * inode_depend() must occur before the igetv() because
		 * the igetv() can temporarily release the inode lock.
		 */
		hammer2_inode_depend(dip, nip); /* before igetv */
		error = hammer2_igetv(nip, LK_EXCLUSIVE, &vp);
		if (error == 0) {
			*ap->a_vpp = vp;
			hammer2_inode_vhold(nip);
		}
		hammer2_inode_unlock(nip);
	}

	/*
	 * Update dip's mtime.
	 * We can use a shared inode lock and allow the meta.mtime update
	 * SMP race.  hammer2_inode_modify() is MPSAFE w/a shared lock.
	 */
	if (error == 0) {
		/*hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);*/
		hammer2_update_time(&mtime);
		hammer2_inode_modify(dip);
		dip->meta.mtime = mtime;
		dip->meta.ctime = mtime;
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);
	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	if (error == 0)
		if ((cnp->cn_flags & MAKEENTRY) != 0)
			cache_enter(dvp, *ap->a_vpp, cnp);
	return (error);
}

static int
hammer2_rmdir(struct vop_rmdir_args *ap)
{
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *dip = VTOI(dvp);
	hammer2_inode_t *ip = VTOI(vp);
	hammer2_xop_unlink_t *xop;
	uint64_t mtime;
	int error;

	/* No rmdir "." please. */
	if (dvp == vp)
		return (EINVAL);

	if ((dip->meta.uflags & APPEND) ||
	    (ip->meta.uflags & (NOUNLINK | IMMUTABLE | APPEND)))
		return (EPERM);

	if (dip->pmp->rdonly)
		return (EROFS);

	/* DragonFly has this disabled, see 568c02c60c. */
	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	hammer2_trans_init(dip->pmp, 0);
	hammer2_inode_lock(dip, 0);

	xop = hammer2_xop_alloc(dip, HAMMER2_XOP_MODIFYING);
	hammer2_xop_setname(&xop->head, cnp->cn_nameptr, cnp->cn_namelen);
	xop->isdir = 1;
	xop->dopermanent = 0;
	hammer2_xop_start(&xop->head, &hammer2_unlink_desc);
	error = hammer2_xop_collect(&xop->head, 0);
	error = hammer2_error_to_errno(error);
	if (error == 0) {
		ip = hammer2_inode_get(dip->pmp, &xop->head, -1, -1);
		hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
		if (ip) {
			/*
			 * Note that ->a_vp isn't provided in DragonFly,
			 * hence vprecycle.
			 */
			KKASSERT(ip->vp == vp);
			hammer2_inode_unlink_finisher(ip, NULL);
			hammer2_inode_depend(dip, ip); /* after modified */
			hammer2_inode_unlock(ip);
		}
	} else {
		hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
	}

	/*
	 * Update dip's mtime.
	 * We can use a shared inode lock and allow the meta.mtime update
	 * SMP race.  hammer2_inode_modify() is MPSAFE w/a shared lock.
	 */
	if (error == 0) {
		/*hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);*/
		hammer2_update_time(&mtime);
		hammer2_inode_modify(dip);
		dip->meta.mtime = mtime;
		dip->meta.ctime = mtime;
		if (dip->meta.nlinks != 1)
			--dip->meta.nlinks;
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);
	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	if (error == 0)
		cache_vop_rmdir(dvp, vp);

	return (error);
}

static int
hammer2_remove(struct vop_remove_args *ap)
{
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp __diagused = ap->a_vp;
	hammer2_inode_t *dip = VTOI(dvp);
	hammer2_inode_t *ip = VTOI(vp);
	hammer2_xop_unlink_t *xop;
	uint64_t mtime;
	int error;

	if ((ip->meta.uflags & (NOUNLINK | IMMUTABLE | APPEND)) ||
	    (dip->meta.uflags & APPEND))
		return (EPERM);

	if (dip->pmp->rdonly)
		return (EROFS);

	/* DragonFly has this disabled, see 568c02c60c. */
	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	hammer2_trans_init(dip->pmp, 0);
	hammer2_inode_lock(dip, 0);

	xop = hammer2_xop_alloc(dip, HAMMER2_XOP_MODIFYING);
	hammer2_xop_setname(&xop->head, cnp->cn_nameptr, cnp->cn_namelen);
	xop->isdir = 0;
	xop->dopermanent = 0;
	hammer2_xop_start(&xop->head, &hammer2_unlink_desc);
	error = hammer2_xop_collect(&xop->head, 0);
	error = hammer2_error_to_errno(error);
	if (error == 0) {
		ip = hammer2_inode_get(dip->pmp, &xop->head, -1, -1);
		hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
		if (ip) {
			/*
			 * Note that ->a_vp isn't provided in DragonFly,
			 * hence vprecycle.
			 */
			KKASSERT(ip->vp == vp);
			hammer2_inode_unlink_finisher(ip, NULL);
			hammer2_inode_depend(dip, ip); /* after modified */
			hammer2_inode_unlock(ip);
		}
	} else {
		hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);
	}

	/*
	 * Update dip's mtime.
	 * We can use a shared inode lock and allow the meta.mtime update
	 * SMP race.  hammer2_inode_modify() is MPSAFE w/a shared lock.
	 */
	if (error == 0) {
		/*hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);*/
		hammer2_update_time(&mtime);
		hammer2_inode_modify(dip);
		dip->meta.mtime = mtime;
		dip->meta.ctime = mtime;
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);
	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	return (error);
}

static int
hammer2_rename(struct vop_rename_args *ap)
{
	struct componentname *fcnp = ap->a_fcnp;
	struct componentname *tcnp = ap->a_tcnp;
	struct vnode *fdvp = ap->a_fdvp;
	struct vnode *fvp = ap->a_fvp;
	struct vnode *tdvp = ap->a_tdvp;
	struct vnode *tvp = ap->a_tvp;
	hammer2_inode_t *fdip = VTOI(fdvp); /* source directory */
	hammer2_inode_t *fip = VTOI(fvp); /* file being renamed */
	hammer2_inode_t *tdip = VTOI(tdvp); /* target directory */
	hammer2_inode_t *tip; /* replaced target during rename or NULL */
	hammer2_inode_t *ip1, *ip2, *ip3, *ip4;
	hammer2_xop_scanlhc_t *sxop;
	hammer2_xop_nrename_t *xop4;
	hammer2_key_t tlhc, lhcbase;
	uint64_t mtime;
	int error, update_fdip = 0, update_tdip = 0;

	KKASSERT(fdvp == tdvp || VOP_ISLOCKED(fdvp) == 0);
	KKASSERT(VOP_ISLOCKED(fvp) == 0);
	KKASSERT(VOP_ISLOCKED(tdvp) == LK_EXCLUSIVE);
	KKASSERT(tvp == NULL || VOP_ISLOCKED(tvp) == LK_EXCLUSIVE);

	/* Check for cross-device rename. */
	if (fdvp->v_mount != fvp->v_mount || fvp->v_mount != tdvp->v_mount ||
	    tdvp->v_mount != fdvp->v_mount ||
	    (tvp && (fvp->v_mount != tvp->v_mount))) {
		error = EXDEV;
		goto abortit;
	}

	if (tvp && ((VTOI(tvp)->meta.uflags & (NOUNLINK | IMMUTABLE | APPEND)) ||
	    (tdip->meta.uflags & APPEND))) {
		error = EPERM;
		goto abortit;
	}

	if (fdip->pmp->rdonly || (fdip->pmp->flags & HAMMER2_PMPF_EMERG)) {
		error = EROFS;
		goto abortit;
	}

	if (hammer2_vfs_enospace(fdip, 0, fcnp->cn_cred) > 1) {
		error = ENOSPC;
		goto abortit;
	}

	/*
	 * Renaming a file to itself has no effect.  The upper layers should
	 * not call us in that case.
	 */
	if (tvp == fvp) {
		error = 0;
		goto abortit;
	}

	error = vn_lock(fvp, LK_EXCLUSIVE);
	if (error)
		goto abortit;
	if ((fip->meta.uflags & (NOUNLINK | IMMUTABLE | APPEND)) ||
	    (fdip->meta.uflags & APPEND)) {
		VOP_UNLOCK(fvp);
		error = EPERM;
		goto abortit;
	}
	if (fdvp != tdvp) {
		error = vn_lock(fdvp, LK_EXCLUSIVE);
		if (error) {
			VOP_UNLOCK(fvp);
			goto abortit;
		}
	}

	/*
	 * If ".." must be changed (ie the directory gets a new
	 * parent) then the source directory must not be in the
	 * directory hierarchy above the target, as this would
	 * orphan everything below the source directory. Also
	 * the user must have write permission in the source so
	 * as to be able to change "..". We must repeat the call
	 * to namei, as the parent directory is unlocked by the
	 * call to checkpath().
	 */
	/* XXX DragonFly does this in VFS. */

	hammer2_trans_init(tdip->pmp, 0);
	hammer2_inode_ref(fip); /* extra ref */

	/*
	 * Lookup the target name to determine if a directory entry
	 * is being overwritten.  We only hold related inode locks
	 * temporarily, the operating system is expected to protect
	 * against rename races.
	 */
	tip = tvp ? VTOI(tvp) : NULL;
	if (tip)
		hammer2_inode_ref(tip); /* extra ref */

	/*
	 * For now try to avoid deadlocks with a simple pointer address
	 * test.  (tip) can be NULL.
	 */
	ip1 = fdip;
	ip2 = tdip;
	ip3 = fip;
	ip4 = tip; /* may be NULL */

	if (fdip > tdip) {
		ip1 = tdip;
		ip2 = fdip;
	}
	if (tip && fip > tip) {
		ip3 = tip;
		ip4 = fip;
	}
	hammer2_inode_lock4(ip1, ip2, ip3, ip4);

	/*
	 * Resolve the collision space for (tdip, tname, tname_len).
	 *
	 * tdip must be held exclusively locked to prevent races since
	 * multiple filenames can end up in the same collision space.
	 */
	tlhc = hammer2_dirhash(tcnp->cn_nameptr, tcnp->cn_namelen);
	lhcbase = tlhc;
	sxop = hammer2_xop_alloc(tdip, HAMMER2_XOP_MODIFYING);
	sxop->lhc = tlhc;
	hammer2_xop_start(&sxop->head, &hammer2_scanlhc_desc);
	while ((error = hammer2_xop_collect(&sxop->head, 0)) == 0) {
		if (tlhc != sxop->head.cluster.focus->bref.key)
			break;
		++tlhc;
	}
	error = hammer2_error_to_errno(error);
	hammer2_xop_retire(&sxop->head, HAMMER2_XOPMASK_VOP);
	if (error) {
		if (error != ENOENT)
			goto done2;
		++tlhc;
		error = 0;
	}
	if ((lhcbase ^ tlhc) & ~HAMMER2_DIRHASH_LOMASK) {
		error = ENOSPC;
		goto done2;
	}

	/*
	 * Ready to go, issue the rename to the backend.  Note that meta-data
	 * updates to the related inodes occur separately from the rename
	 * operation.  ip1|2|3|4 are fdip, fip, tdip, tip in this order.
	 *
	 * NOTE: While it is not necessary to update ip->meta.name*, doing
	 *	 so aids catastrophic recovery and debugging.
	 */
	if (error == 0) {
		xop4 = hammer2_xop_alloc(fdip, HAMMER2_XOP_MODIFYING);
		xop4->lhc = tlhc;
		xop4->ip_key = fip->meta.name_key;
		hammer2_xop_setip2(&xop4->head, fip);
		hammer2_xop_setip3(&xop4->head, tdip);
		if (tip && tip->meta.type == HAMMER2_OBJTYPE_DIRECTORY)
		    hammer2_xop_setip4(&xop4->head, tip);
		hammer2_xop_setname(&xop4->head, fcnp->cn_nameptr,
		    fcnp->cn_namelen);
		hammer2_xop_setname2(&xop4->head, tcnp->cn_nameptr,
		    tcnp->cn_namelen);
		hammer2_xop_start(&xop4->head, &hammer2_nrename_desc);
		error = hammer2_xop_collect(&xop4->head, 0);
		error = hammer2_error_to_errno(error);
		hammer2_xop_retire(&xop4->head, HAMMER2_XOPMASK_VOP);
		if (error == ENOENT)
			error = 0;
		/*
		 * Update inode meta-data.
		 *
		 * WARNING!  The in-memory inode (ip) structure does not
		 *	     maintain a copy of the inode's filename buffer.
		 */
		if (error == 0 &&
		    (fip->meta.name_key & HAMMER2_DIRHASH_VISIBLE)) {
			hammer2_inode_modify(fip);
			fip->meta.name_len = tcnp->cn_namelen;
			fip->meta.name_key = tlhc;
		}
		if (error == 0) {
			hammer2_inode_modify(fip);
			fip->meta.iparent = tdip->meta.inum;
		}
		update_fdip = 1;
		update_tdip = 1;
	}
done2:
	/*
	 * If no error, the backend has replaced the target directory entry.
	 * We must adjust nlinks on the original replace target if it exists.
	 * DragonFly HAMMER2 passes vprecycle here instead of NULL.
	 */
	if (error == 0 && tip)
		hammer2_inode_unlink_finisher(tip, NULL);

	/* Update directory mtimes to represent the something changed. */
	if (update_fdip || update_tdip) {
		hammer2_update_time(&mtime);
		if (update_fdip) {
			hammer2_inode_modify(fdip);
			fdip->meta.mtime = mtime;
			if (fip->meta.type == HAMMER2_OBJTYPE_DIRECTORY &&
			    fdip->meta.nlinks != 1)
				--fdip->meta.nlinks;
		}
		if (update_tdip) {
			hammer2_inode_modify(tdip);
			tdip->meta.mtime = mtime;
			if (fip->meta.type == HAMMER2_OBJTYPE_DIRECTORY &&
			    tdip->meta.nlinks != 1)
				++tdip->meta.nlinks;
		}
	}
	if (tip) {
		hammer2_inode_unlock(tip);
		hammer2_inode_drop(tip);
	}
	hammer2_inode_unlock(fip);
	hammer2_inode_unlock(tdip);
	hammer2_inode_unlock(fdip);
	hammer2_inode_drop(fip);
	hammer2_trans_done(tdip->pmp, HAMMER2_TRANS_SIDEQ);

	cache_vop_rename(fdvp, fvp, tdvp, tvp, fcnp, tcnp);

	if (fdvp != tdvp)
		vput(fdvp);
	else
		vrele(fdvp);
	vput(fvp);
	vput(tdvp);
	if (tvp != NULL) {
		if (tvp != tdvp)
			vput(tvp);
		else /* how ? */
			vrele(tvp);
	}
	return (error);
abortit:
	vrele(fdvp);
	vrele(fvp);
	vput(tdvp);
	if (tvp != NULL) {
		if (tvp != tdvp)
			vput(tvp);
		else /* how ? */
			vrele(tvp);
	}
	return (error);
}

static int
hammer2_link(struct vop_link_args *ap)
{
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_tdvp;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *tdip = VTOI(dvp); /* target directory to create link in */
	hammer2_inode_t *ip = VTOI(vp); /* inode we are hardlinking to */
	uint64_t cmtime;
	int error;

	if (dvp->v_mount != vp->v_mount)
		return (EXDEV);

	if (ip->meta.uflags & (IMMUTABLE | APPEND))
		return (EPERM);

	if (tdip->pmp->rdonly || (tdip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);

	if (hammer2_vfs_enospace(tdip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	/*
	 * ip represents the file being hardlinked.  The file could be a
	 * normal file or a hardlink target if it has already been hardlinked.
	 * (with the new semantics, it will almost always be a hardlink
	 * target).
	 *
	 * Bump nlinks and potentially also create or move the hardlink
	 * target in the parent directory common to (ip) and (tdip).  The
	 * consolidation code can modify ip->cluster.  The returned cluster
	 * is locked.
	 */
	KKASSERT(ip->pmp);
	hammer2_trans_init(ip->pmp, 0);

	/*
	 * Target should be an indexed inode or there's no way we will ever
	 * be able to find it!
	 */
	KKASSERT((ip->meta.name_key & HAMMER2_DIRHASH_VISIBLE) == 0);

	hammer2_inode_lock4(tdip, ip, NULL, NULL);
	hammer2_update_time(&cmtime);

	/*
	 * Create the directory entry and bump nlinks.
	 * Also update ip's ctime.
	 */
	error = hammer2_dirent_create(tdip, cnp->cn_nameptr, cnp->cn_namelen,
	    ip->meta.inum, ip->meta.type);
	hammer2_inode_modify(ip);
	++ip->meta.nlinks;
	ip->meta.ctime = cmtime;

	if (error == 0) {
		/* Update dip's [cm]time. */
		hammer2_inode_modify(tdip);
		tdip->meta.mtime = cmtime;
		tdip->meta.ctime = cmtime;
	}
	hammer2_inode_unlock(ip);
	hammer2_inode_unlock(tdip);

	hammer2_trans_done(ip->pmp, HAMMER2_TRANS_SIDEQ);

	return (error);
}

static int
hammer2_symlink(struct vop_symlink_args *ap)
{
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp;
	struct uio auio;
	struct iovec aiov;
	hammer2_inode_t *dip = VTOI(dvp), *nip;
	hammer2_tid_t inum;
	uint64_t mtime;
	int error;

	if (dip->pmp->rdonly || (dip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);

	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	ap->a_vap->va_type = VLNK; /* enforce type */

	/*
	 * Create the softlink as an inode and then create the directory entry.
	 * dip must be locked before nip to avoid deadlock.
	 */
	hammer2_trans_init(dip->pmp, 0);
	inum = hammer2_trans_newinum(dip->pmp);

	hammer2_inode_lock(dip, 0);
	nip = hammer2_inode_create_normal(dip, ap->a_vap, cnp->cn_cred, inum,
	    &error);
	if (error)
		error = hammer2_error_to_errno(error);
	else
		error = hammer2_dirent_create(dip, cnp->cn_nameptr,
		    cnp->cn_namelen, nip->meta.inum, nip->meta.type);
	if (error) {
		if (nip) {
			hammer2_inode_unlink_finisher(nip, NULL);
			hammer2_inode_unlock(nip);
			nip = NULL;
		}
		*ap->a_vpp = NULL;
		hammer2_inode_unlock(dip);
		hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);
		return (error);
	} else {
		/*
		 * inode_depend() must occur before the igetv() because
		 * the igetv() can temporarily release the inode lock.
		 */
		hammer2_inode_depend(dip, nip); /* before igetv */
		error = hammer2_igetv(nip, LK_EXCLUSIVE, &vp);
		if (error == 0) {
			*ap->a_vpp = vp;
			hammer2_inode_vhold(nip);
		}
		hammer2_inode_unlock(nip);
	}

	/* Build the softlink. */
	if (error == 0) {
		bzero(&auio, sizeof(auio));
		bzero(&aiov, sizeof(aiov));
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = 0;
		auio.uio_resid = strlen(ap->a_target);
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_rw = UIO_WRITE;
		auio.uio_td = curthread;
		aiov.iov_base = __DECONST(void *, ap->a_target);
		aiov.iov_len = strlen(ap->a_target);
		error = hammer2_write_file(nip, &auio, IO_APPEND, NULL);
	}

	/*
	 * Update dip's mtime.
	 * We can use a shared inode lock and allow the meta.mtime update
	 * SMP race.  hammer2_inode_modify() is MPSAFE w/a shared lock.
	 */
	if (error == 0) {
		/*hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);*/
		hammer2_update_time(&mtime);
		hammer2_inode_modify(dip);
		dip->meta.mtime = mtime;
		dip->meta.ctime = mtime;
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);
	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	return (error);
}

static int
hammer2_open(struct vop_open_args *ap)
{
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);

	if (vp->v_type == VCHR || vp->v_type == VBLK)
		return (EOPNOTSUPP);

	/* Files marked append-only must be opened for appending. */
	if ((ip->meta.uflags & APPEND) &&
	    (ap->a_mode & (FWRITE | O_APPEND)) == FWRITE)
		return (EPERM);

	vnode_create_vobject(vp, ip->meta.size, ap->a_td);

	return (0);
}

static void
hammer2_itimes_locked(struct vnode *vp)
{
}

static int
hammer2_close(struct vop_close_args *ap)
{
	struct vnode *vp = ap->a_vp;

	VI_LOCK(vp);
	if (vp->v_usecount > 1)
		hammer2_itimes_locked(vp);
	VI_UNLOCK(vp);

	return (0);
}

static int
hammer2fifo_close(struct vop_close_args *ap)
{
	struct vnode *vp = ap->a_vp;

	VI_LOCK(vp);
	if (vp->v_usecount > 1)
		hammer2_itimes_locked(vp);
	VI_UNLOCK(vp);

	return (fifo_specops.vop_close(ap));
}

static int
hammer2_ioctl(struct vop_ioctl_args *ap)
{
	struct vnode *vp = ap->a_vp;
	int error;

	/*
	 * XXX2 The ioctl implementation is expected to lock vp here,
	 * but fs sync from ioctl causes deadlock loop.
	 */
	error = 0; /* vn_lock(vp, LK_EXCLUSIVE); */
	if (error == 0) {
		error = hammer2_ioctl_impl(vp, ap->a_command, ap->a_data,
		    ap->a_fflag, ap->a_cred);
		/* VOP_UNLOCK(vp); */
	} else {
		error = EBADF;
	}

	return (error);
}

static int
hammer2_print(struct vop_print_args *ap)
{
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);
	hammer2_dev_t *hmp = ip->pmp->pfs_hmps[0];

	vn_printf(hmp->devvp, "\tino %016llx", (long long)ip->meta.inum);
	if (vp->v_type == VFIFO)
		fifo_printinfo(vp);
	printf("\n");

	return (0);
}

static int
hammer2_pathconf(struct vop_pathconf_args *ap)
{
	struct vnode *vp = ap->a_vp;
	int error = 0;

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = INT_MAX;
		break;
	case _PC_NAME_MAX:
		*ap->a_retval = NAME_MAX; /* < HAMMER2_INODE_MAXNAME */
		break;
	case _PC_PIPE_BUF:
		if (vp->v_type == VDIR || vp->v_type == VFIFO)
			*ap->a_retval = PIPE_BUF;
		else
			error = EINVAL;
		break;
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		break;
	case _PC_NO_TRUNC:
		*ap->a_retval = 1;
		break;
	case _PC_MIN_HOLE_SIZE:
		*ap->a_retval = vp->v_mount->mnt_stat.f_iosize;
		break;
	case _PC_PRIO_IO:
		*ap->a_retval = 0;
		break;
	case _PC_SYNC_IO:
		*ap->a_retval = 0;
		break;
	case _PC_ALLOC_SIZE_MIN:
		*ap->a_retval = vp->v_mount->mnt_stat.f_bsize;
		break;
	case _PC_FILESIZEBITS:
		*ap->a_retval = 64;
		break;
	case _PC_REC_INCR_XFER_SIZE:
		*ap->a_retval = vp->v_mount->mnt_stat.f_iosize;
		break;
	case _PC_REC_MAX_XFER_SIZE:
		*ap->a_retval = -1;	/* means ``unlimited'' */
		break;
	case _PC_REC_MIN_XFER_SIZE:
		*ap->a_retval = vp->v_mount->mnt_stat.f_iosize;
		break;
	case _PC_REC_XFER_ALIGN:
		*ap->a_retval = PAGE_SIZE;
		break;
	case _PC_SYMLINK_MAX:
		*ap->a_retval = MAXPATHLEN;
		break;
	default:
		error = vop_stdpathconf(ap);
		break;
	}

	return (error);
}

static int
hammer2_vptofh(struct vop_vptofh_args *ap)
{
	hammer2_inode_t *ip = VTOI(ap->a_vp);
	struct fid *fhp;

#if __FreeBSD_version < FREEBSD_READDIR_COOKIES_64
	return (EOPNOTSUPP);
#endif
	KKASSERT(MAXFIDSZ >= 16);

	fhp = (struct fid *)ap->a_fhp;
	fhp->fid_len = offsetof(struct fid, fid_data[16]);
	((hammer2_tid_t *)fhp->fid_data)[0] = ip->meta.inum;
	((hammer2_tid_t *)fhp->fid_data)[1] = 0;

	return (0);
}

static daddr_t
hammer2_gbp_getblkno(struct vnode *vp, vm_ooffset_t off)
{
	int lblksize = hammer2_get_logical();

	return (off / lblksize);
}

static int
hammer2_gbp_getblksz(struct vnode *vp, daddr_t lbn, long *sz)
{
	int lblksize = hammer2_get_logical();

	*sz = lblksize;

	return (0);
}

static int use_buf_pager = 1;

static int
hammer2_getpages(struct vop_getpages_args *ap)
{
	struct vnode *vp = ap->a_vp;

	if (vp->v_type == VCHR || vp->v_type == VBLK)
		return (EOPNOTSUPP);

	if (use_buf_pager)
		return (vfs_bio_getpages(vp, ap->a_m, ap->a_count,
		    ap->a_rbehind, ap->a_rahead, hammer2_gbp_getblkno,
		    hammer2_gbp_getblksz));

	KKASSERT(0);
	/* panic: vnode_pager_generic_getpages: sector size 65536 too large */
	return (vnode_pager_generic_getpages(vp, ap->a_m, ap->a_count,
	    ap->a_rbehind, ap->a_rahead, NULL, NULL));
}

/*
 * Initialize the vnode associated with a new inode, handle aliased vnodes.
 */
int
hammer2_vinit(struct mount *mp, struct vnode **vpp)
{
	struct vnode *vp = *vpp;
	hammer2_inode_t *ip = VTOI(vp);

	vp->v_type = hammer2_get_vtype(ip->meta.type);

	/* Only unallocated inodes should be of type VNON. */
	if (ip->meta.mode != 0 && vp->v_type == VNON)
		return (EINVAL);

	if (vp->v_type == VFIFO)
		vp->v_op = &hammer2_fifoops;
	KASSERTMSG(vp->v_op, "NULL vnode ops");

	if (ip->meta.inum == 1)
		vp->v_vflag |= VV_ROOT;
	*vpp = vp;

	return (0);
}

struct vop_vector hammer2_vnodeops = {
	.vop_default		= &default_vnodeops,
	.vop_inactive		= hammer2_inactive,
	.vop_reclaim		= hammer2_reclaim,
	.vop_fsync		= hammer2_fsync,
	.vop_fdatasync		= vop_stdfdatasync_buf,
	.vop_access		= hammer2_access,
	.vop_getattr		= hammer2_getattr,
	.vop_setattr		= hammer2_setattr,
	.vop_readdir		= hammer2_readdir,
	.vop_readlink		= hammer2_readlink,
	.vop_read		= hammer2_read,
	.vop_write		= hammer2_write,
	.vop_bmap		= hammer2_bmap,
	.vop_cachedlookup	= hammer2_nresolve,
	.vop_lookup		= vfs_cache_lookup,
	.vop_mknod		= hammer2_mknod,
	.vop_mkdir		= hammer2_mkdir,
	.vop_create		= hammer2_create,
	.vop_rmdir		= hammer2_rmdir,
	.vop_remove		= hammer2_remove,
	.vop_rename		= hammer2_rename,
	.vop_link		= hammer2_link,
	.vop_symlink		= hammer2_symlink,
	.vop_open		= hammer2_open,
	.vop_close		= hammer2_close,
	.vop_ioctl		= hammer2_ioctl,
	.vop_print		= hammer2_print,
	.vop_pathconf		= hammer2_pathconf,
	.vop_vptofh		= hammer2_vptofh,
	.vop_getpages		= hammer2_getpages,
	.vop_strategy		= hammer2_strategy,
};
VFS_VOP_VECTOR_REGISTER(hammer2_vnodeops);

struct vop_vector hammer2_fifoops = {
	.vop_default		= &fifo_specops,
	.vop_inactive		= hammer2_inactive,
	.vop_reclaim		= hammer2_reclaim,
	.vop_fsync		= hammer2_fsync,
	.vop_access		= hammer2_access,
	.vop_getattr		= hammer2_getattr,
	.vop_setattr		= hammer2_setattr,
	.vop_read		= VOP_PANIC,
	.vop_write		= VOP_PANIC,
	.vop_close		= hammer2fifo_close,
	.vop_print		= hammer2_print,
	.vop_pathconf		= hammer2_pathconf,
	.vop_vptofh		= hammer2_vptofh,
};
VFS_VOP_VECTOR_REGISTER(hammer2_fifoops);
