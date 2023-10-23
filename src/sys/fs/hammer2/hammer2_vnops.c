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

#include <sys/dirent.h>
#include <sys/namei.h>
#include <sys/uio.h>
#include <sys/unistd.h>

#include <vm/vnode_pager.h>

static int
hammer2_inactive(struct vop_inactive_args *ap)
{
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *ip = VTOI(vp);
	hammer2_key_t lbase;
	int nblksize;

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
		nblksize = hammer2_calc_logical(ip, 0, &lbase, NULL);
		vtruncbuf(vp, 0, nblksize);

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
		hprintf("inum %016jx unlinked but not disposed\n",
		    (intmax_t)ip->meta.inum);
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
	/*
	 * Flush all dirty buffers associated with a vnode.
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
	uid_t uid;
	gid_t gid;
	mode_t mode;

	/*
	 * Disallow write attempts unless the file is a socket,
	 * fifo resident on the filesystem.
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

	uid = hammer2_to_unix_xid(&ip->meta.uid);
	gid = hammer2_to_unix_xid(&ip->meta.gid);
	mode = ip->meta.mode;

	return (vaccess(vp->v_type, mode, uid, gid, ap->a_accmode, ap->a_cred));
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
	vap->va_mode = ip->meta.mode;
	vap->va_nlink = ip->meta.nlinks;
	vap->va_uid = hammer2_to_unix_xid(&ip->meta.uid);
	vap->va_gid = hammer2_to_unix_xid(&ip->meta.gid);
	vap->va_rdev = NODEV;
	vap->va_size = ip->meta.size;
	vap->va_flags = ip->meta.uflags;
	hammer2_time_to_timespec(ip->meta.ctime, &vap->va_ctime);
	hammer2_time_to_timespec(ip->meta.mtime, &vap->va_mtime);
	hammer2_time_to_timespec(ip->meta.mtime, &vap->va_atime);
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
hammer2_setattr(struct vop_setattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct vattr *vap = ap->a_vap;

	if (vap->va_type != VNON
	    || vap->va_nlink != (nlink_t)VNOVAL
	    || vap->va_fsid != (dev_t)VNOVAL
	    || vap->va_fileid != (ino_t)VNOVAL
	    || vap->va_blocksize != (long)VNOVAL
	    || vap->va_rdev != (dev_t)VNOVAL
	    || vap->va_bytes != (u_quad_t)VNOVAL
	    || vap->va_gen != (u_long)VNOVAL)
		return (EINVAL);

	if (vap->va_flags != (u_long)VNOVAL
	    || vap->va_uid != (uid_t)VNOVAL
	    || vap->va_gid != (gid_t)VNOVAL
	    || vap->va_atime.tv_sec != (time_t)VNOVAL
	    || vap->va_mtime.tv_sec != (time_t)VNOVAL
	    || vap->va_mode != (mode_t)VNOVAL)
		return (EOPNOTSUPP);

	if (vap->va_size != (u_quad_t)VNOVAL) {
		switch (vp->v_type) {
		case VDIR:
			return (EISDIR);
		case VLNK:
		case VREG:
			if (vp->v_mount->mnt_flag & MNT_RDONLY)
				return (EROFS);
			return (0); /* implicit-fallthrough */
		case VCHR:
		case VBLK:
		case VSOCK:
		case VFIFO:
			return (0);
		default:
			return (EINVAL);
		}
	}

	return (EINVAL);
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
		cookies = malloc(ncookies * sizeof(off_t), M_TEMP, M_WAITOK);
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
			free(cookies, M_TEMP);
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
 */
static int
hammer2_read_file(hammer2_inode_t *ip, struct uio *uio, int ioflag)
{
	struct vnode *vp = ip->vp;
	struct buf *bp;
	hammer2_off_t isize = ip->meta.size;
	hammer2_key_t lbase;
	daddr_t lbn;
	size_t n;
	int lblksize, loff, seqcount = 0, error = 0;

	if (ioflag)
		seqcount = ioflag >> IO_SEQSHIFT;

	while (uio->uio_resid > 0 && (hammer2_off_t)uio->uio_offset < isize) {
		lblksize = hammer2_calc_logical(ip, uio->uio_offset, &lbase,
		    NULL);
		lbn = lbase / lblksize;
		bp = NULL;

		if ((hammer2_off_t)(lbn + 1) * lblksize >= isize)
			error = bread(ip->vp, lbn, lblksize, NOCRED, &bp);
		else if ((vp->v_mount->mnt_flag & MNT_NOCLUSTERR) == 0)
			error = cluster_read(vp, isize, lbn, lblksize, NOCRED,
			    uio->uio_resid, seqcount, 0, &bp);
		else
			error = bread(ip->vp, lbn, lblksize, NOCRED, &bp);
		KKASSERT(error == 0 || bp == NULL);
		if (error) {
			bp = NULL;
			break;
		}

		loff = (int)(uio->uio_offset - lbase);
		n = lblksize - loff;
		if (n > uio->uio_resid)
			n = uio->uio_resid;
		if (n > isize - uio->uio_offset)
			n = (int)(isize - uio->uio_offset);
		error = uiomove(bp->b_data + loff, n, uio);
		if (error) {
			brelse(bp);
			bp = NULL;
			break;
		}
		vfs_bio_brelse(bp, ioflag);
	}

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

#if 0
static int
hammer2_write(struct vop_write_args *ap)
{
	return (EOPNOTSUPP);
}
#endif

static int
hammer2_bmap(struct vop_bmap_args *ap)
{
	hammer2_xop_bmap_t *xop;
	hammer2_dev_t *hmp;
	hammer2_inode_t *ip = VTOI(ap->a_vp);
	hammer2_volume_t *vol;
	int error;

	hmp = ip->pmp->pfs_hmps[0];
	if (ap->a_bop != NULL)
		*ap->a_bop = &hmp->devvp->v_bufobj;
	if (ap->a_bnp == NULL)
		return (0);
	if (ap->a_runp != NULL)
		*ap->a_runp = 0; /* unsupported */
	if (ap->a_runb != NULL)
		*ap->a_runb = 0; /* unsupported */

	/* Initialize with error or nonexistent case first. */
	if (ap->a_bnp != NULL)
		*ap->a_bnp = -1;

	xop = hammer2_xop_alloc(ip, 0);
	xop->lbn = ap->a_bn; /* logical block number */
	hammer2_xop_start(&xop->head, &hammer2_bmap_desc);

	error = hammer2_xop_collect(&xop->head, 0);
	error = hammer2_error_to_errno(error);
	if (error) {
		/* No physical block assigned. */
		if (error == ENOENT)
			error = 0;
		goto done;
	}

	if (xop->offset != HAMMER2_OFF_MASK) {
		/* Get volume from the result offset. */
		KKASSERT((xop->offset & HAMMER2_OFF_MASK_RADIX) == 0);
		vol = hammer2_get_volume(hmp, xop->offset);
		KKASSERT(vol);
		KKASSERT(vol->dev);
		KKASSERT(vol->dev->devvp);

		/* Return physical block number within devvp. */
		if (ap->a_bnp != NULL)
			*ap->a_bnp = (xop->offset - vol->offset) / DEV_BSIZE;
	}
done:
	hammer2_xop_retire(&xop->head, HAMMER2_XOPMASK_VOP);

	return (error);
}

static int
hammer2_nresolve(struct vop_cachedlookup_args *ap)
{
	struct vnode *vp, *dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
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

	xop = hammer2_xop_alloc(dip, 0);
	hammer2_xop_setname(&xop->head, cnp->cn_nameptr, cnp->cn_namelen);

	hammer2_inode_lock(dip, HAMMER2_RESOLVE_SHARED);
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
	hammer2_inode_t *dip, *nip;
	hammer2_tid_t inum;
	uint64_t mtime;
	int error;

	dip = VTOI(dvp);
	if (dip->pmp->rdonly || (dip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);
	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	hammer2_trans_init(dip->pmp, 0);

	/*
	 * Create the device inode and then create the directory entry.
	 * dip must be locked before nip to avoid deadlock.
	 */
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
	hammer2_inode_t *dip, *nip;
	hammer2_tid_t inum;
	uint64_t mtime;
	int error;

	dip = VTOI(dvp);
	if (dip->pmp->rdonly || (dip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);
	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	hammer2_trans_init(dip->pmp, 0);

	/*
	 * Create the directory inode and then create the directory entry.
	 * dip must be locked before nip to avoid deadlock.
	 */
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
	hammer2_inode_t *dip, *nip;
	hammer2_tid_t inum;
	uint64_t mtime;
	int error;

	dip = VTOI(dvp);
	if (dip->pmp->rdonly || (dip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);
	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	hammer2_trans_init(dip->pmp, 0);

	/*
	 * Create the regular file inode and then create the directory entry.
	 * dip must be locked before nip to avoid deadlock.
	 */
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
	hammer2_inode_t *dip, *ip;
	hammer2_xop_unlink_t *xop;
	uint64_t mtime;
	int error;

	dip = VTOI(dvp);
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

	/*
	 * Collect the real inode and adjust nlinks, destroy the real
	 * inode if nlinks transitions to 0 and it was the real inode
	 * (else it has already been removed).
	 */
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
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);

	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	if (error == 0) {
		cache_purge(dvp);
		cache_purge(vp);
	}
	return (error);
}

static int
hammer2_remove(struct vop_remove_args *ap)
{
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_dvp;
	struct vnode *vp __diagused = ap->a_vp;
	hammer2_inode_t *dip, *ip;
	hammer2_xop_unlink_t *xop;
	uint64_t mtime;
	int error;

	dip = VTOI(dvp);
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

	/*
	 * Collect the real inode and adjust nlinks, destroy the real
	 * inode if nlinks transitions to 0 and it was the real inode
	 * (else it has already been removed).
	 */
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
		/*hammer2_inode_unlock(dip);*/
	}
	hammer2_inode_unlock(dip);

	hammer2_trans_done(dip->pmp, HAMMER2_TRANS_SIDEQ);

	return (error);
}

#if 0
static int
hammer2_rename(struct vop_rename_args *ap)
{
	return (EOPNOTSUPP);
}
#endif

static int
hammer2_link(struct vop_link_args *ap)
{
	struct componentname *cnp = ap->a_cnp;
	struct vnode *dvp = ap->a_tdvp;
	struct vnode *vp = ap->a_vp;
	hammer2_inode_t *tdip; /* target directory to create link in */
	hammer2_inode_t *ip; /* inode we are hardlinking to */
	uint64_t cmtime;
	int error;

	if (dvp->v_mount != vp->v_mount)
		return (EXDEV);

	tdip = VTOI(dvp);
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
	ip = VTOI(vp);
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
	hammer2_inode_t *dip, *nip;
	hammer2_tid_t inum;
	uint64_t mtime;
	int error;

	return (EOPNOTSUPP); /* XXX */

	dip = VTOI(dvp);
	if (dip->pmp->rdonly || (dip->pmp->flags & HAMMER2_PMPF_EMERG))
		return (EROFS);
	if (hammer2_vfs_enospace(dip, 0, cnp->cn_cred) > 1)
		return (ENOSPC);

	ap->a_vap->va_type = VLNK; /* enforce type */

	hammer2_trans_init(dip->pmp, 0);

	/*
	 * Create the softlink as an inode and then create the directory entry.
	 * dip must be locked before nip to avoid deadlock.
	 */
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
#if 0
		size_t bytes;
		struct uio auio;
		struct iovec aiov;

		bytes = strlen(ap->a_target);
		bzero(&auio, sizeof(auio));
		bzero(&aiov, sizeof(aiov));
		auio.uio_iov = &aiov;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_rw = UIO_WRITE;
		auio.uio_resid = bytes;
		auio.uio_iovcnt = 1;
		auio.uio_td = curthread;
		aiov.iov_base = ap->a_target;
		aiov.iov_len = bytes;
		error = hammer2_write_file(nip, &auio, IO_APPEND, 0);
		/* XXX handle error */
		error = 0;
#endif
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
	hammer2_inode_t *ip = VTOI(vp);
	int error;

	/*
	 * XXX2 The ioctl implementation is expected to lock vp here,
	 * but fs sync from ioctl causes deadlock loop.
	 */
	error = 0; /* vn_lock(vp, LK_EXCLUSIVE); */
	if (error == 0) {
		error = hammer2_ioctl_impl(ip, ap->a_command, ap->a_data,
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

	vn_printf(hmp->devvp, "\tino %ju", (uintmax_t)ip->meta.inum);
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
		*ap->a_retval = HAMMER2_INODE_MAXNAME;
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
		*ap->a_retval = 0;
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
		*ap->a_retval = vp->v_mount->mnt_stat.f_bsize;
		break;
	case _PC_SYMLINK_MAX:
		*ap->a_retval = HAMMER2_INODE_MAXNAME;
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

struct vop_vector hammer2_vnodeops = {
	.vop_default		= &default_vnodeops,
	.vop_inactive		= hammer2_inactive,
	.vop_reclaim		= hammer2_reclaim,
	.vop_fsync		= hammer2_fsync,
	//.vop_fdatasync	= vop_stdfdatasync_buf,
	.vop_access		= hammer2_access,
	.vop_getattr		= hammer2_getattr,
	.vop_setattr		= hammer2_setattr,
	.vop_readdir		= hammer2_readdir,
	.vop_readlink		= hammer2_readlink,
	.vop_read		= hammer2_read,
	.vop_write		= VOP_EOPNOTSUPP,
	.vop_bmap		= hammer2_bmap,
	.vop_cachedlookup	= hammer2_nresolve,
	.vop_lookup		= vfs_cache_lookup,
	.vop_mknod		= hammer2_mknod,
	.vop_mkdir		= hammer2_mkdir,
	.vop_create		= hammer2_create,
	.vop_rmdir		= hammer2_rmdir,
	.vop_remove		= hammer2_remove,
	.vop_rename		= VOP_EOPNOTSUPP,
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
