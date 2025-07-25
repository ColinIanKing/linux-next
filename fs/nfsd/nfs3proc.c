// SPDX-License-Identifier: GPL-2.0
/*
 * Process version 3 NFS requests.
 *
 * Copyright (C) 1996, 1997, 1998 Olaf Kirch <okir@monad.swb.de>
 */

#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/magic.h>
#include <linux/namei.h>

#include "cache.h"
#include "xdr3.h"
#include "vfs.h"
#include "filecache.h"
#include "trace.h"

#define NFSDDBG_FACILITY		NFSDDBG_PROC

static int	nfs3_ftypes[] = {
	0,			/* NF3NON */
	S_IFREG,		/* NF3REG */
	S_IFDIR,		/* NF3DIR */
	S_IFBLK,		/* NF3BLK */
	S_IFCHR,		/* NF3CHR */
	S_IFLNK,		/* NF3LNK */
	S_IFSOCK,		/* NF3SOCK */
	S_IFIFO,		/* NF3FIFO */
};

static __be32 nfsd3_map_status(__be32 status)
{
	switch (status) {
	case nfs_ok:
		break;
	case nfserr_nofilehandle:
		status = nfserr_badhandle;
		break;
	case nfserr_wrongsec:
	case nfserr_file_open:
		status = nfserr_acces;
		break;
	case nfserr_symlink_not_dir:
		status = nfserr_notdir;
		break;
	case nfserr_symlink:
	case nfserr_wrong_type:
		status = nfserr_inval;
		break;
	}
	return status;
}

/*
 * NULL call.
 */
static __be32
nfsd3_proc_null(struct svc_rqst *rqstp)
{
	return rpc_success;
}

/*
 * Get a file's attributes
 */
static __be32
nfsd3_proc_getattr(struct svc_rqst *rqstp)
{
	struct nfsd_fhandle *argp = rqstp->rq_argp;
	struct nfsd3_attrstat *resp = rqstp->rq_resp;

	trace_nfsd_vfs_getattr(rqstp, &argp->fh);

	fh_copy(&resp->fh, &argp->fh);
	resp->status = fh_verify(rqstp, &resp->fh, 0,
				 NFSD_MAY_NOP | NFSD_MAY_BYPASS_GSS_ON_ROOT);
	if (resp->status != nfs_ok)
		goto out;

	resp->status = fh_getattr(&resp->fh, &resp->stat);
out:
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Set a file's attributes
 */
static __be32
nfsd3_proc_setattr(struct svc_rqst *rqstp)
{
	struct nfsd3_sattrargs *argp = rqstp->rq_argp;
	struct nfsd3_attrstat *resp = rqstp->rq_resp;
	struct nfsd_attrs attrs = {
		.na_iattr	= &argp->attrs,
	};
	const struct timespec64 *guardtime = NULL;

	dprintk("nfsd: SETATTR(3)  %s\n",
				SVCFH_fmt(&argp->fh));

	fh_copy(&resp->fh, &argp->fh);
	if (argp->check_guard)
		guardtime = &argp->guardtime;
	resp->status = nfsd_setattr(rqstp, &resp->fh, &attrs, guardtime);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Look up a path name component
 */
static __be32
nfsd3_proc_lookup(struct svc_rqst *rqstp)
{
	struct nfsd3_diropargs *argp = rqstp->rq_argp;
	struct nfsd3_diropres  *resp = rqstp->rq_resp;

	dprintk("nfsd: LOOKUP(3)   %s %.*s\n",
				SVCFH_fmt(&argp->fh),
				argp->len,
				argp->name);

	fh_copy(&resp->dirfh, &argp->fh);
	fh_init(&resp->fh, NFS3_FHSIZE);

	resp->status = nfsd_lookup(rqstp, &resp->dirfh,
				   argp->name, argp->len,
				   &resp->fh);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Check file access
 */
static __be32
nfsd3_proc_access(struct svc_rqst *rqstp)
{
	struct nfsd3_accessargs *argp = rqstp->rq_argp;
	struct nfsd3_accessres *resp = rqstp->rq_resp;

	dprintk("nfsd: ACCESS(3)   %s 0x%x\n",
				SVCFH_fmt(&argp->fh),
				argp->access);

	fh_copy(&resp->fh, &argp->fh);
	resp->access = argp->access;
	resp->status = nfsd_access(rqstp, &resp->fh, &resp->access, NULL);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Read a symlink.
 */
static __be32
nfsd3_proc_readlink(struct svc_rqst *rqstp)
{
	struct nfsd_fhandle *argp = rqstp->rq_argp;
	struct nfsd3_readlinkres *resp = rqstp->rq_resp;

	dprintk("nfsd: READLINK(3) %s\n", SVCFH_fmt(&argp->fh));

	/* Read the symlink. */
	fh_copy(&resp->fh, &argp->fh);
	resp->len = NFS3_MAXPATHLEN;
	resp->pages = rqstp->rq_next_page++;
	resp->status = nfsd_readlink(rqstp, &resp->fh,
				     page_address(*resp->pages), &resp->len);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Read a portion of a file.
 */
static __be32
nfsd3_proc_read(struct svc_rqst *rqstp)
{
	struct nfsd3_readargs *argp = rqstp->rq_argp;
	struct nfsd3_readres *resp = rqstp->rq_resp;

	dprintk("nfsd: READ(3) %s %lu bytes at %Lu\n",
				SVCFH_fmt(&argp->fh),
				(unsigned long) argp->count,
				(unsigned long long) argp->offset);

	argp->count = min_t(u32, argp->count, svc_max_payload(rqstp));
	argp->count = min_t(u32, argp->count, rqstp->rq_res.buflen);
	if (argp->offset > (u64)OFFSET_MAX)
		argp->offset = (u64)OFFSET_MAX;
	if (argp->offset + argp->count > (u64)OFFSET_MAX)
		argp->count = (u64)OFFSET_MAX - argp->offset;

	resp->pages = rqstp->rq_next_page;

	/* Obtain buffer pointer for payload.
	 * 1 (status) + 22 (post_op_attr) + 1 (count) + 1 (eof)
	 * + 1 (xdr opaque byte count) = 26
	 */
	resp->count = argp->count;
	svc_reserve_auth(rqstp, ((1 + NFS3_POST_OP_ATTR_WORDS + 3) << 2) +
			 resp->count + 4);

	fh_copy(&resp->fh, &argp->fh);
	resp->status = nfsd_read(rqstp, &resp->fh, argp->offset,
				 &resp->count, &resp->eof);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Write data to a file
 */
static __be32
nfsd3_proc_write(struct svc_rqst *rqstp)
{
	struct nfsd3_writeargs *argp = rqstp->rq_argp;
	struct nfsd3_writeres *resp = rqstp->rq_resp;
	unsigned long cnt = argp->len;

	dprintk("nfsd: WRITE(3)    %s %d bytes at %Lu%s\n",
				SVCFH_fmt(&argp->fh),
				argp->len,
				(unsigned long long) argp->offset,
				argp->stable ? " stable" : "");

	resp->status = nfserr_fbig;
	if (argp->offset > (u64)OFFSET_MAX ||
	    argp->offset + argp->len > (u64)OFFSET_MAX)
		return rpc_success;

	fh_copy(&resp->fh, &argp->fh);
	resp->committed = argp->stable;
	resp->status = nfsd_write(rqstp, &resp->fh, argp->offset,
				  &argp->payload, &cnt,
				  resp->committed, resp->verf);
	resp->count = cnt;
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Implement NFSv3's unchecked, guarded, and exclusive CREATE
 * semantics for regular files. Except for the created file,
 * this operation is stateless on the server.
 *
 * Upon return, caller must release @fhp and @resfhp.
 */
static __be32
nfsd3_create_file(struct svc_rqst *rqstp, struct svc_fh *fhp,
		  struct svc_fh *resfhp, struct nfsd3_createargs *argp)
{
	struct iattr *iap = &argp->attrs;
	struct dentry *parent, *child;
	struct nfsd_attrs attrs = {
		.na_iattr	= iap,
	};
	__u32 v_mtime, v_atime;
	struct inode *inode;
	__be32 status;
	int host_err;

	trace_nfsd_vfs_create(rqstp, fhp, S_IFREG, argp->name, argp->len);

	if (isdotent(argp->name, argp->len))
		return nfserr_exist;
	if (!(iap->ia_valid & ATTR_MODE))
		iap->ia_mode = 0;

	status = fh_verify(rqstp, fhp, S_IFDIR, NFSD_MAY_EXEC);
	if (status != nfs_ok)
		return status;

	parent = fhp->fh_dentry;
	inode = d_inode(parent);

	host_err = fh_want_write(fhp);
	if (host_err)
		return nfserrno(host_err);

	inode_lock_nested(inode, I_MUTEX_PARENT);

	child = lookup_one(&nop_mnt_idmap,
			   &QSTR_LEN(argp->name, argp->len),
			   parent);
	if (IS_ERR(child)) {
		status = nfserrno(PTR_ERR(child));
		goto out;
	}

	if (d_really_is_negative(child)) {
		status = fh_verify(rqstp, fhp, S_IFDIR, NFSD_MAY_CREATE);
		if (status != nfs_ok)
			goto out;
	}

	status = fh_compose(resfhp, fhp->fh_export, child, fhp);
	if (status != nfs_ok)
		goto out;

	v_mtime = 0;
	v_atime = 0;
	if (argp->createmode == NFS3_CREATE_EXCLUSIVE) {
		u32 *verifier = (u32 *)argp->verf;

		/*
		 * Solaris 7 gets confused (bugid 4218508) if these have
		 * the high bit set, as do xfs filesystems without the
		 * "bigtime" feature. So just clear the high bits.
		 */
		v_mtime = verifier[0] & 0x7fffffff;
		v_atime = verifier[1] & 0x7fffffff;
	}

	if (d_really_is_positive(child)) {
		status = nfs_ok;

		switch (argp->createmode) {
		case NFS3_CREATE_UNCHECKED:
			if (!d_is_reg(child))
				break;
			iap->ia_valid &= ATTR_SIZE;
			goto set_attr;
		case NFS3_CREATE_GUARDED:
			status = nfserr_exist;
			break;
		case NFS3_CREATE_EXCLUSIVE:
			if (inode_get_mtime_sec(d_inode(child)) == v_mtime &&
			    inode_get_atime_sec(d_inode(child)) == v_atime &&
			    d_inode(child)->i_size == 0) {
				break;
			}
			status = nfserr_exist;
		}
		goto out;
	}

	if (!IS_POSIXACL(inode))
		iap->ia_mode &= ~current_umask();

	status = fh_fill_pre_attrs(fhp);
	if (status != nfs_ok)
		goto out;
	host_err = vfs_create(&nop_mnt_idmap, inode, child, iap->ia_mode, true);
	if (host_err < 0) {
		status = nfserrno(host_err);
		goto out;
	}
	fh_fill_post_attrs(fhp);

	/* A newly created file already has a file size of zero. */
	if ((iap->ia_valid & ATTR_SIZE) && (iap->ia_size == 0))
		iap->ia_valid &= ~ATTR_SIZE;
	if (argp->createmode == NFS3_CREATE_EXCLUSIVE) {
		iap->ia_valid = ATTR_MTIME | ATTR_ATIME |
				ATTR_MTIME_SET | ATTR_ATIME_SET;
		iap->ia_mtime.tv_sec = v_mtime;
		iap->ia_atime.tv_sec = v_atime;
		iap->ia_mtime.tv_nsec = 0;
		iap->ia_atime.tv_nsec = 0;
	}

set_attr:
	status = nfsd_create_setattr(rqstp, fhp, resfhp, &attrs);

out:
	inode_unlock(inode);
	if (child && !IS_ERR(child))
		dput(child);
	fh_drop_write(fhp);
	return status;
}

static __be32
nfsd3_proc_create(struct svc_rqst *rqstp)
{
	struct nfsd3_createargs *argp = rqstp->rq_argp;
	struct nfsd3_diropres *resp = rqstp->rq_resp;
	svc_fh *dirfhp, *newfhp;

	dirfhp = fh_copy(&resp->dirfh, &argp->fh);
	newfhp = fh_init(&resp->fh, NFS3_FHSIZE);

	resp->status = nfsd3_create_file(rqstp, dirfhp, newfhp, argp);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Make directory. This operation is not idempotent.
 */
static __be32
nfsd3_proc_mkdir(struct svc_rqst *rqstp)
{
	struct nfsd3_createargs *argp = rqstp->rq_argp;
	struct nfsd3_diropres *resp = rqstp->rq_resp;
	struct nfsd_attrs attrs = {
		.na_iattr	= &argp->attrs,
	};

	argp->attrs.ia_valid &= ~ATTR_SIZE;
	fh_copy(&resp->dirfh, &argp->fh);
	fh_init(&resp->fh, NFS3_FHSIZE);
	resp->status = nfsd_create(rqstp, &resp->dirfh, argp->name, argp->len,
				   &attrs, S_IFDIR, 0, &resp->fh);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

static __be32
nfsd3_proc_symlink(struct svc_rqst *rqstp)
{
	struct nfsd3_symlinkargs *argp = rqstp->rq_argp;
	struct nfsd3_diropres *resp = rqstp->rq_resp;
	struct nfsd_attrs attrs = {
		.na_iattr	= &argp->attrs,
	};

	if (argp->tlen == 0) {
		resp->status = nfserr_inval;
		goto out;
	}
	if (argp->tlen > NFS3_MAXPATHLEN) {
		resp->status = nfserr_nametoolong;
		goto out;
	}

	argp->tname = svc_fill_symlink_pathname(rqstp, &argp->first,
						page_address(rqstp->rq_arg.pages[0]),
						argp->tlen);
	if (IS_ERR(argp->tname)) {
		resp->status = nfserrno(PTR_ERR(argp->tname));
		goto out;
	}

	fh_copy(&resp->dirfh, &argp->ffh);
	fh_init(&resp->fh, NFS3_FHSIZE);
	resp->status = nfsd_symlink(rqstp, &resp->dirfh, argp->fname,
				    argp->flen, argp->tname, &attrs, &resp->fh);
	kfree(argp->tname);
out:
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Make socket/fifo/device.
 */
static __be32
nfsd3_proc_mknod(struct svc_rqst *rqstp)
{
	struct nfsd3_mknodargs *argp = rqstp->rq_argp;
	struct nfsd3_diropres  *resp = rqstp->rq_resp;
	struct nfsd_attrs attrs = {
		.na_iattr	= &argp->attrs,
	};
	int type;
	dev_t	rdev = 0;

	fh_copy(&resp->dirfh, &argp->fh);
	fh_init(&resp->fh, NFS3_FHSIZE);

	if (argp->ftype == NF3CHR || argp->ftype == NF3BLK) {
		rdev = MKDEV(argp->major, argp->minor);
		if (MAJOR(rdev) != argp->major ||
		    MINOR(rdev) != argp->minor) {
			resp->status = nfserr_inval;
			goto out;
		}
	} else if (argp->ftype != NF3SOCK && argp->ftype != NF3FIFO) {
		resp->status = nfserr_badtype;
		goto out;
	}

	type = nfs3_ftypes[argp->ftype];
	resp->status = nfsd_create(rqstp, &resp->dirfh, argp->name, argp->len,
				   &attrs, type, rdev, &resp->fh);
out:
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Remove file/fifo/socket etc.
 */
static __be32
nfsd3_proc_remove(struct svc_rqst *rqstp)
{
	struct nfsd3_diropargs *argp = rqstp->rq_argp;
	struct nfsd3_attrstat *resp = rqstp->rq_resp;

	/* Unlink. -S_IFDIR means file must not be a directory */
	fh_copy(&resp->fh, &argp->fh);
	resp->status = nfsd_unlink(rqstp, &resp->fh, -S_IFDIR,
				   argp->name, argp->len);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Remove a directory
 */
static __be32
nfsd3_proc_rmdir(struct svc_rqst *rqstp)
{
	struct nfsd3_diropargs *argp = rqstp->rq_argp;
	struct nfsd3_attrstat *resp = rqstp->rq_resp;

	fh_copy(&resp->fh, &argp->fh);
	resp->status = nfsd_unlink(rqstp, &resp->fh, S_IFDIR,
				   argp->name, argp->len);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

static __be32
nfsd3_proc_rename(struct svc_rqst *rqstp)
{
	struct nfsd3_renameargs *argp = rqstp->rq_argp;
	struct nfsd3_renameres *resp = rqstp->rq_resp;

	fh_copy(&resp->ffh, &argp->ffh);
	fh_copy(&resp->tfh, &argp->tfh);
	resp->status = nfsd_rename(rqstp, &resp->ffh, argp->fname, argp->flen,
				   &resp->tfh, argp->tname, argp->tlen);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

static __be32
nfsd3_proc_link(struct svc_rqst *rqstp)
{
	struct nfsd3_linkargs *argp = rqstp->rq_argp;
	struct nfsd3_linkres  *resp = rqstp->rq_resp;

	fh_copy(&resp->fh,  &argp->ffh);
	fh_copy(&resp->tfh, &argp->tfh);
	resp->status = nfsd_link(rqstp, &resp->tfh, argp->tname, argp->tlen,
				 &resp->fh);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

static void nfsd3_init_dirlist_pages(struct svc_rqst *rqstp,
				     struct nfsd3_readdirres *resp,
				     u32 count)
{
	struct xdr_buf *buf = &resp->dirlist;
	struct xdr_stream *xdr = &resp->xdr;
	unsigned int sendbuf = min_t(unsigned int, rqstp->rq_res.buflen,
				     svc_max_payload(rqstp));

	memset(buf, 0, sizeof(*buf));

	/* Reserve room for the NULL ptr & eof flag (-2 words) */
	buf->buflen = clamp(count, (u32)(XDR_UNIT * 2), sendbuf);
	buf->buflen -= XDR_UNIT * 2;
	buf->pages = rqstp->rq_next_page;
	rqstp->rq_next_page += (buf->buflen + PAGE_SIZE - 1) >> PAGE_SHIFT;

	xdr_init_encode_pages(xdr, buf);
}

/*
 * Read a portion of a directory.
 */
static __be32
nfsd3_proc_readdir(struct svc_rqst *rqstp)
{
	struct nfsd3_readdirargs *argp = rqstp->rq_argp;
	struct nfsd3_readdirres  *resp = rqstp->rq_resp;
	loff_t		offset;

	trace_nfsd_vfs_readdir(rqstp, &argp->fh, argp->count, argp->cookie);

	nfsd3_init_dirlist_pages(rqstp, resp, argp->count);

	fh_copy(&resp->fh, &argp->fh);
	resp->common.err = nfs_ok;
	resp->cookie_offset = 0;
	resp->rqstp = rqstp;
	offset = argp->cookie;
	resp->status = nfsd_readdir(rqstp, &resp->fh, &offset,
				    &resp->common, nfs3svc_encode_entry3);
	memcpy(resp->verf, argp->verf, 8);
	nfs3svc_encode_cookie3(resp, offset);

	/* Recycle only pages that were part of the reply */
	rqstp->rq_next_page = resp->xdr.page_ptr + 1;

	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Read a portion of a directory, including file handles and attrs.
 * For now, we choose to ignore the dircount parameter.
 */
static __be32
nfsd3_proc_readdirplus(struct svc_rqst *rqstp)
{
	struct nfsd3_readdirargs *argp = rqstp->rq_argp;
	struct nfsd3_readdirres  *resp = rqstp->rq_resp;
	loff_t	offset;

	trace_nfsd_vfs_readdir(rqstp, &argp->fh, argp->count, argp->cookie);

	nfsd3_init_dirlist_pages(rqstp, resp, argp->count);

	fh_copy(&resp->fh, &argp->fh);
	resp->common.err = nfs_ok;
	resp->cookie_offset = 0;
	resp->rqstp = rqstp;
	offset = argp->cookie;

	resp->status = fh_verify(rqstp, &resp->fh, S_IFDIR, NFSD_MAY_NOP);
	if (resp->status != nfs_ok)
		goto out;

	if (resp->fh.fh_export->ex_flags & NFSEXP_NOREADDIRPLUS) {
		resp->status = nfserr_notsupp;
		goto out;
	}

	resp->status = nfsd_readdir(rqstp, &resp->fh, &offset,
				    &resp->common, nfs3svc_encode_entryplus3);
	memcpy(resp->verf, argp->verf, 8);
	nfs3svc_encode_cookie3(resp, offset);

	/* Recycle only pages that were part of the reply */
	rqstp->rq_next_page = resp->xdr.page_ptr + 1;

out:
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Get file system stats
 */
static __be32
nfsd3_proc_fsstat(struct svc_rqst *rqstp)
{
	struct nfsd_fhandle *argp = rqstp->rq_argp;
	struct nfsd3_fsstatres *resp = rqstp->rq_resp;

	resp->status = nfsd_statfs(rqstp, &argp->fh, &resp->stats, 0);
	fh_put(&argp->fh);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Get file system info
 */
static __be32
nfsd3_proc_fsinfo(struct svc_rqst *rqstp)
{
	struct nfsd_fhandle *argp = rqstp->rq_argp;
	struct nfsd3_fsinfores *resp = rqstp->rq_resp;
	u32	max_blocksize = svc_max_payload(rqstp);

	dprintk("nfsd: FSINFO(3)   %s\n",
				SVCFH_fmt(&argp->fh));

	resp->f_rtmax  = max_blocksize;
	resp->f_rtpref = max_blocksize;
	resp->f_rtmult = PAGE_SIZE;
	resp->f_wtmax  = max_blocksize;
	resp->f_wtpref = max_blocksize;
	resp->f_wtmult = PAGE_SIZE;
	resp->f_dtpref = max_blocksize;
	resp->f_maxfilesize = ~(u32) 0;
	resp->f_properties = NFS3_FSF_DEFAULT;

	resp->status = fh_verify(rqstp, &argp->fh, 0,
				 NFSD_MAY_NOP | NFSD_MAY_BYPASS_GSS_ON_ROOT);

	/* Check special features of the file system. May request
	 * different read/write sizes for file systems known to have
	 * problems with large blocks */
	if (resp->status == nfs_ok) {
		struct super_block *sb = argp->fh.fh_dentry->d_sb;

		/* Note that we don't care for remote fs's here */
		if (sb->s_magic == MSDOS_SUPER_MAGIC) {
			resp->f_properties = NFS3_FSF_BILLYBOY;
		}
		resp->f_maxfilesize = sb->s_maxbytes;
	}

	fh_put(&argp->fh);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Get pathconf info for the specified file
 */
static __be32
nfsd3_proc_pathconf(struct svc_rqst *rqstp)
{
	struct nfsd_fhandle *argp = rqstp->rq_argp;
	struct nfsd3_pathconfres *resp = rqstp->rq_resp;

	dprintk("nfsd: PATHCONF(3) %s\n",
				SVCFH_fmt(&argp->fh));

	/* Set default pathconf */
	resp->p_link_max = 255;		/* at least */
	resp->p_name_max = 255;		/* at least */
	resp->p_no_trunc = 0;
	resp->p_chown_restricted = 1;
	resp->p_case_insensitive = 0;
	resp->p_case_preserving = 1;

	resp->status = fh_verify(rqstp, &argp->fh, 0, NFSD_MAY_NOP);

	if (resp->status == nfs_ok) {
		struct super_block *sb = argp->fh.fh_dentry->d_sb;

		/* Note that we don't care for remote fs's here */
		switch (sb->s_magic) {
		case EXT2_SUPER_MAGIC:
			resp->p_link_max = EXT2_LINK_MAX;
			resp->p_name_max = EXT2_NAME_LEN;
			break;
		case MSDOS_SUPER_MAGIC:
			resp->p_case_insensitive = 1;
			resp->p_case_preserving  = 0;
			break;
		}
	}

	fh_put(&argp->fh);
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}

/*
 * Commit a file (range) to stable storage.
 */
static __be32
nfsd3_proc_commit(struct svc_rqst *rqstp)
{
	struct nfsd3_commitargs *argp = rqstp->rq_argp;
	struct nfsd3_commitres *resp = rqstp->rq_resp;
	struct nfsd_file *nf;

	dprintk("nfsd: COMMIT(3)   %s %u@%Lu\n",
				SVCFH_fmt(&argp->fh),
				argp->count,
				(unsigned long long) argp->offset);

	fh_copy(&resp->fh, &argp->fh);
	resp->status = nfsd_file_acquire_gc(rqstp, &resp->fh, NFSD_MAY_WRITE |
					    NFSD_MAY_NOT_BREAK_LEASE, &nf);
	if (resp->status)
		goto out;
	resp->status = nfsd_commit(rqstp, &resp->fh, nf, argp->offset,
				   argp->count, resp->verf);
	nfsd_file_put(nf);
out:
	resp->status = nfsd3_map_status(resp->status);
	return rpc_success;
}


/*
 * NFSv3 Server procedures.
 * Only the results of non-idempotent operations are cached.
 */
#define nfs3svc_encode_attrstatres	nfs3svc_encode_attrstat
#define nfs3svc_encode_wccstatres	nfs3svc_encode_wccstat
#define nfsd3_mkdirargs			nfsd3_createargs
#define nfsd3_readdirplusargs		nfsd3_readdirargs
#define nfsd3_fhandleargs		nfsd_fhandle
#define nfsd3_attrstatres		nfsd3_attrstat
#define nfsd3_wccstatres		nfsd3_attrstat
#define nfsd3_createres			nfsd3_diropres

#define ST 1		/* status*/
#define FH 17		/* filehandle with length */
#define AT 21		/* attributes */
#define pAT (1+AT)	/* post attributes - conditional */
#define WC (7+pAT)	/* WCC attributes */

static const struct svc_procedure nfsd_procedures3[22] = {
	[NFS3PROC_NULL] = {
		.pc_func = nfsd3_proc_null,
		.pc_decode = nfssvc_decode_voidarg,
		.pc_encode = nfssvc_encode_voidres,
		.pc_argsize = sizeof(struct nfsd_voidargs),
		.pc_argzero = sizeof(struct nfsd_voidargs),
		.pc_ressize = sizeof(struct nfsd_voidres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST,
		.pc_name = "NULL",
	},
	[NFS3PROC_GETATTR] = {
		.pc_func = nfsd3_proc_getattr,
		.pc_decode = nfs3svc_decode_fhandleargs,
		.pc_encode = nfs3svc_encode_getattrres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd_fhandle),
		.pc_argzero = sizeof(struct nfsd_fhandle),
		.pc_ressize = sizeof(struct nfsd3_attrstatres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+AT,
		.pc_name = "GETATTR",
	},
	[NFS3PROC_SETATTR] = {
		.pc_func = nfsd3_proc_setattr,
		.pc_decode = nfs3svc_decode_sattrargs,
		.pc_encode = nfs3svc_encode_wccstatres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_sattrargs),
		.pc_argzero = sizeof(struct nfsd3_sattrargs),
		.pc_ressize = sizeof(struct nfsd3_wccstatres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC,
		.pc_name = "SETATTR",
	},
	[NFS3PROC_LOOKUP] = {
		.pc_func = nfsd3_proc_lookup,
		.pc_decode = nfs3svc_decode_diropargs,
		.pc_encode = nfs3svc_encode_lookupres,
		.pc_release = nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_diropargs),
		.pc_argzero = sizeof(struct nfsd3_diropargs),
		.pc_ressize = sizeof(struct nfsd3_diropres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+FH+pAT+pAT,
		.pc_name = "LOOKUP",
	},
	[NFS3PROC_ACCESS] = {
		.pc_func = nfsd3_proc_access,
		.pc_decode = nfs3svc_decode_accessargs,
		.pc_encode = nfs3svc_encode_accessres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_accessargs),
		.pc_argzero = sizeof(struct nfsd3_accessargs),
		.pc_ressize = sizeof(struct nfsd3_accessres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+1,
		.pc_name = "ACCESS",
	},
	[NFS3PROC_READLINK] = {
		.pc_func = nfsd3_proc_readlink,
		.pc_decode = nfs3svc_decode_fhandleargs,
		.pc_encode = nfs3svc_encode_readlinkres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd_fhandle),
		.pc_argzero = sizeof(struct nfsd_fhandle),
		.pc_ressize = sizeof(struct nfsd3_readlinkres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+1+NFS3_MAXPATHLEN/4,
		.pc_name = "READLINK",
	},
	[NFS3PROC_READ] = {
		.pc_func = nfsd3_proc_read,
		.pc_decode = nfs3svc_decode_readargs,
		.pc_encode = nfs3svc_encode_readres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_readargs),
		.pc_argzero = sizeof(struct nfsd3_readargs),
		.pc_ressize = sizeof(struct nfsd3_readres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+4+NFSSVC_MAXBLKSIZE/4,
		.pc_name = "READ",
	},
	[NFS3PROC_WRITE] = {
		.pc_func = nfsd3_proc_write,
		.pc_decode = nfs3svc_decode_writeargs,
		.pc_encode = nfs3svc_encode_writeres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_writeargs),
		.pc_argzero = sizeof(struct nfsd3_writeargs),
		.pc_ressize = sizeof(struct nfsd3_writeres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC+4,
		.pc_name = "WRITE",
	},
	[NFS3PROC_CREATE] = {
		.pc_func = nfsd3_proc_create,
		.pc_decode = nfs3svc_decode_createargs,
		.pc_encode = nfs3svc_encode_createres,
		.pc_release = nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_createargs),
		.pc_argzero = sizeof(struct nfsd3_createargs),
		.pc_ressize = sizeof(struct nfsd3_createres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+(1+FH+pAT)+WC,
		.pc_name = "CREATE",
	},
	[NFS3PROC_MKDIR] = {
		.pc_func = nfsd3_proc_mkdir,
		.pc_decode = nfs3svc_decode_mkdirargs,
		.pc_encode = nfs3svc_encode_createres,
		.pc_release = nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_mkdirargs),
		.pc_argzero = sizeof(struct nfsd3_mkdirargs),
		.pc_ressize = sizeof(struct nfsd3_createres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+(1+FH+pAT)+WC,
		.pc_name = "MKDIR",
	},
	[NFS3PROC_SYMLINK] = {
		.pc_func = nfsd3_proc_symlink,
		.pc_decode = nfs3svc_decode_symlinkargs,
		.pc_encode = nfs3svc_encode_createres,
		.pc_release = nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_symlinkargs),
		.pc_argzero = sizeof(struct nfsd3_symlinkargs),
		.pc_ressize = sizeof(struct nfsd3_createres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+(1+FH+pAT)+WC,
		.pc_name = "SYMLINK",
	},
	[NFS3PROC_MKNOD] = {
		.pc_func = nfsd3_proc_mknod,
		.pc_decode = nfs3svc_decode_mknodargs,
		.pc_encode = nfs3svc_encode_createres,
		.pc_release = nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_mknodargs),
		.pc_argzero = sizeof(struct nfsd3_mknodargs),
		.pc_ressize = sizeof(struct nfsd3_createres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+(1+FH+pAT)+WC,
		.pc_name = "MKNOD",
	},
	[NFS3PROC_REMOVE] = {
		.pc_func = nfsd3_proc_remove,
		.pc_decode = nfs3svc_decode_diropargs,
		.pc_encode = nfs3svc_encode_wccstatres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_diropargs),
		.pc_argzero = sizeof(struct nfsd3_diropargs),
		.pc_ressize = sizeof(struct nfsd3_wccstatres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC,
		.pc_name = "REMOVE",
	},
	[NFS3PROC_RMDIR] = {
		.pc_func = nfsd3_proc_rmdir,
		.pc_decode = nfs3svc_decode_diropargs,
		.pc_encode = nfs3svc_encode_wccstatres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_diropargs),
		.pc_argzero = sizeof(struct nfsd3_diropargs),
		.pc_ressize = sizeof(struct nfsd3_wccstatres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC,
		.pc_name = "RMDIR",
	},
	[NFS3PROC_RENAME] = {
		.pc_func = nfsd3_proc_rename,
		.pc_decode = nfs3svc_decode_renameargs,
		.pc_encode = nfs3svc_encode_renameres,
		.pc_release = nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_renameargs),
		.pc_argzero = sizeof(struct nfsd3_renameargs),
		.pc_ressize = sizeof(struct nfsd3_renameres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+WC+WC,
		.pc_name = "RENAME",
	},
	[NFS3PROC_LINK] = {
		.pc_func = nfsd3_proc_link,
		.pc_decode = nfs3svc_decode_linkargs,
		.pc_encode = nfs3svc_encode_linkres,
		.pc_release = nfs3svc_release_fhandle2,
		.pc_argsize = sizeof(struct nfsd3_linkargs),
		.pc_argzero = sizeof(struct nfsd3_linkargs),
		.pc_ressize = sizeof(struct nfsd3_linkres),
		.pc_cachetype = RC_REPLBUFF,
		.pc_xdrressize = ST+pAT+WC,
		.pc_name = "LINK",
	},
	[NFS3PROC_READDIR] = {
		.pc_func = nfsd3_proc_readdir,
		.pc_decode = nfs3svc_decode_readdirargs,
		.pc_encode = nfs3svc_encode_readdirres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_readdirargs),
		.pc_argzero = sizeof(struct nfsd3_readdirargs),
		.pc_ressize = sizeof(struct nfsd3_readdirres),
		.pc_cachetype = RC_NOCACHE,
		.pc_name = "READDIR",
	},
	[NFS3PROC_READDIRPLUS] = {
		.pc_func = nfsd3_proc_readdirplus,
		.pc_decode = nfs3svc_decode_readdirplusargs,
		.pc_encode = nfs3svc_encode_readdirres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_readdirplusargs),
		.pc_argzero = sizeof(struct nfsd3_readdirplusargs),
		.pc_ressize = sizeof(struct nfsd3_readdirres),
		.pc_cachetype = RC_NOCACHE,
		.pc_name = "READDIRPLUS",
	},
	[NFS3PROC_FSSTAT] = {
		.pc_func = nfsd3_proc_fsstat,
		.pc_decode = nfs3svc_decode_fhandleargs,
		.pc_encode = nfs3svc_encode_fsstatres,
		.pc_argsize = sizeof(struct nfsd3_fhandleargs),
		.pc_argzero = sizeof(struct nfsd3_fhandleargs),
		.pc_ressize = sizeof(struct nfsd3_fsstatres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+2*6+1,
		.pc_name = "FSSTAT",
	},
	[NFS3PROC_FSINFO] = {
		.pc_func = nfsd3_proc_fsinfo,
		.pc_decode = nfs3svc_decode_fhandleargs,
		.pc_encode = nfs3svc_encode_fsinfores,
		.pc_argsize = sizeof(struct nfsd3_fhandleargs),
		.pc_argzero = sizeof(struct nfsd3_fhandleargs),
		.pc_ressize = sizeof(struct nfsd3_fsinfores),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+12,
		.pc_name = "FSINFO",
	},
	[NFS3PROC_PATHCONF] = {
		.pc_func = nfsd3_proc_pathconf,
		.pc_decode = nfs3svc_decode_fhandleargs,
		.pc_encode = nfs3svc_encode_pathconfres,
		.pc_argsize = sizeof(struct nfsd3_fhandleargs),
		.pc_argzero = sizeof(struct nfsd3_fhandleargs),
		.pc_ressize = sizeof(struct nfsd3_pathconfres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+pAT+6,
		.pc_name = "PATHCONF",
	},
	[NFS3PROC_COMMIT] = {
		.pc_func = nfsd3_proc_commit,
		.pc_decode = nfs3svc_decode_commitargs,
		.pc_encode = nfs3svc_encode_commitres,
		.pc_release = nfs3svc_release_fhandle,
		.pc_argsize = sizeof(struct nfsd3_commitargs),
		.pc_argzero = sizeof(struct nfsd3_commitargs),
		.pc_ressize = sizeof(struct nfsd3_commitres),
		.pc_cachetype = RC_NOCACHE,
		.pc_xdrressize = ST+WC+2,
		.pc_name = "COMMIT",
	},
};

static DEFINE_PER_CPU_ALIGNED(unsigned long,
			      nfsd_count3[ARRAY_SIZE(nfsd_procedures3)]);
const struct svc_version nfsd_version3 = {
	.vs_vers	= 3,
	.vs_nproc	= ARRAY_SIZE(nfsd_procedures3),
	.vs_proc	= nfsd_procedures3,
	.vs_dispatch	= nfsd_dispatch,
	.vs_count	= nfsd_count3,
	.vs_xdrsize	= NFS3_SVC_XDRSIZE,
};
