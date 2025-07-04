// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2003 Erez Zadok
 * Copyright (C) 2001-2003 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Michael C. Thompson <mcthomps@us.ibm.com>
 *              Tyler Hicks <code@tyhicks.com>
 */

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/skbuff.h>
#include <linux/pagemap.h>
#include <linux/key.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/fs_stack.h>
#include <linux/sysfs.h>
#include <linux/slab.h>
#include <linux/magic.h>
#include "ecryptfs_kernel.h"

/*
 * Module parameter that defines the ecryptfs_verbosity level.
 */
int ecryptfs_verbosity = 0;

module_param(ecryptfs_verbosity, int, 0);
MODULE_PARM_DESC(ecryptfs_verbosity,
		 "Initial verbosity level (0 or 1; defaults to "
		 "0, which is Quiet)");

/*
 * Module parameter that defines the number of message buffer elements
 */
unsigned int ecryptfs_message_buf_len = ECRYPTFS_DEFAULT_MSG_CTX_ELEMS;

module_param(ecryptfs_message_buf_len, uint, 0);
MODULE_PARM_DESC(ecryptfs_message_buf_len,
		 "Number of message buffer elements");

/*
 * Module parameter that defines the maximum guaranteed amount of time to wait
 * for a response from ecryptfsd.  The actual sleep time will be, more than
 * likely, a small amount greater than this specified value, but only less if
 * the message successfully arrives.
 */
signed long ecryptfs_message_wait_timeout = ECRYPTFS_MAX_MSG_CTX_TTL / HZ;

module_param(ecryptfs_message_wait_timeout, long, 0);
MODULE_PARM_DESC(ecryptfs_message_wait_timeout,
		 "Maximum number of seconds that an operation will "
		 "sleep while waiting for a message response from "
		 "userspace");

/*
 * Module parameter that is an estimate of the maximum number of users
 * that will be concurrently using eCryptfs. Set this to the right
 * value to balance performance and memory use.
 */
unsigned int ecryptfs_number_of_users = ECRYPTFS_DEFAULT_NUM_USERS;

module_param(ecryptfs_number_of_users, uint, 0);
MODULE_PARM_DESC(ecryptfs_number_of_users, "An estimate of the number of "
		 "concurrent users of eCryptfs");

void __ecryptfs_printk(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	if (fmt[1] == '7') { /* KERN_DEBUG */
		if (ecryptfs_verbosity >= 1)
			vprintk(fmt, args);
	} else
		vprintk(fmt, args);
	va_end(args);
}

/*
 * ecryptfs_init_lower_file
 * @ecryptfs_dentry: Fully initialized eCryptfs dentry object, with
 *                   the lower dentry and the lower mount set
 *
 * eCryptfs only ever keeps a single open file for every lower
 * inode. All I/O operations to the lower inode occur through that
 * file. When the first eCryptfs dentry that interposes with the first
 * lower dentry for that inode is created, this function creates the
 * lower file struct and associates it with the eCryptfs
 * inode. When all eCryptfs files associated with the inode are released, the
 * file is closed.
 *
 * The lower file will be opened with read/write permissions, if
 * possible. Otherwise, it is opened read-only.
 *
 * This function does nothing if a lower file is already
 * associated with the eCryptfs inode.
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_init_lower_file(struct dentry *dentry,
				    struct file **lower_file)
{
	const struct cred *cred = current_cred();
	const struct path *path = ecryptfs_dentry_to_lower_path(dentry);
	int rc;

	rc = ecryptfs_privileged_open(lower_file, path->dentry, path->mnt,
				      cred);
	if (rc) {
		printk(KERN_ERR "Error opening lower file "
		       "for lower_dentry [0x%p] and lower_mnt [0x%p]; "
		       "rc = [%d]\n", path->dentry, path->mnt, rc);
		(*lower_file) = NULL;
	}
	return rc;
}

int ecryptfs_get_lower_file(struct dentry *dentry, struct inode *inode)
{
	struct ecryptfs_inode_info *inode_info;
	int count, rc = 0;

	inode_info = ecryptfs_inode_to_private(inode);
	mutex_lock(&inode_info->lower_file_mutex);
	count = atomic_inc_return(&inode_info->lower_file_count);
	if (WARN_ON_ONCE(count < 1))
		rc = -EINVAL;
	else if (count == 1) {
		rc = ecryptfs_init_lower_file(dentry,
					      &inode_info->lower_file);
		if (rc)
			atomic_set(&inode_info->lower_file_count, 0);
	}
	mutex_unlock(&inode_info->lower_file_mutex);
	return rc;
}

void ecryptfs_put_lower_file(struct inode *inode)
{
	struct ecryptfs_inode_info *inode_info;

	inode_info = ecryptfs_inode_to_private(inode);
	if (atomic_dec_and_mutex_lock(&inode_info->lower_file_count,
				      &inode_info->lower_file_mutex)) {
		filemap_write_and_wait(inode->i_mapping);
		fput(inode_info->lower_file);
		inode_info->lower_file = NULL;
		mutex_unlock(&inode_info->lower_file_mutex);
	}
}

enum {
	Opt_sig, Opt_ecryptfs_sig, Opt_cipher, Opt_ecryptfs_cipher,
	Opt_ecryptfs_key_bytes, Opt_passthrough, Opt_xattr_metadata,
	Opt_encrypted_view, Opt_fnek_sig, Opt_fn_cipher,
	Opt_fn_cipher_key_bytes, Opt_unlink_sigs, Opt_mount_auth_tok_only,
	Opt_check_dev_ruid
};

static const struct fs_parameter_spec ecryptfs_fs_param_spec[] = {
	fsparam_string	("sig",			    Opt_sig),
	fsparam_string	("ecryptfs_sig",	    Opt_ecryptfs_sig),
	fsparam_string	("cipher",		    Opt_cipher),
	fsparam_string	("ecryptfs_cipher",	    Opt_ecryptfs_cipher),
	fsparam_u32	("ecryptfs_key_bytes",	    Opt_ecryptfs_key_bytes),
	fsparam_flag	("ecryptfs_passthrough",    Opt_passthrough),
	fsparam_flag	("ecryptfs_xattr_metadata", Opt_xattr_metadata),
	fsparam_flag	("ecryptfs_encrypted_view", Opt_encrypted_view),
	fsparam_string	("ecryptfs_fnek_sig",	    Opt_fnek_sig),
	fsparam_string	("ecryptfs_fn_cipher",	    Opt_fn_cipher),
	fsparam_u32	("ecryptfs_fn_key_bytes",   Opt_fn_cipher_key_bytes),
	fsparam_flag	("ecryptfs_unlink_sigs",    Opt_unlink_sigs),
	fsparam_flag	("ecryptfs_mount_auth_tok_only", Opt_mount_auth_tok_only),
	fsparam_flag	("ecryptfs_check_dev_ruid", Opt_check_dev_ruid),
	{}
};

static int ecryptfs_init_global_auth_toks(
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	struct ecryptfs_global_auth_tok *global_auth_tok;
	struct ecryptfs_auth_tok *auth_tok;
	int rc = 0;

	list_for_each_entry(global_auth_tok,
			    &mount_crypt_stat->global_auth_tok_list,
			    mount_crypt_stat_list) {
		rc = ecryptfs_keyring_auth_tok_for_sig(
			&global_auth_tok->global_auth_tok_key, &auth_tok,
			global_auth_tok->sig);
		if (rc) {
			printk(KERN_ERR "Could not find valid key in user "
			       "session keyring for sig specified in mount "
			       "option: [%s]\n", global_auth_tok->sig);
			global_auth_tok->flags |= ECRYPTFS_AUTH_TOK_INVALID;
			goto out;
		} else {
			global_auth_tok->flags &= ~ECRYPTFS_AUTH_TOK_INVALID;
			up_write(&(global_auth_tok->global_auth_tok_key)->sem);
		}
	}
out:
	return rc;
}

static void ecryptfs_init_mount_crypt_stat(
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat)
{
	memset((void *)mount_crypt_stat, 0,
	       sizeof(struct ecryptfs_mount_crypt_stat));
	INIT_LIST_HEAD(&mount_crypt_stat->global_auth_tok_list);
	mutex_init(&mount_crypt_stat->global_auth_tok_list_mutex);
	mount_crypt_stat->flags |= ECRYPTFS_MOUNT_CRYPT_STAT_INITIALIZED;
}

struct ecryptfs_fs_context {
	/* Mount option status trackers */
	bool check_ruid;
	bool sig_set;
	bool cipher_name_set;
	bool cipher_key_bytes_set;
	bool fn_cipher_name_set;
	bool fn_cipher_key_bytes_set;
};

/**
 * ecryptfs_parse_param
 * @fc: The ecryptfs filesystem context
 * @param: The mount parameter to parse
 *
 * The signature of the key to use must be the description of a key
 * already in the keyring. Mounting will fail if the key can not be
 * found.
 *
 * Returns zero on success; non-zero on error
 */
static int ecryptfs_parse_param(
	struct fs_context *fc,
	struct fs_parameter *param)
{
	int rc;
	int opt;
	struct fs_parse_result result;
	struct ecryptfs_fs_context *ctx = fc->fs_private;
	struct ecryptfs_sb_info *sbi = fc->s_fs_info;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat =
		&sbi->mount_crypt_stat;

	opt = fs_parse(fc, ecryptfs_fs_param_spec, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_sig:
	case Opt_ecryptfs_sig:
		rc = ecryptfs_add_global_auth_tok(mount_crypt_stat,
						  param->string, 0);
		if (rc) {
			printk(KERN_ERR "Error attempting to register "
			       "global sig; rc = [%d]\n", rc);
			return rc;
		}
		ctx->sig_set = 1;
		break;
	case Opt_cipher:
	case Opt_ecryptfs_cipher:
		strscpy(mount_crypt_stat->global_default_cipher_name,
			param->string);
		ctx->cipher_name_set = 1;
		break;
	case Opt_ecryptfs_key_bytes:
		mount_crypt_stat->global_default_cipher_key_size =
			result.uint_32;
		ctx->cipher_key_bytes_set = 1;
		break;
	case Opt_passthrough:
		mount_crypt_stat->flags |=
			ECRYPTFS_PLAINTEXT_PASSTHROUGH_ENABLED;
		break;
	case Opt_xattr_metadata:
		mount_crypt_stat->flags |= ECRYPTFS_XATTR_METADATA_ENABLED;
		break;
	case Opt_encrypted_view:
		mount_crypt_stat->flags |= ECRYPTFS_XATTR_METADATA_ENABLED;
		mount_crypt_stat->flags |= ECRYPTFS_ENCRYPTED_VIEW_ENABLED;
		break;
	case Opt_fnek_sig:
		strscpy(mount_crypt_stat->global_default_fnek_sig,
			param->string);
		rc = ecryptfs_add_global_auth_tok(
			mount_crypt_stat,
			mount_crypt_stat->global_default_fnek_sig,
			ECRYPTFS_AUTH_TOK_FNEK);
		if (rc) {
			printk(KERN_ERR "Error attempting to register "
			       "global fnek sig [%s]; rc = [%d]\n",
			       mount_crypt_stat->global_default_fnek_sig, rc);
			return rc;
		}
		mount_crypt_stat->flags |=
			(ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES
			 | ECRYPTFS_GLOBAL_ENCFN_USE_MOUNT_FNEK);
		break;
	case Opt_fn_cipher:
		strscpy(mount_crypt_stat->global_default_fn_cipher_name,
			param->string);
		ctx->fn_cipher_name_set = 1;
		break;
	case Opt_fn_cipher_key_bytes:
		mount_crypt_stat->global_default_fn_cipher_key_bytes =
			result.uint_32;
		ctx->fn_cipher_key_bytes_set = 1;
		break;
	case Opt_unlink_sigs:
		mount_crypt_stat->flags |= ECRYPTFS_UNLINK_SIGS;
		break;
	case Opt_mount_auth_tok_only:
		mount_crypt_stat->flags |= ECRYPTFS_GLOBAL_MOUNT_AUTH_TOK_ONLY;
		break;
	case Opt_check_dev_ruid:
		ctx->check_ruid = 1;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int ecryptfs_validate_options(struct fs_context *fc)
{
	int rc = 0;
	u8 cipher_code;
	struct ecryptfs_fs_context *ctx = fc->fs_private;
	struct ecryptfs_sb_info *sbi = fc->s_fs_info;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat;


	mount_crypt_stat = &sbi->mount_crypt_stat;

	if (!ctx->sig_set) {
		rc = -EINVAL;
		ecryptfs_printk(KERN_ERR, "You must supply at least one valid "
				"auth tok signature as a mount "
				"parameter; see the eCryptfs README\n");
		goto out;
	}
	if (!ctx->cipher_name_set) {
		int cipher_name_len = strlen(ECRYPTFS_DEFAULT_CIPHER);

		BUG_ON(cipher_name_len > ECRYPTFS_MAX_CIPHER_NAME_SIZE);
		strcpy(mount_crypt_stat->global_default_cipher_name,
		       ECRYPTFS_DEFAULT_CIPHER);
	}
	if ((mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES)
	    && !ctx->fn_cipher_name_set)
		strcpy(mount_crypt_stat->global_default_fn_cipher_name,
		       mount_crypt_stat->global_default_cipher_name);
	if (!ctx->cipher_key_bytes_set)
		mount_crypt_stat->global_default_cipher_key_size = 0;
	if ((mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES)
	    && !ctx->fn_cipher_key_bytes_set)
		mount_crypt_stat->global_default_fn_cipher_key_bytes =
			mount_crypt_stat->global_default_cipher_key_size;

	cipher_code = ecryptfs_code_for_cipher_string(
		mount_crypt_stat->global_default_cipher_name,
		mount_crypt_stat->global_default_cipher_key_size);
	if (!cipher_code) {
		ecryptfs_printk(KERN_ERR,
				"eCryptfs doesn't support cipher: %s\n",
				mount_crypt_stat->global_default_cipher_name);
		rc = -EINVAL;
		goto out;
	}

	mutex_lock(&key_tfm_list_mutex);
	if (!ecryptfs_tfm_exists(mount_crypt_stat->global_default_cipher_name,
				 NULL)) {
		rc = ecryptfs_add_new_key_tfm(
			NULL, mount_crypt_stat->global_default_cipher_name,
			mount_crypt_stat->global_default_cipher_key_size);
		if (rc) {
			printk(KERN_ERR "Error attempting to initialize "
			       "cipher with name = [%s] and key size = [%td]; "
			       "rc = [%d]\n",
			       mount_crypt_stat->global_default_cipher_name,
			       mount_crypt_stat->global_default_cipher_key_size,
			       rc);
			rc = -EINVAL;
			mutex_unlock(&key_tfm_list_mutex);
			goto out;
		}
	}
	if ((mount_crypt_stat->flags & ECRYPTFS_GLOBAL_ENCRYPT_FILENAMES)
	    && !ecryptfs_tfm_exists(
		    mount_crypt_stat->global_default_fn_cipher_name, NULL)) {
		rc = ecryptfs_add_new_key_tfm(
			NULL, mount_crypt_stat->global_default_fn_cipher_name,
			mount_crypt_stat->global_default_fn_cipher_key_bytes);
		if (rc) {
			printk(KERN_ERR "Error attempting to initialize "
			       "cipher with name = [%s] and key size = [%td]; "
			       "rc = [%d]\n",
			       mount_crypt_stat->global_default_fn_cipher_name,
			       mount_crypt_stat->global_default_fn_cipher_key_bytes,
			       rc);
			rc = -EINVAL;
			mutex_unlock(&key_tfm_list_mutex);
			goto out;
		}
	}
	mutex_unlock(&key_tfm_list_mutex);
	rc = ecryptfs_init_global_auth_toks(mount_crypt_stat);
	if (rc)
		printk(KERN_WARNING "One or more global auth toks could not "
		       "properly register; rc = [%d]\n", rc);
out:
	return rc;
}

struct kmem_cache *ecryptfs_sb_info_cache;
static struct file_system_type ecryptfs_fs_type;

/*
 * ecryptfs_get_tree
 * @fc: The filesystem context
 */
static int ecryptfs_get_tree(struct fs_context *fc)
{
	struct super_block *s;
	struct ecryptfs_fs_context *ctx = fc->fs_private;
	struct ecryptfs_sb_info *sbi = fc->s_fs_info;
	struct ecryptfs_mount_crypt_stat *mount_crypt_stat;
	struct ecryptfs_dentry_info *root_info;
	const char *err = "Getting sb failed";
	struct inode *inode;
	struct path path;
	int rc;

	if (!fc->source) {
		rc = -EINVAL;
		err = "Device name cannot be null";
		goto out;
	}

	mount_crypt_stat = &sbi->mount_crypt_stat;
	rc = ecryptfs_validate_options(fc);
	if (rc) {
		err = "Error validating options";
		goto out;
	}

	s = sget_fc(fc, NULL, set_anon_super_fc);
	if (IS_ERR(s)) {
		rc = PTR_ERR(s);
		goto out;
	}

	rc = super_setup_bdi(s);
	if (rc)
		goto out1;

	ecryptfs_set_superblock_private(s, sbi);

	/* ->kill_sb() will take care of sbi after that point */
	sbi = NULL;
	s->s_op = &ecryptfs_sops;
	s->s_xattr = ecryptfs_xattr_handlers;
	set_default_d_op(s, &ecryptfs_dops);

	err = "Reading sb failed";
	rc = kern_path(fc->source, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &path);
	if (rc) {
		ecryptfs_printk(KERN_WARNING, "kern_path() failed\n");
		goto out1;
	}
	if (path.dentry->d_sb->s_type == &ecryptfs_fs_type) {
		rc = -EINVAL;
		printk(KERN_ERR "Mount on filesystem of type "
			"eCryptfs explicitly disallowed due to "
			"known incompatibilities\n");
		goto out_free;
	}

	if (is_idmapped_mnt(path.mnt)) {
		rc = -EINVAL;
		printk(KERN_ERR "Mounting on idmapped mounts currently disallowed\n");
		goto out_free;
	}

	if (ctx->check_ruid &&
	    !uid_eq(d_inode(path.dentry)->i_uid, current_uid())) {
		rc = -EPERM;
		printk(KERN_ERR "Mount of device (uid: %d) not owned by "
		       "requested user (uid: %d)\n",
			i_uid_read(d_inode(path.dentry)),
			from_kuid(&init_user_ns, current_uid()));
		goto out_free;
	}

	ecryptfs_set_superblock_lower(s, path.dentry->d_sb);

	/**
	 * Set the POSIX ACL flag based on whether they're enabled in the lower
	 * mount.
	 */
	s->s_flags = fc->sb_flags & ~SB_POSIXACL;
	s->s_flags |= path.dentry->d_sb->s_flags & SB_POSIXACL;

	/**
	 * Force a read-only eCryptfs mount when:
	 *   1) The lower mount is ro
	 *   2) The ecryptfs_encrypted_view mount option is specified
	 */
	if (sb_rdonly(path.dentry->d_sb) || mount_crypt_stat->flags & ECRYPTFS_ENCRYPTED_VIEW_ENABLED)
		s->s_flags |= SB_RDONLY;

	s->s_maxbytes = path.dentry->d_sb->s_maxbytes;
	s->s_blocksize = path.dentry->d_sb->s_blocksize;
	s->s_magic = ECRYPTFS_SUPER_MAGIC;
	s->s_stack_depth = path.dentry->d_sb->s_stack_depth + 1;

	rc = -EINVAL;
	if (s->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("eCryptfs: maximum fs stacking depth exceeded\n");
		goto out_free;
	}

	inode = ecryptfs_get_inode(d_inode(path.dentry), s);
	rc = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_free;

	s->s_root = d_make_root(inode);
	if (!s->s_root) {
		rc = -ENOMEM;
		goto out_free;
	}

	rc = -ENOMEM;
	root_info = kmem_cache_zalloc(ecryptfs_dentry_info_cache, GFP_KERNEL);
	if (!root_info)
		goto out_free;

	/* ->kill_sb() will take care of root_info */
	ecryptfs_set_dentry_private(s->s_root, root_info);
	root_info->lower_path = path;

	s->s_flags |= SB_ACTIVE;
	fc->root = dget(s->s_root);
	return 0;

out_free:
	path_put(&path);
out1:
	deactivate_locked_super(s);
out:
	if (sbi)
		ecryptfs_destroy_mount_crypt_stat(&sbi->mount_crypt_stat);

	printk(KERN_ERR "%s; rc = [%d]\n", err, rc);
	return rc;
}

/**
 * ecryptfs_kill_block_super
 * @sb: The ecryptfs super block
 *
 * Used to bring the superblock down and free the private data.
 */
static void ecryptfs_kill_block_super(struct super_block *sb)
{
	struct ecryptfs_sb_info *sb_info = ecryptfs_superblock_to_private(sb);
	kill_anon_super(sb);
	if (!sb_info)
		return;
	ecryptfs_destroy_mount_crypt_stat(&sb_info->mount_crypt_stat);
	kmem_cache_free(ecryptfs_sb_info_cache, sb_info);
}

static void ecryptfs_free_fc(struct fs_context *fc)
{
	struct ecryptfs_fs_context *ctx = fc->fs_private;
	struct ecryptfs_sb_info *sbi = fc->s_fs_info;

	kfree(ctx);

	if (sbi) {
		ecryptfs_destroy_mount_crypt_stat(&sbi->mount_crypt_stat);
		kmem_cache_free(ecryptfs_sb_info_cache, sbi);
	}
}

static const struct fs_context_operations ecryptfs_context_ops = {
	.free		= ecryptfs_free_fc,
	.parse_param	= ecryptfs_parse_param,
	.get_tree	= ecryptfs_get_tree,
	.reconfigure	= NULL,
};

static int ecryptfs_init_fs_context(struct fs_context *fc)
{
	struct ecryptfs_fs_context *ctx;
	struct ecryptfs_sb_info *sbi = NULL;

	ctx = kzalloc(sizeof(struct ecryptfs_fs_context), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	sbi = kmem_cache_zalloc(ecryptfs_sb_info_cache, GFP_KERNEL);
	if (!sbi) {
		kfree(ctx);
		ctx = NULL;
		return -ENOMEM;
	}

	ecryptfs_init_mount_crypt_stat(&sbi->mount_crypt_stat);

	fc->fs_private = ctx;
	fc->s_fs_info = sbi;
	fc->ops = &ecryptfs_context_ops;
	return 0;
}

static struct file_system_type ecryptfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "ecryptfs",
	.init_fs_context = ecryptfs_init_fs_context,
	.parameters = ecryptfs_fs_param_spec,
	.kill_sb = ecryptfs_kill_block_super,
	.fs_flags = 0
};
MODULE_ALIAS_FS("ecryptfs");

/*
 * inode_info_init_once
 *
 * Initializes the ecryptfs_inode_info_cache when it is created
 */
static void
inode_info_init_once(void *vptr)
{
	struct ecryptfs_inode_info *ei = (struct ecryptfs_inode_info *)vptr;

	inode_init_once(&ei->vfs_inode);
}

static struct ecryptfs_cache_info {
	struct kmem_cache **cache;
	const char *name;
	size_t size;
	slab_flags_t flags;
	void (*ctor)(void *obj);
} ecryptfs_cache_infos[] = {
	{
		.cache = &ecryptfs_auth_tok_list_item_cache,
		.name = "ecryptfs_auth_tok_list_item",
		.size = sizeof(struct ecryptfs_auth_tok_list_item),
	},
	{
		.cache = &ecryptfs_file_info_cache,
		.name = "ecryptfs_file_cache",
		.size = sizeof(struct ecryptfs_file_info),
	},
	{
		.cache = &ecryptfs_dentry_info_cache,
		.name = "ecryptfs_dentry_info_cache",
		.size = sizeof(struct ecryptfs_dentry_info),
	},
	{
		.cache = &ecryptfs_inode_info_cache,
		.name = "ecryptfs_inode_cache",
		.size = sizeof(struct ecryptfs_inode_info),
		.flags = SLAB_ACCOUNT,
		.ctor = inode_info_init_once,
	},
	{
		.cache = &ecryptfs_sb_info_cache,
		.name = "ecryptfs_sb_cache",
		.size = sizeof(struct ecryptfs_sb_info),
	},
	{
		.cache = &ecryptfs_header_cache,
		.name = "ecryptfs_headers",
		.size = PAGE_SIZE,
	},
	{
		.cache = &ecryptfs_xattr_cache,
		.name = "ecryptfs_xattr_cache",
		.size = PAGE_SIZE,
	},
	{
		.cache = &ecryptfs_key_record_cache,
		.name = "ecryptfs_key_record_cache",
		.size = sizeof(struct ecryptfs_key_record),
	},
	{
		.cache = &ecryptfs_key_sig_cache,
		.name = "ecryptfs_key_sig_cache",
		.size = sizeof(struct ecryptfs_key_sig),
	},
	{
		.cache = &ecryptfs_global_auth_tok_cache,
		.name = "ecryptfs_global_auth_tok_cache",
		.size = sizeof(struct ecryptfs_global_auth_tok),
	},
	{
		.cache = &ecryptfs_key_tfm_cache,
		.name = "ecryptfs_key_tfm_cache",
		.size = sizeof(struct ecryptfs_key_tfm),
	},
};

static void ecryptfs_free_kmem_caches(void)
{
	int i;

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();

	for (i = 0; i < ARRAY_SIZE(ecryptfs_cache_infos); i++) {
		struct ecryptfs_cache_info *info;

		info = &ecryptfs_cache_infos[i];
		kmem_cache_destroy(*(info->cache));
	}
}

/**
 * ecryptfs_init_kmem_caches
 *
 * Returns zero on success; non-zero otherwise
 */
static int ecryptfs_init_kmem_caches(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ecryptfs_cache_infos); i++) {
		struct ecryptfs_cache_info *info;

		info = &ecryptfs_cache_infos[i];
		*(info->cache) = kmem_cache_create(info->name, info->size, 0,
				SLAB_HWCACHE_ALIGN | info->flags, info->ctor);
		if (!*(info->cache)) {
			ecryptfs_free_kmem_caches();
			ecryptfs_printk(KERN_WARNING, "%s: "
					"kmem_cache_create failed\n",
					info->name);
			return -ENOMEM;
		}
	}
	return 0;
}

static struct kobject *ecryptfs_kobj;

static ssize_t version_show(struct kobject *kobj,
			    struct kobj_attribute *attr, char *buff)
{
	return sysfs_emit(buff, "%d\n", ECRYPTFS_VERSIONING_MASK);
}

static struct kobj_attribute version_attr = __ATTR_RO(version);

static struct attribute *attributes[] = {
	&version_attr.attr,
	NULL,
};

static const struct attribute_group attr_group = {
	.attrs = attributes,
};

static int do_sysfs_registration(void)
{
	int rc;

	ecryptfs_kobj = kobject_create_and_add("ecryptfs", fs_kobj);
	if (!ecryptfs_kobj) {
		printk(KERN_ERR "Unable to create ecryptfs kset\n");
		rc = -ENOMEM;
		goto out;
	}
	rc = sysfs_create_group(ecryptfs_kobj, &attr_group);
	if (rc) {
		printk(KERN_ERR
		       "Unable to create ecryptfs version attributes\n");
		kobject_put(ecryptfs_kobj);
	}
out:
	return rc;
}

static void do_sysfs_unregistration(void)
{
	sysfs_remove_group(ecryptfs_kobj, &attr_group);
	kobject_put(ecryptfs_kobj);
}

static int __init ecryptfs_init(void)
{
	int rc;

	if (ECRYPTFS_DEFAULT_EXTENT_SIZE > PAGE_SIZE) {
		rc = -EINVAL;
		ecryptfs_printk(KERN_ERR, "The eCryptfs extent size is "
				"larger than the host's page size, and so "
				"eCryptfs cannot run on this system. The "
				"default eCryptfs extent size is [%u] bytes; "
				"the page size is [%lu] bytes.\n",
				ECRYPTFS_DEFAULT_EXTENT_SIZE,
				(unsigned long)PAGE_SIZE);
		goto out;
	}
	rc = ecryptfs_init_kmem_caches();
	if (rc) {
		printk(KERN_ERR
		       "Failed to allocate one or more kmem_cache objects\n");
		goto out;
	}
	rc = do_sysfs_registration();
	if (rc) {
		printk(KERN_ERR "sysfs registration failed\n");
		goto out_free_kmem_caches;
	}
	rc = ecryptfs_init_kthread();
	if (rc) {
		printk(KERN_ERR "%s: kthread initialization failed; "
		       "rc = [%d]\n", __func__, rc);
		goto out_do_sysfs_unregistration;
	}
	rc = ecryptfs_init_messaging();
	if (rc) {
		printk(KERN_ERR "Failure occurred while attempting to "
				"initialize the communications channel to "
				"ecryptfsd\n");
		goto out_destroy_kthread;
	}
	rc = ecryptfs_init_crypto();
	if (rc) {
		printk(KERN_ERR "Failure whilst attempting to init crypto; "
		       "rc = [%d]\n", rc);
		goto out_release_messaging;
	}
	rc = register_filesystem(&ecryptfs_fs_type);
	if (rc) {
		printk(KERN_ERR "Failed to register filesystem\n");
		goto out_destroy_crypto;
	}
	if (ecryptfs_verbosity > 0)
		printk(KERN_CRIT "eCryptfs verbosity set to %d. Secret values "
			"will be written to the syslog!\n", ecryptfs_verbosity);

	goto out;
out_destroy_crypto:
	ecryptfs_destroy_crypto();
out_release_messaging:
	ecryptfs_release_messaging();
out_destroy_kthread:
	ecryptfs_destroy_kthread();
out_do_sysfs_unregistration:
	do_sysfs_unregistration();
out_free_kmem_caches:
	ecryptfs_free_kmem_caches();
out:
	return rc;
}

static void __exit ecryptfs_exit(void)
{
	int rc;

	rc = ecryptfs_destroy_crypto();
	if (rc)
		printk(KERN_ERR "Failure whilst attempting to destroy crypto; "
		       "rc = [%d]\n", rc);
	ecryptfs_release_messaging();
	ecryptfs_destroy_kthread();
	do_sysfs_unregistration();
	unregister_filesystem(&ecryptfs_fs_type);
	ecryptfs_free_kmem_caches();
}

MODULE_AUTHOR("Michael A. Halcrow <mhalcrow@us.ibm.com>");
MODULE_DESCRIPTION("eCryptfs");

MODULE_LICENSE("GPL");

module_init(ecryptfs_init)
module_exit(ecryptfs_exit)
