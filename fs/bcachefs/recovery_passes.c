// SPDX-License-Identifier: GPL-2.0

#include "bcachefs.h"
#include "alloc_background.h"
#include "backpointers.h"
#include "btree_gc.h"
#include "btree_node_scan.h"
#include "disk_accounting.h"
#include "ec.h"
#include "fsck.h"
#include "inode.h"
#include "journal.h"
#include "lru.h"
#include "logged_ops.h"
#include "movinggc.h"
#include "rebalance.h"
#include "recovery.h"
#include "recovery_passes.h"
#include "snapshot.h"
#include "subvolume.h"
#include "super.h"
#include "super-io.h"

const char * const bch2_recovery_passes[] = {
#define x(_fn, ...)	#_fn,
	BCH_RECOVERY_PASSES()
#undef x
	NULL
};

static const u8 passes_to_stable_map[] = {
#define x(n, id, ...)	[BCH_RECOVERY_PASS_##n] = BCH_RECOVERY_PASS_STABLE_##n,
	BCH_RECOVERY_PASSES()
#undef x
};

static const u8 passes_from_stable_map[] = {
#define x(n, id, ...)	[BCH_RECOVERY_PASS_STABLE_##n] = BCH_RECOVERY_PASS_##n,
	BCH_RECOVERY_PASSES()
#undef x
};

static enum bch_recovery_pass_stable bch2_recovery_pass_to_stable(enum bch_recovery_pass pass)
{
	return passes_to_stable_map[pass];
}

u64 bch2_recovery_passes_to_stable(u64 v)
{
	u64 ret = 0;
	for (unsigned i = 0; i < ARRAY_SIZE(passes_to_stable_map); i++)
		if (v & BIT_ULL(i))
			ret |= BIT_ULL(passes_to_stable_map[i]);
	return ret;
}

static enum bch_recovery_pass bch2_recovery_pass_from_stable(enum bch_recovery_pass_stable pass)
{
	return pass < ARRAY_SIZE(passes_from_stable_map)
		? passes_from_stable_map[pass]
		: 0;
}

u64 bch2_recovery_passes_from_stable(u64 v)
{
	u64 ret = 0;
	for (unsigned i = 0; i < ARRAY_SIZE(passes_from_stable_map); i++)
		if (v & BIT_ULL(i))
			ret |= BIT_ULL(passes_from_stable_map[i]);
	return ret;
}

static int bch2_sb_recovery_passes_validate(struct bch_sb *sb, struct bch_sb_field *f,
					    enum bch_validate_flags flags, struct printbuf *err)
{
	return 0;
}

static void bch2_sb_recovery_passes_to_text(struct printbuf *out,
					    struct bch_sb *sb,
					    struct bch_sb_field *f)
{
	struct bch_sb_field_recovery_passes *r =
		field_to_type(f, recovery_passes);
	unsigned nr = recovery_passes_nr_entries(r);

	if (out->nr_tabstops < 1)
		printbuf_tabstop_push(out, 32);
	if (out->nr_tabstops < 2)
		printbuf_tabstop_push(out, 16);

	prt_printf(out, "Pass\tLast run\tLast runtime\n");

	for (struct recovery_pass_entry *i = r->start; i < r->start + nr; i++) {
		if (!i->last_run)
			continue;

		unsigned idx = i - r->start;

		prt_printf(out, "%s\t", bch2_recovery_passes[bch2_recovery_pass_from_stable(idx)]);

		bch2_prt_datetime(out, le64_to_cpu(i->last_run));
		prt_tab(out);

		bch2_pr_time_units(out, le32_to_cpu(i->last_runtime) * NSEC_PER_SEC);
		prt_newline(out);
	}
}

static void bch2_sb_recovery_pass_complete(struct bch_fs *c,
					   enum bch_recovery_pass pass,
					   s64 start_time)
{
	enum bch_recovery_pass_stable stable = bch2_recovery_pass_to_stable(pass);
	s64 end_time = ktime_get_real_seconds();

	mutex_lock(&c->sb_lock);
	struct bch_sb_field_ext *ext = bch2_sb_field_get(c->disk_sb.sb, ext);
	__clear_bit_le64(stable, ext->recovery_passes_required);

	struct bch_sb_field_recovery_passes *r =
		bch2_sb_field_get(c->disk_sb.sb, recovery_passes);

	if (stable >= recovery_passes_nr_entries(r)) {
		unsigned u64s = struct_size(r, start, stable + 1) / sizeof(u64);

		r = bch2_sb_field_resize(&c->disk_sb, recovery_passes, u64s);
		if (!r) {
			bch_err(c, "error creating recovery_passes sb section");
			goto out;
		}
	}

	r->start[stable].last_run	= cpu_to_le64(end_time);
	r->start[stable].last_runtime	= cpu_to_le32(max(0, end_time - start_time));
out:
	bch2_write_super(c);
	mutex_unlock(&c->sb_lock);
}

const struct bch_sb_field_ops bch_sb_field_ops_recovery_passes = {
	.validate	= bch2_sb_recovery_passes_validate,
	.to_text	= bch2_sb_recovery_passes_to_text
};

/* Fake recovery pass, so that scan_for_btree_nodes isn't 0: */
static int bch2_recovery_pass_empty(struct bch_fs *c)
{
	return 0;
}

static int bch2_set_may_go_rw(struct bch_fs *c)
{
	struct journal_keys *keys = &c->journal_keys;

	/*
	 * After we go RW, the journal keys buffer can't be modified (except for
	 * setting journal_key->overwritten: it will be accessed by multiple
	 * threads
	 */
	move_gap(keys, keys->nr);

	set_bit(BCH_FS_may_go_rw, &c->flags);

	if (keys->nr ||
	    !c->opts.read_only ||
	    !c->sb.clean ||
	    c->opts.recovery_passes ||
	    (c->opts.fsck && !(c->sb.features & BIT_ULL(BCH_FEATURE_no_alloc_info)))) {
		if (c->sb.features & BIT_ULL(BCH_FEATURE_no_alloc_info)) {
			bch_info(c, "mounting a filesystem with no alloc info read-write; will recreate");
			bch2_reconstruct_alloc(c);
		}

		return bch2_fs_read_write_early(c);
	}
	return 0;
}

/*
 * Make sure root inode is readable while we're still in recovery and can rewind
 * for repair:
 */
static int bch2_lookup_root_inode(struct bch_fs *c)
{
	subvol_inum inum = BCACHEFS_ROOT_SUBVOL_INUM;
	struct bch_inode_unpacked inode_u;
	struct bch_subvolume subvol;

	return bch2_trans_do(c,
		bch2_subvolume_get(trans, inum.subvol, true, &subvol) ?:
		bch2_inode_find_by_inum_trans(trans, inum, &inode_u));
}

struct recovery_pass_fn {
	int		(*fn)(struct bch_fs *);
	unsigned	when;
};

static struct recovery_pass_fn recovery_pass_fns[] = {
#define x(_fn, _id, _when)	{ .fn = bch2_##_fn, .when = _when },
	BCH_RECOVERY_PASSES()
#undef x
};

/*
 * For when we need to rewind recovery passes and run a pass we skipped:
 */
static int __bch2_run_explicit_recovery_pass(struct printbuf *out,
					     struct bch_fs *c,
					     enum bch_recovery_pass pass)
{
	if (c->curr_recovery_pass == ARRAY_SIZE(recovery_pass_fns))
		return -BCH_ERR_not_in_recovery;

	if (c->recovery_passes_complete & BIT_ULL(pass))
		return 0;

	bool print = !(c->opts.recovery_passes & BIT_ULL(pass));

	if (pass < BCH_RECOVERY_PASS_set_may_go_rw &&
	    c->curr_recovery_pass >= BCH_RECOVERY_PASS_set_may_go_rw) {
		if (print)
			prt_printf(out, "need recovery pass %s (%u), but already rw\n",
				   bch2_recovery_passes[pass], pass);
		return -BCH_ERR_cannot_rewind_recovery;
	}

	if (print)
		prt_printf(out, "running explicit recovery pass %s (%u), currently at %s (%u)\n",
			   bch2_recovery_passes[pass], pass,
			   bch2_recovery_passes[c->curr_recovery_pass], c->curr_recovery_pass);

	c->opts.recovery_passes |= BIT_ULL(pass);

	if (test_bit(BCH_FS_in_recovery, &c->flags) &&
	    c->curr_recovery_pass > pass) {
		c->next_recovery_pass = pass;
		c->recovery_passes_complete &= (1ULL << pass) >> 1;
		return -BCH_ERR_restart_recovery;
	} else {
		return 0;
	}
}

static int bch2_run_explicit_recovery_pass_printbuf(struct bch_fs *c,
				    struct printbuf *out,
				    enum bch_recovery_pass pass)
{
	bch2_printbuf_make_room(out, 1024);
	out->atomic++;

	unsigned long flags;
	spin_lock_irqsave(&c->recovery_pass_lock, flags);
	int ret = __bch2_run_explicit_recovery_pass(out, c, pass);
	spin_unlock_irqrestore(&c->recovery_pass_lock, flags);

	--out->atomic;
	return ret;
}

int bch2_run_explicit_recovery_pass(struct bch_fs *c,
				    enum bch_recovery_pass pass)
{
	struct printbuf buf = PRINTBUF;
	bch2_log_msg_start(c, &buf);
	unsigned len = buf.pos;

	int ret = bch2_run_explicit_recovery_pass_printbuf(c, &buf, pass);

	if (len != buf.pos)
		bch2_print_str(c, KERN_NOTICE, buf.buf);
	printbuf_exit(&buf);
	return ret;
}

int __bch2_run_explicit_recovery_pass_persistent(struct bch_fs *c,
						 struct printbuf *out,
						 enum bch_recovery_pass pass)
{
	lockdep_assert_held(&c->sb_lock);

	struct bch_sb_field_ext *ext = bch2_sb_field_get(c->disk_sb.sb, ext);
	__set_bit_le64(bch2_recovery_pass_to_stable(pass), ext->recovery_passes_required);

	return bch2_run_explicit_recovery_pass_printbuf(c, out, pass);
}

int bch2_run_explicit_recovery_pass_persistent(struct bch_fs *c,
					       struct printbuf *out,
					       enum bch_recovery_pass pass)
{
	if (c->sb.recovery_passes_required & BIT_ULL(pass))
		return 0;

	mutex_lock(&c->sb_lock);
	int ret = __bch2_run_explicit_recovery_pass_persistent(c, out, pass);
	mutex_unlock(&c->sb_lock);

	return ret;
}

u64 bch2_fsck_recovery_passes(void)
{
	u64 ret = 0;

	for (unsigned i = 0; i < ARRAY_SIZE(recovery_pass_fns); i++)
		if (recovery_pass_fns[i].when & PASS_FSCK)
			ret |= BIT_ULL(i);
	return ret;
}

static bool should_run_recovery_pass(struct bch_fs *c, enum bch_recovery_pass pass)
{
	struct recovery_pass_fn *p = recovery_pass_fns + pass;

	if ((p->when & PASS_ALLOC) && (c->sb.features & BIT_ULL(BCH_FEATURE_no_alloc_info)))
		return false;
	if (c->opts.recovery_passes_exclude & BIT_ULL(pass))
		return false;
	if (c->opts.recovery_passes & BIT_ULL(pass))
		return true;
	if ((p->when & PASS_FSCK) && c->opts.fsck)
		return true;
	if ((p->when & PASS_UNCLEAN) && !c->sb.clean)
		return true;
	if (p->when & PASS_ALWAYS)
		return true;
	return false;
}

static int bch2_run_recovery_pass(struct bch_fs *c, enum bch_recovery_pass pass)
{
	struct recovery_pass_fn *p = recovery_pass_fns + pass;

	if (!(p->when & PASS_SILENT))
		bch2_print(c, KERN_INFO bch2_log_msg(c, "%s..."),
			   bch2_recovery_passes[pass]);

	s64 start_time = ktime_get_real_seconds();
	int ret = p->fn(c);
	if (ret)
		return ret;

	if (!test_bit(BCH_FS_error, &c->flags))
		bch2_sb_recovery_pass_complete(c, pass, start_time);

	if (!(p->when & PASS_SILENT))
		bch2_print(c, KERN_CONT " done\n");

	return 0;
}

int bch2_run_online_recovery_passes(struct bch_fs *c)
{
	for (unsigned i = 0; i < ARRAY_SIZE(recovery_pass_fns); i++) {
		struct recovery_pass_fn *p = recovery_pass_fns + i;

		if (!(p->when & PASS_ONLINE))
			continue;

		int ret = bch2_run_recovery_pass(c, i);
		if (bch2_err_matches(ret, BCH_ERR_restart_recovery)) {
			i = c->curr_recovery_pass;
			continue;
		}
		if (ret)
			return ret;
	}

	return 0;
}

int bch2_run_recovery_passes(struct bch_fs *c)
{
	int ret = 0;

	/*
	 * We can't allow set_may_go_rw to be excluded; that would cause us to
	 * use the journal replay keys for updates where it's not expected.
	 */
	c->opts.recovery_passes_exclude &= ~BCH_RECOVERY_PASS_set_may_go_rw;

	down(&c->run_recovery_passes_lock);
	spin_lock_irq(&c->recovery_pass_lock);

	while (c->curr_recovery_pass < ARRAY_SIZE(recovery_pass_fns) && !ret) {
		unsigned prev_done = c->recovery_pass_done;
		unsigned pass = c->curr_recovery_pass;

		c->next_recovery_pass = pass + 1;

		if (c->opts.recovery_pass_last &&
		    c->curr_recovery_pass > c->opts.recovery_pass_last)
			break;

		if (should_run_recovery_pass(c, pass)) {
			spin_unlock_irq(&c->recovery_pass_lock);
			ret =   bch2_run_recovery_pass(c, pass) ?:
				bch2_journal_flush(&c->journal);
			spin_lock_irq(&c->recovery_pass_lock);

			if (c->next_recovery_pass < c->curr_recovery_pass) {
				/*
				 * bch2_run_explicit_recovery_pass() was called: we
				 * can't always catch -BCH_ERR_restart_recovery because
				 * it may have been called from another thread (btree
				 * node read completion)
				 */
				ret = 0;
				c->recovery_passes_complete &= ~(~0ULL << c->curr_recovery_pass);
			} else {
				c->recovery_passes_complete |= BIT_ULL(pass);
				c->recovery_pass_done = max(c->recovery_pass_done, pass);
			}
		}

		c->curr_recovery_pass = c->next_recovery_pass;

		if (prev_done <= BCH_RECOVERY_PASS_check_snapshots &&
		    c->recovery_pass_done > BCH_RECOVERY_PASS_check_snapshots) {
			bch2_copygc_wakeup(c);
			bch2_rebalance_wakeup(c);
		}
	}

	spin_unlock_irq(&c->recovery_pass_lock);
	up(&c->run_recovery_passes_lock);

	return ret;
}

void bch2_fs_recovery_passes_init(struct bch_fs *c)
{
	spin_lock_init(&c->recovery_pass_lock);
	sema_init(&c->run_recovery_passes_lock, 1);
}
