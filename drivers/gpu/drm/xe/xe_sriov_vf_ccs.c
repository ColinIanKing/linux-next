// SPDX-License-Identifier: MIT
/*
 * Copyright © 2025 Intel Corporation
 */

#include "instructions/xe_mi_commands.h"
#include "instructions/xe_gpu_commands.h"
#include "xe_bb.h"
#include "xe_bo.h"
#include "xe_device.h"
#include "xe_exec_queue_types.h"
#include "xe_guc_submit.h"
#include "xe_lrc.h"
#include "xe_migrate.h"
#include "xe_sa.h"
#include "xe_sriov_printk.h"
#include "xe_sriov_vf_ccs.h"
#include "xe_sriov_vf_ccs_types.h"

/**
 * DOC: VF save/restore of compression Meta Data
 *
 * VF KMD registers two special contexts/LRCAs.
 *
 * Save Context/LRCA: contain necessary cmds+page table to trigger Meta data /
 * compression control surface (Aka CCS) save in regular System memory in VM.
 *
 * Restore Context/LRCA: contain necessary cmds+page table to trigger Meta data /
 * compression control surface (Aka CCS) Restore from regular System memory in
 * VM to corresponding CCS pool.
 *
 * Below diagram explain steps needed for VF save/Restore of compression Meta Data::
 *
 *    CCS Save    CCS Restore          VF KMD                          Guc       BCS
 *     LRCA        LRCA
 *      |           |                     |                              |         |
 *      |           |                     |                              |         |
 *      |     Create Save LRCA            |                              |         |
 *     [ ]<----------------------------- [ ]                             |         |
 *      |           |                     |                              |         |
 *      |           |                     |                              |         |
 *      |           |                     |       Register save LRCA     |         |
 *      |           |                     |           with Guc           |         |
 *      |           |                    [ ]--------------------------->[ ]        |
 *      |           |                     |                              |         |
 *      |           | Create restore LRCA |                              |         |
 *      |          [ ]<------------------[ ]                             |         |
 *      |           |                     |                              |         |
 *      |           |                     |       Register restore LRCA  |         |
 *      |           |                     |           with Guc           |         |
 *      |           |                    [ ]--------------------------->[ ]        |
 *      |           |                     |                              |         |
 *      |           |                     |                              |         |
 *      |           |                    [ ]-------------------------    |         |
 *      |           |                    [ ]  Allocate main memory.  |   |         |
 *      |           |                    [ ]  Allocate CCS memory.   |   |         |
 *      |           |                    [ ]  Update Main memory &   |   |         |
 *     [ ]<------------------------------[ ]  CCS pages PPGTT + BB   |   |         |
 *      |          [ ]<------------------[ ]  cmds to save & restore.|   |         |
 *      |           |                    [ ]<------------------------    |         |
 *      |           |                     |                              |         |
 *      |           |                     |                              |         |
 *      |           |                     |                              |         |
 *      :           :                     :                              :         :
 *      ---------------------------- VF Paused -------------------------------------
 *      |           |                     |                              |         |
 *      |           |                     |                              |         |
 *      |           |                     |                              |Schedule |
 *      |           |                     |                              |CCS Save |
 *      |           |                     |                              | LRCA    |
 *      |           |                     |                             [ ]------>[ ]
 *      |           |                     |                              |         |
 *      |           |                     |                              |         |
 *      |           |                     |                              |CCS save |
 *      |           |                     |                              |completed|
 *      |           |                     |                             [ ]<------[ ]
 *      |           |                     |                              |         |
 *      :           :                     :                              :         :
 *      ---------------------------- VM Migrated -----------------------------------
 *      |           |                     |                              |         |
 *      |           |                     |                              |         |
 *      :           :                     :                              :         :
 *      ---------------------------- VF Resumed ------------------------------------
 *      |           |                     |                              |         |
 *      |           |                     |                              |         |
 *      |           |                    [ ]--------------               |         |
 *      |           |                    [ ] Fix up GGTT  |              |         |
 *      |           |                    [ ]<-------------               |         |
 *      |           |                     |                              |         |
 *      |           |                     |                              |         |
 *      |           |                     |  Notify VF_RESFIX_DONE       |         |
 *      |           |                    [ ]--------------------------->[ ]        |
 *      |           |                     |                              |         |
 *      |           |                     |                              |Schedule |
 *      |           |                     |                              |CCS      |
 *      |           |                     |                              |Restore  |
 *      |           |                     |                              |LRCA     |
 *      |           |                     |                             [ ]------>[ ]
 *      |           |                     |                              |         |
 *      |           |                     |                              |         |
 *      |           |                     |                              |CCS      |
 *      |           |                     |                              |restore  |
 *      |           |                     |                              |completed|
 *      |           |                     |                             [ ]<------[ ]
 *      |           |                     |                              |         |
 *      |           |                     |                              |         |
 *      |           |                     |  VF_RESFIX_DONE complete     |         |
 *      |           |                     |       notification           |         |
 *      |           |                    [ ]<---------------------------[ ]        |
 *      |           |                     |                              |         |
 *      |           |                     |                              |         |
 *      :           :                     :                              :         :
 *      ------------------------- Continue VM restore ------------------------------
 */

static u64 get_ccs_bb_pool_size(struct xe_device *xe)
{
	u64 sys_mem_size, ccs_mem_size, ptes, bb_pool_size;
	struct sysinfo si;

	si_meminfo(&si);
	sys_mem_size = si.totalram * si.mem_unit;
	ccs_mem_size = div64_u64(sys_mem_size, NUM_BYTES_PER_CCS_BYTE(xe));
	ptes = DIV_ROUND_UP_ULL(sys_mem_size + ccs_mem_size, XE_PAGE_SIZE);

	/**
	 * We need below BB size to hold PTE mappings and some DWs for copy
	 * command. In reality, we need space for many copy commands. So, let
	 * us allocate double the calculated size which is enough to holds GPU
	 * instructions for the whole region.
	 */
	bb_pool_size = ptes * sizeof(u32);

	return round_up(bb_pool_size * 2, SZ_1M);
}

static int alloc_bb_pool(struct xe_tile *tile, struct xe_tile_vf_ccs *ctx)
{
	struct xe_device *xe = tile_to_xe(tile);
	struct xe_sa_manager *sa_manager;
	u64 bb_pool_size;
	int offset, err;

	bb_pool_size = get_ccs_bb_pool_size(xe);
	xe_sriov_info(xe, "Allocating %s CCS BB pool size = %lldMB\n",
		      ctx->ctx_id ? "Restore" : "Save", bb_pool_size / SZ_1M);

	sa_manager = xe_sa_bo_manager_init(tile, bb_pool_size, SZ_16);

	if (IS_ERR(sa_manager)) {
		xe_sriov_err(xe, "Suballocator init failed with error: %pe\n",
			     sa_manager);
		err = PTR_ERR(sa_manager);
		return err;
	}

	offset = 0;
	xe_map_memset(xe, &sa_manager->bo->vmap, offset, MI_NOOP,
		      bb_pool_size);

	offset = bb_pool_size - sizeof(u32);
	xe_map_wr(xe, &sa_manager->bo->vmap, offset, u32, MI_BATCH_BUFFER_END);

	ctx->mem.ccs_bb_pool = sa_manager;

	return 0;
}

static void ccs_rw_update_ring(struct xe_tile_vf_ccs *ctx)
{
	struct xe_lrc *lrc = xe_migrate_lrc(ctx->migrate);
	u64 addr = ctx->mem.ccs_bb_pool->gpu_addr;
	u32 dw[10], i = 0;

	dw[i++] = MI_ARB_ON_OFF | MI_ARB_ENABLE;
	dw[i++] = MI_BATCH_BUFFER_START | XE_INSTR_NUM_DW(3);
	dw[i++] = lower_32_bits(addr);
	dw[i++] = upper_32_bits(addr);
	dw[i++] = MI_NOOP;
	dw[i++] = MI_NOOP;

	xe_lrc_write_ring(lrc, dw, i * sizeof(u32));
	xe_lrc_set_ring_tail(lrc, lrc->ring.tail);
}

static int register_save_restore_context(struct xe_migrate *m,
					 enum xe_sriov_vf_ccs_rw_ctxs ctx_id)
{
	int err = -EINVAL;
	int ctx_type;

	switch (ctx_id) {
	case XE_SRIOV_VF_CCS_READ_CTX:
		ctx_type = GUC_CONTEXT_COMPRESSION_SAVE;
		break;
	case XE_SRIOV_VF_CCS_WRITE_CTX:
		ctx_type = GUC_CONTEXT_COMPRESSION_RESTORE;
		break;
	default:
		return err;
	}

	xe_guc_register_exec_queue(xe_migrate_exec_queue(m), ctx_type);
	return 0;
}

/**
 * xe_sriov_vf_ccs_register_context - Register read/write contexts with guc.
 * @xe: the &xe_device to register contexts on.
 *
 * This function registers read and write contexts with Guc. Re-registration
 * is needed whenever resuming from pm runtime suspend.
 *
 * Return: 0 on success. Negative error code on failure.
 */
int xe_sriov_vf_ccs_register_context(struct xe_device *xe)
{
	struct xe_tile *tile = xe_device_get_root_tile(xe);
	enum xe_sriov_vf_ccs_rw_ctxs ctx_id;
	struct xe_tile_vf_ccs *ctx;
	int err;

	if (!IS_VF_CCS_READY(xe))
		return 0;

	for_each_ccs_rw_ctx(ctx_id) {
		ctx = &tile->sriov.vf.ccs[ctx_id];
		err = register_save_restore_context(ctx->migrate, ctx_id);
		if (err)
			return err;
	}

	return err;
}

static void xe_sriov_vf_ccs_fini(void *arg)
{
	struct xe_tile_vf_ccs *ctx = arg;
	struct xe_lrc *lrc = xe_migrate_lrc(ctx->migrate);

	/*
	 * Make TAIL = HEAD in the ring so that no issues are seen if Guc
	 * submits this context to HW on VF pause after unbinding device.
	 */
	xe_lrc_set_ring_tail(lrc, xe_lrc_ring_head(lrc));
}

/**
 * xe_sriov_vf_ccs_init - Setup LRCA for save & restore.
 * @xe: the &xe_device to start recovery on
 *
 * This function shall be called only by VF. It initializes
 * LRCA and suballocator needed for CCS save & restore.
 *
 * Return: 0 on success. Negative error code on failure.
 */
int xe_sriov_vf_ccs_init(struct xe_device *xe)
{
	struct xe_tile *tile = xe_device_get_root_tile(xe);
	enum xe_sriov_vf_ccs_rw_ctxs ctx_id;
	struct xe_migrate *migrate;
	struct xe_tile_vf_ccs *ctx;
	int err;

	xe_assert(xe, IS_SRIOV_VF(xe));
	xe_assert(xe, !IS_DGFX(xe));
	xe_assert(xe, xe_device_has_flat_ccs(xe));

	for_each_ccs_rw_ctx(ctx_id) {
		ctx = &tile->sriov.vf.ccs[ctx_id];
		ctx->ctx_id = ctx_id;

		migrate = xe_migrate_init(tile);
		if (IS_ERR(migrate)) {
			err = PTR_ERR(migrate);
			goto err_ret;
		}
		ctx->migrate = migrate;

		err = alloc_bb_pool(tile, ctx);
		if (err)
			goto err_ret;

		ccs_rw_update_ring(ctx);

		err = register_save_restore_context(ctx->migrate, ctx_id);
		if (err)
			goto err_ret;

		err = devm_add_action_or_reset(xe->drm.dev,
					       xe_sriov_vf_ccs_fini,
					       ctx);
	}

	xe->sriov.vf.ccs.initialized = 1;

	return 0;

err_ret:
	return err;
}

/**
 * xe_sriov_vf_ccs_attach_bo - Insert CCS read write commands in the BO.
 * @bo: the &buffer object to which batch buffer commands will be added.
 *
 * This function shall be called only by VF. It inserts the PTEs and copy
 * command instructions in the BO by calling xe_migrate_ccs_rw_copy()
 * function.
 *
 * Returns: 0 if successful, negative error code on failure.
 */
int xe_sriov_vf_ccs_attach_bo(struct xe_bo *bo)
{
	struct xe_device *xe = xe_bo_device(bo);
	enum xe_sriov_vf_ccs_rw_ctxs ctx_id;
	struct xe_migrate *migrate;
	struct xe_tile *tile;
	struct xe_bb *bb;
	int err = 0;

	if (!IS_VF_CCS_READY(xe))
		return 0;

	tile = xe_device_get_root_tile(xe);

	for_each_ccs_rw_ctx(ctx_id) {
		bb = bo->bb_ccs[ctx_id];
		/* bb should be NULL here. Assert if not NULL */
		xe_assert(xe, !bb);

		migrate = tile->sriov.vf.ccs[ctx_id].migrate;
		err = xe_migrate_ccs_rw_copy(migrate, bo, ctx_id);
	}
	return err;
}

/**
 * xe_sriov_vf_ccs_detach_bo - Remove CCS read write commands from the BO.
 * @bo: the &buffer object from which batch buffer commands will be removed.
 *
 * This function shall be called only by VF. It removes the PTEs and copy
 * command instructions from the BO. Make sure to update the BB with MI_NOOP
 * before freeing.
 *
 * Returns: 0 if successful.
 */
int xe_sriov_vf_ccs_detach_bo(struct xe_bo *bo)
{
	struct xe_device *xe = xe_bo_device(bo);
	enum xe_sriov_vf_ccs_rw_ctxs ctx_id;
	struct xe_bb *bb;

	if (!IS_VF_CCS_READY(xe))
		return 0;

	for_each_ccs_rw_ctx(ctx_id) {
		bb = bo->bb_ccs[ctx_id];
		if (!bb)
			continue;

		memset(bb->cs, MI_NOOP, bb->len * sizeof(u32));
		xe_bb_free(bb, NULL);
		bo->bb_ccs[ctx_id] = NULL;
	}
	return 0;
}
