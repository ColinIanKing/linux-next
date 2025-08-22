// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, Microsoft Corporation.
 *
 * This file contains functions that will be called from one or more modules.
 * If any of these modules are configured to build, this file is built and just
 * statically linked in.
 *
 * Authors: Microsoft Linux virtualization team
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/mshyperv.h>
#include <linux/resume_user_mode.h>
#include <linux/export.h>

#include "mshv.h"

int hv_call_get_vp_registers(u32 vp_index, u64 partition_id, u16 count,
			     union hv_input_vtl input_vtl,
			     struct hv_register_assoc *registers)
{
	struct hv_input_get_vp_registers *input_page;
	union hv_register_value *output_page;
	u16 completed = 0;
	unsigned long batch_size, remaining = count;
	int rep_count, i;
	u64 status = HV_STATUS_SUCCESS;
	unsigned long flags;

	local_irq_save(flags);

	batch_size = hv_setup_inout_array(&input_page, sizeof(*input_page),
			      sizeof(input_page->names[0]),
			      &output_page, 0, sizeof(*output_page));

	input_page->partition_id = partition_id;
	input_page->vp_index = vp_index;
	input_page->input_vtl.as_uint8 = input_vtl.as_uint8;

	while (remaining) {
		rep_count = min(remaining, batch_size);
		for (i = 0; i < rep_count; ++i)
			input_page->names[i] = registers[i].name;

		status = hv_do_rep_hypercall(HVCALL_GET_VP_REGISTERS, rep_count,
					     0, input_page, output_page);
		if (!hv_result_success(status))
			break;

		completed = hv_repcomp(status);
		for (i = 0; i < completed; ++i)
			registers[i].value = output_page[i];

		registers += completed;
		remaining -= completed;
	}
	local_irq_restore(flags);

	return hv_result_to_errno(status);
}
EXPORT_SYMBOL_GPL(hv_call_get_vp_registers);

int hv_call_set_vp_registers(u32 vp_index, u64 partition_id, u16 count,
			     union hv_input_vtl input_vtl,
			     struct hv_register_assoc *registers)
{
	struct hv_input_set_vp_registers *input_page;
	u16 completed = 0;
	unsigned long remaining = count;
	unsigned long rep_count, batch_size;
	u64 status = HV_STATUS_SUCCESS;
	unsigned long flags;

	local_irq_save(flags);
	batch_size = hv_setup_in_array(&input_page, sizeof(*input_page),
			sizeof(input_page->elements[0]));
	input_page->partition_id = partition_id;
	input_page->vp_index = vp_index;
	input_page->input_vtl.as_uint8 = input_vtl.as_uint8;

	while (remaining) {
		rep_count = min(remaining, batch_size);
		memcpy(input_page->elements, registers,
		       sizeof(struct hv_register_assoc) * rep_count);

		status = hv_do_rep_hypercall(HVCALL_SET_VP_REGISTERS, rep_count,
					     0, input_page, NULL);
		if (!hv_result_success(status))
			break;

		completed = hv_repcomp(status);
		registers += completed;
		remaining -= completed;
	}

	local_irq_restore(flags);

	return hv_result_to_errno(status);
}
EXPORT_SYMBOL_GPL(hv_call_set_vp_registers);

int hv_call_get_partition_property(u64 partition_id,
				   u64 property_code,
				   u64 *property_value)
{
	u64 status;
	unsigned long flags;
	struct hv_input_get_partition_property *input;
	struct hv_output_get_partition_property *output;

	local_irq_save(flags);
	hv_setup_inout(&input, sizeof(*input), &output, sizeof(*output));
	input->partition_id = partition_id;
	input->property_code = property_code;
	status = hv_do_hypercall(HVCALL_GET_PARTITION_PROPERTY, input, output);

	if (!hv_result_success(status)) {
		local_irq_restore(flags);
		return hv_result_to_errno(status);
	}
	*property_value = output->property_value;

	local_irq_restore(flags);

	return 0;
}
EXPORT_SYMBOL_GPL(hv_call_get_partition_property);

/*
 * Handle any pre-processing before going into the guest mode on this cpu, most
 * notably call schedule(). Must be invoked with both preemption and
 * interrupts enabled.
 *
 * Returns: 0 on success, -errno on error.
 */
int mshv_do_pre_guest_mode_work(ulong th_flags)
{
	if (th_flags & (_TIF_SIGPENDING | _TIF_NOTIFY_SIGNAL))
		return -EINTR;

	if (th_flags & _TIF_NEED_RESCHED)
		schedule();

	if (th_flags & _TIF_NOTIFY_RESUME)
		resume_user_mode_work(NULL);

	return 0;
}
EXPORT_SYMBOL_GPL(mshv_do_pre_guest_mode_work);
