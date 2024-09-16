/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2024, Broadcom Corporation
 *
 */
#ifndef _UAPI_FWCTL_BNXT_H_
#define _UAPI_FWCTL_BNXT_H_

#include <linux/types.h>

enum fwctl_bnxt_commands {
	FWCTL_BNXT_QUERY_COMMANDS = 0,
	FWCTL_BNXT_SEND_COMMAND,
};

/**
 * struct fwctl_info_bnxt - ioctl(FWCTL_INFO) out_device_data
 * @uctx_caps: The command capabilities driver accepts.
 *
 * Return basic information about the FW interface available.
 */
struct fwctl_info_bnxt {
	__u32 uctx_caps;
	__u32 reserved;
};

#endif
