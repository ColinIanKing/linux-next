/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright(c) Advanced Micro Devices, Inc */

/*
 * fwctl interface info for pds_fwctl
 */

#ifndef _UAPI_FWCTL_PDS_H_
#define _UAPI_FWCTL_PDS_H_

#include <linux/types.h>

/*
 * struct fwctl_info_pds
 *
 * Return basic information about the FW interface available.
 */
struct fwctl_info_pds {
	__u32 uctx_caps;
};

enum pds_fwctl_capabilities {
	PDS_FWCTL_QUERY_CAP = 0,
	PDS_FWCTL_SEND_CAP,
};

struct fwctl_rpc_pds {
	struct {
		__u32 op;
		__u32 ep;
		__u32 rsvd;
		__u32 len;
		__aligned_u64 payload;
	} in;
	struct {
		__u32 retval;
		__u32 rsvd[2];
		__u32 len;
		__aligned_u64 payload;
	} out;
};
#endif /* _UAPI_FWCTL_PDS_H_ */
