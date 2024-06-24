/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LINUX_PLATFORM_DATA_RCAR_FUSE_H__
#define __LINUX_PLATFORM_DATA_RCAR_FUSE_H__

struct rcar_fuse_platform_data {
	void __iomem *base;
	unsigned int offset;
	unsigned int nregs;
};

#endif /* __LINUX_PLATFORM_DATA_RCAR_FUSE_H__ */
