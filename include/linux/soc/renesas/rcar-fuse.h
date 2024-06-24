/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LINUX_SOC_RENESAS_RCAR_FUSE_H__
#define __LINUX_SOC_RENESAS_RCAR_FUSE_H__

#define RCAR_FUSE_MON0		0
#define RCAR_FUSE_MON1		1
#define RCAR_FUSE_MON2		2
#define RCAR_FUSE_MON3		3
#define RCAR_FUSE_MON4		4
#define RCAR_FUSE_MON5		5
#define RCAR_FUSE_MON6		6
#define RCAR_FUSE_MON7		7
#define RCAR_FUSE_MON8		8
#define RCAR_FUSE_MON9		9

#define RCAR_LTM0_MON0		32
#define RCAR_LTM0_MON1		33
#define RCAR_LTM0_MON2		34

#define RCAR_OTPMONITOR0	0
#define RCAR_OTPMONITOR3	3
#define RCAR_OTPMONITOR28	28
#define RCAR_OTPMONITOR32	32
#define RCAR_OTPMONITOR33	33
#define RCAR_OTPMONITOR34	34
#define RCAR_OTPMONITOR35	35
#define RCAR_OTPMONITOR36	36
#define RCAR_OTPMONITOR37	37
#define RCAR_OTPMONITOR38	38
#define RCAR_OTPMONITOR39	39

#if IS_ENABLED(CONFIG_FUSE_RCAR)
int rcar_fuse_read(unsigned int idx, u32 *val);
#else
static inline int rcar_fuse_read(unsigned int idx, u32 *val)
{
	return -ENODEV;
}
#endif

#endif /* __LINUX_SOC_RENESAS_RCAR_FUSE_H__ */
