/*
 *  Generic BitBLT function for frame buffer with packed pixels of any depth.
 *
 *      Copyright (C)  June 1999 James Simmons
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of this archive for
 *  more details.
 *
 */
#include <linux/module.h>
#include <linux/fb.h>
#include <asm/types.h>

#define FB_WRITEL         fb_writel
#define FB_READL          fb_readl
#define FB_MEM            __iomem
#define FB_IMAGEBLIT      cfb_imageblit
#define FB_SPACE          0
#define FB_SPACE_NAME     "I/O"
#define FB_SCREEN_BASE(a) ((a)->screen_base)
#define FB_REV_PIXELS_IN_BYTE CONFIG_FB_CFB_REV_PIXELS_IN_BYTE
#include "fb_imageblit.h"

EXPORT_SYMBOL(cfb_imageblit);

MODULE_AUTHOR("James Simmons <jsimmons@users.sf.net>");
MODULE_DESCRIPTION("Generic software accelerated imaging drawing");
MODULE_LICENSE("GPL");
