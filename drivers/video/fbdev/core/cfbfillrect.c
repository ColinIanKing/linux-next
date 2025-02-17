/*
 *  Generic fillrect for frame buffers with packed pixels of any depth.
 *
 *      Copyright (C)  2000 James Simmons (jsimmons@linux-fbdev.org)
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of this archive for
 *  more details.
 *
 */
#include <linux/module.h>
#include <linux/fb.h>
#include <asm/types.h>

#if BITS_PER_LONG == 32
#  define FB_WRITEL       fb_writel
#  define FB_READL        fb_readl
#else
#  define FB_WRITEL       fb_writeq
#  define FB_READL        fb_readq
#endif
#define FB_MEM            __iomem
#define FB_FILLRECT       cfb_fillrect
#define FB_FILLRECT_NAME  "cfb_fillrect"
#define FB_SPACE          0
#define FB_SPACE_NAME     "I/O"
#define FB_SCREEN_BASE(a) ((a)->screen_base)
#define FB_REV_PIXELS_IN_BYTE CONFIG_FB_CFB_REV_PIXELS_IN_BYTE
#include "fb_fillrect.h"

EXPORT_SYMBOL(cfb_fillrect);

MODULE_AUTHOR("James Simmons <jsimmons@users.sf.net>");
MODULE_DESCRIPTION("Generic software accelerated fill rectangle");
MODULE_LICENSE("GPL");
