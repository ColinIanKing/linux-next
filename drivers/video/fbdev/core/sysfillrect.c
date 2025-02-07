/*
 *  Generic fillrect for frame buffers in system RAM with packed pixels of
 *  any depth.
 *
 *  Based almost entirely from cfbfillrect.c (which is based almost entirely
 *  on Geert Uytterhoeven's fillrect routine)
 *
 *      Copyright (C)  2007 Antonino Daplas <adaplas@pol.net>
 *
 *  This file is subject to the terms and conditions of the GNU General Public
 *  License.  See the file COPYING in the main directory of this archive for
 *  more details.
 */
#include <linux/module.h>
#include <linux/fb.h>
#include <asm/types.h>

#define FB_READL(a)       (*a)
#define FB_WRITEL(a,b)    do { *(b) = (a); } while (false)
#define FB_MEM            /* nothing */
#define FB_FILLRECT       sys_fillrect
#define FB_FILLRECT_NAME  "sys_fillrect"
#define FB_SPACE          FBINFO_VIRTFB
#define FB_SPACE_NAME     "virtual"
#define FB_SCREEN_BASE(a) ((a)->screen_buffer)
#define FB_REV_PIXELS_IN_BYTE CONFIG_FB_SYS_REV_PIXELS_IN_BYTE
#include "fb_fillrect.h"

EXPORT_SYMBOL(sys_fillrect);

MODULE_AUTHOR("Antonino Daplas <adaplas@pol.net>");
MODULE_DESCRIPTION("Generic fill rectangle (sys-to-sys)");
MODULE_LICENSE("GPL");
