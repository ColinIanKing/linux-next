/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NLS_TYPES_H
#define _LINUX_NLS_TYPES_H

#include <linux/types.h>

/*
 * Unicode has changed over the years.  Unicode code points no longer
 * fit into 16 bits; as of Unicode 5 valid code points range from 0
 * to 0x10ffff (17 planes, where each plane holds 65536 code points).
 *
 * The original decision to represent Unicode characters as 16-bit
 * wchar_t values is now outdated.  But plane 0 still includes the
 * most commonly used characters, so we will retain it.  The newer
 * 32-bit unicode_t type can be used when it is necessary to
 * represent the full Unicode character set.
 */

/* Plane-0 Unicode character */
typedef u16 wchar_t;
#define MAX_WCHAR_T	0xffff

/* Arbitrary Unicode character */
typedef u32 unicode_t;

#endif /* _LINUX_NLS_TYPES_H */
