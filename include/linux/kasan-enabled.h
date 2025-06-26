/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KASAN_ENABLED_H
#define _LINUX_KASAN_ENABLED_H

#include <linux/static_key.h>

#ifdef CONFIG_KASAN
/*
 * Global runtime flag. Starts ‘false’; switched to ‘true’ by
 * the appropriate kasan_init_*() once KASAN is fully initialized.
 */
DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
#endif

#ifdef CONFIG_KASAN_HW_TAGS

static __always_inline bool kasan_enabled(void)
{
	return static_branch_likely(&kasan_flag_enabled);
}

static inline bool kasan_hw_tags_enabled(void)
{
	return kasan_enabled();
}

#else /* CONFIG_KASAN_HW_TAGS */

static inline bool kasan_enabled(void)
{
	return IS_ENABLED(CONFIG_KASAN);
}

static inline bool kasan_hw_tags_enabled(void)
{
	return false;
}

#endif /* CONFIG_KASAN_HW_TAGS */

#endif /* LINUX_KASAN_ENABLED_H */
