/* SPDX-License-Identifier: GPL-2.0 */
#ifdef CONFIG_64BIT
#undef CONFIG_X86_32
#else
#define CONFIG_X86_32 1
#endif

#include <asm/cpufeature.h>
#include <../x86/xor_arch.h>
