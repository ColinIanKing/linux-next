// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2023 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

#define __prel64_initconst	__section(".init.rodata.prel64")

typedef volatile signed long prel64_t;

static inline void *prel64_to_pointer(const prel64_t *offset)
{
	if (!*offset)
		return NULL;
	return (void *)offset + *offset;
}
