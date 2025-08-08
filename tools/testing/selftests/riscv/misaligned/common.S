/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Rivos Inc.
 *
 * Authors:
 *     Clément Léger <cleger@rivosinc.com>
 */

.macro lb_sb temp, offset, src, dst
	lb \temp, \offset(\src)
	sb \temp, \offset(\dst)
.endm

.macro copy_long_to temp, src, dst
	lb_sb \temp, 0, \src, \dst,
	lb_sb \temp, 1, \src, \dst,
	lb_sb \temp, 2, \src, \dst,
	lb_sb \temp, 3, \src, \dst,
	lb_sb \temp, 4, \src, \dst,
	lb_sb \temp, 5, \src, \dst,
	lb_sb \temp, 6, \src, \dst,
	lb_sb \temp, 7, \src, \dst,
.endm

.macro sp_stack_prologue offset
	addi sp, sp, -8
	sub sp, sp, \offset
.endm

.macro sp_stack_epilogue offset
	add sp, sp, \offset
	addi sp, sp, 8
.endm
