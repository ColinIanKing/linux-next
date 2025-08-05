/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Rivos Inc.
 *
 * Authors:
 *     Clément Léger <cleger@rivosinc.com>
 */

#include "common.S"

.text

.macro __gen_test_inst inst, src_reg
	\inst a2, 0(\src_reg)
	move a0, a2
.endm

.macro gen_func_header func_name, rvc
	.option arch,\rvc
	.global test_\func_name
	test_\func_name:
.endm

.macro gen_test_inst inst
	.option push
	gen_func_header \inst, -c
	__gen_test_inst \inst, a0
	.option pop
	ret
.endm

.macro gen_test_lwu
	.option push
	gen_func_header lwu, -c
	__gen_test_inst lwu, a0
	.option pop
	# RISC-V ABI states that C expect a sign extended 32 bits integer
	sext.w a0, a0
	ret
.endm

.macro __gen_test_inst_c name, src_reg
	.option push
	gen_func_header c_\name, +c
	 __gen_test_inst c.\name, \src_reg
	.option pop
	ret
.endm

.macro gen_test_inst_c name
 	__gen_test_inst_c \name, a0
.endm


.macro gen_test_inst_c_ldsp
	.option push
	gen_func_header c_ldsp, +c
	sp_stack_prologue a1
	copy_long_to t0, a0, sp
	c.ldsp a0, 0(sp)
	sp_stack_epilogue a1
	.option pop
	ret
.endm

.macro lb_sp_sb_a0 reg, offset
	lb_sb \reg, \offset, sp, a0
.endm

.macro gen_test_inst_c_sdsp
	.option push
	gen_func_header c_sdsp, +c
	/* Misalign stack pointer */
	sp_stack_prologue a1
	/* Misalign access */
	c.sdsp a2, 0(sp)
	copy_long_to t0, sp, a0
	sp_stack_epilogue a1
	.option pop
	ret
.endm


 /*
 * a0 = addr to load from
 * a1 = address offset
 * a2 = value to be loaded
 */
gen_test_inst lh
gen_test_inst lhu
gen_test_inst lw
gen_test_lwu
gen_test_inst ld
#ifdef __riscv_compressed
gen_test_inst_c lw
gen_test_inst_c ld
gen_test_inst_c_ldsp
#endif

/*
 * a0 = addr where to store value
 * a1 = address offset
 * a2 = value to be stored
 */
gen_test_inst sh
gen_test_inst sw
gen_test_inst sd
#ifdef __riscv_compressed
gen_test_inst_c sw
gen_test_inst_c sd
gen_test_inst_c_sdsp
#endif

