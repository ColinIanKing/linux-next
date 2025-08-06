/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2025 Rivos Inc.
 *
 * Authors:
 *     Clément Léger <cleger@rivosinc.com>
 */

#include "common.S"

#define CASE_ALIGN		4

.macro fpu_load_inst fpreg, inst, precision, load_reg
.align CASE_ALIGN
	\inst \fpreg, 0(\load_reg)
	fmv.\precision fa0, \fpreg
	j 2f
.endm

#define flw(__fpreg) fpu_load_inst __fpreg, flw, s, a4
#define fld(__fpreg) fpu_load_inst __fpreg, fld, d, a4
#define c_flw(__fpreg) fpu_load_inst __fpreg, c.flw, s, a4
#define c_fld(__fpreg) fpu_load_inst __fpreg, c.fld, d, a4
#define c_fldsp(__fpreg) fpu_load_inst __fpreg, c.fldsp, d, sp

.macro fpu_store_inst fpreg, inst, precision, store_reg
.align CASE_ALIGN
	fmv.\precision \fpreg, fa0
	\inst \fpreg, 0(\store_reg)
	j 2f
.endm

#define fsw(__fpreg) fpu_store_inst __fpreg, fsw, s, a4
#define fsd(__fpreg) fpu_store_inst __fpreg, fsd, d, a4
#define c_fsw(__fpreg) fpu_store_inst __fpreg, c.fsw, s, a4
#define c_fsd(__fpreg) fpu_store_inst __fpreg, c.fsd, d, a4
#define c_fsdsp(__fpreg) fpu_store_inst __fpreg, c.fsdsp, d, sp

.macro fp_test_prologue
	move a4, a1
	/*
	 * Compute jump offset to store the correct FP register since we don't
	 * have indirect FP register access (or at least we don't use this
	 * extension so that works on all archs)
	 */
	sll t0, a0, CASE_ALIGN
	la t2, 1f
	add t0, t0, t2
	jr t0
.align	CASE_ALIGN
1:
.endm

.macro fp_test_prologue_compressed
	/* FP registers for compressed instructions starts from 8 to 16 */
	addi a0, a0, -8
	fp_test_prologue
.endm

#define fp_test_body_compressed(__inst_func) \
	__inst_func(f8); \
	__inst_func(f9); \
	__inst_func(f10); \
	__inst_func(f11); \
	__inst_func(f12); \
	__inst_func(f13); \
	__inst_func(f14); \
	__inst_func(f15); \
2:

#define fp_test_body(__inst_func) \
	__inst_func(f0); \
	__inst_func(f1); \
	__inst_func(f2); \
	__inst_func(f3); \
	__inst_func(f4); \
	__inst_func(f5); \
	__inst_func(f6); \
	__inst_func(f7); \
	__inst_func(f8); \
	__inst_func(f9); \
	__inst_func(f10); \
	__inst_func(f11); \
	__inst_func(f12); \
	__inst_func(f13); \
	__inst_func(f14); \
	__inst_func(f15); \
	__inst_func(f16); \
	__inst_func(f17); \
	__inst_func(f18); \
	__inst_func(f19); \
	__inst_func(f20); \
	__inst_func(f21); \
	__inst_func(f22); \
	__inst_func(f23); \
	__inst_func(f24); \
	__inst_func(f25); \
	__inst_func(f26); \
	__inst_func(f27); \
	__inst_func(f28); \
	__inst_func(f29); \
	__inst_func(f30); \
	__inst_func(f31); \
2:
.text

#define __gen_test_inst(__inst, __suffix) \
.global test_ ## __inst; \
test_ ## __inst:; \
	fp_test_prologue ## __suffix; \
	fp_test_body ## __suffix(__inst); \
	ret

#define gen_test_inst_compressed(__inst) \
	.option arch,+c; \
	__gen_test_inst(c_ ## __inst, _compressed)

#define gen_test_inst(__inst) \
	.balign 16; \
	.option push; \
	.option arch,-c; \
	__gen_test_inst(__inst, ); \
	.option pop

.macro fp_test_prologue_load_compressed_sp
	copy_long_to t0, a1, sp
.endm

.macro fp_test_epilogue_load_compressed_sp
.endm

.macro fp_test_prologue_store_compressed_sp
.endm

.macro fp_test_epilogue_store_compressed_sp
	copy_long_to t0, sp, a1
.endm

#define gen_inst_compressed_sp(__inst, __type) \
	.global test_c_ ## __inst ## sp; \
	test_c_ ## __inst ## sp:; \
		sp_stack_prologue a2; \
		fp_test_prologue_## __type ## _compressed_sp; \
		fp_test_prologue_compressed; \
		fp_test_body_compressed(c_ ## __inst ## sp); \
		fp_test_epilogue_## __type ## _compressed_sp; \
		sp_stack_epilogue a2; \
		ret

#define gen_test_load_compressed_sp(__inst) gen_inst_compressed_sp(__inst, load)
#define gen_test_store_compressed_sp(__inst) gen_inst_compressed_sp(__inst, store)

/*
 * float_fsw_reg - Set a FP register from a register containing the value
 * a0 = FP register index to be set
 * a1 = addr where to store register value
 * a2 = address offset
 * a3 = value to be store
 */
gen_test_inst(fsw)

/*
 * float_flw_reg - Get a FP register value and return it
 * a0 = FP register index to be retrieved
 * a1 = addr to load register from
 * a2 = address offset
 */
gen_test_inst(flw)

gen_test_inst(fsd)
#ifdef __riscv_compressed
gen_test_inst_compressed(fsd)
gen_test_store_compressed_sp(fsd)
#endif

gen_test_inst(fld)
#ifdef __riscv_compressed
gen_test_inst_compressed(fld)
gen_test_load_compressed_sp(fld)
#endif
