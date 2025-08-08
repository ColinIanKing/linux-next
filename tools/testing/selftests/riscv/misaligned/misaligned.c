// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2025 Rivos Inc.
 *
 * Authors:
 *     Clément Léger <cleger@rivosinc.com>
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/ptrace.h>
#include "../../kselftest_harness.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <float.h>
#include <errno.h>
#include <math.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <inttypes.h>
#include <ucontext.h>

#include <sys/prctl.h>

#define stringify(s) __stringify(s)
#define __stringify(s) #s

#define U8_MAX		((u8)~0U)
#define S8_MAX		((s8)(U8_MAX >> 1))
#define S8_MIN		((s8)(-S8_MAX - 1))
#define U16_MAX		((u16)~0U)
#define S16_MAX		((s16)(U16_MAX >> 1))
#define S16_MIN		((s16)(-S16_MAX - 1))
#define U32_MAX		((u32)~0U)
#define U32_MIN		((u32)0)
#define S32_MAX		((s32)(U32_MAX >> 1))
#define S32_MIN		((s32)(-S32_MAX - 1))
#define U64_MAX		((u64)~0ULL)
#define S64_MAX		((s64)(U64_MAX >> 1))
#define S64_MIN		((s64)(-S64_MAX - 1))

#define int16_TEST_VALUES	{S16_MIN, S16_MIN/2, -1, 1, S16_MAX/2, S16_MAX}
#define int32_TEST_VALUES	{S32_MIN, S32_MIN/2, -1, 1, S32_MAX/2, S32_MAX}
#define int64_TEST_VALUES	{S64_MIN, S64_MIN/2, -1, 1, S64_MAX/2, S64_MAX}
#define uint16_TEST_VALUES	{0, U16_MAX/2, U16_MAX}
#define uint32_TEST_VALUES	{0, U32_MAX/2, U32_MAX}

#define float_TEST_VALUES	{FLT_MIN, FLT_MIN/2, FLT_MAX/2, FLT_MAX}
#define double_TEST_VALUES	{DBL_MIN, DBL_MIN/2, DBL_MAX/2, DBL_MAX}

static bool float_equal(float a, float b)
{
	float scaled_epsilon;
	float difference = fabsf(a - b);

	// Scale to the largest value.
	a = fabsf(a);
	b = fabsf(b);
	if (a > b)
		scaled_epsilon = FLT_EPSILON * a;
	else
		scaled_epsilon = FLT_EPSILON * b;

	return difference <= scaled_epsilon;
}

static bool double_equal(double a, double b)
{
	double scaled_epsilon;
	double difference = fabsl(a - b);

	// Scale to the largest value.
	a = fabs(a);
	b = fabs(b);
	if (a > b)
		scaled_epsilon = DBL_EPSILON * a;
	else
		scaled_epsilon = DBL_EPSILON * b;

	return difference <= scaled_epsilon;
}

#define fpu_load_proto(__inst, __type) \
extern __type test_ ## __inst(unsigned long fp_reg, void *addr, unsigned long offset, __type value)

fpu_load_proto(flw, float);
fpu_load_proto(fld, double);
fpu_load_proto(c_flw, float);
fpu_load_proto(c_fld, double);
fpu_load_proto(c_fldsp, double);

#define fpu_store_proto(__inst, __type) \
extern void test_ ## __inst(unsigned long fp_reg, void *addr, unsigned long offset, __type value)

fpu_store_proto(fsw, float);
fpu_store_proto(fsd, double);
fpu_store_proto(c_fsw, float);
fpu_store_proto(c_fsd, double);
fpu_store_proto(c_fsdsp, double);

#define gp_load_proto(__inst, __type) \
extern __type test_ ## __inst(void *addr, unsigned long offset, __type value)

gp_load_proto(lh, int16_t);
gp_load_proto(lhu, uint16_t);
gp_load_proto(lw, int32_t);
gp_load_proto(lwu, uint32_t);
gp_load_proto(ld, int64_t);
gp_load_proto(c_lw, int32_t);
gp_load_proto(c_ld, int64_t);
gp_load_proto(c_ldsp, int64_t);

#define gp_store_proto(__inst, __type) \
extern void test_ ## __inst(void *addr, unsigned long offset, __type value)

gp_store_proto(sh, int16_t);
gp_store_proto(sw, int32_t);
gp_store_proto(sd, int64_t);
gp_store_proto(c_sw, int32_t);
gp_store_proto(c_sd, int64_t);
gp_store_proto(c_sdsp, int64_t);

#define TEST_GP_LOAD(__inst, __type_size, __type)					\
TEST(gp_load_ ## __inst)								\
{											\
	int offset, ret, val_i;								\
	uint8_t buf[16] __attribute__((aligned(16)));					\
	__type ## __type_size ## _t test_val[] = __type ## __type_size ## _TEST_VALUES;	\
											\
	ret = prctl(PR_SET_UNALIGN, PR_UNALIGN_NOPRINT);				\
	ASSERT_EQ(ret, 0);								\
											\
	for (offset = 1; offset < (__type_size) / 8; offset++) {			\
		for (val_i = 0; val_i < ARRAY_SIZE(test_val); val_i++) {		\
			__type ## __type_size ## _t ref_val = test_val[val_i];		\
			__type ## __type_size ## _t *ptr =				\
					(__type ## __type_size ## _t *)(buf + offset);	\
			memcpy(ptr, &ref_val, sizeof(ref_val));				\
			__type ## __type_size ## _t val =				\
						test_ ## __inst(ptr, offset, ref_val);	\
			EXPECT_EQ(ref_val, val);					\
		}									\
	}										\
}

TEST_GP_LOAD(lh, 16, int)
TEST_GP_LOAD(lhu, 16, uint)
TEST_GP_LOAD(lw, 32, int)
TEST_GP_LOAD(lwu, 32, uint)
TEST_GP_LOAD(ld, 64, int)
#ifdef __riscv_compressed
TEST_GP_LOAD(c_lw, 32, int)
TEST_GP_LOAD(c_ld, 64, int)
TEST_GP_LOAD(c_ldsp, 64, int)
#endif

#define TEST_GP_STORE(__inst, __type_size, __type)				\
TEST(gp_store_ ## __inst)							\
{										\
	int offset, ret, val_i;							\
	uint8_t buf[16] __attribute__((aligned(16)));				\
	__type ## __type_size ## _t test_val[] =				\
					__type ## __type_size ## _TEST_VALUES;	\
										\
	ret = prctl(PR_SET_UNALIGN, PR_UNALIGN_NOPRINT);			\
	ASSERT_EQ(ret, 0);							\
										\
	for (val_i = 0; val_i < ARRAY_SIZE(test_val); val_i++) {		\
		__type ## __type_size ## _t ref_val = test_val[val_i];		\
		for (offset = 1; offset < (__type_size) / 8; offset++) {	\
			__type ## __type_size ## _t val = ref_val;		\
			__type ## __type_size ## _t *ptr =			\
				 (__type ## __type_size ## _t *)(buf + offset); \
			memset(ptr, 0, sizeof(val));				\
			test_ ## __inst(ptr, offset, val);			\
			memcpy(&val, ptr, sizeof(val));				\
			EXPECT_EQ(ref_val, val);				\
		}								\
	}									\
}

TEST_GP_STORE(sh, 16, int)
TEST_GP_STORE(sw, 32, int)
TEST_GP_STORE(sd, 64, int)
#ifdef __riscv_compressed
TEST_GP_STORE(c_sw, 32, int)
TEST_GP_STORE(c_sd, 64, int)
TEST_GP_STORE(c_sdsp, 64, int)
#endif

#define __TEST_FPU_LOAD(__type, __inst, __reg_start, __reg_end)					\
TEST(fpu_load_ ## __inst)									\
{												\
	int ret, offset, fp_reg, val_i;								\
	uint8_t buf[16] __attribute__((aligned(16)));						\
	__type test_val[] = __type ## _TEST_VALUES;						\
												\
	ret = prctl(PR_SET_UNALIGN, PR_UNALIGN_NOPRINT);					\
	ASSERT_EQ(ret, 0);									\
												\
	for (fp_reg = __reg_start; fp_reg < __reg_end; fp_reg++) {				\
		for (offset = 1; offset < 4; offset++) {					\
			for (val_i = 0; val_i < ARRAY_SIZE(test_val); val_i++) {		\
				__type val, ref_val = test_val[val_i];				\
				void *load_addr = (buf + offset);				\
												\
				memcpy(load_addr, &ref_val, sizeof(ref_val));			\
				val = test_ ## __inst(fp_reg, load_addr, offset, ref_val);	\
				EXPECT_TRUE(__type ##_equal(val, ref_val));			\
			}									\
		}										\
	}											\
}

#define TEST_FPU_LOAD(__type, __inst) \
	__TEST_FPU_LOAD(__type, __inst, 0, 32)
#define TEST_FPU_LOAD_COMPRESSED(__type, __inst) \
	__TEST_FPU_LOAD(__type, __inst, 8, 16)

TEST_FPU_LOAD(float, flw)
TEST_FPU_LOAD(double, fld)
#ifdef __riscv_compressed
TEST_FPU_LOAD_COMPRESSED(double, c_fld)
TEST_FPU_LOAD_COMPRESSED(double, c_fldsp)
#endif

#define __TEST_FPU_STORE(__type, __inst, __reg_start, __reg_end)			\
TEST(fpu_store_ ## __inst)								\
{											\
	int ret, offset, fp_reg, val_i;							\
	uint8_t buf[16] __attribute__((aligned(16)));					\
	__type test_val[] = __type ## _TEST_VALUES;					\
											\
	ret = prctl(PR_SET_UNALIGN, PR_UNALIGN_NOPRINT);				\
	ASSERT_EQ(ret, 0);								\
											\
	for (fp_reg = __reg_start; fp_reg < __reg_end; fp_reg++) {			\
		for (offset = 1; offset < 4; offset++) {				\
			for (val_i = 0; val_i < ARRAY_SIZE(test_val); val_i++) {	\
				__type val, ref_val = test_val[val_i];			\
											\
				void *store_addr = (buf + offset);			\
											\
				test_ ## __inst(fp_reg, store_addr, offset, ref_val);	\
				memcpy(&val, store_addr, sizeof(val));			\
				EXPECT_TRUE(__type ## _equal(val, ref_val));		\
			}								\
		}									\
	}										\
}
#define TEST_FPU_STORE(__type, __inst) \
	__TEST_FPU_STORE(__type, __inst, 0, 32)
#define TEST_FPU_STORE_COMPRESSED(__type, __inst) \
	__TEST_FPU_STORE(__type, __inst, 8, 16)

TEST_FPU_STORE(float, fsw)
TEST_FPU_STORE(double, fsd)
#ifdef __riscv_compressed
TEST_FPU_STORE_COMPRESSED(double, c_fsd)
TEST_FPU_STORE_COMPRESSED(double, c_fsdsp)
#endif

TEST_SIGNAL(gen_sigbus, SIGBUS)
{
	uint32_t val = 0xDEADBEEF;
	uint8_t buf[16] __attribute__((aligned(16)));
	int ret;

	ret = prctl(PR_SET_UNALIGN, PR_UNALIGN_SIGBUS);
	ASSERT_EQ(ret, 0);

	asm volatile("sw %0, 1(%1)" : : "r"(val), "r"(buf) : "memory");
}

int main(int argc, char **argv)
{
	int ret, val;

	ret = prctl(PR_GET_UNALIGN, &val);
	if (ret == -1 && errno == EINVAL)
		ksft_exit_skip("SKIP GET_UNALIGN_CTL not supported\n");

	exit(test_harness_run(argc, argv));
}
