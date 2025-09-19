// SPDX-License-Identifier: GPL-2.0-only
#include <asm/msr-index.h>

#include <stdint.h>

#include "kvm_util.h"
#include "processor.h"

/* Use HYPERVISOR for MSRs that are emulated unconditionally (as is HYPERVISOR). */
#define X86_FEATURE_NONE X86_FEATURE_HYPERVISOR

struct kvm_msr {
	const struct kvm_x86_cpu_feature feature;
	const struct kvm_x86_cpu_feature feature2;
	const char *name;
	const u64 reset_val;
	const u64 write_val;
	const u64 rsvd_val;
	const u32 index;
};

#define ____MSR_TEST(msr, str, val, rsvd, reset, feat, f2)		\
{									\
	.index = msr,							\
	.name = str,							\
	.write_val = val,						\
	.rsvd_val = rsvd,						\
	.reset_val = reset,						\
	.feature = X86_FEATURE_ ##feat,					\
	.feature2 = X86_FEATURE_ ##f2,					\
}

#define __MSR_TEST(msr, str, val, rsvd, reset, feat)			\
	____MSR_TEST(msr, str, val, rsvd, reset, feat, feat)

#define MSR_TEST_NON_ZERO(msr, val, rsvd, reset, feat)			\
	__MSR_TEST(msr, #msr, val, rsvd, reset, feat)

#define MSR_TEST(msr, val, rsvd, feat)					\
	__MSR_TEST(msr, #msr, val, rsvd, 0, feat)

#define MSR_TEST2(msr, val, rsvd, feat, f2)				\
	____MSR_TEST(msr, #msr, val, rsvd, 0, feat, f2)

/*
 * Note, use a page aligned value for the canonical value so that the value
 * is compatible with MSRs that use bits 11:0 for things other than addresses.
 */
static const u64 canonical_val = 0x123456789000ull;

#define MSR_TEST_CANONICAL(msr, feat)					\
	__MSR_TEST(msr, #msr, canonical_val, NONCANONICAL, 0, feat)

/*
 * The main struct must be scoped to a function due to the use of structures to
 * define features.  For the global structure, allocate enough space for the
 * foreseeable future without getting too ridiculous, to minimize maintenance
 * costs (bumping the array size every time an MSR is added is really annoying).
 */
static struct kvm_msr msrs[128];
static int idx;

static bool ignore_unsupported_msrs;

static u64 fixup_rdmsr_val(u32 msr, u64 want)
{
	/*
	 * AMD CPUs drop bits 63:32 on some MSRs that Intel CPUs support.  KVM
	 * is supposed to emulate that behavior based on guest vendor model
	 * (which is the same as the host vendor model for this test).
	 */
	if (!host_cpu_is_amd)
		return want;

	switch (msr) {
	case MSR_IA32_SYSENTER_ESP:
	case MSR_IA32_SYSENTER_EIP:
	case MSR_TSC_AUX:
		return want & GENMASK_ULL(31, 0);
	default:
		return want;
	}
}

static void __rdmsr(u32 msr, u64 want)
{
	u64 val;
	u8 vec;

	vec = rdmsr_safe(msr, &val);
	__GUEST_ASSERT(!vec, "Unexpected %s on RDMSR(0x%x)", ex_str(vec), msr);

	__GUEST_ASSERT(val == want, "Wanted 0x%lx from RDMSR(0x%x), got 0x%lx",
		       want, msr, val);
}

static void __wrmsr(u32 msr, u64 val)
{
	u8 vec;

	vec = wrmsr_safe(msr, val);
	__GUEST_ASSERT(!vec, "Unexpected %s on WRMSR(0x%x, 0x%lx)",
		       ex_str(vec), msr, val);
	__rdmsr(msr, fixup_rdmsr_val(msr, val));
}

static void guest_test_supported_msr(const struct kvm_msr *msr)
{
	__rdmsr(msr->index, msr->reset_val);
	__wrmsr(msr->index, msr->write_val);
	GUEST_SYNC(fixup_rdmsr_val(msr->index, msr->write_val));

	__rdmsr(msr->index, msr->reset_val);
}

static void guest_test_unsupported_msr(const struct kvm_msr *msr)
{
	u64 val;
	u8 vec;

	/*
	 * KVM's ABI with respect to ignore_msrs is a mess and largely beyond
	 * repair, just skip the unsupported MSR tests.
	 */
	if (ignore_unsupported_msrs)
		goto skip_wrmsr_gp;

	if (this_cpu_has(msr->feature2))
		goto skip_wrmsr_gp;

	vec = rdmsr_safe(msr->index, &val);
	__GUEST_ASSERT(vec == GP_VECTOR, "Wanted #GP on RDMSR(0x%x), got %s",
		       msr->index, ex_str(vec));

	vec = wrmsr_safe(msr->index, msr->write_val);
	__GUEST_ASSERT(vec == GP_VECTOR, "Wanted #GP on WRMSR(0x%x, 0x%lx), got %s",
		       msr->index, msr->write_val, ex_str(vec));

skip_wrmsr_gp:
	GUEST_SYNC(0);
}

void guest_test_reserved_val(const struct kvm_msr *msr)
{
	/* Skip reserved value checks as well, ignore_msrs is trully a mess. */
	if (ignore_unsupported_msrs)
		return;

	/*
	 * If the CPU will truncate the written value (e.g. SYSENTER on AMD),
	 * expect success and a truncated value, not #GP.
	 */
	if (!this_cpu_has(msr->feature) ||
	    msr->rsvd_val == fixup_rdmsr_val(msr->index, msr->rsvd_val)) {
		u8 vec = wrmsr_safe(msr->index, msr->rsvd_val);

		__GUEST_ASSERT(vec == GP_VECTOR,
			       "Wanted #GP on WRMSR(0x%x, 0x%lx), got %s",
			       msr->index, msr->rsvd_val, ex_str(vec));
	} else {
		__wrmsr(msr->index, msr->rsvd_val);
		__wrmsr(msr->index, msr->reset_val);
	}
}

static void guest_main(void)
{
	for (;;) {
		const struct kvm_msr *msr = &msrs[READ_ONCE(idx)];

		if (this_cpu_has(msr->feature))
			guest_test_supported_msr(msr);
		else
			guest_test_unsupported_msr(msr);

		if (msr->rsvd_val)
			guest_test_reserved_val(msr);

		GUEST_SYNC(msr->reset_val);
	}
}

static void host_test_msr(struct kvm_vcpu *vcpu, u64 guest_val)
{
	u64 reset_val = msrs[idx].reset_val;
	u32 msr = msrs[idx].index;
	u64 val;

	if (!kvm_cpu_has(msrs[idx].feature))
		return;

	val = vcpu_get_msr(vcpu, msr);
	TEST_ASSERT(val == guest_val, "Wanted 0x%lx from get_msr(0x%x), got 0x%lx",
		    guest_val, msr, val);

	vcpu_set_msr(vcpu, msr, reset_val);

	val = vcpu_get_msr(vcpu, msr);
	TEST_ASSERT(val == reset_val, "Wanted 0x%lx from get_msr(0x%x), got 0x%lx",
		    reset_val, msr, val);
}

static void do_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct ucall uc;

	for (;;) {
		vcpu_run(vcpu);

		switch (get_ucall(vcpu, &uc)) {
		case UCALL_SYNC:
			host_test_msr(vcpu, uc.args[1]);
			return;
		case UCALL_PRINTF:
			pr_info("%s", uc.buffer);
			break;
		case UCALL_ABORT:
			REPORT_GUEST_ASSERT(uc);
		case UCALL_DONE:
			TEST_FAIL("Unexpected UCALL_DONE");
		default:
			TEST_FAIL("Unexpected ucall: %lu", uc.cmd);
		}
	}
}

static void vcpus_run(struct kvm_vcpu **vcpus, const int NR_VCPUS)
{
	int i;

	for (i = 0; i < NR_VCPUS; i++)
		do_vcpu_run(vcpus[i]);
}

#define MISC_ENABLES_RESET_VAL (MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL | MSR_IA32_MISC_ENABLE_BTS_UNAVAIL)

static void test_msrs(void)
{
	const struct kvm_msr __msrs[] = {
		MSR_TEST_NON_ZERO(MSR_IA32_MISC_ENABLE,
				  MISC_ENABLES_RESET_VAL | MSR_IA32_MISC_ENABLE_FAST_STRING,
				  MSR_IA32_MISC_ENABLE_FAST_STRING, MISC_ENABLES_RESET_VAL, NONE),
		MSR_TEST_NON_ZERO(MSR_IA32_CR_PAT, 0x07070707, 0, 0x7040600070406, NONE),

		/*
		 * TSC_AUX is supported if RDTSCP *or* RDPID is supported.  Add
		 * entries for each features so that TSC_AUX doesn't exists for
		 * the "unsupported" vCPU, and obviously to test both cases.
		 */
		MSR_TEST2(MSR_TSC_AUX, 0x12345678, canonical_val, RDTSCP, RDPID),
		MSR_TEST2(MSR_TSC_AUX, 0x12345678, canonical_val, RDPID, RDTSCP),

		MSR_TEST(MSR_IA32_SYSENTER_CS, 0x1234, 0, NONE),
		/*
		 * SYSENTER_{ESP,EIP} are technically non-canonical on Intel,
		 * but KVM doesn't emulate that behavior on emulated writes,
		 * i.e. this test will observe different behavior if the MSR
		 * writes are handed by hardware vs. KVM.  KVM's behavior is
		 * intended (though far from ideal), so don't bother testing
		 * non-canonical values.
		 */
		MSR_TEST(MSR_IA32_SYSENTER_ESP, canonical_val, 0, NONE),
		MSR_TEST(MSR_IA32_SYSENTER_EIP, canonical_val, 0, NONE),

		MSR_TEST_CANONICAL(MSR_FS_BASE, LM),
		MSR_TEST_CANONICAL(MSR_GS_BASE, LM),
		MSR_TEST_CANONICAL(MSR_KERNEL_GS_BASE, LM),
		MSR_TEST_CANONICAL(MSR_LSTAR, LM),
		MSR_TEST_CANONICAL(MSR_CSTAR, LM),
		MSR_TEST(MSR_SYSCALL_MASK, 0xffffffff, 0, LM),

		MSR_TEST_CANONICAL(MSR_IA32_PL0_SSP, SHSTK),
		MSR_TEST(MSR_IA32_PL0_SSP, canonical_val, canonical_val | 1, SHSTK),
		MSR_TEST_CANONICAL(MSR_IA32_PL1_SSP, SHSTK),
		MSR_TEST(MSR_IA32_PL1_SSP, canonical_val, canonical_val | 1, SHSTK),
		MSR_TEST_CANONICAL(MSR_IA32_PL2_SSP, SHSTK),
		MSR_TEST(MSR_IA32_PL2_SSP, canonical_val, canonical_val | 1, SHSTK),
		MSR_TEST_CANONICAL(MSR_IA32_PL3_SSP, SHSTK),
		MSR_TEST(MSR_IA32_PL3_SSP, canonical_val, canonical_val | 1, SHSTK),
	};

	/*
	 * Create two vCPUs, but run them on the same task, to validate KVM's
	 * context switching of MSR state.  Don't pin the task to a pCPU to
	 * also validate KVM's handling of cross-pCPU migration.
	 */
	const int NR_VCPUS = 2;
	struct kvm_vcpu *vcpus[NR_VCPUS];
	struct kvm_vm *vm;

	kvm_static_assert(sizeof(__msrs) <= sizeof(msrs));
	kvm_static_assert(ARRAY_SIZE(__msrs) <= ARRAY_SIZE(msrs));
	memcpy(msrs, __msrs, sizeof(__msrs));

	ignore_unsupported_msrs = kvm_is_ignore_msrs();

	vm = vm_create_with_vcpus(NR_VCPUS, guest_main, vcpus);

	sync_global_to_guest(vm, msrs);
	sync_global_to_guest(vm, ignore_unsupported_msrs);

	for (idx = 0; idx < ARRAY_SIZE(__msrs); idx++) {
		sync_global_to_guest(vm, idx);

		vcpus_run(vcpus, NR_VCPUS);
		vcpus_run(vcpus, NR_VCPUS);
	}

	kvm_vm_free(vm);
}

int main(void)
{
	test_msrs();
}
