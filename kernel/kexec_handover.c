// SPDX-License-Identifier: GPL-2.0-only
/*
 * kexec_handover.c - kexec handover metadata processing
 * Copyright (C) 2023 Alexander Graf <graf@amazon.com>
 * Copyright (C) 2025 Microsoft Corporation, Mike Rapoport <rppt@kernel.org>
 */

#define pr_fmt(fmt) "KHO: " fmt

#include <linux/cma.h>
#include <linux/kexec.h>
#include <linux/sysfs.h>
#include <linux/libfdt.h>
#include <linux/memblock.h>
#include <linux/notifier.h>
#include <linux/kexec_handover.h>
#include <linux/page-isolation.h>

static bool kho_enable __ro_after_init;

static int __init kho_parse_enable(char *p)
{
	return kstrtobool(p, &kho_enable);
}
early_param("kho", kho_parse_enable);

/*
 * With KHO enabled, memory can become fragmented because KHO regions may
 * be anywhere in physical address space. The scratch regions give us a
 * safe zones that we will never see KHO allocations from. This is where we
 * can later safely load our new kexec images into and then use the scratch
 * area for early allocations that happen before page allocator is
 * initialized.
 */
static struct kho_mem *kho_scratch;
static unsigned int kho_scratch_cnt;

struct kho_out {
	struct blocking_notifier_head chain_head;
	struct kobject *kobj;
	struct mutex lock;
	void *dt;
	u64 dt_len;
	u64 dt_max;
	bool active;
};

static struct kho_out kho_out = {
	.chain_head = BLOCKING_NOTIFIER_INIT(kho_out.chain_head),
	.lock = __MUTEX_INITIALIZER(kho_out.lock),
	.dt_max = 10 * SZ_1M,
};

struct kho_in {
	struct kobject *kobj;
	phys_addr_t kho_scratch_phys;
	phys_addr_t handover_phys;
	u32 handover_len;
};

static struct kho_in kho_in;

int register_kho_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&kho_out.chain_head, nb);
}
EXPORT_SYMBOL_GPL(register_kho_notifier);

int unregister_kho_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&kho_out.chain_head, nb);
}
EXPORT_SYMBOL_GPL(unregister_kho_notifier);

const void *kho_get_fdt(void)
{
	if (!kho_in.handover_phys)
		return NULL;

	return __va(kho_in.handover_phys);
}
EXPORT_SYMBOL_GPL(kho_get_fdt);

static void kho_return_pfn(ulong pfn)
{
	struct page *page = pfn_to_online_page(pfn);

	if (WARN_ON(!page))
		return;
	__free_page(page);
}

/**
 * kho_return_mem - Notify the kernel that initially reserved memory is no
 * longer needed.
 * @mem: memory range that was preserved during kexec handover
 *
 * When the last consumer of a page returns their memory, kho returns the page
 * to the buddy allocator as free page.
 */
void kho_return_mem(const struct kho_mem *mem)
{
	unsigned long start_pfn, end_pfn, pfn;

	start_pfn = PFN_DOWN(mem->addr);
	end_pfn = PFN_UP(mem->addr + mem->size);

	for (pfn = start_pfn; pfn < end_pfn; pfn++)
		kho_return_pfn(pfn);
}
EXPORT_SYMBOL_GPL(kho_return_mem);

static int kho_claim_pfn(ulong pfn)
{
	struct page *page = pfn_to_online_page(pfn);

	if (!page)
		return -ENOMEM;

	/* almost as free_reserved_page(), just don't free the page */
	ClearPageReserved(page);
	init_page_count(page);
	adjust_managed_page_count(page, 1);

	return 0;
}

/**
 * kho_claim_mem - Notify the kernel that a handed over memory range is now
 * in use
 * @mem: memory range that was preserved during kexec handover
 *
 * A kernel subsystem preserved that range during handover and it is going
 * to reuse this range after kexec. The pages in the range are treated as
 * allocated, but not %PG_reserved.
 *
 * Return: virtual address of the preserved memory range
 */
void *kho_claim_mem(const struct kho_mem *mem)
{
	unsigned long start_pfn, end_pfn, pfn;
	void *va = __va(mem->addr);

	start_pfn = PFN_DOWN(mem->addr);
	end_pfn = PFN_UP(mem->addr + mem->size);

	for (pfn = start_pfn; pfn < end_pfn; pfn++) {
		int err = kho_claim_pfn(pfn);

		if (err)
			return NULL;
	}

	return va;
}
EXPORT_SYMBOL_GPL(kho_claim_mem);

static ssize_t dt_read(struct file *file, struct kobject *kobj,
		       struct bin_attribute *attr, char *buf,
		       loff_t pos, size_t count)
{
	mutex_lock(&kho_out.lock);
	memcpy(buf, attr->private + pos, count);
	mutex_unlock(&kho_out.lock);

	return count;
}

static struct bin_attribute bin_attr_dt_kern = __BIN_ATTR(dt, 0400, dt_read, NULL, 0);

static int kho_expose_dt(void *fdt)
{
	long fdt_len = fdt_totalsize(fdt);
	int err;

	kho_out.dt = fdt;
	kho_out.dt_len = fdt_len;

	bin_attr_dt_kern.size = fdt_totalsize(fdt);
	bin_attr_dt_kern.private = fdt;
	err = sysfs_create_bin_file(kho_out.kobj, &bin_attr_dt_kern);

	return err;
}

static void kho_abort(void)
{
	if (!kho_out.active)
		return;

	sysfs_remove_bin_file(kho_out.kobj, &bin_attr_dt_kern);

	kvfree(kho_out.dt);
	kho_out.dt = NULL;
	kho_out.dt_len = 0;

	blocking_notifier_call_chain(&kho_out.chain_head, KEXEC_KHO_ABORT, NULL);

	kho_out.active = false;
}

static int kho_serialize(void)
{
	void *fdt = NULL;
	int err = -ENOMEM;

	fdt = kvmalloc(kho_out.dt_max, GFP_KERNEL);
	if (!fdt)
		goto out;

	if (fdt_create(fdt, kho_out.dt_max)) {
		err = -EINVAL;
		goto out;
	}

	err = fdt_finish_reservemap(fdt);
	if (err)
		goto out;

	err = fdt_begin_node(fdt, "");
	if (err)
		goto out;

	err = fdt_property_string(fdt, "compatible", "kho-v1");
	if (err)
		goto out;

	/* Loop through all kho dump functions */
	err = blocking_notifier_call_chain(&kho_out.chain_head, KEXEC_KHO_DUMP, fdt);
	err = notifier_to_errno(err);
	if (err)
		goto out;

	/* Close / */
	err =  fdt_end_node(fdt);
	if (err)
		goto out;

	err = fdt_finish(fdt);
	if (err)
		goto out;

	if (WARN_ON(fdt_check_header(fdt))) {
		err = -EINVAL;
		goto out;
	}

	err = kho_expose_dt(fdt);

out:
	if (err) {
		pr_err("failed to serialize state: %d", err);
		kho_abort();
	}
	return err;
}

/* Handling for /sys/kernel/kho */

#define KHO_ATTR_RO(_name) \
	static struct kobj_attribute _name##_attr = __ATTR_RO_MODE(_name, 0400)
#define KHO_ATTR_RW(_name) \
	static struct kobj_attribute _name##_attr = __ATTR_RW_MODE(_name, 0600)

static ssize_t active_store(struct kobject *dev, struct kobj_attribute *attr,
			    const char *buf, size_t size)
{
	ssize_t retsize = size;
	bool val = false;
	int ret;

	if (kstrtobool(buf, &val) < 0)
		return -EINVAL;

	if (!kho_enable)
		return -EOPNOTSUPP;
	if (!kho_scratch_cnt)
		return -ENOMEM;

	mutex_lock(&kho_out.lock);
	if (val != kho_out.active) {
		if (val) {
			ret = kho_serialize();
			if (ret) {
				retsize = -EINVAL;
				goto out;
			}
			kho_out.active = true;
		} else {
			kho_abort();
		}
	}

out:
	mutex_unlock(&kho_out.lock);
	return retsize;
}

static ssize_t active_show(struct kobject *dev, struct kobj_attribute *attr,
			   char *buf)
{
	ssize_t ret;

	mutex_lock(&kho_out.lock);
	ret = sysfs_emit(buf, "%d\n", kho_out.active);
	mutex_unlock(&kho_out.lock);

	return ret;
}
KHO_ATTR_RW(active);

static ssize_t dt_max_store(struct kobject *dev, struct kobj_attribute *attr,
			    const char *buf, size_t size)
{
	u64 val;

	if (kstrtoull(buf, 0, &val))
		return -EINVAL;

	/* FDT already exists, it's too late to change dt_max */
	if (kho_out.dt_len)
		return -EBUSY;

	kho_out.dt_max = val;

	return size;
}

static ssize_t dt_max_show(struct kobject *dev, struct kobj_attribute *attr,
			   char *buf)
{
	return sysfs_emit(buf, "0x%llx\n", kho_out.dt_max);
}
KHO_ATTR_RW(dt_max);

static ssize_t scratch_len_show(struct kobject *dev, struct kobj_attribute *attr,
				char *buf)
{
	ssize_t count = 0;

	for (int i = 0; i < kho_scratch_cnt; i++)
		count += sysfs_emit_at(buf, count, "0x%llx\n", kho_scratch[i].size);

	return count;
}
KHO_ATTR_RO(scratch_len);

static ssize_t scratch_phys_show(struct kobject *dev, struct kobj_attribute *attr,
				 char *buf)
{
	ssize_t count = 0;

	for (int i = 0; i < kho_scratch_cnt; i++)
		count += sysfs_emit_at(buf, count, "0x%llx\n", kho_scratch[i].addr);

	return count;
}
KHO_ATTR_RO(scratch_phys);

static const struct attribute *kho_out_attrs[] = {
	&active_attr.attr,
	&dt_max_attr.attr,
	&scratch_phys_attr.attr,
	&scratch_len_attr.attr,
	NULL,
};

/* Handling for /sys/firmware/kho */
static BIN_ATTR_SIMPLE_RO(dt_fw);

static __init int kho_in_sysfs_init(const void *fdt)
{
	int err;

	kho_in.kobj = kobject_create_and_add("kho", firmware_kobj);
	if (!kho_in.kobj)
		return -ENOMEM;

	bin_attr_dt_fw.size = fdt_totalsize(fdt);
	bin_attr_dt_fw.private = (void *)fdt;
	err = sysfs_create_bin_file(kho_in.kobj, &bin_attr_dt_fw);
	if (err)
		goto err_put_kobj;

	return 0;

err_put_kobj:
	kobject_put(kho_in.kobj);
	return err;
}

static __init int kho_out_sysfs_init(void)
{
	int err;

	kho_out.kobj = kobject_create_and_add("kho", kernel_kobj);
	if (!kho_out.kobj)
		return -ENOMEM;

	err = sysfs_create_files(kho_out.kobj, kho_out_attrs);
	if (err)
		goto err_put_kobj;

	return 0;

err_put_kobj:
	kobject_put(kho_out.kobj);
	return err;
}

static __init int kho_init(void)
{
	const void *fdt = kho_get_fdt();
	int err;

	if (!kho_enable)
		return -EINVAL;

	err = kho_out_sysfs_init();
	if (err)
		return err;

	if (fdt) {
		err = kho_in_sysfs_init(fdt);
		/*
		 * Failure to create /sys/firmware/kho/dt does not prevent
		 * reviving state from KHO and setting up KHO for the next
		 * kexec.
		 */
		if (err)
			pr_err("failed exposing handover FDT in sysfs\n");

		kho_scratch = __va(kho_in.kho_scratch_phys);

		return 0;
	}

	for (int i = 0; i < kho_scratch_cnt; i++) {
		unsigned long base_pfn = PHYS_PFN(kho_scratch[i].addr);
		unsigned long count = kho_scratch[i].size >> PAGE_SHIFT;
		unsigned long pfn;

		for (pfn = base_pfn; pfn < base_pfn + count;
		     pfn += pageblock_nr_pages)
			init_cma_reserved_pageblock(pfn_to_page(pfn));
	}

	return 0;
}
late_initcall(kho_init);

/*
 * The scratch areas are scaled by default as percent of memory allocated from
 * memblock. A user can override the scale with command line parameter:
 *
 * kho_scratch=N%
 *
 * It is also possible to explicitly define size for a global and per-node
 * scratch areas:
 *
 * kho_scratch=n[KMG],m[KMG]
 *
 * The explicit size definition takes precedence over scale definition.
 */
static unsigned int scratch_scale __initdata = 200;
static phys_addr_t scratch_size_global __initdata;
static phys_addr_t scratch_size_pernode __initdata;

static int __init kho_parse_scratch_size(char *p)
{
	unsigned long size, size_pernode;
	char *endptr, *oldp = p;

	if (!p)
		return -EINVAL;

	size = simple_strtoul(p, &endptr, 0);
	if (*endptr == '%') {
		scratch_scale = size;
		pr_notice("scratch scale is %d percent\n", scratch_scale);
	} else {
		size = memparse(p, &p);
		if (!size || p == oldp)
			return -EINVAL;

		if (*p != ',')
			return -EINVAL;

		size_pernode = memparse(p + 1, &p);
		if (!size_pernode)
			return -EINVAL;

		scratch_size_global = size;
		scratch_size_pernode = size_pernode;
		scratch_scale = 0;

		pr_notice("scratch areas: global: %lluMB pernode: %lldMB\n",
			  (u64)(scratch_size_global >> 20),
			  (u64)(scratch_size_pernode >> 20));
	}

	return 0;
}
early_param("kho_scratch", kho_parse_scratch_size);

static phys_addr_t __init scratch_size(int nid)
{
	phys_addr_t size;

	if (scratch_scale) {
		size = memblock_reserved_kern_size(nid) * scratch_scale / 100;
	} else {
		if (numa_valid_node(nid))
			size = scratch_size_pernode;
		else
			size = scratch_size_global;
	}

	return round_up(size, CMA_MIN_ALIGNMENT_BYTES);
}

/**
 * kho_reserve_scratch - Reserve a contiguous chunk of memory for kexec
 *
 * With KHO we can preserve arbitrary pages in the system. To ensure we still
 * have a large contiguous region of memory when we search the physical address
 * space for target memory, let's make sure we always have a large CMA region
 * active. This CMA region will only be used for movable pages which are not a
 * problem for us during KHO because we can just move them somewhere else.
 */
static void __init kho_reserve_scratch(void)
{
	phys_addr_t addr, size;
	int nid, i = 1;

	if (!kho_enable)
		return;

	/* FIXME: deal with node hot-plug/remove */
	kho_scratch_cnt = num_online_nodes() + 1;
	size = kho_scratch_cnt * sizeof(*kho_scratch);
	kho_scratch = memblock_alloc(size, PAGE_SIZE);
	if (!kho_scratch)
		goto err_disable_kho;

	/* reserve large contiguous area for allocations without nid */
	size = scratch_size(NUMA_NO_NODE);
	addr = memblock_phys_alloc(size, CMA_MIN_ALIGNMENT_BYTES);
	if (!addr)
		goto err_free_scratch_desc;

	kho_scratch[0].addr = addr;
	kho_scratch[0].size = size;

	for_each_online_node(nid) {
		size = scratch_size(nid);
		addr = memblock_alloc_range_nid(size, CMA_MIN_ALIGNMENT_BYTES,
						0, MEMBLOCK_ALLOC_ACCESSIBLE,
						nid, true);
		if (!addr)
			goto err_free_scratch_areas;

		kho_scratch[i].addr = addr;
		kho_scratch[i].size = size;
		i++;
	}

	return;

err_free_scratch_areas:
	for (i--; i >= 0; i--)
		memblock_phys_free(kho_scratch[i].addr, kho_scratch[i].size);
err_free_scratch_desc:
	memblock_free(kho_scratch, kho_scratch_cnt * sizeof(*kho_scratch));
err_disable_kho:
	kho_enable = false;
}

/*
 * Scan the DT for any memory ranges and make sure they are reserved in
 * memblock, otherwise they will end up in a weird state on free lists.
 */
static void __init kho_init_reserved_pages(void)
{
	const void *fdt = kho_get_fdt();
	int offset = 0, depth = 0, initial_depth = 0, len;

	if (!fdt)
		return;

	/* Go through the mem list and add 1 for each reference */
	for (offset = 0;
	     offset >= 0 && depth >= initial_depth;
	     offset = fdt_next_node(fdt, offset, &depth)) {
		const struct kho_mem *mems;
		u32 i;

		mems = fdt_getprop(fdt, offset, "mem", &len);
		if (!mems || len & (sizeof(*mems) - 1))
			continue;

		for (i = 0; i < len; i += sizeof(*mems)) {
			const struct kho_mem *mem = &mems[i];

			memblock_reserve(mem->addr, mem->size);
		}
	}
}

static void __init kho_release_scratch(void)
{
	phys_addr_t start, end;
	u64 i;

	memmap_init_kho_scratch_pages();

	/*
	 * Mark scratch mem as CMA before we return it. That way we
	 * ensure that no kernel allocations happen on it. That means
	 * we can reuse it as scratch memory again later.
	 */
	__for_each_mem_range(i, &memblock.memory, NULL, NUMA_NO_NODE,
			     MEMBLOCK_KHO_SCRATCH, &start, &end, NULL) {
		ulong start_pfn = pageblock_start_pfn(PFN_DOWN(start));
		ulong end_pfn = pageblock_align(PFN_UP(end));
		ulong pfn;

		for (pfn = start_pfn; pfn < end_pfn; pfn += pageblock_nr_pages)
			set_pageblock_migratetype(pfn_to_page(pfn), MIGRATE_CMA);
	}
}

void __init kho_memory_init(void)
{
	if (!kho_get_fdt()) {
		kho_reserve_scratch();
	} else {
		kho_init_reserved_pages();
		kho_release_scratch();
	}
}

void __init kho_populate(phys_addr_t handover_dt_phys, phys_addr_t scratch_phys,
			 u64 scratch_len)
{
	void *handover_dt;
	struct kho_mem *scratch;

	/* Determine the real size of the DT */
	handover_dt = early_memremap(handover_dt_phys, sizeof(struct fdt_header));
	if (!handover_dt) {
		pr_warn("setup: failed to memremap kexec FDT (0x%llx)\n", handover_dt_phys);
		return;
	}

	if (fdt_check_header(handover_dt)) {
		pr_warn("setup: kexec handover FDT is invalid (0x%llx)\n", handover_dt_phys);
		early_memunmap(handover_dt, PAGE_SIZE);
		return;
	}

	kho_in.handover_len = fdt_totalsize(handover_dt);
	kho_in.handover_phys = handover_dt_phys;

	early_memunmap(handover_dt, sizeof(struct fdt_header));

	/* Reserve the DT so we can still access it in late boot */
	memblock_reserve(kho_in.handover_phys, kho_in.handover_len);

	kho_in.kho_scratch_phys = scratch_phys;
	kho_scratch_cnt = scratch_len / sizeof(*kho_scratch);
	scratch = early_memremap(scratch_phys, scratch_len);
	if (!scratch) {
		pr_warn("setup: failed to memremap kexec scratch (0x%llx)\n", scratch_phys);
		return;
	}

	/*
	 * We pass a safe contiguous blocks of memory to use for early boot
	 * purporses from the previous kernel so that we can resize the
	 * memblock array as needed.
	 */
	for (int i = 0; i < kho_scratch_cnt; i++) {
		struct kho_mem *area = &scratch[i];
		u64 size = area->size;

		memblock_add(area->addr, size);

		if (WARN_ON(memblock_mark_kho_scratch(area->addr, size))) {
			pr_err("Kexec failed to mark the scratch region. Disabling KHO revival.");
			kho_in.handover_len = 0;
			kho_in.handover_phys = 0;
			scratch = NULL;
			break;
		}
		pr_debug("Marked 0x%pa+0x%pa as scratch", &area->addr, &size);
	}

	early_memunmap(scratch, scratch_len);

	if (!scratch)
		return;

	memblock_reserve(scratch_phys, scratch_len);

	/*
	 * Now that we have a viable region of scratch memory, let's tell
	 * the memblocks allocator to only use that for any allocations.
	 * That way we ensure that nothing scribbles over in use data while
	 * we initialize the page tables which we will need to ingest all
	 * memory reservations from the previous kernel.
	 */
	memblock_set_kho_scratch_only();

	pr_info("setup: Found kexec handover data. Will skip init for some devices\n");
}
