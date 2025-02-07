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
	int err;

	if (!kho_enable)
		return -EINVAL;

	err = kho_out_sysfs_init();
	if (err)
		return err;

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

void __init kho_memory_init(void)
{
	kho_reserve_scratch();
}
