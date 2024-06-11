// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2014 Sergey Senozhatsky.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/cpu.h>
#include <linux/crypto.h>
#include <linux/vmalloc.h>

#include "zcomp.h"

#include "backend_lzo.h"
#include "backend_lzorle.h"
#include "backend_lz4.h"
#include "backend_lz4hc.h"
#include "backend_zstd.h"

static struct zcomp_backend *backends[] = {
#if IS_ENABLED(CONFIG_ZRAM_BACKEND_LZO)
	&backend_lzorle,
	&backend_lzo,
#endif
#if IS_ENABLED(CONFIG_ZRAM_BACKEND_LZ4)
	&backend_lz4,
#endif
#if IS_ENABLED(CONFIG_ZRAM_BACKEND_LZ4HC)
	&backend_lz4hc,
#endif
#if IS_ENABLED(CONFIG_ZRAM_BACKEND_ZSTD)
	&backend_zstd,
#endif
	NULL
};

static void zcomp_strm_free(struct zcomp *comp, struct zcomp_strm *zstrm)
{
	if (zstrm->ctx)
		comp->backend->destroy_ctx(zstrm->ctx);
	vfree(zstrm->buffer);
	zstrm->ctx = NULL;
	zstrm->buffer = NULL;
}

/*
 * Initialize zcomp_strm structure with ->tfm initialized by backend, and
 * ->buffer. Return a negative value on error.
 */
static int zcomp_strm_init(struct zcomp *comp, struct zcomp_strm *zstrm)
{
	zstrm->ctx = comp->backend->create_ctx();

	/*
	 * allocate 2 pages. 1 for compressed data, plus 1 extra for the
	 * case when compressed size is larger than the original one
	 */
	zstrm->buffer = vzalloc(2 * PAGE_SIZE);
	if (!zstrm->ctx || !zstrm->buffer) {
		zcomp_strm_free(comp, zstrm);
		return -ENOMEM;
	}
	return 0;
}

static struct zcomp_backend *lookup_backend(const char *comp)
{
	int i = 0;

	while (backends[i]) {
		if (sysfs_streq(comp, backends[i]->name))
			break;
		i++;
	}
	return backends[i];
}

bool zcomp_available_algorithm(const char *comp)
{
	return lookup_backend(comp) != NULL;
}

/* show available compressors */
ssize_t zcomp_available_show(const char *comp, char *buf)
{
	ssize_t sz = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(backends) - 1; i++) {
		if (!strcmp(comp, backends[i]->name)) {
			sz += scnprintf(buf + sz, PAGE_SIZE - sz - 2,
					"[%s] ", backends[i]->name);
		} else {
			sz += scnprintf(buf + sz, PAGE_SIZE - sz - 2,
					"%s ", backends[i]->name);
		}
	}

	return sz;
}

struct zcomp_strm *zcomp_stream_get(struct zcomp *comp)
{
	local_lock(&comp->stream->lock);
	return this_cpu_ptr(comp->stream);
}

void zcomp_stream_put(struct zcomp *comp)
{
	local_unlock(&comp->stream->lock);
}

int zcomp_compress(struct zcomp *comp, struct zcomp_strm *zstrm,
		   const void *src, unsigned int *dst_len)
{
	/*
	 * Our dst memory (zstrm->buffer) is always `2 * PAGE_SIZE' sized
	 * because sometimes we can endup having a bigger compressed data
	 * due to various reasons: for example compression algorithms tend
	 * to add some padding to the compressed buffer. Speaking of padding,
	 * comp algorithm `842' pads the compressed length to multiple of 8
	 * and returns -ENOSP when the dst memory is not big enough, which
	 * is not something that ZRAM wants to see. We can handle the
	 * `compressed_size > PAGE_SIZE' case easily in ZRAM, but when we
	 * receive -ERRNO from the compressing backend we can't help it
	 * anymore. To make `842' happy we need to tell the exact size of
	 * the dst buffer, zram_drv will take care of the fact that
	 * compressed buffer is too big.
	 */
	size_t dlen = PAGE_SIZE * 2;
	int ret;

	ret = comp->backend->compress(zstrm->ctx, src, zstrm->buffer, &dlen);
	if (!ret)
		*dst_len = dlen;
	return ret;
}

int zcomp_decompress(struct zcomp *comp, struct zcomp_strm *zstrm,
		     const void *src, unsigned int src_len, void *dst)
{
	return comp->backend->decompress(zstrm->ctx, src, src_len, dst);
}

int zcomp_cpu_up_prepare(unsigned int cpu, struct hlist_node *node)
{
	struct zcomp *comp = hlist_entry(node, struct zcomp, node);
	struct zcomp_strm *zstrm;
	int ret;

	zstrm = per_cpu_ptr(comp->stream, cpu);
	local_lock_init(&zstrm->lock);

	ret = zcomp_strm_init(comp, zstrm);
	if (ret)
		pr_err("Can't allocate a compression stream\n");
	return ret;
}

int zcomp_cpu_dead(unsigned int cpu, struct hlist_node *node)
{
	struct zcomp *comp = hlist_entry(node, struct zcomp, node);
	struct zcomp_strm *zstrm;

	zstrm = per_cpu_ptr(comp->stream, cpu);
	zcomp_strm_free(comp, zstrm);
	return 0;
}

static int zcomp_init(struct zcomp *comp)
{
	int ret;

	comp->stream = alloc_percpu(struct zcomp_strm);
	if (!comp->stream)
		return -ENOMEM;

	ret = cpuhp_state_add_instance(CPUHP_ZCOMP_PREPARE, &comp->node);
	if (ret < 0)
		goto cleanup;
	return 0;

cleanup:
	free_percpu(comp->stream);
	return ret;
}

void zcomp_destroy(struct zcomp *comp)
{
	cpuhp_state_remove_instance(CPUHP_ZCOMP_PREPARE, &comp->node);
	free_percpu(comp->stream);
	kfree(comp);
}

struct zcomp *zcomp_create(const char *alg)
{
	struct zcomp *comp;
	int error;

	comp = kzalloc(sizeof(struct zcomp), GFP_KERNEL);
	if (!comp)
		return ERR_PTR(-ENOMEM);

	comp->backend = lookup_backend(alg);
	if (!comp->backend) {
		kfree(comp);
		return ERR_PTR(-EINVAL);
	}

	error = zcomp_init(comp);
	if (error) {
		kfree(comp);
		return ERR_PTR(error);
	}
	return comp;
}
