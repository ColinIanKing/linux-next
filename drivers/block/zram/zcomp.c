// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/vmalloc.h>

#include "zcomp.h"

#include "backend_lzo.h"
#include "backend_lzorle.h"
#include "backend_lz4.h"
#include "backend_lz4hc.h"
#include "backend_zstd.h"
#include "backend_deflate.h"
#include "backend_842.h"

static const struct zcomp_ops *backends[] = {
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
#if IS_ENABLED(CONFIG_ZRAM_BACKEND_DEFLATE)
	&backend_deflate,
#endif
#if IS_ENABLED(CONFIG_ZRAM_BACKEND_842)
	&backend_842,
#endif
	NULL
};

static void zcomp_strm_free(struct zcomp *comp, struct zcomp_strm *strm)
{
	comp->ops->destroy_ctx(&strm->ctx);
	vfree(strm->buffer);
	kfree(strm);
}

static struct zcomp_strm *zcomp_strm_alloc(struct zcomp *comp)
{
	struct zcomp_strm *strm;
	int ret;

	strm = kzalloc(sizeof(*strm), GFP_KERNEL);
	if (!strm)
		return NULL;

	INIT_LIST_HEAD(&strm->entry);

	ret = comp->ops->create_ctx(comp->params, &strm->ctx);
	if (ret) {
		kfree(strm);
		return NULL;
	}

	/*
	 * allocate 2 pages. 1 for compressed data, plus 1 extra in case if
	 * compressed data is larger than the original one.
	 */
	strm->buffer = vzalloc(2 * PAGE_SIZE);
	if (!strm->buffer) {
		zcomp_strm_free(comp, strm);
		return NULL;
	}
	return strm;
}

static const struct zcomp_ops *lookup_backend_ops(const char *comp)
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
	return lookup_backend_ops(comp) != NULL;
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

	sz += scnprintf(buf + sz, PAGE_SIZE - sz, "\n");
	return sz;
}

struct zcomp_strm *zcomp_stream_get(struct zcomp *comp)
{
	struct zcomp_strm *strm;

	might_sleep();

	while (1) {
		spin_lock(&comp->strm_lock);
		if (!list_empty(&comp->idle_strm)) {
			strm = list_first_entry(&comp->idle_strm,
						struct zcomp_strm,
						entry);
			list_del(&strm->entry);
			spin_unlock(&comp->strm_lock);
			return strm;
		}

		/* cannot allocate new stream, wait for an idle one */
		if (comp->avail_strm >= num_online_cpus()) {
			spin_unlock(&comp->strm_lock);
			wait_event(comp->strm_wait,
				   !list_empty(&comp->idle_strm));
			continue;
		}

		/* allocate new stream */
		comp->avail_strm++;
		spin_unlock(&comp->strm_lock);

		strm = zcomp_strm_alloc(comp);
		if (strm)
			break;

		spin_lock(&comp->strm_lock);
		comp->avail_strm--;
		spin_unlock(&comp->strm_lock);
		wait_event(comp->strm_wait, !list_empty(&comp->idle_strm));
	}

	return strm;
}

void zcomp_stream_put(struct zcomp *comp, struct zcomp_strm *strm)
{
	spin_lock(&comp->strm_lock);
	if (comp->avail_strm <= num_online_cpus()) {
		list_add(&strm->entry, &comp->idle_strm);
		spin_unlock(&comp->strm_lock);
		wake_up(&comp->strm_wait);
		return;
	}

	comp->avail_strm--;
	spin_unlock(&comp->strm_lock);
	zcomp_strm_free(comp, strm);
}

int zcomp_compress(struct zcomp *comp, struct zcomp_strm *zstrm,
		   const void *src, unsigned int *dst_len)
{
	struct zcomp_req req = {
		.src = src,
		.dst = zstrm->buffer,
		.src_len = PAGE_SIZE,
		.dst_len = 2 * PAGE_SIZE,
	};
	int ret;

	ret = comp->ops->compress(comp->params, &zstrm->ctx, &req);
	if (!ret)
		*dst_len = req.dst_len;
	return ret;
}

int zcomp_decompress(struct zcomp *comp, struct zcomp_strm *zstrm,
		     const void *src, unsigned int src_len, void *dst)
{
	struct zcomp_req req = {
		.src = src,
		.dst = dst,
		.src_len = src_len,
		.dst_len = PAGE_SIZE,
	};

	return comp->ops->decompress(comp->params, &zstrm->ctx, &req);
}

void zcomp_destroy(struct zcomp *comp)
{
	struct zcomp_strm *strm;

	while (!list_empty(&comp->idle_strm)) {
		strm = list_first_entry(&comp->idle_strm,
					struct zcomp_strm,
					entry);
		list_del(&strm->entry);
		zcomp_strm_free(comp, strm);
	}

	comp->ops->release_params(comp->params);
	kfree(comp);
}

struct zcomp *zcomp_create(const char *alg, struct zcomp_params *params)
{
	struct zcomp *comp;
	int error;

	/*
	 * The backends array has a sentinel NULL value, so the minimum
	 * size is 1. In order to be valid the array, apart from the
	 * sentinel NULL element, should have at least one compression
	 * backend selected.
	 */
	BUILD_BUG_ON(ARRAY_SIZE(backends) <= 1);

	comp = kzalloc(sizeof(struct zcomp), GFP_KERNEL);
	if (!comp)
		return ERR_PTR(-ENOMEM);

	comp->ops = lookup_backend_ops(alg);
	if (!comp->ops) {
		kfree(comp);
		return ERR_PTR(-EINVAL);
	}

	INIT_LIST_HEAD(&comp->idle_strm);
	init_waitqueue_head(&comp->strm_wait);
	spin_lock_init(&comp->strm_lock);

	comp->params = params;
	error = comp->ops->setup_params(comp->params);
	if (error) {
		kfree(comp);
		return ERR_PTR(error);
	}
	return comp;
}
