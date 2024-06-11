#include <linux/kernel.h>
#include <linux/lz4.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "backend_lz4.h"

struct lz4_ctx {
	void *mem;
	s32 level;
};

static int lz4_init_config(struct zcomp_config *config)
{
	if (config->level == ZCOMP_CONFIG_NO_LEVEL)
		config->level = LZ4_ACCELERATION_DEFAULT;

	return 0;
}

static void lz4_release_config(struct zcomp_config *config)
{
}

static void lz4_destroy(void *ctx)
{
	struct lz4_ctx *zctx = ctx;

	vfree(zctx->mem);
	kfree(zctx);
}

static void *lz4_create(struct zcomp_config *config)
{
	struct lz4_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->level = config->level;
	ctx->mem = vmalloc(LZ4_MEM_COMPRESS);
	if (!ctx->mem)
		goto error;

	return ctx;
error:
	lz4_destroy(ctx);
	return NULL;
}

static int lz4_compress(void *ctx, const unsigned char *src,
			unsigned char *dst, size_t *dst_len)
{
	struct lz4_ctx *zctx = ctx;
	int ret;

	ret = LZ4_compress_fast(src, dst, PAGE_SIZE, *dst_len,
				zctx->level, zctx->mem);
	if (!ret)
		return -EINVAL;
	*dst_len = ret;
	return 0;
}

static int lz4_decompress(void *ctx, const unsigned char *src,
			  size_t src_len, unsigned char *dst)
{
	int dst_len = PAGE_SIZE;
	int ret;

	ret = LZ4_decompress_safe(src, dst, src_len, dst_len);
	if (ret < 0)
		return -EINVAL;
	return 0;
}

struct zcomp_backend backend_lz4 = {
	.compress	= lz4_compress,
	.decompress	= lz4_decompress,
	.create_ctx	= lz4_create,
	.destroy_ctx	= lz4_destroy,
	.init_config	= lz4_init_config,
	.release_config	= lz4_release_config,
	.name		= "lz4",
};
