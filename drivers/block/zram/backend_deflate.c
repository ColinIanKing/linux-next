// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/zlib.h>

#include "backend_deflate.h"

/* Use the same value as crypto API */
#define DEFLATE_DEF_WINBITS		11
#define DEFLATE_DEF_MEMLEVEL		MAX_MEM_LEVEL

struct deflate_ctx {
	struct z_stream_s cctx;
	struct z_stream_s dctx;
	s32 level;
};

static void deflate_destroy(void *ctx)
{
	struct deflate_ctx *zctx = ctx;

	if (zctx->cctx.workspace) {
		zlib_deflateEnd(&zctx->cctx);
		vfree(zctx->cctx.workspace);
	}
	if (zctx->dctx.workspace) {
		zlib_inflateEnd(&zctx->dctx);
		vfree(zctx->dctx.workspace);
	}
	kfree(zctx);
}

static void *deflate_create(struct zcomp_config *config)
{
	struct deflate_ctx *ctx;
	size_t sz;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	if (config->level != ZCOMP_CONFIG_NO_LEVEL)
		ctx->level = config->level;
	else
		ctx->level = Z_DEFAULT_COMPRESSION;

	sz = zlib_deflate_workspacesize(-DEFLATE_DEF_WINBITS, MAX_MEM_LEVEL);
	ctx->cctx.workspace = vzalloc(sz);
	if (!ctx->cctx.workspace)
		goto error;

	ret = zlib_deflateInit2(&ctx->cctx, ctx->level, Z_DEFLATED,
				-DEFLATE_DEF_WINBITS, DEFLATE_DEF_MEMLEVEL,
				Z_DEFAULT_STRATEGY);
	if (ret != Z_OK)
		goto error;

	sz = zlib_inflate_workspacesize();
	ctx->dctx.workspace = vzalloc(sz);
	if (!ctx->dctx.workspace)
		goto error;

	ret = zlib_inflateInit2(&ctx->dctx, -DEFLATE_DEF_WINBITS);
	if (ret != Z_OK)
		goto error;

	return ctx;

error:
	deflate_destroy(ctx);
	return NULL;
}

static int deflate_compress(void *ctx, const unsigned char *src,
			    unsigned char *dst, size_t *dst_len)
{
	struct deflate_ctx *zctx = ctx;
	struct z_stream_s *deflate;
	int ret;

	deflate = &zctx->cctx;
	ret = zlib_deflateReset(deflate);
	if (ret != Z_OK)
		return -EINVAL;

	deflate->next_in = (u8 *)src;
	deflate->avail_in = PAGE_SIZE;
	deflate->next_out = (u8 *)dst;
	deflate->avail_out = *dst_len;

	ret = zlib_deflate(deflate, Z_FINISH);
	if (ret != Z_STREAM_END)
		return -EINVAL;

	*dst_len = deflate->total_out;
	return 0;
}

static int deflate_decompress(void *ctx, const unsigned char *src,
			      size_t src_len, unsigned char *dst)
{
	struct deflate_ctx *zctx = ctx;
	struct z_stream_s *inflate;
	int ret;

	inflate = &zctx->dctx;

	ret = zlib_inflateReset(inflate);
	if (ret != Z_OK)
		return -EINVAL;

	inflate->next_in = (u8 *)src;
	inflate->avail_in = src_len;
	inflate->next_out = (u8 *)dst;
	inflate->avail_out = PAGE_SIZE;

	ret = zlib_inflate(inflate, Z_SYNC_FLUSH);
	if (ret != Z_STREAM_END)
		return -EINVAL;

	return 0;
}

struct zcomp_backend backend_deflate = {
	.compress	= deflate_compress,
	.decompress	= deflate_decompress,
	.create_ctx	= deflate_create,
	.destroy_ctx	= deflate_destroy,
	.name		= "deflate",
};
