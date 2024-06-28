// SPDX-License-Identifier: GPL-2.0-only
/*
 * R-Car Gen3/Gen4 E-FUSE/OTP Driver
 *
 * Copyright (C) 2024 Glider bv
 */

#include <linux/cleanup.h>
#include <linux/device.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/mod_devicetable.h>
#include <linux/mutex.h>
#include <linux/nvmem-provider.h>
#include <linux/platform_data/rcar_fuse.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/property.h>
#include <linux/soc/renesas/rcar-fuse.h>

struct rcar_fuse {
	struct device *dev;
	void __iomem *base;
	unsigned int offset;
	unsigned int nregs;
	struct nvmem_device *nvmem;
};

struct rcar_fuse_data {
	unsigned int bank;	/* 0: PFC + E-FUSE, 1: OPT_MEM + E-FUSE */
	unsigned int offset;
	unsigned int nregs;
};

/* NVMEM access must not use the rcar_fuse singleton */
static int rcar_fuse_nvmem_read(void *priv, unsigned int offset, void *val,
				size_t bytes)
{
	struct rcar_fuse *fuse = priv;
	u32 *buf = val;
	int ret;

	ret = pm_runtime_resume_and_get(fuse->dev);
	if (ret < 0)
		return ret;

	for (; bytes >= 4; bytes -= 4, offset += 4)
		*buf++ = readl(fuse->base + fuse->offset + offset);

	pm_runtime_put(fuse->dev);

	return 0;
}

static struct rcar_fuse *rcar_fuse;
static DEFINE_MUTEX(rcar_fuse_lock);	/* Protects rcar_fuse singleton */

int rcar_fuse_read(unsigned int idx, u32 *val)
{
	int ret;

	guard(mutex)(&rcar_fuse_lock);

	if (!rcar_fuse)
		return -EPROBE_DEFER;

	if (idx >= rcar_fuse->nregs)
		return -EINVAL;

	ret = pm_runtime_resume_and_get(rcar_fuse->dev);
	if (ret < 0)
		return ret;

	*val = readl(rcar_fuse->base + rcar_fuse->offset + idx * sizeof(u32));

	pm_runtime_put(rcar_fuse->dev);

	return 0;
}
EXPORT_SYMBOL_GPL(rcar_fuse_read);

static int rcar_fuse_probe(struct platform_device *pdev)
{
	const struct rcar_fuse_platform_data *pdata;
	const struct rcar_fuse_data *data;
	struct device *dev = &pdev->dev;
	struct nvmem_config nvmem;
	struct rcar_fuse *fuse;
	int ret;

	guard(mutex)(&rcar_fuse_lock);

	if (rcar_fuse)
		return -EEXIST;

	ret = devm_pm_runtime_enable(dev);
	if (ret < 0)
		return ret;

	fuse = devm_kzalloc(dev, sizeof(*fuse), GFP_KERNEL);
	if (!fuse)
		return -ENOMEM;

	fuse->dev = dev;

	data = device_get_match_data(dev);
	if (!data) {
		/* Fuse block integrated into PFC */
		pdata = dev->platform_data;
		if (!pdata)
			return -EINVAL;

		fuse->base = pdata->base;
		fuse->offset = pdata->offset;
		fuse->nregs = pdata->nregs;
	} else {
		/* PFC + E-FUSE or OTP_MEM + E-FUSE */
		fuse->base = devm_platform_ioremap_resource(pdev, data->bank);
		if (IS_ERR(fuse->base))
			return PTR_ERR(fuse->base);

		fuse->offset = data->offset;
		fuse->nregs = data->nregs;
	}

	memset(&nvmem, 0, sizeof(nvmem));
	nvmem.dev = dev;
	nvmem.name = "fuse";
	nvmem.id = -1;
	nvmem.owner = THIS_MODULE;
	nvmem.type = NVMEM_TYPE_OTP;
	nvmem.read_only = true;
	nvmem.root_only = true;
	nvmem.reg_read = rcar_fuse_nvmem_read;
	nvmem.size = fuse->nregs * 4;
	nvmem.word_size = 4;
	nvmem.stride = 4;
	nvmem.priv = fuse;

	fuse->nvmem = devm_nvmem_register(dev, &nvmem);
	if (IS_ERR(fuse->nvmem))
		return dev_err_probe(dev, PTR_ERR(fuse->nvmem),
				     "failed to register NVMEM device\n");

	rcar_fuse = fuse;

	return 0;
}

static void rcar_fuse_remove(struct platform_device *pdev)
{
	guard(mutex)(&rcar_fuse_lock);

	rcar_fuse = NULL;
}

static const struct rcar_fuse_data rcar_fuse_v3u = {
	.bank = 0,
	.offset = 0xc0,
	.nregs = 10,
};

static const struct rcar_fuse_data rcar_fuse_s4 = {
	.bank = 0,
	.offset = 0xc0,
	.nregs = 35,
};

static const struct rcar_fuse_data rcar_fuse_v4h = {
	.bank = 1,
	.offset = 0x100,
	.nregs = 40
};

static const struct rcar_fuse_data rcar_fuse_v4m = {
	.bank = 1,
	.offset = 0x100,
	.nregs = 4,
};

static const struct of_device_id rcar_fuse_match[] = {
	{ .compatible = "renesas,r8a779a0-efuse", .data = &rcar_fuse_v3u },
	{ .compatible = "renesas,r8a779f0-efuse", .data = &rcar_fuse_s4 },
	{ .compatible = "renesas,r8a779g0-otp", .data = &rcar_fuse_v4h },
	{ .compatible = "renesas,r8a779h0-otp", .data = &rcar_fuse_v4m },
	{ /* sentinel */ }
};

static struct platform_driver rcar_fuse_driver = {
	.probe = rcar_fuse_probe,
	.remove_new = rcar_fuse_remove,
	.driver = {
		.name = "rcar_fuse",
		.of_match_table = rcar_fuse_match,
	},
};
module_platform_driver(rcar_fuse_driver);

MODULE_DESCRIPTION("Renesas R-Car E-FUSE/OTP driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Geert Uytterhoeven");
