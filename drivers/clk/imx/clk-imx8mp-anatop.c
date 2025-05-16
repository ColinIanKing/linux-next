// SPDX-License-Identifier: GPL-2.0
/*
 * clk-imx8mp-anatop.c - NXP i.MX8MP anatop clock driver
 *
 * Copyright (c) 2025 Dario Binacchi <dario.binacchi@amarulasolutions.com>
 */

#include <dt-bindings/clock/imx8mp-clock.h>

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/of_platform.h>

#include "clk.h"

#define IMX8MP_ANATOP_CLK_END		(IMX8MP_ANATOP_CLK_CLKOUT2 + 1)

static const char * const pll_ref_sels[] = { "osc_24m", "dummy", "dummy", "dummy", };
static const char * const audio_pll1_bypass_sels[] = {"audio_pll1", "audio_pll1_ref_sel", };
static const char * const audio_pll2_bypass_sels[] = {"audio_pll2", "audio_pll2_ref_sel", };
static const char * const video_pll_bypass_sels[] = {"video_pll", "video_pll_ref_sel", };
static const char * const dram_pll_bypass_sels[] = {"dram_pll", "dram_pll_ref_sel", };
static const char * const gpu_pll_bypass_sels[] = {"gpu_pll", "gpu_pll_ref_sel", };
static const char * const vpu_pll_bypass_sels[] = {"vpu_pll", "vpu_pll_ref_sel", };
static const char * const arm_pll_bypass_sels[] = {"arm_pll", "arm_pll_ref_sel", };
static const char * const sys_pll1_bypass_sels[] = {"sys_pll1", "sys_pll1_ref_sel", };
static const char * const sys_pll2_bypass_sels[] = {"sys_pll2", "sys_pll2_ref_sel", };
static const char * const sys_pll3_bypass_sels[] = {"sys_pll3", "sys_pll3_ref_sel", };
static const char * const clkout_sels[] = {"audio_pll1_out", "audio_pll2_out", "video_pll_out",
					   "dummy", "dummy", "gpu_pll_out", "vpu_pll_out",
					   "arm_pll_out", "sys_pll1_out", "sys_pll2_out",
					   "sys_pll3_out", "dummy", "dummy", "osc_24m",
					   "dummy", "osc_32k"};

static struct clk_hw_onecell_data *clk_hw_data;
static struct clk_hw **hws;

static int imx8mp_anatop_clocks_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	void __iomem *base;
	int ret;

	base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(base)) {
		dev_err(dev, "failed to get base address\n");
		return PTR_ERR(base);
	}

	clk_hw_data = devm_kzalloc(dev, struct_size(clk_hw_data, hws,
						    IMX8MP_ANATOP_CLK_END),
				   GFP_KERNEL);
	if (WARN_ON(!clk_hw_data))
		return -ENOMEM;

	clk_hw_data->num = IMX8MP_ANATOP_CLK_END;
	hws = clk_hw_data->hws;

	hws[IMX8MP_ANATOP_CLK_DUMMY] = imx_clk_hw_fixed("dummy", 0);
	hws[IMX8MP_ANATOP_CLK_32K] = imx_get_clk_hw_by_name(np, "osc_32k");
	hws[IMX8MP_ANATOP_CLK_24M] = imx_get_clk_hw_by_name(np, "osc_24m");

	hws[IMX8MP_ANATOP_AUDIO_PLL1_REF_SEL] =
		imx_clk_hw_mux("audio_pll1_ref_sel", base + 0x0, 0, 2,
			       pll_ref_sels, ARRAY_SIZE(pll_ref_sels));
	hws[IMX8MP_ANATOP_AUDIO_PLL2_REF_SEL] =
		imx_clk_hw_mux("audio_pll2_ref_sel", base + 0x14, 0, 2,
			       pll_ref_sels, ARRAY_SIZE(pll_ref_sels));
	hws[IMX8MP_ANATOP_VIDEO_PLL_REF_SEL] =
		imx_clk_hw_mux("video_pll_ref_sel", base + 0x28, 0, 2,
			       pll_ref_sels, ARRAY_SIZE(pll_ref_sels));
	hws[IMX8MP_ANATOP_DRAM_PLL_REF_SEL] =
		imx_clk_hw_mux("dram_pll_ref_sel", base + 0x50, 0, 2,
			       pll_ref_sels, ARRAY_SIZE(pll_ref_sels));
	hws[IMX8MP_ANATOP_GPU_PLL_REF_SEL] =
		imx_clk_hw_mux("gpu_pll_ref_sel", base + 0x64, 0, 2,
			       pll_ref_sels, ARRAY_SIZE(pll_ref_sels));
	hws[IMX8MP_ANATOP_VPU_PLL_REF_SEL] =
		imx_clk_hw_mux("vpu_pll_ref_sel", base + 0x74, 0, 2,
			       pll_ref_sels, ARRAY_SIZE(pll_ref_sels));
	hws[IMX8MP_ANATOP_ARM_PLL_REF_SEL] =
		imx_clk_hw_mux("arm_pll_ref_sel", base + 0x84, 0, 2,
			       pll_ref_sels, ARRAY_SIZE(pll_ref_sels));
	hws[IMX8MP_ANATOP_SYS_PLL1_REF_SEL] =
		imx_clk_hw_mux("sys_pll1_ref_sel", base + 0x94, 0, 2,
			       pll_ref_sels, ARRAY_SIZE(pll_ref_sels));
	hws[IMX8MP_ANATOP_SYS_PLL2_REF_SEL] =
		imx_clk_hw_mux("sys_pll2_ref_sel", base + 0x104, 0, 2,
			       pll_ref_sels, ARRAY_SIZE(pll_ref_sels));
	hws[IMX8MP_ANATOP_SYS_PLL3_REF_SEL] =
		imx_clk_hw_mux("sys_pll3_ref_sel", base + 0x114, 0, 2,
			       pll_ref_sels, ARRAY_SIZE(pll_ref_sels));

	hws[IMX8MP_ANATOP_AUDIO_PLL1] =
		imx_clk_hw_pll14xx("audio_pll1", "audio_pll1_ref_sel",
				   base, &imx_1443x_pll);
	hws[IMX8MP_ANATOP_AUDIO_PLL2] =
		imx_clk_hw_pll14xx("audio_pll2", "audio_pll2_ref_sel",
				   base + 0x14, &imx_1443x_pll);
	hws[IMX8MP_ANATOP_VIDEO_PLL] =
		imx_clk_hw_pll14xx("video_pll", "video_pll_ref_sel",
				   base + 0x28, &imx_1443x_pll);
	hws[IMX8MP_ANATOP_DRAM_PLL] =
		imx_clk_hw_pll14xx("dram_pll", "dram_pll_ref_sel",
				   base + 0x50, &imx_1443x_dram_pll);
	hws[IMX8MP_ANATOP_GPU_PLL] =
		imx_clk_hw_pll14xx("gpu_pll", "gpu_pll_ref_sel",
				   base + 0x64, &imx_1416x_pll);
	hws[IMX8MP_ANATOP_VPU_PLL] =
		imx_clk_hw_pll14xx("vpu_pll", "vpu_pll_ref_sel",
				   base + 0x74, &imx_1416x_pll);
	hws[IMX8MP_ANATOP_ARM_PLL] =
		imx_clk_hw_pll14xx("arm_pll", "arm_pll_ref_sel",
				   base + 0x84, &imx_1416x_pll);
	hws[IMX8MP_ANATOP_SYS_PLL1] =
		imx_clk_hw_pll14xx("sys_pll1", "sys_pll1_ref_sel",
				   base + 0x94, &imx_1416x_pll);
	hws[IMX8MP_ANATOP_SYS_PLL2] =
		imx_clk_hw_pll14xx("sys_pll2", "sys_pll2_ref_sel",
				   base + 0x104, &imx_1416x_pll);
	hws[IMX8MP_ANATOP_SYS_PLL3] =
		imx_clk_hw_pll14xx("sys_pll3", "sys_pll3_ref_sel",
				   base + 0x114, &imx_1416x_pll);

	hws[IMX8MP_ANATOP_AUDIO_PLL1_BYPASS] =
		imx_clk_hw_mux_flags("audio_pll1_bypass", base, 16, 1,
				     audio_pll1_bypass_sels,
				     ARRAY_SIZE(audio_pll1_bypass_sels),
				     CLK_SET_RATE_PARENT);
	hws[IMX8MP_ANATOP_AUDIO_PLL2_BYPASS] =
		imx_clk_hw_mux_flags("audio_pll2_bypass", base + 0x14,
				     16, 1, audio_pll2_bypass_sels,
				     ARRAY_SIZE(audio_pll2_bypass_sels),
				     CLK_SET_RATE_PARENT);
	hws[IMX8MP_ANATOP_VIDEO_PLL_BYPASS] =
		imx_clk_hw_mux_flags("video_pll_bypass", base + 0x28,
				     16, 1, video_pll_bypass_sels,
				     ARRAY_SIZE(video_pll_bypass_sels),
				     CLK_SET_RATE_PARENT);
	hws[IMX8MP_ANATOP_DRAM_PLL_BYPASS] =
		imx_clk_hw_mux_flags("dram_pll_bypass", base + 0x50,
				     16, 1, dram_pll_bypass_sels,
				     ARRAY_SIZE(dram_pll_bypass_sels),
				     CLK_SET_RATE_PARENT);
	hws[IMX8MP_ANATOP_GPU_PLL_BYPASS] =
		imx_clk_hw_mux_flags("gpu_pll_bypass", base + 0x64,
				     28, 1, gpu_pll_bypass_sels,
				     ARRAY_SIZE(gpu_pll_bypass_sels),
				     CLK_SET_RATE_PARENT);
	hws[IMX8MP_ANATOP_VPU_PLL_BYPASS] =
		imx_clk_hw_mux_flags("vpu_pll_bypass", base + 0x74,
				     28, 1, vpu_pll_bypass_sels,
				     ARRAY_SIZE(vpu_pll_bypass_sels),
				     CLK_SET_RATE_PARENT);
	hws[IMX8MP_ANATOP_ARM_PLL_BYPASS] =
		imx_clk_hw_mux_flags("arm_pll_bypass", base + 0x84,
				     28, 1, arm_pll_bypass_sels,
				     ARRAY_SIZE(arm_pll_bypass_sels),
				     CLK_SET_RATE_PARENT);
	hws[IMX8MP_ANATOP_SYS_PLL1_BYPASS] =
		imx_clk_hw_mux_flags("sys_pll1_bypass", base + 0x94,
				     28, 1, sys_pll1_bypass_sels,
				     ARRAY_SIZE(sys_pll1_bypass_sels),
				     CLK_SET_RATE_PARENT);
	hws[IMX8MP_ANATOP_SYS_PLL2_BYPASS] =
		imx_clk_hw_mux_flags("sys_pll2_bypass", base + 0x104,
				     28, 1, sys_pll2_bypass_sels,
				     ARRAY_SIZE(sys_pll2_bypass_sels),
				     CLK_SET_RATE_PARENT);
	hws[IMX8MP_ANATOP_SYS_PLL3_BYPASS] =
		imx_clk_hw_mux_flags("sys_pll3_bypass", base + 0x114,
				     28, 1, sys_pll3_bypass_sels,
				     ARRAY_SIZE(sys_pll3_bypass_sels),
				     CLK_SET_RATE_PARENT);

	hws[IMX8MP_ANATOP_AUDIO_PLL1_OUT] =
		imx_clk_hw_gate("audio_pll1_out", "audio_pll1_bypass",
				base, 13);
	hws[IMX8MP_ANATOP_AUDIO_PLL2_OUT] =
		imx_clk_hw_gate("audio_pll2_out", "audio_pll2_bypass",
				base + 0x14, 13);
	hws[IMX8MP_ANATOP_VIDEO_PLL_OUT] =
		imx_clk_hw_gate("video_pll_out", "video_pll_bypass",
				base + 0x28, 13);
	hws[IMX8MP_ANATOP_DRAM_PLL_OUT] =
		imx_clk_hw_gate("dram_pll_out", "dram_pll_bypass",
				base + 0x50, 13);
	hws[IMX8MP_ANATOP_GPU_PLL_OUT] =
		imx_clk_hw_gate("gpu_pll_out", "gpu_pll_bypass",
				base + 0x64, 11);
	hws[IMX8MP_ANATOP_VPU_PLL_OUT] =
		imx_clk_hw_gate("vpu_pll_out", "vpu_pll_bypass",
				base + 0x74, 11);
	hws[IMX8MP_ANATOP_ARM_PLL_OUT] =
		imx_clk_hw_gate("arm_pll_out", "arm_pll_bypass",
				base + 0x84, 11);
	hws[IMX8MP_ANATOP_SYS_PLL3_OUT] =
		imx_clk_hw_gate("sys_pll3_out", "sys_pll3_bypass",
				base + 0x114, 11);

	hws[IMX8MP_ANATOP_SYS_PLL1_OUT] =
		imx_clk_hw_gate("sys_pll1_out", "sys_pll1_bypass",
				base + 0x94, 11);

	hws[IMX8MP_ANATOP_SYS_PLL1_40M] =
		imx_clk_hw_fixed_factor("sys_pll1_40m", "sys_pll1_out", 1, 20);
	hws[IMX8MP_ANATOP_SYS_PLL1_80M] =
		imx_clk_hw_fixed_factor("sys_pll1_80m", "sys_pll1_out", 1, 10);
	hws[IMX8MP_ANATOP_SYS_PLL1_100M] =
		imx_clk_hw_fixed_factor("sys_pll1_100m", "sys_pll1_out", 1, 8);
	hws[IMX8MP_ANATOP_SYS_PLL1_133M] =
		imx_clk_hw_fixed_factor("sys_pll1_133m", "sys_pll1_out", 1, 6);
	hws[IMX8MP_ANATOP_SYS_PLL1_160M] =
		imx_clk_hw_fixed_factor("sys_pll1_160m", "sys_pll1_out", 1, 5);
	hws[IMX8MP_ANATOP_SYS_PLL1_200M] =
		imx_clk_hw_fixed_factor("sys_pll1_200m", "sys_pll1_out", 1, 4);
	hws[IMX8MP_ANATOP_SYS_PLL1_266M] =
		imx_clk_hw_fixed_factor("sys_pll1_266m", "sys_pll1_out", 1, 3);
	hws[IMX8MP_ANATOP_SYS_PLL1_400M] =
		imx_clk_hw_fixed_factor("sys_pll1_400m", "sys_pll1_out", 1, 2);
	hws[IMX8MP_ANATOP_SYS_PLL1_800M] =
		imx_clk_hw_fixed_factor("sys_pll1_800m", "sys_pll1_out", 1, 1);

	hws[IMX8MP_ANATOP_SYS_PLL2_OUT] =
		imx_clk_hw_gate("sys_pll2_out", "sys_pll2_bypass",
				base + 0x104, 11);

	hws[IMX8MP_ANATOP_SYS_PLL2_50M] =
		imx_clk_hw_fixed_factor("sys_pll2_50m", "sys_pll2_out", 1, 20);
	hws[IMX8MP_ANATOP_SYS_PLL2_100M] =
		imx_clk_hw_fixed_factor("sys_pll2_100m", "sys_pll2_out", 1, 10);
	hws[IMX8MP_ANATOP_SYS_PLL2_125M] =
		imx_clk_hw_fixed_factor("sys_pll2_125m", "sys_pll2_out", 1, 8);
	hws[IMX8MP_ANATOP_SYS_PLL2_166M] =
		imx_clk_hw_fixed_factor("sys_pll2_166m", "sys_pll2_out", 1, 6);
	hws[IMX8MP_ANATOP_SYS_PLL2_200M] =
		imx_clk_hw_fixed_factor("sys_pll2_200m", "sys_pll2_out", 1, 5);
	hws[IMX8MP_ANATOP_SYS_PLL2_250M] =
		imx_clk_hw_fixed_factor("sys_pll2_250m", "sys_pll2_out", 1, 4);
	hws[IMX8MP_ANATOP_SYS_PLL2_333M] =
		imx_clk_hw_fixed_factor("sys_pll2_333m", "sys_pll2_out", 1, 3);
	hws[IMX8MP_ANATOP_SYS_PLL2_500M] =
		imx_clk_hw_fixed_factor("sys_pll2_500m", "sys_pll2_out", 1, 2);
	hws[IMX8MP_ANATOP_SYS_PLL2_1000M] =
		imx_clk_hw_fixed_factor("sys_pll2_1000m", "sys_pll2_out", 1, 1);

	hws[IMX8MP_ANATOP_CLK_CLKOUT1_SEL] =
		imx_clk_hw_mux2("clkout1_sel", base + 0x128, 4, 4,
				clkout_sels, ARRAY_SIZE(clkout_sels));
	hws[IMX8MP_ANATOP_CLK_CLKOUT1_DIV] =
		imx_clk_hw_divider("clkout1_div", "clkout1_sel", base + 0x128,
				   0, 4);
	hws[IMX8MP_ANATOP_CLK_CLKOUT1] =
		imx_clk_hw_gate("clkout1", "clkout1_div", base + 0x128, 8);
	hws[IMX8MP_ANATOP_CLK_CLKOUT2_SEL] =
		imx_clk_hw_mux2("clkout2_sel", base + 0x128, 20, 4,
				clkout_sels, ARRAY_SIZE(clkout_sels));
	hws[IMX8MP_ANATOP_CLK_CLKOUT2_DIV] =
		imx_clk_hw_divider("clkout2_div", "clkout2_sel", base + 0x128,
				   16, 4);
	hws[IMX8MP_ANATOP_CLK_CLKOUT2] =
		imx_clk_hw_gate("clkout2", "clkout2_div", base + 0x128, 24);

	imx_check_clk_hws(hws, IMX8MP_ANATOP_CLK_END);

	ret = of_clk_add_hw_provider(np, of_clk_hw_onecell_get, clk_hw_data);
	if (ret < 0) {
		imx_unregister_hw_clocks(hws, IMX8MP_ANATOP_CLK_END);
		return dev_err_probe(dev, ret,
				     "failed to register anatop clock provider\n");
	}

	dev_info(dev, "NXP i.MX8MP anatop clock driver probed\n");
	return 0;
}

static const struct of_device_id imx8mp_anatop_clk_of_match[] = {
	{ .compatible = "fsl,imx8mp-anatop" },
	{ /* Sentinel */ },
};
MODULE_DEVICE_TABLE(of, imx8mp_anatop_clk_of_match);

static struct platform_driver imx8mp_anatop_clk_driver = {
	.probe = imx8mp_anatop_clocks_probe,
	.driver = {
		.name = "imx8mp-anatop",
		/*
		 * Disable bind attributes: clocks are not removed and
		 * reloading the driver will crash or break devices.
		 */
		.suppress_bind_attrs = true,
		.of_match_table = imx8mp_anatop_clk_of_match,
	},
};

module_platform_driver(imx8mp_anatop_clk_driver);

MODULE_AUTHOR("Dario Binacchi <dario.binacchi@amarulasolutions.com>");
MODULE_DESCRIPTION("NXP i.MX8MP anatop clock driver");
MODULE_LICENSE("GPL");
