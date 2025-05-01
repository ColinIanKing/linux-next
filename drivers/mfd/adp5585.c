// SPDX-License-Identifier: GPL-2.0-only
/*
 * Analog Devices ADP5585 I/O expander, PWM controller and keypad controller
 *
 * Copyright 2022 NXP
 * Copyright 2024 Ideas on Board Oy
 * Copyright 2025 Analog Devices Inc.
 */

#include <linux/array_size.h>
#include <linux/bitfield.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/gpio/consumer.h>
#include <linux/mfd/adp5585.h>
#include <linux/mfd/core.h>
#include <linux/minmax.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/regulator/consumer.h>
#include <linux/types.h>

static const struct mfd_cell adp5585_devs[] = {
	MFD_CELL_NAME("adp5585-keys"),
	MFD_CELL_NAME("adp5585-gpio"),
	MFD_CELL_NAME("adp5585-pwm"),

};

static const struct mfd_cell adp5589_devs[] = {
	MFD_CELL_NAME("adp5589-keys"),
	MFD_CELL_NAME("adp5589-gpio"),
	MFD_CELL_NAME("adp5589-pwm"),

};

static const struct regmap_range adp5585_volatile_ranges[] = {
	regmap_reg_range(ADP5585_ID, ADP5585_GPI_STATUS_B),
};

static const struct regmap_access_table adp5585_volatile_regs = {
	.yes_ranges = adp5585_volatile_ranges,
	.n_yes_ranges = ARRAY_SIZE(adp5585_volatile_ranges),
};

static const struct regmap_range adp5589_volatile_ranges[] = {
	regmap_reg_range(ADP5585_ID, ADP5589_GPI_STATUS_C),
};

static const struct regmap_access_table adp5589_volatile_regs = {
	.yes_ranges = adp5589_volatile_ranges,
	.n_yes_ranges = ARRAY_SIZE(adp5589_volatile_ranges),
};

/*
 * Chip variants differ in the default configuration of pull-up and pull-down
 * resistors, and therefore have different default register values:
 *
 * - The -00, -01 and -03 variants (collectively referred to as
 *   ADP5585_REGMAP_00) have pull-up on all GPIO pins by default.
 * - The -02 variant has no default pull-up or pull-down resistors.
 * - The -04 variant has default pull-down resistors on all GPIO pins.
 */

static const u8 adp5585_regmap_defaults_00[ADP5585_MAX_REG + 1] = {
	/* 0x00 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x08 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x10 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x18 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x20 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x28 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x30 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x38 */ 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 adp5585_regmap_defaults_02[ADP5585_MAX_REG + 1] = {
	/* 0x00 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x08 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x10 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3,
	/* 0x18 */ 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x20 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x28 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x30 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x38 */ 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 adp5585_regmap_defaults_04[ADP5585_MAX_REG + 1] = {
	/* 0x00 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x08 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x10 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55,
	/* 0x18 */ 0x05, 0x55, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x20 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x28 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x30 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x38 */ 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 adp5589_regmap_defaults_00[ADP5589_MAX_REG + 1] = {
	/* 0x00 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x08 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x10 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x18 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x20 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x28 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x30 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x38 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x40 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x48 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 adp5589_regmap_defaults_01[ADP5589_MAX_REG + 1] = {
	/* 0x00 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x08 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x10 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x18 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x20 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x28 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x30 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x38 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
	/* 0x40 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x48 */ 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
};

static const u8 adp5589_regmap_defaults_02[ADP5589_MAX_REG + 1] = {
	/* 0x00 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x08 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x10 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x18 */ 0x00, 0x41, 0x01, 0x00, 0x11, 0x04, 0x00, 0x00,
	/* 0x20 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x28 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x30 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x38 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x40 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* 0x48 */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

enum adp5585_regmap_type {
	ADP5585_REGMAP_00,
	ADP5585_REGMAP_02,
	ADP5585_REGMAP_04,
	ADP5589_REGMAP_00,
	ADP5589_REGMAP_01,
	ADP5589_REGMAP_02,
};

static const struct regmap_config adp5585_regmap_configs[] = {
	[ADP5585_REGMAP_00] = {
		.reg_bits = 8,
		.val_bits = 8,
		.max_register = ADP5585_MAX_REG,
		.volatile_table = &adp5585_volatile_regs,
		.cache_type = REGCACHE_MAPLE,
		.reg_defaults_raw = adp5585_regmap_defaults_00,
		.num_reg_defaults_raw = sizeof(adp5585_regmap_defaults_00),
	},
	[ADP5585_REGMAP_02] = {
		.reg_bits = 8,
		.val_bits = 8,
		.max_register = ADP5585_MAX_REG,
		.volatile_table = &adp5585_volatile_regs,
		.cache_type = REGCACHE_MAPLE,
		.reg_defaults_raw = adp5585_regmap_defaults_02,
		.num_reg_defaults_raw = sizeof(adp5585_regmap_defaults_02),
	},
	[ADP5585_REGMAP_04] = {
		.reg_bits = 8,
		.val_bits = 8,
		.max_register = ADP5585_MAX_REG,
		.volatile_table = &adp5585_volatile_regs,
		.cache_type = REGCACHE_MAPLE,
		.reg_defaults_raw = adp5585_regmap_defaults_04,
		.num_reg_defaults_raw = sizeof(adp5585_regmap_defaults_04),
	},
	[ADP5589_REGMAP_00] = {
		.reg_bits = 8,
		.val_bits = 8,
		.max_register = ADP5589_MAX_REG,
		.volatile_table = &adp5589_volatile_regs,
		.cache_type = REGCACHE_MAPLE,
		.reg_defaults_raw = adp5589_regmap_defaults_00,
		.num_reg_defaults_raw = sizeof(adp5589_regmap_defaults_00),
	},
	[ADP5589_REGMAP_01] = {
		.reg_bits = 8,
		.val_bits = 8,
		.max_register = ADP5589_MAX_REG,
		.volatile_table = &adp5589_volatile_regs,
		.cache_type = REGCACHE_MAPLE,
		.reg_defaults_raw = adp5589_regmap_defaults_01,
		.num_reg_defaults_raw = sizeof(adp5589_regmap_defaults_01),
	},
	[ADP5589_REGMAP_02] = {
		.reg_bits = 8,
		.val_bits = 8,
		.max_register = ADP5589_MAX_REG,
		.volatile_table = &adp5589_volatile_regs,
		.cache_type = REGCACHE_MAPLE,
		.reg_defaults_raw = adp5589_regmap_defaults_02,
		.num_reg_defaults_raw = sizeof(adp5589_regmap_defaults_02),
	},
};

static const struct adp5585_regs adp5585_regs = {
	.debounce_dis_a = ADP5585_DEBOUNCE_DIS_A,
	.rpull_cfg_a = ADP5585_RPULL_CONFIG_A,
	.gpo_data_a = ADP5585_GPO_DATA_OUT_A,
	.gpo_out_a = ADP5585_GPO_OUT_MODE_A,
	.gpio_dir_a = ADP5585_GPIO_DIRECTION_A,
	.gpi_stat_a = ADP5585_GPI_STATUS_A,
	.gpi_ev_a = ADP5585_GPI_EVENT_EN_A,
	.gpi_int_lvl_a = ADP5585_GPI_INT_LEVEL_A,
	.pwm_cfg = ADP5585_PWM_CFG,
	.pwm_offt_low = ADP5585_PWM_OFFT_LOW,
	.pwm_ont_low = ADP5585_PWM_ONT_LOW,
	.reset_cfg = ADP5585_RESET_CFG,
	.gen_cfg = ADP5585_GENERAL_CFG,
	.ext_cfg = ADP5585_PIN_CONFIG_C,
	.pin_cfg_a = ADP5585_PIN_CONFIG_A,
	.poll_ptime_cfg = ADP5585_POLL_PTIME_CFG,
	.int_en = ADP5585_INT_EN,
	.reset1_event_a = ADP5585_RESET1_EVENT_A,
	.reset2_event_a = ADP5585_RESET2_EVENT_A,
};

static const struct adp5585_regs adp5589_regs = {
	.debounce_dis_a = ADP5589_DEBOUNCE_DIS_A,
	.rpull_cfg_a = ADP5589_RPULL_CONFIG_A,
	.gpo_data_a = ADP5589_GPO_DATA_OUT_A,
	.gpo_out_a = ADP5589_GPO_OUT_MODE_A,
	.gpio_dir_a = ADP5589_GPIO_DIRECTION_A,
	.gpi_stat_a = ADP5589_GPI_STATUS_A,
	.gpi_ev_a = ADP5589_GPI_EVENT_EN_A,
	.gpi_int_lvl_a = ADP5589_GPI_INT_LEVEL_A,
	.pwm_cfg = ADP5589_PWM_CFG,
	.pwm_offt_low = ADP5589_PWM_OFFT_LOW,
	.pwm_ont_low = ADP5589_PWM_ONT_LOW,
	.reset_cfg = ADP5589_RESET_CFG,
	.gen_cfg = ADP5589_GENERAL_CFG,
	.ext_cfg = ADP5589_PIN_CONFIG_D,
	.pin_cfg_a = ADP5589_PIN_CONFIG_A,
	.poll_ptime_cfg = ADP5589_POLL_PTIME_CFG,
	.int_en = ADP5589_INT_EN,
	.reset1_event_a = ADP5589_RESET1_EVENT_A,
	.reset2_event_a = ADP5589_RESET2_EVENT_A,
};

static const struct adp5585_info adp5585_info = {
	.adp5585_devs = adp5585_devs,
	.regmap_config = &adp5585_regmap_configs[ADP5585_REGMAP_00],
	.n_devs = ARRAY_SIZE(adp5585_devs),
	.id = ADP5585_MAN_ID_VALUE,
	.regs = &adp5585_regs,
	.max_rows = ADP5585_MAX_ROW_NUM,
	.max_cols = ADP5585_MAX_COL_NUM,
	.gpi_ev_base = ADP5585_GPI_EVENT_START,
	.gpi_ev_end = ADP5585_GPI_EVENT_END,
};

static const struct adp5585_info adp5585_01_info = {
	.adp5585_devs = adp5585_devs,
	.regmap_config = &adp5585_regmap_configs[ADP5585_REGMAP_00],
	.n_devs = ARRAY_SIZE(adp5585_devs),
	.id = ADP5585_MAN_ID_VALUE,
	.has_row5 = true,
	.regs = &adp5585_regs,
	.max_rows = ADP5585_MAX_ROW_NUM,
	.max_cols = ADP5585_MAX_COL_NUM,
	.gpi_ev_base = ADP5585_GPI_EVENT_START,
	.gpi_ev_end = ADP5585_GPI_EVENT_END,
};

static const struct adp5585_info adp5585_02_info = {
	.adp5585_devs = adp5585_devs,
	.regmap_config = &adp5585_regmap_configs[ADP5585_REGMAP_02],
	.n_devs = ARRAY_SIZE(adp5585_devs),
	.id = ADP5585_MAN_ID_VALUE,
	.regs = &adp5585_regs,
	.max_rows = ADP5585_MAX_ROW_NUM,
	.max_cols = ADP5585_MAX_COL_NUM,
	.gpi_ev_base = ADP5585_GPI_EVENT_START,
	.gpi_ev_end = ADP5585_GPI_EVENT_END,
};

static const struct adp5585_info adp5585_04_info = {
	.adp5585_devs = adp5585_devs,
	.regmap_config = &adp5585_regmap_configs[ADP5585_REGMAP_04],
	.n_devs = ARRAY_SIZE(adp5585_devs),
	.id = ADP5585_MAN_ID_VALUE,
	.regs = &adp5585_regs,
	.max_rows = ADP5585_MAX_ROW_NUM,
	.max_cols = ADP5585_MAX_COL_NUM,
	.gpi_ev_base = ADP5585_GPI_EVENT_START,
	.gpi_ev_end = ADP5585_GPI_EVENT_END,
};

static const struct adp5585_info adp5589_info = {
	.adp5585_devs = adp5589_devs,
	.regmap_config = &adp5585_regmap_configs[ADP5589_REGMAP_00],
	.n_devs = ARRAY_SIZE(adp5589_devs),
	.id = ADP5589_MAN_ID_VALUE,
	.has_row5 = true,
	.has_unlock = true,
	.regs = &adp5589_regs,
	.max_rows = ADP5589_MAX_ROW_NUM,
	.max_cols = ADP5589_MAX_COL_NUM,
	.gpi_ev_base = ADP5589_GPI_EVENT_START,
	.gpi_ev_end = ADP5589_GPI_EVENT_END,
};

static const struct adp5585_info adp5589_01_info = {
	.adp5585_devs = adp5589_devs,
	.regmap_config = &adp5585_regmap_configs[ADP5589_REGMAP_01],
	.n_devs = ARRAY_SIZE(adp5589_devs),
	.id = ADP5589_MAN_ID_VALUE,
	.has_row5 = true,
	.has_unlock = true,
	.regs = &adp5589_regs,
	.max_rows = ADP5589_MAX_ROW_NUM,
	.max_cols = ADP5589_MAX_COL_NUM,
	.gpi_ev_base = ADP5589_GPI_EVENT_START,
	.gpi_ev_end = ADP5589_GPI_EVENT_END,
};

static const struct adp5585_info adp5589_02_info = {
	.adp5585_devs = adp5589_devs,
	.regmap_config = &adp5585_regmap_configs[ADP5589_REGMAP_02],
	.n_devs = ARRAY_SIZE(adp5589_devs),
	.id = ADP5589_MAN_ID_VALUE,
	.has_row5 = true,
	.has_unlock = true,
	.regs = &adp5589_regs,
	.max_rows = ADP5589_MAX_ROW_NUM,
	.max_cols = ADP5589_MAX_COL_NUM,
	.gpi_ev_base = ADP5589_GPI_EVENT_START,
	.gpi_ev_end = ADP5589_GPI_EVENT_END,
};

static int adp5585_keys_validate_key(const struct adp5585_dev *adp5585, u32 key,
				     bool is_gpi)
{
	const struct adp5585_info *info = adp5585->info;
	struct device *dev = adp5585->dev;
	u32 row, col;

	if (is_gpi) {
		u32 gpi = key - adp5585->info->gpi_ev_base;

		if (!info->has_row5 && gpi == ADP5585_ROW5)
			return dev_err_probe(dev, -EINVAL,
					     "Invalid unlock/reset GPI(%u) not supported\n",
					     gpi);

		/* check if it's being used in the keypad */
		if (test_bit(gpi, adp5585->keypad))
			return dev_err_probe(dev, -EINVAL,
					     "Invalid unlock/reset GPI(%u) being used in the keypad\n",
					     gpi);

		return 0;
	}

	row = (key - 1) / info->max_cols;
	col = (key - 1) % info->max_cols;

	/* both the row and col must be part of the keypad */
	if (test_bit(row, adp5585->keypad) &&
	    test_bit(col + info->max_rows, adp5585->keypad))
		return 0;

	return dev_err_probe(dev, -EINVAL,
			     "Invalid unlock/reset key(%u) not used in the keypad\n", key);
}

static int adp5585_keys_parse_array(const struct adp5585_dev *adp5585,
				    const char *prop, u32 *keys, u32 *n_keys,
				    u32 max_keys, bool reset_key)
{
	const struct adp5585_info *info = adp5585->info;
	struct device *dev = adp5585->dev;
	unsigned int key, max_keypad;
	int ret;

	ret = device_property_count_u32(dev, prop);
	if (ret < 0)
		return 0;

	*n_keys = ret;

	if (!info->has_unlock && !reset_key)
		return dev_err_probe(dev, -EOPNOTSUPP,
				     "Unlock keys not supported\n");

	if (*n_keys > max_keys)
		return dev_err_probe(dev, -EINVAL,
				     "Invalid number of keys(%u > %u) for %s\n",
				     *n_keys, max_keys, prop);

	ret = device_property_read_u32_array(dev, prop, keys, *n_keys);
	if (ret)
		return ret;

	max_keypad = adp5585->info->max_rows * adp5585->info->max_cols;

	for (key = 0; key < *n_keys; key++) {
		/* part of the keypad... */
		if (in_range(keys[key], 1, max_keypad)) {
			/* is it part of the keypad?! */
			ret = adp5585_keys_validate_key(adp5585, keys[key],
							false);
			if (ret)
				return ret;

			continue;
		}

		/* part of gpio-keys... */
		if (in_range(keys[key], adp5585->info->gpi_ev_base,
			     info->max_cols + info->max_rows)) {
			/* is the GPI being used as part of the keypad?! */
			ret = adp5585_keys_validate_key(adp5585, keys[key],
							true);
			if (ret)
				return ret;

			continue;
		}

		if (!reset_key && keys[key] == 127)
			continue;

		return dev_err_probe(dev, -EINVAL, "Invalid key(%u) for %s\n",
				     keys[key], prop);
	}

	return 0;
}

static int adp5585_keys_unlock_parse(struct adp5585_dev *adp5585)
{
	struct device *dev = adp5585->dev;
	int ret;

	ret = adp5585_keys_parse_array(adp5585, "adi,unlock-keys",
				       adp5585->unlock_keys,
				       &adp5585->nkeys_unlock,
				       ARRAY_SIZE(adp5585->unlock_keys), false);
	if (ret)
		return ret;
	if (!adp5585->nkeys_unlock)
		/* no unlock keys */
		return 0;

	ret = device_property_read_u32(dev, "adi,unlock-trigger-sec",
				       &adp5585->unlock_time);
	if (!ret) {
		if (adp5585->unlock_time > ADP5585_MAX_UNLOCK_TIME_SEC)
			return dev_err_probe(dev, -EINVAL,
					     "Invalid unlock time(%u > %d)\n",
					     adp5585->unlock_time,
					     ADP5585_MAX_UNLOCK_TIME_SEC);
	}

	return 0;
}

static int adp5585_keys_reset_parse(struct adp5585_dev *adp5585)
{
	const struct adp5585_info *info = adp5585->info;
	struct device *dev = adp5585->dev;
	u32 prop_val;
	int ret;

	ret = adp5585_keys_parse_array(adp5585, "adi,reset1-keys",
				       adp5585->reset1_keys,
				       &adp5585->nkeys_reset1,
				       ARRAY_SIZE(adp5585->reset1_keys), true);
	if (ret)
		return ret;

	if (adp5585->nkeys_reset1 > 0) {
		if (test_bit(ADP5585_ROW4, adp5585->keypad))
			return dev_err_probe(dev, -EINVAL,
					     "Invalid reset1 output(R4) being used in the keypad\n");

		if (device_property_read_bool(dev, "adi,reset1-active-high"))
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_RESET1_POL, 1);
	}

	ret = adp5585_keys_parse_array(adp5585, "adi,reset2-keys",
				       adp5585->reset2_keys,
				       &adp5585->nkeys_reset2,
				       ARRAY_SIZE(adp5585->reset2_keys), true);
	if (ret)
		return ret;

	if (adp5585->nkeys_reset2 > 0) {
		if (test_bit(info->max_rows + ADP5585_COL4, adp5585->keypad))
			return dev_err_probe(dev, -EINVAL,
					     "Invalid reset2 output(C4) being used in the keypad\n");

		if (device_property_read_bool(dev, "adi,reset2-active-high"))
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_RESET2_POL, 1);
	}

	if (!adp5585->nkeys_reset1 && !adp5585->nkeys_reset2)
		return 0;

	if (device_property_read_bool(dev, "adi,rst-passtrough-enable"))
		adp5585->reset_cfg |= FIELD_PREP(ADP5585_RST_PASSTHRU_EN, 1);

	ret = device_property_read_u32(dev, "adi,reset-trigger-ms", &prop_val);
	if (!ret) {
		switch (prop_val) {
		case 0:
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_RESET_TRIG_TIME, 0);
			break;
		case 1000:
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_RESET_TRIG_TIME, 1);
			break;
		case 1500:
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_RESET_TRIG_TIME, 2);
			break;
		case 2000:
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_RESET_TRIG_TIME, 3);
			break;
		case 2500:
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_RESET_TRIG_TIME, 4);
			break;
		case 3000:
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_RESET_TRIG_TIME, 5);
			break;
		case 3500:
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_RESET_TRIG_TIME, 6);
			break;
		case 4000:
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_RESET_TRIG_TIME, 7);
			break;
		default:
			return dev_err_probe(dev, -EINVAL,
					     "Invalid value(%u) for adi,reset-trigger-ms\n",
					     prop_val);
		}
	}

	ret = device_property_read_u32(dev, "adi,reset-pulse-width-us",
				       &prop_val);
	if (!ret) {
		switch (prop_val) {
		case 500:
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_PULSE_WIDTH, 0);
			break;
		case 1000:
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_PULSE_WIDTH, 1);
			break;
		case 2000:
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_PULSE_WIDTH, 2);
			break;
		case 10000:
			adp5585->reset_cfg |= FIELD_PREP(ADP5585_PULSE_WIDTH, 3);
			break;
		default:
			return dev_err_probe(dev, -EINVAL,
					     "Invalid value(%u) for adi,reset-pulse-width-us\n",
					     prop_val);
		}
	}

	return 0;
}

static int adp5585_parse_fw(struct device *dev, struct adp5585_dev *adp5585)
{
	const struct adp5585_info *info = adp5585->info;
	unsigned int n_pins = info->max_cols + info->max_rows;
	unsigned int *keypad_pins;
	unsigned int prop_val;
	int n_keys, key, ret;

	adp5585->keypad = devm_bitmap_zalloc(dev, n_pins, GFP_KERNEL);
	if (!adp5585->keypad)
		return -ENOMEM;

	if (device_property_present(dev, "#pwm-cells"))
		adp5585->has_pwm = true;

	n_keys = device_property_count_u32(dev, "adi,keypad-pins");
	if (n_keys <= 0)
		goto no_keypad;
	if (n_keys > n_pins)
		return -EINVAL;

	keypad_pins = devm_kcalloc(dev, n_keys, sizeof(*keypad_pins),
				   GFP_KERNEL);
	if (!keypad_pins)
		return -ENOMEM;

	ret = device_property_read_u32_array(dev, "adi,keypad-pins",
					     keypad_pins, n_keys);
	if (ret)
		return ret;

	for (key = 0; key < n_keys; key++) {
		if (keypad_pins[key] >= n_pins)
			return -EINVAL;
		if (adp5585->has_pwm && keypad_pins[key] == ADP5585_ROW3)
			return dev_err_probe(dev, -EINVAL,
					     "Invalid PWM pin being used in the keypad\n");
		if (!info->has_row5 && keypad_pins[key] == ADP5585_ROW5)
			return dev_err_probe(dev, -EINVAL,
					     "Invalid row5 being used in the keypad\n");
		__set_bit(keypad_pins[key], adp5585->keypad);
	}

no_keypad:
	ret = device_property_read_u32(dev, "adi,key-poll-ms", &prop_val);
	if (!ret) {
		switch (prop_val) {
		case 10:
			fallthrough;
		case 20:
			fallthrough;
		case 30:
			fallthrough;
		case 40:
			adp5585->key_poll_time = prop_val / 10 - 1;
			break;
		default:
			return dev_err_probe(dev, -EINVAL,
					     "Invalid value(%u) for adi,key-poll-ms\n",
					     prop_val);
		}
	}

	ret = adp5585_keys_unlock_parse(adp5585);
	if (ret)
		return ret;

	return adp5585_keys_reset_parse(adp5585);
}

static void adp5585_report_events(struct adp5585_dev *adp5585, int ev_cnt)
{
	unsigned int i;

	guard(mutex)(&adp5585->ev_lock);

	for (i = 0; i < ev_cnt; i++) {
		unsigned int key, key_val, key_press;
		int ret;

		ret = regmap_read(adp5585->regmap, ADP5585_FIFO_1 + i, &key);
		if (ret)
			return;

		key_val = FIELD_GET(ADP5585_KEY_EVENT_MASK, key);
		key_press = FIELD_GET(ADP5585_KEV_EV_PRESS_MASK, key);

		if (key_val >= adp5585->info->gpi_ev_base &&
		    key_val <= adp5585->info->gpi_ev_end) {
			unsigned int gpi = key_val - adp5585->info->gpi_ev_base;

			if (adp5585->gpio_irq_handle)
				adp5585->gpio_irq_handle(adp5585->gpio_dev, gpi,
							 key_press);
		} else if (adp5585->keys_irq_handle) {
			adp5585->keys_irq_handle(adp5585->input_dev, key_val,
						 key_press);
		}
	}
}

static irqreturn_t adp5585_irq(int irq, void *data)
{
	struct adp5585_dev *adp5585 = data;
	unsigned int status, ev_cnt;
	int ret;

	ret = regmap_read(adp5585->regmap, ADP5585_INT_STATUS, &status);
	if (ret)
		return IRQ_HANDLED;

	if (status & ADP5585_OVRFLOW_INT)
		dev_err_ratelimited(adp5585->dev, "Event Overflow Error\n");

	if (!(status & ADP5585_EVENT_INT))
		goto out_irq;

	ret = regmap_read(adp5585->regmap, ADP5585_STATUS, &ev_cnt);
	if (ret)
		goto out_irq;

	ev_cnt = FIELD_GET(ADP5585_EC_MASK, ev_cnt);
	if (!ev_cnt)
		goto out_irq;

	adp5585_report_events(adp5585, ev_cnt);
out_irq:
	regmap_write(adp5585->regmap, ADP5585_INT_STATUS, status);
	return IRQ_HANDLED;
}

static void adp5585_osc_disable(void *data)
{
	const struct adp5585_dev *adp5585 = data;

	regmap_write(adp5585->regmap, ADP5585_GENERAL_CFG, 0);
}

static int adp5585_setup(struct adp5585_dev *adp5585)
{
	const struct adp5585_regs *regs = adp5585->info->regs;
	unsigned int reg_val, i;
	int ret;

	for (i = 0; i < adp5585->nkeys_unlock; i++) {
		ret = regmap_write(adp5585->regmap, ADP5589_UNLOCK1 + i,
				   adp5585->unlock_keys[i] | ADP5589_UNLOCK_EV_PRESS);
		if (ret)
			return ret;
	}

	if (adp5585->nkeys_unlock) {
		ret = regmap_update_bits(adp5585->regmap, ADP5589_UNLOCK_TIMERS,
					 ADP5589_UNLOCK_TIMER,
					 adp5585->unlock_time);
		if (ret)
			return ret;

		ret = regmap_set_bits(adp5585->regmap, ADP5589_LOCK_CFG,
				      ADP5589_LOCK_EN);
		if (ret)
			return ret;
	}

	for (i = 0; i < adp5585->nkeys_reset1; i++) {
		ret = regmap_write(adp5585->regmap, regs->reset1_event_a + i,
				   adp5585->reset1_keys[i] | ADP5585_RESET_EV_PRESS);
		if (ret)
			return ret;
	}

	for (i = 0; i < adp5585->nkeys_reset2; i++) {
		ret = regmap_write(adp5585->regmap, regs->reset2_event_a + i,
				   adp5585->reset2_keys[i] | ADP5585_RESET_EV_PRESS);
		if (ret)
			return ret;
	}

	if (adp5585->nkeys_reset1 || adp5585->nkeys_reset2) {
		ret = regmap_write(adp5585->regmap, regs->reset_cfg,
				   adp5585->reset_cfg);
		if (ret)
			return ret;

		reg_val = 0;
		if (adp5585->nkeys_reset1)
			reg_val = ADP5585_R4_EXTEND_CFG_RESET1;
		if (adp5585->nkeys_reset2)
			reg_val |= ADP5585_C4_EXTEND_CFG_RESET2;

		ret = regmap_update_bits(adp5585->regmap, regs->ext_cfg,
					 ADP5585_C4_EXTEND_CFG_MASK |
						 ADP5585_R4_EXTEND_CFG_MASK,
					 reg_val);
		if (ret)
			return ret;
	}

	for (i = 0; i < ADP5585_EV_MAX; i++) {
		ret = regmap_read(adp5585->regmap, ADP5585_FIFO_1 + i,
				  &reg_val);
		if (ret)
			return ret;
	}

	ret = regmap_write(adp5585->regmap, regs->poll_ptime_cfg,
			   adp5585->key_poll_time);
	if (ret)
		return ret;

	ret = regmap_write(adp5585->regmap, regs->gen_cfg,
			   ADP5585_OSC_FREQ_500KHZ | ADP5585_INT_CFG |
			   ADP5585_OSC_EN);
	if (ret)
		return ret;

	return devm_add_action_or_reset(adp5585->dev, adp5585_osc_disable,
					adp5585);
}

static void adp5585_irq_disable(void *data)
{
	struct adp5585_dev *adp5585 = data;

	regmap_write(adp5585->regmap, adp5585->info->regs->int_en, 0);
}

static int adp5585_irq_enable(struct i2c_client *i2c,
			      struct adp5585_dev *adp5585)
{
	const struct adp5585_regs *regs = adp5585->info->regs;
	unsigned int stat;
	int ret;

	if (i2c->irq <= 0)
		return 0;

	ret = devm_request_threaded_irq(&i2c->dev, i2c->irq, NULL, adp5585_irq,
					IRQF_ONESHOT, i2c->name, adp5585);
	if (ret)
		return ret;

	/* clear any possible outstanding interrupt before enabling them... */
	ret = regmap_read(adp5585->regmap, ADP5585_INT_STATUS, &stat);
	if (ret)
		return ret;

	ret = regmap_write(adp5585->regmap, ADP5585_INT_STATUS, stat);
	if (ret)
		return ret;

	ret = regmap_write(adp5585->regmap, regs->int_en,
			   ADP5585_OVRFLOW_IEN | ADP5585_EVENT_IEN);
	if (ret)
		return ret;

	return devm_add_action_or_reset(&i2c->dev, adp5585_irq_disable,
					adp5585);
}

static int adp5585_i2c_probe(struct i2c_client *i2c)
{
	const struct adp5585_info *info;
	struct adp5585_dev *adp5585;
	struct gpio_desc *gpio;
	unsigned int id;
	int ret;

	adp5585 = devm_kzalloc(&i2c->dev, sizeof(*adp5585), GFP_KERNEL);
	if (!adp5585)
		return -ENOMEM;

	i2c_set_clientdata(i2c, adp5585);

	info = i2c_get_match_data(i2c);
	if (!info)
		return -ENODEV;

	adp5585->info = info;
	adp5585->dev = &i2c->dev;
	adp5585->irq = i2c->irq;

	ret = devm_regulator_get_enable(&i2c->dev, "vdd");
	if (ret)
		return ret;

	gpio = devm_gpiod_get_optional(&i2c->dev, "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(gpio))
		return PTR_ERR(gpio);

	if (gpio) {
		fsleep(30);
		gpiod_set_value_cansleep(gpio, 0);
		fsleep(60);
	}

	adp5585->regmap = devm_regmap_init_i2c(i2c, info->regmap_config);
	if (IS_ERR(adp5585->regmap))
		return dev_err_probe(&i2c->dev, PTR_ERR(adp5585->regmap),
				     "Failed to initialize register map\n");

	ret = regmap_read(adp5585->regmap, ADP5585_ID, &id);
	if (ret)
		return dev_err_probe(&i2c->dev, ret,
				     "Failed to read device ID\n");

	id &= ADP5585_MAN_ID_MASK;
	if (id != adp5585->info->id)
		return dev_err_probe(&i2c->dev, -ENODEV,
				     "Invalid device ID 0x%02x\n", id);

	ret = adp5585_parse_fw(&i2c->dev, adp5585);
	if (ret)
		return ret;

	ret = adp5585_setup(adp5585);
	if (ret)
		return ret;

	ret = devm_mutex_init(&i2c->dev, &adp5585->ev_lock);
	if (ret)
		return ret;

	ret = devm_mfd_add_devices(&i2c->dev, PLATFORM_DEVID_AUTO,
				   adp5585->info->adp5585_devs,
				   adp5585->info->n_devs, NULL, 0, NULL);
	if (ret)
		return dev_err_probe(&i2c->dev, ret,
				     "Failed to add child devices\n");

	return adp5585_irq_enable(i2c, adp5585);
}

static int adp5585_suspend(struct device *dev)
{
	struct adp5585_dev *adp5585 = dev_get_drvdata(dev);

	if (adp5585->irq)
		disable_irq(adp5585->irq);

	regcache_cache_only(adp5585->regmap, true);

	return 0;
}

static int adp5585_resume(struct device *dev)
{
	struct adp5585_dev *adp5585 = dev_get_drvdata(dev);
	int ret;

	regcache_cache_only(adp5585->regmap, false);
	regcache_mark_dirty(adp5585->regmap);

	ret = regcache_sync(adp5585->regmap);
	if (ret)
		return ret;

	if (adp5585->irq)
		enable_irq(adp5585->irq);

	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(adp5585_pm, adp5585_suspend, adp5585_resume);

static const struct of_device_id adp5585_of_match[] = {
	{
		.compatible = "adi,adp5585-00",
		.data = &adp5585_info,
	}, {
		.compatible = "adi,adp5585-01",
		.data = &adp5585_01_info,
	}, {
		.compatible = "adi,adp5585-02",
		.data = &adp5585_02_info,
	}, {
		.compatible = "adi,adp5585-03",
		.data = &adp5585_info,
	}, {
		.compatible = "adi,adp5585-04",
		.data = &adp5585_04_info,
	}, {
		.compatible = "adi,adp5589-00",
		.data = &adp5589_info,
	}, {
		.compatible = "adi,adp5589-01",
		.data = &adp5589_01_info,
	}, {
		.compatible = "adi,adp5589-02",
		.data = &adp5589_02_info,
	}, {
		.compatible = "adi,adp5589",
		.data = &adp5589_info,
	},
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, adp5585_of_match);

static struct i2c_driver adp5585_i2c_driver = {
	.driver = {
		.name = "adp5585",
		.of_match_table = adp5585_of_match,
		.pm = pm_sleep_ptr(&adp5585_pm),
	},
	.probe = adp5585_i2c_probe,
};
module_i2c_driver(adp5585_i2c_driver);

MODULE_DESCRIPTION("ADP5585 core driver");
MODULE_AUTHOR("Haibo Chen <haibo.chen@nxp.com>");
MODULE_LICENSE("GPL");
