// SPDX-License-Identifier: GPL-2.0-only
/*
 * Analog Devices ADP5585 Keys driver
 *
 * Copyright (C) 2025 Analog Devices, Inc.
 */

#include <linux/bitmap.h>
#include <linux/device.h>
#include <linux/find.h>
#include <linux/input.h>
#include <linux/input/matrix_keypad.h>
#include <linux/mfd/adp5585.h>
#include <linux/module.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/regmap.h>
#include <linux/types.h>

/* As needed for the matrix parsing code */
#define ADP5589_MAX_KEYMAPSIZE		123

struct adp5585_kpad {
	struct input_dev *input;
	unsigned short keycode[ADP5589_MAX_KEYMAPSIZE];
	struct device *dev;
	int row_shift;
	u8 max_rows;
	u8 max_cols;
};

static int adp5585_keys_parse_fw(const struct adp5585_dev *adp5585,
				 struct adp5585_kpad *kpad)
{
	unsigned long row_map, col_map;
	struct device *dev = kpad->dev;
	u32 cols = 0, rows = 0;
	int ret;

	row_map = bitmap_read(adp5585->keypad, 0, kpad->max_rows);
	col_map = bitmap_read(adp5585->keypad, kpad->max_rows, kpad->max_cols);
	/*
	 * Note that given that we get a mask (and the HW allows it), we
	 * can have holes in our keypad (eg: row0, row1 and row7 enabled).
	 * However, for the matrix parsing functions we need to pass the
	 * number of rows/cols as the maximum row/col used plus 1. This
	 * pretty much means we will also have holes in our SW keypad.
	 */
	if (!bitmap_empty(&row_map, kpad->max_rows))
		rows = find_last_bit(&row_map, kpad->max_rows) + 1;
	if (!bitmap_empty(&col_map, kpad->max_cols))
		cols = find_last_bit(&col_map, kpad->max_cols) + 1;

	if (!rows && !cols)
		return dev_err_probe(dev, -EINVAL,
				     "No rows or columns defined for the keypad\n");

	if (cols && !rows)
		return dev_err_probe(dev, -EINVAL,
				     "Cannot have columns with no rows!\n");

	if (rows && !cols)
		return dev_err_probe(dev, -EINVAL,
				     "Cannot have rows with no columns!\n");

	ret = matrix_keypad_build_keymap(NULL, NULL, rows, cols,
					 kpad->keycode, kpad->input);
	if (ret)
		return ret;

	kpad->row_shift = get_count_order(cols);

	if (device_property_present(kpad->dev, "autorepeat"))
		__set_bit(EV_REP, kpad->input->evbit);

	return 0;
}

static int adp5585_keys_setup(const struct adp5585_dev *adp5585,
			      struct adp5585_kpad *kpad)
{
	unsigned long keys_bits, start = 0, nbits = kpad->max_rows;
	const struct adp5585_regs *regs = adp5585->info->regs;
	unsigned int i = 0, max_cols = kpad->max_cols;
	int ret;

	/*
	 * Take care as the below assumes max_rows is always less or equal than
	 * 8 which is true for the supported devices. If we happen to add
	 * another device we need to make sure this still holds true. Although
	 * adding a new device is very unlikely.
	 */
	do {
		keys_bits = bitmap_read(adp5585->keypad, start, nbits);
		if (keys_bits) {
			ret = regmap_write(adp5585->regmap, regs->pin_cfg_a + i,
					   keys_bits);
			if (ret)
				return ret;
		}

		start += nbits;
		if (max_cols > 8) {
			nbits = 8;
			max_cols -= nbits;
		} else {
			nbits = max_cols;
		}

		i++;
	} while (start < kpad->max_rows + kpad->max_cols);

	return 0;
}

static void adp5585_keys_ev_handle(struct device *dev, unsigned int key,
				   bool key_press)
{
	struct adp5585_kpad *kpad = dev_get_drvdata(dev);
	unsigned int row, col, code;

	row = (key - 1) / (kpad->max_cols);
	col = (key - 1) % (kpad->max_cols);
	code = MATRIX_SCAN_CODE(row, col, kpad->row_shift);

	dev_dbg_ratelimited(kpad->dev, "report key(%d) r(%d) c(%d) code(%d)\n",
			    key, row, col, kpad->keycode[code]);

	input_report_key(kpad->input, kpad->keycode[code], key_press);
	input_sync(kpad->input);
}

static void adp5585_keys_ev_handle_clean(void *adp5585)
{
	adp5585_keys_ev_handle_set(adp5585, NULL, NULL);
}

static int adp5585_keys_probe(struct platform_device *pdev)
{
	struct adp5585_dev *adp5585 = dev_get_drvdata(pdev->dev.parent);
	struct device *dev = &pdev->dev;
	struct adp5585_kpad *kpad;
	unsigned int revid;
	const char *phys;
	int ret;

	kpad = devm_kzalloc(dev, sizeof(*kpad), GFP_KERNEL);
	if (!kpad)
		return -ENOMEM;

	if (!adp5585->irq)
		return dev_err_probe(dev, -EINVAL,
				     "IRQ is mandatory for the keypad\n");

	kpad->dev = dev;
	kpad->max_cols = adp5585->info->max_cols;
	kpad->max_rows = adp5585->info->max_rows;

	kpad->input = devm_input_allocate_device(dev);
	if (!kpad->input)
		return -ENOMEM;

	ret = regmap_read(adp5585->regmap, ADP5585_ID, &revid);
	if (ret)
		return dev_err_probe(dev, ret, "Failed to read device ID\n");

	phys = devm_kasprintf(dev, GFP_KERNEL, "%s/input0", pdev->name);
	if (!phys)
		return -ENOMEM;

	kpad->input->name = pdev->name;
	kpad->input->phys = phys;
	kpad->input->dev.parent = dev;

	input_set_drvdata(kpad->input, kpad);

	kpad->input->id.bustype = BUS_I2C;
	kpad->input->id.vendor = 0x0001;
	kpad->input->id.product = 0x0001;
	kpad->input->id.version = revid & ADP5585_REV_ID_MASK;

	device_set_of_node_from_dev(dev, dev->parent);

	ret = adp5585_keys_parse_fw(adp5585, kpad);
	if (ret)
		return ret;

	ret = adp5585_keys_setup(adp5585, kpad);
	if (ret)
		return ret;

	platform_set_drvdata(pdev, kpad);
	adp5585_keys_ev_handle_set(adp5585, adp5585_keys_ev_handle, dev);
	ret = devm_add_action_or_reset(dev, adp5585_keys_ev_handle_clean,
				       adp5585);
	if (ret)
		return ret;

	return input_register_device(kpad->input);
}

static const struct platform_device_id adp5585_keys_id_table[] = {
	{ "adp5585-keys" },
	{ "adp5589-keys" },
	{ }
};
MODULE_DEVICE_TABLE(platform, adp5585_keys_id_table);

static struct platform_driver adp5585_keys_driver = {
	.driver	= {
		.name = "adp5585-keys",
	},
	.probe = adp5585_keys_probe,
	.id_table = adp5585_keys_id_table,
};
module_platform_driver(adp5585_keys_driver);

MODULE_AUTHOR("Nuno Sá <nuno.sa@analog.com>");
MODULE_DESCRIPTION("ADP5585 Keys Driver");
MODULE_LICENSE("GPL");
