// SPDX-License-Identifier: GPL-2.0-only
/*
 * Analog Devices ADP5585 GPIO driver
 *
 * Copyright 2022 NXP
 * Copyright 2024 Ideas on Board Oy
 * Copyright 2025 Analog Devices, Inc.
 */

#include <linux/device.h>
#include <linux/gpio/driver.h>
#include <linux/mfd/adp5585.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/types.h>

struct adp5585_gpio_chip {
	unsigned int max_gpio;
	int (*bank)(unsigned int off);
	int (*bit)(unsigned int off);
	bool has_bias_hole;
};

struct adp5585_gpio_dev {
	struct gpio_chip gpio_chip;
	const struct adp5585_gpio_chip *info;
	struct regmap *regmap;
	const struct adp5585_regs *regs;
	unsigned long irq_mask;
	unsigned long irq_en;
	unsigned long irq_active_high;
	/* used for irqchip bus locking */
	struct mutex bus_lock;
};

static int adp5585_gpio_bank(unsigned int off)
{
	return ADP5585_BANK(off);
}

static int adp5585_gpio_bit(unsigned int off)
{
	return ADP5585_BIT(off);
}

static int adp5589_gpio_bank(unsigned int off)
{
	return ADP5589_BANK(off);
}

static int adp5589_gpio_bit(unsigned int off)
{
	return ADP5589_BIT(off);
}

static int adp5585_gpio_get_direction(struct gpio_chip *chip, unsigned int off)
{
	struct adp5585_gpio_dev *adp5585_gpio = gpiochip_get_data(chip);
	const struct adp5585_regs *regs = adp5585_gpio->regs;
	unsigned int bank = adp5585_gpio->info->bank(off);
	unsigned int bit = adp5585_gpio->info->bit(off);
	unsigned int val;

	regmap_read(adp5585_gpio->regmap, regs->gpio_dir_a + bank, &val);

	return val & bit ? GPIO_LINE_DIRECTION_OUT : GPIO_LINE_DIRECTION_IN;
}

static int adp5585_gpio_direction_input(struct gpio_chip *chip, unsigned int off)
{
	struct adp5585_gpio_dev *adp5585_gpio = gpiochip_get_data(chip);
	const struct adp5585_regs *regs = adp5585_gpio->regs;
	unsigned int bank = adp5585_gpio->info->bank(off);
	unsigned int bit = adp5585_gpio->info->bit(off);

	return regmap_clear_bits(adp5585_gpio->regmap, regs->gpio_dir_a + bank,
				 bit);
}

static int adp5585_gpio_direction_output(struct gpio_chip *chip, unsigned int off, int val)
{
	struct adp5585_gpio_dev *adp5585_gpio = gpiochip_get_data(chip);
	const struct adp5585_regs *regs = adp5585_gpio->regs;
	unsigned int bank = adp5585_gpio->info->bank(off);
	unsigned int bit = adp5585_gpio->info->bit(off);
	int ret;

	ret = regmap_update_bits(adp5585_gpio->regmap, regs->gpo_data_a + bank,
				 bit, val ? bit : 0);
	if (ret)
		return ret;

	return regmap_set_bits(adp5585_gpio->regmap, regs->gpio_dir_a + bank,
			       bit);
}

static int adp5585_gpio_get_value(struct gpio_chip *chip, unsigned int off)
{
	struct adp5585_gpio_dev *adp5585_gpio = gpiochip_get_data(chip);
	const struct adp5585_regs *regs = adp5585_gpio->regs;
	unsigned int bank = adp5585_gpio->info->bank(off);
	unsigned int bit = adp5585_gpio->info->bit(off);
	unsigned int reg;
	unsigned int val;

	/*
	 * The input status register doesn't reflect the pin state when the
	 * GPIO is configured as an output. Check the direction, and read the
	 * input status from GPI_STATUS or output value from GPO_DATA_OUT
	 * accordingly.
	 *
	 * We don't need any locking, as concurrent access to the same GPIO
	 * isn't allowed by the GPIO API, so there's no risk of the
	 * .direction_input(), .direction_output() or .set() operations racing
	 * with this.
	 */
	regmap_read(adp5585_gpio->regmap, regs->gpio_dir_a + bank, &val);
	reg = val & bit ? regs->gpo_data_a : regs->gpi_stat_a;
	regmap_read(adp5585_gpio->regmap, reg + bank, &val);

	return !!(val & bit);
}

static int adp5585_gpio_set_value(struct gpio_chip *chip, unsigned int off,
				  int val)
{
	struct adp5585_gpio_dev *adp5585_gpio = gpiochip_get_data(chip);
	const struct adp5585_regs *regs = adp5585_gpio->regs;
	unsigned int bank = adp5585_gpio->info->bank(off);
	unsigned int bit = adp5585_gpio->info->bit(off);

	return regmap_update_bits(adp5585_gpio->regmap, regs->gpo_data_a + bank,
				  bit, val ? bit : 0);
}

static int adp5585_gpio_set_bias(struct adp5585_gpio_dev *adp5585_gpio,
				 unsigned int off, unsigned int bias)
{
	const struct adp5585_gpio_chip *info = adp5585_gpio->info;
	const struct adp5585_regs *regs = adp5585_gpio->regs;
	unsigned int bit, reg, mask, val;

	/*
	 * The bias configuration fields are 2 bits wide and laid down in
	 * consecutive registers ADP5585_RPULL_CONFIG_*, with a hole of 4 bits
	 * after R5.
	 */
	bit = off * 2;
	if (info->has_bias_hole)
		bit += (off > 5 ? 4 : 0);
	reg = regs->rpull_cfg_a + bit / 8;
	mask = ADP5585_Rx_PULL_CFG_MASK << (bit % 8);
	val = bias << (bit % 8);

	return regmap_update_bits(adp5585_gpio->regmap, reg, mask, val);
}

static int adp5585_gpio_set_drive(struct adp5585_gpio_dev *adp5585_gpio,
				  unsigned int off, enum pin_config_param drive)
{
	const struct adp5585_regs *regs = adp5585_gpio->regs;
	unsigned int bank = adp5585_gpio->info->bank(off);
	unsigned int bit = adp5585_gpio->info->bit(off);

	return regmap_update_bits(adp5585_gpio->regmap,
				  regs->gpo_out_a + bank, bit,
				  drive == PIN_CONFIG_DRIVE_OPEN_DRAIN ? bit : 0);
}

static int adp5585_gpio_set_debounce(struct adp5585_gpio_dev *adp5585_gpio,
				     unsigned int off, unsigned int debounce)
{
	const struct adp5585_regs *regs = adp5585_gpio->regs;
	unsigned int bank = adp5585_gpio->info->bank(off);
	unsigned int bit = adp5585_gpio->info->bit(off);

	return regmap_update_bits(adp5585_gpio->regmap,
				  regs->debounce_dis_a + bank, bit,
				  debounce ? 0 : bit);
}

static int adp5585_gpio_set_config(struct gpio_chip *chip, unsigned int off,
				   unsigned long config)
{
	struct adp5585_gpio_dev *adp5585_gpio = gpiochip_get_data(chip);
	enum pin_config_param param = pinconf_to_config_param(config);
	u32 arg = pinconf_to_config_argument(config);

	switch (param) {
	case PIN_CONFIG_BIAS_DISABLE:
		return adp5585_gpio_set_bias(adp5585_gpio, off,
					     ADP5585_Rx_PULL_CFG_DISABLE);

	case PIN_CONFIG_BIAS_PULL_DOWN:
		return adp5585_gpio_set_bias(adp5585_gpio, off, arg ?
					     ADP5585_Rx_PULL_CFG_PD_300K :
					     ADP5585_Rx_PULL_CFG_DISABLE);

	case PIN_CONFIG_BIAS_PULL_UP:
		return adp5585_gpio_set_bias(adp5585_gpio, off, arg ?
					     ADP5585_Rx_PULL_CFG_PU_300K :
					     ADP5585_Rx_PULL_CFG_DISABLE);

	case PIN_CONFIG_DRIVE_OPEN_DRAIN:
	case PIN_CONFIG_DRIVE_PUSH_PULL:
		return adp5585_gpio_set_drive(adp5585_gpio, off, param);

	case PIN_CONFIG_INPUT_DEBOUNCE:
		return adp5585_gpio_set_debounce(adp5585_gpio, off, arg);

	default:
		return -ENOTSUPP;
	};
}

static int adp5585_gpio_init_valid_mask(struct gpio_chip *chip,
					unsigned long *valid_mask,
					unsigned int ngpios)
{
	struct device *dev = chip->parent;
	struct adp5585_dev *adp5585 = dev_get_drvdata(dev->parent);

	bitmap_complement(valid_mask, adp5585->keypad, ngpios);
	/*
	 * the keypad won't have (nor can't) have any special pin enabled which
	 * means bitmap_complement() will set them to 1. Make sure we clear them.
	 */
	if (adp5585->has_pwm)
		__clear_bit(ADP5585_ROW3, valid_mask);
	if (adp5585->nkeys_reset1)
		__clear_bit(ADP5585_ROW4, valid_mask);
	if (adp5585->nkeys_reset2)
		__clear_bit(adp5585->info->max_rows + ADP5585_COL4, valid_mask);
	if (!adp5585->info->has_row5)
		__clear_bit(ADP5585_ROW5, valid_mask);

	return 0;
}

static void adp5585_gpio_key_event(struct device *dev, unsigned int off,
				   bool key_press)
{
	struct adp5585_gpio_dev *adp5585_gpio = dev_get_drvdata(dev);
	bool active_high = test_bit(off, &adp5585_gpio->irq_active_high);
	unsigned int irq, irq_type;
	struct irq_data *irqd;

	irq = irq_find_mapping(adp5585_gpio->gpio_chip.irq.domain, off);
	if (!irq)
		return;

	irqd = irq_get_irq_data(irq);
	if (!irqd) {
		dev_err(dev, "Could not get irq(%u) data\n", irq);
		return;
	}

	dev_dbg_ratelimited(dev, "gpio-keys event(%u) press=%u, a_high=%u\n",
			    off, key_press, active_high);

	if (!active_high)
		key_press = !key_press;

	irq_type = irqd_get_trigger_type(irqd);

	if ((irq_type & IRQ_TYPE_EDGE_RISING && key_press) ||
	    (irq_type & IRQ_TYPE_EDGE_FALLING && !key_press))
		handle_nested_irq(irq);
}

static void adp5585_irq_bus_lock(struct irq_data *d)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct adp5585_gpio_dev *adp5585_gpio = gpiochip_get_data(gc);

	mutex_lock(&adp5585_gpio->bus_lock);
}

static void adp5585_irq_bus_sync_unlock(struct irq_data *d)
{
	struct gpio_chip *chip = irq_data_get_irq_chip_data(d);
	struct adp5585_gpio_dev *adp5585_gpio = gpiochip_get_data(chip);
	const struct adp5585_regs *regs = adp5585_gpio->regs;
	irq_hw_number_t hwirq = irqd_to_hwirq(d);
	bool active_high = test_bit(hwirq, &adp5585_gpio->irq_active_high);
	bool enabled = test_bit(hwirq, &adp5585_gpio->irq_en);
	bool masked = test_bit(hwirq, &adp5585_gpio->irq_mask);
	unsigned int bank = adp5585_gpio->info->bank(hwirq);
	unsigned int bit = adp5585_gpio->info->bit(hwirq);

	if (masked && !enabled)
		goto out_unlock;
	if (!masked && enabled)
		goto out_unlock;

	regmap_update_bits(adp5585_gpio->regmap, regs->gpi_int_lvl_a + bank, bit,
			   active_high ? bit : 0);
	regmap_update_bits(adp5585_gpio->regmap, regs->gpi_ev_a + bank, bit,
			   masked ? 0 : bit);
	assign_bit(hwirq, &adp5585_gpio->irq_en, !masked);

out_unlock:
	mutex_unlock(&adp5585_gpio->bus_lock);
}

static void adp5585_irq_mask(struct irq_data *d)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct adp5585_gpio_dev *adp5585_gpio = gpiochip_get_data(gc);
	irq_hw_number_t hwirq = irqd_to_hwirq(d);

	__set_bit(hwirq, &adp5585_gpio->irq_mask);
	gpiochip_disable_irq(gc, hwirq);
}

static void adp5585_irq_unmask(struct irq_data *d)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct adp5585_gpio_dev *adp5585_gpio = gpiochip_get_data(gc);
	irq_hw_number_t hwirq = irqd_to_hwirq(d);

	gpiochip_enable_irq(gc, hwirq);
	__clear_bit(hwirq, &adp5585_gpio->irq_mask);
}

static int adp5585_irq_set_type(struct irq_data *d, unsigned int type)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct adp5585_gpio_dev *adp5585_gpio = gpiochip_get_data(gc);
	irq_hw_number_t hwirq = irqd_to_hwirq(d);

	if (!(type & IRQ_TYPE_EDGE_BOTH))
		return -EINVAL;

	assign_bit(hwirq, &adp5585_gpio->irq_active_high,
		   type == IRQ_TYPE_EDGE_RISING);

	irq_set_handler_locked(d, handle_edge_irq);
	return 0;
}

static const struct irq_chip adp5585_irq_chip = {
	.name = "adp5585",
	.irq_mask = adp5585_irq_mask,
	.irq_unmask = adp5585_irq_unmask,
	.irq_bus_lock = adp5585_irq_bus_lock,
	.irq_bus_sync_unlock = adp5585_irq_bus_sync_unlock,
	.irq_set_type = adp5585_irq_set_type,
	.flags = IRQCHIP_SKIP_SET_WAKE | IRQCHIP_IMMUTABLE,
	GPIOCHIP_IRQ_RESOURCE_HELPERS,
};

static void adp5585_gpio_ev_handle_clean(void *adp5585)
{
	adp5585_gpio_ev_handle_set(adp5585, NULL, NULL);
}

static int adp5585_gpio_probe(struct platform_device *pdev)
{
	struct adp5585_dev *adp5585 = dev_get_drvdata(pdev->dev.parent);
	const struct platform_device_id *id = platform_get_device_id(pdev);
	struct adp5585_gpio_dev *adp5585_gpio;
	struct device *dev = &pdev->dev;
	struct gpio_irq_chip *girq;
	struct gpio_chip *gc;
	int ret;

	adp5585_gpio = devm_kzalloc(dev, sizeof(*adp5585_gpio), GFP_KERNEL);
	if (!adp5585_gpio)
		return -ENOMEM;

	adp5585_gpio->regmap = adp5585->regmap;
	adp5585_gpio->regs = adp5585->info->regs;

	adp5585_gpio->info = (const struct adp5585_gpio_chip *)id->driver_data;
	if (!adp5585_gpio->info)
		return -ENODEV;

	device_set_of_node_from_dev(dev, dev->parent);

	gc = &adp5585_gpio->gpio_chip;
	gc->parent = dev;
	gc->get_direction = adp5585_gpio_get_direction;
	gc->direction_input = adp5585_gpio_direction_input;
	gc->direction_output = adp5585_gpio_direction_output;
	gc->get = adp5585_gpio_get_value;
	gc->set_rv = adp5585_gpio_set_value;
	gc->set_config = adp5585_gpio_set_config;
	gc->init_valid_mask = adp5585_gpio_init_valid_mask;
	gc->can_sleep = true;

	gc->base = -1;
	gc->ngpio = adp5585->info->max_cols + adp5585->info->max_rows;
	gc->label = pdev->name;
	gc->owner = THIS_MODULE;

	if (device_property_present(dev->parent, "interrupt-controller")) {
		if (!adp5585->irq)
			return dev_err_probe(dev, -EINVAL,
					     "Unable to serve as interrupt controller without IRQ\n");

		girq = &adp5585_gpio->gpio_chip.irq;
		gpio_irq_chip_set_chip(girq, &adp5585_irq_chip);
		girq->handler = handle_bad_irq;
		girq->threaded = true;

		platform_set_drvdata(pdev, adp5585_gpio);
		adp5585_gpio_ev_handle_set(adp5585, adp5585_gpio_key_event,
					   dev);

		ret = devm_add_action_or_reset(dev,
					       adp5585_gpio_ev_handle_clean,
					       adp5585);
		if (ret)
			return ret;
	}

	/* everything masked by default */
	adp5585_gpio->irq_mask = ~0UL;

	ret = devm_mutex_init(dev, &adp5585_gpio->bus_lock);
	if (ret)
		return ret;

	ret = devm_gpiochip_add_data(dev, &adp5585_gpio->gpio_chip,
				     adp5585_gpio);
	if (ret)
		return dev_err_probe(dev, ret, "failed to add GPIO chip\n");

	return 0;
}

static const struct adp5585_gpio_chip adp5585_gpio_chip_info = {
	.bank = adp5585_gpio_bank,
	.bit = adp5585_gpio_bit,
	.has_bias_hole = true,
};

static const struct adp5585_gpio_chip adp5589_gpio_chip_info = {
	.bank = adp5589_gpio_bank,
	.bit = adp5589_gpio_bit,
};

static const struct platform_device_id adp5585_gpio_id_table[] = {
	{ "adp5585-gpio", (kernel_ulong_t)&adp5585_gpio_chip_info },
	{ "adp5589-gpio", (kernel_ulong_t)&adp5589_gpio_chip_info },
	{ /* Sentinel */ }
};
MODULE_DEVICE_TABLE(platform, adp5585_gpio_id_table);

static struct platform_driver adp5585_gpio_driver = {
	.driver	= {
		.name = "adp5585-gpio",
	},
	.probe = adp5585_gpio_probe,
	.id_table = adp5585_gpio_id_table,
};
module_platform_driver(adp5585_gpio_driver);

MODULE_AUTHOR("Haibo Chen <haibo.chen@nxp.com>");
MODULE_DESCRIPTION("GPIO ADP5585 Driver");
MODULE_LICENSE("GPL");
