// SPDX-License-Identifier: GPL-2.0-only
/*
 * ADXL345 3-Axis Digital Accelerometer SPI driver
 *
 * Copyright (c) 2017 Eva Rachel Retuya <eraretuya@gmail.com>
 */

#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/spi/spi.h>

#include "adxl345.h"

#define ADXL345_MAX_SPI_FREQ_HZ		5000000
#define ADXL345_MAX_FREQ_NO_FIFO_DELAY	1500000

static const struct regmap_config adxl345_spi_regmap_config = {
	.reg_bits = 8,
	.val_bits = 8,
	 /* Setting bits 7 and 6 enables multiple-byte read */
	.read_flag_mask = BIT(7) | BIT(6),
	.volatile_reg = adxl345_is_volatile_reg,
	.cache_type = REGCACHE_MAPLE,
};

static int adxl345_spi_setup(struct device *dev, struct regmap *regmap)
{
	return regmap_write(regmap, ADXL345_REG_DATA_FORMAT, ADXL345_DATA_FORMAT_SPI_3WIRE);
}

static int adxl345_spi_probe(struct spi_device *spi)
{
	struct regmap *regmap;
	bool needs_delay;

	/* Bail out if max_speed_hz exceeds 5 MHz */
	if (spi->max_speed_hz > ADXL345_MAX_SPI_FREQ_HZ)
		return dev_err_probe(&spi->dev, -EINVAL, "SPI CLK, %d Hz exceeds 5 MHz\n",
				     spi->max_speed_hz);

	regmap = devm_regmap_init_spi(spi, &adxl345_spi_regmap_config);
	if (IS_ERR(regmap))
		return dev_err_probe(&spi->dev, PTR_ERR(regmap), "Error initializing regmap\n");

	needs_delay = spi->max_speed_hz > ADXL345_MAX_FREQ_NO_FIFO_DELAY;
	if (spi->mode & SPI_3WIRE)
		return adxl345_core_probe(&spi->dev, regmap, needs_delay, adxl345_spi_setup);
	else
		return adxl345_core_probe(&spi->dev, regmap, needs_delay, NULL);
}

static const struct adxl345_chip_info adxl345_spi_info = {
	.name = "adxl345",
	.uscale = ADXL345_USCALE,
};

static const struct adxl345_chip_info adxl375_spi_info = {
	.name = "adxl375",
	.uscale = ADXL375_USCALE,
};

static const struct spi_device_id adxl345_spi_id[] = {
	{ "adxl345", (kernel_ulong_t)&adxl345_spi_info },
	{ "adxl375", (kernel_ulong_t)&adxl375_spi_info },
	{ }
};
MODULE_DEVICE_TABLE(spi, adxl345_spi_id);

static const struct of_device_id adxl345_of_match[] = {
	{ .compatible = "adi,adxl345", .data = &adxl345_spi_info },
	{ .compatible = "adi,adxl375", .data = &adxl375_spi_info },
	{ }
};
MODULE_DEVICE_TABLE(of, adxl345_of_match);

static const struct acpi_device_id adxl345_acpi_match[] = {
	{ "ADS0345", (kernel_ulong_t)&adxl345_spi_info },
	{ }
};
MODULE_DEVICE_TABLE(acpi, adxl345_acpi_match);

static struct spi_driver adxl345_spi_driver = {
	.driver = {
		.name	= "adxl345_spi",
		.of_match_table = adxl345_of_match,
		.acpi_match_table = adxl345_acpi_match,
	},
	.probe		= adxl345_spi_probe,
	.id_table	= adxl345_spi_id,
};
module_spi_driver(adxl345_spi_driver);

MODULE_AUTHOR("Eva Rachel Retuya <eraretuya@gmail.com>");
MODULE_DESCRIPTION("ADXL345 3-Axis Digital Accelerometer SPI driver");
MODULE_LICENSE("GPL v2");
MODULE_IMPORT_NS("IIO_ADXL345");
