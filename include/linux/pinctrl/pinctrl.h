/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Interface the pinctrl subsystem
 *
 * Copyright (C) 2011 ST-Ericsson SA
 * Written on behalf of Linaro for ST-Ericsson
 * This interface is used in the core to keep track of pins.
 *
 * Author: Linus Walleij <linus.walleij@linaro.org>
 */
#ifndef __LINUX_PINCTRL_PINCTRL_H
#define __LINUX_PINCTRL_PINCTRL_H

#include <linux/types.h>

struct device;
struct device_node;
struct gpio_chip;
struct module;
struct seq_file;

struct pin_config_item;
struct pinconf_generic_params;
struct pinconf_ops;
struct pinctrl_dev;
struct pinctrl_map;
struct pinmux_ops;

/**
 * struct pingroup - provides information on pingroup
 * @name: a name for pingroup
 * @pins: an array of pins in the pingroup
 * @npins: number of pins in the pingroup
 */
struct pingroup {
	const char *name;
	const unsigned int *pins;
	size_t npins;
};

/* Convenience macro to define a single named or anonymous pingroup */
#define PINCTRL_PINGROUP(_name, _pins, _npins)	\
(struct pingroup) {				\
	.name = _name,				\
	.pins = _pins,				\
	.npins = _npins,			\
}

/**
 * struct pinctrl_pin_desc - boards/machines provide information on their
 * pins, pads or other muxable units in this struct
 * @number: unique pin number from the global pin number space
 * @name: a name for this pin
 * @drv_data: driver-defined per-pin data. pinctrl core does not touch this
 */
struct pinctrl_pin_desc {
	unsigned int number;
	const char *name;
	void *drv_data;
};

/* Convenience macro to define a single named or anonymous pin descriptor */
#define PINCTRL_PIN(a, b) { .number = a, .name = b }
#define PINCTRL_PIN_ANON(a) { .number = a }

/**
 * struct pinctrl_gpio_range - each pin controller can provide subranges of
 * the GPIO number space to be handled by the controller
 * @node: list node for internal use
 * @name: a name for the chip in this range
 * @id: an ID number for the chip in this range
 * @base: base offset of the GPIO range
 * @pin_base: base pin number of the GPIO range if pins == NULL
 * @npins: number of pins in the GPIO range, including the base number
 * @pins: enumeration of pins in GPIO range or NULL
 * @gc: an optional pointer to a gpio_chip
 */
struct pinctrl_gpio_range {
	struct list_head node;
	const char *name;
	unsigned int id;
	unsigned int base;
	unsigned int pin_base;
	unsigned int npins;
	unsigned int const *pins;
	struct gpio_chip *gc;
};

/**
 * struct pinctrl_ops - global pin control operations, to be implemented by
 * pin controller drivers.
 * @get_groups_count: Returns the count of total number of groups registered.
 * @get_group_name: return the group name of the pin group
 * @get_group_pins: return an array of pins corresponding to a certain
 *	group selector @pins, and the size of the array in @num_pins
 * @pin_dbg_show: optional debugfs display hook that will provide per-device
 *	info for a certain pin in debugfs
 * @dt_node_to_map: parse a device tree "pin configuration node", and create
 *	mapping table entries for it. These are returned through the @map and
 *	@num_maps output parameters. This function is optional, and may be
 *	omitted for pinctrl drivers that do not support device tree.
 * @dt_free_map: free mapping table entries created via @dt_node_to_map. The
 *	top-level @map pointer must be freed, along with any dynamically
 *	allocated members of the mapping table entries themselves. This
 *	function is optional, and may be omitted for pinctrl drivers that do
 *	not support device tree.
 */
struct pinctrl_ops {
	int (*get_groups_count) (struct pinctrl_dev *pctldev);
	const char *(*get_group_name) (struct pinctrl_dev *pctldev,
				       unsigned int selector);
	int (*get_group_pins) (struct pinctrl_dev *pctldev,
			       unsigned int selector,
			       const unsigned int **pins,
			       unsigned int *num_pins);
	void (*pin_dbg_show) (struct pinctrl_dev *pctldev, struct seq_file *s,
			      unsigned int offset);
	int (*dt_node_to_map) (struct pinctrl_dev *pctldev,
			       struct device_node *np_config,
			       struct pinctrl_map **map, unsigned int *num_maps);
	void (*dt_free_map) (struct pinctrl_dev *pctldev,
			     struct pinctrl_map *map, unsigned int num_maps);
};

/**
 * struct pinctrl_desc - pin controller descriptor, register this to pin
 * control subsystem
 * @name: name for the pin controller
 * @pins: an array of pin descriptors describing all the pins handled by
 *	this pin controller
 * @npins: number of descriptors in the array, usually just ARRAY_SIZE()
 *	of the pins field above
 * @pctlops: pin control operation vtable, to support global concepts like
 *	grouping of pins, this is optional.
 * @pmxops: pinmux operations vtable, if you support pinmuxing in your driver
 * @confops: pin config operations vtable, if you support pin configuration in
 *	your driver
 * @owner: module providing the pin controller, used for refcounting
 * @num_custom_params: Number of driver-specific custom parameters to be parsed
 *	from the hardware description
 * @custom_params: List of driver_specific custom parameters to be parsed from
 *	the hardware description
 * @custom_conf_items: Information how to print @params in debugfs, must be
 *	the same size as the @custom_params, i.e. @num_custom_params
 * @link_consumers: If true create a device link between pinctrl and its
 *	consumers (i.e. the devices requesting pin control states). This is
 *	sometimes necessary to ascertain the right suspend/resume order for
 *	example.
 */
struct pinctrl_desc {
	const char *name;
	const struct pinctrl_pin_desc *pins;
	unsigned int npins;
	const struct pinctrl_ops *pctlops;
	const struct pinmux_ops *pmxops;
	const struct pinconf_ops *confops;
	struct module *owner;
#ifdef CONFIG_GENERIC_PINCONF
	unsigned int num_custom_params;
	const struct pinconf_generic_params *custom_params;
	const struct pin_config_item *custom_conf_items;
#endif
	bool link_consumers;
};

/* External interface to pin controller */

extern int pinctrl_register_and_init(const struct pinctrl_desc *pctldesc,
				     struct device *dev, void *driver_data,
				     struct pinctrl_dev **pctldev);
extern int pinctrl_enable(struct pinctrl_dev *pctldev);

/* Please use pinctrl_register_and_init() and pinctrl_enable() instead */
extern struct pinctrl_dev *pinctrl_register(const struct pinctrl_desc *pctldesc,
				struct device *dev, void *driver_data);

extern void pinctrl_unregister(struct pinctrl_dev *pctldev);

extern int devm_pinctrl_register_and_init(struct device *dev,
				const struct pinctrl_desc *pctldesc,
				void *driver_data,
				struct pinctrl_dev **pctldev);

/* Please use devm_pinctrl_register_and_init() instead */
extern struct pinctrl_dev *devm_pinctrl_register(struct device *dev,
				const struct pinctrl_desc *pctldesc,
				void *driver_data);

extern void devm_pinctrl_unregister(struct device *dev,
				struct pinctrl_dev *pctldev);

extern void pinctrl_add_gpio_range(struct pinctrl_dev *pctldev,
				struct pinctrl_gpio_range *range);
extern void pinctrl_add_gpio_ranges(struct pinctrl_dev *pctldev,
				struct pinctrl_gpio_range *ranges,
				unsigned int nranges);
extern void pinctrl_remove_gpio_range(struct pinctrl_dev *pctldev,
				struct pinctrl_gpio_range *range);

extern struct pinctrl_dev *pinctrl_find_and_add_gpio_range(const char *devname,
		struct pinctrl_gpio_range *range);
extern struct pinctrl_gpio_range *
pinctrl_find_gpio_range_from_pin(struct pinctrl_dev *pctldev,
				 unsigned int pin);
extern int pinctrl_get_group_pins(struct pinctrl_dev *pctldev,
				  const char *pin_group, const unsigned int **pins,
				  unsigned int *num_pins);

/**
 * struct pinfunction - Description about a function
 * @name: Name of the function
 * @groups: An array of groups for this function
 * @ngroups: Number of groups in @groups
 */
struct pinfunction {
	const char *name;
	const char * const *groups;
	size_t ngroups;
};

/* Convenience macro to define a single named pinfunction */
#define PINCTRL_PINFUNCTION(_name, _groups, _ngroups)	\
(struct pinfunction) {					\
		.name = (_name),			\
		.groups = (_groups),			\
		.ngroups = (_ngroups),			\
	}

#if IS_ENABLED(CONFIG_OF) && IS_ENABLED(CONFIG_PINCTRL)
extern struct pinctrl_dev *of_pinctrl_get(struct device_node *np);
#else
static inline
struct pinctrl_dev *of_pinctrl_get(struct device_node *np)
{
	return NULL;
}
#endif /* CONFIG_OF */

extern const char *pinctrl_dev_get_name(struct pinctrl_dev *pctldev);
extern const char *pinctrl_dev_get_devname(struct pinctrl_dev *pctldev);
extern void *pinctrl_dev_get_drvdata(struct pinctrl_dev *pctldev);

#endif /* __LINUX_PINCTRL_PINCTRL_H */
