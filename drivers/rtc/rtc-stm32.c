// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) STMicroelectronics 2017
 * Author:  Amelie Delaunay <amelie.delaunay@st.com>
 */

#include <linux/bcd.h>
#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/errno.h>
#include <linux/iopoll.h>
#include <linux/ioport.h>
#include <linux/mfd/syscon.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pinctrl/pinctrl.h>
#include <linux/pinctrl/pinconf-generic.h>
#include <linux/pinctrl/pinmux.h>
#include <linux/platform_device.h>
#include <linux/pm_wakeirq.h>
#include <linux/regmap.h>
#include <linux/rtc.h>

#define DRIVER_NAME "stm32_rtc"

/* STM32_RTC_TR bit fields  */
#define STM32_RTC_TR_SEC_SHIFT		0
#define STM32_RTC_TR_SEC		GENMASK(6, 0)
#define STM32_RTC_TR_MIN_SHIFT		8
#define STM32_RTC_TR_MIN		GENMASK(14, 8)
#define STM32_RTC_TR_HOUR_SHIFT		16
#define STM32_RTC_TR_HOUR		GENMASK(21, 16)

/* STM32_RTC_DR bit fields */
#define STM32_RTC_DR_DATE_SHIFT		0
#define STM32_RTC_DR_DATE		GENMASK(5, 0)
#define STM32_RTC_DR_MONTH_SHIFT	8
#define STM32_RTC_DR_MONTH		GENMASK(12, 8)
#define STM32_RTC_DR_WDAY_SHIFT		13
#define STM32_RTC_DR_WDAY		GENMASK(15, 13)
#define STM32_RTC_DR_YEAR_SHIFT		16
#define STM32_RTC_DR_YEAR		GENMASK(23, 16)

/* STM32_RTC_CR bit fields */
#define STM32_RTC_CR_FMT		BIT(6)
#define STM32_RTC_CR_ALRAE		BIT(8)
#define STM32_RTC_CR_ALRAIE		BIT(12)
#define STM32_RTC_CR_OSEL		GENMASK(22, 21)
#define STM32_RTC_CR_OSEL_ALARM_A	FIELD_PREP(STM32_RTC_CR_OSEL, 0x01)
#define STM32_RTC_CR_COE		BIT(23)
#define STM32_RTC_CR_TAMPOE		BIT(26)
#define STM32_RTC_CR_TAMPALRM_TYPE	BIT(30)
#define STM32_RTC_CR_OUT2EN		BIT(31)

/* STM32_RTC_ISR/STM32_RTC_ICSR bit fields */
#define STM32_RTC_ISR_ALRAWF		BIT(0)
#define STM32_RTC_ISR_INITS		BIT(4)
#define STM32_RTC_ISR_RSF		BIT(5)
#define STM32_RTC_ISR_INITF		BIT(6)
#define STM32_RTC_ISR_INIT		BIT(7)
#define STM32_RTC_ISR_ALRAF		BIT(8)

/* STM32_RTC_PRER bit fields */
#define STM32_RTC_PRER_PRED_S_SHIFT	0
#define STM32_RTC_PRER_PRED_S		GENMASK(14, 0)
#define STM32_RTC_PRER_PRED_A_SHIFT	16
#define STM32_RTC_PRER_PRED_A		GENMASK(22, 16)

/* STM32_RTC_ALRMAR and STM32_RTC_ALRMBR bit fields */
#define STM32_RTC_ALRMXR_SEC_SHIFT	0
#define STM32_RTC_ALRMXR_SEC		GENMASK(6, 0)
#define STM32_RTC_ALRMXR_SEC_MASK	BIT(7)
#define STM32_RTC_ALRMXR_MIN_SHIFT	8
#define STM32_RTC_ALRMXR_MIN		GENMASK(14, 8)
#define STM32_RTC_ALRMXR_MIN_MASK	BIT(15)
#define STM32_RTC_ALRMXR_HOUR_SHIFT	16
#define STM32_RTC_ALRMXR_HOUR		GENMASK(21, 16)
#define STM32_RTC_ALRMXR_PM		BIT(22)
#define STM32_RTC_ALRMXR_HOUR_MASK	BIT(23)
#define STM32_RTC_ALRMXR_DATE_SHIFT	24
#define STM32_RTC_ALRMXR_DATE		GENMASK(29, 24)
#define STM32_RTC_ALRMXR_WDSEL		BIT(30)
#define STM32_RTC_ALRMXR_WDAY_SHIFT	24
#define STM32_RTC_ALRMXR_WDAY		GENMASK(27, 24)
#define STM32_RTC_ALRMXR_DATE_MASK	BIT(31)

/* STM32_RTC_SR/_SCR bit fields */
#define STM32_RTC_SR_ALRA		BIT(0)

/* STM32_RTC_CFGR bit fields */
#define STM32_RTC_CFGR_OUT2_RMP		BIT(0)
#define STM32_RTC_CFGR_LSCOEN		GENMASK(2, 1)
#define STM32_RTC_CFGR_LSCOEN_OUT1	1
#define STM32_RTC_CFGR_LSCOEN_OUT2_RMP	2

/* STM32_RTC_VERR bit fields */
#define STM32_RTC_VERR_MINREV_SHIFT	0
#define STM32_RTC_VERR_MINREV		GENMASK(3, 0)
#define STM32_RTC_VERR_MAJREV_SHIFT	4
#define STM32_RTC_VERR_MAJREV		GENMASK(7, 4)

/* STM32_RTC_SECCFGR bit fields */
#define STM32_RTC_SECCFGR		0x20
#define STM32_RTC_SECCFGR_ALRA_SEC	BIT(0)
#define STM32_RTC_SECCFGR_INIT_SEC	BIT(14)
#define STM32_RTC_SECCFGR_SEC		BIT(15)

/* STM32_RTC_RXCIDCFGR bit fields */
#define STM32_RTC_RXCIDCFGR(x)		(0x80 + 0x4 * (x))
#define STM32_RTC_RXCIDCFGR_CFEN	BIT(0)
#define STM32_RTC_RXCIDCFGR_CID		GENMASK(6, 4)
#define STM32_RTC_RXCIDCFGR_CID1	1

/* STM32_RTC_WPR key constants */
#define RTC_WPR_1ST_KEY			0xCA
#define RTC_WPR_2ND_KEY			0x53
#define RTC_WPR_WRONG_KEY		0xFF

/* Max STM32 RTC register offset is 0x3FC */
#define UNDEF_REG			0xFFFF

/* STM32 RTC driver time helpers */
#define SEC_PER_DAY		(24 * 60 * 60)

/* STM32 RTC pinctrl helpers */
#define STM32_RTC_PINMUX(_name, _action, ...) { \
	.name = (_name), \
	.action = (_action), \
	.groups = ((const char *[]){ __VA_ARGS__ }), \
	.num_groups = ARRAY_SIZE(((const char *[]){ __VA_ARGS__ })), \
}

struct stm32_rtc;

struct stm32_rtc_registers {
	u16 tr;
	u16 dr;
	u16 cr;
	u16 isr;
	u16 prer;
	u16 alrmar;
	u16 wpr;
	u16 sr;
	u16 scr;
	u16 cfgr;
	u16 verr;
};

struct stm32_rtc_events {
	u32 alra;
};

struct stm32_rtc_data {
	const struct stm32_rtc_registers regs;
	const struct stm32_rtc_events events;
	void (*clear_events)(struct stm32_rtc *rtc, unsigned int flags);
	bool has_pclk;
	bool need_dbp;
	bool need_accuracy;
	bool rif_protected;
	bool has_lsco;
	bool has_alarm_out;
};

struct stm32_rtc {
	struct rtc_device *rtc_dev;
	void __iomem *base;
	struct regmap *dbp;
	unsigned int dbp_reg;
	unsigned int dbp_mask;
	struct clk *pclk;
	struct clk *rtc_ck;
	const struct stm32_rtc_data *data;
	int irq_alarm;
	struct clk *clk_lsco;
};

struct stm32_rtc_rif_resource {
	unsigned int num;
	u32 bit;
};

static const struct stm32_rtc_rif_resource STM32_RTC_RES_ALRA = {0, STM32_RTC_SECCFGR_ALRA_SEC};
static const struct stm32_rtc_rif_resource STM32_RTC_RES_INIT = {5, STM32_RTC_SECCFGR_INIT_SEC};

static void stm32_rtc_wpr_unlock(struct stm32_rtc *rtc)
{
	const struct stm32_rtc_registers *regs = &rtc->data->regs;

	writel_relaxed(RTC_WPR_1ST_KEY, rtc->base + regs->wpr);
	writel_relaxed(RTC_WPR_2ND_KEY, rtc->base + regs->wpr);
}

static void stm32_rtc_wpr_lock(struct stm32_rtc *rtc)
{
	const struct stm32_rtc_registers *regs = &rtc->data->regs;

	writel_relaxed(RTC_WPR_WRONG_KEY, rtc->base + regs->wpr);
}

enum stm32_rtc_pin_name {
	NONE,
	OUT1,
	OUT2,
	OUT2_RMP
};

static const struct pinctrl_pin_desc stm32_rtc_pinctrl_pins[] = {
	PINCTRL_PIN(OUT1, "out1"),
	PINCTRL_PIN(OUT2, "out2"),
	PINCTRL_PIN(OUT2_RMP, "out2_rmp"),
};

static int stm32_rtc_pinctrl_get_groups_count(struct pinctrl_dev *pctldev)
{
	return ARRAY_SIZE(stm32_rtc_pinctrl_pins);
}

static const char *stm32_rtc_pinctrl_get_group_name(struct pinctrl_dev *pctldev,
						    unsigned int selector)
{
	return stm32_rtc_pinctrl_pins[selector].name;
}

static int stm32_rtc_pinctrl_get_group_pins(struct pinctrl_dev *pctldev,
					    unsigned int selector,
					    const unsigned int **pins,
					    unsigned int *num_pins)
{
	*pins = &stm32_rtc_pinctrl_pins[selector].number;
	*num_pins = 1;
	return 0;
}

static const struct pinctrl_ops stm32_rtc_pinctrl_ops = {
	.dt_node_to_map		= pinconf_generic_dt_node_to_map_all,
	.dt_free_map		= pinconf_generic_dt_free_map,
	.get_groups_count	= stm32_rtc_pinctrl_get_groups_count,
	.get_group_name		= stm32_rtc_pinctrl_get_group_name,
	.get_group_pins		= stm32_rtc_pinctrl_get_group_pins,
};

struct stm32_rtc_pinmux_func {
	const char *name;
	const char * const *groups;
	const unsigned int num_groups;
	int (*action)(struct pinctrl_dev *pctl_dev, unsigned int pin);
};

static int stm32_rtc_pinmux_action_alarm(struct pinctrl_dev *pctldev, unsigned int pin)
{
	struct stm32_rtc *rtc = pinctrl_dev_get_drvdata(pctldev);
	struct stm32_rtc_registers regs = rtc->data->regs;
	unsigned int cr = readl_relaxed(rtc->base + regs.cr);
	unsigned int cfgr = readl_relaxed(rtc->base + regs.cfgr);

	if (!rtc->data->has_alarm_out)
		return -EPERM;

	cr &= ~STM32_RTC_CR_OSEL;
	cr |= STM32_RTC_CR_OSEL_ALARM_A;
	cr &= ~STM32_RTC_CR_TAMPOE;
	cr &= ~STM32_RTC_CR_COE;
	cr &= ~STM32_RTC_CR_TAMPALRM_TYPE;

	switch (pin) {
	case OUT1:
		cr &= ~STM32_RTC_CR_OUT2EN;
		cfgr &= ~STM32_RTC_CFGR_OUT2_RMP;
		break;
	case OUT2:
		cr |= STM32_RTC_CR_OUT2EN;
		cfgr &= ~STM32_RTC_CFGR_OUT2_RMP;
		break;
	case OUT2_RMP:
		cr |= STM32_RTC_CR_OUT2EN;
		cfgr |= STM32_RTC_CFGR_OUT2_RMP;
		break;
	default:
		return -EINVAL;
	}

	stm32_rtc_wpr_unlock(rtc);
	writel_relaxed(cr, rtc->base + regs.cr);
	writel_relaxed(cfgr, rtc->base + regs.cfgr);
	stm32_rtc_wpr_lock(rtc);

	return 0;
}

static int stm32_rtc_pinmux_lsco_available(struct pinctrl_dev *pctldev, unsigned int pin)
{
	struct stm32_rtc *rtc = pinctrl_dev_get_drvdata(pctldev);
	struct stm32_rtc_registers regs = rtc->data->regs;
	unsigned int cr = readl_relaxed(rtc->base + regs.cr);
	unsigned int cfgr = readl_relaxed(rtc->base + regs.cfgr);
	unsigned int calib = STM32_RTC_CR_COE;
	unsigned int tampalrm = STM32_RTC_CR_TAMPOE | STM32_RTC_CR_OSEL;

	switch (pin) {
	case OUT1:
		if ((!(cr & STM32_RTC_CR_OUT2EN) &&
		     ((cr & calib) || cr & tampalrm)) ||
		     ((cr & calib) && (cr & tampalrm)))
			return -EBUSY;
		break;
	case OUT2_RMP:
		if ((cr & STM32_RTC_CR_OUT2EN) &&
		    (cfgr & STM32_RTC_CFGR_OUT2_RMP) &&
		    ((cr & calib) || (cr & tampalrm)))
			return -EBUSY;
		break;
	default:
		return -EINVAL;
	}

	if (clk_get_rate(rtc->rtc_ck) != 32768)
		return -ERANGE;

	return 0;
}

static int stm32_rtc_pinmux_action_lsco(struct pinctrl_dev *pctldev, unsigned int pin)
{
	struct stm32_rtc *rtc = pinctrl_dev_get_drvdata(pctldev);
	struct stm32_rtc_registers regs = rtc->data->regs;
	struct device *dev = rtc->rtc_dev->dev.parent;
	u8 lscoen;
	int ret;

	if (!rtc->data->has_lsco)
		return -EPERM;

	ret = stm32_rtc_pinmux_lsco_available(pctldev, pin);
	if (ret)
		return ret;

	lscoen = (pin == OUT1) ? STM32_RTC_CFGR_LSCOEN_OUT1 : STM32_RTC_CFGR_LSCOEN_OUT2_RMP;

	rtc->clk_lsco = clk_register_gate(dev, "rtc_lsco", __clk_get_name(rtc->rtc_ck),
					  CLK_IGNORE_UNUSED | CLK_IS_CRITICAL,
					  rtc->base + regs.cfgr, lscoen, 0, NULL);
	if (IS_ERR(rtc->clk_lsco))
		return PTR_ERR(rtc->clk_lsco);

	of_clk_add_provider(dev->of_node, of_clk_src_simple_get, rtc->clk_lsco);

	return 0;
}

static const struct stm32_rtc_pinmux_func stm32_rtc_pinmux_functions[] = {
	STM32_RTC_PINMUX("lsco", &stm32_rtc_pinmux_action_lsco, "out1", "out2_rmp"),
	STM32_RTC_PINMUX("alarm-a", &stm32_rtc_pinmux_action_alarm, "out1", "out2", "out2_rmp"),
};

static int stm32_rtc_pinmux_get_functions_count(struct pinctrl_dev *pctldev)
{
	return ARRAY_SIZE(stm32_rtc_pinmux_functions);
}

static const char *stm32_rtc_pinmux_get_fname(struct pinctrl_dev *pctldev, unsigned int selector)
{
	return stm32_rtc_pinmux_functions[selector].name;
}

static int stm32_rtc_pinmux_get_groups(struct pinctrl_dev *pctldev, unsigned int selector,
				       const char * const **groups, unsigned int * const num_groups)
{
	*groups = stm32_rtc_pinmux_functions[selector].groups;
	*num_groups = stm32_rtc_pinmux_functions[selector].num_groups;
	return 0;
}

static int stm32_rtc_pinmux_set_mux(struct pinctrl_dev *pctldev, unsigned int selector,
				    unsigned int group)
{
	struct stm32_rtc_pinmux_func selected_func = stm32_rtc_pinmux_functions[selector];
	struct pinctrl_pin_desc pin = stm32_rtc_pinctrl_pins[group];

	/* Call action */
	if (selected_func.action)
		return selected_func.action(pctldev, pin.number);

	return -EINVAL;
}

static const struct pinmux_ops stm32_rtc_pinmux_ops = {
	.get_functions_count	= stm32_rtc_pinmux_get_functions_count,
	.get_function_name	= stm32_rtc_pinmux_get_fname,
	.get_function_groups	= stm32_rtc_pinmux_get_groups,
	.set_mux		= stm32_rtc_pinmux_set_mux,
	.strict			= true,
};

static const struct pinctrl_desc stm32_rtc_pdesc = {
	.name = DRIVER_NAME,
	.pins = stm32_rtc_pinctrl_pins,
	.npins = ARRAY_SIZE(stm32_rtc_pinctrl_pins),
	.owner = THIS_MODULE,
	.pctlops = &stm32_rtc_pinctrl_ops,
	.pmxops = &stm32_rtc_pinmux_ops,
};

static int stm32_rtc_enter_init_mode(struct stm32_rtc *rtc)
{
	const struct stm32_rtc_registers *regs = &rtc->data->regs;
	unsigned int isr = readl_relaxed(rtc->base + regs->isr);

	if (!(isr & STM32_RTC_ISR_INITF)) {
		isr |= STM32_RTC_ISR_INIT;
		writel_relaxed(isr, rtc->base + regs->isr);

		/*
		 * It takes around 2 rtc_ck clock cycles to enter in
		 * initialization phase mode (and have INITF flag set). As
		 * slowest rtc_ck frequency may be 32kHz and highest should be
		 * 1MHz, we poll every 10 us with a timeout of 100ms.
		 */
		return readl_relaxed_poll_timeout_atomic(rtc->base + regs->isr, isr,
							 (isr & STM32_RTC_ISR_INITF),
							 10, 100000);
	}

	return 0;
}

static void stm32_rtc_exit_init_mode(struct stm32_rtc *rtc)
{
	const struct stm32_rtc_registers *regs = &rtc->data->regs;
	unsigned int isr = readl_relaxed(rtc->base + regs->isr);

	isr &= ~STM32_RTC_ISR_INIT;
	writel_relaxed(isr, rtc->base + regs->isr);
}

static int stm32_rtc_wait_sync(struct stm32_rtc *rtc)
{
	const struct stm32_rtc_registers *regs = &rtc->data->regs;
	unsigned int isr = readl_relaxed(rtc->base + regs->isr);

	isr &= ~STM32_RTC_ISR_RSF;
	writel_relaxed(isr, rtc->base + regs->isr);

	/*
	 * Wait for RSF to be set to ensure the calendar registers are
	 * synchronised, it takes around 2 rtc_ck clock cycles
	 */
	return readl_relaxed_poll_timeout_atomic(rtc->base + regs->isr,
						 isr,
						 (isr & STM32_RTC_ISR_RSF),
						 10, 100000);
}

static void stm32_rtc_clear_event_flags(struct stm32_rtc *rtc,
					unsigned int flags)
{
	rtc->data->clear_events(rtc, flags);
}

static irqreturn_t stm32_rtc_alarm_irq(int irq, void *dev_id)
{
	struct stm32_rtc *rtc = (struct stm32_rtc *)dev_id;
	const struct stm32_rtc_registers *regs = &rtc->data->regs;
	const struct stm32_rtc_events *evts = &rtc->data->events;
	unsigned int status, cr;

	rtc_lock(rtc->rtc_dev);

	status = readl_relaxed(rtc->base + regs->sr);
	cr = readl_relaxed(rtc->base + regs->cr);

	if ((status & evts->alra) &&
	    (cr & STM32_RTC_CR_ALRAIE)) {
		/* Alarm A flag - Alarm interrupt */
		dev_dbg(&rtc->rtc_dev->dev, "Alarm occurred\n");

		/* Pass event to the kernel */
		rtc_update_irq(rtc->rtc_dev, 1, RTC_IRQF | RTC_AF);

		/* Clear event flags, otherwise new events won't be received */
		stm32_rtc_clear_event_flags(rtc, evts->alra);
	}

	rtc_unlock(rtc->rtc_dev);

	return IRQ_HANDLED;
}

/* Convert rtc_time structure from bin to bcd format */
static void tm2bcd(struct rtc_time *tm)
{
	tm->tm_sec = bin2bcd(tm->tm_sec);
	tm->tm_min = bin2bcd(tm->tm_min);
	tm->tm_hour = bin2bcd(tm->tm_hour);

	tm->tm_mday = bin2bcd(tm->tm_mday);
	tm->tm_mon = bin2bcd(tm->tm_mon + 1);
	tm->tm_year = bin2bcd(tm->tm_year - 100);
	/*
	 * Number of days since Sunday
	 * - on kernel side, 0=Sunday...6=Saturday
	 * - on rtc side, 0=invalid,1=Monday...7=Sunday
	 */
	tm->tm_wday = (!tm->tm_wday) ? 7 : tm->tm_wday;
}

/* Convert rtc_time structure from bcd to bin format */
static void bcd2tm(struct rtc_time *tm)
{
	tm->tm_sec = bcd2bin(tm->tm_sec);
	tm->tm_min = bcd2bin(tm->tm_min);
	tm->tm_hour = bcd2bin(tm->tm_hour);

	tm->tm_mday = bcd2bin(tm->tm_mday);
	tm->tm_mon = bcd2bin(tm->tm_mon) - 1;
	tm->tm_year = bcd2bin(tm->tm_year) + 100;
	/*
	 * Number of days since Sunday
	 * - on kernel side, 0=Sunday...6=Saturday
	 * - on rtc side, 0=invalid,1=Monday...7=Sunday
	 */
	tm->tm_wday %= 7;
}

static int stm32_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct stm32_rtc *rtc = dev_get_drvdata(dev);
	const struct stm32_rtc_registers *regs = &rtc->data->regs;
	unsigned int tr, dr;

	/* Time and Date in BCD format */
	tr = readl_relaxed(rtc->base + regs->tr);
	dr = readl_relaxed(rtc->base + regs->dr);

	tm->tm_sec = (tr & STM32_RTC_TR_SEC) >> STM32_RTC_TR_SEC_SHIFT;
	tm->tm_min = (tr & STM32_RTC_TR_MIN) >> STM32_RTC_TR_MIN_SHIFT;
	tm->tm_hour = (tr & STM32_RTC_TR_HOUR) >> STM32_RTC_TR_HOUR_SHIFT;

	tm->tm_mday = (dr & STM32_RTC_DR_DATE) >> STM32_RTC_DR_DATE_SHIFT;
	tm->tm_mon = (dr & STM32_RTC_DR_MONTH) >> STM32_RTC_DR_MONTH_SHIFT;
	tm->tm_year = (dr & STM32_RTC_DR_YEAR) >> STM32_RTC_DR_YEAR_SHIFT;
	tm->tm_wday = (dr & STM32_RTC_DR_WDAY) >> STM32_RTC_DR_WDAY_SHIFT;

	/* We don't report tm_yday and tm_isdst */

	bcd2tm(tm);

	return 0;
}

static int stm32_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	struct stm32_rtc *rtc = dev_get_drvdata(dev);
	const struct stm32_rtc_registers *regs = &rtc->data->regs;
	unsigned int tr, dr;
	int ret = 0;

	tm2bcd(tm);

	/* Time in BCD format */
	tr = ((tm->tm_sec << STM32_RTC_TR_SEC_SHIFT) & STM32_RTC_TR_SEC) |
	     ((tm->tm_min << STM32_RTC_TR_MIN_SHIFT) & STM32_RTC_TR_MIN) |
	     ((tm->tm_hour << STM32_RTC_TR_HOUR_SHIFT) & STM32_RTC_TR_HOUR);

	/* Date in BCD format */
	dr = ((tm->tm_mday << STM32_RTC_DR_DATE_SHIFT) & STM32_RTC_DR_DATE) |
	     ((tm->tm_mon << STM32_RTC_DR_MONTH_SHIFT) & STM32_RTC_DR_MONTH) |
	     ((tm->tm_year << STM32_RTC_DR_YEAR_SHIFT) & STM32_RTC_DR_YEAR) |
	     ((tm->tm_wday << STM32_RTC_DR_WDAY_SHIFT) & STM32_RTC_DR_WDAY);

	stm32_rtc_wpr_unlock(rtc);

	ret = stm32_rtc_enter_init_mode(rtc);
	if (ret) {
		dev_err(dev, "Can't enter in init mode. Set time aborted.\n");
		goto end;
	}

	writel_relaxed(tr, rtc->base + regs->tr);
	writel_relaxed(dr, rtc->base + regs->dr);

	stm32_rtc_exit_init_mode(rtc);

	ret = stm32_rtc_wait_sync(rtc);
end:
	stm32_rtc_wpr_lock(rtc);

	return ret;
}

static int stm32_rtc_read_alarm(struct device *dev, struct rtc_wkalrm *alrm)
{
	struct stm32_rtc *rtc = dev_get_drvdata(dev);
	const struct stm32_rtc_registers *regs = &rtc->data->regs;
	const struct stm32_rtc_events *evts = &rtc->data->events;
	struct rtc_time *tm = &alrm->time;
	unsigned int alrmar, cr, status;

	alrmar = readl_relaxed(rtc->base + regs->alrmar);
	cr = readl_relaxed(rtc->base + regs->cr);
	status = readl_relaxed(rtc->base + regs->sr);

	if (alrmar & STM32_RTC_ALRMXR_DATE_MASK) {
		/*
		 * Date/day doesn't matter in Alarm comparison so alarm
		 * triggers every day
		 */
		tm->tm_mday = -1;
		tm->tm_wday = -1;
	} else {
		if (alrmar & STM32_RTC_ALRMXR_WDSEL) {
			/* Alarm is set to a day of week */
			tm->tm_mday = -1;
			tm->tm_wday = (alrmar & STM32_RTC_ALRMXR_WDAY) >>
				      STM32_RTC_ALRMXR_WDAY_SHIFT;
			tm->tm_wday %= 7;
		} else {
			/* Alarm is set to a day of month */
			tm->tm_wday = -1;
			tm->tm_mday = (alrmar & STM32_RTC_ALRMXR_DATE) >>
				       STM32_RTC_ALRMXR_DATE_SHIFT;
		}
	}

	if (alrmar & STM32_RTC_ALRMXR_HOUR_MASK) {
		/* Hours don't matter in Alarm comparison */
		tm->tm_hour = -1;
	} else {
		tm->tm_hour = (alrmar & STM32_RTC_ALRMXR_HOUR) >>
			       STM32_RTC_ALRMXR_HOUR_SHIFT;
		if (alrmar & STM32_RTC_ALRMXR_PM)
			tm->tm_hour += 12;
	}

	if (alrmar & STM32_RTC_ALRMXR_MIN_MASK) {
		/* Minutes don't matter in Alarm comparison */
		tm->tm_min = -1;
	} else {
		tm->tm_min = (alrmar & STM32_RTC_ALRMXR_MIN) >>
			      STM32_RTC_ALRMXR_MIN_SHIFT;
	}

	if (alrmar & STM32_RTC_ALRMXR_SEC_MASK) {
		/* Seconds don't matter in Alarm comparison */
		tm->tm_sec = -1;
	} else {
		tm->tm_sec = (alrmar & STM32_RTC_ALRMXR_SEC) >>
			      STM32_RTC_ALRMXR_SEC_SHIFT;
	}

	bcd2tm(tm);

	alrm->enabled = (cr & STM32_RTC_CR_ALRAE) ? 1 : 0;
	alrm->pending = (status & evts->alra) ? 1 : 0;

	return 0;
}

static int stm32_rtc_alarm_irq_enable(struct device *dev, unsigned int enabled)
{
	struct stm32_rtc *rtc = dev_get_drvdata(dev);
	const struct stm32_rtc_registers *regs = &rtc->data->regs;
	const struct stm32_rtc_events *evts = &rtc->data->events;
	unsigned int cr;

	cr = readl_relaxed(rtc->base + regs->cr);

	stm32_rtc_wpr_unlock(rtc);

	/* We expose Alarm A to the kernel */
	if (enabled)
		cr |= (STM32_RTC_CR_ALRAIE | STM32_RTC_CR_ALRAE);
	else
		cr &= ~(STM32_RTC_CR_ALRAIE | STM32_RTC_CR_ALRAE);
	writel_relaxed(cr, rtc->base + regs->cr);

	/* Clear event flags, otherwise new events won't be received */
	stm32_rtc_clear_event_flags(rtc, evts->alra);

	stm32_rtc_wpr_lock(rtc);

	return 0;
}

static int stm32_rtc_valid_alrm(struct device *dev, struct rtc_time *tm)
{
	static struct rtc_time now;
	time64_t max_alarm_time64;
	int max_day_forward;
	int next_month;
	int next_year;

	/*
	 * Assuming current date is M-D-Y H:M:S.
	 * RTC alarm can't be set on a specific month and year.
	 * So the valid alarm range is:
	 *	M-D-Y H:M:S < alarm <= (M+1)-D-Y H:M:S
	 */
	stm32_rtc_read_time(dev, &now);

	/*
	 * Find the next month and the year of the next month.
	 * Note: tm_mon and next_month are from 0 to 11
	 */
	next_month = now.tm_mon + 1;
	if (next_month == 12) {
		next_month = 0;
		next_year = now.tm_year + 1;
	} else {
		next_year = now.tm_year;
	}

	/* Find the maximum limit of alarm in days. */
	max_day_forward = rtc_month_days(now.tm_mon, now.tm_year)
			 - now.tm_mday
			 + min(rtc_month_days(next_month, next_year), now.tm_mday);

	/* Convert to timestamp and compare the alarm time and its upper limit */
	max_alarm_time64 = rtc_tm_to_time64(&now) + max_day_forward * SEC_PER_DAY;
	return rtc_tm_to_time64(tm) <= max_alarm_time64 ? 0 : -EINVAL;
}

static int stm32_rtc_set_alarm(struct device *dev, struct rtc_wkalrm *alrm)
{
	struct stm32_rtc *rtc = dev_get_drvdata(dev);
	const struct stm32_rtc_registers *regs = &rtc->data->regs;
	struct rtc_time *tm = &alrm->time;
	unsigned int cr, isr, alrmar;
	int ret = 0;

	/*
	 * RTC alarm can't be set on a specific date, unless this date is
	 * up to the same day of month next month.
	 */
	if (stm32_rtc_valid_alrm(dev, tm) < 0) {
		dev_err(dev, "Alarm can be set only on upcoming month.\n");
		return -EINVAL;
	}

	tm2bcd(tm);

	alrmar = 0;
	/* tm_year and tm_mon are not used because not supported by RTC */
	alrmar |= (tm->tm_mday << STM32_RTC_ALRMXR_DATE_SHIFT) &
		  STM32_RTC_ALRMXR_DATE;
	/* 24-hour format */
	alrmar &= ~STM32_RTC_ALRMXR_PM;
	alrmar |= (tm->tm_hour << STM32_RTC_ALRMXR_HOUR_SHIFT) &
		  STM32_RTC_ALRMXR_HOUR;
	alrmar |= (tm->tm_min << STM32_RTC_ALRMXR_MIN_SHIFT) &
		  STM32_RTC_ALRMXR_MIN;
	alrmar |= (tm->tm_sec << STM32_RTC_ALRMXR_SEC_SHIFT) &
		  STM32_RTC_ALRMXR_SEC;

	stm32_rtc_wpr_unlock(rtc);

	/* Disable Alarm */
	cr = readl_relaxed(rtc->base + regs->cr);
	cr &= ~STM32_RTC_CR_ALRAE;
	writel_relaxed(cr, rtc->base + regs->cr);

	/*
	 * Poll Alarm write flag to be sure that Alarm update is allowed: it
	 * takes around 2 rtc_ck clock cycles
	 */
	ret = readl_relaxed_poll_timeout_atomic(rtc->base + regs->isr,
						isr,
						(isr & STM32_RTC_ISR_ALRAWF),
						10, 100000);

	if (ret) {
		dev_err(dev, "Alarm update not allowed\n");
		goto end;
	}

	/* Write to Alarm register */
	writel_relaxed(alrmar, rtc->base + regs->alrmar);

	stm32_rtc_alarm_irq_enable(dev, alrm->enabled);
end:
	stm32_rtc_wpr_lock(rtc);

	return ret;
}

static const struct rtc_class_ops stm32_rtc_ops = {
	.read_time	= stm32_rtc_read_time,
	.set_time	= stm32_rtc_set_time,
	.read_alarm	= stm32_rtc_read_alarm,
	.set_alarm	= stm32_rtc_set_alarm,
	.alarm_irq_enable = stm32_rtc_alarm_irq_enable,
};

static void stm32_rtc_clear_events(struct stm32_rtc *rtc,
				   unsigned int flags)
{
	const struct stm32_rtc_registers *regs = &rtc->data->regs;

	/* Flags are cleared by writing 0 in RTC_ISR */
	writel_relaxed(readl_relaxed(rtc->base + regs->isr) & ~flags,
		       rtc->base + regs->isr);
}

static const struct stm32_rtc_data stm32_rtc_data = {
	.has_pclk = false,
	.need_dbp = true,
	.need_accuracy = false,
	.rif_protected = false,
	.has_lsco = false,
	.has_alarm_out = false,
	.regs = {
		.tr = 0x00,
		.dr = 0x04,
		.cr = 0x08,
		.isr = 0x0C,
		.prer = 0x10,
		.alrmar = 0x1C,
		.wpr = 0x24,
		.sr = 0x0C, /* set to ISR offset to ease alarm management */
		.scr = UNDEF_REG,
		.cfgr = UNDEF_REG,
		.verr = UNDEF_REG,
	},
	.events = {
		.alra = STM32_RTC_ISR_ALRAF,
	},
	.clear_events = stm32_rtc_clear_events,
};

static const struct stm32_rtc_data stm32h7_rtc_data = {
	.has_pclk = true,
	.need_dbp = true,
	.need_accuracy = false,
	.rif_protected = false,
	.has_lsco = false,
	.has_alarm_out = false,
	.regs = {
		.tr = 0x00,
		.dr = 0x04,
		.cr = 0x08,
		.isr = 0x0C,
		.prer = 0x10,
		.alrmar = 0x1C,
		.wpr = 0x24,
		.sr = 0x0C, /* set to ISR offset to ease alarm management */
		.scr = UNDEF_REG,
		.cfgr = UNDEF_REG,
		.verr = UNDEF_REG,
	},
	.events = {
		.alra = STM32_RTC_ISR_ALRAF,
	},
	.clear_events = stm32_rtc_clear_events,
};

static void stm32mp1_rtc_clear_events(struct stm32_rtc *rtc,
				      unsigned int flags)
{
	struct stm32_rtc_registers regs = rtc->data->regs;

	/* Flags are cleared by writing 1 in RTC_SCR */
	writel_relaxed(flags, rtc->base + regs.scr);
}

static const struct stm32_rtc_data stm32mp1_data = {
	.has_pclk = true,
	.need_dbp = false,
	.need_accuracy = true,
	.rif_protected = false,
	.has_lsco = true,
	.has_alarm_out = true,
	.regs = {
		.tr = 0x00,
		.dr = 0x04,
		.cr = 0x18,
		.isr = 0x0C, /* named RTC_ICSR on stm32mp1 */
		.prer = 0x10,
		.alrmar = 0x40,
		.wpr = 0x24,
		.sr = 0x50,
		.scr = 0x5C,
		.cfgr = 0x60,
		.verr = 0x3F4,
	},
	.events = {
		.alra = STM32_RTC_SR_ALRA,
	},
	.clear_events = stm32mp1_rtc_clear_events,
};

static const struct stm32_rtc_data stm32mp25_data = {
	.has_pclk = true,
	.need_dbp = false,
	.need_accuracy = true,
	.rif_protected = true,
	.has_lsco = true,
	.has_alarm_out = true,
	.regs = {
		.tr = 0x00,
		.dr = 0x04,
		.cr = 0x18,
		.isr = 0x0C, /* named RTC_ICSR on stm32mp25 */
		.prer = 0x10,
		.alrmar = 0x40,
		.wpr = 0x24,
		.sr = 0x50,
		.scr = 0x5C,
		.cfgr = 0x60,
		.verr = 0x3F4,
	},
	.events = {
		.alra = STM32_RTC_SR_ALRA,
	},
	.clear_events = stm32mp1_rtc_clear_events,
};

static const struct of_device_id stm32_rtc_of_match[] = {
	{ .compatible = "st,stm32-rtc", .data = &stm32_rtc_data },
	{ .compatible = "st,stm32h7-rtc", .data = &stm32h7_rtc_data },
	{ .compatible = "st,stm32mp1-rtc", .data = &stm32mp1_data },
	{ .compatible = "st,stm32mp25-rtc", .data = &stm32mp25_data },
	{}
};
MODULE_DEVICE_TABLE(of, stm32_rtc_of_match);

static void stm32_rtc_clean_outs(struct stm32_rtc *rtc)
{
	struct stm32_rtc_registers regs = rtc->data->regs;
	unsigned int cr = readl_relaxed(rtc->base + regs.cr);

	cr &= ~STM32_RTC_CR_OSEL;
	cr &= ~STM32_RTC_CR_TAMPOE;
	cr &= ~STM32_RTC_CR_COE;
	cr &= ~STM32_RTC_CR_TAMPALRM_TYPE;
	cr &= ~STM32_RTC_CR_OUT2EN;

	stm32_rtc_wpr_unlock(rtc);
	writel_relaxed(cr, rtc->base + regs.cr);
	stm32_rtc_wpr_lock(rtc);

	if (regs.cfgr != UNDEF_REG) {
		unsigned int cfgr = readl_relaxed(rtc->base + regs.cfgr);

		cfgr &= ~STM32_RTC_CFGR_LSCOEN;
		cfgr &= ~STM32_RTC_CFGR_OUT2_RMP;
		writel_relaxed(cfgr, rtc->base + regs.cfgr);
	}
}

static int stm32_rtc_check_rif(struct stm32_rtc *stm32_rtc,
			       struct stm32_rtc_rif_resource res)
{
	u32 rxcidcfgr = readl_relaxed(stm32_rtc->base + STM32_RTC_RXCIDCFGR(res.num));
	u32 seccfgr;

	/* Check if RTC available for our CID */
	if ((rxcidcfgr & STM32_RTC_RXCIDCFGR_CFEN) &&
	    (FIELD_GET(STM32_RTC_RXCIDCFGR_CID, rxcidcfgr) != STM32_RTC_RXCIDCFGR_CID1))
		return -EACCES;

	/* Check if RTC available for non secure world */
	seccfgr = readl_relaxed(stm32_rtc->base + STM32_RTC_SECCFGR);
	if ((seccfgr & STM32_RTC_SECCFGR_SEC) | (seccfgr & res.bit))
		return -EACCES;

	return 0;
}

static int stm32_rtc_init(struct platform_device *pdev,
			  struct stm32_rtc *rtc)
{
	const struct stm32_rtc_registers *regs = &rtc->data->regs;
	unsigned int prer, pred_a, pred_s, pred_a_max, pred_s_max, cr;
	unsigned int rate;
	int ret;

	rate = clk_get_rate(rtc->rtc_ck);

	/* Find prediv_a and prediv_s to obtain the 1Hz calendar clock */
	pred_a_max = STM32_RTC_PRER_PRED_A >> STM32_RTC_PRER_PRED_A_SHIFT;
	pred_s_max = STM32_RTC_PRER_PRED_S >> STM32_RTC_PRER_PRED_S_SHIFT;

	if (rate > (pred_a_max + 1) * (pred_s_max + 1)) {
		dev_err(&pdev->dev, "rtc_ck rate is too high: %dHz\n", rate);
		return -EINVAL;
	}

	if (rtc->data->need_accuracy) {
		for (pred_a = 0; pred_a <= pred_a_max; pred_a++) {
			pred_s = (rate / (pred_a + 1)) - 1;

			if (pred_s <= pred_s_max && ((pred_s + 1) * (pred_a + 1)) == rate)
				break;
		}
	} else {
		for (pred_a = pred_a_max; pred_a + 1 > 0; pred_a--) {
			pred_s = (rate / (pred_a + 1)) - 1;

			if (((pred_s + 1) * (pred_a + 1)) == rate)
				break;
		}
	}

	/*
	 * Can't find a 1Hz, so give priority to RTC power consumption
	 * by choosing the higher possible value for prediv_a
	 */
	if (pred_s > pred_s_max || pred_a > pred_a_max) {
		pred_a = pred_a_max;
		pred_s = (rate / (pred_a + 1)) - 1;

		dev_warn(&pdev->dev, "rtc_ck is %s\n",
			 (rate < ((pred_a + 1) * (pred_s + 1))) ?
			 "fast" : "slow");
	}

	cr = readl_relaxed(rtc->base + regs->cr);

	prer = readl_relaxed(rtc->base + regs->prer);
	prer &= STM32_RTC_PRER_PRED_S | STM32_RTC_PRER_PRED_A;

	pred_s = (pred_s << STM32_RTC_PRER_PRED_S_SHIFT) &
		 STM32_RTC_PRER_PRED_S;
	pred_a = (pred_a << STM32_RTC_PRER_PRED_A_SHIFT) &
		 STM32_RTC_PRER_PRED_A;

	/* quit if there is nothing to initialize */
	if ((cr & STM32_RTC_CR_FMT) == 0 && prer == (pred_s | pred_a))
		return 0;

	stm32_rtc_wpr_unlock(rtc);

	ret = stm32_rtc_enter_init_mode(rtc);
	if (ret) {
		dev_err(&pdev->dev,
			"Can't enter in init mode. Prescaler config failed.\n");
		goto end;
	}

	writel_relaxed(pred_s, rtc->base + regs->prer);
	writel_relaxed(pred_a | pred_s, rtc->base + regs->prer);

	/* Force 24h time format */
	cr &= ~STM32_RTC_CR_FMT;
	writel_relaxed(cr, rtc->base + regs->cr);

	stm32_rtc_exit_init_mode(rtc);

	ret = stm32_rtc_wait_sync(rtc);
end:
	stm32_rtc_wpr_lock(rtc);

	return ret;
}

static int stm32_rtc_probe(struct platform_device *pdev)
{
	struct stm32_rtc *rtc;
	const struct stm32_rtc_registers *regs;
	struct pinctrl_dev *pctl;
	int ret;

	rtc = devm_kzalloc(&pdev->dev, sizeof(*rtc), GFP_KERNEL);
	if (!rtc)
		return -ENOMEM;

	rtc->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(rtc->base))
		return PTR_ERR(rtc->base);

	rtc->data = (struct stm32_rtc_data *)
		    of_device_get_match_data(&pdev->dev);
	regs = &rtc->data->regs;

	if (rtc->data->need_dbp) {
		unsigned int args[2];

		rtc->dbp = syscon_regmap_lookup_by_phandle_args(pdev->dev.of_node,
								"st,syscfg",
								2, args);
		if (IS_ERR(rtc->dbp)) {
			dev_err(&pdev->dev, "no st,syscfg\n");
			return PTR_ERR(rtc->dbp);
		}

		rtc->dbp_reg = args[0];
		rtc->dbp_mask = args[1];
	}

	if (!rtc->data->has_pclk) {
		rtc->pclk = NULL;
		rtc->rtc_ck = devm_clk_get(&pdev->dev, NULL);
	} else {
		rtc->pclk = devm_clk_get(&pdev->dev, "pclk");
		if (IS_ERR(rtc->pclk))
			return dev_err_probe(&pdev->dev, PTR_ERR(rtc->pclk), "no pclk clock");

		rtc->rtc_ck = devm_clk_get(&pdev->dev, "rtc_ck");
	}
	if (IS_ERR(rtc->rtc_ck))
		return dev_err_probe(&pdev->dev, PTR_ERR(rtc->rtc_ck), "no rtc_ck clock");

	if (rtc->data->has_pclk) {
		ret = clk_prepare_enable(rtc->pclk);
		if (ret)
			return ret;
	}

	ret = clk_prepare_enable(rtc->rtc_ck);
	if (ret)
		goto err_no_rtc_ck;

	if (rtc->data->need_dbp)
		regmap_update_bits(rtc->dbp, rtc->dbp_reg,
				   rtc->dbp_mask, rtc->dbp_mask);

	if (rtc->data->rif_protected) {
		ret = stm32_rtc_check_rif(rtc, STM32_RTC_RES_INIT);
		if (!ret)
			ret = stm32_rtc_check_rif(rtc, STM32_RTC_RES_ALRA);
		if (ret) {
			dev_err(&pdev->dev, "Failed to probe RTC due to RIF configuration\n");
			goto err;
		}
	}

	/*
	 * After a system reset, RTC_ISR.INITS flag can be read to check if
	 * the calendar has been initialized or not. INITS flag is reset by a
	 * power-on reset (no vbat, no power-supply). It is not reset if
	 * rtc_ck parent clock has changed (so RTC prescalers need to be
	 * changed). That's why we cannot rely on this flag to know if RTC
	 * init has to be done.
	 */
	ret = stm32_rtc_init(pdev, rtc);
	if (ret)
		goto err;

	rtc->irq_alarm = platform_get_irq(pdev, 0);
	if (rtc->irq_alarm <= 0) {
		ret = rtc->irq_alarm;
		goto err;
	}

	ret = devm_device_init_wakeup(&pdev->dev);
	if (ret)
		goto err;

	ret = devm_pm_set_wake_irq(&pdev->dev, rtc->irq_alarm);
	if (ret)
		goto err;

	platform_set_drvdata(pdev, rtc);

	rtc->rtc_dev = devm_rtc_device_register(&pdev->dev, pdev->name,
						&stm32_rtc_ops, THIS_MODULE);
	if (IS_ERR(rtc->rtc_dev)) {
		ret = PTR_ERR(rtc->rtc_dev);
		dev_err(&pdev->dev, "rtc device registration failed, err=%d\n",
			ret);
		goto err;
	}

	/* Handle RTC alarm interrupts */
	ret = devm_request_threaded_irq(&pdev->dev, rtc->irq_alarm, NULL,
					stm32_rtc_alarm_irq, IRQF_ONESHOT,
					pdev->name, rtc);
	if (ret) {
		dev_err(&pdev->dev, "IRQ%d (alarm interrupt) already claimed\n",
			rtc->irq_alarm);
		goto err;
	}

	stm32_rtc_clean_outs(rtc);

	ret = devm_pinctrl_register_and_init(&pdev->dev, &stm32_rtc_pdesc, rtc, &pctl);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "pinctrl register failed");

	ret = pinctrl_enable(pctl);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "pinctrl enable failed");

	/*
	 * If INITS flag is reset (calendar year field set to 0x00), calendar
	 * must be initialized
	 */
	if (!(readl_relaxed(rtc->base + regs->isr) & STM32_RTC_ISR_INITS))
		dev_warn(&pdev->dev, "Date/Time must be initialized\n");

	if (regs->verr != UNDEF_REG) {
		u32 ver = readl_relaxed(rtc->base + regs->verr);

		dev_info(&pdev->dev, "registered rev:%d.%d\n",
			 (ver >> STM32_RTC_VERR_MAJREV_SHIFT) & 0xF,
			 (ver >> STM32_RTC_VERR_MINREV_SHIFT) & 0xF);
	}

	return 0;

err:
	clk_disable_unprepare(rtc->rtc_ck);
err_no_rtc_ck:
	if (rtc->data->has_pclk)
		clk_disable_unprepare(rtc->pclk);

	if (rtc->data->need_dbp)
		regmap_update_bits(rtc->dbp, rtc->dbp_reg, rtc->dbp_mask, 0);

	return ret;
}

static void stm32_rtc_remove(struct platform_device *pdev)
{
	struct stm32_rtc *rtc = platform_get_drvdata(pdev);
	const struct stm32_rtc_registers *regs = &rtc->data->regs;
	unsigned int cr;

	if (!IS_ERR_OR_NULL(rtc->clk_lsco))
		clk_unregister_gate(rtc->clk_lsco);

	/* Disable interrupts */
	stm32_rtc_wpr_unlock(rtc);
	cr = readl_relaxed(rtc->base + regs->cr);
	cr &= ~STM32_RTC_CR_ALRAIE;
	writel_relaxed(cr, rtc->base + regs->cr);
	stm32_rtc_wpr_lock(rtc);

	clk_disable_unprepare(rtc->rtc_ck);
	if (rtc->data->has_pclk)
		clk_disable_unprepare(rtc->pclk);

	/* Enable backup domain write protection if needed */
	if (rtc->data->need_dbp)
		regmap_update_bits(rtc->dbp, rtc->dbp_reg, rtc->dbp_mask, 0);
}

static int stm32_rtc_suspend(struct device *dev)
{
	struct stm32_rtc *rtc = dev_get_drvdata(dev);

	if (rtc->data->has_pclk)
		clk_disable_unprepare(rtc->pclk);

	return 0;
}

static int stm32_rtc_resume(struct device *dev)
{
	struct stm32_rtc *rtc = dev_get_drvdata(dev);
	int ret = 0;

	if (rtc->data->has_pclk) {
		ret = clk_prepare_enable(rtc->pclk);
		if (ret)
			return ret;
	}

	ret = stm32_rtc_wait_sync(rtc);
	if (ret < 0) {
		if (rtc->data->has_pclk)
			clk_disable_unprepare(rtc->pclk);
		return ret;
	}

	return ret;
}

static const struct dev_pm_ops stm32_rtc_pm_ops = {
	NOIRQ_SYSTEM_SLEEP_PM_OPS(stm32_rtc_suspend, stm32_rtc_resume)
};

static struct platform_driver stm32_rtc_driver = {
	.probe		= stm32_rtc_probe,
	.remove		= stm32_rtc_remove,
	.driver		= {
		.name	= DRIVER_NAME,
		.pm	= &stm32_rtc_pm_ops,
		.of_match_table = stm32_rtc_of_match,
	},
};

module_platform_driver(stm32_rtc_driver);

MODULE_AUTHOR("Amelie Delaunay <amelie.delaunay@st.com>");
MODULE_DESCRIPTION("STMicroelectronics STM32 Real Time Clock driver");
MODULE_LICENSE("GPL v2");
