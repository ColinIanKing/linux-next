// SPDX-License-Identifier: GPL-2.0
//
// Renesas MFIS (Multifunctional Inferface) Mailbox Driver
//
// Copyright (C) 2025, Renesas Electronics Corporation.
//

#include <linux/device.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/interrupt.h>
#include <linux/mailbox_controller.h>
#include <linux/module.h>
#include <linux/platform_device.h>

enum direction {
	TX,
	RX,
	NUM_DIRECTION,
};

struct mfis_chan {
	u32 __iomem *reg;
	bool active;
};

struct mfis_priv {
	struct mbox_controller mbox;
	spinlock_t lock;
	struct mbox_chan  chan[NUM_DIRECTION];
	struct mfis_chan mchan[NUM_DIRECTION];
};

#define mfis_chan_to_priv(ch) chan->con_priv
#define mfis_chan_to_mchan(priv, ch) (priv->mchan + (ch - priv->chan))

static int mfis_send_data(struct mbox_chan *chan, void *data)
{
	struct mfis_priv *priv  = mfis_chan_to_priv(chan);
	struct mfis_chan *mchan = mfis_chan_to_mchan(priv, chan);

	iowrite32(0x1, mchan->reg);

	return 0;
}

static irqreturn_t mfis_interrupt(int irq, void *data)
{
	struct mfis_priv *priv = data;

	guard(spinlock)(&priv->lock);

	for (int i = 0; i < NUM_DIRECTION; i++) {
		struct mbox_chan *chan  = priv->chan  + i;
		struct mfis_chan *mchan = priv->mchan + i;

		if (mchan->active)
			mbox_chan_received_data(chan, 0);

		iowrite32(0x0, mchan->reg);
	}

	return IRQ_HANDLED;
}

static int mfis_chan_set_active(struct mbox_chan *chan, bool active)
{
	struct mfis_priv *priv  = mfis_chan_to_priv(chan);
	struct mfis_chan *mchan = mfis_chan_to_mchan(priv, chan);

	guard(spinlock_irqsave)(&priv->lock);

	mchan->active = active;

	return 0;
}

static int mfis_startup(struct mbox_chan *chan)
{
	return mfis_chan_set_active(chan, true);
}

static void mfis_shutdown(struct mbox_chan *chan)
{
	mfis_chan_set_active(chan, false);
}

static bool mfis_last_tx_done(struct mbox_chan *chan)
{
	return true;
}

static const struct mbox_chan_ops mfis_chan_ops = {
	.send_data	= mfis_send_data,
	.startup	= mfis_startup,
	.shutdown	= mfis_shutdown,
	.last_tx_done	= mfis_last_tx_done
};

static int mfis_mbox_probe(struct platform_device *pdev)
{
	struct mfis_priv *priv;
	struct device *dev = &pdev->dev;
	struct mbox_controller *mbox;
	void __iomem *reg;
	int ret, irq;

	irq = of_irq_get(dev->of_node, 0);
	if (irq < 0)
		return irq;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ret = devm_request_irq(dev, irq, mfis_interrupt, 0, dev_name(dev), priv);
	if (ret < 0)
		return ret;

	reg = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(reg))
		return PTR_ERR(reg);

	spin_lock_init(&priv->lock);

	priv->mchan[TX].reg	= reg + 0x4;
	priv->mchan[RX].reg	= reg;

	mbox = &priv->mbox;

	mbox->chans	= priv->chan;
	mbox->chans[TX].mbox = mbox;
	mbox->chans[RX].mbox = mbox;
	mbox->chans[TX].con_priv = priv;
	mbox->chans[RX].con_priv = priv;
	mbox->txdone_poll = true;
	mbox->txdone_irq = false;
	mbox->txpoll_period = 1;
	mbox->num_chans = NUM_DIRECTION;
	mbox->ops = &mfis_chan_ops;
	mbox->dev = dev;

	ret = mbox_controller_register(mbox);
	if (ret)
		return ret;

	platform_set_drvdata(pdev, mbox);

	return 0;
}

static const struct of_device_id mfis_mbox_of_match[] = {
	{ .compatible = "rcar,mfis-mailbox-gen5" },
	{}
};
MODULE_DEVICE_TABLE(of, mfis_mbox_of_match);

static struct platform_driver mfis_mbox_driver = {
	.driver = {
		.name = "rcar-mfis-mailbox",
		.of_match_table = mfis_mbox_of_match,
	},
	.probe	= mfis_mbox_probe,
};
module_platform_driver(mfis_mbox_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("R-Car MFIS mailbox driver");
