// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 James.Bottomley@HansenPartnership.com
 */
#include <linux/slab.h>
#include "tpm-dev.h"

struct tpmrm_priv {
	struct file_priv priv;
	struct tpm_space space;
};

static int tpmrm_open(struct inode *inode, struct file *file)
{
	struct tpm_chip *chip;
	struct tpmrm_priv *priv;
	int rc;

	chip = container_of(inode->i_cdev, struct tpm_chip, cdevs);

	/*
	 * Only one client is allowed to have /dev/tpm0 open at a time, so we
	 * treat it as a write lock. The shared /dev/tpmrm0 is treated as a
	 * read lock.
	 */
	if (!down_read_trylock(&chip->open_lock)) {
		dev_dbg(&chip->dev, "Another process owns this TPM\n");
		return -EBUSY;
	}

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (priv == NULL)
		goto err;

	rc = tpm2_init_space(&priv->space, TPM2_SPACE_BUFFER_SIZE);
	if (rc) {
		kfree(priv);
		goto err;
	}

	tpm_common_open(file, chip, &priv->priv, &priv->space);

	return 0;

err:
	up_read(&chip->open_lock);
	return -ENOMEM;
}

static int tpmrm_release(struct inode *inode, struct file *file)
{
	struct file_priv *fpriv = file->private_data;
	struct tpmrm_priv *priv = container_of(fpriv, struct tpmrm_priv, priv);

	tpm_common_release(file, fpriv);
	tpm2_del_space(fpriv->chip, &priv->space);
	kfree(priv);
	up_read(&fpriv->chip->open_lock);

	return 0;
}

const struct file_operations tpmrm_fops = {
	.owner = THIS_MODULE,
	.open = tpmrm_open,
	.read = tpm_common_read,
	.write = tpm_common_write,
	.poll = tpm_common_poll,
	.release = tpmrm_release,
};
