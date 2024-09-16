// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, Broadcom Corporation
 */
#include <linux/fwctl.h>
#include <linux/auxiliary_bus.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <uapi/fwctl/bnxt.h>

/* FIXME need a include/linux header for the aux related definitions */
#include <../../../drivers/net/ethernet/broadcom/bnxt/bnxt.h>
#include <../../../drivers/net/ethernet/broadcom/bnxt/bnxt_ulp.h>

struct bnxtctl_uctx {
	struct fwctl_uctx uctx;
	u32 uctx_caps;
};

struct bnxtctl_dev {
	struct fwctl_device fwctl;
	struct bnxt_aux_priv *aux_priv;
};

DEFINE_FREE(bnxtctl, struct bnxtctl_dev *, if (_T) fwctl_put(&_T->fwctl))

static int bnxtctl_open_uctx(struct fwctl_uctx *uctx)
{
	struct bnxtctl_uctx *bnxtctl_uctx =
		container_of(uctx, struct bnxtctl_uctx, uctx);

	bnxtctl_uctx->uctx_caps = BIT(FWCTL_BNXT_QUERY_COMMANDS) |
				  BIT(FWCTL_BNXT_SEND_COMMAND);
	return 0;
}

static void bnxtctl_close_uctx(struct fwctl_uctx *uctx)
{
}

static void *bnxtctl_info(struct fwctl_uctx *uctx, size_t *length)
{
	struct bnxtctl_uctx *bnxtctl_uctx =
		container_of(uctx, struct bnxtctl_uctx, uctx);
	struct fwctl_info_bnxt *info;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return ERR_PTR(-ENOMEM);

	info->uctx_caps = bnxtctl_uctx->uctx_caps;

	*length = sizeof(*info);
	return info;
}

/*
 * bnxt_fw_msg->msg has the whole command
 * the start of message is of type struct input
 * struct input {
 *         __le16  req_type;
 *         __le16  cmpl_ring;
 *         __le16  seq_id;
 *         __le16  target_id;
 *         __le64  resp_addr;
 * };
 * so the hwrm op should be (struct input *)(hwrm_in->msg)->req_type
 */
static bool bnxtctl_validate_rpc(struct fwctl_uctx *uctx,
				 struct bnxt_fw_msg *hwrm_in)
{
	struct input *req = (struct input *)hwrm_in->msg;

	switch (req->req_type) {
	case HWRM_VER_GET:
		return true;
	default:
		return false;
	}
}

static void *bnxtctl_fw_rpc(struct fwctl_uctx *uctx, enum fwctl_rpc_scope scope,
			    void *in, size_t in_len, size_t *out_len)
{
	struct bnxtctl_dev *bnxtctl =
		container_of(uctx->fwctl, struct bnxtctl_dev, fwctl);
	struct bnxt_aux_priv *bnxt_aux_priv = bnxtctl->aux_priv;
	/* FIXME: Check me */
	struct bnxt_fw_msg rpc_in = {
		// FIXME: does bnxt_send_msg() copy?
		.msg = in,
		.msg_len = in_len,
		.resp = in,
		// FIXME: Dynamic memory for out_len
		.resp_max_len = in_len,
	};
	int rc;

	if (!bnxtctl_validate_rpc(uctx, &rpc_in))
		return ERR_PTR(-EPERM);

	rc = bnxt_send_msg(bnxt_aux_priv->edev, &rpc_in);
	if (!rc)
		return ERR_PTR(-EOPNOTSUPP);
	return in;
}

static const struct fwctl_ops bnxtctl_ops = {
	.device_type = FWCTL_DEVICE_TYPE_BNXT,
	.uctx_size = sizeof(struct bnxtctl_uctx),
	.open_uctx = bnxtctl_open_uctx,
	.close_uctx = bnxtctl_close_uctx,
	.info = bnxtctl_info,
	.fw_rpc = bnxtctl_fw_rpc,
};

static int bnxtctl_probe(struct auxiliary_device *adev,
			 const struct auxiliary_device_id *id)
{
	struct bnxt_aux_priv *aux_priv =
		container_of(adev, struct bnxt_aux_priv, aux_dev);
	struct bnxtctl_dev *bnxtctl __free(bnxtctl) =
		fwctl_alloc_device(&aux_priv->edev->pdev->dev, &bnxtctl_ops,
				   struct bnxtctl_dev, fwctl);
	int rc;

	if (!bnxtctl)
		return -ENOMEM;

	bnxtctl->aux_priv = aux_priv;

	rc = fwctl_register(&bnxtctl->fwctl);
	if (rc)
		return rc;

	auxiliary_set_drvdata(adev, no_free_ptr(bnxtctl));
	return 0;
}

static void bnxtctl_remove(struct auxiliary_device *adev)
{
	struct bnxtctl_dev *ctldev = auxiliary_get_drvdata(adev);

	fwctl_unregister(&ctldev->fwctl);
	fwctl_put(&ctldev->fwctl);
}

static const struct auxiliary_device_id bnxtctl_id_table[] = {
	{ .name = "bnxt_en.fwctl", },
	{},
};
MODULE_DEVICE_TABLE(auxiliary, bnxtctl_id_table);

static struct auxiliary_driver bnxtctl_driver = {
	.name = "bnxt_fwctl",
	.probe = bnxtctl_probe,
	.remove = bnxtctl_remove,
	.id_table = bnxtctl_id_table,
};

module_auxiliary_driver(bnxtctl_driver);

MODULE_IMPORT_NS(BNXT);
MODULE_IMPORT_NS(FWCTL);
MODULE_DESCRIPTION("BNXT fwctl driver");
MODULE_AUTHOR("Broadcom Corporation");
MODULE_LICENSE("GPL");
