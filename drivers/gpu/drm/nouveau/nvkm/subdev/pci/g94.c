/*
 * Copyright 2015 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors: Ben Skeggs <bskeggs@redhat.com>
 */
#include "priv.h"

static const struct nvkm_pci_func
g94_pci_func = {
	.cfg = { .addr = 0x088000, .size = 0x1000 },

	.init = g84_pci_init,
	.msi_rearm = nv40_pci_msi_rearm,

	.pcie.init = g84_pcie_init,
	.pcie.set_link = g84_pcie_set_link,

	.pcie.max_speed = g84_pcie_max_speed,
	.pcie.cur_speed = g84_pcie_cur_speed,

	.pcie.set_version = g84_pcie_set_version,
	.pcie.version = g84_pcie_version,
	.pcie.version_supported = g92_pcie_version_supported,
};

int
g94_pci_new(struct nvkm_device *device, enum nvkm_subdev_type type, int inst,
	    struct nvkm_pci **ppci)
{
	return nvkm_pci_new_(&g94_pci_func, device, type, inst, ppci);
}
