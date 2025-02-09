.. SPDX-License-Identifier: GPL-2.0-or-later

=======================
Kexec Handover Concepts
=======================

Kexec HandOver (KHO) is a mechanism that allows Linux to preserve state -
arbitrary properties as well as memory locations - across kexec.

It introduces multiple concepts:

KHO Device Tree
---------------

Every KHO kexec carries a KHO specific flattened device tree blob that
describes the state of the system. Device drivers can register to KHO to
serialize their state before kexec. After KHO, device drivers can read
the device tree and extract previous state.

KHO only uses the fdt container format and libfdt library, but does not
adhere to the same property semantics that normal device trees do: Properties
are passed in native endianness and standardized properties like ``regs`` and
``ranges`` do not exist, hence there are no ``#...-cells`` properties.

KHO introduces a new concept to its device tree: ``mem`` properties. A
``mem`` property can be inside any subnode in the device tree. When present,
it contains an array of physical memory ranges that the new kernel must mark
as reserved on boot. It is recommended, but not required, to make these ranges
as physically contiguous as possible to reduce the number of array elements ::

    struct kho_mem {
            __u64 addr;
            __u64 len;
    };

After boot, drivers can call the kho subsystem to transfer ownership of memory
that was reserved via a ``mem`` property to themselves to continue using memory
from the previous execution.

The KHO device tree follows the in-Linux schema requirements. Any element in
the device tree is documented via device tree schema yamls that explain what
data gets transferred.

Scratch Regions
---------------

To boot into kexec, we need to have a physically contiguous memory range that
contains no handed over memory. Kexec then places the target kernel and initrd
into that region. The new kernel exclusively uses this region for memory
allocations before during boot up to the initialization of the page allocator.

We guarantee that we always have such regions through the scratch regions: On
first boot KHO allocates several physically contiguous memory regions. Since
after kexec these regions will be used by early memory allocations, there is a
scratch region per NUMA node plus a scratch region to satisfy allocations
requests that do not require particilar NUMA node assignment.
By default, size of the scratch region is calculated based on amount of memory
allocated during boot. The ``kho_scratch`` kernel command line option may be used to explicitly define size of the scratch regions.
The scratch regions are declared as CMA when page allocator is initialized so
that their memory can be used during system lifetime. CMA gives us the
guarantee that no handover pages land in that region, because handover pages
must be at a static physical memory location and CMA enforces that only
movable pages can be located inside.

After KHO kexec, we ignore the ``kho_scratch`` kernel command line option and
instead reuse the exact same region that was originally allocated. This allows
us to recursively execute any amount of KHO kexecs. Because we used this region
for boot memory allocations and as target memory for kexec blobs, some parts
of that memory region may be reserved. These reservations are irrenevant for
the next KHO, because kexec can overwrite even the original kernel.

KHO active phase
----------------

To enable user space based kexec file loader, the kernel needs to be able to
provide the device tree that describes the previous kernel's state before
performing the actual kexec. The process of generating that device tree is
called serialization. When the device tree is generated, some properties
of the system may become immutable because they are already written down
in the device tree. That state is called the KHO active phase.
