.. SPDX-License-Identifier: GPL-2.0

Arch Support
============

Currently, the Rust compiler (``rustc``) uses LLVM for code generation,
which limits the supported architectures that can be targeted. In addition,
support for building the kernel with LLVM/Clang varies (please see
Documentation/kbuild/llvm.rst). This support is needed for ``bindgen``
which uses ``libclang``.

Below is a general summary of architectures that currently work. Level of
support corresponds to ``S`` values in the ``MAINTAINERS`` file.

============  ================  ==============================================
Architecture  Level of support  Constraints
============  ================  ==============================================
``arm``       Maintained        ``armv6`` and compatible only,
                                ``RUST_OPT_LEVEL >= 2``.
``arm64``     Maintained        None.
``powerpc``   Maintained        ``ppc64le`` only, ``RUST_OPT_LEVEL < 2``
                                requires ``CONFIG_THREAD_SHIFT=15``.
``riscv``     Maintained        ``riscv64`` only.
``x86``       Maintained        ``x86_64`` only.
============  ================  ==============================================
