.. SPDX-License-Identifier: GPL-2.0

=============
Shadow Stacks
=============

Introduction
============

Several architectures have features which provide backward edge
control flow protection through a hardware maintained stack, only
writable by userspace through very limited operations.  This feature
is referred to as shadow stacks on Linux, on x86 it is part of Intel
Control Enforcement Technology (CET), on arm64 it is Guarded Control
Stacks feature (FEAT_GCS) and for RISC-V it is the Zicfiss extension.
It is expected that this feature will normally be managed by the
system dynamic linker and libc in ways broadly transparent to
application code, this document covers interfaces and considerations.


Enabling
========

Shadow stacks default to disabled when a userspace process is
executed, they can be enabled for the current thread with a syscall:

 - For x86 the ARCH_SHSTK_ENABLE arch_prctl()
 - For other architectures the PR_SET_SHADOW_STACK_ENABLE prctl()

It is expected that this will normally be done by the dynamic linker.
Any new threads created by a thread with shadow stacks enabled will
themselves have shadow stacks enabled.


Enablement considerations
=========================

- Returning from the function that enables shadow stacks without first
  disabling them will cause a shadow stack exception.  This includes
  any syscall wrapper or other library functions, the syscall will need
  to be inlined.
- A lock feature allows userspace to prevent disabling of shadow stacks.
- Those that change the stack context like longjmp() or use of ucontext
  changes on signal return will need support from libc.
