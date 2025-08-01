.. SPDX-License-Identifier: GPL-2.0

:Author: Deepak Gupta <debug@rivosinc.com>
:Date:   12 January 2024

=========================================================
Shadow stack to protect function returns on RISC-V Linux
=========================================================

This document briefly describes the interface provided to userspace by Linux
to enable shadow stack for user mode applications on RISC-V

1. Feature Overview
--------------------

Memory corruption issues usually result into crashes, however when in hands of
an adversary and if used creatively can result into a variety security issues.

One of those security issues can be code re-use attacks on program where
adversary can use corrupt return addresses present on stack and chain them
together to perform return oriented programming (ROP) and thus compromising
control flow integrity (CFI) of the program.

Return addresses live on stack and thus in read-write memory and thus are
susceptible to corruption and which allows an adversary to reach any program
counter (PC) in address space. On RISC-V ``zicfiss`` extension provides an
alternate stack termed as shadow stack on which return addresses can be safely
placed in prolog of the function and retrieved in epilog. ``zicfiss`` extension
makes following changes:

- PTE encodings for shadow stack virtual memory
  An earlier reserved encoding in first stage translation i.e.
  PTE.R=0, PTE.W=1, PTE.X=0  becomes PTE encoding for shadow stack pages.

- ``sspush x1/x5`` instruction pushes (stores) ``x1/x5`` to shadow stack.

- ``sspopchk x1/x5`` instruction pops (loads) from shadow stack and compares
  with ``x1/x5`` and if un-equal, CPU raises ``software check exception`` with
  ``*tval = 3``

Compiler toolchain makes sure that function prologue have ``sspush x1/x5`` to
save return address on shadow stack in addition to regular stack. Similarly
function epilogs have ``ld x5, offset(x2)`` followed by ``sspopchk x5`` to
ensure that popped value from regular stack matches with popped value from
shadow stack.

2. Shadow stack protections and linux memory manager
-----------------------------------------------------

As mentioned earlier, shadow stacks get new page table encodings and thus have
some special properties assigned to them and instructions that operate on them
as below:

- Regular stores to shadow stack memory raises access store faults. This way
  shadow stack memory is protected from stray inadvertent writes.

- Regular loads to shadow stack memory are allowed. This allows stack trace
  utilities or backtrace functions to read true callstack (not tampered).

- Only shadow stack instructions can generate shadow stack load or shadow stack
  store.

- Shadow stack load / shadow stack store on read-only memory raises AMO/store
  page fault. Thus both ``sspush x1/x5`` and ``sspopchk x1/x5`` will raise AMO/
  store page fault. This simplies COW handling in kernel during fork, kernel
  can convert shadow stack pages into read-only memory (as it does for regular
  read-write memory) and as soon as subsequent ``sspush`` or ``sspopchk`` in
  userspace is encountered, then kernel can perform COW.

- Shadow stack load / shadow stack store on read-write, read-write-execute
  memory raises an access fault. This is a fatal condition because shadow stack
  should never be operating on read-write, read-write-execute memory.

3. ELF and psABI
-----------------

Toolchain sets up :c:macro:`GNU_PROPERTY_RISCV_FEATURE_1_BCFI` for property
:c:macro:`GNU_PROPERTY_RISCV_FEATURE_1_AND` in notes section of the object file.

4. Linux enabling
------------------

User space programs can have multiple shared objects loaded in its address space
and it's a difficult task to make sure all the dependencies have been compiled
with support of shadow stack. Thus it's left to dynamic loader to enable
shadow stack for the program.

5. prctl() enabling
--------------------

:c:macro:`PR_SET_SHADOW_STACK_STATUS` / :c:macro:`PR_GET_SHADOW_STACK_STATUS` /
:c:macro:`PR_LOCK_SHADOW_STACK_STATUS` are three prctls added to manage shadow
stack enabling for tasks. prctls are arch agnostic and returns -EINVAL on other
arches.

* prctl(PR_SET_SHADOW_STACK_STATUS, unsigned long arg)

If arg1 :c:macro:`PR_SHADOW_STACK_ENABLE` and if CPU supports ``zicfiss`` then
kernel will enable shadow stack for the task. Dynamic loader can issue this
:c:macro:`prctl` once it has determined that all the objects loaded in address
space have support for shadow stack. Additionally if there is a
:c:macro:`dlopen` to an object which wasn't compiled with ``zicfiss``, dynamic
loader can issue this prctl with arg1 set to 0 (i.e.
:c:macro:`PR_SHADOW_STACK_ENABLE` being clear)

* prctl(PR_GET_SHADOW_STACK_STATUS, unsigned long *arg)

Returns current status of indirect branch tracking. If enabled it'll return
:c:macro:`PR_SHADOW_STACK_ENABLE`.

* prctl(PR_LOCK_SHADOW_STACK_STATUS, unsigned long arg)

Locks current status of shadow stack enabling on the task. User space may want
to run with strict security posture and wouldn't want loading of objects
without ``zicfiss`` support in it and thus would want to disallow disabling of
shadow stack on current task. In that case user space can use this prctl to
lock current settings.

5. violations related to returns with shadow stack enabled
-----------------------------------------------------------

Pertaining to shadow stack, CPU raises software check exception in following
condition:

- On execution of ``sspopchk x1/x5``, ``x1/x5`` didn't match top of shadow
  stack. If mismatch happens then cpu does ``*tval = 3`` and raise software
  check exception.

Linux kernel will treat this as :c:macro:`SIGSEV`` with code =
:c:macro:`SEGV_CPERR` and follow normal course of signal delivery.

6. Shadow stack tokens
-----------------------
Regular stores on shadow stacks are not allowed and thus can't be tampered
with via arbitrary stray writes due to bugs. However method of pivoting /
switching to shadow stack is simply writing to csr ``CSR_SSP`` and that will
change active shadow stack for the program. Instances of writes to ``CSR_SSP``
in the address space of the program should be mostly limited to context
switching, stack unwind, longjmp or similar mechanisms (like context switching
of green threads) in languages like go, rust. This can be problematic because
an attacker can use memory corruption bugs and eventually use such context
switching routines to pivot to any shadow stack. Shadow stack tokens can help
mitigate this problem by making sure that:

- When software is switching away from a shadow stack, shadow stack pointer
  should be saved on shadow stack itself and call it ``shadow stack token``

- When software is switching to a shadow stack, it should read the
  ``shadow stack token`` from shadow stack pointer and verify that
  ``shadow stack token`` itself is pointer to shadow stack itself.

- Once the token verification is done, software can perform the write to
  ``CSR_SSP`` to switch shadow stack.

Here software can be user mode task runtime itself which is managing various
contexts as part of single thread. Software can be kernel as well when kernel
has to deliver a signal to user task and must save shadow stack pointer. Kernel
can perform similar procedure by saving a token on user shadow stack itself.
This way whenever :c:macro:`sigreturn` happens, kernel can read the token and
verify the token and then switch to shadow stack. Using this mechanism, kernel
helps user task so that any corruption issue in user task is not exploited by
adversary by arbitrarily using :c:macro:`sigreturn`. Adversary will have to
make sure that there is a ``shadow stack token`` in addition to invoking
:c:macro:`sigreturn`

7. Signal shadow stack
-----------------------
Following structure has been added to sigcontext for RISC-V::

    struct __sc_riscv_cfi_state {
        unsigned long ss_ptr;
    };

As part of signal delivery, shadow stack token is saved on current shadow stack
itself and updated pointer is saved away in :c:macro:`ss_ptr` field in
:c:macro:`__sc_riscv_cfi_state` under :c:macro:`sigcontext`. Existing shadow
stack allocation is used for signal delivery. During :c:macro:`sigreturn`,
kernel will obtain :c:macro:`ss_ptr` from :c:macro:`sigcontext` and verify the
saved token on shadow stack itself and switch shadow stack.
