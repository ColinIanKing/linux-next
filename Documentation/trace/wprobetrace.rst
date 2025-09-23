.. SPDX-License-Identifier: GPL-2.0

=======================================
Watchpoint probe (wprobe) Event Tracing
=======================================

.. Author: Masami Hiramatsu <mhiramat@kernel.org>

Overview
--------

Wprobe event is a dynamic event based on the hardware breakpoint, which is
similar to other probe events, but it is for watching data access. It allows
you to trace which code accesses a specified data.

As same as other dynamic events, wprobe events are defined via
`dynamic_events` interface file on tracefs.

Synopsis of wprobe-events
-------------------------
::

  w:[GRP/][EVENT] SPEC [FETCHARGS]                       : Probe on data access

 GRP            : Group name for wprobe. If omitted, use "wprobes" for it.
 EVENT          : Event name for wprobe. If omitted, an event name is
                  generated based on the address or symbol.
 SPEC           : Breakpoint specification.
                  [r|w|rw]@<ADDRESS|SYMBOL[+|-OFFS]>[:LENGTH]

   r|w|rw       : Access type, r for read, w for write, and rw for both.
                  Default is rw if omitted.
   ADDRESS      : Address to trace (hexadecimal).
   SYMBOL       : Symbol name to trace.
   LENGTH       : Length of the data to trace in bytes. (1, 2, 4, or 8)

 FETCHARGS      : Arguments. Each probe can have up to 128 args.
  $addr         : Fetch the accessing address.
  @ADDR         : Fetch memory at ADDR (ADDR should be in kernel)
  @SYM[+|-offs] : Fetch memory at SYM +|- offs (SYM should be a data symbol)
  +|-[u]OFFS(FETCHARG) : Fetch memory at FETCHARG +|- OFFS address.(\*1)(\*2)
  \IMM          : Store an immediate value to the argument.
  NAME=FETCHARG : Set NAME as the argument name of FETCHARG.
  FETCHARG:TYPE : Set TYPE as the type of FETCHARG. Currently, basic types
                  (u8/u16/u32/u64/s8/s16/s32/s64), hexadecimal types
                  (x8/x16/x32/x64), "char", "string", "ustring", "symbol", "symstr"
                  and bitfield are supported.

  (\*1) this is useful for fetching a field of data structures.
  (\*2) "u" means user-space dereference.

For the details of TYPE, see :ref:`kprobetrace documentation <kprobetrace_types>`.

Usage examples
--------------
Here is an example to add a wprobe event on a variable `jiffies`.
::

  # echo 'w:my_jiffies w@jiffies' >> dynamic_events
  # cat dynamic_events
  w:wprobes/my_jiffies w@jiffies
  # echo 1 > events/wprobes/enable
  # cat trace | head
  #           TASK-PID     CPU#  |||||  TIMESTAMP  FUNCTION
  #              | |         |   |||||     |         |
           <idle>-0       [000] d.Z1.  717.026259: my_jiffies: (tick_do_update_jiffies64+0xbe/0x130)
           <idle>-0       [000] d.Z1.  717.026373: my_jiffies: (tick_do_update_jiffies64+0xbe/0x130)

You can see the code which writes to `jiffies` is `tick_do_update_jiffies64()`.
