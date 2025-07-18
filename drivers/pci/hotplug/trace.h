/* SPDX-License-Identifier: GPL-2.0 */
#if !defined(_TRACE_HW_EVENT_PCI_HP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HW_EVENT_PCI_HP_H

#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM pci

#define PCI_HOTPLUG_EVENT					\
	EM(PCI_HOTPLUG_LINK_UP,			"Link Up")	\
	EM(PCI_HOTPLUG_LINK_DOWN,		"Link Down")	\
	EM(PCI_HOTPLUG_CARD_PRESENT,		"Card present")	\
	EMe(PCI_HOTPLUG_CARD_NOT_PRESENT,	"Card not present")

/* Enums require being exported to userspace, for user tool parsing */
#undef EM
#undef EMe
#define EM(a, b)	TRACE_DEFINE_ENUM(a);
#define EMe(a, b)	TRACE_DEFINE_ENUM(a);

PCI_HOTPLUG_EVENT

/*
 * Now redefine the EM() and EMe() macros to map the enums to the strings
 * that will be printed in the output.
 */
#undef EM
#undef EMe
#define EM(a, b)	{a, b},
#define EMe(a, b)	{a, b}

TRACE_EVENT(pci_hp_event,

	TP_PROTO(const char *port_name,
		 const char *slot,
		 const int event),

	TP_ARGS(port_name, slot, event),

	TP_STRUCT__entry(
		__string(	port_name,	port_name	)
		__string(	slot,		slot		)
		__field(	int,		event	)
	),

	TP_fast_assign(
		__assign_str(port_name);
		__assign_str(slot);
		__entry->event = event;
	),

	TP_printk("%s slot:%s, event:%s\n",
		__get_str(port_name),
		__get_str(slot),
		__print_symbolic(__entry->event, PCI_HOTPLUG_EVENT)
	)
);

#endif /* _TRACE_HW_EVENT_PCI_HP_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
