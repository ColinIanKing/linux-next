/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CONTEXT_TRACKING_H
#define _LINUX_CONTEXT_TRACKING_H

#include <linux/sched.h>
#include <linux/vtime.h>
#include <linux/context_tracking_state.h>
#include <linux/instrumentation.h>

#include <asm/ptrace.h>


#ifdef CONFIG_CONTEXT_TRACKING_USER
extern void ct_cpu_track_user(int cpu);

/* Called with interrupts disabled.  */
extern void __ct_user_enter(enum ctx_state state);
extern void __ct_user_exit(enum ctx_state state);

extern void ct_user_enter(enum ctx_state state);
extern void ct_user_exit(enum ctx_state state);

extern void user_enter_callable(void);
extern void user_exit_callable(void);

static inline void user_enter(void)
{
	if (context_tracking_enabled())
		ct_user_enter(CONTEXT_USER);

}
static inline void user_exit(void)
{
	if (context_tracking_enabled())
		ct_user_exit(CONTEXT_USER);
}

/* Called with interrupts disabled.  */
static __always_inline void user_enter_irqoff(void)
{
	if (context_tracking_enabled())
		__ct_user_enter(CONTEXT_USER);

}
static __always_inline void user_exit_irqoff(void)
{
	if (context_tracking_enabled())
		__ct_user_exit(CONTEXT_USER);
}

static inline enum ctx_state exception_enter(void)
{
	enum ctx_state prev_ctx;

	if (IS_ENABLED(CONFIG_HAVE_CONTEXT_TRACKING_USER_OFFSTACK) ||
	    !context_tracking_enabled())
		return 0;

	prev_ctx = this_cpu_read(context_tracking.state);
	if (prev_ctx != CONTEXT_KERNEL)
		ct_user_exit(prev_ctx);

	return prev_ctx;
}

static inline void exception_exit(enum ctx_state prev_ctx)
{
	if (!IS_ENABLED(CONFIG_HAVE_CONTEXT_TRACKING_USER_OFFSTACK) &&
	    context_tracking_enabled()) {
		if (prev_ctx != CONTEXT_KERNEL)
			ct_user_enter(prev_ctx);
	}
}

static __always_inline bool context_tracking_guest_enter(void)
{
	if (context_tracking_enabled())
		__ct_user_enter(CONTEXT_GUEST);

	return context_tracking_enabled_this_cpu();
}

static __always_inline void context_tracking_guest_exit(void)
{
	if (context_tracking_enabled())
		__ct_user_exit(CONTEXT_GUEST);
}

/**
 * ct_state() - return the current context tracking state if known
 *
 * Returns the current cpu's context tracking state if context tracking
 * is enabled.  If context tracking is disabled, returns
 * CONTEXT_DISABLED.  This should be used primarily for debugging.
 */
static __always_inline enum ctx_state ct_state(void)
{
	return context_tracking_enabled() ?
		this_cpu_read(context_tracking.state) : CONTEXT_DISABLED;
}
#else
static inline void user_enter(void) { }
static inline void user_exit(void) { }
static inline void user_enter_irqoff(void) { }
static inline void user_exit_irqoff(void) { }
static inline enum ctx_state exception_enter(void) { return 0; }
static inline void exception_exit(enum ctx_state prev_ctx) { }
static inline enum ctx_state ct_state(void) { return CONTEXT_DISABLED; }
static __always_inline bool context_tracking_guest_enter(void) { return false; }
static inline void context_tracking_guest_exit(void) { }

#endif /* !CONFIG_CONTEXT_TRACKING_USER */

#define CT_WARN_ON(cond) WARN_ON(context_tracking_enabled() && (cond))

#ifdef CONFIG_CONTEXT_TRACKING_USER_FORCE
extern void context_tracking_init(void);
#else
static inline void context_tracking_init(void) { }
#endif /* CONFIG_CONTEXT_TRACKING_USER_FORCE */

#ifdef CONFIG_CONTEXT_TRACKING_IDLE
extern void ct_idle_enter(void);
extern void ct_idle_exit(void);

/*
 * Is the current CPU in an extended quiescent state?
 *
 * No ordering, as we are sampling CPU-local information.
 */
static __always_inline bool rcu_dynticks_curr_cpu_in_eqs(void)
{
	return !(arch_atomic_read(this_cpu_ptr(&context_tracking.dynticks)) & 0x1);
}

/*
 * Increment the current CPU's context_tracking structure's ->dynticks field
 * with ordering.  Return the new value.
 */
static __always_inline unsigned long rcu_dynticks_inc(int incby)
{
	return arch_atomic_add_return(incby, this_cpu_ptr(&context_tracking.dynticks));
}

#else
static inline void ct_idle_enter(void) { }
static inline void ct_idle_exit(void) { }
#endif /* !CONFIG_CONTEXT_TRACKING_IDLE */

#endif
