// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stack tracing support
 *
 * Copyright (C) 2012 ARM Ltd.
 */
#include <linux/kernel.h>
#include <linux/efi.h>
#include <linux/export.h>
#include <linux/ftrace.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/stacktrace.h>

#include <asm/efi.h>
#include <asm/irq.h>
#include <asm/stack_pointer.h>
#include <asm/stacktrace.h>

#include <asm/orc_types.h>
#include <asm/orc_lookup.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <asm/ptrace.h>

#define orc_warn(fmt, ...) \
	printk_deferred_once(KERN_WARNING "WARNING: " fmt, ##__VA_ARGS__)

#define orc_warn_current(args...)					\
({									\
	if (state->task == current && !state->error)			\
		orc_warn(args);						\
})

extern int __start_orc_unwind_ip[];
extern int __stop_orc_unwind_ip[];
extern struct orc_entry __start_orc_unwind[];
extern struct orc_entry __stop_orc_unwind[];

static bool orc_init __ro_after_init;
static unsigned int lookup_num_blocks __ro_after_init;

static struct orc_entry orc_fp_entry = {
	.type		= ORC_TYPE_CALL,
	.sp_reg		= ORC_REG_BP,
	.sp_offset	= 16,
	.bp_reg		= ORC_REG_PREV_SP,
	.bp_offset	= -16,
};

/*
 * Start an unwind from a pt_regs.
 *
 * The unwind will begin at the PC within the regs.
 *
 * The regs must be on a stack currently owned by the calling task.
 */
static __always_inline void
unwind_init_from_regs(struct unwind_state *state,
		      struct pt_regs *regs)
{
	unwind_init_common(state, current);

	state->fp = regs->regs[29];
	state->pc = regs->pc;
}

/*
 * Start an unwind from a caller.
 *
 * The unwind will begin at the caller of whichever function this is inlined
 * into.
 *
 * The function which invokes this must be noinline.
 */
static __always_inline void
unwind_init_from_caller(struct unwind_state *state)
{
	unwind_init_common(state, current);

	state->fp = (unsigned long)__builtin_frame_address(1);
	state->pc = (unsigned long)__builtin_return_address(0);
}

/*
 * Start an unwind from a blocked task.
 *
 * The unwind will begin at the blocked tasks saved PC (i.e. the caller of
 * cpu_switch_to()).
 *
 * The caller should ensure the task is blocked in cpu_switch_to() for the
 * duration of the unwind, or the unwind will be bogus. It is never valid to
 * call this for the current task.
 */
static __always_inline void
unwind_init_from_task(struct unwind_state *state,
		      struct task_struct *task)
{
	unwind_init_common(state, task);

	state->fp = thread_saved_fp(task);
	state->pc = thread_saved_pc(task);
}

static __always_inline int
unwind_recover_return_address(struct unwind_state *state)
{
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (state->task->ret_stack &&
	    (state->pc == (unsigned long)return_to_handler)) {
		unsigned long orig_pc;
		orig_pc = ftrace_graph_ret_addr(state->task, NULL, state->pc,
						(void *)state->fp);
		if (WARN_ON_ONCE(state->pc == orig_pc))
			return -EINVAL;
		state->pc = orig_pc;
	}
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

#ifdef CONFIG_KRETPROBES
	if (is_kretprobe_trampoline(state->pc)) {
		state->pc = kretprobe_find_ret_addr(state->task,
						    (void *)state->fp,
						    &state->kr_cur);
	}
#endif /* CONFIG_KRETPROBES */

	return 0;
}

/*
 * Unwind from one frame record (A) to the next frame record (B).
 *
 * We terminate early if the location of B indicates a malformed chain of frame
 * records (e.g. a cycle), determined based on the location and fp value of A
 * and the location (but not the fp value) of B.
 */
static __always_inline int
unwind_next(struct unwind_state *state)
{
	struct task_struct *tsk = state->task;
	unsigned long fp = state->fp;
	int err;

	/* Final frame; nothing to unwind */
	if (fp == (unsigned long)task_pt_regs(tsk)->stackframe)
		return -ENOENT;

	err = unwind_next_frame_record(state);
	if (err)
		return err;

	state->pc = ptrauth_strip_kernel_insn_pac(state->pc);

	return unwind_recover_return_address(state);
}

static bool get_reg(struct unwind_state *state, unsigned int reg_off,
		    unsigned long *val)
{
	unsigned int reg = reg_off/8;

	if (!state->regs)
		return false;

	if (state->full_regs) {
		*val = READ_ONCE_NOCHECK(((unsigned long *)state->regs)[reg]);
		return true;
	}

	if (state->prev_regs) {
		*val = READ_ONCE_NOCHECK(((unsigned long *)state->prev_regs)[reg]);
		return true;
	}

	return false;
}

bool noinstr in_task_stack(unsigned long *stack, struct task_struct *task,
			   struct stack_info *info)
{
	unsigned long *begin = task_stack_page(task);
	unsigned long *end   = task_stack_page(task) + THREAD_SIZE;

	if (stack < begin || stack >= end)
		return false;

	info->type	= STACK_TYPE_TASK;
	info->begin	= begin;
	info->end	= end;
	info->next_sp	= NULL;

	return true;
}

bool noinstr get_stack_info_noinstr(unsigned long *stack, struct task_struct *task,
				    struct stack_info *info)
{
	if (in_task_stack(stack, task, info))
		return true;

	if (task != current)
		return false;

       // if (in_irq_stack(stack, info))
       // 	return true;

	return false;
}

static int get_stack_info(unsigned long *stack, struct task_struct *task,
		   struct stack_info *info, unsigned long *visit_mask)
{
	task = task ? : current;

	if (!stack)
		goto unknown;

	if (!get_stack_info_noinstr(stack, task, info))
		goto unknown;

	/*
	 * Make sure we don't iterate through any given stack more than once.
	 * If it comes up a second time then there's something wrong going on:
	 * just break out and report an unknown stack type.
	 */
	if (visit_mask) {
		if (*visit_mask & (1UL << info->type)) {
			if (task == current)
				printk_deferred_once(KERN_WARNING "WARNING: stack recursion on stack type %d\n", info->type);
			goto unknown;
		}
		*visit_mask |= 1UL << info->type;
	}

	return 0;

unknown:
	info->type = STACK_TYPE_UNKNOWN;
	return -EINVAL;
}

static inline bool on_stack(struct stack_info *info, void *addr, size_t len)
{
	void *begin = info->begin;
	void *end   = info->end;

	return (info->type != STACK_TYPE_UNKNOWN &&
		addr >= begin && addr < end &&
		addr + len > begin && addr + len <= end);
}

static struct orc_entry null_orc_entry = {
	.sp_offset = sizeof(long),
	.sp_reg = ORC_REG_SP,
	.bp_reg = ORC_REG_UNDEFINED,
	.type = ORC_TYPE_CALL
};

static inline unsigned long orc_ip(const int *ip)
{
	return (unsigned long)ip + *ip;
}

static struct orc_entry *__orc_find(int *ip_table, struct orc_entry *u_table,
				    unsigned int num_entries, unsigned long ip)
{
	int *first = ip_table;
	int *last = ip_table + num_entries - 1;
	int *mid = first, *found = first;

	if (!num_entries)
		return NULL;

	/*
	 * Do a binary range search to find the rightmost duplicate of a given
	 * starting address.  Some entries are section terminators which are
	 * "weak" entries for ensuring there are no gaps.  They should be
	 * ignored when they conflict with a real entry.
	 */
	while (first <= last) {
		mid = first + ((last - first) / 2);

		if (orc_ip(mid) <= ip) {
			found = mid;
			first = mid + 1;
		} else
			last = mid - 1;
	}

	return u_table + (found - ip_table);
}

#ifdef CONFIG_MODULES
static struct orc_entry *orc_module_find(unsigned long ip)
{
	struct module *mod;

	mod = __module_address(ip);
	if (!mod || !mod->arch.orc_unwind || !mod->arch.orc_unwind_ip)
		return NULL;
	return __orc_find(mod->arch.orc_unwind_ip, mod->arch.orc_unwind,
			  mod->arch.num_orcs, ip);
}
#else
static struct orc_entry *orc_module_find(unsigned long ip)
{
	return NULL;
}
#endif

#ifdef CONFIG_DYNAMIC_FTRACE
static struct orc_entry *orc_find(unsigned long ip);

/*
 * Ftrace dynamic trampolines do not have orc entries of their own.
 * But they are copies of the ftrace entries that are static and
 * defined in ftrace_*.S, which do have orc entries.
 *
 * If the unwinder comes across a ftrace trampoline, then find the
 * ftrace function that was used to create it, and use that ftrace
 * function's orc entry, as the placement of the return code in
 * the stack will be identical.
 */
static struct orc_entry *orc_ftrace_find(unsigned long ip)
{
	return NULL;
}
#else
static struct orc_entry *orc_ftrace_find(unsigned long ip)
{
	return NULL;
}
#endif

#ifdef CONFIG_CALL_THUNKS
static struct orc_entry *orc_callthunk_find(unsigned long ip)
{
	if (!is_callthunk((void *)ip))
		return NULL;

	return &null_orc_entry;
}
#else
static struct orc_entry *orc_callthunk_find(unsigned long ip)
{
	return NULL;
}
#endif

static inline bool unwind_done(struct unwind_state *state)
{
	return state->stack.type == STACK_TYPE_UNKNOWN;
}

static struct orc_entry *orc_find(unsigned long ip)
{
	static struct orc_entry *orc;

	if (ip == 0)
		return &null_orc_entry;

	/* For non-init vmlinux addresses, use the fast lookup table: */
	if (ip >= LOOKUP_START_IP && ip < LOOKUP_STOP_IP) {
		unsigned int idx, start, stop;

		idx = (ip - LOOKUP_START_IP) / LOOKUP_BLOCK_SIZE;

		if (unlikely((idx >= lookup_num_blocks-1))) {
			orc_warn("WARNING: bad lookup idx: idx=%u num=%u ip=%pB\n",
				 idx, lookup_num_blocks, (void *)ip);
			return NULL;
		}

		start = orc_lookup[idx];
		stop = orc_lookup[idx + 1] + 1;

		if (unlikely((__start_orc_unwind + start >= __stop_orc_unwind) ||
			     (__start_orc_unwind + stop > __stop_orc_unwind))) {
			orc_warn("WARNING: bad lookup value: idx=%u num=%u start=%u stop=%u ip=%pB\n",
				 idx, lookup_num_blocks, start, stop, (void *)ip);
			return NULL;
		}

		return __orc_find(__start_orc_unwind_ip + start,
				  __start_orc_unwind + start, stop - start, ip);
	}

	/* vmlinux .init slow lookup: */
	if (is_kernel_inittext(ip))
		return __orc_find(__start_orc_unwind_ip, __start_orc_unwind,
				  __stop_orc_unwind_ip - __start_orc_unwind_ip, ip);

	/* Module lookup: */
	orc = orc_module_find(ip);
	if (orc)
		return orc;

	orc =  orc_ftrace_find(ip);
	if (orc)
		return orc;

	return orc_callthunk_find(ip);
}

static bool stack_access_ok(struct unwind_state *state, unsigned long _addr,
			    size_t len)
{
	struct stack_info *info = &state->stack;
	void *addr = (void *)_addr;

	if (on_stack(info, addr, len))
		return true;

	return !get_stack_info(addr, state->task, info, &state->stack_mask) &&
		on_stack(info, addr, len);
}

static bool deref_stack_reg(struct unwind_state *state, unsigned long addr,
			    unsigned long *val)
{
	if (!stack_access_ok(state, addr, sizeof(long)))
		return false;

	*val = READ_ONCE_NOCHECK(*(unsigned long *)addr);
	return true;
}

static inline
unsigned long unwind_recover_rethook(struct unwind_state *state,
				     unsigned long addr, unsigned long *addr_p)
{
#ifdef CONFIG_RETHOOK
	if (is_rethook_trampoline(addr))
		return rethook_find_ret_addr(state->task, (unsigned long)addr_p,
					     &state->kr_cur);
#endif
	return addr;
}

/* Recover the return address modified by rethook and ftrace_graph. */
static inline
unsigned long unwind_recover_ret_addr(struct unwind_state *state,
				     unsigned long addr, unsigned long *addr_p)
{
	unsigned long ret;

	ret = ftrace_graph_ret_addr(state->task, &state->graph_idx,
				    addr, addr_p);
	return unwind_recover_rethook(state, ret, addr_p);
}

static __always_inline bool
unwind_next_frame(struct unwind_state *state)
{
	unsigned long ip_p, sp, tmp, orig_ip = state->ip, prev_sp = state->sp;
	enum stack_type prev_type = state->stack.type;
	struct orc_entry *orc;
	bool indirect = false;

	if (unwind_done(state))
		return false;

	/* Don't let modules unload while we're reading their ORC data. */
	preempt_disable();

	/* End-of-stack check for user tasks: */
	if (state->regs && user_mode(state->regs))
		goto the_end;

	/*
	 * Find the orc_entry associated with the text address.
	 *
	 * For a call frame (as opposed to a signal frame), state->ip points to
	 * the instruction after the call.  That instruction's stack layout
	 * could be different from the call instruction's layout, for example
	 * if the call was to a noreturn function.  So get the ORC data for the
	 * call instruction itself.
	 */
	orc = orc_find(state->signal ? state->ip : state->ip - 1);
	if (!orc) {
		/*
		 * As a fallback, try to assume this code uses a frame pointer.
		 * This is useful for generated code, like BPF, which ORC
		 * doesn't know about.  This is just a guess, so the rest of
		 * the unwind is no longer considered reliable.
		 */
		orc = &orc_fp_entry;
		state->error = true;
	} else {
		if (orc->type == ORC_TYPE_UNDEFINED)
			goto err;

		if (orc->type == ORC_TYPE_END_OF_STACK)
			goto the_end;
	}

	state->signal = orc->signal;

	/* Find the previous frame's stack: */
	switch (orc->sp_reg) {
	case ORC_REG_SP:
		sp = state->sp + orc->sp_offset;
		break;

	case ORC_REG_BP:
		sp = state->bp + orc->sp_offset;
		break;

	default:
		orc_warn("unknown SP base reg %d at %pB\n",
			 orc->sp_reg, (void *)state->ip);
		goto err;
	}

	if (indirect) {
		if (!deref_stack_reg(state, sp, &sp))
			goto err;

		if (orc->sp_reg == ORC_REG_SP_INDIRECT)
			sp += orc->sp_offset;
	}

	/* Find IP, SP and possibly regs: */
	switch (orc->type) {
	case ORC_TYPE_CALL:
		ip_p = sp - sizeof(long);

		if (!deref_stack_reg(state, ip_p, &state->ip))
			goto err;

		state->ip = unwind_recover_ret_addr(state, state->ip,
						    (unsigned long *)ip_p);
		state->sp = sp;
		state->regs = NULL;
		state->prev_regs = NULL;
		break;

	default:
		orc_warn("unknown .orc_unwind entry type %d at %pB\n",
			 orc->type, (void *)orig_ip);
		goto err;
	}

	/* Find BP: */
	switch (orc->bp_reg) {
	case ORC_REG_UNDEFINED:
		if (get_reg(state, offsetof(struct pt_regs, bp), &tmp))
			state->bp = tmp;
		break;

	case ORC_REG_PREV_SP:
		if (!deref_stack_reg(state, sp + orc->bp_offset, &state->bp))
			goto err;
		break;

	case ORC_REG_BP:
		if (!deref_stack_reg(state, state->bp + orc->bp_offset, &state->bp))
			goto err;
		break;

	default:
		orc_warn("unknown BP base reg %d for ip %pB\n",
			 orc->bp_reg, (void *)orig_ip);
		goto err;
	}

	/* Prevent a recursive loop due to bad ORC data: */
	if (state->stack.type == prev_type &&
	    on_stack(&state->stack, (void *)state->sp, sizeof(long)) &&
	    state->sp <= prev_sp) {
		orc_warn_current("stack going in the wrong direction? at %pB\n",
				 (void *)orig_ip);
		goto err;
	}

	preempt_enable();
	return true;

err:
	state->error = true;

the_end:
	preempt_enable();
	state->stack.type = STACK_TYPE_UNKNOWN;
	return false;
}

void __init unwind_init(void)
{
	size_t orc_ip_size = (void *)__stop_orc_unwind_ip - (void *)__start_orc_unwind_ip;
	size_t orc_size = (void *)__stop_orc_unwind - (void *)__start_orc_unwind;
	size_t num_entries = orc_ip_size / sizeof(int);
	struct orc_entry *orc;
	int i;

	if (!num_entries || orc_ip_size % sizeof(int) != 0 ||
	    orc_size % sizeof(struct orc_entry) != 0 ||
	    num_entries != orc_size / sizeof(struct orc_entry)) {
		orc_warn("WARNING: Bad or missing .orc_unwind table.  Disabling unwinder.\n");
		return;
	}

	/*
	 * Note, the orc_unwind and orc_unwind_ip tables were already
	 * sorted at build time via the 'sorttable' tool.
	 * It's ready for binary search straight away, no need to sort it.
	 */

	/* Initialize the fast lookup table: */
	lookup_num_blocks = orc_lookup_end - orc_lookup;
	for (i = 0; i < lookup_num_blocks-1; i++) {
		orc = __orc_find(__start_orc_unwind_ip, __start_orc_unwind,
				 num_entries,
				 LOOKUP_START_IP + (LOOKUP_BLOCK_SIZE * i));
		if (!orc) {
			orc_warn("WARNING: Corrupt .orc_unwind table.  Disabling unwinder.\n");
			return;
		}

		orc_lookup[i] = orc - __start_orc_unwind;
	}

	/* Initialize the ending block: */
	orc = __orc_find(__start_orc_unwind_ip, __start_orc_unwind, num_entries,
			 LOOKUP_STOP_IP);
	if (!orc) {
		orc_warn("WARNING: Corrupt .orc_unwind table.  Disabling unwinder.\n");
		return;
	}
	orc_lookup[lookup_num_blocks-1] = orc - __start_orc_unwind;

	orc_init = true;
}

static __always_inline void
unwind(struct unwind_state *state, stack_trace_consume_fn consume_entry,
       void *cookie)
{
	if (unwind_recover_return_address(state))
		return;

	while (1) {
		int ret;

		if (!consume_entry(cookie, state->pc))
			break;
		ret = unwind_next(state);
		pr_info("fp:fp: %lx, pc: %lx\n", state->fp, state->pc);
		unwind_next_frame(state);
		pr_info("orc:fp: %lx, pc: %lx\n", state->fp, state->pc);
		pr_info("sp: %lx, bp: %lx\n", state->sp, state->bp);
		if (ret < 0)
			break;
	}
}

/*
 * Per-cpu stacks are only accessible when unwinding the current task in a
 * non-preemptible context.
 */
#define STACKINFO_CPU(name)					\
	({							\
		((task == current) && !preemptible())		\
			? stackinfo_get_##name()		\
			: stackinfo_get_unknown();		\
	})

/*
 * SDEI stacks are only accessible when unwinding the current task in an NMI
 * context.
 */
#define STACKINFO_SDEI(name)					\
	({							\
		((task == current) && in_nmi())			\
			? stackinfo_get_sdei_##name()		\
			: stackinfo_get_unknown();		\
	})

#define STACKINFO_EFI						\
	({							\
		((task == current) && current_in_efi())		\
			? stackinfo_get_efi()			\
			: stackinfo_get_unknown();		\
	})

noinline noinstr void arch_stack_walk(stack_trace_consume_fn consume_entry,
			      void *cookie, struct task_struct *task,
			      struct pt_regs *regs)
{
	struct stack_info stacks[] = {
		stackinfo_get_task(task),
		STACKINFO_CPU(irq),
#if defined(CONFIG_VMAP_STACK)
		STACKINFO_CPU(overflow),
#endif
#if defined(CONFIG_VMAP_STACK) && defined(CONFIG_ARM_SDE_INTERFACE)
		STACKINFO_SDEI(normal),
		STACKINFO_SDEI(critical),
#endif
#ifdef CONFIG_EFI
		STACKINFO_EFI,
#endif
	};
	struct unwind_state state = {
		.stacks = stacks,
		.nr_stacks = ARRAY_SIZE(stacks),
	};

	if (regs) {
		if (task != current)
			return;
		unwind_init_from_regs(&state, regs);
	} else if (task == current) {
		unwind_init_from_caller(&state);
	} else {
		unwind_init_from_task(&state, task);
	}

	unwind(&state, consume_entry, cookie);
}

static bool dump_backtrace_entry(void *arg, unsigned long where)
{
	char *loglvl = arg;
	printk("%s %pSb\n", loglvl, (void *)where);
	return true;
}

void dump_backtrace(struct pt_regs *regs, struct task_struct *tsk,
		    const char *loglvl)
{
	pr_debug("%s(regs = %p tsk = %p)\n", __func__, regs, tsk);

	if (regs && user_mode(regs))
		return;

	if (!tsk)
		tsk = current;

	if (!try_get_task_stack(tsk))
		return;

	printk("%sCall trace:\n", loglvl);
	arch_stack_walk(dump_backtrace_entry, (void *)loglvl, tsk, regs);

	put_task_stack(tsk);
}

void show_stack(struct task_struct *tsk, unsigned long *sp, const char *loglvl)
{
	dump_backtrace(NULL, tsk, loglvl);
	barrier();
}
