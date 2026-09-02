/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SPP_DIAG_TRACE_CORE_SHIM_LINUX_SCHED_H
#define SPP_DIAG_TRACE_CORE_SHIM_LINUX_SCHED_H

struct task_struct {
	int pid;
	int tgid;
};

extern struct task_struct host_current_task;
#define current (&host_current_task)

static inline int task_pid_nr(const struct task_struct *task)
{
	return task->pid;
}

static inline int task_tgid_nr(const struct task_struct *task)
{
	return task->tgid;
}

#endif
