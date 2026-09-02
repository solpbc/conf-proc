/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/kmod.h>
#include <linux/stddef.h>

static struct host_kmod_call last_call;
static int forced_result;
static int force_result;
static int (*gate_fn)(struct linux_binprm *);

int call_usermodehelper(const char *path, char **argv, char **envp, int wait)
{
	struct linux_binprm bprm = { .filename = path };

	last_call.path = path;
	last_call.argv = argv;
	last_call.envp = envp;
	last_call.wait = wait;
	last_call.calls++;
	if (force_result)
		return forced_result;
	return gate_fn ? gate_fn(&bprm) : 0;
}

void host_kmod_reset(void)
{
	last_call.path = NULL;
	last_call.argv = NULL;
	last_call.envp = NULL;
	last_call.wait = 0;
	last_call.calls = 0;
	forced_result = 0;
	force_result = 0;
	gate_fn = NULL;
}

void host_kmod_set_result(int result, int forced)
{
	forced_result = result;
	force_result = forced;
}

void host_kmod_set_gate(int (*gate)(struct linux_binprm *))
{
	gate_fn = gate;
}

const struct host_kmod_call *host_kmod_last_call(void)
{
	return &last_call;
}
