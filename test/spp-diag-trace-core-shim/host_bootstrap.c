/* SPDX-License-Identifier: GPL-2.0-only */

#include <setjmp.h>
#include <stdlib.h>
#include <string.h>

#include <linux/init.h>
#include <linux/panic.h>
#include <linux/sched.h>

char *saved_command_line;
unsigned int saved_command_line_len;
struct task_struct host_current_task;

static jmp_buf *panic_target;
static const char *panic_text;

void host_saved_command_line_set(const char *value)
{
	saved_command_line = (char *)value;
	saved_command_line_len = value ? (unsigned int)strlen(value) : 0;
}

void host_panic_arm(jmp_buf *target)
{
	panic_target = target;
	panic_text = NULL;
}

void host_panic_disarm(void)
{
	panic_target = NULL;
}

const char *host_panic_message(void)
{
	return panic_text;
}

void host_panic(const char *message)
{
	panic_text = message;
	if (panic_target)
		longjmp(*panic_target, 1);
	abort();
}
