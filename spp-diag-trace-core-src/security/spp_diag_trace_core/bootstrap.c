/* SPDX-License-Identifier: GPL-2.0-only */

#include <crypto/sha2.h>
#include <linux/init.h>
#include <linux/panic.h>
#include <linux/string.h>

#include <linux/spp_diag_trace_bootstrap.h>

#include "core.h"

static int hex_value(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	return -1;
}

static int decode_identity(const char *value, size_t value_len, u8 out[32])
{
	size_t i;

	if (value_len != 64)
		return -1;
	for (i = 0; i < 32; i++) {
		int high = hex_value(value[i * 2]);
		int low = hex_value(value[i * 2 + 1]);

		if (high < 0 || low < 0)
			return -1;
		out[i] = (u8)((high << 4) | low);
	}
	return 0;
}

static int whitespace(char value)
{
	return value == ' ' || value == '\t' || value == '\n' || value == '\r';
}

static int set_identity(const char *token, size_t token_len, const char *name,
			int *seen, u8 out[32])
{
	size_t name_len = strlen(name);

	if (token_len < name_len || memcmp(token, name, name_len) != 0)
		return 0;
	if (*seen || decode_identity(token + name_len, token_len - name_len, out))
		return -1;
	*seen = 1;
	return 1;
}

static int parse_command_line(const char *command_line, size_t command_line_len,
			      u8 challenge[32], u8 run[32],
			      u8 control_plan[32])
{
	static const char ima_policy[] = "ima_policy=critical_data";
	size_t start = 0;
	int after_double_dash = 0;
	int challenge_seen = 0, run_seen = 0, control_plan_seen = 0;
	int ima_policy_seen = 0;

	while (start < command_line_len) {
		size_t end;
		int result = 0;

		while (start < command_line_len && whitespace(command_line[start]))
			start++;
		end = start;
		while (end < command_line_len && !whitespace(command_line[end]))
			end++;
		if (start == end)
			break;
		if (!after_double_dash && end - start == 2 &&
		    command_line[start] == '-' && command_line[start + 1] == '-') {
			after_double_dash = 1;
			start = end;
			continue;
		}
		if (!after_double_dash) {
			result = set_identity(command_line + start, end - start,
					      "sol_spp_diag.challenge=",
					      &challenge_seen, challenge);
			if (!result)
				result = set_identity(command_line + start,
						      end - start,
						      "sol_spp_diag.run=", &run_seen,
						      run);
			if (!result)
				result = set_identity(command_line + start,
						      end - start,
						      "sol_spp_diag.control_plan=",
						      &control_plan_seen, control_plan);
			if (result < 0)
				return -1;
			if (!result && end - start == sizeof(ima_policy) - 1 &&
			    !memcmp(command_line + start, ima_policy,
				    sizeof(ima_policy) - 1)) {
				if (ima_policy_seen)
					return -1;
				ima_policy_seen = 1;
				result = 1;
			}
			if (!result &&
			    ((end - start >= 13 &&
			      !memcmp(command_line + start, "sol_spp_diag.", 13)) ||
			     (end - start >= 11 &&
			      !memcmp(command_line + start, "ima_policy=", 11))))
				return -1;
		}
		start = end;
	}
	return challenge_seen && run_seen && control_plan_seen && ima_policy_seen
		       ? 0
		       : -1;
}

void __init spp_diag_trace_bootstrap_init(void)
{
	u8 challenge[32], run[32], control_plan[32], command_line[32];

	if (!saved_command_line ||
	    parse_command_line(saved_command_line, saved_command_line_len,
			       challenge, run, control_plan)) {
		panic("spp diag trace bootstrap command line");
		return;
	}
	sha256((const u8 *)saved_command_line, saved_command_line_len, command_line);
	if (spp_diag_trace_core_init(challenge, run, control_plan, command_line)) {
		panic("spp diag trace bootstrap core init");
		return;
	}
}

#if IS_ENABLED(CONFIG_KUNIT)
int spp_diag_trace_bootstrap_test_parse(const char *command_line,
					size_t command_line_len,
					u8 challenge[32], u8 run[32],
					u8 control_plan[32])
{
	return parse_command_line(command_line, command_line_len, challenge, run,
				  control_plan);
}
#endif
