#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 sol pbc
"""Compiles and exercises the real /spp-diag-handoff binary via its scripted test harness.

This compiles the production source with its test-only ops table enabled. A second
compile proves that harness code is absent from the production binary.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(ROOT, "spp-diag-runtime-src", "spp_diag_handoff.c")
FIXED_ARGV = [
    "/usr/bin/python3.10",
    "-I",
    "-B",
    "-S",
    "/usr/lib/spp/spp-diag-controller",
    "sol_spp_diag.target_profile=spp-r1-production",
    "sol_spp_diag.binding_partuuid=33333333-3333-4333-8333-333333333333",
]
FIXED_ENVP = [
    "LANG=C",
    "LC_ALL=C",
    "TZ=UTC",
]
DATA_PARTUUID = "11111111-1111-4111-8111-111111111111"
HASH_PARTUUID = "22222222-2222-4222-8222-222222222222"
BINDING_PARTUUID = "33333333-3333-4333-8333-333333333333"
ROOT_HASH = "1fc5677fe596f6472ef82f8bf872505788b6759b5c282de504079990efb5a6c4"
CHALLENGE = "cd" * 32
RUN_IDENTITY = "de" * 32
CONTROL_PLAN = "ef" * 32
VERITY_SALT = "01" * 32
DATA_BLOCKS = 262144
HASH_DEVICE_BYTES = 8462336
VERITY_HEADER_HEX = (
    "7665726974790000010000000100000011111111111151118111111111111111"
    "7368613235360000000000000000000000000000000000000000000000000000"
    "001000000010000000000400000000002000000000000000"
    "0101010101010101010101010101010101010101010101010101010101010101"
    + "00" * (512 - 120)
)
CMDLINE_OK = (
    "ro rdinit=/spp-diag-handoff init=/usr/lib/spp/spp-diag-controller "
    "root=/dev/mapper/spp-diag-root rootfstype=squashfs ip=off ima_policy=critical_data "
    f"spp_diag.root_data=PARTUUID={DATA_PARTUUID} spp_diag.root_hash=PARTUUID={HASH_PARTUUID} "
    f"spp_diag.roothash={ROOT_HASH} sol_spp_diag.challenge={CHALLENGE} "
    f"sol_spp_diag.run={RUN_IDENTITY} sol_spp_diag.control_plan={CONTROL_PLAN} -- "
    f"sol_spp_diag.target_profile=spp-r1-production sol_spp_diag.binding_partuuid={BINDING_PARTUUID}"
)


def compile_fixture(build_dir: str) -> str:
    fixture = os.path.join(build_dir, "spp-diag-handoff-fixture")
    result = subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-DSPP_DIAG_HANDOFF_TEST=1", "-o", fixture, SOURCE],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(f"compile failed:\n{result.stdout}\n{result.stderr}")
    if result.stdout.strip() or result.stderr.strip():
        raise SystemExit(f"compile produced unexpected output (warnings?):\n{result.stdout}\n{result.stderr}")
    return fixture


def compile_production(build_dir: str) -> str:
    binary = os.path.join(build_dir, "spp-diag-handoff-production")
    result = subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-o", binary, SOURCE],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or result.stdout.strip() or result.stderr.strip():
        raise SystemExit(f"production compile failed or warned:\n{result.stdout}\n{result.stderr}")
    with open(binary, "rb") as handle:
        production_bytes = handle.read()
    assert b"SPP_DIAG_HANDOFF_TEST_HARNESS" not in production_bytes
    assert b"SPP_DIAG_HANDOFF_TEST_LOG" not in production_bytes
    return binary


def run_production_ops_oracle(build_dir: str) -> None:
    """Execute the production resolver/DM/fd functions with libc calls link-wrapped.

    Unlike the orchestration harness, this compiles and invokes the real production
    implementations. The independent wrapper checks exact sysfs interpretation,
    retained block-fd identity, ioctl buffer packing, mapped-node creation/removal,
    and close-on-exec manipulation without requiring host root privileges.
    """

    wrapper_source = os.path.join(build_dir, "production-ops-oracle.c")
    wrapper_binary = os.path.join(build_dir, "production-ops-oracle")
    source_literal = SOURCE.replace("\\", "\\\\").replace('"', '\\"')
    code = textwrap.dedent(
        f"""
        #define main spp_diag_embedded_main
        #include "{source_literal}"
        #undef main
        #include <stdarg.h>

        static int oracle_failed = 0;
        static int unlink_calls = 0;
        static int remove_should_fail = 0;
        static const char *expected_table =
            "1 8:2 8:3 4096 4096 262144 1 sha256 {ROOT_HASH} {VERITY_SALT}";

        static void require_true(int condition) {{
            if (!condition) oracle_failed = 1;
        }}

        int __wrap_glob(const char *pattern, int flags, int (*errfunc)(const char *, int), glob_t *out) {{
            static char path[] = "/sys/class/block/sda2/uevent";
            static char *paths[] = {{path, NULL}};
            (void)flags; (void)errfunc;
            require_true(strcmp(pattern, "/sys/class/block/*/uevent") == 0);
            memset(out, 0, sizeof(*out));
            out->gl_pathc = 1;
            out->gl_pathv = paths;
            return 0;
        }}

        void __wrap_globfree(glob_t *paths) {{ (void)paths; }}

        int __wrap_open(const char *path, int flags, ...) {{
            if (strcmp(path, "/sys/class/block/sda2/uevent") == 0) {{
                require_true(flags == (O_RDONLY | O_CLOEXEC));
                return 100;
            }}
            if (strcmp(path, "/dev/sda2") == 0) {{
                require_true(flags == (O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
                return 102;
            }}
            oracle_failed = 1;
            return -1;
        }}

        ssize_t __wrap_read(int fd, void *buf, size_t count) {{
            static const char uevent[] =
                "MAJOR=8\\nMINOR=2\\nDEVNAME=sda2\\nDEVTYPE=partition\\nPARTN=2\\n"
                "PARTUUID={DATA_PARTUUID}\\n";
            require_true(fd == 100 && count >= sizeof(uevent) - 1);
            memcpy(buf, uevent, sizeof(uevent) - 1);
            return (ssize_t)(sizeof(uevent) - 1);
        }}

        int __wrap_close(int fd) {{ require_true(fd == 100 || fd == 102); return 0; }}

        int __wrap_fstat(int fd, struct stat *st) {{
            require_true(fd == 102);
            memset(st, 0, sizeof(*st));
            st->st_mode = S_IFBLK | 0600;
            st->st_rdev = makedev(8, 2);
            return 0;
        }}

        int __wrap_mknod(const char *path, mode_t mode, dev_t dev) {{
            require_true(strcmp(path, SPP_DIAG_DM_NODE) == 0);
            require_true(mode == (S_IFBLK | 0600));
            require_true(major(dev) == 253 && minor(dev) == 0);
            return 0;
        }}

        int __wrap_unlink(const char *path) {{
            require_true(strcmp(path, SPP_DIAG_DM_NODE) == 0);
            unlink_calls++;
            return 0;
        }}

        int __wrap_ioctl(int fd, unsigned long request, ...) {{
            va_list args;
            va_start(args, request);
            void *arg = va_arg(args, void *);
            va_end(args);
            require_true(fd == 77);
            struct dm_ioctl *io = (struct dm_ioctl *)arg;
            require_true(io->version[0] == DM_VERSION_MAJOR && io->version[1] == DM_VERSION_MINOR);
            require_true(strcmp(io->name, SPP_DIAG_DM_NAME) == 0);
            if (request == DM_DEV_CREATE) {{
                io->dev = (uint64_t)makedev(253, 0);
                return 0;
            }}
            if (request == DM_TABLE_LOAD) {{
                struct dm_target_spec *spec = (struct dm_target_spec *)((unsigned char *)arg + io->data_start);
                const char *params = (const char *)spec + sizeof(*spec);
                require_true(io->target_count == 1 && spec->sector_start == 0);
                require_true(spec->length == (uint64_t)262144 * 8 && strcmp(spec->target_type, "verity") == 0);
                require_true(strcmp(params, expected_table) == 0);
                return 0;
            }}
            if (request == DM_DEV_SUSPEND) {{
                require_true(io->flags == 0);
                return 0;
            }}
            if (request == DM_DEV_REMOVE) {{
                if (remove_should_fail) {{ errno = EBUSY; return -1; }}
                return 0;
            }}
            oracle_failed = 1;
            return -1;
        }}

        int __wrap_fcntl(int fd, int command, ...) {{
            require_true(fd == 5);
            if (command == F_GETFD) return FD_CLOEXEC;
            if (command == F_SETFD) {{
                va_list args;
                va_start(args, command);
                int flags = va_arg(args, int);
                va_end(args);
                require_true(flags == 0);
                return 0;
            }}
            oracle_failed = 1;
            return -1;
        }}

        int __wrap_close_range(unsigned int first, unsigned int last, int flags) {{
            require_true(first == 6 && last == UINT_MAX && flags == 0);
            return 0;
        }}

        int main(void) {{
            char device_id[64];
            dev_t rdev = 0;
            int retained_fd = -1;
            require_true(real_resolve_partuuid(NULL, "{DATA_PARTUUID}", device_id, sizeof(device_id), &rdev, &retained_fd) == 0);
            require_true(strcmp(device_id, "8:2") == 0 && rdev == makedev(8, 2) && retained_fd == 102);
            require_true(real_dm_dev_create(NULL, 77, SPP_DIAG_DM_NAME) == 0);
            require_true(real_dm_table_load(NULL, 77, SPP_DIAG_DM_NAME, (uint64_t)262144 * 8, expected_table) == 0);
            require_true(real_dm_dev_suspend(NULL, 77, SPP_DIAG_DM_NAME) == 0);
            remove_should_fail = 1;
            require_true(real_dm_dev_remove(NULL, 77, SPP_DIAG_DM_NAME) != 0 && unlink_calls == 0);
            remove_should_fail = 0;
            require_true(real_dm_dev_remove(NULL, 77, SPP_DIAG_DM_NAME) == 0 && unlink_calls == 1);
            require_true(real_set_inheritable(NULL, 5) == 0);
            require_true(real_close_range(NULL, 6, UINT_MAX) == 0);
            return oracle_failed ? 1 : 0;
        }}
        """
    )
    with open(wrapper_source, "w", encoding="utf-8") as handle:
        handle.write(code)
    wrapped = ("glob", "globfree", "open", "read", "close", "fstat", "mknod", "unlink", "ioctl", "fcntl", "close_range")
    command = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-o", wrapper_binary, wrapper_source]
    command.extend(f"-Wl,--wrap={name}" for name in wrapped)
    compiled = subprocess.run(command, capture_output=True, text=True)
    if compiled.returncode != 0 or compiled.stdout.strip() or compiled.stderr.strip():
        raise SystemExit(f"production ops oracle compile failed or warned:\n{compiled.stdout}\n{compiled.stderr}")
    ran = subprocess.run([wrapper_binary], capture_output=True, text=True)
    if ran.returncode != 0 or ran.stdout.strip() or ran.stderr.strip():
        raise SystemExit(f"production ops oracle failed:\n{ran.stdout}\n{ran.stderr}")


def script_line(op: str, **fields: object) -> str:
    parts = [op] + [f"{key}={value}" for key, value in fields.items()]
    return "\t".join(parts)


def force_result(line: str, result: int) -> str:
    fields = line.split("\t")
    return "\t".join(
        f"result={result}" if field.startswith("result=") else field
        for field in fields
    )


def stdio_script() -> list[str]:
    return [
        script_line("open", result=0),
        script_line("dup2", result=0),
        script_line("set_inheritable", result=0),
        script_line("dup2", result=1),
        script_line("set_inheritable", result=0),
        script_line("dup2", result=2),
        script_line("set_inheritable", result=0),
    ]


def happy_path_script(
    cmdline: str = CMDLINE_OK,
    root_verity_ok: bool = True,
    mount_writable: bool = False,
    root_mount_ok: bool = True,
    direct_runtime_fds: bool = False,
) -> list[str]:
    lines = [
        script_line("mount", result=0),
        script_line("mount", result=0),
        script_line("mount", result=0),
        *stdio_script(),
        script_line("open", result=0, data=cmdline),
        script_line("resolve_partuuid", result=0, device_id="8:2", rdev=2050, fd=1100),
        script_line("resolve_partuuid", result=0, device_id="8:3", rdev=2051, fd=1101),
        script_line("blkgetsize64", result=0, size=1073741824),
        script_line("blkgetsize64", result=0, size=HASH_DEVICE_BYTES),
        script_line("pread", result=0, bytes_hex=VERITY_HEADER_HEX),
        script_line("open", result=0),
        script_line("dm_dev_create", result=0),
        script_line("dm_table_load", result=0 if root_verity_ok else -1),
    ]
    if not root_verity_ok:
        lines.append(script_line("dm_dev_remove", result=0))
        return lines
    lines += [
        script_line("dm_dev_suspend", result=0),
        script_line("mount", result=0 if root_mount_ok else -1),
    ]
    if not root_mount_ok:
        lines.append(script_line("dm_dev_remove", result=0))
        return lines
    lines += [
        script_line("statvfs_rdonly", result=0 if mount_writable else 1),
    ]
    if mount_writable:
        lines += [script_line("umount2", result=0), script_line("dm_dev_remove", result=0)]
        return lines
    lines += [
        script_line("mount", result=0),
        script_line("mount", result=0),
        script_line("mount", result=0),
        script_line("chdir", result=0),
        script_line("mount", result=0),
        script_line("chroot", result=0),
        script_line("chdir", result=0),
        script_line("mount", result=0),
    ]
    for fd in (3, 4, 5):
        lines.append(script_line("open", result=0, **({"exact_fd": fd} if direct_runtime_fds else {})))
        if not direct_runtime_fds:
            lines.append(script_line("dup2", result=fd))
        lines.append(script_line("set_inheritable", result=0))
    lines += [script_line("close_range", result=0), script_line("execve", result=0)]
    return lines


def run_fixture(fixture: str, script_lines: list[str], work_dir: str) -> tuple[int, list[str]]:
    script_path = os.path.join(work_dir, "script.tsv")
    log_path = os.path.join(work_dir, "log.tsv")
    with open(script_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(script_lines) + "\n")
    env = {
        "SPP_DIAG_HANDOFF_TEST_HARNESS": script_path,
        "SPP_DIAG_HANDOFF_TEST_LOG": log_path,
        "PATH": "/usr/bin:/bin",
    }
    result = subprocess.run([fixture], env=env, capture_output=True, text=True, timeout=10)
    log_lines: list[str] = []
    if os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8") as handle:
            log_lines = [line.rstrip("\n") for line in handle if line.strip()]
    return result.returncode, log_lines


def log_ops(log_lines: list[str]) -> list[str]:
    return [line.split("\t", 1)[0] for line in log_lines]


def find_log_entry(log_lines: list[str], op: str, occurrence: int = 0) -> str:
    matches = [line for line in log_lines if line.split("\t", 1)[0] == op]
    return matches[occurrence]


def main() -> int:
    with tempfile.TemporaryDirectory() as build_dir:
        compile_production(build_dir)
        print("ok   production_binary_excludes_test_harness")
        run_production_ops_oracle(build_dir)
        print("ok   production_sysfs_dm_and_fd_ops_oracle")
        fixture = compile_fixture(build_dir)
        tests = 2

        with tempfile.TemporaryDirectory() as work_dir:
            rc, log = run_fixture(fixture, happy_path_script(), work_dir)
            assert rc == 0, f"happy path exit {rc}, log={log}"
            assert log_ops(log)[-1] == "execve", log
            execve_entry = find_log_entry(log, "execve")
            assert f"path=/usr/bin/python3.10" in execve_entry, execve_entry
            assert f"argv={','.join(FIXED_ARGV)}" in execve_entry, execve_entry
            assert f"envp={','.join(FIXED_ENVP)}" in execve_entry, execve_entry
            dup2_entries = [line for line in log if line.startswith("dup2\t")]
            assert len(dup2_entries) == 6, dup2_entries
            assert [f"newfd={fd}" in entry for fd, entry in enumerate(dup2_entries[:3])] == [True, True, True]
            assert "newfd=3" in dup2_entries[3] and "result=3" in dup2_entries[3], dup2_entries[3]
            assert "newfd=4" in dup2_entries[4] and "result=4" in dup2_entries[4], dup2_entries[4]
            assert "newfd=5" in dup2_entries[5] and "result=5" in dup2_entries[5], dup2_entries[5]
            inherited_entries = [line for line in log if line.startswith("set_inheritable\t")]
            assert [entry.split("fd=", 1)[1].split("\t", 1)[0] for entry in inherited_entries] == [
                "0", "1", "2", "3", "4", "5"
            ]
            serial_open = [line for line in log if "/dev/ttyS0" in line][0]
            serial_flags = os.O_WRONLY | os.O_NOCTTY | os.O_CLOEXEC | os.O_NONBLOCK
            assert f"flags={serial_flags}" in serial_open, serial_open
            table_load_entry = find_log_entry(log, "dm_table_load")
            expected_table = f"1 8:2 8:3 4096 4096 {DATA_BLOCKS} 1 sha256 {ROOT_HASH} {VERITY_SALT}"
            assert f"length_sectors={DATA_BLOCKS * 8}\tparams={expected_table}\tresult=0" in table_load_entry, table_load_entry
            root_mount_entry = find_log_entry(log, "mount", 3)
            assert "fstype=squashfs" in root_mount_entry, root_mount_entry
            proc_move = find_log_entry(log, "mount", 4)
            sys_move = find_log_entry(log, "mount", 5)
            dev_move = find_log_entry(log, "mount", 6)
            assert "source=/proc" in proc_move and "target=/mnt/spp-diag-root/proc" in proc_move
            assert "source=/sys" in sys_move and "target=/mnt/spp-diag-root/sys" in sys_move
            assert "source=/dev" in dev_move and "target=/mnt/spp-diag-root/dev" in dev_move
            move_mount_entry = find_log_entry(log, "mount", 7)
            assert "target=/" in move_mount_entry, move_mount_entry
            close_range_entry = find_log_entry(log, "close_range")
            assert "first=6" in close_range_entry and f"last={2**32 - 1}" in close_range_entry
            print("ok   happy_path_full_sequence")
            tests += 1

        with tempfile.TemporaryDirectory() as work_dir:
            script = happy_path_script()
            first_resolve = next(i for i, line in enumerate(script) if line.startswith("resolve_partuuid\t"))
            script[first_resolve] = script_line("resolve_partuuid", result=-1)
            rc, log = run_fixture(fixture, script, work_dir)
            assert rc == 13, f"expected ERR_PARTUUID_MISSING(13), got {rc}"
            assert "execve" not in log_ops(log), log
            assert log_ops(log).count("resolve_partuuid") == 1, log
            print("ok   missing_partuuid_rejects_before_verity")
            tests += 1

        with tempfile.TemporaryDirectory() as work_dir:
            script = happy_path_script()
            first_resolve = next(i for i, line in enumerate(script) if line.startswith("resolve_partuuid\t"))
            script[first_resolve] = script_line("resolve_partuuid", result=0, device_id="8:2", rdev=2050, fd=1100)
            script[first_resolve + 1] = script_line("resolve_partuuid", result=0, device_id="8:18", rdev=2050, fd=1101)
            rc, log = run_fixture(fixture, script, work_dir)
            assert rc == 14, f"expected ERR_PARTUUID_DUPLICATE(14), got {rc}"
            assert "execve" not in log_ops(log), log
            assert log_ops(log).count("open") == 2, log
            print("ok   duplicate_partuuid_rejects")
            tests += 1

        with tempfile.TemporaryDirectory() as work_dir:
            wrong_root = ("0" if ROOT_HASH[0] != "0" else "1") + ROOT_HASH[1:]
            script = happy_path_script(cmdline=CMDLINE_OK.replace(ROOT_HASH, wrong_root), root_mount_ok=False)
            rc, log = run_fixture(fixture, script, work_dir)
            assert rc == 16, f"expected ERR_MOUNT_ROOT(16), got {rc}"
            assert "execve" not in log_ops(log), log
            table_load = find_log_entry(log, "dm_table_load")
            assert wrong_root in table_load and ROOT_HASH not in table_load, table_load
            assert "dm_dev_remove" in log_ops(log), log
            print("ok   mutated_root_hash_reaches_only_failing_verified_mount_and_cleans_mapper")
            tests += 1

        with tempfile.TemporaryDirectory() as work_dir:
            script = happy_path_script(mount_writable=True)
            rc, log = run_fixture(fixture, script, work_dir)
            assert rc == 17, f"expected ERR_MOUNT_WRITABLE(17), got {rc}"
            assert "execve" not in log_ops(log), log
            assert "chdir" not in log_ops(log), log
            print("ok   writable_mount_rejects_before_switch_root")
            tests += 1

        malformed_cases = {
            "missing_dash": CMDLINE_OK.replace(" -- ", " "),
            "console": "console=ttyS0 " + CMDLINE_OK,
            "missing_root_hash": CMDLINE_OK.replace(f" spp_diag.roothash={ROOT_HASH}", ""),
            "unexpected_token": CMDLINE_OK + " spp_diag.extra=1",
            "second_dash": CMDLINE_OK + " --",
            "reordered": CMDLINE_OK.replace("ro rdinit=/spp-diag-handoff", "rdinit=/spp-diag-handoff ro"),
            "double_space": CMDLINE_OK.replace("ro rdinit", "ro  rdinit"),
            "duplicate_partition": CMDLINE_OK.replace(HASH_PARTUUID, DATA_PARTUUID),
        }
        for name, cmdline in malformed_cases.items():
            with tempfile.TemporaryDirectory() as work_dir:
                script = [
                    script_line("mount", result=0),
                    script_line("mount", result=0),
                    script_line("mount", result=0),
                    *stdio_script(),
                    script_line("open", result=0, data=cmdline),
                ]
                rc, log = run_fixture(fixture, script, work_dir)
                assert rc == 12, f"{name}: expected ERR_CMDLINE_MALFORMED(12), got {rc}, log={log}"
                assert log_ops(log) == [
                    "mount", "mount", "mount", "open", "dup2", "set_inheritable", "dup2",
                    "set_inheritable", "dup2", "set_inheritable", "close", "open", "close",
                ], f"{name}: {log}"
                print(f"ok   malformed_cmdline_{name}")
                tests += 1

        with tempfile.TemporaryDirectory() as work_dir:
            script = happy_path_script()[:-1]
            rc, log = run_fixture(fixture, script, work_dir)
            assert rc == 99, f"expected harness-exhaustion sentinel(99), got {rc}"
            print("ok   script_exhaustion_after_last_fd_setup_is_a_test_failure_not_a_pass")
            tests += 1

        with tempfile.TemporaryDirectory() as work_dir:
            rc, log = run_fixture(fixture, happy_path_script(direct_runtime_fds=True), work_dir)
            assert rc == 0, f"direct 3/4/5 path exit {rc}, log={log}"
            runtime_dup2 = [line for line in log if line.startswith("dup2\t") and any(f"newfd={fd}" in line for fd in (3, 4, 5))]
            assert runtime_dup2 == [], runtime_dup2
            assert [line for line in log if line.startswith("set_inheritable\tfd=")][-3:] == [
                "set_inheritable\tfd=3\tresult=0",
                "set_inheritable\tfd=4\tresult=0",
                "set_inheritable\tfd=5\tresult=0",
            ]
            print("ok   already_assigned_runtime_fds_are_not_closed_or_duplicated")
            tests += 1

        with tempfile.TemporaryDirectory() as work_dir:
            script = happy_path_script()
            pread_index = next(i for i, line in enumerate(script) if line.startswith("pread\t"))
            corrupted_header = ("0" if VERITY_HEADER_HEX[0] != "0" else "1") + VERITY_HEADER_HEX[1:]
            script[pread_index] = script_line("pread", result=0, bytes_hex=corrupted_header)
            rc, log = run_fixture(fixture, script, work_dir)
            assert rc == 15, f"expected malformed verity header to fail 15, got {rc}, log={log}"
            assert "dm_dev_create" not in log_ops(log), log
            print("ok   malformed_verity_superblock_rejects_before_mapper_create")
            tests += 1

        base = happy_path_script()
        faultable_ops = {
            "mount", "open", "resolve_partuuid", "blkgetsize64", "pread",
            "dm_dev_create", "dm_table_load", "dm_dev_suspend", "statvfs_rdonly",
            "chdir", "chroot", "dup2", "set_inheritable", "close_range", "execve",
        }
        occurrences: dict[str, int] = {}
        fault_cases = 0
        for index, line in enumerate(base):
            op = line.split("\t", 1)[0]
            if op not in faultable_ops:
                continue
            occurrence = occurrences.get(op, 0)
            occurrences[op] = occurrence + 1
            mutated = list(base)
            mutated[index] = force_result(mutated[index], -1)
            if op in {"dm_table_load", "dm_dev_suspend"}:
                mutated.insert(index + 1, script_line("dm_dev_remove", result=0))
            elif op == "mount" and occurrence == 3:
                mutated.insert(index + 1, script_line("dm_dev_remove", result=0))
            elif op == "statvfs_rdonly":
                mutated.insert(index + 1, script_line("umount2", result=0))
                mutated.insert(index + 2, script_line("dm_dev_remove", result=0))
            with tempfile.TemporaryDirectory() as work_dir:
                rc, log = run_fixture(fixture, mutated, work_dir)
            assert rc != 0, f"{op}[{occurrence}] fault unexpectedly passed: {log}"
            if op != "execve":
                assert "execve" not in log_ops(log), f"{op}[{occurrence}] reached exec: {log}"
            if op in {"dm_table_load", "dm_dev_suspend"} or (op == "mount" and occurrence == 3):
                assert "dm_dev_remove" in log_ops(log), f"{op}[{occurrence}] did not clean mapper: {log}"
            fault_cases += 1
        assert fault_cases >= 30, fault_cases
        print(f"ok   privileged_operation_fault_matrix_{fault_cases}_cases")
        tests += 1

        veritysetup = shutil.which("veritysetup")
        assert veritysetup is not None
        with tempfile.TemporaryDirectory() as work_dir:
            data_path = os.path.join(work_dir, "data")
            hash_path = os.path.join(work_dir, "hash")
            with open(data_path, "wb") as handle:
                handle.write(b"x")
                handle.truncate(1024 * 1024 * 1024)
            formatted = subprocess.run(
                [
                    veritysetup, "format", data_path, hash_path,
                    "--data-block-size=4096", "--hash-block-size=4096", "--hash=sha256",
                    f"--salt={VERITY_SALT}", "--uuid=11111111-1111-5111-8111-111111111111",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            root_match = re.search(r"^Root hash:\s*([0-9a-f]{64})$", formatted.stdout, re.MULTILINE)
            assert root_match is not None and root_match.group(1) == ROOT_HASH, formatted.stdout
            with open(hash_path, "rb") as handle:
                assert handle.read(512).hex() == VERITY_HEADER_HEX
            wrong_root = ("0" if ROOT_HASH[0] != "0" else "1") + ROOT_HASH[1:]
            verified = subprocess.run(
                [veritysetup, "verify", data_path, hash_path, ROOT_HASH], capture_output=True
            )
            rejected = subprocess.run(
                [veritysetup, "verify", data_path, hash_path, wrong_root], capture_output=True
            )
            assert verified.returncode == 0 and rejected.returncode != 0
            print("ok   real_veritysetup_header_and_wrong_root_oracle")
            tests += 1

        print(f"SPP diagnostic handoff native binary: ok ({tests} tests)")
        return 0


if __name__ == "__main__":
    sys.exit(main())
