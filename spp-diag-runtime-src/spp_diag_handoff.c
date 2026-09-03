/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 sol pbc */

/*
 * Native initramfs PID-1 handoff for the SPP diagnostic appliance.
 *
 * Runs as rdinit=/spp-diag-handoff. Reads the reserved cmdline tokens
 * produced by conf_proc_spp_diag_runtime_build.finalize_command_line
 * (spp_diag_data_partuuid=, spp_diag_hash_partuuid=, spp_diag_root_hash=),
 * activates the dm-verity mapped device over the resolved partitions,
 * mounts it read-only as the SquashFS root, switch_roots into it, and
 * execve's the fixed PID-1 controller with three pre-opened, inheritable
 * fds (trace control=3, trace stream=4, serial=5).
 *
 * Every privileged operation is routed through struct spp_diag_handoff_ops
 * so that SPP_DIAG_HANDOFF_TEST_HARNESS can substitute a recording/scripted
 * fake implementation inside this SAME compiled binary for testing -- this
 * file never branches on a test-only compile flag, only on an environment
 * variable that production boot never sets.
 *
 * The kernel's own pre-release canary check (call_usermodehelper against
 * /usr/local/libexec/solstone/pre-release-denied) runs entirely inside the
 * kernel_init kthread before this binary's first instruction executes; this
 * binary neither implements nor calls anything related to it.
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Fixed contract constants                                            */
/* ------------------------------------------------------------------ */

#define SPP_DIAG_RDINIT_TOKEN "rdinit=/spp-diag-handoff"
#define SPP_DIAG_CONTROLLER_INTERP "/usr/bin/python3.10"
#define SPP_DIAG_CONTROLLER_SCRIPT "/usr/local/libexec/solstone/spp-diag-controller.py"
#define SPP_DIAG_ROOT_MOUNTPOINT "/mnt/spp-diag-root"
#define SPP_DIAG_DM_NAME "spp-diag-root"
#define SPP_DIAG_DM_NODE "/dev/mapper/" SPP_DIAG_DM_NAME
#define SPP_DIAG_SECURITYFS_MOUNTPOINT "/sys/kernel/security"
#define SPP_DIAG_TRACE_CONTROL_PATH "/sys/kernel/security/sol_spp_diag_trace/control"
#define SPP_DIAG_TRACE_STREAM_PATH "/sys/kernel/security/sol_spp_diag_trace/stream"
#define SPP_DIAG_SERIAL_PATH "/dev/ttyS0"

#define SPP_DIAG_TRACE_CONTROL_FD 3
#define SPP_DIAG_TRACE_STREAM_FD 4
#define SPP_DIAG_SERIAL_FD 5

enum spp_diag_handoff_status {
    SPP_DIAG_HANDOFF_OK = 0,
    SPP_DIAG_HANDOFF_ERR_MOUNT_PROC = 10,
    SPP_DIAG_HANDOFF_ERR_CMDLINE_READ = 11,
    SPP_DIAG_HANDOFF_ERR_CMDLINE_MALFORMED = 12,
    SPP_DIAG_HANDOFF_ERR_PARTUUID_MISSING = 13,
    SPP_DIAG_HANDOFF_ERR_PARTUUID_DUPLICATE = 14,
    SPP_DIAG_HANDOFF_ERR_VERITY = 15,
    SPP_DIAG_HANDOFF_ERR_MOUNT_ROOT = 16,
    SPP_DIAG_HANDOFF_ERR_MOUNT_WRITABLE = 17,
    SPP_DIAG_HANDOFF_ERR_SWITCH_ROOT = 18,
    SPP_DIAG_HANDOFF_ERR_SECURITYFS = 19,
    SPP_DIAG_HANDOFF_ERR_FD_SETUP = 20,
    SPP_DIAG_HANDOFF_ERR_EXEC = 21,
};

/* ------------------------------------------------------------------ */
/* Ops table -- every privileged operation this binary performs        */
/* ------------------------------------------------------------------ */

struct spp_diag_handoff_ops {
    int (*open)(void *ctx, const char *path, int flags, mode_t mode);
    int (*close)(void *ctx, int fd);
    ssize_t (*read)(void *ctx, int fd, void *buf, size_t count);
    ssize_t (*readlink)(void *ctx, const char *path, char *buf, size_t bufsize);
    int (*blkgetsize64)(void *ctx, int fd, uint64_t *out_bytes);
    int (*dm_dev_create)(void *ctx, int fd, const char *name);
    int (*dm_table_load)(void *ctx, int fd, const char *name, uint64_t length_sectors, const char *target_params);
    int (*dm_dev_suspend)(void *ctx, int fd, const char *name);
    int (*mount)(void *ctx, const char *source, const char *target, const char *fstype, unsigned long flags, const void *data);
    int (*chdir)(void *ctx, const char *path);
    int (*chroot)(void *ctx, const char *path);
    int (*statvfs_rdonly)(void *ctx, const char *path);
    int (*dup2)(void *ctx, int oldfd, int newfd);
    int (*execve)(void *ctx, const char *path, char *const argv[], char *const envp[]);
};

/* ------------------------------------------------------------------ */
/* Cmdline parsing                                                     */
/* ------------------------------------------------------------------ */

struct spp_diag_cmdline_fields {
    char data_partuuid[128];
    char hash_partuuid[128];
    char root_hash[128];
};

static int spp_diag_parse_cmdline(char *cmdline, struct spp_diag_cmdline_fields *fields) {
    char *tokens[64];
    int count = 0;
    char *save = NULL;
    char *tok = strtok_r(cmdline, " \t", &save);
    while (tok != NULL) {
        if (count >= 64) {
            return -1;
        }
        tokens[count++] = tok;
        tok = strtok_r(NULL, " \t", &save);
    }

    int dash_index = -1;
    int dash_count = 0;
    for (int i = 0; i < count; i++) {
        if (strcmp(tokens[i], "--") == 0) {
            dash_index = i;
            dash_count++;
        }
    }
    if (dash_count != 1) {
        return -1;
    }

    int console_count = 0;
    int rdinit_count = 0;
    int extra_pre = 0;
    for (int i = 0; i < dash_index; i++) {
        if (strncmp(tokens[i], "console=", 8) == 0) {
            console_count++;
        } else if (strcmp(tokens[i], SPP_DIAG_RDINIT_TOKEN) == 0) {
            rdinit_count++;
        } else {
            extra_pre++;
        }
    }
    if (console_count != 1 || rdinit_count != 1 || extra_pre != 0) {
        return -1;
    }

    int post_count = count - dash_index - 1;
    if (post_count != 3) {
        return -1;
    }

    int has_data = 0;
    int has_hash = 0;
    int has_root = 0;
    memset(fields, 0, sizeof(*fields));
    for (int i = dash_index + 1; i < count; i++) {
        char *eq = strchr(tokens[i], '=');
        if (eq == NULL || eq == tokens[i] || eq[1] == '\0') {
            return -1;
        }
        *eq = '\0';
        const char *key = tokens[i];
        const char *value = eq + 1;
        if (strcmp(key, "spp_diag_data_partuuid") == 0 && !has_data) {
            has_data = 1;
            strncpy(fields->data_partuuid, value, sizeof(fields->data_partuuid) - 1);
        } else if (strcmp(key, "spp_diag_hash_partuuid") == 0 && !has_hash) {
            has_hash = 1;
            strncpy(fields->hash_partuuid, value, sizeof(fields->hash_partuuid) - 1);
        } else if (strcmp(key, "spp_diag_root_hash") == 0 && !has_root) {
            has_root = 1;
            strncpy(fields->root_hash, value, sizeof(fields->root_hash) - 1);
        } else {
            return -1;
        }
    }
    if (!has_data || !has_hash || !has_root) {
        return -1;
    }
    return 0;
}

static int spp_diag_read_cmdline(const struct spp_diag_handoff_ops *ops, void *ctx, char *out, size_t out_size) {
    int fd = ops->open(ctx, "/proc/cmdline", O_RDONLY, 0);
    if (fd < 0) {
        return -1;
    }
    size_t total = 0;
    for (;;) {
        if (total >= out_size - 1) {
            break;
        }
        ssize_t n = ops->read(ctx, fd, out + total, out_size - 1 - total);
        if (n < 0) {
            ops->close(ctx, fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        total += (size_t)n;
    }
    out[total] = '\0';
    ops->close(ctx, fd);
    while (total > 0 && (out[total - 1] == '\n' || out[total - 1] == '\r')) {
        out[--total] = '\0';
    }
    return 0;
}

static int spp_diag_resolve_partuuid(const struct spp_diag_handoff_ops *ops, void *ctx, const char *partuuid, char *out, size_t out_size) {
    char path[256];
    int written = snprintf(path, sizeof(path), "/dev/disk/by-partuuid/%s", partuuid);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return -1;
    }
    ssize_t n = ops->readlink(ctx, path, out, out_size - 1);
    if (n < 0) {
        return -1;
    }
    out[n] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* Core orchestration -- calls only through the ops vtable             */
/* ------------------------------------------------------------------ */

int spp_diag_handoff_run(const struct spp_diag_handoff_ops *ops, void *ctx) {
    if (ops->mount(ctx, "proc", "/proc", "proc", 0, NULL) != 0) {
        return SPP_DIAG_HANDOFF_ERR_MOUNT_PROC;
    }

    char cmdline[4096];
    if (spp_diag_read_cmdline(ops, ctx, cmdline, sizeof(cmdline)) != 0) {
        return SPP_DIAG_HANDOFF_ERR_CMDLINE_READ;
    }

    struct spp_diag_cmdline_fields fields;
    if (spp_diag_parse_cmdline(cmdline, &fields) != 0) {
        return SPP_DIAG_HANDOFF_ERR_CMDLINE_MALFORMED;
    }

    char data_link[256];
    char hash_link[256];
    if (spp_diag_resolve_partuuid(ops, ctx, fields.data_partuuid, data_link, sizeof(data_link)) != 0) {
        return SPP_DIAG_HANDOFF_ERR_PARTUUID_MISSING;
    }
    if (spp_diag_resolve_partuuid(ops, ctx, fields.hash_partuuid, hash_link, sizeof(hash_link)) != 0) {
        return SPP_DIAG_HANDOFF_ERR_PARTUUID_MISSING;
    }
    if (strcmp(data_link, hash_link) == 0) {
        return SPP_DIAG_HANDOFF_ERR_PARTUUID_DUPLICATE;
    }

    int data_fd = ops->open(ctx, data_link, O_RDONLY, 0);
    if (data_fd < 0) {
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }
    uint64_t data_bytes = 0;
    int size_rc = ops->blkgetsize64(ctx, data_fd, &data_bytes);
    ops->close(ctx, data_fd);
    if (size_rc != 0 || data_bytes == 0) {
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }

    int dm_fd = ops->open(ctx, "/dev/mapper/control", O_RDWR, 0);
    if (dm_fd < 0) {
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }
    if (ops->dm_dev_create(ctx, dm_fd, SPP_DIAG_DM_NAME) != 0) {
        ops->close(ctx, dm_fd);
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }

    uint64_t data_sectors = data_bytes / 512;
    uint64_t num_data_blocks = data_bytes / 4096;
    char target_params[512];
    int params_written = snprintf(
        target_params, sizeof(target_params), "1 %s %s 4096 4096 %" PRIu64 " 1 sha256 %s -",
        data_link, hash_link, num_data_blocks, fields.root_hash
    );
    if (params_written < 0 || (size_t)params_written >= sizeof(target_params)) {
        ops->close(ctx, dm_fd);
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }
    if (ops->dm_table_load(ctx, dm_fd, SPP_DIAG_DM_NAME, data_sectors, target_params) != 0) {
        ops->close(ctx, dm_fd);
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }
    if (ops->dm_dev_suspend(ctx, dm_fd, SPP_DIAG_DM_NAME) != 0) {
        ops->close(ctx, dm_fd);
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }
    ops->close(ctx, dm_fd);

    if (ops->mount(ctx, SPP_DIAG_DM_NODE, SPP_DIAG_ROOT_MOUNTPOINT, "squashfs", MS_RDONLY, NULL) != 0) {
        return SPP_DIAG_HANDOFF_ERR_MOUNT_ROOT;
    }
    if (ops->statvfs_rdonly(ctx, SPP_DIAG_ROOT_MOUNTPOINT) != 1) {
        return SPP_DIAG_HANDOFF_ERR_MOUNT_WRITABLE;
    }

    if (ops->chdir(ctx, SPP_DIAG_ROOT_MOUNTPOINT) != 0) {
        return SPP_DIAG_HANDOFF_ERR_SWITCH_ROOT;
    }
    if (ops->mount(ctx, ".", "/", NULL, MS_MOVE, NULL) != 0) {
        return SPP_DIAG_HANDOFF_ERR_SWITCH_ROOT;
    }
    if (ops->chroot(ctx, ".") != 0) {
        return SPP_DIAG_HANDOFF_ERR_SWITCH_ROOT;
    }
    if (ops->chdir(ctx, "/") != 0) {
        return SPP_DIAG_HANDOFF_ERR_SWITCH_ROOT;
    }

    if (ops->mount(ctx, "securityfs", SPP_DIAG_SECURITYFS_MOUNTPOINT, "securityfs", 0, NULL) != 0) {
        return SPP_DIAG_HANDOFF_ERR_SECURITYFS;
    }

    int control_fd = ops->open(ctx, SPP_DIAG_TRACE_CONTROL_PATH, O_WRONLY, 0);
    if (control_fd < 0) {
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    if (ops->dup2(ctx, control_fd, SPP_DIAG_TRACE_CONTROL_FD) != SPP_DIAG_TRACE_CONTROL_FD) {
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    ops->close(ctx, control_fd);

    int stream_fd = ops->open(ctx, SPP_DIAG_TRACE_STREAM_PATH, O_RDONLY, 0);
    if (stream_fd < 0) {
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    if (ops->dup2(ctx, stream_fd, SPP_DIAG_TRACE_STREAM_FD) != SPP_DIAG_TRACE_STREAM_FD) {
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    ops->close(ctx, stream_fd);

    int serial_fd = ops->open(ctx, SPP_DIAG_SERIAL_PATH, O_RDWR, 0);
    if (serial_fd < 0) {
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    if (ops->dup2(ctx, serial_fd, SPP_DIAG_SERIAL_FD) != SPP_DIAG_SERIAL_FD) {
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    ops->close(ctx, serial_fd);

    char *argv[] = {
        (char *)SPP_DIAG_CONTROLLER_INTERP, (char *)"-I", (char *)"-B", (char *)"-S",
        (char *)SPP_DIAG_CONTROLLER_SCRIPT, NULL,
    };
    char *envp[] = {
        (char *)"LANG=C", (char *)"LC_ALL=C", (char *)"PATH=/nonexistent",
        (char *)"PYTHONNOUSERSITE=1", (char *)"PYTHONDONTWRITEBYTECODE=1", NULL,
    };
    ops->execve(ctx, SPP_DIAG_CONTROLLER_INTERP, argv, envp);
    return SPP_DIAG_HANDOFF_ERR_EXEC;
}

/* ------------------------------------------------------------------ */
/* Real production ops -- actual Linux syscalls                        */
/* ------------------------------------------------------------------ */

static int real_open(void *ctx, const char *path, int flags, mode_t mode) {
    (void)ctx;
    return open(path, flags, mode);
}

static int real_close(void *ctx, int fd) {
    (void)ctx;
    return close(fd);
}

static ssize_t real_read(void *ctx, int fd, void *buf, size_t count) {
    (void)ctx;
    return read(fd, buf, count);
}

static ssize_t real_readlink(void *ctx, const char *path, char *buf, size_t bufsize) {
    (void)ctx;
    return readlink(path, buf, bufsize);
}

static int real_blkgetsize64(void *ctx, int fd, uint64_t *out_bytes) {
    (void)ctx;
    return ioctl(fd, BLKGETSIZE64, out_bytes);
}

static int real_dm_dev_create(void *ctx, int fd, const char *name) {
    (void)ctx;
    struct dm_ioctl io;
    memset(&io, 0, sizeof(io));
    io.version[0] = DM_VERSION_MAJOR;
    io.version[1] = DM_VERSION_MINOR;
    io.version[2] = DM_VERSION_PATCHLEVEL;
    io.data_size = sizeof(io);
    io.data_start = sizeof(io);
    strncpy(io.name, name, sizeof(io.name) - 1);
    return ioctl(fd, DM_DEV_CREATE, &io);
}

static int real_dm_table_load(void *ctx, int fd, const char *name, uint64_t length_sectors, const char *target_params) {
    (void)ctx;
    unsigned char buf[4096];
    memset(buf, 0, sizeof(buf));
    struct dm_ioctl *io = (struct dm_ioctl *)buf;
    struct dm_target_spec *spec = (struct dm_target_spec *)(buf + sizeof(struct dm_ioctl));
    size_t params_offset = sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec);
    size_t params_len = strlen(target_params) + 1;
    size_t total = params_offset + params_len;
    total = (total + 7u) & ~((size_t)7u);
    if (total > sizeof(buf)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    io->version[0] = DM_VERSION_MAJOR;
    io->version[1] = DM_VERSION_MINOR;
    io->version[2] = DM_VERSION_PATCHLEVEL;
    io->data_size = (uint32_t)total;
    io->data_start = sizeof(struct dm_ioctl);
    io->target_count = 1;
    strncpy(io->name, name, sizeof(io->name) - 1);
    spec->sector_start = 0;
    spec->length = length_sectors;
    spec->status = 0;
    spec->next = 0;
    strncpy(spec->target_type, "verity", sizeof(spec->target_type) - 1);
    memcpy(buf + params_offset, target_params, strlen(target_params) + 1);
    return ioctl(fd, DM_TABLE_LOAD, buf);
}

static int real_dm_dev_suspend(void *ctx, int fd, const char *name) {
    (void)ctx;
    struct dm_ioctl io;
    memset(&io, 0, sizeof(io));
    io.version[0] = DM_VERSION_MAJOR;
    io.version[1] = DM_VERSION_MINOR;
    io.version[2] = DM_VERSION_PATCHLEVEL;
    io.data_size = sizeof(io);
    io.data_start = sizeof(io);
    strncpy(io.name, name, sizeof(io.name) - 1);
    return ioctl(fd, DM_DEV_SUSPEND, &io);
}

static int real_mount(void *ctx, const char *source, const char *target, const char *fstype, unsigned long flags, const void *data) {
    (void)ctx;
    return mount(source, target, fstype, flags, data);
}

static int real_chdir(void *ctx, const char *path) {
    (void)ctx;
    return chdir(path);
}

static int real_chroot(void *ctx, const char *path) {
    (void)ctx;
    return chroot(path);
}

static int real_statvfs_rdonly(void *ctx, const char *path) {
    (void)ctx;
    struct statvfs st;
    if (statvfs(path, &st) != 0) {
        return -1;
    }
    return (st.f_flag & ST_RDONLY) ? 1 : 0;
}

static int real_dup2(void *ctx, int oldfd, int newfd) {
    (void)ctx;
    return dup2(oldfd, newfd);
}

static int real_execve(void *ctx, const char *path, char *const argv[], char *const envp[]) {
    (void)ctx;
    return execve(path, argv, envp);
}

static const struct spp_diag_handoff_ops g_real_ops = {
    .open = real_open,
    .close = real_close,
    .read = real_read,
    .readlink = real_readlink,
    .blkgetsize64 = real_blkgetsize64,
    .dm_dev_create = real_dm_dev_create,
    .dm_table_load = real_dm_table_load,
    .dm_dev_suspend = real_dm_dev_suspend,
    .mount = real_mount,
    .chdir = real_chdir,
    .chroot = real_chroot,
    .statvfs_rdonly = real_statvfs_rdonly,
    .dup2 = real_dup2,
    .execve = real_execve,
};

/* ------------------------------------------------------------------ */
/* Test harness -- a scripted/recording fake ops table compiled into   */
/* this same binary, selected only when SPP_DIAG_HANDOFF_TEST_HARNESS  */
/* names a script file. Production boot never sets this variable.     */
/*                                                                      */
/* Script format: one directive per line, tab-separated fields:        */
/*   <op>\tkey=value\tkey=value...                                     */
/* Every line must supply "result=<int>"; op-specific fields supply    */
/* forced output data the real logic cannot otherwise obtain (e.g. the */
/* content behind a fake fd, or a resolved readlink target). Ops are   */
/* matched strictly in the script's line order; a call that doesn't    */
/* match the next expected op, or occurs after the script is           */
/* exhausted, is a hard test failure (exit 99).                        */
/*                                                                      */
/* Log format: one JSON-free tab-separated line per actual call        */
/* received, written to SPP_DIAG_HANDOFF_TEST_LOG as it happens.       */
/* ------------------------------------------------------------------ */

#define SPP_DIAG_HARNESS_MAX_LINES 64
#define SPP_DIAG_HARNESS_MAX_FIELDS 8
#define SPP_DIAG_HARNESS_MAX_FAKE_FDS 8

struct spp_diag_harness_field {
    char key[64];
    char value[2048];
};

struct spp_diag_harness_line {
    char op[32];
    struct spp_diag_harness_field fields[SPP_DIAG_HARNESS_MAX_FIELDS];
    int field_count;
};

struct spp_diag_harness_fake_fd {
    int fd;
    char *data;
    size_t data_len;
    size_t offset;
};

struct spp_diag_harness_ctx {
    struct spp_diag_harness_line lines[SPP_DIAG_HARNESS_MAX_LINES];
    int line_count;
    int next_line;
    FILE *log;
    int next_fake_fd;
    struct spp_diag_harness_fake_fd fake_fds[SPP_DIAG_HARNESS_MAX_FAKE_FDS];
    int fake_fd_count;
};

static const char *spp_diag_harness_field(struct spp_diag_harness_line *line, const char *key) {
    for (int i = 0; i < line->field_count; i++) {
        if (strcmp(line->fields[i].key, key) == 0) {
            return line->fields[i].value;
        }
    }
    return NULL;
}

static int spp_diag_harness_field_int(struct spp_diag_harness_line *line, const char *key, int default_value) {
    const char *value = spp_diag_harness_field(line, key);
    if (value == NULL) {
        return default_value;
    }
    return atoi(value);
}

static void spp_diag_harness_unexpected(struct spp_diag_harness_ctx *hctx, const char *op) {
    if (hctx->log != NULL) {
        fprintf(hctx->log, "UNEXPECTED\top=%s\n", op);
        fflush(hctx->log);
    }
    fprintf(stderr, "spp-diag-handoff test harness: unexpected call to %s (script exhausted or out of order)\n", op);
    exit(99);
}

static struct spp_diag_harness_line *spp_diag_harness_next(struct spp_diag_harness_ctx *hctx, const char *op) {
    if (hctx->next_line >= hctx->line_count) {
        spp_diag_harness_unexpected(hctx, op);
    }
    struct spp_diag_harness_line *line = &hctx->lines[hctx->next_line];
    if (strcmp(line->op, op) != 0) {
        spp_diag_harness_unexpected(hctx, op);
    }
    hctx->next_line++;
    return line;
}

static void spp_diag_harness_log(struct spp_diag_harness_ctx *hctx, const char *op, const char *detail, int result) {
    if (hctx->log == NULL) {
        return;
    }
    fprintf(hctx->log, "%s\t%s\tresult=%d\n", op, detail, result);
    fflush(hctx->log);
}

static int spp_diag_harness_open(void *ctx, const char *path, int flags, mode_t mode) {
    (void)flags;
    (void)mode;
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "open");
    int result = spp_diag_harness_field_int(line, "result", -1);
    char detail[2200];
    snprintf(detail, sizeof(detail), "path=%s", path);
    if (result >= 0) {
        const char *data = spp_diag_harness_field(line, "data");
        if (hctx->fake_fd_count >= SPP_DIAG_HARNESS_MAX_FAKE_FDS) {
            spp_diag_harness_unexpected(hctx, "open");
        }
        struct spp_diag_harness_fake_fd *entry = &hctx->fake_fds[hctx->fake_fd_count++];
        entry->fd = 1000 + hctx->next_fake_fd++;
        if (data != NULL) {
            entry->data_len = strlen(data);
            entry->data = malloc(entry->data_len + 1);
            memcpy(entry->data, data, entry->data_len + 1);
        } else {
            entry->data = NULL;
            entry->data_len = 0;
        }
        entry->offset = 0;
        result = entry->fd;
    }
    spp_diag_harness_log(hctx, "open", detail, result);
    return result;
}

static int spp_diag_harness_close(void *ctx, int fd) {
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    char detail[64];
    snprintf(detail, sizeof(detail), "fd=%d", fd);
    spp_diag_harness_log(hctx, "close", detail, 0);
    return 0;
}

static ssize_t spp_diag_harness_read(void *ctx, int fd, void *buf, size_t count) {
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    for (int i = 0; i < hctx->fake_fd_count; i++) {
        if (hctx->fake_fds[i].fd == fd) {
            struct spp_diag_harness_fake_fd *entry = &hctx->fake_fds[i];
            size_t remaining = entry->data_len - entry->offset;
            size_t take = remaining < count ? remaining : count;
            if (take > 0) {
                memcpy(buf, entry->data + entry->offset, take);
                entry->offset += take;
            }
            return (ssize_t)take;
        }
    }
    return 0;
}

static ssize_t spp_diag_harness_readlink(void *ctx, const char *path, char *buf, size_t bufsize) {
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "readlink");
    int result = spp_diag_harness_field_int(line, "result", -1);
    char detail[2200];
    snprintf(detail, sizeof(detail), "path=%s", path);
    spp_diag_harness_log(hctx, "readlink", detail, result);
    if (result != 0) {
        return -1;
    }
    const char *out = spp_diag_harness_field(line, "out");
    if (out == NULL) {
        return -1;
    }
    size_t len = strlen(out);
    if (len > bufsize) {
        len = bufsize;
    }
    memcpy(buf, out, len);
    return (ssize_t)len;
}

static int spp_diag_harness_blkgetsize64(void *ctx, int fd, uint64_t *out_bytes) {
    (void)fd;
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "blkgetsize64");
    int result = spp_diag_harness_field_int(line, "result", -1);
    const char *size_str = spp_diag_harness_field(line, "size");
    uint64_t size = size_str != NULL ? strtoull(size_str, NULL, 10) : 0;
    char detail[64];
    snprintf(detail, sizeof(detail), "size=%" PRIu64, size);
    spp_diag_harness_log(hctx, "blkgetsize64", detail, result);
    if (result == 0) {
        *out_bytes = size;
    }
    return result;
}

static int spp_diag_harness_dm_dev_create(void *ctx, int fd, const char *name) {
    (void)fd;
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "dm_dev_create");
    int result = spp_diag_harness_field_int(line, "result", -1);
    char detail[128];
    snprintf(detail, sizeof(detail), "name=%s", name);
    spp_diag_harness_log(hctx, "dm_dev_create", detail, result);
    return result;
}

static int spp_diag_harness_dm_table_load(void *ctx, int fd, const char *name, uint64_t length_sectors, const char *target_params) {
    (void)fd;
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "dm_table_load");
    int result = spp_diag_harness_field_int(line, "result", -1);
    char detail[2200];
    snprintf(detail, sizeof(detail), "name=%s\tlength_sectors=%" PRIu64 "\tparams=%s", name, length_sectors, target_params);
    spp_diag_harness_log(hctx, "dm_table_load", detail, result);
    return result;
}

static int spp_diag_harness_dm_dev_suspend(void *ctx, int fd, const char *name) {
    (void)fd;
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "dm_dev_suspend");
    int result = spp_diag_harness_field_int(line, "result", -1);
    char detail[128];
    snprintf(detail, sizeof(detail), "name=%s", name);
    spp_diag_harness_log(hctx, "dm_dev_suspend", detail, result);
    return result;
}

static int spp_diag_harness_mount(void *ctx, const char *source, const char *target, const char *fstype, unsigned long flags, const void *data) {
    (void)data;
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "mount");
    int result = spp_diag_harness_field_int(line, "result", -1);
    char detail[512];
    snprintf(
        detail, sizeof(detail), "source=%s\ttarget=%s\tfstype=%s\tflags=%lu", source ? source : "(null)",
        target ? target : "(null)", fstype ? fstype : "(null)", flags
    );
    spp_diag_harness_log(hctx, "mount", detail, result);
    return result;
}

static int spp_diag_harness_chdir(void *ctx, const char *path) {
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "chdir");
    int result = spp_diag_harness_field_int(line, "result", -1);
    char detail[256];
    snprintf(detail, sizeof(detail), "path=%s", path);
    spp_diag_harness_log(hctx, "chdir", detail, result);
    return result;
}

static int spp_diag_harness_chroot(void *ctx, const char *path) {
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "chroot");
    int result = spp_diag_harness_field_int(line, "result", -1);
    char detail[256];
    snprintf(detail, sizeof(detail), "path=%s", path);
    spp_diag_harness_log(hctx, "chroot", detail, result);
    return result;
}

static int spp_diag_harness_statvfs_rdonly(void *ctx, const char *path) {
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "statvfs_rdonly");
    int result = spp_diag_harness_field_int(line, "result", -1);
    char detail[256];
    snprintf(detail, sizeof(detail), "path=%s", path);
    spp_diag_harness_log(hctx, "statvfs_rdonly", detail, result);
    return result;
}

static int spp_diag_harness_dup2(void *ctx, int oldfd, int newfd) {
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "dup2");
    int result = spp_diag_harness_field_int(line, "result", newfd);
    char detail[64];
    snprintf(detail, sizeof(detail), "oldfd=%d\tnewfd=%d", oldfd, newfd);
    spp_diag_harness_log(hctx, "dup2", detail, result);
    return result;
}

static int spp_diag_harness_execve(void *ctx, const char *path, char *const argv[], char *const envp[]) {
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "execve");
    int result = spp_diag_harness_field_int(line, "result", 0);
    char detail[2200];
    size_t offset = 0;
    offset += (size_t)snprintf(detail + offset, sizeof(detail) - offset, "path=%s\targv=", path);
    for (int i = 0; argv[i] != NULL && offset < sizeof(detail); i++) {
        offset += (size_t)snprintf(detail + offset, sizeof(detail) - offset, "%s%s", i == 0 ? "" : ",", argv[i]);
    }
    offset += (size_t)snprintf(detail + offset, sizeof(detail) - offset, "\tenvp=");
    for (int i = 0; envp[i] != NULL && offset < sizeof(detail); i++) {
        offset += (size_t)snprintf(detail + offset, sizeof(detail) - offset, "%s%s", i == 0 ? "" : ",", envp[i]);
    }
    spp_diag_harness_log(hctx, "execve", detail, result);
    if (hctx->log != NULL) {
        fclose(hctx->log);
        hctx->log = NULL;
    }
    _exit(result);
}

static const struct spp_diag_handoff_ops g_harness_ops = {
    .open = spp_diag_harness_open,
    .close = spp_diag_harness_close,
    .read = spp_diag_harness_read,
    .readlink = spp_diag_harness_readlink,
    .blkgetsize64 = spp_diag_harness_blkgetsize64,
    .dm_dev_create = spp_diag_harness_dm_dev_create,
    .dm_table_load = spp_diag_harness_dm_table_load,
    .dm_dev_suspend = spp_diag_harness_dm_dev_suspend,
    .mount = spp_diag_harness_mount,
    .chdir = spp_diag_harness_chdir,
    .chroot = spp_diag_harness_chroot,
    .statvfs_rdonly = spp_diag_harness_statvfs_rdonly,
    .dup2 = spp_diag_harness_dup2,
    .execve = spp_diag_harness_execve,
};

static int spp_diag_harness_parse_script(const char *path, struct spp_diag_harness_ctx *hctx) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    char raw[4096];
    while (fgets(raw, sizeof(raw), f) != NULL) {
        size_t len = strlen(raw);
        while (len > 0 && (raw[len - 1] == '\n' || raw[len - 1] == '\r')) {
            raw[--len] = '\0';
        }
        if (len == 0) {
            continue;
        }
        if (hctx->line_count >= SPP_DIAG_HARNESS_MAX_LINES) {
            fclose(f);
            return -1;
        }
        struct spp_diag_harness_line *line = &hctx->lines[hctx->line_count++];
        memset(line, 0, sizeof(*line));
        char *save = NULL;
        char *tok = strtok_r(raw, "\t", &save);
        if (tok == NULL) {
            fclose(f);
            return -1;
        }
        strncpy(line->op, tok, sizeof(line->op) - 1);
        tok = strtok_r(NULL, "\t", &save);
        while (tok != NULL) {
            if (line->field_count >= SPP_DIAG_HARNESS_MAX_FIELDS) {
                fclose(f);
                return -1;
            }
            char *eq = strchr(tok, '=');
            if (eq == NULL) {
                fclose(f);
                return -1;
            }
            *eq = '\0';
            struct spp_diag_harness_field *field = &line->fields[line->field_count++];
            strncpy(field->key, tok, sizeof(field->key) - 1);
            strncpy(field->value, eq + 1, sizeof(field->value) - 1);
            tok = strtok_r(NULL, "\t", &save);
        }
    }
    fclose(f);
    return 0;
}

static const struct spp_diag_handoff_ops *spp_diag_handoff_load_test_harness(const char *script_path, void **out_ctx) {
    struct spp_diag_harness_ctx *hctx = calloc(1, sizeof(struct spp_diag_harness_ctx));
    if (hctx == NULL) {
        return NULL;
    }
    if (spp_diag_harness_parse_script(script_path, hctx) != 0) {
        free(hctx);
        return NULL;
    }
    const char *log_path = getenv("SPP_DIAG_HANDOFF_TEST_LOG");
    if (log_path != NULL) {
        hctx->log = fopen(log_path, "w");
    }
    *out_ctx = hctx;
    return &g_harness_ops;
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    const struct spp_diag_handoff_ops *ops = &g_real_ops;
    void *ctx = NULL;
    const char *harness = getenv("SPP_DIAG_HANDOFF_TEST_HARNESS");
    if (harness != NULL) {
        ops = spp_diag_handoff_load_test_harness(harness, &ctx);
        if (ops == NULL) {
            return 90;
        }
    }
    int rc = spp_diag_handoff_run(ops, ctx);
    return rc;
}
