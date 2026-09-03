/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 sol pbc */

/*
 * Native initramfs PID-1 handoff for the SPP diagnostic appliance.
 *
 * Runs as rdinit=/spp-diag-handoff. Reads the reserved cmdline tokens
 * produced by conf_proc_spp_diag_runtime_build.finalize_command_line
 * (root data/hash PARTUUIDs, root hash, run identities, target and binding),
 * activates the dm-verity mapped device over the resolved partitions,
 * mounts it read-only as the SquashFS root, switch_roots into it, and
 * execve's the fixed PID-1 controller with the two tokens after ``--`` and
 * three pre-opened, inheritable fds (trace control=3, trace stream=4, serial=5).
 *
 * Every privileged operation is routed through struct spp_diag_handoff_ops
 * A compile-time-only test build substitutes a recording/scripted fake. The
 * production binary contains no environment-selected harness path.
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
#include <glob.h>
#include <inttypes.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Fixed contract constants                                            */
/* ------------------------------------------------------------------ */

#define SPP_DIAG_RDINIT_TOKEN "rdinit=/spp-diag-handoff"
#define SPP_DIAG_CONTROLLER_INTERP "/usr/bin/python3.10"
#define SPP_DIAG_CONTROLLER_SCRIPT "/usr/lib/spp/spp-diag-controller"
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
    SPP_DIAG_HANDOFF_ERR_MOUNT_SYS = 22,
    SPP_DIAG_HANDOFF_ERR_MOUNT_DEV = 23,
};

struct spp_diag_verity_geometry {
    uint64_t data_blocks;
    char salt[65];
};

/* ------------------------------------------------------------------ */
/* Ops table -- every privileged operation this binary performs        */
/* ------------------------------------------------------------------ */

struct spp_diag_handoff_ops {
    int (*open)(void *ctx, const char *path, int flags, mode_t mode);
    int (*close)(void *ctx, int fd);
    ssize_t (*read)(void *ctx, int fd, void *buf, size_t count);
    ssize_t (*pread)(void *ctx, int fd, void *buf, size_t count, off_t offset);
    int (*resolve_partuuid)(
        void *ctx, const char *partuuid, char *out_device_id, size_t out_size, dev_t *out_rdev, int *out_fd
    );
    int (*blkgetsize64)(void *ctx, int fd, uint64_t *out_bytes);
    int (*dm_dev_create)(void *ctx, int fd, const char *name);
    int (*dm_dev_remove)(void *ctx, int fd, const char *name);
    int (*dm_table_load)(void *ctx, int fd, const char *name, uint64_t length_sectors, const char *target_params);
    int (*dm_dev_suspend)(void *ctx, int fd, const char *name);
    int (*mount)(void *ctx, const char *source, const char *target, const char *fstype, unsigned long flags, const void *data);
    int (*umount2)(void *ctx, const char *target, int flags);
    int (*chdir)(void *ctx, const char *path);
    int (*chroot)(void *ctx, const char *path);
    int (*statvfs_rdonly)(void *ctx, const char *path);
    int (*dup2)(void *ctx, int oldfd, int newfd);
    int (*set_inheritable)(void *ctx, int fd);
    int (*close_range)(void *ctx, unsigned int first, unsigned int last);
    int (*execve)(void *ctx, const char *path, char *const argv[], char *const envp[]);
};

/* ------------------------------------------------------------------ */
/* Cmdline parsing                                                     */
/* ------------------------------------------------------------------ */

struct spp_diag_cmdline_fields {
    char data_partuuid[128];
    char hash_partuuid[128];
    char root_hash[128];
    char challenge[65];
    char run_identity[65];
    char control_plan[65];
    char target_profile[129];
    char binding_partuuid[128];
};

static int spp_diag_is_lower_hex(const char *value, size_t length) {
    if (strlen(value) != length) {
        return 0;
    }
    for (size_t i = 0; i < length; i++) {
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int spp_diag_is_partuuid(const char *value) {
    if (strlen(value) != 36) {
        return 0;
    }
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') {
                return 0;
            }
        } else if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int spp_diag_is_profile(const char *value) {
    size_t length = strlen(value);
    if (length == 0 || length > 128 ||
        !((value[0] >= '0' && value[0] <= '9') || (value[0] >= 'A' && value[0] <= 'Z') ||
          (value[0] >= 'a' && value[0] <= 'z'))) {
        return 0;
    }
    for (size_t i = 1; i < length; i++) {
        unsigned char c = (unsigned char)value[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              c == '.' || c == '_' || c == ':' || c == '-')) {
            return 0;
        }
    }
    return 1;
}

static int spp_diag_copy_value(char *out, size_t out_size, const char *token, const char *prefix) {
    size_t prefix_length = strlen(prefix);
    if (strncmp(token, prefix, prefix_length) != 0) {
        return -1;
    }
    const char *value = token + prefix_length;
    size_t length = strlen(value);
    if (length == 0 || length >= out_size) {
        return -1;
    }
    memcpy(out, value, length + 1);
    return 0;
}

static int spp_diag_parse_cmdline(char *cmdline, struct spp_diag_cmdline_fields *fields) {
    char original[4096];
    if (strlen(cmdline) >= sizeof(original)) {
        return -1;
    }
    strcpy(original, cmdline);
    char *tokens[16];
    int count = 0;
    char *save = NULL;
    char *tok = strtok_r(cmdline, " \t", &save);
    while (tok != NULL) {
        if (count >= 16) {
            return -1;
        }
        tokens[count++] = tok;
        tok = strtok_r(NULL, " \t", &save);
    }

    if (count != 16 || strcmp(tokens[0], "ro") != 0 || strcmp(tokens[1], SPP_DIAG_RDINIT_TOKEN) != 0 ||
        strcmp(tokens[2], "init=/usr/lib/spp/spp-diag-controller") != 0 ||
        strcmp(tokens[3], "root=/dev/mapper/spp-diag-root") != 0 || strcmp(tokens[4], "rootfstype=squashfs") != 0 ||
        strcmp(tokens[5], "ip=off") != 0 || strcmp(tokens[6], "ima_policy=critical_data") != 0 ||
        strcmp(tokens[13], "--") != 0) {
        return -1;
    }
    memset(fields, 0, sizeof(*fields));
    if (spp_diag_copy_value(fields->data_partuuid, sizeof(fields->data_partuuid), tokens[7], "spp_diag.root_data=PARTUUID=") != 0 ||
        spp_diag_copy_value(fields->hash_partuuid, sizeof(fields->hash_partuuid), tokens[8], "spp_diag.root_hash=PARTUUID=") != 0 ||
        spp_diag_copy_value(fields->root_hash, sizeof(fields->root_hash), tokens[9], "spp_diag.roothash=") != 0 ||
        spp_diag_copy_value(fields->challenge, sizeof(fields->challenge), tokens[10], "sol_spp_diag.challenge=") != 0 ||
        spp_diag_copy_value(fields->run_identity, sizeof(fields->run_identity), tokens[11], "sol_spp_diag.run=") != 0 ||
        spp_diag_copy_value(fields->control_plan, sizeof(fields->control_plan), tokens[12], "sol_spp_diag.control_plan=") != 0 ||
        spp_diag_copy_value(fields->target_profile, sizeof(fields->target_profile), tokens[14], "sol_spp_diag.target_profile=") != 0 ||
        spp_diag_copy_value(fields->binding_partuuid, sizeof(fields->binding_partuuid), tokens[15], "sol_spp_diag.binding_partuuid=") != 0) {
        return -1;
    }
    if (!spp_diag_is_partuuid(fields->data_partuuid) || !spp_diag_is_partuuid(fields->hash_partuuid) ||
        !spp_diag_is_partuuid(fields->binding_partuuid) || !spp_diag_is_lower_hex(fields->root_hash, 64) ||
        !spp_diag_is_lower_hex(fields->challenge, 64) || !spp_diag_is_lower_hex(fields->run_identity, 64) ||
        !spp_diag_is_lower_hex(fields->control_plan, 64) || !spp_diag_is_profile(fields->target_profile) ||
        strcmp(fields->data_partuuid, fields->hash_partuuid) == 0 ||
        strcmp(fields->data_partuuid, fields->binding_partuuid) == 0 ||
        strcmp(fields->hash_partuuid, fields->binding_partuuid) == 0) {
        return -1;
    }
    char expected[4096];
    int written = snprintf(
        expected, sizeof(expected),
        "ro rdinit=/spp-diag-handoff init=/usr/lib/spp/spp-diag-controller root=/dev/mapper/spp-diag-root "
        "rootfstype=squashfs ip=off ima_policy=critical_data spp_diag.root_data=PARTUUID=%s "
        "spp_diag.root_hash=PARTUUID=%s spp_diag.roothash=%s sol_spp_diag.challenge=%s "
        "sol_spp_diag.run=%s sol_spp_diag.control_plan=%s -- sol_spp_diag.target_profile=%s "
        "sol_spp_diag.binding_partuuid=%s",
        fields->data_partuuid, fields->hash_partuuid, fields->root_hash, fields->challenge, fields->run_identity,
        fields->control_plan, fields->target_profile, fields->binding_partuuid
    );
    return written >= 0 && (size_t)written < sizeof(expected) && strcmp(original, expected) == 0 ? 0 : -1;
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

static uint16_t spp_diag_le16(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t spp_diag_le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t spp_diag_le64(const unsigned char *p) {
    return (uint64_t)spp_diag_le32(p) | ((uint64_t)spp_diag_le32(p + 4) << 32);
}

static int spp_diag_read_verity_geometry(
    const struct spp_diag_handoff_ops *ops,
    void *ctx,
    int hash_fd,
    struct spp_diag_verity_geometry *out
) {
    unsigned char header[512];
    ssize_t n = ops->pread(ctx, hash_fd, header, sizeof(header), 0);
    if (n != (ssize_t)sizeof(header) || memcmp(header, "verity\0\0", 8) != 0 ||
        spp_diag_le32(header + 8) != 1 || spp_diag_le32(header + 12) != 1 ||
        memcmp(header + 32, "sha256\0", 7) != 0 || spp_diag_le32(header + 64) != 4096 ||
        spp_diag_le32(header + 68) != 4096 || spp_diag_le16(header + 80) != 32) {
        return -1;
    }
    for (size_t i = 39; i < 64; i++) {
        if (header[i] != 0) {
            return -1;
        }
    }
    for (size_t i = 82; i < 88; i++) {
        if (header[i] != 0) {
            return -1;
        }
    }
    out->data_blocks = spp_diag_le64(header + 72);
    if (out->data_blocks == 0 || out->data_blocks > UINT64_MAX / 4096) {
        return -1;
    }
    for (size_t i = 0; i < 32; i++) {
        static const char hex[] = "0123456789abcdef";
        out->salt[i * 2] = hex[header[88 + i] >> 4];
        out->salt[i * 2 + 1] = hex[header[88 + i] & 0x0f];
    }
    out->salt[64] = '\0';
    return 0;
}

static int spp_diag_setup_stdio(const struct spp_diag_handoff_ops *ops, void *ctx) {
    int null_fd = ops->open(ctx, "/dev/null", O_RDWR | O_CLOEXEC, 0);
    if (null_fd < 0) {
        return -1;
    }
    for (int target = 0; target <= 2; target++) {
        if (null_fd != target && ops->dup2(ctx, null_fd, target) != target) {
            if (null_fd > 2) {
                ops->close(ctx, null_fd);
            }
            return -1;
        }
        if (ops->set_inheritable(ctx, target) != 0) {
            if (null_fd > 2) {
                ops->close(ctx, null_fd);
            }
            return -1;
        }
    }
    if (null_fd > 2 && ops->close(ctx, null_fd) != 0) {
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Core orchestration -- calls only through the ops vtable             */
/* ------------------------------------------------------------------ */

int spp_diag_handoff_run(const struct spp_diag_handoff_ops *ops, void *ctx) {
    if (ops->mount(ctx, "proc", "/proc", "proc", 0, NULL) != 0) {
        return SPP_DIAG_HANDOFF_ERR_MOUNT_PROC;
    }
    if (ops->mount(ctx, "sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0) {
        return SPP_DIAG_HANDOFF_ERR_MOUNT_SYS;
    }
    if (ops->mount(ctx, "devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755") != 0) {
        return SPP_DIAG_HANDOFF_ERR_MOUNT_DEV;
    }
    if (spp_diag_setup_stdio(ops, ctx) != 0) {
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }

    char cmdline[4096];
    if (spp_diag_read_cmdline(ops, ctx, cmdline, sizeof(cmdline)) != 0) {
        return SPP_DIAG_HANDOFF_ERR_CMDLINE_READ;
    }

    struct spp_diag_cmdline_fields fields;
    if (spp_diag_parse_cmdline(cmdline, &fields) != 0) {
        return SPP_DIAG_HANDOFF_ERR_CMDLINE_MALFORMED;
    }

    char data_device_id[64];
    char hash_device_id[64];
    dev_t data_rdev = 0;
    dev_t hash_rdev = 0;
    int data_fd = -1;
    int hash_fd = -1;
    if (ops->resolve_partuuid(
            ctx, fields.data_partuuid, data_device_id, sizeof(data_device_id), &data_rdev, &data_fd
        ) != 0) {
        return SPP_DIAG_HANDOFF_ERR_PARTUUID_MISSING;
    }
    if (ops->resolve_partuuid(
            ctx, fields.hash_partuuid, hash_device_id, sizeof(hash_device_id), &hash_rdev, &hash_fd
        ) != 0) {
        ops->close(ctx, data_fd);
        return SPP_DIAG_HANDOFF_ERR_PARTUUID_MISSING;
    }
    if (data_rdev == hash_rdev) {
        ops->close(ctx, hash_fd);
        ops->close(ctx, data_fd);
        return SPP_DIAG_HANDOFF_ERR_PARTUUID_DUPLICATE;
    }

    uint64_t data_bytes = 0;
    int size_rc = ops->blkgetsize64(ctx, data_fd, &data_bytes);
    if (size_rc != 0 || data_bytes < 4096) {
        ops->close(ctx, hash_fd);
        ops->close(ctx, data_fd);
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }

    uint64_t hash_bytes = 0;
    struct spp_diag_verity_geometry geometry;
    int hash_size_rc = ops->blkgetsize64(ctx, hash_fd, &hash_bytes);
    int geometry_rc = spp_diag_read_verity_geometry(ops, ctx, hash_fd, &geometry);
    if (hash_size_rc != 0 || geometry_rc != 0 || hash_bytes < 8192 ||
        geometry.data_blocks > data_bytes / 4096) {
        ops->close(ctx, hash_fd);
        ops->close(ctx, data_fd);
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }

    int dm_fd = ops->open(ctx, "/dev/mapper/control", O_RDWR, 0);
    if (dm_fd < 0) {
        ops->close(ctx, hash_fd);
        ops->close(ctx, data_fd);
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }
    if (ops->dm_dev_create(ctx, dm_fd, SPP_DIAG_DM_NAME) != 0) {
        ops->close(ctx, dm_fd);
        ops->close(ctx, hash_fd);
        ops->close(ctx, data_fd);
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }

    uint64_t data_sectors = geometry.data_blocks * 8;
    char target_params[512];
    int params_written = snprintf(
        target_params, sizeof(target_params), "1 %s %s 4096 4096 %" PRIu64 " 1 sha256 %s %s",
        data_device_id, hash_device_id, geometry.data_blocks, fields.root_hash, geometry.salt
    );
    if (params_written < 0 || (size_t)params_written >= sizeof(target_params)) {
        ops->dm_dev_remove(ctx, dm_fd, SPP_DIAG_DM_NAME);
        ops->close(ctx, dm_fd);
        ops->close(ctx, hash_fd);
        ops->close(ctx, data_fd);
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }
    if (ops->dm_table_load(ctx, dm_fd, SPP_DIAG_DM_NAME, data_sectors, target_params) != 0) {
        ops->dm_dev_remove(ctx, dm_fd, SPP_DIAG_DM_NAME);
        ops->close(ctx, dm_fd);
        ops->close(ctx, hash_fd);
        ops->close(ctx, data_fd);
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }
    if (ops->dm_dev_suspend(ctx, dm_fd, SPP_DIAG_DM_NAME) != 0) {
        ops->dm_dev_remove(ctx, dm_fd, SPP_DIAG_DM_NAME);
        ops->close(ctx, dm_fd);
        ops->close(ctx, hash_fd);
        ops->close(ctx, data_fd);
        return SPP_DIAG_HANDOFF_ERR_VERITY;
    }
    ops->close(ctx, hash_fd);
    ops->close(ctx, data_fd);

    if (ops->mount(ctx, SPP_DIAG_DM_NODE, SPP_DIAG_ROOT_MOUNTPOINT, "squashfs", MS_RDONLY, NULL) != 0) {
        ops->dm_dev_remove(ctx, dm_fd, SPP_DIAG_DM_NAME);
        ops->close(ctx, dm_fd);
        return SPP_DIAG_HANDOFF_ERR_MOUNT_ROOT;
    }
    if (ops->statvfs_rdonly(ctx, SPP_DIAG_ROOT_MOUNTPOINT) != 1) {
        ops->umount2(ctx, SPP_DIAG_ROOT_MOUNTPOINT, 0);
        ops->dm_dev_remove(ctx, dm_fd, SPP_DIAG_DM_NAME);
        ops->close(ctx, dm_fd);
        return SPP_DIAG_HANDOFF_ERR_MOUNT_WRITABLE;
    }
    ops->close(ctx, dm_fd);

    if (ops->mount(ctx, "/proc", SPP_DIAG_ROOT_MOUNTPOINT "/proc", NULL, MS_MOVE, NULL) != 0 ||
        ops->mount(ctx, "/sys", SPP_DIAG_ROOT_MOUNTPOINT "/sys", NULL, MS_MOVE, NULL) != 0 ||
        ops->mount(ctx, "/dev", SPP_DIAG_ROOT_MOUNTPOINT "/dev", NULL, MS_MOVE, NULL) != 0) {
        return SPP_DIAG_HANDOFF_ERR_SWITCH_ROOT;
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

    int control_fd = ops->open(ctx, SPP_DIAG_TRACE_CONTROL_PATH, O_WRONLY | O_CLOEXEC, 0);
    if (control_fd < 0) {
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    if (control_fd != SPP_DIAG_TRACE_CONTROL_FD &&
        ops->dup2(ctx, control_fd, SPP_DIAG_TRACE_CONTROL_FD) != SPP_DIAG_TRACE_CONTROL_FD) {
        ops->close(ctx, control_fd);
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    if (ops->set_inheritable(ctx, SPP_DIAG_TRACE_CONTROL_FD) != 0) {
        ops->close(ctx, control_fd);
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    if (control_fd != SPP_DIAG_TRACE_CONTROL_FD) {
        ops->close(ctx, control_fd);
    }

    int stream_fd = ops->open(ctx, SPP_DIAG_TRACE_STREAM_PATH, O_RDONLY | O_CLOEXEC, 0);
    if (stream_fd < 0) {
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    if (stream_fd != SPP_DIAG_TRACE_STREAM_FD &&
        ops->dup2(ctx, stream_fd, SPP_DIAG_TRACE_STREAM_FD) != SPP_DIAG_TRACE_STREAM_FD) {
        ops->close(ctx, stream_fd);
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    if (ops->set_inheritable(ctx, SPP_DIAG_TRACE_STREAM_FD) != 0) {
        ops->close(ctx, stream_fd);
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    if (stream_fd != SPP_DIAG_TRACE_STREAM_FD) {
        ops->close(ctx, stream_fd);
    }

    int serial_fd = ops->open(ctx, SPP_DIAG_SERIAL_PATH, O_WRONLY | O_NOCTTY | O_CLOEXEC | O_NONBLOCK, 0);
    if (serial_fd < 0) {
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    if (serial_fd != SPP_DIAG_SERIAL_FD &&
        ops->dup2(ctx, serial_fd, SPP_DIAG_SERIAL_FD) != SPP_DIAG_SERIAL_FD) {
        ops->close(ctx, serial_fd);
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    if (ops->set_inheritable(ctx, SPP_DIAG_SERIAL_FD) != 0) {
        ops->close(ctx, serial_fd);
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    if (serial_fd != SPP_DIAG_SERIAL_FD) {
        ops->close(ctx, serial_fd);
    }
    if (ops->close_range(ctx, 6, UINT_MAX) != 0) {
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }

    char *argv[] = {
        (char *)SPP_DIAG_CONTROLLER_INTERP, (char *)"-I", (char *)"-B", (char *)"-S",
        (char *)SPP_DIAG_CONTROLLER_SCRIPT, NULL, NULL, NULL,
    };
    char target_profile_arg[192];
    char binding_partuuid_arg[192];
    int target_written = snprintf(target_profile_arg, sizeof(target_profile_arg), "sol_spp_diag.target_profile=%s", fields.target_profile);
    int binding_written = snprintf(binding_partuuid_arg, sizeof(binding_partuuid_arg), "sol_spp_diag.binding_partuuid=%s", fields.binding_partuuid);
    if (target_written < 0 || (size_t)target_written >= sizeof(target_profile_arg) ||
        binding_written < 0 || (size_t)binding_written >= sizeof(binding_partuuid_arg)) {
        return SPP_DIAG_HANDOFF_ERR_EXEC;
    }
    argv[5] = target_profile_arg;
    argv[6] = binding_partuuid_arg;
    char *envp[] = {
        (char *)"LANG=C", (char *)"LC_ALL=C", (char *)"TZ=UTC", NULL,
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

static ssize_t real_pread(void *ctx, int fd, void *buf, size_t count, off_t offset) {
    (void)ctx;
    return pread(fd, buf, count, offset);
}

static int real_resolve_partuuid(
    void *ctx,
    const char *partuuid,
    char *out_device_id,
    size_t out_size,
    dev_t *out_rdev,
    int *out_fd
) {
    (void)ctx;
    glob_t paths;
    memset(&paths, 0, sizeof(paths));
    int glob_rc = glob("/sys/class/block/*/uevent", GLOB_NOSORT, NULL, &paths);
    if (glob_rc != 0) {
        globfree(&paths);
        return -1;
    }
    int found = 0;
    int selected_fd = -1;
    dev_t selected_rdev = 0;
    for (size_t i = 0; i < paths.gl_pathc; i++) {
        int fd = open(paths.gl_pathv[i], O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            goto fail;
        }
        char uevent[4096];
        ssize_t n = read(fd, uevent, sizeof(uevent) - 1);
        int saved_errno = errno;
        if (close(fd) != 0 || n < 0 || n == (ssize_t)(sizeof(uevent) - 1)) {
            errno = saved_errno;
            goto fail;
        }
        uevent[n] = '\0';
        const char *matched_uuid = NULL;
        const char *devname = NULL;
        char *save = NULL;
        char *line = strtok_r(uevent, "\n", &save);
        while (line != NULL) {
            if (strncmp(line, "PARTUUID=", 9) == 0) {
                matched_uuid = line + 9;
            } else if (strncmp(line, "DEVNAME=", 8) == 0) {
                devname = line + 8;
            }
            line = strtok_r(NULL, "\n", &save);
        }
        if (matched_uuid == NULL || strcmp(matched_uuid, partuuid) != 0) {
            continue;
        }
        if (found || devname == NULL || *devname == '\0' || strchr(devname, '/') != NULL) {
            goto fail;
        }
        for (const unsigned char *p = (const unsigned char *)devname; *p != '\0'; p++) {
            if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-')) {
                goto fail;
            }
        }
        char device_path[256];
        int written = snprintf(device_path, sizeof(device_path), "/dev/%s", devname);
        if (written < 0 || (size_t)written >= sizeof(device_path)) {
            goto fail;
        }
        int device_fd = open(device_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (device_fd < 0) {
            goto fail;
        }
        struct stat st;
        int stat_rc = fstat(device_fd, &st);
        if (stat_rc != 0 || !S_ISBLK(st.st_mode)) {
            close(device_fd);
            goto fail;
        }
        selected_rdev = st.st_rdev;
        selected_fd = device_fd;
        found = 1;
    }
    globfree(&paths);
    if (!found) {
        return -1;
    }
    int written = snprintf(out_device_id, out_size, "%u:%u", major(selected_rdev), minor(selected_rdev));
    if (written < 0 || (size_t)written >= out_size) {
        close(selected_fd);
        return -1;
    }
    *out_rdev = selected_rdev;
    *out_fd = selected_fd;
    return 0;

fail:
    globfree(&paths);
    if (selected_fd >= 0) {
        close(selected_fd);
    }
    return -1;
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
    if (ioctl(fd, DM_DEV_CREATE, &io) != 0 || io.dev == 0) {
        return -1;
    }
    if (mknod(SPP_DIAG_DM_NODE, S_IFBLK | 0600, (dev_t)io.dev) != 0) {
        struct dm_ioctl remove_io;
        memset(&remove_io, 0, sizeof(remove_io));
        remove_io.version[0] = DM_VERSION_MAJOR;
        remove_io.version[1] = DM_VERSION_MINOR;
        remove_io.version[2] = DM_VERSION_PATCHLEVEL;
        remove_io.data_size = sizeof(remove_io);
        remove_io.data_start = sizeof(remove_io);
        strncpy(remove_io.name, name, sizeof(remove_io.name) - 1);
        ioctl(fd, DM_DEV_REMOVE, &remove_io);
        return -1;
    }
    return 0;
}

static int real_dm_dev_remove(void *ctx, int fd, const char *name) {
    (void)ctx;
    struct dm_ioctl io;
    memset(&io, 0, sizeof(io));
    io.version[0] = DM_VERSION_MAJOR;
    io.version[1] = DM_VERSION_MINOR;
    io.version[2] = DM_VERSION_PATCHLEVEL;
    io.data_size = sizeof(io);
    io.data_start = sizeof(io);
    strncpy(io.name, name, sizeof(io.name) - 1);
    if (ioctl(fd, DM_DEV_REMOVE, &io) != 0) {
        return -1;
    }
    return unlink(SPP_DIAG_DM_NODE);
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

static int real_umount2(void *ctx, const char *target, int flags) {
    (void)ctx;
    return umount2(target, flags);
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

static int real_set_inheritable(void *ctx, int fd) {
    (void)ctx;
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC);
}

static int real_close_range(void *ctx, unsigned int first, unsigned int last) {
    (void)ctx;
    return close_range(first, last, 0);
}

static int real_execve(void *ctx, const char *path, char *const argv[], char *const envp[]) {
    (void)ctx;
    return execve(path, argv, envp);
}

static const struct spp_diag_handoff_ops g_real_ops = {
    .open = real_open,
    .close = real_close,
    .read = real_read,
    .pread = real_pread,
    .resolve_partuuid = real_resolve_partuuid,
    .blkgetsize64 = real_blkgetsize64,
    .dm_dev_create = real_dm_dev_create,
    .dm_dev_remove = real_dm_dev_remove,
    .dm_table_load = real_dm_table_load,
    .dm_dev_suspend = real_dm_dev_suspend,
    .mount = real_mount,
    .umount2 = real_umount2,
    .chdir = real_chdir,
    .chroot = real_chroot,
    .statvfs_rdonly = real_statvfs_rdonly,
    .dup2 = real_dup2,
    .set_inheritable = real_set_inheritable,
    .close_range = real_close_range,
    .execve = real_execve,
};

/* ------------------------------------------------------------------ */
/* Test harness -- compiled only into the dedicated fixture binary.    */
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

#ifdef SPP_DIAG_HANDOFF_TEST

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
    (void)mode;
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "open");
    int result = spp_diag_harness_field_int(line, "result", -1);
    char detail[2200];
    snprintf(detail, sizeof(detail), "path=%s\tflags=%d", path, flags);
    if (result >= 0) {
        const char *data = spp_diag_harness_field(line, "data");
        const char *exact_fd = spp_diag_harness_field(line, "exact_fd");
        if (hctx->fake_fd_count >= SPP_DIAG_HARNESS_MAX_FAKE_FDS) {
            spp_diag_harness_unexpected(hctx, "open");
        }
        struct spp_diag_harness_fake_fd *entry = &hctx->fake_fds[hctx->fake_fd_count++];
        entry->fd = exact_fd != NULL ? atoi(exact_fd) : 1000 + hctx->next_fake_fd++;
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

static ssize_t spp_diag_harness_pread(void *ctx, int fd, void *buf, size_t count, off_t offset) {
    (void)fd;
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "pread");
    int result = spp_diag_harness_field_int(line, "result", -1);
    char detail[128];
    snprintf(detail, sizeof(detail), "count=%zu\toffset=%lld", count, (long long)offset);
    spp_diag_harness_log(hctx, "pread", detail, result);
    if (result != 0 || count < 512 || offset != 0) {
        return -1;
    }
    const char *bytes_hex = spp_diag_harness_field(line, "bytes_hex");
    if (bytes_hex == NULL || strlen(bytes_hex) != 1024) {
        return -1;
    }
    unsigned char *header = (unsigned char *)buf;
    for (size_t i = 0; i < 512; i++) {
        char byte_text[3] = {bytes_hex[i * 2], bytes_hex[i * 2 + 1], '\0'};
        if (!isxdigit((unsigned char)byte_text[0]) || !isxdigit((unsigned char)byte_text[1])) {
            return -1;
        }
        header[i] = (unsigned char)strtoul(byte_text, NULL, 16);
    }
    return 512;
}

static int spp_diag_harness_resolve_partuuid(
    void *ctx,
    const char *partuuid,
    char *out_device_id,
    size_t out_size,
    dev_t *out_rdev,
    int *out_fd
) {
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "resolve_partuuid");
    int result = spp_diag_harness_field_int(line, "result", -1);
    char detail[256];
    snprintf(detail, sizeof(detail), "partuuid=%s", partuuid);
    spp_diag_harness_log(hctx, "resolve_partuuid", detail, result);
    const char *device_id = spp_diag_harness_field(line, "device_id");
    const char *rdev_text = spp_diag_harness_field(line, "rdev");
    const char *fd_text = spp_diag_harness_field(line, "fd");
    if (result != 0 || device_id == NULL || rdev_text == NULL || fd_text == NULL ||
        strlen(device_id) >= out_size) {
        return -1;
    }
    strcpy(out_device_id, device_id);
    *out_rdev = (dev_t)strtoull(rdev_text, NULL, 10);
    *out_fd = atoi(fd_text);
    return 0;
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

static int spp_diag_harness_dm_dev_remove(void *ctx, int fd, const char *name) {
    (void)fd;
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "dm_dev_remove");
    int result = spp_diag_harness_field_int(line, "result", 0);
    char detail[128];
    snprintf(detail, sizeof(detail), "name=%s", name);
    spp_diag_harness_log(hctx, "dm_dev_remove", detail, result);
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

static int spp_diag_harness_umount2(void *ctx, const char *target, int flags) {
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "umount2");
    int result = spp_diag_harness_field_int(line, "result", 0);
    char detail[256];
    snprintf(detail, sizeof(detail), "target=%s\tflags=%d", target, flags);
    spp_diag_harness_log(hctx, "umount2", detail, result);
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

static int spp_diag_harness_set_inheritable(void *ctx, int fd) {
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "set_inheritable");
    int result = spp_diag_harness_field_int(line, "result", 0);
    char detail[64];
    snprintf(detail, sizeof(detail), "fd=%d", fd);
    spp_diag_harness_log(hctx, "set_inheritable", detail, result);
    return result;
}

static int spp_diag_harness_close_range(void *ctx, unsigned int first, unsigned int last) {
    struct spp_diag_harness_ctx *hctx = (struct spp_diag_harness_ctx *)ctx;
    struct spp_diag_harness_line *line = spp_diag_harness_next(hctx, "close_range");
    int result = spp_diag_harness_field_int(line, "result", 0);
    char detail[128];
    snprintf(detail, sizeof(detail), "first=%u\tlast=%u", first, last);
    spp_diag_harness_log(hctx, "close_range", detail, result);
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
    .pread = spp_diag_harness_pread,
    .resolve_partuuid = spp_diag_harness_resolve_partuuid,
    .blkgetsize64 = spp_diag_harness_blkgetsize64,
    .dm_dev_create = spp_diag_harness_dm_dev_create,
    .dm_dev_remove = spp_diag_harness_dm_dev_remove,
    .dm_table_load = spp_diag_harness_dm_table_load,
    .dm_dev_suspend = spp_diag_harness_dm_dev_suspend,
    .mount = spp_diag_harness_mount,
    .umount2 = spp_diag_harness_umount2,
    .chdir = spp_diag_harness_chdir,
    .chroot = spp_diag_harness_chroot,
    .statvfs_rdonly = spp_diag_harness_statvfs_rdonly,
    .dup2 = spp_diag_harness_dup2,
    .set_inheritable = spp_diag_harness_set_inheritable,
    .close_range = spp_diag_harness_close_range,
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

#endif

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    const struct spp_diag_handoff_ops *ops = &g_real_ops;
    void *ctx = NULL;
#ifdef SPP_DIAG_HANDOFF_TEST
    const char *harness = getenv("SPP_DIAG_HANDOFF_TEST_HARNESS");
    if (harness != NULL) {
        ops = spp_diag_handoff_load_test_harness(harness, &ctx);
        if (ops == NULL) {
            return 90;
        }
    }
#endif
    int rc = spp_diag_handoff_run(ops, ctx);
    return rc;
}
