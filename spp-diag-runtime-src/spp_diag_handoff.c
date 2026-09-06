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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
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

#ifndef SPP_R1_SYSTEMD_INIT
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
#endif

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

#ifdef SPP_R1_SYSTEMD_INIT
/*
 * R1 minimal sealed image: a lenient command-line parser. The R1 appliance
 * needs only the verity root: the data-partition PARTUUID, the hash-partition
 * PARTUUID, and the verity root hash. It carries no trace/diagnostic tokens,
 * and it tolerates ordinary kernel tokens (ro, root=, rootfstype=, console=,
 * ip=off, ...) that the strict diagnostic parser rejected. Values are validated
 * exactly as the diagnostic parser validates its own.
 */
static int spp_r1_parse_cmdline(char *cmdline, struct spp_diag_cmdline_fields *fields) {
    memset(fields, 0, sizeof(*fields));
    int have_data = 0;
    int have_hash = 0;
    int have_roothash = 0;
    char *save = NULL;
    for (char *tok = strtok_r(cmdline, " \t", &save); tok != NULL; tok = strtok_r(NULL, " \t", &save)) {
        if (spp_diag_copy_value(fields->data_partuuid, sizeof(fields->data_partuuid), tok,
                                "spp_diag.root_data=PARTUUID=") == 0) {
            have_data = 1;
        } else if (spp_diag_copy_value(fields->hash_partuuid, sizeof(fields->hash_partuuid), tok,
                                       "spp_diag.root_hash=PARTUUID=") == 0) {
            have_hash = 1;
        } else if (spp_diag_copy_value(fields->root_hash, sizeof(fields->root_hash), tok,
                                       "spp_diag.roothash=") == 0) {
            have_roothash = 1;
        }
    }
    if (!have_data || !have_hash || !have_roothash) {
        return -1;
    }
    if (!spp_diag_is_partuuid(fields->data_partuuid) || !spp_diag_is_partuuid(fields->hash_partuuid) ||
        !spp_diag_is_lower_hex(fields->root_hash, 64) ||
        strcmp(fields->data_partuuid, fields->hash_partuuid) == 0) {
        return -1;
    }
    return 0;
}
#else
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
#endif

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
#ifdef SPP_R1_SYSTEMD_INIT
    if (spp_r1_parse_cmdline(cmdline, &fields) != 0) {
        return SPP_DIAG_HANDOFF_ERR_CMDLINE_MALFORMED;
    }
#else
    if (spp_diag_parse_cmdline(cmdline, &fields) != 0) {
        return SPP_DIAG_HANDOFF_ERR_CMDLINE_MALFORMED;
    }
#endif

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

#ifdef SPP_R1_SYSTEMD_INIT
    /*
     * R1 minimal sealed image (founder decision 2026-09-06). The verity root
     * is mounted read-only and is measured through the signed UKI at PCR 4; no
     * trace plane and no diagnostic controller run. Close everything above the
     * inherited console (0/1/2) and hand PID 1 to the baked systemd, which
     * brings up the sealed serving cohort from the immutable rootfs. The
     * deferred trace/controller handoff is the #else branch below and is
     * unchanged for the default diagnostic build.
     */
    if (ops->close_range(ctx, 3, UINT_MAX) != 0) {
        return SPP_DIAG_HANDOFF_ERR_FD_SETUP;
    }
    {
        char *r1_argv[] = {(char *)"/sbin/init", NULL};
        char *r1_envp[] = {NULL};
        ops->execve(ctx, "/sbin/init", r1_argv, r1_envp);
    }
    return SPP_DIAG_HANDOFF_ERR_EXEC;
#else
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
#endif
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

/*
 * Sysfs tells us which kernel partition belongs to which disk; GPT bytes tell
 * us which UUID it has.  In particular, neither a sysfs name nor a uevent
 * PARTUUID is ever an authority for this resolver.
 *
 * The roots/bindings argument is deliberately a direct-call fixture seam.  It
 * has no environment switch and is not used by the production wrapper below.
 */
#define SPP_DIAG_GPT_SECTOR 512U
#define SPP_DIAG_GPT_ENTRIES 128U
#define SPP_DIAG_GPT_ENTRY_SIZE 128U
#define SPP_DIAG_GPT_ARRAY_BYTES (SPP_DIAG_GPT_ENTRIES * SPP_DIAG_GPT_ENTRY_SIZE)
#define SPP_DIAG_GPT_ARRAY_SECTORS (SPP_DIAG_GPT_ARRAY_BYTES / SPP_DIAG_GPT_SECTOR)
#define SPP_DIAG_GPT_MAX_METADATA_BYTES (64U * 1024U)
#define SPP_DIAG_GPT_MAX_DISKS 256U
#define SPP_DIAG_GPT_MAX_CLASS 65536U
#define SPP_DIAG_GPT_MAX_ANCESTORS 64U

struct spp_diag_fixture_node_binding {
    unsigned int major_number;
    unsigned int minor_number;
    dev_t st_dev;
    ino_t st_ino;
};

struct spp_diag_resolver_roots {
    const char *class_block_root;
    const char *dev_block_root;
    const char *virtual_root;
    const char *device_root;
    const struct spp_diag_fixture_node_binding *fixture_bindings;
    size_t fixture_binding_count;
};

struct spp_diag_sysfs_identity {
    dev_t st_dev;
    ino_t st_ino;
};

struct spp_diag_resolver_disk {
    struct spp_diag_sysfs_identity object;
    unsigned int major_number;
    unsigned int minor_number;
    char devname[128];
    unsigned char part_seen[SPP_DIAG_GPT_ENTRIES];
};

struct spp_diag_resolver_part {
    struct spp_diag_sysfs_identity parent;
    unsigned int major_number;
    unsigned int minor_number;
    unsigned int number;
    uint64_t start;
    uint64_t size;
    char devname[128];
};

struct spp_diag_gpt_header {
    uint32_t header_size;
    uint64_t current_lba;
    uint64_t alternate_lba;
    uint64_t first_usable;
    uint64_t last_usable;
    uint64_t array_lba;
    uint32_t array_crc;
    unsigned char disk_guid[16];
};

struct spp_diag_gpt_match {
    struct spp_diag_sysfs_identity disk;
    unsigned int number;
    uint64_t start;
    uint64_t size;
};

static uint32_t spp_diag_crc32(const unsigned char *data, size_t size) {
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for (unsigned int bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ ((crc & 1U) ? UINT32_C(0xedb88320) : 0U);
        }
    }
    return ~crc;
}

static int spp_diag_u64_add(uint64_t left, uint64_t right, uint64_t *out) {
    if (left > UINT64_MAX - right) {
        return -1;
    }
    *out = left + right;
    return 0;
}

static int spp_diag_u64_mul(uint64_t left, uint64_t right, uint64_t *out) {
    if (left != 0 && right > UINT64_MAX / left) {
        return -1;
    }
    *out = left * right;
    return 0;
}

static int spp_diag_identity_equal(struct spp_diag_sysfs_identity left, struct spp_diag_sysfs_identity right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino;
}

static int spp_diag_fd_identity(int fd, struct spp_diag_sysfs_identity *out) {
    struct stat st;
    if (fstat(fd, &st) != 0) {
        return -1;
    }
    out->st_dev = st.st_dev;
    out->st_ino = st.st_ino;
    return 0;
}

static int spp_diag_read_exact_at(int fd, unsigned char *out, size_t count, uint64_t offset, uint64_t size) {
    uint64_t end;
    if (spp_diag_u64_add(offset, (uint64_t)count, &end) != 0 || end > size || offset > (uint64_t)INT64_MAX) {
        return -1;
    }
    size_t done = 0;
    while (done < count) {
        ssize_t got = pread(fd, out + done, count - done, (off_t)(offset + done));
        if (got <= 0) {
            return -1;
        }
        done += (size_t)got;
    }
    return 0;
}

static int spp_diag_read_text_at(int directory_fd, const char *name, char *out, size_t out_size) {
    if (out_size < 2) {
        return -1;
    }
    int fd = openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    struct stat st;
    size_t used = 0;
    int result = -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        goto done;
    }
    while (used < out_size - 1) {
        ssize_t got = read(fd, out + used, out_size - 1 - used);
        if (got < 0) {
            goto done;
        }
        if (got == 0) {
            out[used] = '\0';
            result = 0;
            goto done;
        }
        used += (size_t)got;
    }
    {
        unsigned char extra;
        if (read(fd, &extra, 1) != 0) {
            goto done;
        }
    }
    out[used] = '\0';
    result = 0;
done:
    if (close(fd) != 0) {
        result = -1;
    }
    return result;
}

static int spp_diag_parse_uint(const char *value, uint64_t maximum, uint64_t *out) {
    if (value == NULL || *value == '\0') {
        return -1;
    }
    uint64_t result = 0;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
        if (*p < '0' || *p > '9' || result > (maximum - (uint64_t)(*p - '0')) / 10U) {
            return -1;
        }
        result = result * 10U + (uint64_t)(*p - '0');
    }
    *out = result;
    return 0;
}

static int spp_diag_parse_dev_text(const char *text, unsigned int *major_number, unsigned int *minor_number) {
    char copy[64];
    size_t length = strlen(text);
    if (length == 0 || length >= sizeof(copy)) {
        return -1;
    }
    memcpy(copy, text, length + 1);
    while (length > 0 && (copy[length - 1] == '\n' || copy[length - 1] == '\r')) {
        copy[--length] = '\0';
    }
    char *colon = strchr(copy, ':');
    uint64_t major_value;
    uint64_t minor_value;
    if (colon == NULL || strchr(colon + 1, ':') != NULL) {
        return -1;
    }
    *colon = '\0';
    if (spp_diag_parse_uint(copy, UINT32_MAX, &major_value) != 0 ||
        spp_diag_parse_uint(colon + 1, UINT32_MAX, &minor_value) != 0) {
        return -1;
    }
    *major_number = (unsigned int)major_value;
    *minor_number = (unsigned int)minor_value;
    return 0;
}

static int spp_diag_read_dev_at(int directory_fd, unsigned int *major_number, unsigned int *minor_number) {
    char text[64];
    return spp_diag_read_text_at(directory_fd, "dev", text, sizeof(text)) == 0
        ? spp_diag_parse_dev_text(text, major_number, minor_number) : -1;
}

static int spp_diag_optional_uint_at(int directory_fd, const char *name, uint64_t *out, int *present) {
    int fd = openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno == ENOENT) {
            *present = 0;
            return 0;
        }
        return -1;
    }
    char text[64];
    struct stat st;
    ssize_t got;
    int result = -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (got = read(fd, text, sizeof(text) - 1)) < 0 || got == (ssize_t)(sizeof(text) - 1)) {
        goto done;
    }
    text[got] = '\0';
    while (got > 0 && (text[got - 1] == '\n' || text[got - 1] == '\r')) {
        text[--got] = '\0';
    }
    if (spp_diag_parse_uint(text, UINT64_MAX, out) != 0) {
        goto done;
    }
    *present = 1;
    result = 0;
done:
    if (close(fd) != 0) {
        result = -1;
    }
    return result;
}

struct spp_diag_uevent {
    char devname[128];
    char devtype[32];
    unsigned int major_number;
    unsigned int minor_number;
    uint64_t partn;
    int has_partn;
};

static int spp_diag_copy_field(char *out, size_t out_size, const char *value) {
    size_t length = strlen(value);
    if (length == 0 || length >= out_size) {
        return -1;
    }
    memcpy(out, value, length + 1);
    return 0;
}

static int spp_diag_safe_devname(const char *value) {
    if (value == NULL || *value == '\0') {
        return -1;
    }
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
        if (!(isalnum(*p) || *p == '.' || *p == '_' || *p == '-')) {
            return -1;
        }
    }
    return 0;
}

static int spp_diag_read_uevent(int directory_fd, struct spp_diag_uevent *out) {
    char text[4097];
    unsigned int seen = 0;
    memset(out, 0, sizeof(*out));
    if (spp_diag_read_text_at(directory_fd, "uevent", text, sizeof(text)) != 0) {
        return -1;
    }
    char *save = NULL;
    for (char *line = strtok_r(text, "\n", &save); line != NULL; line = strtok_r(NULL, "\n", &save)) {
        char *equals = strchr(line, '=');
        if (equals == NULL || equals == line) {
            return -1;
        }
        *equals = '\0';
        const char *value = equals + 1;
        uint64_t number;
        if (strcmp(line, "DEVNAME") == 0) {
            if ((seen & 1U) != 0 || spp_diag_copy_field(out->devname, sizeof(out->devname), value) != 0) return -1;
            seen |= 1U;
        } else if (strcmp(line, "DEVTYPE") == 0) {
            if ((seen & 2U) != 0 || spp_diag_copy_field(out->devtype, sizeof(out->devtype), value) != 0) return -1;
            seen |= 2U;
        } else if (strcmp(line, "MAJOR") == 0) {
            if ((seen & 4U) != 0 || spp_diag_parse_uint(value, UINT32_MAX, &number) != 0) return -1;
            out->major_number = (unsigned int)number;
            seen |= 4U;
        } else if (strcmp(line, "MINOR") == 0) {
            if ((seen & 8U) != 0 || spp_diag_parse_uint(value, UINT32_MAX, &number) != 0) return -1;
            out->minor_number = (unsigned int)number;
            seen |= 8U;
        } else if (strcmp(line, "PARTN") == 0) {
            if ((seen & 16U) != 0 || spp_diag_parse_uint(value, SPP_DIAG_GPT_ENTRIES, &out->partn) != 0) return -1;
            out->has_partn = 1;
            seen |= 16U;
        }
    }
    return (seen & 15U) == 15U && spp_diag_safe_devname(out->devname) == 0 ? 0 : -1;
}

static int spp_diag_is_virtual_ancestor(int fd, struct spp_diag_sysfs_identity virtual_root) {
    int current = dup(fd);
    if (current < 0) {
        return -1;
    }
    for (unsigned int depth = 0; depth < SPP_DIAG_GPT_MAX_ANCESTORS; depth++) {
        struct spp_diag_sysfs_identity current_identity;
        struct spp_diag_sysfs_identity parent_identity;
        int parent;
        if (spp_diag_fd_identity(current, &current_identity) != 0) {
            close(current);
            return -1;
        }
        if (spp_diag_identity_equal(current_identity, virtual_root)) {
            close(current);
            return 1;
        }
        parent = openat(current, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (parent < 0 || spp_diag_fd_identity(parent, &parent_identity) != 0) {
            if (parent >= 0) close(parent);
            close(current);
            return -1;
        }
        if (spp_diag_identity_equal(current_identity, parent_identity)) {
            close(parent);
            close(current);
            return 0;
        }
        close(current);
        current = parent;
    }
    close(current);
    return -1;
}

static int spp_diag_read_disk(int fd, struct spp_diag_resolver_disk *out) {
    uint64_t ignored;
    int present;
    struct spp_diag_uevent uevent;
    if (spp_diag_optional_uint_at(fd, "partition", &ignored, &present) != 0 || present ||
        spp_diag_read_uevent(fd, &uevent) != 0 || strcmp(uevent.devtype, "disk") != 0 ||
        spp_diag_read_dev_at(fd, &out->major_number, &out->minor_number) != 0 ||
        uevent.major_number != out->major_number || uevent.minor_number != out->minor_number ||
        spp_diag_fd_identity(fd, &out->object) != 0) {
        return -1;
    }
    memcpy(out->devname, uevent.devname, sizeof(out->devname));
    return 0;
}

static int spp_diag_read_part(int fd, struct spp_diag_resolver_part *out, struct spp_diag_resolver_disk *parent) {
    uint64_t number;
    uint64_t start;
    uint64_t size;
    int present;
    struct spp_diag_uevent uevent;
    if (spp_diag_optional_uint_at(fd, "partition", &number, &present) != 0 || !present || number == 0 ||
        number > SPP_DIAG_GPT_ENTRIES || spp_diag_read_uevent(fd, &uevent) != 0 ||
        strcmp(uevent.devtype, "partition") != 0 || !uevent.has_partn || uevent.partn != number ||
        spp_diag_read_dev_at(fd, &out->major_number, &out->minor_number) != 0 ||
        uevent.major_number != out->major_number || uevent.minor_number != out->minor_number ||
        spp_diag_optional_uint_at(fd, "start", &start, &present) != 0 || !present ||
        spp_diag_optional_uint_at(fd, "size", &size, &present) != 0 || !present || size == 0 ||
        start > UINT64_MAX - (size - 1)) {
        return -1;
    }
    int parent_fd = openat(fd, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parent_fd < 0) {
        return -1;
    }
    int result = spp_diag_read_disk(parent_fd, parent);
    if (close(parent_fd) != 0) {
        result = -1;
    }
    if (result != 0) {
        return -1;
    }
    out->parent = parent->object;
    out->number = (unsigned int)number;
    out->start = start;
    out->size = size;
    memcpy(out->devname, uevent.devname, sizeof(out->devname));
    return 0;
}

static int spp_diag_find_disk(const struct spp_diag_resolver_disk *disks, size_t count, struct spp_diag_sysfs_identity object) {
    for (size_t i = 0; i < count; i++) {
        if (spp_diag_identity_equal(disks[i].object, object)) {
            return (int)i;
        }
    }
    return -1;
}

static int spp_diag_add_disk(struct spp_diag_resolver_disk *disks, size_t *count, const struct spp_diag_resolver_disk *disk) {
    int existing = spp_diag_find_disk(disks, *count, disk->object);
    if (existing >= 0) {
        if (disks[existing].major_number != disk->major_number || disks[existing].minor_number != disk->minor_number ||
            strcmp(disks[existing].devname, disk->devname) != 0) {
            return -1;
        }
        return existing;
    }
    if (*count >= SPP_DIAG_GPT_MAX_DISKS) {
        return -1;
    }
    disks[*count] = *disk;
    memset(disks[*count].part_seen, 0, sizeof(disks[*count].part_seen));
    (*count)++;
    return (int)(*count - 1);
}

static int spp_diag_collect_topology(
    const struct spp_diag_resolver_roots *roots,
    struct spp_diag_resolver_disk *disks,
    size_t *disk_count,
    const struct spp_diag_gpt_match *wanted,
    struct spp_diag_resolver_part *selected_part,
    unsigned int *selected_count
) {
    int virtual_fd = -1;
    int class_fd = -1;
    int dev_block_fd = -1;
    DIR *class_dir = NULL;
    struct spp_diag_sysfs_identity virtual_identity;
    unsigned int class_count = 0;
    int result = -1;
    *disk_count = 0;
    *selected_count = 0;
    virtual_fd = open(roots->virtual_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    class_fd = open(roots->class_block_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    dev_block_fd = open(roots->dev_block_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (virtual_fd < 0 || class_fd < 0 || dev_block_fd < 0 || spp_diag_fd_identity(virtual_fd, &virtual_identity) != 0) {
        goto done;
    }
    class_dir = fdopendir(class_fd);
    if (class_dir == NULL) {
        goto done;
    }
    class_fd = -1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(class_dir);
        if (entry == NULL) {
            if (errno != 0) {
                goto done;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (++class_count > SPP_DIAG_GPT_MAX_CLASS || strchr(entry->d_name, '/') != NULL) {
            goto done;
        }
        int class_object_fd = openat(dirfd(class_dir), entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        int physical_fd = -1;
        struct spp_diag_sysfs_identity class_identity;
        struct spp_diag_sysfs_identity physical_identity;
        unsigned int major_number;
        unsigned int minor_number;
        char dev_text[64];
        int virtual_result;
        if (class_object_fd < 0 || spp_diag_fd_identity(class_object_fd, &class_identity) != 0 ||
            spp_diag_read_dev_at(class_object_fd, &major_number, &minor_number) != 0 ||
            snprintf(dev_text, sizeof(dev_text), "%u:%u", major_number, minor_number) < 0) {
            if (class_object_fd >= 0) close(class_object_fd);
            goto done;
        }
        physical_fd = openat(dev_block_fd, dev_text, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (physical_fd < 0 || spp_diag_fd_identity(physical_fd, &physical_identity) != 0 ||
            !spp_diag_identity_equal(class_identity, physical_identity)) {
            if (physical_fd >= 0) close(physical_fd);
            close(class_object_fd);
            goto done;
        }
        if (close(class_object_fd) != 0) {
            close(physical_fd);
            goto done;
        }
        unsigned int physical_major;
        unsigned int physical_minor;
        if (spp_diag_read_dev_at(physical_fd, &physical_major, &physical_minor) != 0 ||
            physical_major != major_number || physical_minor != minor_number ||
            (virtual_result = spp_diag_is_virtual_ancestor(physical_fd, virtual_identity)) < 0) {
            close(physical_fd);
            goto done;
        }
        if (virtual_result == 0) {
            uint64_t partition_number;
            int partition_present;
            if (spp_diag_optional_uint_at(physical_fd, "partition", &partition_number, &partition_present) != 0) {
                close(physical_fd);
                goto done;
            }
            if (!partition_present) {
                struct spp_diag_resolver_disk disk;
                if (spp_diag_read_disk(physical_fd, &disk) != 0 || spp_diag_add_disk(disks, disk_count, &disk) < 0) {
                    close(physical_fd);
                    goto done;
                }
            } else {
                struct spp_diag_resolver_part part;
                struct spp_diag_resolver_disk parent;
                if (spp_diag_read_part(physical_fd, &part, &parent) != 0) {
                    close(physical_fd);
                    goto done;
                }
                int disk_index = spp_diag_add_disk(disks, disk_count, &parent);
                if (disk_index < 0 || disks[disk_index].part_seen[part.number - 1] != 0) {
                    close(physical_fd);
                    goto done;
                }
                disks[disk_index].part_seen[part.number - 1] = 1;
                if (wanted != NULL && spp_diag_identity_equal(part.parent, wanted->disk) &&
                    part.number == wanted->number && part.start == wanted->start && part.size == wanted->size) {
                    if (++*selected_count > 1) {
                        close(physical_fd);
                        goto done;
                    }
                    *selected_part = part;
                }
            }
        }
        if (close(physical_fd) != 0) {
            goto done;
        }
    }
    result = 0;
done:
    if (class_dir != NULL) {
        closedir(class_dir);
    } else if (class_fd >= 0) {
        close(class_fd);
    }
    if (dev_block_fd >= 0) close(dev_block_fd);
    if (virtual_fd >= 0) close(virtual_fd);
    return result;
}

static int spp_diag_parse_partuuid(const char *value, unsigned char out[16]) {
    unsigned char rfc[16];
    unsigned int position = 0;
    if (!spp_diag_is_partuuid(value)) {
        return -1;
    }
    for (size_t i = 0; value[i] != '\0';) {
        if (value[i] == '-') {
            i++;
            continue;
        }
        unsigned char high = (unsigned char)(isdigit((unsigned char)value[i]) ? value[i] - '0' : value[i] - 'a' + 10);
        unsigned char low = (unsigned char)(isdigit((unsigned char)value[i + 1]) ? value[i + 1] - '0' : value[i + 1] - 'a' + 10);
        rfc[position++] = (unsigned char)((high << 4) | low);
        i += 2;
    }
    if (position != sizeof(rfc)) return -1;
    out[0] = rfc[3]; out[1] = rfc[2]; out[2] = rfc[1]; out[3] = rfc[0];
    out[4] = rfc[5]; out[5] = rfc[4]; out[6] = rfc[7]; out[7] = rfc[6];
    memcpy(out + 8, rfc + 8, 8);
    return 0;
}

static int spp_diag_protective_mbr(const unsigned char mbr[SPP_DIAG_GPT_SECTOR], uint64_t final_lba) {
    unsigned int nonempty = 0;
    const unsigned char *protective = NULL;
    for (unsigned int i = 0; i < 4; i++) {
        const unsigned char *entry = mbr + 446 + i * 16;
        int empty = 1;
        for (unsigned int j = 0; j < 16; j++) if (entry[j] != 0) empty = 0;
        if (!empty) nonempty++;
        if (entry[4] == 0xee) protective = entry;
    }
    if (protective == NULL) return 0;
    if (mbr[510] != 0x55 || mbr[511] != 0xaa || nonempty != 1 || protective[0] != 0 ||
        spp_diag_le32(protective + 8) != 1 || spp_diag_le32(protective + 12) != (uint32_t)(final_lba > UINT32_MAX ? UINT32_MAX : final_lba)) {
        return -1;
    }
    return 1;
}

static int spp_diag_parse_gpt_header(
    const unsigned char data[SPP_DIAG_GPT_SECTOR], uint64_t expected_current, uint64_t final_lba, struct spp_diag_gpt_header *out
) {
    if (memcmp(data, "EFI PART", 8) != 0 || spp_diag_le32(data + 8) != UINT32_C(0x00010000)) return -1;
    uint32_t header_size = spp_diag_le32(data + 12);
    if (header_size < 92 || header_size > SPP_DIAG_GPT_SECTOR || spp_diag_le32(data + 20) != 0) return -1;
    unsigned char checked[SPP_DIAG_GPT_SECTOR];
    memcpy(checked, data, header_size);
    memset(checked + 16, 0, 4);
    if (spp_diag_crc32(checked, header_size) != spp_diag_le32(data + 16)) return -1;
    out->header_size = header_size;
    out->current_lba = spp_diag_le64(data + 24);
    out->alternate_lba = spp_diag_le64(data + 32);
    out->first_usable = spp_diag_le64(data + 40);
    out->last_usable = spp_diag_le64(data + 48);
    memcpy(out->disk_guid, data + 56, sizeof(out->disk_guid));
    out->array_lba = spp_diag_le64(data + 72);
    out->array_crc = spp_diag_le32(data + 88);
    if (out->current_lba != expected_current || out->alternate_lba > final_lba ||
        out->first_usable < 2 || out->first_usable > out->last_usable || out->last_usable >= final_lba ||
        spp_diag_le32(data + 80) != SPP_DIAG_GPT_ENTRIES || spp_diag_le32(data + 84) != SPP_DIAG_GPT_ENTRY_SIZE ||
        out->array_lba == 0 || out->array_lba > final_lba || !memcmp(out->disk_guid, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16)) return -1;
    uint64_t array_end;
    return spp_diag_u64_add(out->array_lba, SPP_DIAG_GPT_ARRAY_SECTORS - 1, &array_end) == 0 && array_end <= final_lba ? 0 : -1;
}

static int spp_diag_gpt_ranges_valid(const struct spp_diag_gpt_header *first, const struct spp_diag_gpt_header *second, uint64_t final_lba) {
    uint64_t first_end;
    uint64_t second_end;
    if (first->alternate_lba != final_lba || second->alternate_lba != 1 || first->header_size != second->header_size ||
        first->first_usable != second->first_usable || first->last_usable != second->last_usable ||
        first->array_crc != second->array_crc || memcmp(first->disk_guid, second->disk_guid, 16) != 0 ||
        spp_diag_u64_add(first->array_lba, SPP_DIAG_GPT_ARRAY_SECTORS - 1, &first_end) != 0 ||
        spp_diag_u64_add(second->array_lba, SPP_DIAG_GPT_ARRAY_SECTORS - 1, &second_end) != 0) return -1;
    uint64_t starts[2] = {first->array_lba, second->array_lba};
    uint64_t ends[2] = {first_end, second_end};
    for (unsigned int i = 0; i < 2; i++) {
        if (starts[i] == 0 || (starts[i] <= 1 && 1 <= ends[i]) || (starts[i] <= final_lba && final_lba <= ends[i]) ||
            !(ends[i] < first->first_usable || starts[i] > first->last_usable)) return -1;
    }
    return first_end < second->array_lba || second_end < first->array_lba ? 0 : -1;
}

static int spp_diag_fixture_binding(
    const struct spp_diag_resolver_roots *roots, unsigned int major_number, unsigned int minor_number, const struct stat *st
) {
    if (roots->fixture_bindings == NULL) {
        return S_ISBLK(st->st_mode) && st->st_rdev == makedev(major_number, minor_number) ? 0 : -1;
    }
    for (size_t i = 0; i < roots->fixture_binding_count; i++) {
        const struct spp_diag_fixture_node_binding *binding = &roots->fixture_bindings[i];
        if (binding->major_number == major_number && binding->minor_number == minor_number) {
            return S_ISREG(st->st_mode) && st->st_dev == binding->st_dev && st->st_ino == binding->st_ino ? 0 : -1;
        }
    }
    return -1;
}

static int spp_diag_open_node(
    const struct spp_diag_resolver_roots *roots, const char *devname, unsigned int major_number, unsigned int minor_number,
    int *out_fd, uint64_t *out_size
) {
    char path[PATH_MAX];
    struct stat before;
    struct stat opened;
    uint64_t size;
    int written = snprintf(path, sizeof(path), "%s/%s", roots->device_root, devname);
    if (written < 0 || (size_t)written >= sizeof(path) || lstat(path, &before) != 0) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    int result = -1;
    if (fstat(fd, &opened) != 0 || before.st_dev != opened.st_dev || before.st_ino != opened.st_ino ||
        spp_diag_fixture_binding(roots, major_number, minor_number, &opened) != 0) goto done;
    if (roots->fixture_bindings != NULL) {
        if (opened.st_size < 0) goto done;
        size = (uint64_t)opened.st_size;
    } else {
        int sector_size = 0;
        if (ioctl(fd, BLKSSZGET, &sector_size) != 0 || sector_size != (int)SPP_DIAG_GPT_SECTOR || ioctl(fd, BLKGETSIZE64, &size) != 0) goto done;
    }
    *out_fd = fd;
    *out_size = size;
    return 0;
done:
    close(fd);
    return result;
}

static int spp_diag_revalidate_node(
    const struct spp_diag_resolver_roots *roots, int fd, unsigned int major_number, unsigned int minor_number, const struct stat *expected
) {
    struct stat st;
    return fstat(fd, &st) == 0 && st.st_dev == expected->st_dev && st.st_ino == expected->st_ino &&
        spp_diag_fixture_binding(roots, major_number, minor_number, &st) == 0 ? 0 : -1;
}

static int spp_diag_scan_disk(
    const struct spp_diag_resolver_roots *roots, const struct spp_diag_resolver_disk *disk, const unsigned char wanted[16],
    struct spp_diag_gpt_match *match, int *found
) {
    int fd = -1;
    uint64_t size;
    unsigned char mbr[SPP_DIAG_GPT_SECTOR];
    unsigned char primary[SPP_DIAG_GPT_SECTOR];
    unsigned char backup[SPP_DIAG_GPT_SECTOR];
    unsigned char first_array[SPP_DIAG_GPT_ARRAY_BYTES];
    unsigned char second_array[SPP_DIAG_GPT_ARRAY_BYTES];
    struct stat selected_stat;
    int result = -1;
    *found = 0;
    if (3U * SPP_DIAG_GPT_SECTOR + 2U * SPP_DIAG_GPT_ARRAY_BYTES > SPP_DIAG_GPT_MAX_METADATA_BYTES) goto done;
    if (spp_diag_open_node(roots, disk->devname, disk->major_number, disk->minor_number, &fd, &size) != 0 ||
        fstat(fd, &selected_stat) != 0 || size < 2 * SPP_DIAG_GPT_SECTOR || size % SPP_DIAG_GPT_SECTOR != 0) goto done;
    uint64_t final_lba = size / SPP_DIAG_GPT_SECTOR - 1;
    uint64_t final_offset;
    if (spp_diag_u64_mul(final_lba, SPP_DIAG_GPT_SECTOR, &final_offset) != 0 ||
        spp_diag_read_exact_at(fd, mbr, sizeof(mbr), 0, size) != 0 ||
        spp_diag_read_exact_at(fd, primary, sizeof(primary), SPP_DIAG_GPT_SECTOR, size) != 0 ||
        spp_diag_read_exact_at(fd, backup, sizeof(backup), final_offset, size) != 0) goto done;
    int protective = spp_diag_protective_mbr(mbr, final_lba);
    int marked = protective != 0 || memcmp(primary, "EFI PART", 8) == 0 || memcmp(backup, "EFI PART", 8) == 0;
    if (!marked) {
        result = 0;
        goto done;
    }
    if (protective != 1 || memcmp(primary, "EFI PART", 8) != 0 || memcmp(backup, "EFI PART", 8) != 0) goto done;
    struct spp_diag_gpt_header first;
    struct spp_diag_gpt_header second;
    if (spp_diag_parse_gpt_header(primary, 1, final_lba, &first) != 0 ||
        spp_diag_parse_gpt_header(backup, final_lba, final_lba, &second) != 0 ||
        spp_diag_gpt_ranges_valid(&first, &second, final_lba) != 0) goto done;
    uint64_t first_offset;
    uint64_t second_offset;
    if (spp_diag_u64_mul(first.array_lba, SPP_DIAG_GPT_SECTOR, &first_offset) != 0 ||
        spp_diag_u64_mul(second.array_lba, SPP_DIAG_GPT_SECTOR, &second_offset) != 0 ||
        spp_diag_read_exact_at(fd, first_array, sizeof(first_array), first_offset, size) != 0 ||
        spp_diag_read_exact_at(fd, second_array, sizeof(second_array), second_offset, size) != 0 ||
        spp_diag_crc32(first_array, sizeof(first_array)) != first.array_crc ||
        spp_diag_crc32(second_array, sizeof(second_array)) != second.array_crc || memcmp(first_array, second_array, sizeof(first_array)) != 0) goto done;
    unsigned char entry_guids[SPP_DIAG_GPT_ENTRIES][16];
    uint64_t starts[SPP_DIAG_GPT_ENTRIES];
    uint64_t ends[SPP_DIAG_GPT_ENTRIES];
    size_t used = 0;
    for (unsigned int index = 0; index < SPP_DIAG_GPT_ENTRIES; index++) {
        const unsigned char *entry = first_array + index * SPP_DIAG_GPT_ENTRY_SIZE;
        int type_zero = 1;
        int entry_zero = 1;
        for (unsigned int i = 0; i < 16; i++) if (entry[i] != 0) type_zero = 0;
        for (unsigned int i = 0; i < SPP_DIAG_GPT_ENTRY_SIZE; i++) if (entry[i] != 0) entry_zero = 0;
        if (type_zero) {
            if (!entry_zero) goto done;
            continue;
        }
        int unique_zero = 1;
        for (unsigned int i = 0; i < 16; i++) if (entry[16 + i] != 0) unique_zero = 0;
        uint64_t start = spp_diag_le64(entry + 32);
        uint64_t end = spp_diag_le64(entry + 40);
        if (unique_zero || start > end || start < first.first_usable || end > first.last_usable) goto done;
        for (size_t other = 0; other < used; other++) {
            if (memcmp(entry + 16, entry_guids[other], 16) == 0 || !(end < starts[other] || start > ends[other])) goto done;
        }
        memcpy(entry_guids[used], entry + 16, 16);
        starts[used] = start;
        ends[used] = end;
        used++;
        if (memcmp(entry + 16, wanted, 16) == 0) {
            if (*found) goto done;
            uint64_t entry_size;
            if (spp_diag_u64_add(end - start, 1, &entry_size) != 0) goto done;
            match->disk = disk->object;
            match->number = index + 1;
            match->start = start;
            match->size = entry_size;
            *found = 1;
        }
    }
    result = spp_diag_revalidate_node(roots, fd, disk->major_number, disk->minor_number, &selected_stat);
done:
    if (fd >= 0 && close(fd) != 0) result = -1;
    return result;
}

static int spp_diag_resolve_partuuid_at(
    const struct spp_diag_resolver_roots *roots, const char *partuuid, char *out_device_id, size_t out_size, dev_t *out_rdev, int *out_fd
) {
    struct spp_diag_resolver_disk first[SPP_DIAG_GPT_MAX_DISKS];
    struct spp_diag_resolver_disk second[SPP_DIAG_GPT_MAX_DISKS];
    struct spp_diag_resolver_part selected_part;
    struct spp_diag_gpt_match winning;
    unsigned char wanted[16];
    size_t first_count;
    size_t second_count;
    unsigned int ignored_selected;
    unsigned int selected_count;
    int matching_disks = 0;
    if (roots == NULL || out_device_id == NULL || out_rdev == NULL || out_fd == NULL ||
        spp_diag_parse_partuuid(partuuid, wanted) != 0 ||
        spp_diag_collect_topology(roots, first, &first_count, NULL, NULL, &ignored_selected) != 0) return -1;
    for (size_t i = 0; i < first_count; i++) {
        struct spp_diag_gpt_match candidate;
        int found;
        if (spp_diag_scan_disk(roots, &first[i], wanted, &candidate, &found) != 0) return -1;
        if (found && ++matching_disks > 1) return -1;
        if (found) winning = candidate;
    }
    if (matching_disks != 1 || spp_diag_collect_topology(roots, second, &second_count, &winning, &selected_part, &selected_count) != 0 ||
        second_count != first_count || selected_count != 1) return -1;
    for (size_t i = 0; i < first_count; i++) {
        int match = spp_diag_find_disk(second, second_count, first[i].object);
        if (match < 0 || second[match].major_number != first[i].major_number || second[match].minor_number != first[i].minor_number ||
            strcmp(second[match].devname, first[i].devname) != 0) return -1;
    }
    int selected_fd = -1;
    uint64_t selected_size;
    struct stat selected_stat;
    if (spp_diag_open_node(roots, selected_part.devname, selected_part.major_number, selected_part.minor_number, &selected_fd, &selected_size) != 0 ||
        fstat(selected_fd, &selected_stat) != 0 || selected_part.size > UINT64_MAX / SPP_DIAG_GPT_SECTOR ||
        selected_size != selected_part.size * SPP_DIAG_GPT_SECTOR ||
        spp_diag_revalidate_node(roots, selected_fd, selected_part.major_number, selected_part.minor_number, &selected_stat) != 0) {
        if (selected_fd >= 0) close(selected_fd);
        return -1;
    }
    int written = snprintf(out_device_id, out_size, "%u:%u", selected_part.major_number, selected_part.minor_number);
    if (written < 0 || (size_t)written >= out_size) {
        close(selected_fd);
        return -1;
    }
    *out_rdev = makedev(selected_part.major_number, selected_part.minor_number);
    *out_fd = selected_fd;
    return 0;
}

static int real_resolve_partuuid(
    void *ctx, const char *partuuid, char *out_device_id, size_t out_size, dev_t *out_rdev, int *out_fd
) {
    static const struct spp_diag_resolver_roots roots = {
        .class_block_root = "/sys/class/block",
        .dev_block_root = "/sys/dev/block",
        .virtual_root = "/sys/devices/virtual",
        .device_root = "/dev",
        .fixture_bindings = NULL,
        .fixture_binding_count = 0,
    };
    (void)ctx;
    return spp_diag_resolve_partuuid_at(&roots, partuuid, out_device_id, out_size, out_rdev, out_fd);
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
    io->flags = DM_READONLY_FLAG;
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
