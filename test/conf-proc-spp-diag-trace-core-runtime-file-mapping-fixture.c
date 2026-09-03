/* SPDX-License-Identifier: GPL-2.0-only */

#include <string.h>

#include <linux/fcntl.h>
#include <linux/kdev_t.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/spp_diag_trace_adapter.h>
#include <linux/spp_diag_trace_adapter_shim.h>

#include "conf-proc-spp-diag-trace-core-runtime-adapter-fixture.h"

int main(int argc, char **argv)
{
	struct task_struct root;
	struct super_block sb = { .s_magic = 0xef53, .s_dev = MKDEV(8, 1) };
	struct inode inode = { .i_mode = S_IFREG, .i_ino = 81, .i_size = 4096, .i_sb = &sb };
	struct mount mount = { .mnt_id_unique = 99 };
	struct file file = { .f_inode = &inode, .f_flags = O_RDONLY | O_NOFOLLOW,
		.f_path = { .mnt = &mount.mnt } };
	struct vm_area_struct vma = { .vm_file = &file, .vm_flags = VM_READ | VM_SHARED };
	bool cloexec = argc == 2 && !strcmp(argv[1], "--cloexec");
	bool untracked_open = argc == 2 && !strcmp(argv[1], "--untracked-open");
	bool fmode_probe = argc == 2 && !strcmp(argv[1], "--fmode-probe");
	bool mapping_red = argc == 2 && !strcmp(argv[1], "--mapping-red");
	bool shm_red = argc == 2 && !strcmp(argv[1], "--shm-red");

	if (argc > 2 || (argc == 2 && !cloexec && !untracked_open &&
					  !fmode_probe && !mapping_red && !shm_red) ||
	    spp_adapter_fixture_start(&root))
		return 64;
	if (mapping_red || shm_red) {
		/* remap_file_pages and SHM_EXEC report, but never alter caller results. */
		spp_diag_trace_adapter_mapping_unsupported();
		return spp_diag_trace_core_is_green() ? 2 : 42;
	}
	if (untracked_open || fmode_probe) {
		if (fmode_probe)
			file.f_mode = FMODE_EXEC;
		/* vfs_open()/kernel_file_open() do not have a syscall attempt. */
		spp_diag_trace_adapter_file_open_policy(&file, 0);
		if (!spp_diag_trace_core_is_green())
			return 3;
		return spp_adapter_fixture_stream() ? 6 : 0;
	}
	if (cloexec)
		/* build_open_flags() strips this before file->f_flags is observed. */
		spp_diag_trace_adapter_file_open_attempt(-100, "/tmp/openat2",
			file.f_flags | O_CLOEXEC);
	else
		spp_diag_trace_adapter_file_open_attempt(-100, "/tmp/openat2", file.f_flags);
	spp_diag_trace_adapter_file_open_policy(&file, 0);
	spp_diag_trace_adapter_file_open_return(0);
	if (!spp_diag_trace_core_is_green())
		return 4;
	/* Non-executable mmap is intentionally a no-op adapter boundary. */
	spp_diag_trace_adapter_mapping_policy(&file, PROT_READ, 0, 0);
	spp_diag_trace_adapter_mapping_policy(&file, PROT_READ | PROT_EXEC, MAP_SHARED, -1);
	spp_diag_trace_adapter_mapping_return(-1);
	spp_diag_trace_adapter_mprotect_policy(&vma, PROT_READ | PROT_WRITE | PROT_EXEC,
		PROT_READ | PROT_WRITE | PROT_EXEC, -1);
	spp_diag_trace_adapter_mprotect_return(-1);
	if (!spp_diag_trace_core_is_green())
		return 5;
	return spp_adapter_fixture_stream() ? 6 : 0;
}
