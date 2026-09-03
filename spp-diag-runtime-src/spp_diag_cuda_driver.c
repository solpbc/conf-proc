/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 sol pbc */

/* Fixed CUDA-driver child for the non-serving SPP diagnostic appliance. */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

typedef int CUresult;
typedef int CUdevice;
typedef struct CUctx_st *CUcontext;
typedef struct CUmod_st *CUmodule;
typedef struct CUfunc_st *CUfunction;
typedef unsigned long long CUdeviceptr;

#define CUDA_SUCCESS 0
#define RESULT_BYTES 32U
#define MAX_MODEL_BYTES (8U * 1024U * 1024U)

#ifndef SPP_DIAG_MODEL_PATH
#define SPP_DIAG_MODEL_PATH "/opt/solstone/models/synthetic-fixture-v1.bin"
#endif

typedef CUresult (*cuInit_t)(unsigned int);
typedef CUresult (*cuDeviceGetCount_t)(int *);
typedef CUresult (*cuDeviceGet_t)(CUdevice *, int);
typedef CUresult (*cuCtxCreate_v2_t)(CUcontext *, unsigned int, CUdevice);
typedef CUresult (*cuCtxDestroy_v2_t)(CUcontext);
typedef CUresult (*cuCtxSynchronize_t)(void);
typedef CUresult (*cuModuleLoadData_t)(CUmodule *, const void *);
typedef CUresult (*cuModuleGetFunction_t)(CUfunction *, CUmodule, const char *);
typedef CUresult (*cuModuleUnload_t)(CUmodule);
typedef CUresult (*cuMemAlloc_v2_t)(CUdeviceptr *, size_t);
typedef CUresult (*cuMemcpyHtoD_v2_t)(CUdeviceptr, const void *, size_t);
typedef CUresult (*cuMemcpyDtoH_v2_t)(void *, CUdeviceptr, size_t);
typedef CUresult (*cuMemFree_v2_t)(CUdeviceptr);
typedef CUresult (*cuLaunchKernel_t)(
    CUfunction, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int,
    void *, void **, void **
);

/* One thread owns each result byte. It XOR-reduces the corresponding
 * stride-32 model lane into the caller's deterministic 32-byte seed. */
static const char k_witness_ptx[] =
    ".version 8.0\n"
    ".target sm_90\n"
    ".address_size 64\n"
    ".visible .entry spp_diag_witness(\n"
    "    .param .u64 model,\n"
    "    .param .u64 seed,\n"
    "    .param .u64 output,\n"
    "    .param .u64 model_size\n"
    ")\n"
    "{\n"
    "    .reg .pred %p<2>;\n"
    "    .reg .b32 %r<5>;\n"
    "    .reg .b64 %rd<10>;\n"
    "    ld.param.u64 %rd1, [model];\n"
    "    ld.param.u64 %rd2, [seed];\n"
    "    ld.param.u64 %rd3, [output];\n"
    "    ld.param.u64 %rd4, [model_size];\n"
    "    mov.u32 %r1, %tid.x;\n"
    "    setp.ge.u32 %p1, %r1, 32;\n"
    "    @%p1 bra DONE;\n"
    "    cvt.u64.u32 %rd5, %r1;\n"
    "    add.u64 %rd6, %rd2, %rd5;\n"
    "    ld.global.u8 %r2, [%rd6];\n"
    "LOOP:\n"
    "    setp.ge.u64 %p1, %rd5, %rd4;\n"
    "    @%p1 bra STORE;\n"
    "    add.u64 %rd7, %rd1, %rd5;\n"
    "    ld.global.u8 %r3, [%rd7];\n"
    "    xor.b32 %r2, %r2, %r3;\n"
    "    add.u64 %rd5, %rd5, 32;\n"
    "    bra LOOP;\n"
    "STORE:\n"
    "    cvt.u64.u32 %rd8, %r1;\n"
    "    add.u64 %rd9, %rd3, %rd8;\n"
    "    st.global.u8 [%rd9], %r2;\n"
    "DONE:\n"
    "    ret;\n"
    "}\n";

static const char k_witness_function[] = "spp_diag_witness";
static const unsigned char k_output_magic[8] = {'S', 'P', 'P', 'G', 'P', 'U', 'O', '1'};

static int parse_lower_hex32(const char *hex, unsigned char out[RESULT_BYTES]) {
    static const char digits[] = "0123456789abcdef";
    if (strlen(hex) != RESULT_BYTES * 2U) {
        return -1;
    }
    for (size_t index = 0; index < RESULT_BYTES; index++) {
        const char *high = strchr(digits, hex[index * 2U]);
        const char *low = strchr(digits, hex[index * 2U + 1U]);
        if (high == NULL || low == NULL) {
            return -1;
        }
        out[index] = (unsigned char)(((high - digits) << 4) | (low - digits));
    }
    return 0;
}

static int write_output_record(const unsigned char result[RESULT_BYTES]) {
    unsigned char record[48] = {0};
    memcpy(record, k_output_magic, sizeof(k_output_magic));
    record[9] = 1;  /* wire version, big-endian u16 */
    record[11] = 1; /* algorithm id, big-endian u16 */
    record[15] = RESULT_BYTES; /* payload length, big-endian u32 */
    memcpy(record + 16, result, RESULT_BYTES);
    if (fwrite(record, 1, sizeof(record), stdout) != sizeof(record) || fflush(stdout) != 0) {
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    int infer_mode = 0;
    unsigned char seed[RESULT_BYTES] = {0};
    if (argc == 2 && strcmp(argv[1], "cold") == 0) {
        infer_mode = 0;
    } else if (argc == 3 && strcmp(argv[1], "infer") == 0 && parse_lower_hex32(argv[2], seed) == 0) {
        infer_mode = 1;
    } else {
        fprintf(stderr, "spp-diag-cuda-driver: invalid invocation\n");
        return 2;
    }

    int model_fd = -1;
    void *model = MAP_FAILED;
    size_t model_size = 0;
    if (infer_mode) {
        model_fd = open(SPP_DIAG_MODEL_PATH, O_RDONLY | O_CLOEXEC);
        if (model_fd < 0) {
            fprintf(stderr, "spp-diag-cuda-driver: model open failed\n");
            return 3;
        }
        struct stat model_stat;
        if (fstat(model_fd, &model_stat) != 0 || !S_ISREG(model_stat.st_mode) || model_stat.st_size < 1 ||
            (uintmax_t)model_stat.st_size > MAX_MODEL_BYTES) {
            fprintf(stderr, "spp-diag-cuda-driver: model stat failed\n");
            close(model_fd);
            return 3;
        }
        model_size = (size_t)model_stat.st_size;
        model = mmap(NULL, model_size, PROT_READ, MAP_PRIVATE, model_fd, 0);
        if (model == MAP_FAILED) {
            fprintf(stderr, "spp-diag-cuda-driver: model mmap failed\n");
            close(model_fd);
            return 3;
        }
    }

    void *handle = dlopen("libcuda.so.1", RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "spp-diag-cuda-driver: CUDA driver unavailable\n");
        if (model != MAP_FAILED) {
            munmap(model, model_size);
        }
        if (model_fd >= 0) {
            close(model_fd);
        }
        return 4;
    }

#define RESOLVE(name)                                                                                                  \
    name##_t name = NULL;                                                                                              \
    do {                                                                                                                \
        void *symbol = dlsym(handle, #name);                                                                            \
        memcpy(&name, &symbol, sizeof(name));                                                                            \
        if (name == NULL) {                                                                                              \
            fprintf(stderr, "spp-diag-cuda-driver: CUDA symbol unavailable\n");                                      \
            goto cleanup;                                                                                                \
        }                                                                                                                \
    } while (0)

    int rc = 5;
    int cleanup_failed = 0;
    CUcontext context = NULL;
    CUmodule module = NULL;
    CUdeviceptr model_device = 0;
    CUdeviceptr seed_device = 0;
    CUdeviceptr output_device = 0;
    unsigned char result[RESULT_BYTES] = {0};

    RESOLVE(cuInit);
    RESOLVE(cuDeviceGetCount);
    RESOLVE(cuDeviceGet);
    RESOLVE(cuCtxCreate_v2);
    RESOLVE(cuCtxDestroy_v2);
    RESOLVE(cuCtxSynchronize);
    RESOLVE(cuModuleLoadData);
    RESOLVE(cuModuleGetFunction);
    RESOLVE(cuModuleUnload);
    RESOLVE(cuMemAlloc_v2);
    RESOLVE(cuMemcpyHtoD_v2);
    RESOLVE(cuMemcpyDtoH_v2);
    RESOLVE(cuMemFree_v2);
    RESOLVE(cuLaunchKernel);

#undef RESOLVE

    int device_count = 0;
    CUdevice device;
    if (cuInit(0) != CUDA_SUCCESS || cuDeviceGetCount(&device_count) != CUDA_SUCCESS || device_count != 1 ||
        cuDeviceGet(&device, 0) != CUDA_SUCCESS || cuCtxCreate_v2(&context, 0, device) != CUDA_SUCCESS) {
        fprintf(stderr, "spp-diag-cuda-driver: CUDA initialization failed\n");
        goto cleanup;
    }
    if (!infer_mode) {
        rc = 0;
        goto cleanup;
    }

    if (cuModuleLoadData(&module, k_witness_ptx) != CUDA_SUCCESS) {
        fprintf(stderr, "spp-diag-cuda-driver: PTX load failed\n");
        goto cleanup;
    }
    CUfunction function;
    if (cuModuleGetFunction(&function, module, k_witness_function) != CUDA_SUCCESS ||
        cuMemAlloc_v2(&model_device, model_size) != CUDA_SUCCESS ||
        cuMemAlloc_v2(&seed_device, RESULT_BYTES) != CUDA_SUCCESS ||
        cuMemAlloc_v2(&output_device, RESULT_BYTES) != CUDA_SUCCESS ||
        cuMemcpyHtoD_v2(model_device, model, model_size) != CUDA_SUCCESS ||
        cuMemcpyHtoD_v2(seed_device, seed, RESULT_BYTES) != CUDA_SUCCESS) {
        fprintf(stderr, "spp-diag-cuda-driver: CUDA input setup failed\n");
        goto cleanup;
    }

    uint64_t model_size_u64 = model_size;
    void *kernel_params[] = {&model_device, &seed_device, &output_device, &model_size_u64};
    if (cuLaunchKernel(function, 1, 1, 1, RESULT_BYTES, 1, 1, 0, NULL, kernel_params, NULL) != CUDA_SUCCESS ||
        cuCtxSynchronize() != CUDA_SUCCESS ||
        cuMemcpyDtoH_v2(result, output_device, RESULT_BYTES) != CUDA_SUCCESS) {
        fprintf(stderr, "spp-diag-cuda-driver: CUDA execution failed\n");
        goto cleanup;
    }
    rc = 0;

cleanup:
    if (output_device != 0 && cuMemFree_v2(output_device) != CUDA_SUCCESS) {
        cleanup_failed = 1;
    }
    if (seed_device != 0 && cuMemFree_v2(seed_device) != CUDA_SUCCESS) {
        cleanup_failed = 1;
    }
    if (model_device != 0 && cuMemFree_v2(model_device) != CUDA_SUCCESS) {
        cleanup_failed = 1;
    }
    if (module != NULL && cuModuleUnload(module) != CUDA_SUCCESS) {
        cleanup_failed = 1;
    }
    if (context != NULL && cuCtxDestroy_v2(context) != CUDA_SUCCESS) {
        cleanup_failed = 1;
    }
    if (dlclose(handle) != 0) {
        cleanup_failed = 1;
    }
    if (model != MAP_FAILED && munmap(model, model_size) != 0) {
        cleanup_failed = 1;
    }
    if (model_fd >= 0 && close(model_fd) != 0) {
        cleanup_failed = 1;
    }
    if (cleanup_failed) {
        fprintf(stderr, "spp-diag-cuda-driver: cleanup failed\n");
        rc = 6;
    }
    if (rc == 0 && infer_mode && write_output_record(result) != 0) {
        fprintf(stderr, "spp-diag-cuda-driver: output failed\n");
        rc = 7;
    }
    return rc;
}
