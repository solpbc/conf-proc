/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 sol pbc */

/*
 * Test-only fake libcuda.so.1 for exercising spp_diag_cuda_driver.c without a
 * real GPU. Implements the exact fixed subset of the CUDA Driver API the
 * driver resolves via dlsym, validates the fixed module/function contract,
 * and emulates the "spp_diag_witness" PTX operation as a deterministic
 * transform of the input nonce so at least two distinct literal input
 * vectors produce two distinct, independently-predictable outputs.
 *
 * Fault injection via environment variables (never set in production, since
 * production dlopens the real vendor libcuda.so.1, not this file):
 *   SPP_DIAG_CUDA_FAKE_FORCE_MODULE_MISMATCH   -- reject cuModuleLoadData
 *   SPP_DIAG_CUDA_FAKE_FORCE_FUNCTION_MISMATCH -- reject cuModuleGetFunction
 *   SPP_DIAG_CUDA_FAKE_FORCE_GEOMETRY_MISMATCH -- reject cuLaunchKernel geometry
 *   SPP_DIAG_CUDA_FAKE_FORCE_DRIVER_RESULT=<n> -- cuLaunchKernel returns <n>
 *   SPP_DIAG_CUDA_FAKE_FORCE_TIMEOUT           -- cuLaunchKernel sleeps 5s
 *   SPP_DIAG_CUDA_FAKE_FORCE_CLEANUP_FAIL      -- cuCtxDestroy returns nonzero
 *   SPP_DIAG_CUDA_FAKE_FORCE_CONSTANT_OUTPUT   -- ignore the nonce, always
 *                                                 emit the same fixed output
 *                                                 (also stands in for "stale
 *                                                 output" per the same failure
 *                                                 class)
 */

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef int CUresult;
typedef int CUdevice;
struct CUctx_st {
    int marker;
};
struct CUmod_st {
    int marker;
};
struct CUfunc_st {
    int marker;
};
typedef struct CUctx_st *CUcontext;
typedef struct CUmod_st *CUmodule;
typedef struct CUfunc_st *CUfunction;
typedef unsigned long long CUdeviceptr;

#define CUDA_SUCCESS 0
#define CUDA_ERROR_INVALID_VALUE 1
#define CUDA_ERROR_INVALID_IMAGE 200
#define CUDA_ERROR_NOT_FOUND 500
#define CUDA_ERROR_LAUNCH_FAILED 719
#define CUDA_ERROR_DEINITIALIZED 4

#define WITNESS_BYTES 32

static const unsigned char k_fixed_key[WITNESS_BYTES] = {
    0x53, 0x50, 0x50, 0x2d, 0x44, 0x49, 0x41, 0x47, 0x2d, 0x57, 0x49, 0x54, 0x4e, 0x45, 0x53, 0x53,
    0x2d, 0x56, 0x31, 0x2d, 0x4b, 0x45, 0x59, 0x2d, 0x30, 0x31, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
};

static const char k_expected_function[] = "spp_diag_witness";

static struct CUctx_st g_ctx;
static struct CUmod_st g_module;
static struct CUfunc_st g_function;
static unsigned char g_last_input[WITNESS_BYTES];

int cuInit(unsigned int flags) {
    (void)flags;
    return CUDA_SUCCESS;
}

int cuDeviceGet(CUdevice *device, int ordinal) {
    (void)ordinal;
    *device = 0;
    return CUDA_SUCCESS;
}

int cuCtxCreate(CUcontext *ctx, unsigned int flags, CUdevice device) {
    (void)flags;
    (void)device;
    *ctx = &g_ctx;
    return CUDA_SUCCESS;
}

int cuModuleLoadData(CUmodule *module, const void *image) {
    if (getenv("SPP_DIAG_CUDA_FAKE_FORCE_MODULE_MISMATCH") != NULL) {
        return CUDA_ERROR_INVALID_IMAGE;
    }
    if (image == NULL || strstr((const char *)image, "spp_diag_witness_v1") == NULL) {
        return CUDA_ERROR_INVALID_IMAGE;
    }
    *module = &g_module;
    return CUDA_SUCCESS;
}

int cuModuleGetFunction(CUfunction *function, CUmodule module, const char *name) {
    (void)module;
    if (getenv("SPP_DIAG_CUDA_FAKE_FORCE_FUNCTION_MISMATCH") != NULL) {
        return CUDA_ERROR_NOT_FOUND;
    }
    if (name == NULL || strcmp(name, k_expected_function) != 0) {
        return CUDA_ERROR_NOT_FOUND;
    }
    *function = &g_function;
    return CUDA_SUCCESS;
}

int cuMemAlloc(CUdeviceptr *ptr, size_t bytes) {
    void *mem = malloc(bytes);
    if (mem == NULL) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    *ptr = (CUdeviceptr)(uintptr_t)mem;
    return CUDA_SUCCESS;
}

int cuMemcpyHtoD(CUdeviceptr dst, const void *src, size_t bytes) {
    memcpy((void *)(uintptr_t)dst, src, bytes);
    if (bytes == WITNESS_BYTES) {
        memcpy(g_last_input, src, WITNESS_BYTES);
    }
    return CUDA_SUCCESS;
}

int cuMemcpyDtoH(void *dst, CUdeviceptr src, size_t bytes) {
    memcpy(dst, (const void *)(uintptr_t)src, bytes);
    return CUDA_SUCCESS;
}

int cuMemFree(CUdeviceptr ptr) {
    free((void *)(uintptr_t)ptr);
    return CUDA_SUCCESS;
}

int cuLaunchKernel(
    CUfunction function, unsigned int gridX, unsigned int gridY, unsigned int gridZ, unsigned int blockX,
    unsigned int blockY, unsigned int blockZ, unsigned int sharedMemBytes, void *hStream, void **kernelParams,
    void **extra
) {
    (void)hStream;
    (void)extra;
    if (function != &g_function) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    const char *forced_result = getenv("SPP_DIAG_CUDA_FAKE_FORCE_DRIVER_RESULT");
    if (forced_result != NULL) {
        return atoi(forced_result);
    }
    if (getenv("SPP_DIAG_CUDA_FAKE_FORCE_TIMEOUT") != NULL) {
        sleep(5);
    }
    unsigned int expected_grid_x = 1, expected_grid_y = 1, expected_grid_z = 1;
    unsigned int expected_block_x = WITNESS_BYTES, expected_block_y = 1, expected_block_z = 1;
    if (getenv("SPP_DIAG_CUDA_FAKE_FORCE_GEOMETRY_MISMATCH") != NULL) {
        expected_grid_x = 99;
    }
    if (gridX != expected_grid_x || gridY != expected_grid_y || gridZ != expected_grid_z || blockX != expected_block_x ||
        blockY != expected_block_y || blockZ != expected_block_z || sharedMemBytes != 0) {
        return CUDA_ERROR_LAUNCH_FAILED;
    }
    if (kernelParams == NULL || kernelParams[0] == NULL || kernelParams[1] == NULL) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    CUdeviceptr in_ptr = *(CUdeviceptr *)kernelParams[0];
    CUdeviceptr out_ptr = *(CUdeviceptr *)kernelParams[1];
    unsigned char *in_bytes = (unsigned char *)(uintptr_t)in_ptr;
    unsigned char *out_bytes = (unsigned char *)(uintptr_t)out_ptr;
    if (getenv("SPP_DIAG_CUDA_FAKE_FORCE_CONSTANT_OUTPUT") != NULL) {
        for (int i = 0; i < WITNESS_BYTES; i++) {
            out_bytes[i] = 0x42;
        }
        return CUDA_SUCCESS;
    }
    for (int i = 0; i < WITNESS_BYTES; i++) {
        out_bytes[i] = (unsigned char)(in_bytes[i] ^ k_fixed_key[i]);
    }
    return CUDA_SUCCESS;
}

int cuCtxDestroy(CUcontext ctx) {
    if (ctx != &g_ctx) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    if (getenv("SPP_DIAG_CUDA_FAKE_FORCE_CLEANUP_FAIL") != NULL) {
        return CUDA_ERROR_DEINITIALIZED;
    }
    return CUDA_SUCCESS;
}
