/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 sol pbc */

/* Test-only CUDA Driver API emulator for spp_diag_cuda_driver.c. */

#define _GNU_SOURCE

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef int CUresult;
typedef int CUdevice;
struct CUctx_st { int marker; };
struct CUmod_st { int marker; };
struct CUfunc_st { int marker; };
typedef struct CUctx_st *CUcontext;
typedef struct CUmod_st *CUmodule;
typedef struct CUfunc_st *CUfunction;
typedef unsigned long long CUdeviceptr;

#define CUDA_SUCCESS 0
#define CUDA_ERROR_INVALID_VALUE 1
#define CUDA_ERROR_DEINITIALIZED 4
#define CUDA_ERROR_INVALID_IMAGE 200
#define CUDA_ERROR_NOT_FOUND 500
#define CUDA_ERROR_LAUNCH_FAILED 719
#define RESULT_BYTES 32U

struct allocation {
    CUdeviceptr pointer;
    size_t size;
    int copied;
};

static struct CUctx_st g_context;
static struct CUmod_st g_module;
static struct CUfunc_st g_function;
static struct allocation g_allocations[3];
static size_t g_allocation_count;
static int g_launched;
static int g_synchronized;

static const char k_expected_ptx[] =
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

static struct allocation *find_allocation(CUdeviceptr pointer) {
    for (size_t index = 0; index < g_allocation_count; index++) {
        if (g_allocations[index].pointer == pointer) {
            return &g_allocations[index];
        }
    }
    return NULL;
}

int cuInit(unsigned int flags) {
    return flags == 0 ? CUDA_SUCCESS : CUDA_ERROR_INVALID_VALUE;
}

int cuDeviceGetCount(int *count) {
    if (count == NULL) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    *count = getenv("SPP_DIAG_CUDA_FAKE_FORCE_TWO_DEVICES") == NULL ? 1 : 2;
    return CUDA_SUCCESS;
}

int cuDeviceGet(CUdevice *device, int ordinal) {
    if (device == NULL || ordinal != 0) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    *device = 0;
    return CUDA_SUCCESS;
}

int cuCtxCreate_v2(CUcontext *context, unsigned int flags, CUdevice device) {
    if (context == NULL || flags != 0 || device != 0) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    *context = &g_context;
    return CUDA_SUCCESS;
}

int cuModuleLoadData(CUmodule *module, const void *image) {
    const char *ptx = image;
    if (module == NULL || ptx == NULL || getenv("SPP_DIAG_CUDA_FAKE_FORCE_MODULE_MISMATCH") != NULL ||
        strcmp(ptx, k_expected_ptx) != 0) {
        return CUDA_ERROR_INVALID_IMAGE;
    }
    *module = &g_module;
    return CUDA_SUCCESS;
}

int cuModuleGetFunction(CUfunction *function, CUmodule module, const char *name) {
    if (function == NULL || module != &g_module || name == NULL ||
        getenv("SPP_DIAG_CUDA_FAKE_FORCE_FUNCTION_MISMATCH") != NULL || strcmp(name, "spp_diag_witness") != 0) {
        return CUDA_ERROR_NOT_FOUND;
    }
    *function = &g_function;
    return CUDA_SUCCESS;
}

int cuMemAlloc_v2(CUdeviceptr *pointer, size_t size) {
    if (pointer == NULL || size == 0 || g_allocation_count == 3) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    void *memory = calloc(1, size);
    if (memory == NULL) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    *pointer = (CUdeviceptr)(uintptr_t)memory;
    g_allocations[g_allocation_count++] = (struct allocation){*pointer, size, 0};
    return CUDA_SUCCESS;
}

int cuMemcpyHtoD_v2(CUdeviceptr destination, const void *source, size_t size) {
    struct allocation *allocation = find_allocation(destination);
    if (allocation == NULL || source == NULL || size != allocation->size) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    memcpy((void *)(uintptr_t)destination, source, size);
    allocation->copied = 1;
    return CUDA_SUCCESS;
}

int cuLaunchKernel(
    CUfunction function, unsigned int grid_x, unsigned int grid_y, unsigned int grid_z, unsigned int block_x,
    unsigned int block_y, unsigned int block_z, unsigned int shared_bytes, void *stream, void **parameters,
    void **extra
) {
    (void)stream;
    (void)extra;
    const char *forced_result = getenv("SPP_DIAG_CUDA_FAKE_FORCE_DRIVER_RESULT");
    if (forced_result != NULL) {
        return atoi(forced_result);
    }
    if (getenv("SPP_DIAG_CUDA_FAKE_FORCE_TIMEOUT") != NULL) {
        sleep(5);
    }
    unsigned int expected_grid_x = getenv("SPP_DIAG_CUDA_FAKE_FORCE_GEOMETRY_MISMATCH") == NULL ? 1U : 2U;
    if (function != &g_function || grid_x != expected_grid_x || grid_y != 1 || grid_z != 1 ||
        block_x != RESULT_BYTES || block_y != 1 || block_z != 1 || shared_bytes != 0 || parameters == NULL ||
        parameters[0] == NULL || parameters[1] == NULL || parameters[2] == NULL || parameters[3] == NULL) {
        return CUDA_ERROR_LAUNCH_FAILED;
    }
    CUdeviceptr model_pointer = *(CUdeviceptr *)parameters[0];
    CUdeviceptr seed_pointer = *(CUdeviceptr *)parameters[1];
    CUdeviceptr output_pointer = *(CUdeviceptr *)parameters[2];
    uint64_t model_size = *(uint64_t *)parameters[3];
    struct allocation *model = find_allocation(model_pointer);
    struct allocation *seed = find_allocation(seed_pointer);
    struct allocation *output = find_allocation(output_pointer);
    if (model == NULL || seed == NULL || output == NULL || !model->copied || !seed->copied || output->copied ||
        model->size != model_size || seed->size != RESULT_BYTES || output->size != RESULT_BYTES) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    unsigned char *model_bytes = (unsigned char *)(uintptr_t)model_pointer;
    unsigned char *seed_bytes = (unsigned char *)(uintptr_t)seed_pointer;
    unsigned char *output_bytes = (unsigned char *)(uintptr_t)output_pointer;
    for (size_t lane = 0; lane < RESULT_BYTES; lane++) {
        unsigned char value = seed_bytes[lane];
        for (size_t offset = lane; offset < model_size; offset += RESULT_BYTES) {
            value ^= model_bytes[offset];
        }
        output_bytes[lane] = getenv("SPP_DIAG_CUDA_FAKE_FORCE_CONSTANT_OUTPUT") == NULL ? value : 0x42;
    }
    g_launched = 1;
    return CUDA_SUCCESS;
}

int cuCtxSynchronize(void) {
    if (!g_launched || getenv("SPP_DIAG_CUDA_FAKE_FORCE_SYNC_FAIL") != NULL) {
        return CUDA_ERROR_LAUNCH_FAILED;
    }
    g_synchronized = 1;
    return CUDA_SUCCESS;
}

int cuMemcpyDtoH_v2(void *destination, CUdeviceptr source, size_t size) {
    struct allocation *allocation = find_allocation(source);
    if (destination == NULL || allocation == NULL || allocation->size != RESULT_BYTES || size != RESULT_BYTES ||
        !g_synchronized) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    memcpy(destination, (const void *)(uintptr_t)source, size);
    return CUDA_SUCCESS;
}

int cuMemFree_v2(CUdeviceptr pointer) {
    struct allocation *allocation = find_allocation(pointer);
    if (allocation == NULL) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    free((void *)(uintptr_t)pointer);
    allocation->pointer = 0;
    return CUDA_SUCCESS;
}

int cuModuleUnload(CUmodule module) {
    return module == &g_module ? CUDA_SUCCESS : CUDA_ERROR_INVALID_VALUE;
}

int cuCtxDestroy_v2(CUcontext context) {
    if (context != &g_context) {
        return CUDA_ERROR_INVALID_VALUE;
    }
    return getenv("SPP_DIAG_CUDA_FAKE_FORCE_CLEANUP_FAIL") == NULL ? CUDA_SUCCESS : CUDA_ERROR_DEINITIALIZED;
}
