/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (c) 2026 sol pbc */

/*
 * Header-free CUDA-driver child for the SPP diagnostic appliance.
 *
 * Dlopens libcuda.so.1 by SONAME and resolves the small fixed subset of the
 * CUDA Driver API this program needs via dlsym -- no CUDA headers or link
 * libraries. The needed entry-point prototypes are hand-declared below,
 * matching the stable public CUDA Driver ABI.
 *
 * Invocation: spp-diag-cuda-driver <32-byte-hex-nonce>
 * Output: a 32-byte-hex witness result on stdout, nothing else, exit 0 on
 * success. Any driver-call failure prints one line to stderr and exits
 * nonzero without printing a result line.
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int CUresult;
typedef int CUdevice;
typedef struct CUctx_st *CUcontext;
typedef struct CUmod_st *CUmodule;
typedef struct CUfunc_st *CUfunction;
typedef unsigned long long CUdeviceptr;

#define CUDA_SUCCESS 0

typedef CUresult (*cuInit_t)(unsigned int);
typedef CUresult (*cuDeviceGet_t)(CUdevice *, int);
typedef CUresult (*cuCtxCreate_t)(CUcontext *, unsigned int, CUdevice);
typedef CUresult (*cuModuleLoadData_t)(CUmodule *, const void *);
typedef CUresult (*cuModuleGetFunction_t)(CUfunction *, CUmodule, const char *);
typedef CUresult (*cuMemAlloc_t)(CUdeviceptr *, size_t);
typedef CUresult (*cuMemcpyHtoD_t)(CUdeviceptr, const void *, size_t);
typedef CUresult (*cuMemcpyDtoH_t)(void *, CUdeviceptr, size_t);
typedef CUresult (*cuMemFree_t)(CUdeviceptr);
typedef CUresult (*cuLaunchKernel_t)(
    CUfunction, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int,
    void *, void **, void **
);
typedef CUresult (*cuCtxDestroy_t)(CUcontext);

/* Fixed literal PTX-shaped payload identifying the witness operation. This
 * program never compiles or executes real PTX -- the payload is a stable
 * identifying constant that the driver-side module loader (real or fake)
 * validates, exactly like a real cuModuleLoadData call validates its module
 * image bytes. */
static const char k_witness_module[] =
    ".version 8.0\n.target spp_diag_witness_v1\n.address_size 64\n"
    ".visible .entry spp_diag_witness(.param .u64 in, .param .u64 out) { ret; }\n";

static const char k_witness_function[] = "spp_diag_witness";

#define WITNESS_BYTES 32

static int parse_hex32(const char *hex, unsigned char *out) {
    if (strlen(hex) != WITNESS_BYTES * 2) {
        return -1;
    }
    for (int i = 0; i < WITNESS_BYTES; i++) {
        char high = hex[i * 2];
        char low = hex[i * 2 + 1];
        if (!isxdigit((unsigned char)high) || !isxdigit((unsigned char)low)) {
            return -1;
        }
        char byte_str[3] = {high, low, '\0'};
        out[i] = (unsigned char)strtoul(byte_str, NULL, 16);
    }
    return 0;
}

static void print_hex32(const unsigned char *data) {
    for (int i = 0; i < WITNESS_BYTES; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: spp-diag-cuda-driver <32-byte-hex-nonce>\n");
        return 2;
    }
    unsigned char nonce[WITNESS_BYTES];
    if (parse_hex32(argv[1], nonce) != 0) {
        fprintf(stderr, "spp-diag-cuda-driver: malformed nonce\n");
        return 2;
    }

    void *handle = dlopen("libcuda.so.1", RTLD_NOW);
    if (handle == NULL) {
        fprintf(stderr, "spp-diag-cuda-driver: dlopen failed: %s\n", dlerror());
        return 3;
    }

#define RESOLVE(name)                                                                                                \
    name##_t name;                                                                                                    \
    {                                                                                                                  \
        void *sym = dlsym(handle, #name);                                                                             \
        memcpy(&name, &sym, sizeof(name));                                                                            \
    }                                                                                                                  \
    if (name == NULL) {                                                                                             \
        fprintf(stderr, "spp-diag-cuda-driver: dlsym %s failed: %s\n", #name, dlerror());                           \
        dlclose(handle);                                                                                             \
        return 4;                                                                                                    \
    }

    RESOLVE(cuInit)
    RESOLVE(cuDeviceGet)
    RESOLVE(cuCtxCreate)
    RESOLVE(cuModuleLoadData)
    RESOLVE(cuModuleGetFunction)
    RESOLVE(cuMemAlloc)
    RESOLVE(cuMemcpyHtoD)
    RESOLVE(cuMemcpyDtoH)
    RESOLVE(cuMemFree)
    RESOLVE(cuLaunchKernel)
    RESOLVE(cuCtxDestroy)

#undef RESOLVE

    int rc = 5;
    CUcontext ctx = NULL;
    CUdeviceptr in_ptr = 0;
    CUdeviceptr out_ptr = 0;

    if (cuInit(0) != CUDA_SUCCESS) {
        fprintf(stderr, "spp-diag-cuda-driver: cuInit failed\n");
        goto cleanup;
    }
    CUdevice device;
    if (cuDeviceGet(&device, 0) != CUDA_SUCCESS) {
        fprintf(stderr, "spp-diag-cuda-driver: cuDeviceGet failed\n");
        goto cleanup;
    }
    if (cuCtxCreate(&ctx, 0, device) != CUDA_SUCCESS) {
        fprintf(stderr, "spp-diag-cuda-driver: cuCtxCreate failed\n");
        goto cleanup;
    }
    CUmodule module;
    if (cuModuleLoadData(&module, k_witness_module) != CUDA_SUCCESS) {
        fprintf(stderr, "spp-diag-cuda-driver: cuModuleLoadData failed\n");
        goto cleanup;
    }
    CUfunction function;
    if (cuModuleGetFunction(&function, module, k_witness_function) != CUDA_SUCCESS) {
        fprintf(stderr, "spp-diag-cuda-driver: cuModuleGetFunction failed\n");
        goto cleanup;
    }
    if (cuMemAlloc(&in_ptr, WITNESS_BYTES) != CUDA_SUCCESS || cuMemAlloc(&out_ptr, WITNESS_BYTES) != CUDA_SUCCESS) {
        fprintf(stderr, "spp-diag-cuda-driver: cuMemAlloc failed\n");
        goto cleanup;
    }
    if (cuMemcpyHtoD(in_ptr, nonce, WITNESS_BYTES) != CUDA_SUCCESS) {
        fprintf(stderr, "spp-diag-cuda-driver: cuMemcpyHtoD failed\n");
        goto cleanup;
    }
    void *kernel_params[2];
    kernel_params[0] = &in_ptr;
    kernel_params[1] = &out_ptr;
    if (cuLaunchKernel(function, 1, 1, 1, WITNESS_BYTES, 1, 1, 0, NULL, kernel_params, NULL) != CUDA_SUCCESS) {
        fprintf(stderr, "spp-diag-cuda-driver: cuLaunchKernel failed\n");
        goto cleanup;
    }
    unsigned char result[WITNESS_BYTES];
    if (cuMemcpyDtoH(result, out_ptr, WITNESS_BYTES) != CUDA_SUCCESS) {
        fprintf(stderr, "spp-diag-cuda-driver: cuMemcpyDtoH failed\n");
        goto cleanup;
    }

    print_hex32(result);
    rc = 0;

cleanup:
    if (in_ptr != 0) {
        cuMemFree(in_ptr);
    }
    if (out_ptr != 0) {
        cuMemFree(out_ptr);
    }
    if (ctx != NULL) {
        if (cuCtxDestroy(ctx) != CUDA_SUCCESS && rc == 0) {
            fprintf(stderr, "spp-diag-cuda-driver: cuCtxDestroy failed\n");
            rc = 6;
        }
    }
    dlclose(handle);
    return rc;
}
