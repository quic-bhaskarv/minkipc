// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause

/*
 * Compatibility header for comdef.h
 * Provides basic type definitions needed by RPMB code
 */

#ifndef _COMDEF_H
#define _COMDEF_H

#include <stdint.h>
#include <stdbool.h>

/* Basic type definitions */
typedef uint8_t   uint8;
typedef uint16_t  uint16;
typedef uint32_t  uint32;
typedef uint64_t  uint64;

typedef int8_t    int8;
typedef int16_t   int16;
typedef int32_t   int32;
typedef int64_t   int64;

typedef uint8_t   byte;
typedef uint16_t  word;
typedef uint32_t  dword;

typedef unsigned int uint;

/* Boolean definitions */
#ifndef TRUE
#define TRUE  1
#endif

#ifndef FALSE
#define FALSE 0
#endif

/* NULL definition */
#ifndef NULL
#define NULL ((void*)0)
#endif

/* Size definitions */
#define SIZE_1KB    1024
#define SIZE_4KB    (4 * SIZE_1KB)

/* Logging macros for compatibility */
#define LOGI(fmt, ...) printf("[RPMB_INFO] " fmt, ##__VA_ARGS__)
#define LOGD(fmt, ...) printf("[RPMB_DEBUG] " fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) printf("[RPMB_ERROR] " fmt, ##__VA_ARGS__)
#define LOGV(fmt, ...) printf("[RPMB_VERBOSE] " fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) printf("[RPMB_WARNING] " fmt, ##__VA_ARGS__)

/* Common macros */
#ifndef UNUSED
#define UNUSED(x) ((void)(x))
#endif

#endif /* _COMDEF_H */
