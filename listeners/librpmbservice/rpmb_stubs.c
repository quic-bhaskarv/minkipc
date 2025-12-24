// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause

/*
 * RPMB stub implementations for missing eMMC and UFS functions
 * This allows the service to compile and run with basic functionality
 */

#include "rpmb.h"
#include "rpmb_logging.h"

/* Replace comdef.h logging macros with RPMB logging system */
#undef LOGI
#undef LOGE  
#undef LOGV
#undef LOGD

#define LOGI(fmt, ...) RPMB_LOG_INFO(fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) RPMB_LOG_ERROR(fmt, ##__VA_ARGS__)
#define LOGV(fmt, ...) RPMB_LOG_DEBUG(fmt, ##__VA_ARGS__)
#define LOGD(fmt, ...) RPMB_LOG_DEBUG(fmt, ##__VA_ARGS__)
#include "comdef.h"

/* Stub implementations for eMMC RPMB functions */
int rpmb_emmc_init(rpmb_init_info_t *rpmb_info)
{
    LOGI("rpmb_emmc_init: STUB implementation - eMMC RPMB not supported");
    
    if (rpmb_info) {
        rpmb_info->size = 256;  /* Default 256 sectors */
        rpmb_info->rel_wr_count = 1;
        rpmb_info->dev_type = EMMC_RPMB;
        rpmb_info->reserved = 0;
    }
    
    return -1;  /* Return error to indicate not supported */
}

int rpmb_emmc_read(uint32_t *req_buf, uint32_t blk_cnt,
                   uint32_t *resp_buf, uint32_t *resp_len)
{
    LOGI("rpmb_emmc_read: STUB implementation - eMMC RPMB not supported");
    UNUSED(req_buf);
    UNUSED(blk_cnt);
    UNUSED(resp_buf);
    
    if (resp_len) {
        *resp_len = 0;
    }
    
    return -1;  /* Return error to indicate not supported */
}

int rpmb_emmc_write(uint32_t *req_buf, uint32_t blk_cnt,
                    uint32_t *resp_buf, uint32_t *resp_len,
                    uint32_t frames_per_rpmb_op)
{
    LOGI("rpmb_emmc_write: STUB implementation - eMMC RPMB not supported");
    UNUSED(req_buf);
    UNUSED(blk_cnt);
    UNUSED(resp_buf);
    UNUSED(frames_per_rpmb_op);
    
    if (resp_len) {
        *resp_len = 0;
    }
    
    return -1;  /* Return error to indicate not supported */
}

void rpmb_emmc_exit(void)
{
    LOGI("rpmb_emmc_exit: STUB implementation");
    /* Nothing to do */
}

/* UFS RPMB functions are provided by rpmb_ufs_bsg.c - no stubs needed */
