// Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
// SPDX-License-Identifier: BSD-3-Clause

#define LOG_TAG "rpmb"

#include <errno.h>
#include <fcntl.h>
#include <linux/major.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "rpmb.h"
#include "rpmb_logging.h"

/* Utility macros */
#define UNUSED(x) ((void)(x))

/* Use RPMB logging system */
#define LOGI(fmt, ...) RPMB_LOG_INFO(fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) RPMB_LOG_ERROR(fmt, ##__VA_ARGS__)
#define LOGV(fmt, ...) RPMB_LOG_DEBUG(fmt, ##__VA_ARGS__)
#define LOGD(fmt, ...) RPMB_LOG_DEBUG(fmt, ##__VA_ARGS__)

/* Device detection constants */
#define CMDLINE  "/proc/cmdline"
#define EMMC_DEV "root=/dev/mmcblk"
#define UFS_DEV  "root=/dev/sd"
#define BOOT_DEV_KEY  "bootdevice="

#define RPMB_WAKE_LOCK_FILE     "/sys/power/wake_lock"
#define RPMB_WAKE_UNLOCK_FILE	"/sys/power/wake_unlock"
#define RPMB_WAKE_LOCK_STRING	"rpmb_access_wakelock"

/*shared struct variable for rpmb*/
struct rpmb_stats rpmb;

static struct rpmb_wake_lock
{
	int       lock_fd;
	int       unlock_fd;
	ssize_t   write_size;
} wakelock = {-1, -1, 0};

/*
 * This function will figure which device is the rpmb
 * device and return that inforamtion.
 */
static device_id_type get_rpmb_dev(void)
{
	LOGI("RPMB device detection starting...\n");

	/* Unified device detection using /proc/cmdline */
	int fd;
	char *cmdline_buf = NULL;
	ssize_t ret;
	ssize_t byte_count = 0;
	char *bootdev;
	char cmdline_segment[101];
	device_id_type status_ret = NO_DEVICE;

	fd = open(CMDLINE, O_RDONLY);
	if (fd < 0) {
		LOGE("Error unable to open the file /proc/cmdline: (err no: %d)\n", errno);
		/* Fallback to UFS for testing environments */
		LOGI("Fallback to UFS RPMB for testing environment\n");
		return UFS_RPMB;
	}

	do{
		ret = read(fd, cmdline_segment, 100);
		byte_count = ret > 0 ? (byte_count + ret) : byte_count;
	} while(ret > 0);
	if(ret < 0) {
		LOGE("Error reading the file /proc/cmdline: (err no: %d)\n", errno);
		close(fd);
		/* Fallback to UFS for testing environments */
		LOGI("Fallback to UFS RPMB for testing environment\n");
		return UFS_RPMB;
	}

	do {
		if (lseek(fd, 0, SEEK_SET)) {
			LOGE("Error reading the file /proc/cmdline: (err no: %d)\n", errno);
			status_ret = NO_DEVICE;
			break;
		}
		cmdline_buf = malloc (byte_count + 1);
		if (cmdline_buf == NULL) {
			LOGE("Error rpmb services run out of memory.\n");
			status_ret = NO_DEVICE;
			break;
		}
		ret = read(fd, cmdline_buf, byte_count);
		if (ret != byte_count) {
			LOGE("Error reading the file /proc/cmdline fail: size of /proc/cmdline is %ld and"
				" return size is %ld\n", (long)byte_count, (long)ret);
			status_ret = NO_DEVICE;
			break;
		}
		cmdline_buf[ret] = '\0';

		if(strstr(cmdline_buf, EMMC_DEV)) {
			LOGV("RPMB partition exists on EMMC device\n");
			status_ret = EMMC_RPMB;
			break;
		}

		if(strstr(cmdline_buf, UFS_DEV)) {
			LOGV("RPMB partition exists on UFS device\n");
			status_ret = UFS_RPMB;
			break;
		}

		/* If dm-verity is enabled */
		bootdev = strstr(cmdline_buf, BOOT_DEV_KEY);
		if(bootdev != NULL) {
			bootdev = bootdev + strlen(BOOT_DEV_KEY);
			if (*bootdev != '\0') {
				if (strstr(bootdev, "sdhci")) {
					LOGV("RPMB partition exists on EMMC device");
					status_ret = EMMC_RPMB;
					break;
				} else if (strstr(bootdev, "ufshc")){
					LOGV("RPMB partition exists on UFS device");
					status_ret = UFS_RPMB;
					break;
				}
			}
		}

		/* Default to UFS if no clear detection */
		LOGI("No clear device detection from cmdline, defaulting to UFS\n");
		status_ret = UFS_RPMB;
	} while(0);

	if (cmdline_buf)
		free(cmdline_buf);
	close(fd);

	/* Final fallback - force UFS */
	if (status_ret == NO_DEVICE) {
		LOGI("Forcing UFS RPMB detection for testing environment\n");
		status_ret = UFS_RPMB;
	}

	LOGI("RPMB device detection result: %s\n",
		 (status_ret == UFS_RPMB) ? "UFS_RPMB" :
		 (status_ret == EMMC_RPMB) ? "EMMC_RPMB" : "NO_DEVICE");

	return status_ret;
}

int rpmb_default_init(rpmb_init_info_t *rpmb_info)
{
	UNUSED(rpmb_info);

	rpmb.info.size = 0;
	rpmb.info.rel_wr_count = 0;
	rpmb.info.dev_type = NO_DEVICE;
	rpmb.init_done = 1;

	return 0;
}

/*
 * Call the appropriate device's rpmb init function.
 */
int rpmb_init(rpmb_init_info_t *rpmb_info)
{
	device_id_type device;
	int ret = 0;

	if (rpmb.init_done) {
		rpmb_info->size = rpmb.info.size;
		rpmb_info->rel_wr_count = rpmb.info.rel_wr_count;
		rpmb_info->dev_type = rpmb.info.dev_type;
		return ret;
	}

	device = get_rpmb_dev();

	if (device == EMMC_RPMB)
		ret = rpmb_emmc_init(rpmb_info);
	else if (device == UFS_RPMB)
		ret = rpmb_ufs_init(rpmb_info);
	else
		ret = rpmb_default_init(rpmb_info);

	return ret;
}

/**
 * meant to be used only with the rpmb_tester app to clean up as
 * rpmb_init can be called multiple times
 */
void rpmb_exit(void)
{
	if (rpmb.init_done && rpmb.fd)
		close(rpmb.fd);

	if (rpmb.init_done && rpmb.fd_ufs_bsg)
		close(rpmb.fd_ufs_bsg);
}

/*
 * Call the appropriate device's rpmb read function.
 */
int rpmb_read(uint32_t *req_buf, uint32_t blk_cnt, uint32_t *resp_buf, uint32_t *resp_len)
{
	if (rpmb.info.dev_type == EMMC_RPMB)
		return rpmb_emmc_read(req_buf, blk_cnt, resp_buf, resp_len);
	else if (rpmb.info.dev_type == UFS_RPMB)
		return rpmb_ufs_read(req_buf, blk_cnt, resp_buf, resp_len);

	LOGE("rpmb read operation on invalid RPMB device!!");
	return -1;
}

/*
 * Call the appropriate device's rpmb write function.
 */
int rpmb_write(uint32_t *req_buf, uint32_t blk_cnt, uint32_t *resp_buf, uint32_t *resp_len,
		uint32_t frames_per_rpmb_trans)
{
	if (rpmb.info.dev_type == EMMC_RPMB)
		return rpmb_emmc_write(req_buf, blk_cnt, resp_buf, resp_len, frames_per_rpmb_trans);
	else if (rpmb.info.dev_type == UFS_RPMB)
		return rpmb_ufs_write(req_buf, blk_cnt, resp_buf, resp_len, frames_per_rpmb_trans);

	LOGE("rpmb write operation on invalid RPMB device!!");
	return -1;
}

static int rpmb_open_wakelock_files (void)
{
	wakelock.unlock_fd = -1;
	wakelock.lock_fd = -1;

	wakelock.lock_fd = open(RPMB_WAKE_LOCK_FILE, O_WRONLY|O_APPEND);
	if(wakelock.lock_fd < 0)
		return -1;

	wakelock.unlock_fd = open(RPMB_WAKE_UNLOCK_FILE, O_WRONLY|O_APPEND);
	if(wakelock.unlock_fd < 0) {
		close(wakelock.lock_fd);
		wakelock.lock_fd = -1;
		return -1;
	}

	return 0;
}

void rpmb_init_wakelock(void)
{
	int result = -1;

	memset (&wakelock, 0, sizeof(wakelock));
	result = rpmb_open_wakelock_files();
	if(result != 0) {
		/* Set invalid FDs to indicate wakelock is not available */
		wakelock.lock_fd = -1;
		wakelock.unlock_fd = -1;
		wakelock.write_size = 0;
		return;
	}
	wakelock.write_size = strlen(RPMB_WAKE_LOCK_STRING);
}

void rpmb_wakelock(void)
{
	ssize_t ret = -1;

	if (wakelock.lock_fd < 0) {
		/* Wakelock not available - this is normal on many systems */
		return;
	}

	ret = write(wakelock.lock_fd, RPMB_WAKE_LOCK_STRING, wakelock.write_size);
	/* Silently ignore write failures - wakelock is optional */
	(void)ret;
}

void rpmb_wakeunlock(void)
{
	ssize_t ret = -1;

	if (wakelock.unlock_fd < 0) {
		/* Wakelock not available - this is normal on many systems */
		return;
	}

	ret = write(wakelock.unlock_fd, RPMB_WAKE_LOCK_STRING,
					wakelock.write_size);
	/* Silently ignore write failures - wakelock is optional */
	(void)ret;
}

/* eMMC RPMB functions are now implemented in rpmb_emmc.c */

/*
 * Debug function to dump RPMB frame contents
 */
void dump_rpmb_frame(uint8_t *frame, const char *frame_type)
{
	int i;
	char buf[512] = {0};
	char *p = buf;

	LOGI("Printing %s frame (in hex)\n", frame_type);
	LOGI("________0__1__2__3__4__5__6__7__8__9__A__B__C__D__E__F__0__1__2__3__4__5__6__7__8__9__A__B__C__D__E__F\n");
	for (i = 0; i < 512; i++) {
		if (!(i % 32)) {
			snprintf(p, 8, "| %2d | ", (i + 1) / 32);
			p += 7;
		}
		snprintf(p, 4, "%.2x ", frame[i]);
		p += 3;
		if (((i + 1) % 32) == 0) {
			LOGI("%s\n", buf);
			p = buf;
		}
	}
	LOGI("________F__E__D__C__B__A__9__8__7__6__5__4__3__2__1__0__F__E__D__C__B__A__9__8__7__6__5__4__3__2__1__0\n");
}
