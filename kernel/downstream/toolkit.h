// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 \xx
 *
 * This file is a downstream extension and NOT affiliated, endorsed by,
 * or maintained by the official KernelSU developers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#pragma once
#ifndef __KSU_H_TOOLKIT
#define __KSU_H_TOOLKIT

// extensions
#define CHANGE_MANAGER_UID 	10006
#define KSU_UMOUNT_GETSIZE 	107	// get list size // shit is u8 we cant fit 10k+ on it
#define KSU_UMOUNT_GETLIST 	108	// get list
#define GET_SULOG_DUMP		10009	// get sulog dump, max, last 100 escalations, deprecated
#define GET_SULOG_DUMP_V2	10010	// get sulog dump, timestamped, last 250 escalations
#define CHANGE_KSUVER		10011	// change ksu version
#define CHANGE_SPOOF_UNAME	10012	// spoof uname
#define CHANGE_KSUFLAGS		10013	// change ksuflags, do the bit calc on your own, 0 + 1 + 2 + 4 + 8 blah

static uint32_t ksuver_override = 0;
static uint32_t ksuflags_override = 0;

static inline int toolkit_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{
	// only root is allowed for these commands
	if (!!current_uid().val)
		return 0;
	
	// extensions
	uint64_t reply = (uint64_t)*(void **)arg;

	if (magic2 == CHANGE_MANAGER_UID)
		goto change_manager_uid;

	// deprecated
	if (magic2 == GET_SULOG_DUMP)
		return 0;

	if (magic2 == GET_SULOG_DUMP_V2)
		goto get_sulog_dump_v2;

	if (magic2 == CHANGE_KSUVER)
		goto change_ksuver;

	if (magic2 == CHANGE_SPOOF_UNAME)
		goto change_spoof_uname;

	if (magic2 == CHANGE_KSUFLAGS)
		goto change_ksuflags;
	
	return 0;

change_manager_uid:
	pr_info("toolkit: ksu_set_manager_appid to: %d\n", cmd);
	ksu_set_manager_appid(cmd);

	if (cmd != ksu_get_manager_appid())
		return 0;
	
	return !!copy_to_user((void __user *)*arg, &reply, sizeof(reply));

get_sulog_dump_v2:
	if (!!send_sulog_dump(*arg))
		return 0;

	return !!copy_to_user((void __user *)*arg, &reply, sizeof(reply));

change_ksuver:
	pr_info("toolkit: ksu_change_ksuver to: %d\n", cmd);
	ksuver_override = cmd;

	return !!copy_to_user((void __user *)*arg, &reply, sizeof(reply));

// WARNING!!! triple ptr zone! ***
// https://wiki.c2.com/?ThreeStarProgrammer
// https://github.com/backslashxx/ksu_toolkit/pull/1
change_spoof_uname:
{ // scope ++
	char release_buf[65];
	char version_buf[65];
	static char original_release_buf[65] = {0};
	static char original_version_buf[65] = {0};

	// basically void * void __user * void __user *arg
	void ***ppptr = (void ***)(uintptr_t)arg;

	// user pointer storage
	// init this as zero so this works on 32-on-64 compat (LE)
	uint64_t u_pptr = 0;
	uint64_t u_ptr = 0;

	pr_info("toolkit: ppptr: 0x%lx \n", (uintptr_t)ppptr);

	// arg here is ***, dereference to pull out **
	if (copy_from_user(&u_pptr, (void __user *)*ppptr, sizeof(u_pptr)))
		return 0;

	pr_info("toolkit: u_pptr: 0x%lx \n", (uintptr_t)u_pptr);

	// now we got the __user **
	// we cannot dereference this as this is __user
	// we just do another copy_from_user to get it
	if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
		return 0;

	pr_info("toolkit: u_ptr: 0x%lx \n", (uintptr_t)u_ptr);

	// for release
	if (strncpy_from_user(release_buf, (char __user *)u_ptr, sizeof(release_buf)) < 0)
		return 0;

	// for version
	if (strncpy_from_user(version_buf, (char __user *)(u_ptr + strlen(release_buf) + 1), sizeof(version_buf)) < 0)
		return 0;

	release_buf[sizeof(release_buf) - 1] = '\0'; 
	version_buf[sizeof(version_buf) - 1] = '\0'; 

	if (original_release_buf[0] == '\0') {
		struct new_utsname *u_curr = utsname();
		// we save current version as the original before modifying
		strscpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
		strscpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
		pr_info("toolkit: original uname saved: %s %s\n", original_release_buf, original_version_buf);
	}

	constexpr char d[] = "default";
	if (!memcmp_inline(release_buf, d, sizeof(d)))
		memcpy(release_buf, original_release_buf, sizeof(release_buf));
	if (!memcmp_inline(version_buf, d, sizeof(d)))
		memcpy(version_buf, original_version_buf, sizeof(version_buf));

	pr_info("toolkit: spoofing kernel to: %s - %s\n", release_buf, version_buf);

	struct new_utsname *u = utsname();

	down_write(&uts_sem);
	strscpy(u->release, release_buf, sizeof(u->release));
	strscpy(u->version, version_buf, sizeof(u->version));
	up_write(&uts_sem);

	// we write our confirmation on **
	return !!copy_to_user((void __user *)*arg, &reply, sizeof(reply));
	
} // scope --

change_ksuflags:
	pr_info("toolkit: ksu_change_ksuflags to: %d\n", cmd);
	ksuflags_override = cmd;

	return !!copy_to_user((void __user *)*arg, &reply, sizeof(reply));
}

#endif // __KSU_H_TOOLKIT
