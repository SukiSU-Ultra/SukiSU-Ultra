#include <linux/err.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>

#include "allowlist.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "manager.h"
#include "throne_tracker.h"
#include "kernel_compat.h"
#include "dynamic_manager.h"
#include "user_data_scanner.h"

uid_t ksu_manager_uid = KSU_INVALID_UID;


static int get_pkg_from_apk_path(char *pkg, const char *path)
{
	int len = strlen(path);
	if (len >= KSU_MAX_PACKAGE_NAME || len < 1)
		return -1;

	const char *last_slash = NULL;
	const char *second_last_slash = NULL;

	int i;
	for (i = len - 1; i >= 0; i--) {
		if (path[i] == '/') {
			if (!last_slash) {
				last_slash = &path[i];
			} else {
				second_last_slash = &path[i];
				break;
			}
		}
	}

	if (!last_slash || !second_last_slash)
		return -1;

	const char *last_hyphen = strchr(second_last_slash, '-');
	if (!last_hyphen || last_hyphen > last_slash)
		return -1;

	int pkg_len = last_hyphen - second_last_slash - 1;
	if (pkg_len >= KSU_MAX_PACKAGE_NAME || pkg_len <= 0)
		return -1;

	// Copying the package name
	strncpy(pkg, second_last_slash + 1, pkg_len);
	pkg[pkg_len] = '\0';

	return 0;
}

static void crown_manager(const char *apk, struct list_head *uid_data,
			  int signature_index, struct work_buffers *work_buf)
{
	if (get_pkg_from_apk_path(work_buf->package_buffer, apk) < 0) {
		pr_err("Failed to get package name from apk path: %s\n", apk);
		return;
	}

	pr_info("manager pkg: %s, signature_index: %d\n", work_buf->package_buffer, signature_index);

#ifdef KSU_MANAGER_PACKAGE
	// pkg is `/<real package>`
	if (strncmp(work_buf->package_buffer, KSU_MANAGER_PACKAGE, sizeof(KSU_MANAGER_PACKAGE))) {
		pr_info("manager package is inconsistent with kernel build: %s\n",
			KSU_MANAGER_PACKAGE);
		return;
	}
#endif

	struct uid_data *np;

	list_for_each_entry(np, uid_data, list) {
		if (strncmp(np->package, work_buf->package_buffer, KSU_MAX_PACKAGE_NAME) == 0) {
			pr_info("Crowning manager: %s(uid=%d, signature_index=%d, user=%u)\n",
				work_buf->package_buffer, np->uid, signature_index, np->user_id);

			// Dynamic Sign index (100) or multi-manager signatures (>= 2)
			if (signature_index == DYNAMIC_SIGN_INDEX || signature_index >= 2) {
				ksu_add_manager(np->uid, signature_index);
				if (!ksu_is_manager_uid_valid()) {
					ksu_set_manager_uid(np->uid);
				}
			} else {
				ksu_set_manager_uid(np->uid);
			}
			break;
		}
	}
}

struct data_path {
	char dirpath[DATA_PATH_LEN];
	int depth;
	struct list_head list;
};

struct apk_path_hash {
	unsigned int hash;
	bool exists;
	struct list_head list;
};

static struct list_head apk_path_hash_list;

struct my_dir_context {
	struct dir_context ctx;
	struct list_head *data_path_list;
	char *parent_dir;
	void *private_data;
	int depth;
	int *stop;
	bool found_dynamic_manager;
	struct work_buffers *work_buf; // Passing the work buffer
	size_t processed_count;
};

FILLDIR_RETURN_TYPE my_actor(struct dir_context *ctx, const char *name,
			     int namelen, loff_t off, u64 ino,
			     unsigned int d_type)
{
	struct my_dir_context *my_ctx =
		container_of(ctx, struct my_dir_context, ctx);
	struct work_buffers *work_buf = my_ctx->work_buf;

	if (!my_ctx) {
		pr_err("Invalid context\n");
		return FILLDIR_ACTOR_STOP;
	}

	my_ctx->processed_count++;
	if (my_ctx->processed_count % SCHEDULE_INTERVAL == 0) {
		cond_resched();
	}

	if (my_ctx->stop && *my_ctx->stop) {
		pr_info("Stop searching\n");
		return FILLDIR_ACTOR_STOP;
	}

	if (!strncmp(name, "..", namelen) || !strncmp(name, ".", namelen))
		return FILLDIR_ACTOR_CONTINUE; // Skip "." and ".."

	if (d_type == DT_DIR && namelen >= 8 && !strncmp(name, "vmdl", 4) &&
	    !strncmp(name + namelen - 4, ".tmp", 4)) {
		pr_info("Skipping directory: %.*s\n", namelen, name);
		return FILLDIR_ACTOR_CONTINUE; // Skip staging package
	}
 

	if (snprintf(work_buf->path_buffer, DATA_PATH_LEN, "%s/%.*s", my_ctx->parent_dir, 
		     namelen, name) >= DATA_PATH_LEN) {
		pr_err("Path too long: %s/%.*s\n", my_ctx->parent_dir, namelen,
		       name);
		return FILLDIR_ACTOR_CONTINUE;
	}

	if (d_type == DT_DIR && my_ctx->depth > 0 &&
	    (my_ctx->stop && !*my_ctx->stop)) {
		struct data_path *data = kmalloc(sizeof(struct data_path), GFP_ATOMIC);

		if (!data) {
			pr_err("Failed to allocate memory for %s\n", work_buf->path_buffer);
			return FILLDIR_ACTOR_CONTINUE;
		}

		strscpy(data->dirpath, work_buf->path_buffer, DATA_PATH_LEN);
		data->depth = my_ctx->depth - 1;
		list_add_tail(&data->list, my_ctx->data_path_list);
	} else {
		if ((namelen == 8) && (strncmp(name, "base.apk", namelen) == 0)) {
			struct apk_path_hash *pos, *n;
			unsigned int hash = full_name_hash(NULL, work_buf->path_buffer, strlen(work_buf->path_buffer));
			list_for_each_entry(pos, &apk_path_hash_list, list) {
				if (hash == pos->hash) {
					pos->exists = true;
					return FILLDIR_ACTOR_CONTINUE;
				}
			}

			int signature_index = -1;
			bool is_multi_manager = is_dynamic_manager_apk(
				work_buf->path_buffer, &signature_index);

			pr_info("Found new base.apk at path: %s, is_multi_manager: %d, signature_index: %d\n",
				work_buf->path_buffer, is_multi_manager, signature_index);
				
			// Check for dynamic sign or multi-manager signatures
			if (is_multi_manager && (signature_index == DYNAMIC_SIGN_INDEX || signature_index >= 2)) {
				my_ctx->found_dynamic_manager = true;
				crown_manager(work_buf->path_buffer, my_ctx->private_data, 
								signature_index, work_buf);

				struct apk_path_hash *apk_data = kmalloc(sizeof(struct apk_path_hash), GFP_ATOMIC);
				if (apk_data) {
					apk_data->hash = hash;
					apk_data->exists = true;
					list_add_tail(&apk_data->list, &apk_path_hash_list);
				}

			} else if (is_manager_apk(work_buf->path_buffer)) {
				crown_manager(work_buf->path_buffer,
						my_ctx->private_data, 0, work_buf);
				
				if (!my_ctx->found_dynamic_manager && !ksu_is_dynamic_manager_enabled()) {
				*my_ctx->stop = 1;
				}

				// Manager found, clear APK cache list
				if (!ksu_is_dynamic_manager_enabled()) {
				list_for_each_entry_safe(pos, n, &apk_path_hash_list, list) {
					list_del(&pos->list);
					kfree(pos);
					}
				}
			} else {
				struct apk_path_hash *apk_data = kmalloc(sizeof(struct apk_path_hash), GFP_ATOMIC);
				if (apk_data) {
				apk_data->hash = hash;
				apk_data->exists = true;
				list_add_tail(&apk_data->list, &apk_path_hash_list);
				}
			}
		}
	}

	return FILLDIR_ACTOR_CONTINUE;
}

void search_manager(const char *path, int depth, struct list_head *uid_data)
{
	int i, stop = 0;
	struct list_head data_path_list;
	struct work_buffers *work_buf = get_work_buffer();
	
	if (!work_buf) {
		pr_err("Failed to get work buffer for search_manager\n");
		return;
	}
	
	INIT_LIST_HEAD(&data_path_list);
	INIT_LIST_HEAD(&apk_path_hash_list);
	unsigned long data_app_magic = 0;
	bool found_dynamic_manager = false;
	// Initialize APK cache list
	struct apk_path_hash *pos, *n;
	list_for_each_entry(pos, &apk_path_hash_list, list) {
		pos->exists = false;
	}

	// First depth
	struct data_path data;
	strscpy(data.dirpath, path, DATA_PATH_LEN);
	data.depth = depth;
	list_add_tail(&data.list, &data_path_list);

	for (i = depth; i >= 0; i--) {
		struct data_path *pos, *n;

		list_for_each_entry_safe(pos, n, &data_path_list, list) {
			struct my_dir_context ctx = { .ctx.actor = my_actor,
				.data_path_list = &data_path_list,
				.parent_dir = pos->dirpath,
				.private_data = uid_data,
				.depth = pos->depth,
				.stop = &stop,
				.found_dynamic_manager = false,
				.work_buf = work_buf,
				.processed_count = 0 };
			struct file *file;

			if (!stop) {
				file = ksu_filp_open_compat(pos->dirpath, O_RDONLY | O_NOFOLLOW, 0);
				if (IS_ERR(file)) {
					pr_err("Failed to open directory: %s, err: %ld\n", pos->dirpath, PTR_ERR(file));
					goto skip_iterate;
				}
				
				// grab magic on first folder, which is /data/app
				if (!data_app_magic) {
					if (file->f_inode->i_sb->s_magic) {
						data_app_magic = file->f_inode->i_sb->s_magic;
						pr_info("%s: dir: %s got magic! 0x%lx\n", __func__, pos->dirpath, data_app_magic);
					} else {
						filp_close(file, NULL);
						goto skip_iterate;
					}
				}
				
				if (file->f_inode->i_sb->s_magic != data_app_magic) {
					pr_info("%s: skip: %s magic: 0x%lx expected: 0x%lx\n", __func__, pos->dirpath, 
						file->f_inode->i_sb->s_magic, data_app_magic);
					filp_close(file, NULL);
					goto skip_iterate;
				}

				iterate_dir(file, &ctx.ctx);
				filp_close(file, NULL);
				
				if (ctx.found_dynamic_manager) {
					found_dynamic_manager = true;
				}

				cond_resched();
			}
skip_iterate:
			list_del(&pos->list);
			if (pos != &data)
				kfree(pos);
		}

		cond_resched();
	}

	// Remove stale cached APK entries
	list_for_each_entry_safe(pos, n, &apk_path_hash_list, list) {
		if (!pos->exists) {
			list_del(&pos->list);
			kfree(pos);
		}
	}
}

static bool is_uid_exist(uid_t uid, char *package, void *data)
{
	struct list_head *list = (struct list_head *)data;
	struct uid_data *np;

	bool exist = false;
	list_for_each_entry(np, list, list) {
		if (np->uid == uid % 100000 &&
		    strncmp(np->package, package, KSU_MAX_PACKAGE_NAME) == 0) {
			exist = true;
			break;
		}
	}
	return exist;
}

void track_throne()
{
	struct list_head uid_list;
	INIT_LIST_HEAD(&uid_list);
	// scan user data for uids
	int ret = scan_user_data_for_uids(&uid_list, scan_all_users);
	
	if (ret < 0) {
		pr_err("Improved UserDE UID scan failed: %d. scan_all_users=%d\n", ret, scan_all_users);
			goto out;
		}

	// now update uid list
	struct uid_data *np;
	struct uid_data *n;

	// first, check if manager_uid exist!
	bool manager_exist = false;
	bool dynamic_manager_exist = false;

	list_for_each_entry(np, &uid_list, list) {
		// if manager is installed in work profile, the uid in packages.list is still equals main profile
		// don't delete it in this case!
		int manager_uid = ksu_get_manager_uid() % 100000;
		if (np->uid == manager_uid) {
			manager_exist = true;
			break;
		}
	}

	// Check for dynamic managers
	if (ksu_is_dynamic_manager_enabled()) {
		dynamic_manager_exist = ksu_has_dynamic_managers();
		
		if (!dynamic_manager_exist) {
			list_for_each_entry(np, &uid_list, list) {
			// Check if this uid is a dynamic manager (not the traditional manager)
				if (ksu_is_any_manager(np->uid) && np->uid != ksu_get_manager_uid()) {
					dynamic_manager_exist = true;
					break;
				}
			}
		}
	}

	if (!manager_exist) {
		if (ksu_is_manager_uid_valid()) {
			pr_info("manager is uninstalled, invalidate it!\n");
			ksu_invalidate_manager_uid();
			goto prune;
		}
		pr_info("Searching manager...\n");
		search_manager("/data/app", 2, &uid_list);
		pr_info("Search manager finished\n");
		// Always perform search when called from dynamic manager rescan
	} else if (!dynamic_manager_exist && ksu_is_dynamic_manager_enabled()) {
		pr_info("Dynamic sign enabled, Searching manager...\n");
		search_manager("/data/app", 2, &uid_list);
		pr_info("Search Dynamic sign manager finished\n");
	}

prune:
	// then prune the allowlist
	ksu_prune_allowlist(is_uid_exist, &uid_list);
out:
	// free uid_list
	list_for_each_entry_safe (np, n, &uid_list, list) {
		list_del(&np->list);
		kfree(np);
	}
}

void ksu_throne_tracker_init()
{
	// nothing to do
}

void ksu_throne_tracker_exit()
{
	// nothing to do
}
