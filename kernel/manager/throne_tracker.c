static DEFINE_MUTEX(throne_tracker_mutex);

uid_t ksu_manager_appid = KSU_INVALID_APPID;

#define DATA_PATH_LEN 384 // 384 is enough for /data/app/<package>/base.apk

static char cached_manager_apk_path[DATA_PATH_LEN];

// extendable manager support
#define extra_manager_apk(tgt, name) ({			\
	static_assert(__builtin_constant_p(name));	\
	static_assert(DATA_PATH_LEN > sizeof(name));	\
	!strncmp(tgt, name, sizeof(name));		\
})
#define is_kowsu_apk(tgt) extra_manager_apk(tgt, "com.kowx712.supermanager")
#define is_midorisu_apk(tgt) extra_manager_apk(tgt, "com.midori.supermanager")
#define test_extra_pkgs(tgt) (is_kowsu_apk(tgt) || is_midorisu_apk(tgt))

#define SYSTEM_PACKAGES_LIST_PATH "/data/system/packages.list"

static void crown_manager(const char *apk, struct list_head *uid_data)
{
	struct list_head *list = (struct list_head *)uid_data;
	struct uid_data *np;

	list_for_each_entry (np, list, list) {
		if (test_extra_pkgs(np->package) || strncmp(np->package, KSU_PACKAGE_NAME, KSU_MAX_PACKAGE_NAME) == 0) {
			pr_info("Crowning manager: uid=%d\n", np->uid);
			ksu_set_manager_appid(np->uid);
			break;
		}
	}
}

struct data_path {
	char dirpath[DATA_PATH_LEN];
	int depth;
	struct list_head list;
};

struct my_dir_context {
	struct dir_context ctx;
	struct list_head *data_path_list;
	char *parent_dir;
	void *private_data;
	int depth;
};
// https://docs.kernel.org/filesystems/porting.html
// filldir_t (readdir callbacks) calling conventions have changed. Instead of returning 0 or -E... it returns bool now. false means "no more" (as -E... used to) and true - "keep going" (as 0 in old calling conventions). Rationale: callers never looked at specific -E... values anyway. -> iterate_shared() instances require no changes at all, all filldir_t ones in the tree converted.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define FILLDIR_RETURN_TYPE bool
#define FILLDIR_ACTOR_CONTINUE true
#define FILLDIR_ACTOR_STOP false
#else
#define FILLDIR_RETURN_TYPE int
#define FILLDIR_ACTOR_CONTINUE 0
#define FILLDIR_ACTOR_STOP -EINVAL
#endif

static bool maybe_manager_apk_dir(const char *path)
{
	_Static_assert(sizeof(KSU_PACKAGE_NAME) < KSU_MAX_PACKAGE_NAME, "KSU_PACKAGE_NAME too long!");
	char pkg[KSU_MAX_PACKAGE_NAME];
	if (get_pkg_from_apk_dir_path(pkg, path) < 0) {
		pr_err("Failed to get package name from apk dir path: %s\n", path);
		return false;
	}

	if (test_extra_pkgs(pkg))
		return true;

	// pkg is `<real package>`
	return strncmp(pkg, KSU_PACKAGE_NAME, sizeof(KSU_PACKAGE_NAME)) == 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
#define MY_ACTOR_CTX_ARG struct dir_context *ctx
#else
#define MY_ACTOR_CTX_ARG void *ctx_void
#endif

static FILLDIR_RETURN_TYPE my_actor(MY_ACTOR_CTX_ARG, const char *name, int namelen, loff_t off, u64 ino,
									unsigned int d_type)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
	struct dir_context *ctx = (struct dir_context *)ctx_void;
#endif
	struct my_dir_context *my_ctx = container_of(ctx, struct my_dir_context, ctx);

	// we put the apk path we collected here
	char *candidate_path = (char *)my_ctx->private_data;

	char dirpath[DATA_PATH_LEN];

	if (!strncmp(name, "..", namelen) || !strncmp(name, ".", namelen))
		return FILLDIR_ACTOR_CONTINUE; // Skip "." and ".."

	if (d_type == DT_DIR && namelen >= 8 && !strncmp(name, "vmdl", 4) && !strncmp(name + namelen - 4, ".tmp", 4)) {
		pr_info("Skipping directory: %.*s\n", namelen, name);
		return FILLDIR_ACTOR_CONTINUE; // Skip staging package
	}

	if (snprintf(dirpath, DATA_PATH_LEN, "%s/%.*s", my_ctx->parent_dir, namelen, name) >= DATA_PATH_LEN) {
		pr_err("Path too long: %s/%.*s\n", my_ctx->parent_dir, namelen, name);
		return FILLDIR_ACTOR_CONTINUE;
	}

	if (d_type == DT_DIR && my_ctx->depth > 0) {
		struct data_path *data = kzalloc(sizeof(struct data_path), GFP_KERNEL);

		if (!data) {
			pr_err("Failed to allocate memory for %s\n", dirpath);
			return FILLDIR_ACTOR_CONTINUE;
		}

		strscpy(data->dirpath, dirpath, DATA_PATH_LEN);
		data->depth = my_ctx->depth - 1;
		list_add_tail(&data->list, my_ctx->data_path_list);

		return FILLDIR_ACTOR_CONTINUE;
	}

	// now put this on candidate_path
	if (d_type == DT_REG && namelen == 8 && !memcmp(name, "base.apk", 8)) {
		if (maybe_manager_apk_dir(my_ctx->parent_dir)) {
			snprintf(candidate_path, DATA_PATH_LEN, "%s/%.*s", my_ctx->parent_dir, namelen, name);
			strcpy(cached_manager_apk_path, candidate_path);
		}
		// As soon as we met the base.apk, we can stop
		return FILLDIR_ACTOR_STOP;
	}

	return FILLDIR_ACTOR_CONTINUE;
}

// compat: https://elixir.bootlin.com/linux/v3.9/source/include/linux/fs.h#L771
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
#define ksu_get_magic(x) ((x)->f_inode->i_sb->s_magic)
#else
#define ksu_get_magic(x) ((x)->f_path.dentry->d_inode->i_sb->s_magic)
#endif

static noinline void search_manager(const char *path, int depth, struct list_head *uid_data)
{
	int i, stop = 0;
	struct list_head data_path_list;
	INIT_LIST_HEAD(&data_path_list);
	unsigned long data_app_magic = 0;

	char *memory __offstack(sizeof(struct data_path) + DATA_PATH_LEN);

	// First depth
	struct data_path *data = (struct data_path *)memory;
	strscpy(data->dirpath, path, DATA_PATH_LEN);
	data->depth = depth;
	list_add_tail(&data->list, &data_path_list);

	// we put the apk path we collected here
	char *candidate_path = memory + sizeof(struct data_path);
	candidate_path[0] = 0;

	for (i = depth; i >= 0; i--) {
		struct data_path *pos, *n;

		list_for_each_entry_safe (pos, n, &data_path_list, list) {
			if (stop)
				goto skip_iterate;
			struct my_dir_context ctx = { .ctx.actor = my_actor,
							.data_path_list = &data_path_list,
							.parent_dir = pos->dirpath,
							.private_data = candidate_path,
							.depth = pos->depth };
			struct file *file = ksu_filp_open_nonotify(pos->dirpath, O_RDONLY | O_NOFOLLOW | O_NOATIME | O_DIRECTORY);
			if (IS_ERR(file)) {
				pr_err("Failed to open directory: %s, err: %ld\n", pos->dirpath, PTR_ERR(file));
				goto skip_iterate;
			}

			// grab magic on first folder, which is /data/app
			if (!data_app_magic) {
				if (ksu_get_magic(file)) {
					data_app_magic = ksu_get_magic(file);
					pr_info("%s: dir: %s got magic! 0x%lx\n", __func__, pos->dirpath, data_app_magic);
				} else {
					filp_close(file, NULL);
					goto skip_iterate;
				}
			}
				
			if (ksu_get_magic(file) != data_app_magic) {
				pr_info("%s: skip: %s magic: 0x%lx expected: 0x%lx\n", __func__, pos->dirpath, ksu_get_magic(file), data_app_magic);
				filp_close(file, NULL);
				goto skip_iterate;
			}

			iterate_dir(file, &ctx.ctx);
			filp_close(file, NULL);

			if (!candidate_path[0])
				goto skip_iterate;

			// As soon as we get the manager apk path, we can stop
			stop = 1;

			bool is_manager = is_manager_apk(candidate_path);
			pr_info("Found manager base.apk at path: %s, is_manager: %d\n", candidate_path, is_manager);

			// Only crown if signature verification pass
			if (unlikely(!is_manager))
				goto skip_iterate;

			crown_manager(candidate_path, uid_data);

		skip_iterate:
			list_del(&pos->list);
			if (pos != data)
				kfree(pos);
		}
	}
}

static bool is_uid_exist(uid_t uid, char *package, void *data)
{
	struct list_head *list = (struct list_head *)data;
	struct uid_data *np;

	bool exist = false;
	list_for_each_entry (np, list, list) {
		if (np->uid == uid % PER_USER_RANGE && strncmp(np->package, package, KSU_MAX_PACKAGE_NAME) == 0) {
			exist = true;
			break;
		}
	}
	return exist;
}

static void throne_tracker_fn(bool prune_only)
{
	struct file *fp = filp_open(SYSTEM_PACKAGES_LIST_PATH, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_err("%s: open " SYSTEM_PACKAGES_LIST_PATH " failed: %ld\n", __func__, PTR_ERR(fp));
		return;
	}

	struct list_head uid_list;
	INIT_LIST_HEAD(&uid_list);

	char chr = 0;
	loff_t pos = 0;
	loff_t line_start = 0;
	char buf[KSU_MAX_PACKAGE_NAME];
	for (;;) {
		ssize_t count = kernel_read(fp, &chr, sizeof(chr), &pos);
		if (count != sizeof(chr))
			break;
		if (chr != '\n')
			continue;

		count = kernel_read(fp, buf, sizeof(buf) - 1, &line_start);
		if (count <= 0) {
			break;
		}
		buf[count] = '\0';

		struct uid_data *data = kzalloc(sizeof(struct uid_data), GFP_KERNEL);
		if (!data) {
			filp_close(fp, 0);
			goto out;
		}

		char *tmp = buf;
		const char *delim = " ";
		char *package = strsep(&tmp, delim);
		char *uid = strsep(&tmp, delim);
		if (!uid || !package) {
			kfree(data);
			pr_err("update_uid: package or uid is NULL!\n");
			break;
		}

		u32 res;
		if (kstrtou32(uid, 10, &res)) {
			kfree(data);
			pr_err("update_uid: uid parse err\n");
			break;
		}
		data->uid = res;
		strscpy(data->package, package, sizeof(data->package));
		list_add_tail(&data->list, &uid_list);
		// reset line start
		line_start = pos;
	}
	filp_close(fp, 0);

	// now update uid list
	struct uid_data *np;
	struct uid_data *n;

	if (prune_only)
		goto prune;

	// first, check if manager_uid exist!
	uid_t manager_package_uid = KSU_INVALID_APPID;
	bool need_rescan = false;
	list_for_each_entry (np, &uid_list, list) {
		if (test_extra_pkgs(np->package) || strcmp(np->package, KSU_PACKAGE_NAME) == 0) {
			manager_package_uid = np->uid;
			break;
		}
	}

	if (manager_package_uid == KSU_INVALID_APPID) {
		cached_manager_apk_path[0] = 0;
		if (ksu_is_manager_appid_valid()) {
			struct uid_data *cur;
			bool still_installed = false;

			list_for_each_entry (cur, &uid_list, list) {
				if (cur->uid == ksu_get_manager_appid()) {
					still_installed = true;
					break;
				}
			}

			if (still_installed) {
				pr_info("manager uid=%u still installed (signature fallback), skip search!\n",
						ksu_get_manager_appid());
				goto prune;
			}

			pr_info("manager is uninstalled, invalidate it!\n");
			ksu_invalidate_manager_uid();
		}

		if (ksu_sig_fallback_run(&uid_list))
			goto prune;
			
	} else {
		if (!ksu_is_manager_appid_valid()) {
			need_rescan = true;
		} else if (unlikely(np->uid != ksu_get_manager_appid())) {
			// this should not happen in normal android system
			pr_info("manager uid changed, invalidate it!\n");
			cached_manager_apk_path[0] = 0;
			ksu_invalidate_manager_uid();
			need_rescan = true;
		} else {
			// uid unchanged, skip
			pr_info("manager uid unchanged, skip search!\n");
		}
	}

	if (need_rescan) {
		// If the apk path still exists, the verification result won't be changed
		if (cached_manager_apk_path[0]) {
			struct path p;
			int ret = kern_path(cached_manager_apk_path, 0, &p);
			if (ret == 0) {
				// skip search
				pr_info("manager apk path unchanged, skip search!\n");
				path_put(&p);
				goto prune;
			} else if (ret != -ENOENT) {
				pr_err("stat cached manager path failed: %d (path=%s)\n", ret, cached_manager_apk_path);
			}
		}
		pr_info("Searching manager " KSU_PACKAGE_NAME "...\n");
		search_manager("/data/app", 2, &uid_list);
		pr_info("Search manager finished\n");
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

static int throne_tracker_thread(void *data)
{
	// now de-void it here
	bool prune_only = (bool)data;

	pr_info("throne_tracker: pid: %d started\n", current->pid);

	guarded_mutex_lock(&throne_tracker_mutex);

test_tmp:
	if (!is_file_existing("/data/system/packages.list.tmp"))
		goto test_list;

	if (IS_ENABLED(CONFIG_KSU_DEBUG))
		pr_info("throne_tracker: rename not finished! retry!\n");

	msleep(20); // yield
	goto test_tmp;

test_list:
	if (is_file_stable(SYSTEM_PACKAGES_LIST_PATH))
		goto start_tt;

	if (IS_ENABLED(CONFIG_KSU_DEBUG))
		pr_info("throne_tracker: rename not finished! retry!\n");

	msleep(20); // yield
	goto test_list;	

start_tt:
	// lessen that window where user opens manager right away, yet its not crowned
	set_user_nice(current, -10);

	// this in exchange of override creds, we escape this whole thread.
	escape_to_root_forced();
	throne_tracker_fn(prune_only);

	pr_info("throne_tracker: pid: %d exit!\n", current->pid);
	return 0;
}

void track_throne(bool prune_only)
{
#ifndef CONFIG_KSU_THRONE_TRACKER_ALWAYS_THREADED
	static void *label = &&first_run;
	goto *label;

first_run:
	if (guarded_mutex_lock(&throne_tracker_mutex))
		throne_tracker_fn(prune_only);
	
	label = &&threaded;
	return;
threaded:
#endif
	// HACK: force cast prune_only to be a void *
	kthread_run(throne_tracker_thread, (void *)prune_only, "kthread");
}

void __init ksu_throne_tracker_init()
{
	// nothing to do
}

void __exit ksu_throne_tracker_exit()
{
	// nothing to do
}
