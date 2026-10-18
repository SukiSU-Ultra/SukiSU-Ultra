#ifndef __KSU_H_UID_OBSERVER
#define __KSU_H_UID_OBSERVER

void ksu_throne_tracker_init();

void ksu_throne_tracker_exit();

void track_throne(bool prune_only);

/*
 * small helper to check if file exists
 * true - file exists
 * false - file does NOT exist
 *
 */
static inline bool is_file_existing(const char *path) 
{
	struct path kpath;

	if (!!kern_path(path, 0, &kpath))
		return false;
	
	path_put(&kpath);
	return true;
}

/*
 * small helper to check if file is stable
 * note: if we can hold d_lock ourselves, file is stable
 * true - file is stable
 * false - file is deleted / being deleted/renamed
 *
 */
static bool is_file_stable(const char *path) 
{
	struct path kpath;

	// kern_path returns 0 on success
	if (kern_path(path, 0, &kpath))
		return false;

	// just being defensive
	if (!kpath.dentry) {
		path_put(&kpath);
		return false;
	}

	if (!spin_trylock(&kpath.dentry->d_lock)) {
		pr_info("%s: lock held for %s, bail out!\n", __func__, path);
		path_put(&kpath);
		return false;
	}
	// we hold it ourselves here!

	spin_unlock(&kpath.dentry->d_lock);
	path_put(&kpath);
	return true;
}

#endif
