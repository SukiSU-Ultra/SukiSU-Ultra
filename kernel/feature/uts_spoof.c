static void do_spoof_version(struct rw_semaphore *sem, struct uts_namespace *ns,
                             const char *release, const char *version)
{
#ifndef MODULE
    /*
     * Built-in (all 3.4 .. 5.4 builds): init_uts_ns and uts_sem are linked
     * in, so the direct references are safe even when kallsyms could not
     * resolve them (KALLSYMS_ALL off hides data symbols from kallsyms).
     */
    if (!ns)
        ns = &init_uts_ns;
    if (!sem)
        sem = &uts_sem;
#else
    /*
     * Module: uts_sem is not exported on any supported kernel, and a
     * relocation against it would make the module unloadable. Only
     * proceed when the lookup resolved both; LKM requires KALLSYMS_ALL,
     * so the data symbols are available there.
     */
    if (unlikely(!sem || !ns))
        return;
#endif

    down_write(sem);

    if (release && release[0] != '\0') {
        strscpy(ns->name.release, release, sizeof(ns->name.release));
    }
    if (version && version[0] != '\0') {
        strscpy(ns->name.version, version, sizeof(ns->name.version));
    }

    up_write(sem);

    pr_info("ksu: spoofed version: %s, release: %s\n",
            ns->name.version, ns->name.release);
}

void ksu_spoof_version(const char *spoof_release, const char *spoof_version)
{
    struct rw_semaphore *sem = (struct rw_semaphore *)find_kernel_symbol_exact("uts_sem");
    struct uts_namespace *ns = (struct uts_namespace *)find_kernel_symbol_exact("init_uts_ns");

    do_spoof_version(sem, ns, spoof_release, spoof_version);
}

int ksu_set_spoof_version(const char *release, const char *version)
{
    struct rw_semaphore *sem = (struct rw_semaphore *)find_kernel_symbol_exact("uts_sem");
    struct uts_namespace *ns = (struct uts_namespace *)find_kernel_symbol_exact("init_uts_ns");

    do_spoof_version(sem, ns, release, version);

    return 0;
}
