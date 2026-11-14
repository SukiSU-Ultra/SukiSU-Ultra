package com.sukisu.ultra.ui.screen.kernelmodules

import com.sukisu.ultra.ui.util.KNOWN_BLOCKABLE_MODULES
import com.sukisu.ultra.ui.util.getRootShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Reads the blocklist state in one root shell round trip.
 *
 * The kernel's native `module_blacklist` is a core_param with mode 0400, so
 * root can read the *effective* list from sysfs. `/ksu_config` is the ramdisk
 * copy written by boot-patch, and the kernel command line covers a built-in
 * setup. /proc/modules and the module tables provide the dependency side.
 */
internal suspend fun readKernelModulesSnapshot(): KernelModulesSnapshot =
    withContext(Dispatchers.IO) {
        val result = getRootShell().newJob()
            .add(KERNEL_MODULES_SCRIPT)
            .to(ArrayList(), null)
            .exec()
        if (!result.isSuccess) {
            error(result.err.joinToString("\n").ifBlank { "cannot read kernel module state" })
        }
        KernelModulesParser.buildSnapshot(
            KernelModulesParser.parseShellOutput(result.out),
            KNOWN_BLOCKABLE_MODULES.toSet(),
        )
    }

private val KERNEL_MODULES_SCRIPT = $$"""
    echo '__KSU_SECTION__ active'
    if cat /sys/module/kernel/parameters/module_blacklist 2>/dev/null; then
      echo
      echo '__KSU_FLAG__ active=1'
    else
      echo '__KSU_FLAG__ active=0'
    fi
    echo '__KSU_SECTION__ config'
    if cat /ksu_config 2>/dev/null; then
      echo
      echo '__KSU_FLAG__ config=1'
    else
      echo '__KSU_FLAG__ config=0'
    fi
    echo '__KSU_SECTION__ cmdline'
    cat /proc/cmdline 2>/dev/null
    echo
    echo '__KSU_SECTION__ proc'
    cat /proc/modules 2>/dev/null
    echo
    dep_dir=''
    for d in /lib/modules /lib/modules/* /vendor/lib/modules /vendor_dlkm/lib/modules /system/lib/modules /system_dlkm/lib/modules /odm/lib/modules; do
      if [ -f "$d/modules.dep" ]; then
        dep_dir="$d"
        break
      fi
    done
    echo '__KSU_SECTION__ dep'
    if [ -n "$dep_dir" ] && cat "$dep_dir/modules.dep" 2>/dev/null; then
      echo
      echo '__KSU_FLAG__ dep=1'
      echo "__KSU_FLAG__ dir=$dep_dir"
      echo '__KSU_SECTION__ load'
      cat "$dep_dir/modules.load" 2>/dev/null
      echo
      echo '__KSU_SECTION__ blocklist'
      cat "$dep_dir/modules.blocklist" 2>/dev/null
      echo
    else
      echo '__KSU_FLAG__ dep=0'
    fi
""".trimIndent()
