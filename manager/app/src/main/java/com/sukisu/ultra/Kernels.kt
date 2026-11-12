package com.sukisu.ultra

import android.system.Os

/**
 * @author weishu
 * @date 2022/12/10.
 */

data class KernelVersion(val major: Int, val patchLevel: Int, val subLevel: Int) {
    override fun toString(): String {
        return "$major.$patchLevel.$subLevel"
    }

    fun isGKI(): Boolean {

        // kernel 6.x
        if (major > 5) {
            return true
        }

        // kernel 5.10.x
        if (major == 5) {
            return patchLevel >= 10
        }

        return false
    }

    /**
     * Whether this kernel is within the range the manager can install and
     * manage at all.
     *
     * GKI-ness only selects the install method: GKI kernels can use the
     * LKM/direct flows, while non-GKI trees fall back to boot-image
     * patching. It must not be used as a support check, otherwise working
     * non-GKI kernels (4.9, 5.4, vendor 3.4 ...) are reported as
     * "Unsupported" on the home card. KernelSU's oldest supported tree is
     * Linux 3.4.
     */
    fun isSupported(): Boolean {
        // parseKernelVersion() returns (-1, -1, -1) when uname is unreadable.
        if (major < 0 || patchLevel < 0) return false
        return major > 3 || (major == 3 && patchLevel >= 4)
    }
}

fun parseKernelVersion(version: String): KernelVersion {
    val find = "(\\d+)\\.(\\d+)\\.(\\d+)".toRegex().find(version)
    if (find != null) {
        val major = find.groupValues[1].toIntOrNull()
        val patchLevel = find.groupValues[2].toIntOrNull()
        val subLevel = find.groupValues[3].toIntOrNull()
        if (major != null && patchLevel != null && subLevel != null) {
            return KernelVersion(major, patchLevel, subLevel)
        }
    }
    return KernelVersion(-1, -1, -1)
}

fun getKernelVersion(): KernelVersion {
    Os.uname().release.let {
        return parseKernelVersion(it)
    }
}