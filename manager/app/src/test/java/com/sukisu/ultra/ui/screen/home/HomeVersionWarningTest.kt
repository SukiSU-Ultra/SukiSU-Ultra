package com.sukisu.ultra.ui.screen.home

import com.sukisu.ultra.KernelVersion
import com.sukisu.ultra.ui.util.module.LatestVersionInfo
import org.junit.Assert.*
import org.junit.Test

class HomeVersionWarningTest {
    private fun state() = HomeUiState(
        kernelVersion = KernelVersion(6, 1, 0), ksuVersion = 40000,
        managerUAPIVersion = 6, kernelUAPIVersion = 6, lkmMode = false,
        isLkmBundled = false, isManager = true, isManagerPrBuild = false,
        isKernelPrBuild = false, requiresNewKernel = false, requiresNewManager = false,
        isRootAvailable = true, isSafeMode = false, isLateLoadMode = false,
        checkUpdateEnabled = false, latestVersionInfo = LatestVersionInfo(),
        currentManagerVersionCode = 40000,
        systemInfo = SystemInfo("", "", "", null, "", "Enforcing", 0),
    )

    @Test fun matchingVersionsDoNotWarn() {
        assertFalse(state().showVersionMismatchWarning)
    }

    @Test fun eitherMismatchWarnsByDefault() {
        assertTrue(state().copy(ksuVersion = 40001).showVersionMismatchWarning)
        assertTrue(state().copy(kernelUAPIVersion = 99).showVersionMismatchWarning)
    }

    @Test fun hidingWarningDoesNotChangeCompatibilityFlags() {
        val hidden = state().copy(kernelUAPIVersion = 99, requiresNewManager = true,
            hideVersionMismatchWarning = true)
        assertFalse(hidden.showVersionMismatchWarning)
        assertTrue(hidden.isVersionMismatch)
        assertTrue(hidden.requiresNewManager)
    }

    @Test fun noKernelDoesNotWarn() {
        assertFalse(state().copy(isManager = false, ksuVersion = null).showVersionMismatchWarning)
    }
}
