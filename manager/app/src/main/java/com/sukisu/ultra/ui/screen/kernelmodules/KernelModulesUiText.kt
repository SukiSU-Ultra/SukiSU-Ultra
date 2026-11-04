package com.sukisu.ultra.ui.screen.kernelmodules

import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R

@StringRes
internal fun kernelModuleStatusLabel(status: KernelModuleStatus): Int = when (status) {
    KernelModuleStatus.Blocked -> R.string.kernel_modules_status_blocked
    KernelModuleStatus.BlockedLoaded -> R.string.kernel_modules_status_loaded
    KernelModuleStatus.ConfigPending -> R.string.kernel_modules_status_pending
    KernelModuleStatus.DeviceBlocklist -> R.string.kernel_modules_status_device
    KernelModuleStatus.NotFound -> R.string.kernel_modules_status_missing
}

@Composable
internal fun kernelModuleStatusText(
    status: KernelModuleStatus,
    activeKnown: Boolean,
): String = stringResource(
    if (status == KernelModuleStatus.ConfigPending && !activeKnown) {
        R.string.kernel_modules_status_configured
    } else {
        kernelModuleStatusLabel(status)
    },
)

@StringRes
internal fun kernelModuleReason(entry: KernelModuleEntry, activeKnown: Boolean): Int = when {
    entry.path == null && !entry.loaded -> R.string.kernel_modules_reason_missing
    entry.configured && entry.active -> R.string.kernel_modules_reason_configured
    !entry.configured && entry.active -> R.string.kernel_modules_reason_kernel
    entry.configured -> if (activeKnown) {
        R.string.kernel_modules_reason_pending
    } else {
        R.string.kernel_modules_reason_configured
    }

    entry.deviceBlocklist -> R.string.kernel_modules_reason_device
    else -> R.string.kernel_modules_reason_missing
}

/**
 * One-line explanation under the module name. The known-vendor and still-loaded
 * facts are suffixes because they qualify the source, not replace it.
 */
@Composable
internal fun kernelModuleSummary(
    entry: KernelModuleEntry,
    activeKnown: Boolean,
): String {
    val reason = stringResource(kernelModuleReason(entry, activeKnown))
    val known = stringResource(R.string.kernel_modules_tag_known)
    val stillLoaded = stringResource(R.string.kernel_modules_reason_loaded)
    return buildString {
        append(reason)
        if (entry.knownAntiRoot) append(" · ").append(known)
        if (entry.loaded && (entry.active || entry.deviceBlocklist)) {
            append(" · ").append(stillLoaded)
        }
    }
}

@StringRes
internal fun kernelModulesParamsSourceLabel(source: KernelModulesParamsSource): Int = when (source) {
    KernelModulesParamsSource.Config -> R.string.kernel_modules_params_source_config
    KernelModulesParamsSource.Suggested -> R.string.kernel_modules_params_source_suggested
    KernelModulesParamsSource.Active -> R.string.kernel_modules_params_source_active
    KernelModulesParamsSource.None -> R.string.kernel_modules_params_source_none
}


@Composable
internal fun kernelModulesSourceNotice(snapshot: KernelModulesSnapshot): String? = when {
    !snapshot.activeAvailable && !snapshot.configAvailable ->
        stringResource(R.string.kernel_modules_source_both_unavailable)

    !snapshot.activeAvailable -> stringResource(R.string.kernel_modules_source_active_unavailable)
    !snapshot.configAvailable -> stringResource(R.string.kernel_modules_source_config_unavailable)
    else -> null
}
