package com.sukisu.ultra.ui.screen.extensions

import androidx.annotation.StringRes
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.ExtensionState


internal enum class ExtensionPill(@StringRes val labelRes: Int) {
    Unsupported(R.string.extension_status_unsupported_short),
    Forced(R.string.extension_status_forced),
    Managed(R.string.extension_status_managed),
    Enabled(R.string.config_status_applied),
    Disabled(R.string.extension_status_disabled),
    Supported(R.string.extension_status_supported),
}

internal fun pillFor(state: ExtensionState): ExtensionPill = when {
    !state.supported -> ExtensionPill.Unsupported
    state.forced -> ExtensionPill.Forced
    state.managed -> ExtensionPill.Managed
    !state.sticky -> ExtensionPill.Supported
    state.value != 0L -> ExtensionPill.Enabled
    else -> ExtensionPill.Disabled
}
