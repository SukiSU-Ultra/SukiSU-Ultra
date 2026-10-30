package com.sukisu.ultra.ui.screen.about

import androidx.compose.runtime.Immutable
import com.sukisu.ultra.ui.util.BuiltinAppIcon

@Immutable
data class AboutUiState(
    val title: String,
    val appName: String,
    val versionName: String,
    val icon: BuiltinAppIcon,
    val links: List<LinkInfo>,
    val checkUpdate: Boolean = true,
    val checkCiUpdate: Boolean = false,
    val checkModuleUpdate: Boolean = true,
)

@Immutable
data class AboutScreenActions(
    val onBack: () -> Unit,
    val onOpenLink: (String) -> Unit,
    val onSetCheckUpdate: (Boolean) -> Unit = {},
    val onSetCheckCiUpdate: (Boolean) -> Unit = {},
    val onSetCheckModuleUpdate: (Boolean) -> Unit = {},
)
