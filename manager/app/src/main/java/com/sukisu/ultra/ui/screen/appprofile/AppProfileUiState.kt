package com.sukisu.ultra.ui.screen.appprofile

import androidx.compose.runtime.Immutable
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ui.screen.superuser.GroupedApps

@Immutable
data class AppProfileUiState(
    val uid: Int,
    val packageName: String,
    val profile: Natives.Profile,
    val appGroup: GroupedApps,
    val sharedUserId: String,
    val temporaryRoot: Boolean = false,
) {
    val isUidGroup get() = appGroup.apps.size > 1
}

@Immutable
data class AppProfileActions(
    val onPermanentRootChange: (Boolean) -> Unit = {},
    val onTemporaryRootChange: (Boolean) -> Unit = {},
    val onTemporaryRootGrant: (Long?) -> Unit = {},
    val onBack: () -> Unit,
    val onLaunchApp: (String, Int) -> Unit,
    val onForceStopApp: (String, Int) -> Unit,
    val onRestartApp: (String, Int) -> Unit,
    val onViewTemplate: (String) -> Unit,
    val onManageTemplate: () -> Unit,
    val onProfileChange: (Natives.Profile) -> Unit,
)
