package com.sukisu.ultra.ui.screen

import androidx.annotation.StringRes
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.Archive
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.AdminPanelSettings
import androidx.compose.material.icons.outlined.Archive
import androidx.compose.material.icons.outlined.Extension
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.Dp
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.MainActivity
import com.sukisu.ultra.ui.activity.util.AppData.getKpmVersionUse
import com.sukisu.ultra.ui.activity.util.AppData.isFullFeatured
import com.sukisu.ultra.ui.screen.main.HomePage
import com.sukisu.ultra.ui.screen.main.KpmPage
import com.sukisu.ultra.ui.screen.main.ModulePage
import com.sukisu.ultra.ui.screen.main.SettingsPage
import com.sukisu.ultra.ui.screen.main.SuperUserPage

enum class BottomBarDestination(
    val direction: @Composable (navigator: DestinationsNavigator, bottomPadding: Dp) -> Unit,
    @param:StringRes val label: Int,
    val iconSelected: ImageVector,
    val iconNotSelected: ImageVector,
    val rootRequired: Boolean,
) {
    Home({ navigator, bottomPadding -> HomePage(navigator, bottomPadding) }, R.string.home, Icons.Filled.Home, Icons.Outlined.Home, false),
    Kpm({ navigator, bottomPadding -> KpmPage(bottomPadding) }, R.string.kpm_title, Icons.Filled.Archive, Icons.Outlined.Archive, true),
    SuperUser({ navigator, bottomPadding -> SuperUserPage(navigator, bottomPadding) }, R.string.superuser, Icons.Filled.AdminPanelSettings, Icons.Outlined.AdminPanelSettings, true),
    Module({ navigator, bottomPadding -> ModulePage(navigator, bottomPadding) }, R.string.module, Icons.Filled.Extension, Icons.Outlined.Extension, true),
    Settings({ navigator, bottomPadding -> SettingsPage(navigator, bottomPadding) }, R.string.settings, Icons.Filled.Settings, Icons.Outlined.Settings, false);

    companion object {
        fun getPages(settings: MainActivity.SettingsState) : List<BottomBarDestination> {
            if (isFullFeatured()) {
                // 全功能管理器
                val kpmVersion = getKpmVersionUse()

                val showKpmInfo = settings.showKpmInfo
                return BottomBarDestination.entries.filter {
                    when (it) {
                        Kpm -> {
                            kpmVersion.isNotEmpty() && !kpmVersion.startsWith("Error") && !showKpmInfo && Natives.version >= Natives.MINIMAL_SUPPORTED_KPM
                        }

                        else -> true
                    }
                }
            } else {
                return BottomBarDestination.entries.filter {
                    !it.rootRequired
                }
            }
        }
    }
}
