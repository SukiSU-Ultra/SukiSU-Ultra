package com.sukisu.ultra.ui.navigation3

import android.net.Uri
import android.os.Parcelable
import kotlinx.parcelize.Parcelize
import kotlinx.serialization.Serializable
import com.sukisu.ultra.ui.screen.flash.FlashIt
import com.sukisu.ultra.ui.screen.modulerepo.RepoModuleArg
import com.sukisu.ultra.ui.screen.scriptrun.ScriptRunArg
import com.sukisu.ultra.ui.util.FlashItSerializer
import com.sukisu.ultra.ui.util.RepoModuleArgSerializer
import com.sukisu.ultra.ui.util.ScriptRunArgSerializer
import com.sukisu.ultra.ui.util.TemplateInfoSerializer
import com.sukisu.ultra.ui.util.UriSerializer
import com.sukisu.ultra.ui.viewmodel.TemplateViewModel
import top.yukonga.miuix.kmp.nav.core.NavKey

/**
 * Type-safe navigation keys for miuix-nav.
 * Each destination is a NavKey (data object/data class) and can be saved/restored in the back stack.
 */
@Serializable
sealed interface Route : NavKey, Parcelable {
    @Parcelize
    @Serializable
    data object Main : Route

    @Parcelize
    @Serializable
    data object Home : Route

    @Parcelize
    @Serializable
    data object SuperUser : Route

    @Parcelize
    @Serializable
    data object Module : Route

    @Parcelize
    @Serializable
    data object Settings : Route

    @Parcelize
    @Serializable
    data object About : Route

    @Parcelize
    @Serializable
    data object Sulog : Route

    
    @Parcelize
    @Serializable
    data class ColorPalette(
        val section: String? = null,
        
        val importUri: String? = null,
    ) : Route

    @Parcelize
    @Serializable
    data object AppearanceOverlay : Route

    @Parcelize
    @Serializable
    data object CustomTexts : Route

    
    @Parcelize
    @Serializable
    data class ThemeStore(
        val themeId: String? = null,
        val sourceBaseUrl: String? = null,
    ) : Route

    
    @Parcelize
    @Serializable
    data object ThemeStoreAdaptiveUpload : Route

    
    @Parcelize
    @Serializable
    data object ThemeStoreSources : Route

    
    @Parcelize
    @Serializable
    data class ThemeAccount(val tab: String? = null) : Route

    
    @Parcelize
    @Serializable
    data object AdaptiveThemeBuilder : Route

    
    @Parcelize
    @Serializable
    data object AppIcon : Route

    
    @Parcelize
    @Serializable
    data class BackgroundCrop(val sourcePath: String) : Route

    @Parcelize
    @Serializable
    data object AppProfileTemplate : Route

    @Parcelize
    @Serializable
    data class TemplateEditor(
        @Serializable(with = TemplateInfoSerializer::class) val template: TemplateViewModel.TemplateInfo,
        val readOnly: Boolean
    ) : Route

    @Parcelize
    @Serializable
    data class AppProfile(val uid: Int) : Route

    @Parcelize
    @Serializable
    data class Install(@Serializable(with = UriSerializer::class) val preselectedKernelUri: Uri? = null) : Route

    @Parcelize
    @Serializable
    data class ModuleRepoDetail(@Serializable(with = RepoModuleArgSerializer::class) val module: RepoModuleArg) : Route

    @Parcelize
    @Serializable
    data object ModuleRepo : Route

    @Parcelize
    @Serializable
    data class Flash(@Serializable(with = FlashItSerializer::class) val flashIt: FlashIt) : Route

    @Parcelize
    @Serializable
    data class ExecuteModuleAction(val moduleId: String, val fromShortcut: Boolean = false) : Route

    @Parcelize
    @Serializable
    data class ScriptRun(@Serializable(with = ScriptRunArgSerializer::class) val arg: ScriptRunArg) : Route

    @Parcelize
    @Serializable
    data class KernelFlash(@Serializable(with = UriSerializer::class) val kernelUri: Uri, val selectedSlot: String?, val kpmPatchEnabled: Boolean, val kpmUndoPatch: Boolean) : Route

    @Parcelize
    @Serializable
    data object Kpm: Route

    
    @Parcelize
    @Serializable
    data class SuSFS(val tab: String? = null): Route

    @Parcelize
    @Serializable
    data object Tool: Route

    @Parcelize
    @Serializable
    data object UmountManager: Route

    
    @Parcelize
    @Serializable
    data object KernelModules : Route

    @Parcelize
    @Serializable
    data object DynamicManagers : Route

    
    @Parcelize
    @Serializable
    data object Extensions : Route

    
    @Parcelize
    @Serializable
    data object CpuSpoof : Route

    
    @Parcelize
    @Serializable
    data object VersionSpoof : Route

    
    @Parcelize
    @Serializable
    data object AiAssistant : Route

    
    @Parcelize
    @Serializable
    data object AiSettings : Route
}
