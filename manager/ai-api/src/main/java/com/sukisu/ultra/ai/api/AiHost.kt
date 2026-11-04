package com.sukisu.ultra.ai.api

import android.content.Context
import android.net.Uri
import java.io.File

/**
 * Stable integration surface shared by the host application and the optional
 * AI library.
 *
 * The host only compiles against this module. The full assistant is an AAR
 * discovered at runtime through [AiFeatureBridge]; when it is absent the host
 * still builds and every AI entry stays hidden.
 */
interface AiHost {
    val context: Context

    
    fun isBackgroundImageActive(): Boolean

    
    fun cardBackgroundAlpha(): Float

    
    fun avatarDrawables(): AiAvatarDrawables?

    
    fun showAiHomeCard(): Boolean

    
    fun registerShowAiHomeCardListener(listener: () -> Unit): AutoCloseable

    
    suspend fun executeRootShell(command: String): AiShellOutput

    val environment: AiEnvironmentService
    val theme: AiThemeService
    val extensions: AiExtensionsService
    val superuser: AiSuperuserService
    val modules: AiModuleService
    val features: AiFeatureService
    val themeImages: AiThemeImageService
}

data class AiAvatarDrawables(
    val iconRes: Int,
    val foregroundRes: Int,
)

data class AiShellOutput(
    val output: String,
    val exitCode: Int,
    val timedOut: Boolean = false,
)


interface AiNavigationTarget

data class AiOpenPageResult(
    val text: String,
    val target: AiNavigationTarget? = null,
    val title: String? = null,
)

data class AiThemeImageResult(
    val displayPath: String,
    val themePath: String,
    val target: String,
)

data class GithubModuleAsset(
    val repo: String,
    val tag: String,
    val name: String,
    val size: Long,
    val url: String,
    val sha256: String?,
)


data class AiEnvironmentScopes(
    val root: Boolean,
    val superuser: Boolean,
    val superuserRootControl: Boolean,
    val superuserTemporaryRoot: Boolean,
    val superuserSwitch: Boolean,
    val modules: Boolean,
    val extensions: Boolean,
    val web: Boolean,
    val theme: Boolean,
    val includeContext: Boolean,
)

interface AiEnvironmentService {
    suspend fun snapshot(scopes: AiEnvironmentScopes, force: Boolean = false): String
}


interface AiThemeService {
    suspend fun read(): String
    fun optionsJson(): String
    fun customTextKeysJson(): String
    suspend fun summaryJson(): String
    suspend fun set(key: String, value: String): String
    suspend fun setCustomText(key: String, text: String): String
    suspend fun resetAppearance(): String
    suspend fun resetAllCustomTexts(): String
    suspend fun clearThemeImage(target: String): String
    suspend fun exportThemePackage(uri: Uri): String
    suspend fun shareThemePackage(): String
}


interface AiExtensionsService {
    suspend fun readOverview(): String
    suspend fun capabilities(): String
    suspend fun toggleExtension(name: String, enabled: Boolean): String
    suspend fun setVersionSpoof(
        version: String? = null,
        full: String? = null,
        uapi: String? = null,
        hideWarning: Boolean? = null,
        reset: Boolean = false,
    ): String

    suspend fun setCpuSpoof(
        cpus: List<Int>,
        midr: String,
        bogomips: Int = 0,
        hwcap: String = "",
        hwcap2: String = "",
    ): String

    suspend fun umount(action: String, path: String? = null, flags: Int = -1): String
    suspend fun dynamicManager(action: String, enabled: Boolean? = null, name: String? = null): String
    suspend fun kpm(
        action: String,
        name: String? = null,
        path: String? = null,
        args: String? = null,
        embed: Boolean = false,
    ): String

    suspend fun susfs(action: String, enabled: Boolean? = null): String
    suspend fun susfsConfigRead(): String
    suspend fun susfsConfigSet(
        action: String,
        enabled: Boolean? = null,
        uname: String? = null,
        buildTime: String? = null,
        path: String? = null,
        newPath: String? = null,
        packageName: String? = null,
        oldConfig: String? = null,
        configFields: String? = null,
        packages: List<String> = emptyList(),
        fileUri: Uri? = null,
    ): String
}


interface AiSuperuserService {
    suspend fun capabilities(): String
    suspend fun readApps(limit: Int = 50, includeDenied: Boolean = false): String
    suspend fun appInfo(packageName: String? = null, uid: Int? = null): String
    suspend fun setRoot(packageName: String?, uid: Int?, enabled: Boolean): String
    suspend fun setTemporaryRoot(
        packageName: String?,
        uid: Int?,
        seconds: Long?,
        untilReboot: Boolean,
        revoke: Boolean,
    ): String

    suspend fun setGlobalSu(mode: String): String
}


interface AiModuleService {
    suspend fun installedModules(limit: Int = 80): String
    fun moduleCapabilities(): String
    suspend fun search(query: String?, limit: Int = 8): String
    suspend fun install(moduleId: String, version: String? = null, onProgress: (String) -> Unit = {}): String
    suspend fun installGithubAsset(asset: GithubModuleAsset, onProgress: (String) -> Unit = {}): String
}


interface AiFeatureService {
    suspend fun entriesJson(rootProbeAllowed: Boolean = true, extensionReadAllowed: Boolean = true): String
    suspend fun openPage(
        id: String,
        rootProbeAllowed: Boolean = true,
        extensionReadAllowed: Boolean = true,
        allowSuperuserRead: Boolean = true,
        packageName: String? = null,
        uid: Int? = null,
        moduleId: String? = null,
        section: String? = null,
        tab: String? = null,
    ): AiOpenPageResult
}

/**
 * Theme image storage. Image generation/editing stays in the optional library;
 * the host only stores the resulting files and exposes the current slots.
 */
interface AiThemeImageService {
    suspend fun applyToTheme(source: File, target: String): AiThemeImageResult
    suspend fun setFromUri(uri: Uri, target: String): AiThemeImageResult
    fun currentThemeImage(target: String): File?
    fun shareImages(files: List<File>, title: String): Boolean
}
