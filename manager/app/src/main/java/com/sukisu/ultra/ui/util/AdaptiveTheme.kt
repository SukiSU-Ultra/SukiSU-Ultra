package com.sukisu.ultra.ui.util

import com.sukisu.ultra.data.repository.SettingsRepository
import com.sukisu.ultra.ui.theme.ColorMode
import java.io.File
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json


@Serializable
data class AdaptiveThemeVariantState(
    val data: ThemeVariantData,
    val backgroundPath: String = "",
    val cardBackgroundPath: String = "",
    val stickers: List<HomeCardSticker> = emptyList(),
)


@Serializable
data class AdaptiveThemeState(
    val light: AdaptiveThemeVariantState,
    val dark: AdaptiveThemeVariantState,
) {
    fun variant(dark: Boolean): AdaptiveThemeVariantState = if (dark) this.dark else light
}


@Serializable
data class AdaptiveThemeDraft(
    val light: AdaptiveThemeVariantState? = null,
    val dark: AdaptiveThemeVariantState? = null,
) {
    val complete: Boolean
        get() = light != null && dark != null

    fun variant(dark: Boolean): AdaptiveThemeVariantState? = if (dark) this.dark else light
}

/**
 * Owns the adaptive theme binding. Both variants are stored once at import time; switching the
 * system mode only swaps the active settings and image paths, so no image is copied again.
 */
object AdaptiveThemeStore {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    fun load(repo: SettingsRepository): AdaptiveThemeState? {
        val raw = repo.adaptiveThemeJson
        if (raw.isBlank()) return null
        return runCatching {
            json.decodeFromString(AdaptiveThemeState.serializer(), raw)
        }.getOrNull()
    }

    fun save(repo: SettingsRepository, state: AdaptiveThemeState) {
        repo.adaptiveThemeJson = json.encodeToString(AdaptiveThemeState.serializer(), state)
    }

    fun clear(repo: SettingsRepository) {
        repo.adaptiveThemeJson = ""
        repo.adaptiveAppliedMode = -1
    }

    fun isActive(repo: SettingsRepository): Boolean = load(repo) != null

    fun loadDraft(repo: SettingsRepository): AdaptiveThemeDraft? {
        val raw = repo.adaptiveDraftJson
        if (raw.isBlank()) return null
        return runCatching {
            json.decodeFromString(AdaptiveThemeDraft.serializer(), raw)
        }.getOrNull()
    }

    fun saveDraft(repo: SettingsRepository, draft: AdaptiveThemeDraft) {
        repo.adaptiveDraftJson = json.encodeToString(AdaptiveThemeDraft.serializer(), draft)
    }

    fun clearDraft(repo: SettingsRepository) {
        repo.adaptiveDraftJson = ""
    }

    
    fun exportPayload(repo: SettingsRepository): ThemePackageAdaptiveExport? {
        val draft = loadDraft(repo)?.takeIf { it.complete }
        val state = if (draft != null) {
            AdaptiveThemeState(
                light = draft.light ?: return null,
                dark = draft.dark ?: return null,
            )
        } else {
            load(repo) ?: return null
        }
        fun variant(value: AdaptiveThemeVariantState): ThemePackageVariantExport =
            ThemePackageVariantExport(
                data = value.data,
                backgroundFile = if (value.data.hasBackground == true) {
                    File(value.backgroundPath).takeIf { it.isFile }
                } else {
                    null
                },
                cardBackgroundFile = if (value.data.hasCardBackground == true) {
                    File(value.cardBackgroundPath).takeIf { it.isFile }
                } else {
                    null
                },
                cardStickerFiles = value.stickers
                    .map { File(it.path) }
                    .filter { it.isFile },
            )
        return ThemePackageAdaptiveExport(
            light = variant(state.light),
            dark = variant(state.dark),
        )
    }

    /**
     * Applies the settings half selected by the current system mode. Mode switches pass
     * [includeChrome] = false: the chrome, gesture and module display settings are global user
     * choices captured at apply time, and silently rewriting them on every light/dark flip would
     * revert whatever the user changed on the appearance page afterwards.
     */
    suspend fun apply(
        repo: SettingsRepository,
        variant: AdaptiveThemeVariantState,
        includeChrome: Boolean = true,
    ) {
        val data = variant.data

        data.miuixMonet?.let { repo.miuixMonet = it }
        if (data.themeMode != null) {
            val currentMode = ColorMode.fromValue(repo.themeMode)
            // Follow the system when the user has not forced a light/dark app mode. A forced mode
            // is kept so the caller can select the matching adaptive half without a feedback loop.
            if (currentMode.isSystem) {
                val monet = data.miuixMonet ?: repo.miuixMonet
                repo.themeMode = if (monet) ColorMode.MONET_SYSTEM.value else ColorMode.SYSTEM.value
            }
        }
        data.keyColor?.let { repo.keyColor = it }
        data.colorStyle
            ?.takeIf { runCatching { com.materialkolor.PaletteStyle.valueOf(it) }.isSuccess }
            ?.let { repo.colorStyle = it }
        data.colorSpec
            ?.takeIf { runCatching { com.materialkolor.dynamiccolor.ColorSpec.SpecVersion.valueOf(it) }.isSuccess }
            ?.let { repo.colorSpec = it }

        data.cardBackgroundAlphaPercent?.let {
            repo.cardBackgroundAlphaPercent = it.coerceIn(ImageStorage.CARD_ALPHA_MIN, ImageStorage.CARD_ALPHA_MAX)
        }
        data.customBackgroundBlurPercent?.let {
            repo.customBackgroundBlurPercent = it.coerceIn(
                ImageStorage.BACKGROUND_BLUR_PERCENT_MIN,
                ImageStorage.BACKGROUND_BLUR_PERCENT_MAX,
            )
        }
        data.customBackgroundScrimPercent?.let {
            repo.customBackgroundScrimPercent = it.coerceIn(
                ImageStorage.BACKGROUND_SCRIM_MIN,
                ImageStorage.BACKGROUND_SCRIM_MAX,
            )
        }

        data.hideHomeCardDecoration?.let { repo.hideHomeCardDecoration = it }
        data.hideHomeCardStatusText?.let { repo.hideHomeCardStatusText = it }

        if (includeChrome) {
            data.uiMode
                ?.takeIf { it == "miuix" || it == "material" }
                ?.let { repo.uiMode = it }
            data.enableFloatingBottomBar?.let { repo.enableFloatingBottomBar = it }
            data.enableFloatingBottomBarBlur?.let { repo.enableFloatingBottomBarBlur = it }
            data.enableNavigationBadge?.let { repo.enableNavigationBadge = it }
            data.enablePredictiveBack?.let { repo.enablePredictiveBack = it }
            data.enableSwipeDismiss?.let { repo.enableSwipeDismiss = it }
            data.enableBlur?.let { repo.enableBlur = it }
            data.pagerInterceptionMode?.let { repo.pagerInterceptionMode = it.coerceIn(0, 2) }
            data.pageScale?.let { repo.pageScale = it.coerceIn(0.8f, 1.1f) }
            data.moduleDescriptionMaxLines?.let { repo.moduleDescriptionMaxLines = it.coerceIn(1, 5) }
        }

        if (data.hasBackground != null) {
            val target = if (data.hasBackground) {
                variant.backgroundPath.takeIf { it.isNotBlank() && File(it).isFile }.orEmpty()
            } else {
                ""
            }
            repo.useSystemWallpaper = false
            if (repo.customBackgroundUri != target) {
                repo.customBackgroundUri = target
                repo.customBackgroundUpdatedAt = System.currentTimeMillis()
            }
        }
        if (data.hasCardBackground != null) {
            repo.homeCardImagePath = if (data.hasCardBackground) {
                variant.cardBackgroundPath.takeIf { it.isNotBlank() && File(it).isFile }.orEmpty()
            } else {
                ""
            }
        }
        if (data.homeCardStickerTransforms != null) {
            repo.homeCardStickers = variant.stickers
                .filter { File(it.path).isFile }
                .take(HomeCardSticker.MAX_COUNT)
        }
    }

    /**
     * Re-applies the variant when the system switched. Returns true when settings changed.
     * The applied-mode marker avoids writing preferences on every recomposition.
     */
    suspend fun sync(repo: SettingsRepository, dark: Boolean): Boolean {
        val state = load(repo) ?: return false
        val mode = if (dark) 1 else 0
        if (repo.adaptiveAppliedMode == mode) return false
        apply(repo, state.variant(dark), includeChrome = false)
        repo.adaptiveAppliedMode = mode
        return true
    }
}
