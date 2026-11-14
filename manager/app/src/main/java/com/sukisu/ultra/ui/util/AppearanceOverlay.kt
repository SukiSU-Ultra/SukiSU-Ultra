package com.sukisu.ultra.ui.util

import com.sukisu.ultra.data.repository.SettingsRepository
import java.io.InputStream
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Static appearance overlay shared by the user editor and theme packages.
 *
 * This is deliberately a closed, data-only schema: colors are hex strings, image effects are
 * plain numbers, and the only branching dimension is light/dark. There are no expressions,
 * references or per-screen values, so the overlay is parsed once at the boundary and the
 * Compose tree only ever reads resolved primitives.
 */
@Serializable
data class AppearanceOverlayData(
    val schema: Int = AppearanceOverlayStore.SCHEMA_VERSION,
    val colors: AppearanceColorsData? = null,
    val image: AppearanceImageData? = null,
)

@Serializable
data class AppearanceColorsData(
    /** Applied to both modes before the mode-specific section. */
    val shared: ColorTokensData? = null,
    val light: ColorTokensData? = null,
    val dark: ColorTokensData? = null,
)

@Serializable
data class ColorTokensData(
    val accent: String? = null,
    val onAccent: String? = null,
    val textPrimary: String? = null,
    val textSecondary: String? = null,
    val textDisabled: String? = null,
    val surface: String? = null,
    val card: String? = null,
    val outline: String? = null,
    val error: String? = null,
)

@Serializable
data class AppearanceImageData(
    val background: ImageEffectsData? = null,
)

@Serializable
data class ImageEffectsData(
    /** Unsharp mask strength, 0..100. */
    val sharpen: Float? = null,
    /** Color saturation in percent, 20..200. */
    val saturation: Float? = null,
    /** Color contrast in percent, 20..200. */
    val contrast: Float? = null,
    /** Brightness offset in percent, -100..100. */
    val brightness: Float? = null,
)

enum class AppearanceColorToken {
    ACCENT,
    ON_ACCENT,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    TEXT_DISABLED,
    SURFACE,
    CARD,
    OUTLINE,
    ERROR,
}

/** Which section of [AppearanceColorsData] a colour row edits. */
enum class AppearanceColorMode {
    SHARED,
    LIGHT,
    DARK,
}

enum class AppearanceEffectKey {
    SHARPEN,
    SATURATION,
    CONTRAST,
    BRIGHTNESS,
}

fun ColorTokensData.value(token: AppearanceColorToken): String? = when (token) {
    AppearanceColorToken.ACCENT -> accent
    AppearanceColorToken.ON_ACCENT -> onAccent
    AppearanceColorToken.TEXT_PRIMARY -> textPrimary
    AppearanceColorToken.TEXT_SECONDARY -> textSecondary
    AppearanceColorToken.TEXT_DISABLED -> textDisabled
    AppearanceColorToken.SURFACE -> surface
    AppearanceColorToken.CARD -> card
    AppearanceColorToken.OUTLINE -> outline
    AppearanceColorToken.ERROR -> error
}

fun ColorTokensData.withValue(token: AppearanceColorToken, value: String?): ColorTokensData =
    when (token) {
        AppearanceColorToken.ACCENT -> copy(accent = value)
        AppearanceColorToken.ON_ACCENT -> copy(onAccent = value)
        AppearanceColorToken.TEXT_PRIMARY -> copy(textPrimary = value)
        AppearanceColorToken.TEXT_SECONDARY -> copy(textSecondary = value)
        AppearanceColorToken.TEXT_DISABLED -> copy(textDisabled = value)
        AppearanceColorToken.SURFACE -> copy(surface = value)
        AppearanceColorToken.CARD -> copy(card = value)
        AppearanceColorToken.OUTLINE -> copy(outline = value)
        AppearanceColorToken.ERROR -> copy(error = value)
    }

fun ColorTokensData.isEmpty(): Boolean =
    accent == null &&
        onAccent == null &&
        textPrimary == null &&
        textSecondary == null &&
        textDisabled == null &&
        surface == null &&
        card == null &&
        outline == null &&
        error == null

fun AppearanceColorsData.tokensFor(mode: AppearanceColorMode): ColorTokensData? = when (mode) {
    AppearanceColorMode.SHARED -> shared
    AppearanceColorMode.LIGHT -> light
    AppearanceColorMode.DARK -> dark
}

fun AppearanceOverlayData.colorTokenValue(
    mode: AppearanceColorMode,
    token: AppearanceColorToken,
): String? = colors?.tokensFor(mode)?.value(token)

/** Explicit value for [mode], or the shared value when the mode has no override. */
fun AppearanceOverlayData.effectiveColorToken(
    mode: AppearanceColorMode,
    token: AppearanceColorToken,
): Pair<AppearanceColorMode, String>? {
    colorTokenValue(mode, token)?.let { return mode to it }
    if (mode != AppearanceColorMode.SHARED) {
        colorTokenValue(AppearanceColorMode.SHARED, token)?.let {
            return AppearanceColorMode.SHARED to it
        }
    }
    return null
}

fun AppearanceOverlayData.withColorToken(
    mode: AppearanceColorMode,
    token: AppearanceColorToken,
    value: String?,
): AppearanceOverlayData {
    val current = colors ?: AppearanceColorsData()
    val section = current.tokensFor(mode) ?: ColorTokensData()
    val updated = section.withValue(token, value)
    val nextColors = when (mode) {
        AppearanceColorMode.SHARED -> current.copy(shared = updated.takeUnless { it.isEmpty() })
        AppearanceColorMode.LIGHT -> current.copy(light = updated.takeUnless { it.isEmpty() })
        AppearanceColorMode.DARK -> current.copy(dark = updated.takeUnless { it.isEmpty() })
    }
    val normalized = nextColors.takeUnless {
        it.shared == null && it.light == null && it.dark == null
    }
    return copy(colors = normalized)
}

fun ImageEffectsData.value(key: AppearanceEffectKey): Float? = when (key) {
    AppearanceEffectKey.SHARPEN -> sharpen
    AppearanceEffectKey.SATURATION -> saturation
    AppearanceEffectKey.CONTRAST -> contrast
    AppearanceEffectKey.BRIGHTNESS -> brightness
}

fun ImageEffectsData.withValue(key: AppearanceEffectKey, value: Float?): ImageEffectsData =
    when (key) {
        AppearanceEffectKey.SHARPEN -> copy(sharpen = value)
        AppearanceEffectKey.SATURATION -> copy(saturation = value)
        AppearanceEffectKey.CONTRAST -> copy(contrast = value)
        AppearanceEffectKey.BRIGHTNESS -> copy(brightness = value)
    }

fun ImageEffectsData.isEmpty(): Boolean =
    sharpen == null && saturation == null && contrast == null && brightness == null

fun AppearanceOverlayData.imageEffectValue(key: AppearanceEffectKey): Float? =
    image?.background?.value(key)

fun AppearanceOverlayData.withImageEffect(
    key: AppearanceEffectKey,
    value: Float?,
): AppearanceOverlayData {
    val current = image?.background ?: ImageEffectsData()
    val updated = current.withValue(key, value)
    val nextImage = if (updated.isEmpty()) null else AppearanceImageData(background = updated)
    return copy(image = nextImage)
}

fun Int.toOverlayColorString(): String =
    java.lang.String.format(java.util.Locale.ROOT, "#%08X", this)


data class ResolvedColorTokens(
    val values: Map<AppearanceColorToken, Int> = emptyMap(),
) {
    val isEmpty: Boolean get() = values.isEmpty()

    /** [this] wins over [base], one token at a time. */
    fun over(base: ResolvedColorTokens): ResolvedColorTokens =
        if (values.isEmpty()) base else ResolvedColorTokens(base.values + values)
}

data class ResolvedImageEffects(
    val sharpen: Float = 0f,
    val saturation: Float = 100f,
    val contrast: Float = 100f,
    val brightness: Float = 0f,
) {
    val affectsColor: Boolean
        get() = saturation != 100f || contrast != 100f || brightness != 0f

    val affectsImage: Boolean
        get() = affectsColor || sharpen > 0f
}

data class ResolvedAppearance(
    val shared: ResolvedColorTokens = ResolvedColorTokens(),
    val light: ResolvedColorTokens = ResolvedColorTokens(),
    val dark: ResolvedColorTokens = ResolvedColorTokens(),
    val background: ResolvedImageEffects? = null,
) {
    val hasColors: Boolean
        get() = !shared.isEmpty || !light.isEmpty || !dark.isEmpty

    val hasImageEffects: Boolean
        get() = background?.affectsImage == true

    val isEmpty: Boolean
        get() = !hasColors && !hasImageEffects

    private val lightTokens: ResolvedColorTokens by lazy { light.over(shared) }
    private val darkTokens: ResolvedColorTokens by lazy { dark.over(shared) }

    /** Shared tokens first, then the active mode's overrides. Cached per mode. */
    fun colorsFor(dark: Boolean): ResolvedColorTokens =
        if (dark) darkTokens else lightTokens
}

data class ParsedAppearance(
    val data: AppearanceOverlayData,
    val resolved: ResolvedAppearance,
)

/**
 * Parses and caches the overlay. The canonical JSON string is the only persisted form; the
 * resolved object is cached so `ThemeController.getAppSettings()` never decodes during
 * composition. A cache miss happens once per settings change, not per frame.
 */
object AppearanceOverlayStore {
    const val SCHEMA_VERSION = 1
    const val MAX_BYTES = 16 * 1024

    private const val SHARPEN_MIN = 0f
    private const val SHARPEN_MAX = 100f
    private const val SATURATION_MIN = 20f
    private const val SATURATION_MAX = 200f
    private const val CONTRAST_MIN = 20f
    private const val CONTRAST_MAX = 200f
    private const val BRIGHTNESS_MIN = -100f
    private const val BRIGHTNESS_MAX = 100f

    private val strictJson = Json {
        ignoreUnknownKeys = false
        isLenient = false
        encodeDefaults = true
        explicitNulls = false
    }

    private val prettyJson = Json {
        ignoreUnknownKeys = false
        isLenient = false
        encodeDefaults = true
        explicitNulls = false
        prettyPrint = true
        prettyPrintIndent = "  "
    }

    private data class Cached(
        val raw: String,
        val data: AppearanceOverlayData,
        val resolved: ResolvedAppearance,
    )

    @Volatile
    private var cached: Cached? = null

    fun parse(text: String): Result<ParsedAppearance> = runCatching {
        require(text.toByteArray(Charsets.UTF_8).size <= MAX_BYTES) {
            "Appearance JSON must be at most ${MAX_BYTES / 1024} KB"
        }
        val data = strictJson.decodeFromString(AppearanceOverlayData.serializer(), text)
        require(data.schema in 1..SCHEMA_VERSION) {
            "Unsupported appearance schema ${data.schema}"
        }
        ParsedAppearance(data = data, resolved = data.resolve())
    }

    fun encode(data: AppearanceOverlayData): String =
        strictJson.encodeToString(AppearanceOverlayData.serializer(), data)

    fun encodePretty(data: AppearanceOverlayData): String =
        prettyJson.encodeToString(AppearanceOverlayData.serializer(), data)

    /** Returns the ARGB value for a stored colour string, or null when it is invalid. */
    fun parseColorValue(value: String): Int? =
        runCatching { parseColor(value, "color") }.getOrNull()

    fun load(repo: SettingsRepository): ResolvedAppearance? = read(repo)?.second

    fun data(repo: SettingsRepository): AppearanceOverlayData? = read(repo)?.first

    private fun read(repo: SettingsRepository): Pair<AppearanceOverlayData, ResolvedAppearance>? {
        val raw = repo.customAppearanceJson
        if (raw.isBlank()) return null
        cached?.takeIf { it.raw == raw }?.let { return it.data to it.resolved }
        val parsed = parse(raw).getOrNull() ?: return null
        cached = Cached(raw = raw, data = parsed.data, resolved = parsed.resolved)
        return parsed.data to parsed.resolved
    }

    fun save(repo: SettingsRepository, data: AppearanceOverlayData) {
        val resolved = data.resolve()
        val raw = encode(data)
        repo.customAppearanceJson = raw
        cached = Cached(raw = raw, data = data, resolved = resolved)
    }

    fun clear(repo: SettingsRepository) {
        repo.customAppearanceJson = ""
        cached = null
    }

    /**
     * Replaces only the sections selected by the import options. Unselected sections keep the
     * user's current values; selecting a section that the package does not carry clears it.
     */
    fun merge(
        current: AppearanceOverlayData?,
        incoming: AppearanceOverlayData?,
        applyColors: Boolean,
        applyImageEffects: Boolean,
    ): AppearanceOverlayData? {
        val colors = if (applyColors) incoming?.colors else current?.colors
        val image = if (applyImageEffects) incoming?.image else current?.image
        if (colors == null && image == null) return null
        return AppearanceOverlayData(
            schema = SCHEMA_VERSION,
            colors = colors,
            image = image,
        )
    }

    fun readText(input: InputStream): String {
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(4 * 1024)
        var total = 0
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            require(total <= MAX_BYTES) {
                "Appearance JSON must be at most ${MAX_BYTES / 1024} KB"
            }
            output.write(buffer, 0, read)
        }
        return output.toByteArray().toString(Charsets.UTF_8)
    }

    private fun AppearanceOverlayData.resolve(): ResolvedAppearance = ResolvedAppearance(
        shared = colors?.shared?.resolve("colors.shared") ?: ResolvedColorTokens(),
        light = colors?.light?.resolve("colors.light") ?: ResolvedColorTokens(),
        dark = colors?.dark?.resolve("colors.dark") ?: ResolvedColorTokens(),
        background = image?.background?.resolve("image.background"),
    )

    private fun ColorTokensData.resolve(path: String): ResolvedColorTokens {
        val values = buildMap {
            parseColor(accent, "$path.accent")?.let { put(AppearanceColorToken.ACCENT, it) }
            parseColor(onAccent, "$path.onAccent")?.let { put(AppearanceColorToken.ON_ACCENT, it) }
            parseColor(textPrimary, "$path.textPrimary")
                ?.let { put(AppearanceColorToken.TEXT_PRIMARY, it) }
            parseColor(textSecondary, "$path.textSecondary")
                ?.let { put(AppearanceColorToken.TEXT_SECONDARY, it) }
            parseColor(textDisabled, "$path.textDisabled")
                ?.let { put(AppearanceColorToken.TEXT_DISABLED, it) }
            parseColor(surface, "$path.surface")?.let { put(AppearanceColorToken.SURFACE, it) }
            parseColor(card, "$path.card")?.let { put(AppearanceColorToken.CARD, it) }
            parseColor(outline, "$path.outline")?.let { put(AppearanceColorToken.OUTLINE, it) }
            parseColor(error, "$path.error")?.let { put(AppearanceColorToken.ERROR, it) }
        }
        return ResolvedColorTokens(values)
    }

    private fun ImageEffectsData.resolve(path: String): ResolvedImageEffects? {
        if (sharpen == null && saturation == null && contrast == null && brightness == null) {
            return null
        }
        return ResolvedImageEffects(
            sharpen = sharpen.effect("$path.sharpen", SHARPEN_MIN, SHARPEN_MAX, 0f),
            saturation = saturation.effect("$path.saturation", SATURATION_MIN, SATURATION_MAX, 100f),
            contrast = contrast.effect("$path.contrast", CONTRAST_MIN, CONTRAST_MAX, 100f),
            brightness = brightness.effect(
                "$path.brightness",
                BRIGHTNESS_MIN,
                BRIGHTNESS_MAX,
                0f,
            ),
        )
    }

    private fun Float?.effect(path: String, min: Float, max: Float, default: Float): Float {
        if (this == null) return default
        require(isFinite()) { "$path must be a finite number" }
        return coerceIn(min, max)
    }

    private fun parseColor(value: String?, path: String): Int? {
        if (value == null) return null
        val text = value.trim()
        require(text.startsWith("#")) { "$path must be #RRGGBB or #AARRGGBB" }
        val hex = text.substring(1)
        require(hex.length == 6 || hex.length == 8) { "$path must be #RRGGBB or #AARRGGBB" }
        require(hex.all { it.digitToIntOrNull(16) != null }) {
            "$path contains a non-hex character"
        }
        val parsed = hex.toLong(16)
        return if (hex.length == 6) (0xFF000000L or parsed).toInt() else parsed.toInt()
    }
}
