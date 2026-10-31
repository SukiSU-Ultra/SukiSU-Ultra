package com.sukisu.ultra.ui.screen.ai

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import com.sukisu.ultra.ksuApp
import java.net.URI
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Wire format spoken by the configured endpoint. [AUTO] picks a format from the
 * address: Ollama ports/routes, Anthropic routes, everything else OpenAI-compatible.
 */
@Serializable
enum class AiThinkingMode {
    AUTO,
    OFF,
    LOW,
    MEDIUM,
    HIGH;

    companion object {
        fun fromStored(value: String?): AiThinkingMode =
            entries.firstOrNull { it.name == value } ?: AUTO
    }
}

@Serializable
enum class AiProviderFormat {
    AUTO,
    OPENAI,
    OLLAMA,
    ANTHROPIC;

    companion object {
        fun fromStored(value: String?): AiProviderFormat =
            entries.firstOrNull { it.name == value } ?: AUTO

        /** Never returns [AUTO]; used to build the request. */
        fun detect(endpoint: String): AiProviderFormat {
            val lower = endpoint.lowercase()
            return when {
                lower.contains("anthropic") || lower.contains("/messages") -> ANTHROPIC
                lower.contains("/api/chat") || lower.contains("/api/generate") -> OLLAMA
                // Ollama's OpenAI-compatible endpoint lives under /v1 on the same port.
                lower.contains("/v1") -> OPENAI
                lower.contains(":11434") -> OLLAMA
                lower.contains("ollama") -> OLLAMA
                else -> OPENAI
            }
        }
    }
}

/**
 * Everything the assistant needs to talk to a model. Endpoint is the only field
 * without a usable default; a local Ollama server works with just the address
 * and model name.
 */
@Serializable
data class AiConfig(
    val endpoint: String = "",
    val apiKey: String = "",
    val model: String = "",
    /** Optional OpenAI-compatible image model. Blank disables image generation/editing. */
    val imageModel: String = "",
    val format: AiProviderFormat = AiProviderFormat.AUTO,
    val enabled: Boolean = true,
    val thinkingMode: AiThinkingMode = AiThinkingMode.AUTO,
    /** Let the assistant run root-backed tools. Off by default; one request can be granted inline. */
    val allowRootAccess: Boolean = false,
    /** Read granted apps / superuser data. */
    val allowSuperuserAccess: Boolean = false,
    /** Read installed modules and search module sources. */
    val allowModuleAccess: Boolean = false,
    /** Read extension/KPM/SuSFS/version-spoof state. */
    val allowExtensionAccess: Boolean = false,
    /** Search the public web and GitHub. */
    val allowWebAccess: Boolean = false,
    /** Read appearance/theme settings. On by default because it is read-only. */
    val allowThemeRead: Boolean = true,
    /** Master switch for appearance/theme writes. */
    val allowThemeWrite: Boolean = false,
    /** Fine-grained theme write scopes; only consulted when [allowThemeWrite] is on. */
    val themeWriteFeatures: Set<String> = AiThemeFeature.ALL_IDS,
    /** Permit the assistant to change extension state (version/CPU spoof, umount, dynamic manager, KPM). */
    val allowExtensionWrite: Boolean = false,
    /** Fine-grained extension write scopes; only consulted when [allowExtensionWrite] is on. */
    val extensionWriteFeatures: Set<String> = AiExtensionFeature.ALL_IDS,
    /** Permit permanent root grants/revocations for a specified app. */
    val allowSuperuserRootControl: Boolean = false,
    /** Permit temporary root grants/revocations (with a duration) for a specified app. */
    val allowSuperuserTemporaryRoot: Boolean = false,
    /** Permit switching the global su compatibility mode. */
    val allowSuperuserSwitch: Boolean = false,
    /** Permit the assistant to download and install modules from the module registry. */
    val allowModuleInstall: Boolean = false,
    val requireConfirmation: Boolean = true,
    /** Show a Run action on shell code blocks (manual, confirmed). */
    val allowCodeExecution: Boolean = false,
    val includeContext: Boolean = true,
    val streaming: Boolean = true,
    val toolCalling: Boolean = true,
    val keepHistory: Boolean = true,
    val temperature: Float = 0.7f,
    val systemPrompt: String = "",
    /** Expert mode; advanced fields are ignored until this is enabled. */
    val advancedMode: Boolean = false,
    /** JSON object of [AiAdvancedOptions]; parsed only in advanced mode. */
    val advancedOptionsJson: String = "",
) {
    val isConfigured: Boolean
        get() = endpoint.isNotBlank() && model.isNotBlank()

    fun effectiveFormat(): AiProviderFormat =
        if (format == AiProviderFormat.AUTO) AiProviderFormat.detect(endpoint) else format

    val isImageConfigured: Boolean
        get() = imageModel.isNotBlank() && effectiveFormat() == AiProviderFormat.OPENAI

    fun themeFeatureEnabled(feature: AiThemeFeature): Boolean =
        allowThemeWrite && feature.id in themeWriteFeatures

    fun extensionFeatureEnabled(feature: AiExtensionFeature): Boolean =
        allowExtensionWrite && feature.id in extensionWriteFeatures

    fun disabledThemeFeatures(): List<String> =
        AiThemeFeature.entries.filterNot { it.id in themeWriteFeatures }.map { it.id }

    fun disabledExtensionFeatures(): List<String> =
        AiExtensionFeature.entries.filterNot { it.id in extensionWriteFeatures }.map { it.id }

    /** Validated expert options, or safe defaults when disabled/invalid. */
    fun advancedOptions(): AiAdvancedOptions =
        if (!advancedMode) {
            AiAdvancedOptions.DEFAULT
        } else {
            AiAdvancedOptions.parse(advancedOptionsJson).getOrDefault(AiAdvancedOptions.DEFAULT)
        }

    /** OpenAI-compatible image endpoints derived from the chat endpoint. */
    fun resolvedImageEndpoint(): String = resolvedEndpoint()
        .removeSuffix("/chat/completions") + "/images/generations"

    fun resolvedImageEditEndpoint(): String = resolvedEndpoint()
        .removeSuffix("/chat/completions") + "/images/edits"

    /**
     * Accepts a base address or a complete endpoint. Missing schemes default to
     * plain HTTP because local inference servers rarely have TLS.
     */
    fun resolvedEndpoint(): String {
        val raw = endpoint.trim()
        if (raw.isEmpty()) return ""
        val withScheme = if (raw.startsWith("http://", true) || raw.startsWith("https://", true)) {
            raw
        } else {
            "http://$raw"
        }
        val base = withScheme.trimEnd('/')
        val path = runCatching { URI(base).path.orEmpty() }.getOrDefault("")
        val hasCustomPath = path.isNotEmpty() && path != "/"
        return when (effectiveFormat()) {
            AiProviderFormat.OPENAI -> when {
                base.endsWith("/chat/completions", true) -> base
                base.endsWith("/v1", true) -> "$base/chat/completions"
                else -> "$base/v1/chat/completions"
            }

            AiProviderFormat.OLLAMA -> when {
                base.endsWith("/api/chat", true) -> base
                base.endsWith("/api", true) -> "$base/chat"
                hasCustomPath -> "$base/api/chat"
                else -> "$base/api/chat"
            }

            AiProviderFormat.ANTHROPIC -> when {
                base.endsWith("/v1/messages", true) || base.endsWith("/messages", true) -> base
                base.endsWith("/v1", true) -> "$base/messages"
                hasCustomPath -> "$base/v1/messages"
                else -> "$base/v1/messages"
            }

            // effectiveFormat() never returns AUTO, but keep the when exhaustive.
            AiProviderFormat.AUTO -> base
        }
    }
}

@Serializable
data class AiTurn(val role: String, val content: String)

object AiSettings {

    const val PREFS_NAME = "ai_assistant"

    private const val KEY_ENDPOINT = "endpoint"
    private const val KEY_API_KEY = "api_key"
    private const val KEY_MODEL = "model"
    private const val KEY_IMAGE_MODEL = "image_model"
    private const val KEY_FORMAT = "format"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_THINKING_MODE = "thinking_mode"
    private const val KEY_ALLOW_ROOT = "allow_root_access"
    private const val KEY_ALLOW_SUPERUSER = "allow_superuser_access"
    private const val KEY_ALLOW_MODULE = "allow_module_access"
    private const val KEY_ALLOW_EXTENSION = "allow_extension_access"
    private const val KEY_ALLOW_WEB = "allow_web_access"
    private const val KEY_ALLOW_THEME_READ = "allow_theme_read"
    private const val KEY_ALLOW_THEME_WRITE = "allow_theme_write"
    private const val KEY_THEME_WRITE_FEATURES = "theme_write_features"
    private const val KEY_ALLOW_EXTENSION_WRITE = "allow_extension_write"
    private const val KEY_EXTENSION_WRITE_FEATURES = "extension_write_features"
    private const val KEY_ALLOW_SUPERUSER_ROOT = "allow_superuser_root_control"
    private const val KEY_ALLOW_SUPERUSER_TEMP_ROOT = "allow_superuser_temp_root"
    private const val KEY_ALLOW_SUPERUSER_SWITCH = "allow_superuser_switch"
    private const val KEY_ALLOW_MODULE_INSTALL = "allow_module_install"
    private const val KEY_REQUIRE_CONFIRMATION = "require_confirmation"
    private const val KEY_ALLOW_CODE_EXECUTION = "allow_code_execution"
    private const val KEY_INCLUDE_CONTEXT = "include_context"
    private const val KEY_STREAMING = "streaming"
    private const val KEY_TOOL_CALLING = "tool_calling"
    private const val KEY_KEEP_HISTORY = "keep_history"
    private const val KEY_TEMPERATURE = "temperature"
    private const val KEY_SYSTEM_PROMPT = "system_prompt"
    private const val KEY_ADVANCED_MODE = "advanced_mode"
    private const val KEY_ADVANCED_OPTIONS = "advanced_options"
    private const val KEY_HISTORY = "chat_history"

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    fun prefs(): SharedPreferences =
        ksuApp.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /**
     * Missing key means "all features" (migration from the old coarse switches);
     * an explicit empty set means the user deselected every feature.
     */
    private fun readFeatureSet(
        p: SharedPreferences,
        key: String,
        allIds: Set<String>,
        isValid: (String) -> Boolean,
    ): Set<String> {
        val stored = p.getStringSet(key, null) ?: return allIds
        return stored.asSequence().filter(isValid).toSet()
    }

    fun load(): AiConfig {
        val p = prefs()
        return AiConfig(
            endpoint = p.getString(KEY_ENDPOINT, "").orEmpty(),
            apiKey = p.getString(KEY_API_KEY, "").orEmpty(),
            model = p.getString(KEY_MODEL, "").orEmpty(),
            imageModel = p.getString(KEY_IMAGE_MODEL, "").orEmpty(),
            format = AiProviderFormat.fromStored(p.getString(KEY_FORMAT, null)),
            enabled = p.getBoolean(KEY_ENABLED, true),
            thinkingMode = AiThinkingMode.fromStored(p.getString(KEY_THINKING_MODE, null)),
            allowRootAccess = p.getBoolean(KEY_ALLOW_ROOT, false),
            allowSuperuserAccess = p.getBoolean(KEY_ALLOW_SUPERUSER, false),
            allowModuleAccess = p.getBoolean(KEY_ALLOW_MODULE, false),
            allowExtensionAccess = p.getBoolean(KEY_ALLOW_EXTENSION, false),
            allowWebAccess = p.getBoolean(KEY_ALLOW_WEB, false),
            allowThemeRead = p.getBoolean(KEY_ALLOW_THEME_READ, true),
            allowThemeWrite = p.getBoolean(KEY_ALLOW_THEME_WRITE, false),
            themeWriteFeatures = readFeatureSet(
                p = p,
                key = KEY_THEME_WRITE_FEATURES,
                allIds = AiThemeFeature.ALL_IDS,
            ) { AiThemeFeature.fromId(it) != null },
            allowExtensionWrite = p.getBoolean(KEY_ALLOW_EXTENSION_WRITE, false),
            extensionWriteFeatures = readFeatureSet(
                p = p,
                key = KEY_EXTENSION_WRITE_FEATURES,
                allIds = AiExtensionFeature.ALL_IDS,
            ) { AiExtensionFeature.fromId(it) != null },
            allowSuperuserRootControl = p.getBoolean(KEY_ALLOW_SUPERUSER_ROOT, false),
            allowSuperuserTemporaryRoot = p.getBoolean(KEY_ALLOW_SUPERUSER_TEMP_ROOT, false),
            allowSuperuserSwitch = p.getBoolean(KEY_ALLOW_SUPERUSER_SWITCH, false),
            allowModuleInstall = p.getBoolean(KEY_ALLOW_MODULE_INSTALL, false),
            requireConfirmation = p.getBoolean(KEY_REQUIRE_CONFIRMATION, true),
            allowCodeExecution = p.getBoolean(KEY_ALLOW_CODE_EXECUTION, false),
            includeContext = p.getBoolean(KEY_INCLUDE_CONTEXT, true),
            streaming = p.getBoolean(KEY_STREAMING, true),
            toolCalling = p.getBoolean(KEY_TOOL_CALLING, true),
            keepHistory = p.getBoolean(KEY_KEEP_HISTORY, true),
            temperature = p.getFloat(KEY_TEMPERATURE, 0.7f).coerceIn(0f, 2f),
            systemPrompt = p.getString(KEY_SYSTEM_PROMPT, "").orEmpty(),
            advancedMode = p.getBoolean(KEY_ADVANCED_MODE, false),
            advancedOptionsJson = p.getString(KEY_ADVANCED_OPTIONS, "").orEmpty(),
        )
    }

    fun save(config: AiConfig) {
        prefs().edit {
            putString(KEY_ENDPOINT, config.endpoint.trim())
            putString(KEY_API_KEY, config.apiKey.trim())
            putString(KEY_MODEL, config.model.trim())
            putString(KEY_IMAGE_MODEL, config.imageModel.trim())
            putString(KEY_FORMAT, config.format.name)
            putBoolean(KEY_ENABLED, config.enabled)
            putString(KEY_THINKING_MODE, config.thinkingMode.name)
            putBoolean(KEY_ALLOW_ROOT, config.allowRootAccess)
            putBoolean(KEY_ALLOW_SUPERUSER, config.allowSuperuserAccess)
            putBoolean(KEY_ALLOW_MODULE, config.allowModuleAccess)
            putBoolean(KEY_ALLOW_EXTENSION, config.allowExtensionAccess)
            putBoolean(KEY_ALLOW_WEB, config.allowWebAccess)
            putBoolean(KEY_ALLOW_THEME_READ, config.allowThemeRead)
            putBoolean(KEY_ALLOW_THEME_WRITE, config.allowThemeWrite)
            putStringSet(
                KEY_THEME_WRITE_FEATURES,
                config.themeWriteFeatures.filter { AiThemeFeature.fromId(it) != null }.toSet(),
            )
            putBoolean(KEY_ALLOW_EXTENSION_WRITE, config.allowExtensionWrite)
            putStringSet(
                KEY_EXTENSION_WRITE_FEATURES,
                config.extensionWriteFeatures.filter { AiExtensionFeature.fromId(it) != null }.toSet(),
            )
            putBoolean(KEY_ALLOW_SUPERUSER_ROOT, config.allowSuperuserRootControl)
            putBoolean(KEY_ALLOW_SUPERUSER_TEMP_ROOT, config.allowSuperuserTemporaryRoot)
            putBoolean(KEY_ALLOW_SUPERUSER_SWITCH, config.allowSuperuserSwitch)
            putBoolean(KEY_ALLOW_MODULE_INSTALL, config.allowModuleInstall)
            putBoolean(KEY_REQUIRE_CONFIRMATION, config.requireConfirmation)
            putBoolean(KEY_ALLOW_CODE_EXECUTION, config.allowCodeExecution)
            putBoolean(KEY_INCLUDE_CONTEXT, config.includeContext)
            putBoolean(KEY_STREAMING, config.streaming)
            putBoolean(KEY_TOOL_CALLING, config.toolCalling)
            putBoolean(KEY_KEEP_HISTORY, config.keepHistory)
            putFloat(KEY_TEMPERATURE, config.temperature.coerceIn(0f, 2f))
            putString(KEY_SYSTEM_PROMPT, config.systemPrompt)
            putBoolean(KEY_ADVANCED_MODE, config.advancedMode)
            putString(KEY_ADVANCED_OPTIONS, config.advancedOptionsJson)
        }
    }

    fun loadHistory(): List<AiTurn> {
        val stored = prefs().getString(KEY_HISTORY, null) ?: return emptyList()
        return runCatching { json.decodeFromString<List<AiTurn>>(stored) }.getOrDefault(emptyList())
    }

    fun saveHistory(turns: List<AiTurn>) {
        val encoded = json.encodeToString(turns)
        prefs().edit { putString(KEY_HISTORY, encoded) }
    }

    fun clearHistory() {
        prefs().edit { remove(KEY_HISTORY) }
    }
}
