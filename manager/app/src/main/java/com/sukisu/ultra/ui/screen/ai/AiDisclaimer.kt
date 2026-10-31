package com.sukisu.ultra.ui.screen.ai

import android.content.Context
import androidx.annotation.StringRes
import androidx.core.content.edit
import com.sukisu.ultra.R

/**
 * Dangerous permissions that need a second, explicit acknowledgement whenever
 * they are enabled. The same kinds are used by the settings page and the
 * inline capability card in chat.
 */
enum class AiRiskKind(@StringRes val bodyRes: Int) {
    ROOT(R.string.ai_risk_body_root),
    PERMANENT_ROOT(R.string.ai_risk_body_permanent_root),
    TEMPORARY_ROOT(R.string.ai_risk_body_temporary_root),
    GLOBAL_SU(R.string.ai_risk_body_global_su),
    EXTENSION_WRITE(R.string.ai_risk_body_extension_write),
    MODULE_INSTALL(R.string.ai_risk_body_module_install),
    CODE_EXECUTION(R.string.ai_risk_body_code_execution),
    ADVANCED_API(R.string.ai_risk_body_advanced_api),
}

/** Risk acknowledgement required when this capability is switched on, if any. */
fun AiCapability.riskKind(): AiRiskKind? = when (this) {
    AiCapability.ROOT -> AiRiskKind.ROOT
    AiCapability.SUPERUSER_ROOT -> AiRiskKind.PERMANENT_ROOT
    AiCapability.SUPERUSER_TEMP_ROOT -> AiRiskKind.TEMPORARY_ROOT
    AiCapability.SUPERUSER_SWITCH -> AiRiskKind.GLOBAL_SU
    AiCapability.EXTENSIONS -> AiRiskKind.EXTENSION_WRITE
    AiCapability.MODULES -> AiRiskKind.MODULE_INSTALL
    AiCapability.SUPERUSER,
    AiCapability.MODULE_DATA,
    AiCapability.EXTENSION_DATA,
    AiCapability.WEB,
    AiCapability.THEME_READ,
    AiCapability.THEME,
    -> null
}

/**
 * Persisted acknowledgement for the assistant disclaimer. Bump [VERSION] when
 * the disclaimer text changes so users must acknowledge the new version.
 */
object AiDisclaimer {

    const val VERSION = 1

    private const val PREFS = "ai_assistant"
    private const val KEY_ACCEPTED_VERSION = "disclaimer_accepted_version"

    fun isAccepted(context: Context): Boolean =
        prefs(context).getInt(KEY_ACCEPTED_VERSION, 0) >= VERSION

    fun accept(context: Context) {
        prefs(context).edit { putInt(KEY_ACCEPTED_VERSION, VERSION) }
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
