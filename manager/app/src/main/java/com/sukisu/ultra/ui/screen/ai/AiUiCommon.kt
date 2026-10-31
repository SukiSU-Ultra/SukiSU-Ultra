package com.sukisu.ultra.ui.screen.ai

import android.content.ClipData
import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.ClipEntry
import androidx.compose.ui.platform.LocalClipboard
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.withLink
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.graphics.drawable.toBitmap
import com.sukisu.ultra.R
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.util.BuiltinAppIcons
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class AiTestState(
    val testing: Boolean = false,
    val message: String? = null,
    val success: Boolean = true,
)

suspend fun runAiConnectionTest(config: AiConfig): AiTestState = withContext(Dispatchers.IO) {
    if (config.endpoint.isBlank()) {
        return@withContext AiTestState(message = ksuApp.getString(R.string.ai_address_required), success = false)
    }
    if (config.model.isBlank()) {
        return@withContext AiTestState(message = ksuApp.getString(R.string.ai_model_required), success = false)
    }
    try {
        val reply = AiApiClient.test(config)
        AiTestState(message = reply.ifBlank { "OK" }, success = true)
    } catch (cancelled: kotlinx.coroutines.CancellationException) {
        throw cancelled
    } catch (error: Exception) {
        AiTestState(
            message = error.message ?: error.javaClass.simpleName,
            success = false,
        )
    }
}

internal fun AiThinkingMode.labelRes(): Int = when (this) {
    AiThinkingMode.AUTO -> R.string.ai_thinking_auto
    AiThinkingMode.OFF -> R.string.ai_thinking_off
    AiThinkingMode.LOW -> R.string.ai_thinking_low
    AiThinkingMode.MEDIUM -> R.string.ai_thinking_medium
    AiThinkingMode.HIGH -> R.string.ai_thinking_high
}

internal fun AiCapability.labelRes(): Int = when (this) {
    AiCapability.ROOT -> R.string.ai_capability_root
    AiCapability.SUPERUSER -> R.string.ai_capability_superuser
    AiCapability.SUPERUSER_ROOT -> R.string.ai_capability_superuser_root
    AiCapability.SUPERUSER_TEMP_ROOT -> R.string.ai_capability_superuser_temp_root
    AiCapability.SUPERUSER_SWITCH -> R.string.ai_capability_superuser_switch
    AiCapability.MODULE_DATA -> R.string.ai_capability_module_data
    AiCapability.EXTENSION_DATA -> R.string.ai_capability_extension_data
    AiCapability.WEB -> R.string.ai_capability_web
    AiCapability.THEME_READ -> R.string.ai_capability_theme_read
    AiCapability.THEME -> R.string.ai_capability_theme
    AiCapability.EXTENSIONS -> R.string.ai_capability_extensions
    AiCapability.MODULES -> R.string.ai_capability_modules
}

internal fun AiConfig.capabilityEnabled(capability: AiCapability): Boolean = when (capability) {
    AiCapability.ROOT -> allowRootAccess
    AiCapability.SUPERUSER -> allowSuperuserAccess
    AiCapability.SUPERUSER_ROOT -> allowSuperuserRootControl
    AiCapability.SUPERUSER_TEMP_ROOT -> allowSuperuserTemporaryRoot
    AiCapability.SUPERUSER_SWITCH -> allowSuperuserSwitch
    AiCapability.MODULE_DATA -> allowModuleAccess
    AiCapability.EXTENSION_DATA -> allowExtensionAccess
    AiCapability.WEB -> allowWebAccess
    AiCapability.THEME_READ -> allowThemeRead
    AiCapability.THEME -> allowThemeWrite
    AiCapability.EXTENSIONS -> allowExtensionWrite
    AiCapability.MODULES -> allowModuleInstall
}

internal fun AiProviderFormat.labelRes(): Int = when (this) {
    AiProviderFormat.AUTO -> R.string.ai_format_auto
    AiProviderFormat.OPENAI -> R.string.ai_format_openai
    AiProviderFormat.OLLAMA -> R.string.ai_format_ollama
    AiProviderFormat.ANTHROPIC -> R.string.ai_format_anthropic
}

/** Compose clipboard helper; avoids the ClipboardManager setter/property mismatch. */
@Composable
internal fun rememberAiCopyText(): (String) -> Unit {
    val clipboard = LocalClipboard.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val copied = stringResource(R.string.ai_copied)
    return remember(clipboard, context, copied) {
        { text ->
            if (text.isNotEmpty()) {
                scope.launch {
                    clipboard.setClipEntry(ClipEntry(ClipData.newPlainText("SukiSU AI", text)))
                    Toast.makeText(context, copied, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
}

/** One-line preview for the home card. */
internal fun compactSnippet(text: String, limit: Int = 160): String =
    text.lineSequence()
        .filterNot { it.trimStart().startsWith("```") }
        .joinToString(" ")
        .replace(Regex("\\s+"), " ")
        .trim()
        .take(limit)

private val AI_URL_REGEX = Regex("""https?://[^\s<>"']+""")
private val AI_URL_TRAILING = charArrayOf(
    '.', ',', ';', ':', ')', ']', '}', '。', '，', '、', '！', '？',
)

/** Make http(s) URLs tappable in assistant and tool text. */
internal fun linkifyAiText(text: String, linkColor: Color): AnnotatedString = buildAnnotatedString {
    val matches = AI_URL_REGEX.findAll(text).toList()
    if (matches.isEmpty()) {
        append(text)
        return@buildAnnotatedString
    }
    var index = 0
    for (match in matches) {
        if (match.range.first > index) append(text.substring(index, match.range.first))
        val raw = match.value
        val url = raw.trimEnd(*AI_URL_TRAILING)
        if (url.length <= "https://".length) {
            append(raw)
        } else {
            withStyle(SpanStyle(color = linkColor, textDecoration = TextDecoration.Underline)) {
                withLink(LinkAnnotation.Url(url)) { append(url) }
            }
            if (url.length < raw.length) append(raw.substring(url.length))
        }
        index = match.range.last + 1
    }
    if (index < text.length) append(text.substring(index))
}

private val aiAvatarBitmapCache = mutableMapOf<Int, ImageBitmap?>()

/**
 * The assistant avatar mirrors the selected built-in launcher icon. It renders
 * the complete adaptive icon (background and foreground) instead of tinting the
 * foreground: a color filter flattens multicolor artwork and the adaptive
 * foreground has a large safe-zone margin, which made the old avatar look
 * clipped or like a solid color blob.
 *
 * Dynamic launcher color is a system-level effect for the home-screen icon and
 * is intentionally not applied here, so the avatar always shows the real icon.
 */
@Composable
fun AiAvatarImage(
    modifier: Modifier = Modifier,
    size: Dp = 24.dp,
) {
    val context = LocalContext.current
    val icon = BuiltinAppIcons.find(SettingsRepositoryImpl().appIconId)
    val bitmap = remember(icon.id, context) {
        aiAvatarBitmapCache.getOrPut(icon.iconRes) {
            runCatching {
                ContextCompat.getDrawable(context, icon.iconRes)
                    ?.toBitmap(width = 256, height = 256)
                    ?.asImageBitmap()
            }.getOrNull()
        }
    }
    if (bitmap != null) {
        Image(
            bitmap = bitmap,
            contentDescription = null,
            modifier = modifier.size(size),
            contentScale = ContentScale.Crop,
        )
    } else {
        // Adaptive-icon XML may fail to load on unusual ROMs; a fitted foreground
        // is still better than an empty avatar, and it is never tinted.
        Image(
            painter = painterResource(icon.foregroundRes),
            contentDescription = null,
            modifier = modifier.size(size),
            contentScale = ContentScale.Fit,
        )
    }
}
