package com.sukisu.ultra.ui.navigation3

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.ReceiveChannel
import kotlinx.coroutines.withContext
import com.sukisu.ultra.Natives
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.ui.util.ThemePackageCrypto
import com.sukisu.ultra.ui.util.ThemePackageStorage
import com.sukisu.ultra.ui.util.getFileName
import com.sukisu.ultra.ui.webui.WebUIActivity

private const val SCHEME_KSU = "ksu"
private const val HOST_ACTION = "action"
private const val HOST_WEBUI = "webui"
private const val PARAM_ID = "id"
private const val PARAM_TOKEN = "token"

/**
 * Resolved intent action to execute after validation.
 */
private sealed interface PendingAction {
    /** Execute a module's action script — triggered by shortcut or deep link. */
    data class ExecuteAction(val moduleId: String) : PendingAction

    /** Open a module's WebUI — triggered by shortcut. */
    data class OpenWebUI(val moduleId: String) : PendingAction
}

private sealed interface KsuDeepLink {
    data class Action(val moduleId: String) : KsuDeepLink
    data class WebUi(val moduleId: String) : KsuDeepLink
}

private fun buildInternalWebUiUri(moduleId: String): Uri {
    return Uri.Builder()
        .scheme(SCHEME_KSU)
        .authority(HOST_WEBUI)
        .appendQueryParameter(PARAM_ID, moduleId)
        .build()
}

/**
 * Resolve an intent snapshot into a [PendingAction].
 * Returns null if the intent carries no recognized action.
 */
private fun resolveIntent(intent: Intent): PendingAction? {
    // Check deep links
    return when (val deepLink = parseValidatedDeepLink(intent.data)) {
        is KsuDeepLink.Action -> PendingAction.ExecuteAction(deepLink.moduleId)
        is KsuDeepLink.WebUi -> PendingAction.OpenWebUI(deepLink.moduleId)
        null -> null
    }
}

private fun parseValidatedDeepLink(uri: Uri?): KsuDeepLink? {
    if (uri?.scheme != SCHEME_KSU) return null

    val moduleId = uri.getQueryParameter(PARAM_ID)?.takeIf { it.isNotBlank() } ?: return null
    val token = uri.getQueryParameter(PARAM_TOKEN)?.takeIf { it.isNotBlank() } ?: return null
    if (token != SettingsRepositoryImpl().intentToken) return null

    return when (uri.host) {
        HOST_ACTION -> KsuDeepLink.Action(moduleId)
        HOST_WEBUI -> KsuDeepLink.WebUi(moduleId)
        else -> null
    }
}

private suspend fun extractThemePackageUri(context: Context, intent: Intent): Uri? =
    withContext(Dispatchers.IO) {
        val uris = linkedSetOf<Uri>()

        fun add(uri: Uri?) {
            if (uri != null) uris.add(uri)
        }

        add(intent.data)
        when (intent.action) {
            Intent.ACTION_VIEW, Intent.ACTION_SEND -> add(intent.getThemeStreamUri())
            Intent.ACTION_SEND_MULTIPLE -> intent.getThemeStreamUris()?.forEach(::add)
        }

        val clipData = intent.clipData
        if (clipData != null) {
            for (i in 0 until clipData.itemCount) {
                add(clipData.getItemAt(i)?.uri)
            }
        }

        if (uris.isEmpty()) return@withContext null

        uris.firstOrNull { isThemePackageUri(context, intent, it) }
            ?: uris.firstOrNull { hasThemeHeader(context, it) }
    }

private fun Intent.getThemeStreamUri(): Uri? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
    getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
} else {
    @Suppress("DEPRECATION")
    getParcelableExtra(Intent.EXTRA_STREAM)
}

private fun Intent.getThemeStreamUris(): List<Uri>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
    getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
} else {
    @Suppress("DEPRECATION")
    getParcelableArrayListExtra(Intent.EXTRA_STREAM)
}

private fun isThemePackageUri(context: Context, intent: Intent, uri: Uri): Boolean {
    val fileName = uri.getFileName(context) ?: uri.lastPathSegment.orEmpty()
    val cleanName = fileName.substringBefore('?')
    if (cleanName.endsWith(".sukisu", ignoreCase = true)) return true

    val declaredType = intent.type
        ?.substringBefore(';')
        ?.trim()
        ?.lowercase()
    if (declaredType == ThemePackageStorage.THEME_MIME_TYPE) return true

    val resolvedType = runCatching { context.contentResolver.getType(uri) }
        .getOrNull()
        ?.substringBefore(';')
        ?.trim()
        ?.lowercase()
    return resolvedType == ThemePackageStorage.THEME_MIME_TYPE
}

/**
 * Shared files often arrive as octet-stream with a content URI that has no usable display
 * name, so filename and MIME checks are not enough. The encrypted package header is stable
 * and cheap to read, which lets us tell themes apart from module ZIPs before routing.
 */
private fun hasThemeHeader(context: Context, uri: Uri): Boolean = runCatching {
    context.contentResolver.openInputStream(uri)?.use { input ->
        val header = ByteArray(ThemePackageCrypto.HEADER_SIZE)
        var read = 0
        while (read < header.size) {
            val count = input.read(header, read, header.size - read)
            if (count < 0) break
            read += count
        }
        ThemePackageCrypto.hasValidHeader(header.copyOf(read))
    } ?: false
}.getOrDefault(false)

@Composable
fun IntentDispatcher(intentChannel: ReceiveChannel<Intent>) {
    val context = LocalContext.current
    val navigator = LocalNavigator.current
    val isManager = Natives.isManager
    val handleZipIntent = rememberZipFileIntentHandler()

    CollectIntentChannel(intentChannel) { intent ->
        if (!isManager) return@CollectIntentChannel

        val themeUri = extractThemePackageUri(context, intent)
        if (themeUri != null) {
            // Forward the URI through the route. The appearance destination owns a per-entry
            // SettingsViewModel, so setting dialog state on the activity-scoped dispatcher
            // view model would never be observed by the screen that renders the dialog.
            navigator.push(Route.ColorPalette(importUri = themeUri.toString()))
            return@CollectIntentChannel
        }

        if (hasZipFileIntent(context, intent)) {
            handleZipIntent(intent)
            return@CollectIntentChannel
        }

        val action = resolveIntent(intent) ?: return@CollectIntentChannel

        when (action) {
            is PendingAction.ExecuteAction -> {
                navigator.push(Route.ExecuteModuleAction(action.moduleId, fromShortcut = true))
            }

            is PendingAction.OpenWebUI -> {
                val webIntent = Intent(context, WebUIActivity::class.java)
                    .setData(buildInternalWebUiUri(action.moduleId))
                context.startActivity(webIntent)
            }
        }
    }
}

/**
 * Receive intents inside a [LaunchedEffect] tied to the channel identity.
 * Each emitted intent is processed exactly once; no activity.intent mutation needed.
 */
@Composable
private fun CollectIntentChannel(intentChannel: ReceiveChannel<Intent>, onIntent: suspend (Intent) -> Unit) {
    LaunchedEffect(intentChannel) {
        for (intent in intentChannel) {
            onIntent(intent)
        }
    }
}
