package com.sukisu.ultra.ai.api

import androidx.compose.runtime.Composable

/**
 * Entry points implemented by the optional AI library.
 *
 * Methods return composable lambdas instead of declaring abstract composable
 * functions so this module stays a plain, stable API surface.
 */
interface AiFeatureProvider {
    fun install(host: AiHost)

    fun chatScreen(
        uiMode: AiUiMode,
        onClose: () -> Unit,
        onOpenSettings: () -> Unit,
        onNavigate: (AiNavigationTarget) -> Unit,
    ): @Composable () -> Unit

    fun settingsScreen(
        uiMode: AiUiMode,
        onBack: () -> Unit,
    ): @Composable () -> Unit

    fun homeCardMaterial(onOpenChat: () -> Unit): @Composable () -> Unit

    fun homeCardMiuix(onOpenChat: () -> Unit): @Composable () -> Unit
}

/**
 * Runtime lookup for the optional AI library.
 *
 * The implementation class is loaded by name, so the host never has a compile
 * dependency on the AAR. When the AAR is not bundled, [isAvailable] is false and
 * every entry point is a no-op.
 */
object AiFeatureBridge {

    private const val PROVIDER_CLASS = "com.sukisu.ultra.ai.AiFeatureProviderImpl"

    private val provider: AiFeatureProvider? by lazy(LazyThreadSafetyMode.PUBLICATION) {
        runCatching {
            val type = Class.forName(PROVIDER_CLASS)
            type.getDeclaredConstructor().newInstance() as AiFeatureProvider
        }.getOrNull()
    }

    val isAvailable: Boolean get() = provider != null

    fun install(host: AiHost) {
        provider?.install(host)
    }

    @Composable
    fun ChatScreen(
        uiMode: AiUiMode,
        onClose: () -> Unit,
        onOpenSettings: () -> Unit,
        onNavigate: (AiNavigationTarget) -> Unit,
    ) {
        provider?.chatScreen(uiMode, onClose, onOpenSettings, onNavigate)?.invoke()
    }

    @Composable
    fun SettingsScreen(
        uiMode: AiUiMode,
        onBack: () -> Unit,
    ) {
        provider?.settingsScreen(uiMode, onBack)?.invoke()
    }

    @Composable
    fun HomeCardMaterial(onOpenChat: () -> Unit) {
        provider?.homeCardMaterial(onOpenChat)?.invoke()
    }

    @Composable
    fun HomeCardMiuix(onOpenChat: () -> Unit) {
        provider?.homeCardMiuix(onOpenChat)?.invoke()
    }
}
