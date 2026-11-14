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
        onClose: () -> Unit,
        onOpenSettings: () -> Unit,
        onNavigate: (AiNavigationTarget) -> Unit,
    ): @Composable () -> Unit

    fun settingsScreen(
        onBack: () -> Unit,
    ): @Composable () -> Unit

    fun homeCard(onOpenChat: () -> Unit): @Composable () -> Unit
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
        onClose: () -> Unit,
        onOpenSettings: () -> Unit,
        onNavigate: (AiNavigationTarget) -> Unit,
    ) {
        provider?.chatScreen(onClose, onOpenSettings, onNavigate)?.invoke()
    }

    @Composable
    fun SettingsScreen(
        onBack: () -> Unit,
    ) {
        provider?.settingsScreen(onBack)?.invoke()
    }

    @Composable
    fun HomeCard(onOpenChat: () -> Unit) {
        provider?.homeCard(onOpenChat)?.invoke()
    }
}
