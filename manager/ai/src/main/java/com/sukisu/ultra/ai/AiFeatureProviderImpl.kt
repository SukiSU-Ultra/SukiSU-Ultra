package com.sukisu.ultra.ai

import androidx.compose.runtime.Composable
import com.sukisu.ultra.ai.api.AiFeatureProvider
import com.sukisu.ultra.ai.api.AiHost
import com.sukisu.ultra.ai.api.AiNavigationTarget
import com.sukisu.ultra.ai.api.AiUiMode

/**
 * Reflectively loaded by [com.sukisu.ultra.ai.api.AiFeatureBridge]. Keeping the
 * name and public no-argument constructor stable is part of the ABI.
 */
class AiFeatureProviderImpl : AiFeatureProvider {

    override fun install(host: AiHost) {
        AiAssistant.install(host)
    }

    override fun chatScreen(
        uiMode: AiUiMode,
        onClose: () -> Unit,
        onOpenSettings: () -> Unit,
        onNavigate: (AiNavigationTarget) -> Unit,
    ): @Composable () -> Unit = {
        AiChatScreen(
            uiMode = uiMode,
            onClose = onClose,
            onOpenSettings = onOpenSettings,
            onNavigate = onNavigate,
        )
    }

    override fun settingsScreen(
        uiMode: AiUiMode,
        onBack: () -> Unit,
    ): @Composable () -> Unit = {
        AiSettingsScreen(uiMode = uiMode, onBack = onBack)
    }

    override fun homeCardMaterial(onOpenChat: () -> Unit): @Composable () -> Unit = {
        AiHomeCardMaterial(onOpenChat = onOpenChat)
    }

    override fun homeCardMiuix(onOpenChat: () -> Unit): @Composable () -> Unit = {
        AiHomeCardMiuix(onOpenChat = onOpenChat)
    }
}
