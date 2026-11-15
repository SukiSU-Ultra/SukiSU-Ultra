package com.sukisu.nova.ui.screen.susfs.content

import androidx.compose.runtime.Composable
import com.sukisu.nova.ui.LocalUiMode
import com.sukisu.nova.ui.UiMode
import com.sukisu.nova.ui.screen.susfs.content.miuix.KstatConfigContentMiuix
import com.sukisu.nova.ui.screen.susfs.content.material.KstatConfigContentMaterial

@Composable
fun KstatConfigContent(
    kstatConfigs: Set<String>,
    addKstatPaths: Set<String>,
    isLoading: Boolean,
    onAddKstatStatically: () -> Unit,
    onAddKstat: () -> Unit,
    onRemoveKstatConfig: (String) -> Unit,
    onEditKstatConfig: ((String) -> Unit)? = null,
    onRemoveAddKstat: (String) -> Unit,
    onEditAddKstat: ((String) -> Unit)? = null,
    onUpdateKstat: (String) -> Unit,
    onUpdateKstatFullClone: (String) -> Unit
) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> KstatConfigContentMiuix(
            kstatConfigs = kstatConfigs,
            addKstatPaths = addKstatPaths,
            isLoading = isLoading,
            onAddKstatStatically = onAddKstatStatically,
            onAddKstat = onAddKstat,
            onRemoveKstatConfig = onRemoveKstatConfig,
            onEditKstatConfig = onEditKstatConfig,
            onRemoveAddKstat = onRemoveAddKstat,
            onEditAddKstat = onEditAddKstat,
            onUpdateKstat = onUpdateKstat,
            onUpdateKstatFullClone = onUpdateKstatFullClone
        )
        UiMode.Material -> KstatConfigContentMaterial(
            kstatConfigs = kstatConfigs,
            addKstatPaths = addKstatPaths,
            isLoading = isLoading,
            onAddKstatStatically = onAddKstatStatically,
            onAddKstat = onAddKstat,
            onRemoveKstatConfig = onRemoveKstatConfig,
            onEditKstatConfig = { onEditKstatConfig?.invoke(it) },
            onRemoveAddKstat = onRemoveAddKstat,
            onEditAddKstat = { onEditAddKstat?.invoke(it) },
            onUpdateKstat = onUpdateKstat,
            onUpdateKstatFullClone = onUpdateKstatFullClone
        )
    }
}
