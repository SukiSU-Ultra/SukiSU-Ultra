package com.sukisu.ultra.ui.screen.appearanceoverlay

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TextButton as MaterialTextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.appearance.AppearanceColorPickerDialog
import com.sukisu.ultra.ui.component.appearance.AppearanceOverlayDialog
import com.sukisu.ultra.ui.component.appearance.titleRes
import com.sukisu.ultra.ui.component.material.ExpressiveDialog
import com.sukisu.ultra.ui.theme.isInDarkTheme
import com.sukisu.ultra.ui.util.AppearanceColorMode
import com.sukisu.ultra.ui.util.AppearanceColorToken
import com.sukisu.ultra.ui.util.AppearanceOverlayData
import com.sukisu.ultra.ui.util.AppearanceOverlayStore
import com.sukisu.ultra.ui.util.colorTokenValue
import com.sukisu.ultra.ui.util.effectiveColorToken
import com.sukisu.ultra.ui.util.toOverlayColorString
import com.sukisu.ultra.ui.util.withColorToken
import com.sukisu.ultra.ui.viewmodel.SettingsViewModel
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.TextButton as MiuixTextButton
import top.yukonga.miuix.kmp.overlay.OverlayDialog

@Immutable
data class OverlayColorTarget(
    val mode: AppearanceColorMode,
    val token: AppearanceColorToken,
)

data class AppearanceOverlayActions(
    val onBack: () -> Unit,
    val onUpdate: (AppearanceOverlayData) -> Unit,
    val onPickColor: (OverlayColorTarget) -> Unit,
    val onOpenJson: () -> Unit,
    /** Immediate reset used by the top-bar rescue action. */
    val onResetAll: () -> Unit,
    /** Asks for confirmation before clearing from the advanced section. */
    val onRequestClear: () -> Unit,
)

@Composable
fun AppearanceOverlayScreen(onBack: () -> Unit) {
    val viewModel = viewModel<SettingsViewModel>()
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val data = uiState.appearanceData ?: AppearanceOverlayData()
    val isDark = isInDarkTheme()

    var pickerTarget by remember { mutableStateOf<OverlayColorTarget?>(null) }
    var showJsonEditor by rememberSaveable { mutableStateOf(false) }
    var showClearConfirm by rememberSaveable { mutableStateOf(false) }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        viewModel.refreshCustomAppearance()
    }

    val actions = AppearanceOverlayActions(
        onBack = onBack,
        onUpdate = viewModel::applyCustomAppearance,
        onPickColor = { pickerTarget = it },
        onOpenJson = { showJsonEditor = true },
        onResetAll = viewModel::resetCustomAppearance,
        onRequestClear = { showClearConfirm = true },
    )

    val target = pickerTarget
    if (target != null) {
        val effective = data.effectiveColorToken(target.mode, target.token)
        val defaultArgb = when (target.mode) {
            AppearanceColorMode.LIGHT -> 0xFF000000.toInt()
            AppearanceColorMode.DARK -> 0xFFFFFFFF.toInt()
            AppearanceColorMode.SHARED -> if (isDark) 0xFFFFFFFF.toInt() else 0xFF000000.toInt()
        }
        val initialArgb = effective?.second
            ?.let(AppearanceOverlayStore::parseColorValue)
            ?: defaultArgb
        AppearanceColorPickerDialog(
            show = true,
            title = "${stringResource(target.token.titleRes())} · ${
                stringResource(target.mode.titleRes())
            }",
            initialColor = Color(initialArgb),
            clearable = data.colorTokenValue(target.mode, target.token) != null,
            onDismissRequest = { pickerTarget = null },
            onConfirm = { color ->
                actions.onUpdate(
                    data.withColorToken(
                        target.mode,
                        target.token,
                        color.toArgb().toOverlayColorString(),
                    )
                )
                pickerTarget = null
            },
            onClear = {
                actions.onUpdate(data.withColorToken(target.mode, target.token, null))
                pickerTarget = null
            },
        )
    }

    AppearanceOverlayDialog(
        show = showJsonEditor,
        initialJson = uiState.customAppearanceJson,
        onDismissRequest = { showJsonEditor = false },
        onApply = viewModel::applyCustomAppearance,
        onReset = viewModel::resetCustomAppearance,
    )

    if (showClearConfirm) {
        when (LocalUiMode.current) {
            UiMode.Miuix -> OverlayDialog(
                show = true,
                title = stringResource(R.string.appearance_clear_all_confirm_title),
                summary = stringResource(R.string.appearance_clear_all_confirm_message),
                onDismissRequest = { showClearConfirm = false },
                insideMargin = DpSize(0.dp, 24.dp),
                content = {
                    Row(
                        modifier = Modifier.padding(horizontal = 24.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        MiuixTextButton(
                            text = stringResource(R.string.cancel),
                            onClick = { showClearConfirm = false },
                            modifier = Modifier.weight(1f),
                        )
                        Spacer(Modifier.width(20.dp))
                        MiuixTextButton(
                            text = stringResource(R.string.appearance_clear),
                            onClick = {
                                viewModel.resetCustomAppearance()
                                showClearConfirm = false
                            },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.textButtonColorsPrimary(),
                        )
                    }
                },
            )

            UiMode.Material -> ExpressiveDialog(
                onDismissRequest = { showClearConfirm = false },
                title = { MaterialText(stringResource(R.string.appearance_clear_all_confirm_title)) },
                text = { MaterialText(stringResource(R.string.appearance_clear_all_confirm_message)) },
                confirmButton = {
                    MaterialTextButton(
                        onClick = {
                            viewModel.resetCustomAppearance()
                            showClearConfirm = false
                        },
                    ) {
                        MaterialText(stringResource(R.string.appearance_clear))
                    }
                },
                dismissButton = {
                    MaterialTextButton(onClick = { showClearConfirm = false }) {
                        MaterialText(stringResource(R.string.cancel))
                    }
                },
            )
        }
    }

    when (LocalUiMode.current) {
        UiMode.Miuix -> AppearanceOverlayScreenMiuix(
            state = uiState,
            data = data,
            actions = actions,
        )

        UiMode.Material -> AppearanceOverlayScreenMaterial(
            state = uiState,
            data = data,
            actions = actions,
        )
    }
}
