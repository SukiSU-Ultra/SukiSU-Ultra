package com.sukisu.ultra.ui.screen.customtext

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.DeleteOutline
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.RestartAlt
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text as MaterialText
import androidx.compose.material3.TextButton as MaterialTextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.ui.component.dialog.rememberConfirmDialog
import com.sukisu.ultra.ui.component.material.ExpressiveScaffold
import com.sukisu.ultra.ui.component.material.IconTile
import com.sukisu.ultra.ui.component.material.SegmentedColumn
import com.sukisu.ultra.ui.component.material.SegmentedListItem
import com.sukisu.ultra.ui.component.material.expressiveTopAppBarColors
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.util.CustomTextGroup
import com.sukisu.ultra.ui.util.CustomTextKey
import com.sukisu.ultra.ui.viewmodel.SettingsViewModel
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon as MiuixIcon
import top.yukonga.miuix.kmp.basic.IconButton as MiuixIconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTitle
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.window.WindowDialog

@Composable
fun CustomTextScreen(
    viewModel: SettingsViewModel = viewModel(),
) {
    val navigator = LocalNavigator.current
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    var editingKey by remember { mutableStateOf<CustomTextKey?>(null) }
    var editTextValue by remember { mutableStateOf("") }
    var showResetAllConfirm by remember { mutableStateOf(false) }

    val onStartEdit = { key: CustomTextKey ->
        editingKey = key
        editTextValue = uiState.customTexts[key.key].orEmpty()
    }

    when (LocalUiMode.current) {
        UiMode.Miuix -> {
            CustomTextScreenMiuix(
                customTexts = uiState.customTexts,
                onBack = { navigator.pop() },
                onItemClick = onStartEdit,
                onResetAll = { showResetAllConfirm = true },
            )
        }
        UiMode.Material -> {
            CustomTextScreenMaterial(
                customTexts = uiState.customTexts,
                onBack = { navigator.pop() },
                onItemClick = onStartEdit,
                onResetAll = { showResetAllConfirm = true },
            )
        }
    }

    editingKey?.let { key ->
        CustomTextEditDialog(
            key = key,
            initialValue = editTextValue,
            onDismiss = { editingKey = null },
            onConfirm = { newVal ->
                viewModel.setCustomText(key.key, newVal)
                editingKey = null
            },
            onRestoreDefault = {
                viewModel.setCustomText(key.key, "")
                editingKey = null
            }
        )
    }

    if (showResetAllConfirm) {
        ResetAllConfirmDialog(
            onDismiss = { showResetAllConfirm = false },
            onConfirm = {
                viewModel.resetAllCustomTexts()
                showResetAllConfirm = false
            }
        )
    }
}

@Composable
private fun CustomTextScreenMiuix(
    customTexts: Map<String, String>,
    onBack: () -> Unit,
    onItemClick: (CustomTextKey) -> Unit,
    onResetAll: () -> Unit,
) {
    val scrollBehavior = MiuixScrollBehavior()
    val groups = remember { CustomTextGroup.entries }

    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.settings_custom_texts),
                navigationIcon = {
                    MiuixIconButton(onClick = onBack) {
                        MiuixIcon(
                            imageVector = Icons.AutoMirrored.Rounded.ArrowBack,
                            contentDescription = null,
                        )
                    }
                },
                actions = {
                    MiuixIconButton(onClick = onResetAll) {
                        MiuixIcon(
                            imageVector = Icons.Rounded.RestartAlt,
                            contentDescription = stringResource(R.string.custom_text_restore_all),
                        )
                    }
                },
                scrollBehavior = scrollBehavior,
            )
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 12.dp),
            contentPadding = innerPadding,
            overscrollEffect = null,
        ) {
            groups.forEach { group ->
                val itemsInGroup = CustomTextKey.entries.filter { it.group == group }
                if (itemsInGroup.isNotEmpty()) {
                    item {
                        SmallTitle(text = stringResource(group.titleRes))
                    }
                    item {
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column {
                                itemsInGroup.forEach { key ->
                                    val customVal = customTexts[key.key]
                                    val defaultVal = stringResource(key.defaultRes)
                                    val summary = customVal?.takeIf { it.isNotBlank() }
                                        ?: stringResource(R.string.custom_text_default_value, defaultVal)

                                    ArrowPreference(
                                        title = stringResource(key.nameRes),
                                        summary = summary,
                                        onClick = { onItemClick(key) }
                                    )
                                }
                            }
                        }
                    }
                }
            }
            item {
                Spacer(Modifier.height(WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() + 16.dp))
            }
        }
    }
}

@Composable
private fun CustomTextScreenMaterial(
    customTexts: Map<String, String>,
    onBack: () -> Unit,
    onItemClick: (CustomTextKey) -> Unit,
    onResetAll: () -> Unit,
) {
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val groups = remember { CustomTextGroup.entries }

    ExpressiveScaffold(
        containerColor = if (hasCustomBackground) Color.Transparent else MaterialTheme.colorScheme.surfaceContainer,
        topBar = {
            TopAppBar(
                title = { MaterialText(stringResource(R.string.settings_custom_texts)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Rounded.ArrowBack,
                            contentDescription = null,
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onResetAll) {
                        Icon(
                            imageVector = Icons.Rounded.RestartAlt,
                            contentDescription = stringResource(R.string.custom_text_restore_all),
                        )
                    }
                },
                colors = expressiveTopAppBarColors(
                    containerColor = if (hasCustomBackground) Color.Transparent else MaterialTheme.colorScheme.surfaceContainer,
                    scrolledContainerColor = if (hasCustomBackground) Color.Transparent else MaterialTheme.colorScheme.surfaceContainer,
                ),
                windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
            )
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            groups.forEach { group ->
                val itemsInGroup = CustomTextKey.entries.filter { it.group == group }
                if (itemsInGroup.isNotEmpty()) {
                    item {
                        MaterialText(
                            text = stringResource(group.titleRes),
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(start = 8.dp, bottom = 4.dp),
                        )
                        SegmentedColumn {
                            itemsInGroup.forEach { key ->
                                item(key = key.key) {
                                    val customVal = customTexts[key.key]
                                    val defaultVal = stringResource(key.defaultRes)
                                    val summary = customVal?.takeIf { it.isNotBlank() }
                                        ?: stringResource(R.string.custom_text_default_value, defaultVal)

                                    SegmentedListItem(
                                        onClick = { onItemClick(key) },
                                        headlineContent = { MaterialText(stringResource(key.nameRes)) },
                                        supportingContent = { MaterialText(summary) },
                                        leadingContent = {
                                            IconTile(
                                                icon = Icons.Rounded.Edit,
                                                contentDescription = null,
                                            )
                                        }
                                    )
                                }
                            }
                        }
                    }
                }
            }
            item {
                Spacer(Modifier.height(WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() + 16.dp))
            }
        }
    }
}

@Composable
private fun CustomTextEditDialog(
    key: CustomTextKey,
    initialValue: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
    onRestoreDefault: () -> Unit,
) {
    var text by remember(key) { mutableStateOf(initialValue) }
    val defaultVal = stringResource(key.defaultRes)

    when (LocalUiMode.current) {
        UiMode.Miuix -> {
            WindowDialog(
                show = true,
                title = stringResource(R.string.custom_text_edit_title) + " - " + stringResource(key.nameRes),
                onDismissRequest = onDismiss,
                content = {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 24.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        TextField(
                            value = text,
                            onValueChange = { text = it },
                            label = defaultVal,
                            useLabelAsPlaceholder = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Text(
                            text = stringResource(R.string.custom_text_edit_hint),
                            style = MiuixTheme.textStyles.body2,
                            color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                        )
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            TextButton(
                                text = stringResource(R.string.custom_text_restore_default),
                                onClick = onRestoreDefault,
                                modifier = Modifier.weight(1f),
                            )
                            TextButton(
                                text = stringResource(R.string.confirm),
                                colors = ButtonDefaults.textButtonColorsPrimary(),
                                onClick = { onConfirm(text) },
                                modifier = Modifier.weight(1f),
                            )
                        }
                    }
                }
            )
        }
        UiMode.Material -> {
            AlertDialog(
                onDismissRequest = onDismiss,
                title = { MaterialText(stringResource(key.nameRes)) },
                text = {
                    Column(modifier = Modifier.fillMaxWidth()) {
                        OutlinedTextField(
                            value = text,
                            onValueChange = { text = it },
                            placeholder = { MaterialText(defaultVal) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Spacer(Modifier.height(8.dp))
                        MaterialText(
                            text = stringResource(R.string.custom_text_edit_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                confirmButton = {
                    MaterialTextButton(onClick = { onConfirm(text) }) {
                        MaterialText(stringResource(R.string.confirm))
                    }
                },
                dismissButton = {
                    Row {
                        MaterialTextButton(onClick = onRestoreDefault) {
                            MaterialText(stringResource(R.string.custom_text_restore_default))
                        }
                        MaterialTextButton(onClick = onDismiss) {
                            MaterialText(stringResource(R.string.cancel))
                        }
                    }
                }
            )
        }
    }
}

@Composable
private fun ResetAllConfirmDialog(
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    val confirmDialog = rememberConfirmDialog(onConfirm = onConfirm)
    confirmDialog.showConfirm(
        title = stringResource(R.string.custom_text_restore_all),
        content = stringResource(R.string.custom_text_restore_all_confirm),
    )
}
