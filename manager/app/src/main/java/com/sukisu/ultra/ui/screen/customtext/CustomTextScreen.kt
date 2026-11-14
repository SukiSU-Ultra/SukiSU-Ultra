package com.sukisu.ultra.ui.screen.customtext

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.LayoutDirection
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
import com.sukisu.ultra.ui.component.miuix.AppCard
import com.sukisu.ultra.ui.component.miuix.AppScaffold
import com.sukisu.ultra.ui.navigation3.LocalNavigator
import com.sukisu.ultra.ui.theme.LocalBackgroundImagePath
import com.sukisu.ultra.ui.theme.LocalEnableBlur
import com.sukisu.ultra.ui.util.BlurredBar
import com.sukisu.ultra.ui.util.CustomTextArg
import com.sukisu.ultra.ui.util.CustomTextGroup
import com.sukisu.ultra.ui.util.CustomTextKey
import com.sukisu.ultra.ui.util.customText
import com.sukisu.ultra.ui.util.customTextSummary
import com.sukisu.ultra.ui.util.joinTemplate
import com.sukisu.ultra.ui.util.rememberBlurBackdrop
import com.sukisu.ultra.ui.util.splitTemplate
import com.sukisu.ultra.ui.viewmodel.SettingsViewModel
import top.yukonga.miuix.kmp.basic.ButtonDefaults
import top.yukonga.miuix.kmp.basic.Icon as MiuixIcon
import top.yukonga.miuix.kmp.basic.IconButton as MiuixIconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.SmallTitle
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TextButton
import top.yukonga.miuix.kmp.basic.TextField
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.icon.extended.Undo
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic
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
    val enableBlur = LocalEnableBlur.current
    val backdrop = rememberBlurBackdrop(enableBlur)
    val blurActive = backdrop != null
    val hasCustomBackground = LocalBackgroundImagePath.current.isNotEmpty()
    val barColor = if (blurActive || hasCustomBackground) Color.Transparent else colorScheme.surface

    AppScaffold(
        topBar = {
            BlurredBar(backdrop = backdrop, scrollBehavior = scrollBehavior) {
                TopAppBar(
                    title = customText(CustomTextKey.PAGE_CUSTOM_TEXTS),
                    color = barColor,
                    navigationIcon = {
                        MiuixIconButton(onClick = onBack) {
                            val layoutDirection = LocalLayoutDirection.current
                            MiuixIcon(
                                modifier = Modifier.graphicsLayer {
                                    if (layoutDirection == LayoutDirection.Rtl) scaleX = -1f
                                },
                                imageVector = MiuixIcons.Back,
                                contentDescription = null,
                                tint = colorScheme.onBackground,
                            )
                        }
                    },
                    actions = {
                        MiuixIconButton(onClick = onResetAll) {
                            MiuixIcon(
                                imageVector = MiuixIcons.Undo,
                                contentDescription = stringResource(R.string.custom_text_restore_all),
                                tint = colorScheme.onBackground,
                            )
                        }
                    },
                    scrollBehavior = scrollBehavior,
                )
            }
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout)
            .only(WindowInsetsSides.Horizontal),
    ) { innerPadding ->
        Box(modifier = if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxHeight()
                    .scrollEndHaptic()
                    .overScrollVertical()
                    .nestedScroll(scrollBehavior.nestedScrollConnection)
                    .padding(horizontal = 12.dp),
                contentPadding = innerPadding,
                overscrollEffect = null,
            ) {
                var isFirstGroup = true
                groups.forEach { group ->
                    val itemsInGroup = CustomTextKey.entries.filter { it.group == group }
                    if (itemsInGroup.isNotEmpty()) {
                        val isFirst = isFirstGroup
                        isFirstGroup = false
                        item(key = "title-${group.name}") {
                            SmallTitle(
                                text = stringResource(group.titleRes),
                                modifier = Modifier.padding(top = if (isFirst) 12.dp else 16.dp),
                                insideMargin = PaddingValues(start = 16.dp, end = 16.dp, bottom = 8.dp),
                            )
                        }
                        item(key = "card-${group.name}") {
                            AppCard(modifier = Modifier.fillMaxWidth()) {
                                Column {
                                    itemsInGroup.forEach { key ->
                                        ArrowPreference(
                                            title = stringResource(key.nameRes),
                                            summary = customTextSummary(key, customTexts[key.key]),
                                            onClick = { onItemClick(key) }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
                item(key = "bottom-inset") {
                    Spacer(Modifier.height(WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() + 16.dp))
                }
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
                title = { MaterialText(customText(CustomTextKey.PAGE_CUSTOM_TEXTS)) },
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
                                    SegmentedListItem(
                                        onClick = { onItemClick(key) },
                                        headlineContent = { MaterialText(stringResource(key.nameRes)) },
                                        supportingContent = {
                                            MaterialText(customTextSummary(key, customTexts[key.key]))
                                        },
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
    val defaultText = stringResource(key.defaultRes)
    val hasVariables = key.formatArgs.isNotEmpty()
    val defaultParts = remember(key, defaultText) { key.splitTemplate(defaultText) }
    var text by remember(key, initialValue) { mutableStateOf(initialValue) }
    var parts by remember(key, initialValue) {
        mutableStateOf(key.splitTemplate(initialValue.ifBlank { defaultText }))
    }

    // The variable itself is never edited: the app inserts it between the two text pieces.
    val assembled = when {
        !hasVariables -> text
        parts.all { it.isBlank() } || parts == defaultParts -> ""
        else -> key.joinTemplate(parts)
    }

    fun updatePart(index: Int, value: String) {
        parts = parts.toMutableList().also { it[index] = value }
    }

    val hintRes = if (hasVariables) R.string.custom_text_variable_hint else R.string.custom_text_edit_hint

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
                        if (hasVariables) {
                            key.formatArgs.forEachIndexed { index, arg ->
                                TextField(
                                    value = parts[index],
                                    onValueChange = { updatePart(index, it) },
                                    label = defaultParts[index],
                                    useLabelAsPlaceholder = true,
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                MiuixVariableRow(arg = arg)
                            }
                            TextField(
                                value = parts.last(),
                                onValueChange = { updatePart(parts.lastIndex, it) },
                                label = defaultParts.last(),
                                useLabelAsPlaceholder = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        } else {
                            TextField(
                                value = text,
                                onValueChange = { text = it },
                                label = defaultText,
                                useLabelAsPlaceholder = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                        Text(
                            text = stringResource(hintRes),
                            style = MiuixTheme.textStyles.body2,
                            color = colorScheme.onSurfaceVariantSummary,
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
                                onClick = { onConfirm(assembled) },
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
                        if (hasVariables) {
                            key.formatArgs.forEachIndexed { index, arg ->
                                OutlinedTextField(
                                    value = parts[index],
                                    onValueChange = { updatePart(index, it) },
                                    label = {
                                        MaterialText(stringResource(R.string.custom_text_part_before))
                                    },
                                    placeholder = { MaterialText(defaultParts[index]) },
                                    singleLine = true,
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                MaterialVariableRow(
                                    arg = arg,
                                    modifier = Modifier.padding(vertical = 4.dp),
                                )
                            }
                            OutlinedTextField(
                                value = parts.last(),
                                onValueChange = { updatePart(parts.lastIndex, it) },
                                label = {
                                    MaterialText(stringResource(R.string.custom_text_part_after))
                                },
                                placeholder = { MaterialText(defaultParts.last()) },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        } else {
                            OutlinedTextField(
                                value = text,
                                onValueChange = { text = it },
                                placeholder = { MaterialText(defaultText) },
                                singleLine = true,
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        MaterialText(
                            text = stringResource(hintRes),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                confirmButton = {
                    MaterialTextButton(onClick = { onConfirm(assembled) }) {
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
private fun MiuixVariableRow(arg: CustomTextArg) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = stringResource(R.string.custom_text_variable),
            style = MiuixTheme.textStyles.body2,
            color = colorScheme.onSurfaceVariantSummary,
        )
        Text(
            text = stringResource(arg.labelRes),
            style = MiuixTheme.textStyles.body2,
            color = colorScheme.onPrimaryContainer,
            modifier = Modifier
                .clip(RoundedCornerShape(8.dp))
                .background(colorScheme.primaryContainer)
                .padding(horizontal = 8.dp, vertical = 2.dp),
        )
    }
}

@Composable
private fun MaterialVariableRow(arg: CustomTextArg, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        MaterialText(
            text = stringResource(R.string.custom_text_variable),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.primaryContainer)
                .padding(horizontal = 8.dp, vertical = 2.dp),
        ) {
            MaterialText(
                text = stringResource(arg.labelRes),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
            )
        }
    }
}

@Composable
private fun ResetAllConfirmDialog(
    onConfirm: () -> Unit,
) {
    val confirmDialog = rememberConfirmDialog(onConfirm = onConfirm)
    confirmDialog.showConfirm(
        title = stringResource(R.string.custom_text_restore_all),
        content = stringResource(R.string.custom_text_restore_all_confirm),
    )
}
