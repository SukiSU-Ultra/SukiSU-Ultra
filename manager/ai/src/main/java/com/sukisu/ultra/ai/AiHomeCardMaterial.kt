package com.sukisu.ultra.ai

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Chat
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.sukisu.ultra.ai.R

/**
 * Compact home entry point. The card only shows live status and a snippet;
 * every setting lives in the chat screen.
 */
@Composable
fun AiHomeCardMaterial(onOpenChat: () -> Unit) {
    val model = rememberAiChatViewModel()
    val state by model.uiState.collectAsStateWithLifecycle()
    val config = state.config

    val status = when {
        !config.enabled -> stringResource(R.string.ai_status_disabled)
        !config.isConfigured -> stringResource(R.string.ai_status_not_configured)
        state.pendingApproval != null -> stringResource(R.string.ai_status_waiting_approval)
        state.pendingQuestion != null -> stringResource(R.string.ai_status_waiting_choice)
        state.isSending -> stringResource(R.string.ai_status_working)
        state.messages.lastOrNull()?.role == AiMessageRole.ERROR ->
            stringResource(R.string.ai_status_error)
        else -> stringResource(R.string.ai_status_ready, config.model)
    }
    val snippet = when {
        state.pendingApproval != null -> state.pendingApproval?.request?.let {
            compactSnippet("${it.title} · ${it.detail}")
        }

        state.pendingQuestion != null -> state.pendingQuestion?.let {
            compactSnippet(it.question)
        }

        state.isSending -> {
            val runningTool = state.messages.lastOrNull {
                it.role == AiMessageRole.TOOL && it.streaming && it.content.isNotBlank()
            }
            val streamingAssistant = state.messages.lastOrNull {
                it.role == AiMessageRole.ASSISTANT && it.streaming && it.content.isNotBlank()
            }
            when {
                runningTool != null -> compactSnippet(runningTool.content)
                streamingAssistant != null -> compactSnippet(streamingAssistant.content)
                else -> stringResource(R.string.ai_thinking)
            }
        }

        else -> state.messages.lastOrNull {
            it.content.isNotBlank() && it.role != AiMessageRole.ERROR
        }?.let { compactSnippet(it.content) }
    }

    AiTonalCard(
        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        shape = RoundedCornerShape(28.dp),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Surface(
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.primaryContainer,
                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ) {
                    AiAvatarImage(
                        modifier = Modifier.padding(8.dp),
                        size = 32.dp,
                    )
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.ai_assistant_title),
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(
                        text = status,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                if (state.isSending) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                    )
                }
            }

            if (!snippet.isNullOrBlank()) {
                Text(
                    text = snippet,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            Button(
                onClick = onOpenChat,
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
            ) {
                Icon(
                    imageVector = Icons.AutoMirrored.Rounded.Chat,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp),
                )
                Text(
                    text = stringResource(R.string.ai_open_chat),
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        }
    }
}

@Composable
internal fun AiConfigEditorMaterial(
    draft: AiConfig,
    onDraftChange: (AiConfig) -> Unit,
    testState: AiTestState,
    onTest: () -> Unit,
    fetchingModels: Boolean = false,
    onFetchModels: (Boolean) -> Unit = {},
) {
    var showKey by remember { mutableStateOf(false) }
    var pendingRiskKind by remember { mutableStateOf<AiRiskKind?>(null) }
    var pendingRiskPhrase by remember { mutableStateOf<String?>(null) }
    var pendingRiskAction by remember { mutableStateOf<(() -> Unit)?>(null) }
    fun requestRisk(kind: AiRiskKind, phrase: String? = null, action: () -> Unit) {
        pendingRiskKind = kind
        pendingRiskPhrase = phrase
        pendingRiskAction = action
    }
    val detected = if (draft.endpoint.isNotBlank()) draft.effectiveFormat() else null

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        AiToggleRow(
            title = stringResource(R.string.ai_master_switch),
            summary = stringResource(R.string.ai_master_switch_summary),
            checked = draft.enabled,
            onCheckedChange = { onDraftChange(draft.copy(enabled = it)) },
        )
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
        Text(
            text = stringResource(R.string.ai_connection_section),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
        )
        Text(
            text = stringResource(R.string.ai_connection_trust),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = draft.endpoint,
            onValueChange = { onDraftChange(draft.copy(endpoint = it)) },
            label = { Text(stringResource(R.string.ai_endpoint)) },
            placeholder = { Text(stringResource(R.string.ai_endpoint_hint)) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
        )
        if (detected != null) {
            Text(
                text = stringResource(
                    R.string.ai_format_detected,
                    stringResource(detected.labelRes()),
                ) + " · " + draft.resolvedEndpoint(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        OutlinedTextField(
            value = draft.apiKey,
            onValueChange = { onDraftChange(draft.copy(apiKey = it)) },
            label = { Text(stringResource(R.string.ai_api_key)) },
            placeholder = { Text(stringResource(R.string.ai_api_key_hint)) },
            singleLine = true,
            visualTransformation = if (showKey) VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = {
                IconButton(onClick = { showKey = !showKey }) {
                    Icon(
                        imageVector = if (showKey) Icons.Rounded.VisibilityOff else Icons.Rounded.Visibility,
                        contentDescription = stringResource(
                            if (showKey) R.string.ai_hide_key else R.string.ai_show_key
                        ),
                    )
                }
            },
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = draft.model,
            onValueChange = { onDraftChange(draft.copy(model = it)) },
            label = { Text(stringResource(R.string.ai_model)) },
            placeholder = { Text(stringResource(R.string.ai_model_hint)) },
            singleLine = true,
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = draft.imageModel,
            onValueChange = { onDraftChange(draft.copy(imageModel = it)) },
            label = { Text(stringResource(R.string.ai_image_model)) },
            placeholder = { Text(stringResource(R.string.ai_image_model_hint)) },
            singleLine = true,
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            TextButton(
                onClick = { onFetchModels(false) },
                enabled = !fetchingModels,
            ) {
                if (fetchingModels) {
                    CircularProgressIndicator(
                        modifier = Modifier.padding(end = 6.dp).size(14.dp),
                        strokeWidth = 2.dp,
                    )
                } else {
                    Icon(
                        imageVector = Icons.Rounded.Refresh,
                        contentDescription = null,
                        modifier = Modifier.padding(end = 6.dp).size(16.dp),
                    )
                }
                Text(
                    stringResource(
                        if (fetchingModels) R.string.ai_fetching_models else R.string.ai_fetch_models
                    )
                )
            }
            TextButton(
                onClick = { onFetchModels(true) },
                enabled = !fetchingModels,
            ) {
                Text(stringResource(R.string.ai_fetch_image_models))
            }
        }

        Text(
            text = stringResource(R.string.ai_format),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AiProviderFormat.entries.forEach { format ->
                FilterChip(
                    selected = draft.format == format,
                    onClick = { onDraftChange(draft.copy(format = format)) },
                    label = { Text(stringResource(format.labelRes())) },
                )
            }
        }

        Text(
            text = stringResource(R.string.ai_thinking_mode),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AiThinkingMode.entries.forEach { mode ->
                FilterChip(
                    selected = draft.thinkingMode == mode,
                    onClick = { onDraftChange(draft.copy(thinkingMode = mode)) },
                    label = { Text(stringResource(mode.labelRes())) },
                )
            }
        }
        Text(
            text = stringResource(R.string.ai_thinking_summary),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        OutlinedTextField(
            value = draft.systemPrompt,
            onValueChange = { onDraftChange(draft.copy(systemPrompt = it)) },
            label = { Text(stringResource(R.string.ai_system_prompt)) },
            placeholder = { Text(stringResource(R.string.ai_system_prompt_hint)) },
            minLines = 2,
            maxLines = 4,
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedButton(
            onClick = onTest,
            enabled = !testState.testing,
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (testState.testing) {
                CircularProgressIndicator(
                    modifier = Modifier.padding(end = 8.dp).size(16.dp),
                    strokeWidth = 2.dp,
                )
                Text(stringResource(R.string.ai_testing))
            } else {
                Text(stringResource(R.string.ai_test_connection))
            }
        }

        testState.message?.let { message ->
            Surface(
                shape = MaterialTheme.shapes.medium,
                color = if (testState.success) {
                    MaterialTheme.colorScheme.primaryContainer
                } else {
                    MaterialTheme.colorScheme.errorContainer
                },
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Icon(
                        imageVector = if (testState.success) Icons.Rounded.CheckCircle else Icons.Rounded.ErrorOutline,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                        tint = if (testState.success) {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        } else {
                            MaterialTheme.colorScheme.onErrorContainer
                        },
                    )
                    Text(
                        text = message,
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = if (testState.success) {
                            MaterialTheme.colorScheme.onPrimaryContainer
                        } else {
                            MaterialTheme.colorScheme.onErrorContainer
                        },
                    )
                }
            }
        }

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
        AiToggleRow(
            title = stringResource(R.string.ai_advanced_mode),
            summary = stringResource(R.string.ai_advanced_mode_summary),
            checked = draft.advancedMode,
            onCheckedChange = { enabled ->
                if (!enabled) {
                    onDraftChange(draft.copy(advancedMode = false))
                } else {
                    requestRisk(AiRiskKind.ADVANCED_API, "ADVANCED") {
                        onDraftChange(draft.copy(advancedMode = true))
                    }
                }
            },
        )
        if (draft.advancedMode) {
            Text(
                text = stringResource(R.string.ai_advanced_warning),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
            OutlinedTextField(
                value = draft.advancedOptionsJson,
                onValueChange = { onDraftChange(draft.copy(advancedOptionsJson = it)) },
                label = { Text(stringResource(R.string.ai_advanced_options)) },
                placeholder = { Text(stringResource(R.string.ai_advanced_options_hint)) },
                minLines = 4,
                maxLines = 10,
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                shape = MaterialTheme.shapes.large,
                modifier = Modifier.fillMaxWidth(),
            )
            val validationError = remember(draft.advancedOptionsJson) {
                if (draft.advancedOptionsJson.isBlank()) {
                    null
                } else {
                    AiAdvancedOptions.parse(draft.advancedOptionsJson).exceptionOrNull()
                }
            }
            if (validationError != null) {
                Text(
                    text = stringResource(
                        R.string.ai_advanced_options_invalid,
                        validationError.message ?: validationError.javaClass.simpleName,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            Text(
                text = stringResource(R.string.ai_advanced_options_help),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(
                    onClick = {
                        onDraftChange(
                            draft.copy(advancedOptionsJson = AiAdvancedOptions.exampleJson())
                        )
                    },
                ) {
                    Text(stringResource(R.string.ai_advanced_fill_example))
                }
                TextButton(
                    onClick = {
                        onDraftChange(draft.copy(advancedOptionsJson = ""))
                    },
                ) {
                    Text(stringResource(R.string.ai_advanced_reset))
                }
            }
        }

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
        Text(
            text = stringResource(R.string.ai_scope_section),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
        )
        Text(
            text = stringResource(R.string.ai_scope_summary),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        AiToggleRow(
            title = stringResource(R.string.ai_allow_root),
            summary = stringResource(R.string.ai_allow_root_summary),
            checked = draft.allowRootAccess,
            onCheckedChange = { enabled ->
                if (!enabled) {
                    onDraftChange(draft.copy(allowRootAccess = false))
                } else {
                    requestRisk(AiRiskKind.ROOT) {
                        onDraftChange(draft.copy(allowRootAccess = true))
                    }
                }
            },
        )
        AiToggleRow(
            title = stringResource(R.string.ai_allow_superuser),
            summary = stringResource(R.string.ai_allow_superuser_summary),
            checked = draft.allowSuperuserAccess,
            onCheckedChange = { onDraftChange(draft.copy(allowSuperuserAccess = it)) },
        )
        AiToggleRow(
            title = stringResource(R.string.ai_allow_module_data),
            summary = stringResource(R.string.ai_allow_module_data_summary),
            checked = draft.allowModuleAccess,
            onCheckedChange = { onDraftChange(draft.copy(allowModuleAccess = it)) },
        )
        AiToggleRow(
            title = stringResource(R.string.ai_allow_extension_data),
            summary = stringResource(R.string.ai_allow_extension_data_summary),
            checked = draft.allowExtensionAccess,
            onCheckedChange = { onDraftChange(draft.copy(allowExtensionAccess = it)) },
        )
        AiToggleRow(
            title = stringResource(R.string.ai_allow_web),
            summary = stringResource(R.string.ai_allow_web_summary),
            checked = draft.allowWebAccess,
            onCheckedChange = { onDraftChange(draft.copy(allowWebAccess = it)) },
        )
        AiToggleRow(
            title = stringResource(R.string.ai_allow_theme_read),
            summary = stringResource(R.string.ai_allow_theme_read_summary),
            checked = draft.allowThemeRead,
            onCheckedChange = { onDraftChange(draft.copy(allowThemeRead = it)) },
        )

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
        Text(
            text = stringResource(R.string.ai_superuser_section),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
        )
        Text(
            text = stringResource(R.string.ai_superuser_section_summary),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        AiToggleRow(
            title = stringResource(R.string.ai_allow_superuser_root),
            summary = stringResource(R.string.ai_allow_superuser_root_summary),
            checked = draft.allowSuperuserRootControl,
            onCheckedChange = { enabled ->
                if (!enabled) {
                    onDraftChange(draft.copy(allowSuperuserRootControl = false))
                } else {
                    requestRisk(AiRiskKind.PERMANENT_ROOT) {
                        onDraftChange(
                            draft.copy(
                                allowSuperuserRootControl = true,
                                allowSuperuserAccess = true,
                                allowRootAccess = true,
                            )
                        )
                    }
                }
            },
        )
        AiToggleRow(
            title = stringResource(R.string.ai_allow_superuser_temp_root),
            summary = stringResource(R.string.ai_allow_superuser_temp_root_summary),
            checked = draft.allowSuperuserTemporaryRoot,
            onCheckedChange = { enabled ->
                if (!enabled) {
                    onDraftChange(draft.copy(allowSuperuserTemporaryRoot = false))
                } else {
                    requestRisk(AiRiskKind.TEMPORARY_ROOT) {
                        onDraftChange(
                            draft.copy(
                                allowSuperuserTemporaryRoot = true,
                                allowSuperuserAccess = true,
                                allowRootAccess = true,
                            )
                        )
                    }
                }
            },
        )
        AiToggleRow(
            title = stringResource(R.string.ai_allow_superuser_switch),
            summary = stringResource(R.string.ai_allow_superuser_switch_summary),
            checked = draft.allowSuperuserSwitch,
            onCheckedChange = { enabled ->
                if (!enabled) {
                    onDraftChange(draft.copy(allowSuperuserSwitch = false))
                } else {
                    requestRisk(AiRiskKind.GLOBAL_SU) {
                        onDraftChange(
                            draft.copy(
                                allowSuperuserSwitch = true,
                                allowRootAccess = true,
                            )
                        )
                    }
                }
            },
        )

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
        Text(
            text = stringResource(R.string.ai_write_section),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
        )

        AiToggleRow(
            title = stringResource(R.string.ai_allow_theme),
            summary = stringResource(R.string.ai_allow_theme_summary),
            checked = draft.allowThemeWrite,
            onCheckedChange = { enabled ->
                onDraftChange(
                    draft.copy(
                        allowThemeWrite = enabled,
                        allowThemeRead = enabled || draft.allowThemeRead,
                        themeWriteFeatures = if (enabled) AiThemeFeature.ALL_IDS else draft.themeWriteFeatures,
                    )
                )
            },
        )
        if (draft.allowThemeWrite) {
            AiThemeFeatureChips(
                selected = draft.themeWriteFeatures,
                onToggle = { feature, enabled ->
                    val updated = draft.themeWriteFeatures.toMutableSet()
                    if (enabled) updated += feature.id else updated -= feature.id
                    onDraftChange(draft.copy(themeWriteFeatures = updated))
                },
            )
        }
        AiToggleRow(
            title = stringResource(R.string.ai_allow_extensions),
            summary = stringResource(R.string.ai_allow_extensions_summary),
            checked = draft.allowExtensionWrite,
            onCheckedChange = { enabled ->
                if (!enabled) {
                    onDraftChange(draft.copy(allowExtensionWrite = false))
                } else {
                    requestRisk(AiRiskKind.EXTENSION_WRITE) {
                        onDraftChange(
                            draft.copy(
                                allowExtensionWrite = true,
                                allowExtensionAccess = true,
                                extensionWriteFeatures = AiExtensionFeature.ALL_IDS,
                            )
                        )
                    }
                }
            },
        )
        if (draft.allowExtensionWrite) {
            AiExtensionFeatureChips(
                selected = draft.extensionWriteFeatures,
                onToggle = { feature, enabled ->
                    val updated = draft.extensionWriteFeatures.toMutableSet()
                    if (enabled) updated += feature.id else updated -= feature.id
                    onDraftChange(draft.copy(extensionWriteFeatures = updated))
                },
            )
        }
        AiToggleRow(
            title = stringResource(R.string.ai_allow_modules),
            summary = stringResource(R.string.ai_allow_modules_summary),
            checked = draft.allowModuleInstall,
            onCheckedChange = { enabled ->
                if (!enabled) {
                    onDraftChange(draft.copy(allowModuleInstall = false))
                } else {
                    requestRisk(AiRiskKind.MODULE_INSTALL) {
                        onDraftChange(
                            draft.copy(
                                allowModuleInstall = true,
                                allowModuleAccess = true,
                            )
                        )
                    }
                }
            },
        )
        AiToggleRow(
            title = stringResource(R.string.ai_confirm_actions),
            summary = stringResource(R.string.ai_confirm_actions_summary),
            checked = draft.requireConfirmation,
            onCheckedChange = { onDraftChange(draft.copy(requireConfirmation = it)) },
        )

        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
        Text(
            text = stringResource(R.string.ai_behavior_section),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
        )
        AiToggleRow(
            title = stringResource(R.string.ai_include_context),
            summary = stringResource(R.string.ai_include_context_summary),
            checked = draft.includeContext,
            onCheckedChange = { onDraftChange(draft.copy(includeContext = it)) },
        )
        AiToggleRow(
            title = stringResource(R.string.ai_streaming),
            summary = stringResource(R.string.ai_streaming_summary),
            checked = draft.streaming,
            onCheckedChange = { onDraftChange(draft.copy(streaming = it)) },
        )
        AiToggleRow(
            title = stringResource(R.string.ai_tool_calling),
            summary = stringResource(R.string.ai_tool_calling_summary),
            checked = draft.toolCalling,
            onCheckedChange = { onDraftChange(draft.copy(toolCalling = it)) },
        )
        AiToggleRow(
            title = stringResource(R.string.ai_allow_code_execution),
            summary = stringResource(R.string.ai_allow_code_execution_summary),
            checked = draft.allowCodeExecution,
            onCheckedChange = { enabled ->
                if (!enabled) {
                    onDraftChange(draft.copy(allowCodeExecution = false))
                } else {
                    requestRisk(AiRiskKind.CODE_EXECUTION) {
                        onDraftChange(draft.copy(allowCodeExecution = true))
                    }
                }
            },
        )
        AiToggleRow(
            title = stringResource(R.string.ai_keep_history),
            summary = stringResource(R.string.ai_keep_history_summary),
            checked = draft.keepHistory,
            onCheckedChange = { onDraftChange(draft.copy(keepHistory = it)) },
        )

    }

    pendingRiskKind?.let { kind ->
        AiRiskDialogMaterial(
            kind = kind,
            phrase = pendingRiskPhrase,
            onConfirm = {
                pendingRiskAction?.invoke()
                pendingRiskKind = null
                pendingRiskPhrase = null
                pendingRiskAction = null
            },
            onDismiss = {
                pendingRiskKind = null
                pendingRiskPhrase = null
                pendingRiskAction = null
            },
        )
    }
}

@Composable
private fun AiThemeFeatureChips(
    selected: Set<String>,
    onToggle: (AiThemeFeature, Boolean) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(
            text = stringResource(R.string.ai_theme_features),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AiThemeFeature.entries.forEach { feature ->
                FilterChip(
                    selected = feature.id in selected,
                    onClick = { onToggle(feature, feature.id !in selected) },
                    label = { Text(stringResource(feature.labelRes)) },
                )
            }
        }
    }
}

@Composable
private fun AiExtensionFeatureChips(
    selected: Set<String>,
    onToggle: (AiExtensionFeature, Boolean) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(
            text = stringResource(R.string.ai_extension_features),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AiExtensionFeature.entries.forEach { feature ->
                FilterChip(
                    selected = feature.id in selected,
                    onClick = { onToggle(feature, feature.id !in selected) },
                    label = { Text(stringResource(feature.labelRes)) },
                )
            }
        }
    }
}

@Composable
private fun AiToggleRow(
    title: String,
    summary: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = summary,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        AiExpressiveSwitch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
