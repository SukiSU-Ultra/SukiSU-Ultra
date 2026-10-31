package com.sukisu.ultra.ui.screen.ai

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.R
import com.sukisu.ultra.ksuApp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import java.util.UUID
import kotlin.time.Duration.Companion.milliseconds

enum class AiMessageRole { USER, ASSISTANT, TOOL, ERROR }

data class AiChatMessage(
    val id: String,
    val role: AiMessageRole,
    val content: String,
    val streaming: Boolean = false,
    val toolName: String? = null,
    /** Set by open_app_page for a clickable tool-card button. */
    val navigation: AiNavigationTarget? = null,
    val navigationTitle: String? = null,
    /** Set when a write tool was blocked by a disabled capability. */
    val capability: AiCapability? = null,
    /** Local image produced or selected by an image tool. */
    val imagePath: String? = null,
)

enum class AiFilePickerMode { OPEN_IMAGE, CREATE_IMAGE, OPEN_FILE, CREATE_FILE }

data class AiFilePickerRequest(
    val id: String,
    val mode: AiFilePickerMode,
    val title: String,
    val suggestedName: String = "",
)

data class AiPendingApproval(
    val request: AiApprovalRequest,
)

data class AiChatUiState(
    val config: AiConfig = AiConfig(),
    val messages: List<AiChatMessage> = emptyList(),
    val input: String = "",
    val isSending: Boolean = false,
    val pendingApproval: AiPendingApproval? = null,
    /** A multiple-choice question waiting at the bottom of the chat. */
    val pendingQuestion: AiUserQuestion? = null,
    val error: String? = null,
    val suggestions: List<String> = emptyList(),
    val suggestionsLoading: Boolean = false,
    val pendingFilePicker: AiFilePickerRequest? = null,
    val rootGrantedForRequest: Boolean = false,
)

/**
 * Chat loop for the scoped assistant. The only side effects it can trigger are
 * the tools in [AiTools]; every write is gated by the user's capability toggles
 * and, optionally, an approval dialog.
 */
class AiChatViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(initialState())
    val uiState: StateFlow<AiChatUiState> = _uiState.asStateFlow()

    private var chatJob: Job? = null
    private var approvalDeferred: CompletableDeferred<Boolean>? = null
    private var questionDeferred: CompletableDeferred<String?>? = null
    private var historyGeneration = 0
    private var autoApproveForRequest = false
    private var suggestionJob: Job? = null
    private var suggestionGeneration = 0
    private var suggestionRequestedGeneration = -1
    private var filePickerDeferred: CompletableDeferred<Uri?>? = null
    private var rootGrantedForRequest = false
    private var rootRequestDeferred: CompletableDeferred<Boolean>? = null

    private fun initialState(): AiChatUiState {
        val config = AiSettings.load()
        val restored = if (config.keepHistory) {
            AiSettings.loadHistory().map { turn ->
                AiChatMessage(
                    id = newId(),
                    role = if (turn.role == "assistant") AiMessageRole.ASSISTANT else AiMessageRole.USER,
                    content = turn.content,
                )
            }
        } else {
            emptyList()
        }
        return AiChatUiState(
            config = config,
            messages = restored,
            suggestions = defaultSuggestions(),
        )
    }

    fun refreshConfig() {
        val config = AiSettings.load()
        _uiState.update { it.copy(config = config) }
    }

    /** Persist edits from the settings page without starting a chat turn. */
    fun updateConfig(config: AiConfig) {
        val previous = _uiState.value.config
        AiSettings.save(config)
        if (previous.keepHistory && !config.keepHistory) AiSettings.clearHistory()
        _uiState.update { it.copy(config = config) }
    }

    fun saveConfig(config: AiConfig) {
        updateConfig(config)
        if (_uiState.value.messages.isEmpty()) {
            suggestionGeneration++
            suggestionRequestedGeneration = -1
            ensureSuggestions()
        }
    }

    /** Enable a capability from the inline agent-style permission card. */
    fun setCapability(capability: AiCapability, enabled: Boolean) {
        val config = AiSettings.load()
        val updated = when (capability) {
            AiCapability.ROOT -> config.copy(allowRootAccess = enabled)
            AiCapability.SUPERUSER -> config.copy(allowSuperuserAccess = enabled)
            AiCapability.SUPERUSER_ROOT -> config.copy(
                allowSuperuserRootControl = enabled,
                allowSuperuserAccess = enabled || config.allowSuperuserAccess,
                allowRootAccess = enabled || config.allowRootAccess,
            )
            AiCapability.SUPERUSER_TEMP_ROOT -> config.copy(
                allowSuperuserTemporaryRoot = enabled,
                allowSuperuserAccess = enabled || config.allowSuperuserAccess,
                allowRootAccess = enabled || config.allowRootAccess,
            )
            AiCapability.SUPERUSER_SWITCH -> config.copy(
                allowSuperuserSwitch = enabled,
                allowRootAccess = enabled || config.allowRootAccess,
            )
            AiCapability.MODULE_DATA -> config.copy(allowModuleAccess = enabled)
            AiCapability.EXTENSION_DATA -> config.copy(allowExtensionAccess = enabled)
            AiCapability.WEB -> config.copy(allowWebAccess = enabled)
            AiCapability.THEME_READ -> config.copy(allowThemeRead = enabled)
            AiCapability.THEME -> config.copy(
                allowThemeWrite = enabled,
                allowThemeRead = enabled || config.allowThemeRead,
                themeWriteFeatures = if (enabled) AiThemeFeature.ALL_IDS else config.themeWriteFeatures,
            )
            AiCapability.EXTENSIONS -> config.copy(
                allowExtensionWrite = enabled,
                allowExtensionAccess = enabled || config.allowExtensionAccess,
                extensionWriteFeatures = if (enabled) AiExtensionFeature.ALL_IDS else config.extensionWriteFeatures,
            )
            AiCapability.MODULES -> config.copy(
                allowModuleInstall = enabled,
                allowModuleAccess = enabled || config.allowModuleAccess,
            )
        }
        saveConfig(updated)
        if (capability == AiCapability.ROOT && enabled) grantRootForRequest()
    }

    /** Allow root only for the current user request. */
    fun grantRootForRequest() {
        rootGrantedForRequest = true
        _uiState.update { it.copy(rootGrantedForRequest = true) }
        rootRequestDeferred?.complete(true)
    }

    fun onInputChange(value: String) {
        _uiState.update { it.copy(input = value) }
    }

    fun clearError() {
        _uiState.update { it.copy(error = null) }
    }

    fun reportError(message: String) {
        _uiState.update { it.copy(error = message) }
    }

    fun onFilePicked(uri: Uri?) {
        filePickerDeferred?.complete(uri)
    }

    private suspend fun requestFile(
        mode: AiFilePickerMode,
        title: String,
        suggestedName: String = "",
    ): Uri? {
        val deferred = CompletableDeferred<Uri?>()
        filePickerDeferred = deferred
        _uiState.update {
            it.copy(
                pendingFilePicker = AiFilePickerRequest(
                    id = newId(),
                    mode = mode,
                    title = title,
                    suggestedName = suggestedName,
                )
            )
        }
        return try {
            withTimeoutOrNull((5 * 60 * 1000L).milliseconds) { deferred.await() }
        } finally {
            filePickerDeferred = null
            _uiState.update { it.copy(pendingFilePicker = null) }
        }
    }

    /** Generate a fresh set once per chat session (openers or follow-ups). */
    fun ensureSuggestions() {
        if (suggestionRequestedGeneration == suggestionGeneration) return
        suggestionRequestedGeneration = suggestionGeneration
        refreshSuggestions()
    }

    /** The shuffle action in the welcome card always asks the model again. */
    fun refreshSuggestions() {
        val config = AiSettings.load()
        if (!config.enabled || !config.isConfigured) {
            _uiState.update {
                it.copy(suggestions = defaultSuggestions(), suggestionsLoading = false)
            }
            return
        }
        if (AiLocalNetwork.needsPermission(ksuApp, config)) {
            _uiState.update {
                it.copy(suggestions = defaultSuggestions(), suggestionsLoading = false)
            }
            return
        }
        suggestionJob?.cancel()
        _uiState.update { it.copy(suggestionsLoading = true) }
        suggestionJob = viewModelScope.launch {
            val recent = _uiState.value.messages
                .filter { it.role == AiMessageRole.USER || it.role == AiMessageRole.ASSISTANT }
                .filter { it.content.isNotBlank() }
                .takeLast(6)
                .joinToString("\n") { message ->
                    val role = if (message.role == AiMessageRole.USER) "user" else "assistant"
                    "$role: ${message.content.take(400)}"
                }
            val raw = try {
                withTimeoutOrNull(SUGGESTION_TIMEOUT_MS.milliseconds) {
                    AiApiClient.complete(
                        config = config.copy(
                            streaming = false,
                            toolCalling = false,
                            thinkingMode = AiThinkingMode.OFF,
                        ),
                        messages = listOf(
                            AiApiMessage(
                                "system",
                                suggestionPrompt(recent, _uiState.value.suggestions, config),
                            ),
                            AiApiMessage("user", "Generate the suggestions now."),
                        ),
                        tools = emptyList(),
                        useTools = false,
                        maxTokens = 700,
                    ).text
                }.orEmpty()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                ""
            }
            val suggestions = (parseSuggestions(raw) + defaultSuggestions())
                .distinct()
                .take(4)
            _uiState.update {
                it.copy(suggestions = suggestions, suggestionsLoading = false)
            }
        }
    }

    private fun suggestionPrompt(
        recentConversation: String,
        previous: List<String>,
        config: AiConfig,
    ): String {
        val locale = ksuApp.resources.configuration.locales[0]
        val language = locale.getDisplayLanguage(locale)
        val context = if (recentConversation.isBlank()) {
            "The conversation has not started yet. Suggest opener ideas."
        } else {
            "Continue this conversation. Suggest plausible next user messages or follow-up actions based on it. Do not repeat a previous user message verbatim.\nRecent conversation:\n$recentConversation"
        }
        val avoid = if (previous.isEmpty()) {
            ""
        } else {
            "Do not repeat these previous suggestions: ${previous.joinToString("; ")}"
        }
        val capabilities = buildList {
            add("manager/root status")
            if (config.allowThemeRead || config.allowThemeWrite) add("theme and appearance")
            if (config.allowExtensionAccess) add("extension status and SuSFS/KPM state")
            if (config.allowModuleAccess) add("installed modules and the module repository")
            if (config.allowSuperuserAccess) add("superuser apps and temporary-root status")
            if (config.allowSuperuserRootControl) add("permanent root review")
            if (config.allowSuperuserTemporaryRoot) add("temporary root")
            if (config.allowSuperuserSwitch) add("global su mode")
            if (config.allowModuleInstall) add("module installation")
            if (config.allowWebAccess) add("web/GitHub module discovery")
        }.joinToString(", ")
        return """
            You generate four short suggestion chips for the built-in assistant of SukiSU Ultra Manager,
            an Android kernel-level root manager.
            UI language: $language. Write the suggestions in that language.
            Output ONLY a JSON array of four strings, each under 60 characters.
            Make them varied and practical. At most one may be casual chat. Prefer:
            - status and diagnostics: root, kernel/LKM, safe or jailbreak mode, KPM, SuSFS, module updates
            - exact app areas: Appearance, Extensions, Superuser app profile, Module repository, Settings
            - inspections and, only when allowed, changes within: $capabilities
            Never suggest arbitrary shell, flashing, uninstalling, disabling the AI home entry, or actions
            outside the allowed capabilities. Do not promise features or pages the device does not support.
            $context
            $avoid
        """.trimIndent()
    }

    private fun parseSuggestions(raw: String): List<String> {
        val cleaned = raw.trim()
            .removePrefix("```json")
            .removePrefix("```")
            .removeSuffix("```")
            .trim()
        val array = runCatching {
            when (val parsed = Json.parseToJsonElement(cleaned)) {
                is JsonArray -> parsed
                is JsonObject -> parsed["suggestions"] as? JsonArray
                else -> null
            }
        }.getOrNull()
        val values = array?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            ?: cleaned.lineSequence()
                .map { line ->
                    line.trim()
                        .trimStart('-', '*', '•')
                        .replace(Regex("^\\d+[.)]\\s*"), "")
                        .trim()
                }
                .filter { it.isNotEmpty() }
                .toList()
        return values
            .mapNotNull(::sanitizeAiSuggestion)
            .distinct()
            .shuffled()
            .take(4)
    }

    private fun defaultSuggestions(): List<String> = listOf(
        ksuApp.getString(R.string.ai_suggestion_status),
        ksuApp.getString(R.string.ai_suggestion_extensions),
        ksuApp.getString(R.string.ai_suggestion_modules),
        ksuApp.getString(R.string.ai_suggestion_chat),
    )

    fun clearHistory() {
        historyGeneration++
        suggestionGeneration++
        suggestionRequestedGeneration = -1
        suggestionJob?.cancel()
        stop()
        AiSettings.clearHistory()
        _uiState.update {
            it.copy(
                messages = emptyList(),
                input = "",
                error = null,
                suggestions = defaultSuggestions(),
                suggestionsLoading = false,
            )
        }
    }

    fun deleteMessage(id: String) {
        _uiState.update { state -> state.copy(messages = state.messages.filterNot { it.id == id }) }
        if (_uiState.value.messages.isEmpty()) {
            suggestionGeneration++
            suggestionRequestedGeneration = -1
        }
        persistHistory(historyGeneration)
    }

    /**
     * Run a shell block the user tapped Run on. The result is appended as a local
     * tool card; it is never fed back to the model automatically.
     */
    fun runCodeBlock(command: String) {
        val config = AiSettings.load()
        if (!config.allowCodeExecution) {
            appendErrorMessage(ksuApp.getString(R.string.ai_code_execution_disabled))
            return
        }
        if (command.isBlank()) return
        val id = newId()
        _uiState.update { state ->
            state.copy(
                messages = state.messages + AiChatMessage(
                    id = id,
                    role = AiMessageRole.TOOL,
                    content = ksuApp.getString(R.string.ai_code_running),
                    streaming = true,
                    toolName = ksuApp.getString(R.string.ai_code_tool),
                )
            )
        }
        viewModelScope.launch {
            val output = AiCodeExecutor.run(command)
            _uiState.update { state ->
                state.copy(
                    messages = state.messages.map { message ->
                        if (message.id == id) {
                            message.copy(content = output, streaming = false)
                        } else {
                            message
                        }
                    }
                )
            }
        }
    }

    fun approvePending() {
        approvalDeferred?.complete(true)
    }

    /** Skip every remaining approval dialog until this user request finishes. */
    fun approveAlwaysForRequest() {
        autoApproveForRequest = true
        approvalDeferred?.complete(true)
    }

    fun denyPending() {
        approvalDeferred?.complete(false)
    }

    fun stop() {
        chatJob?.cancel()
        chatJob = null
        suggestionJob?.cancel()
        approvalDeferred?.cancel()
        approvalDeferred = null
        questionDeferred?.cancel()
        questionDeferred = null
        rootRequestDeferred?.cancel()
        rootRequestDeferred = null
        _uiState.update { state ->
            state.copy(
                isSending = false,
                suggestionsLoading = false,
                pendingApproval = null,
                pendingQuestion = null,
                messages = state.messages
                    .filterNot { it.role == AiMessageRole.ASSISTANT && it.content.isBlank() }
                    .map { it.copy(streaming = false) },
            )
        }
    }

    fun send() {
        if (_uiState.value.isSending) return
        val text = _uiState.value.input.trim()
        if (text.isEmpty()) return
        val config = AiSettings.load()
        if (!config.enabled) {
            _uiState.update { it.copy(error = ksuApp.getString(R.string.ai_error_disabled)) }
            return
        }
        if (!config.isConfigured) {
            _uiState.update { it.copy(error = ksuApp.getString(R.string.ai_error_not_configured)) }
            return
        }
        if (AiLocalNetwork.needsPermission(ksuApp, config)) {
            _uiState.update {
                it.copy(error = ksuApp.getString(R.string.ai_local_network_permission_denied))
            }
            return
        }
        autoApproveForRequest = false
        rootGrantedForRequest = false
        rootRequestDeferred?.cancel()
        rootRequestDeferred = null
        _uiState.update { it.copy(rootGrantedForRequest = false) }
        suggestionJob?.cancel()
        val userMessage = AiChatMessage(newId(), AiMessageRole.USER, text)
        _uiState.update {
            it.copy(
                input = "",
                messages = it.messages + userMessage,
                isSending = true,
                error = null,
                suggestionsLoading = false,
            )
        }
        val generation = historyGeneration
        chatJob = viewModelScope.launch {
            try {
                runChat(config, text, generation)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                appendErrorMessage(error.message ?: error.javaClass.simpleName)
            } finally {
                _uiState.update { state ->
                    state.copy(
                        isSending = false,
                        pendingApproval = null,
                        pendingQuestion = null,
                        messages = state.messages.map { it.copy(streaming = false) },
                    )
                }
                persistHistory(generation)
            }
        }
    }

    private suspend fun runChat(config: AiConfig, userText: String, generation: Int) {
        val apiMessages = buildInitialMessages(config, userText)
        var round = 0
        var actionRounds = 0
        while (true) {
            val assistantId = newId()
            appendAssistantPlaceholder(assistantId)
            var started = false
            val tools = if (config.toolCalling) AiTools.specsFor(config) else emptyList()
            val deltaSink: (String) -> Unit = { chunk ->
                started = true
                appendAssistantDelta(assistantId, chunk)
            }
            val completion = try {
                AiApiClient.complete(
                    config = config,
                    messages = apiMessages,
                    tools = tools,
                    useTools = tools.isNotEmpty(),
                    maxTokens = config.advancedOptions().maxOutputTokens,
                    onDelta = deltaSink,
                )
            } catch (error: AiApiException) {
                val rejectedTools = !started && tools.isNotEmpty() &&
                    error.statusCode?.let { it in setOf(400, 404, 422) } == true
                if (!rejectedTools) throw error
                AiApiClient.complete(
                    config = config,
                    messages = apiMessages,
                    tools = emptyList(),
                    useTools = false,
                    maxTokens = config.advancedOptions().maxOutputTokens,
                    onDelta = deltaSink,
                )
            }

            if (!started && completion.text.isNotBlank()) {
                appendAssistantDelta(assistantId, completion.text)
                started = true
            }
            if (started) {
                finishAssistantMessage(assistantId)
            } else {
                removeEmptyAssistant(assistantId)
            }

            if (completion.text.isBlank() && completion.toolCalls.isEmpty()) {
                appendErrorMessage(ksuApp.getString(R.string.ai_error_empty_response))
                return
            }

            val toolCalls = completion.toolCalls.mapIndexed { index, call ->
                if (call.id.isBlank()) call.copy(id = "call_${round}_$index") else call
            }
            apiMessages += AiApiMessage(
                role = "assistant",
                content = completion.text,
                toolCalls = toolCalls,
            )

            if (completion.toolCalls.isEmpty()) {
                persistHistory(generation)
                // Keep the follow-up chips coming after every completed answer.
                refreshSuggestions()
                return
            }
            if (!config.toolCalling) {
                appendErrorMessage(ksuApp.getString(R.string.ai_error_tool_calling_disabled))
                return
            }
            // Choosing from ask_user is a conversation turn, not an action.
            // Do not let repeated choices consume the action-tool budget.
            val onlyQuestions = toolCalls.all { it.name == AiTools.ASK_USER_TOOL }
            if (!onlyQuestions) {
                if (actionRounds >= config.advancedOptions().maxToolRounds) {
                    appendErrorMessage(ksuApp.getString(R.string.ai_error_tool_rounds))
                    return
                }
                actionRounds++
            }
            round++

            for (call in toolCalls) {
                val callId = call.id
                // The ask_user tool renders its own question panel and message;
                // a "Running ask_user(...)" tool card would only add noise.
                val toolMessageId = if (call.name == AiTools.ASK_USER_TOOL) null else newId()
                if (toolMessageId != null) {
                    val label = "${call.name}(${call.arguments.take(160)})"
                    _uiState.update { state ->
                        state.copy(
                            messages = state.messages + AiChatMessage(
                                id = toolMessageId,
                                role = AiMessageRole.TOOL,
                                content = "Running $label…",
                                streaming = true,
                                toolName = call.name,
                            )
                        )
                    }
                }
                var navTarget: AiNavigationTarget? = null
                var navTitle: String? = null
                var capability: AiCapability? = null
                var imagePath: String? = null
                var attempt = 0
                var resultText: String? = null
                while (resultText == null) {
                    val toolConfig = AiSettings.load()
                    try {
                        resultText = AiTools.execute(
                            call = call,
                            config = toolConfig,
                            rootGranted = rootGrantedForRequest,
                            onProgress = { text ->
                                toolMessageId?.let { updateToolMessage(it, text) }
                            },
                            onNavigation = { target, title ->
                                navTarget = target
                                navTitle = title
                            },
                            onImage = { path -> imagePath = path },
                            onPickFile = { mode, title, suggestedName ->
                                requestFile(mode, title, suggestedName)
                            },
                            ask = { question -> requestQuestion(question) },
                        ) { request -> requestApproval(request) }
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (required: AiPermissionRequiredException) {
                        capability = required.capability
                        // Root can be granted for the current request. Keep this
                        // turn open until the user decides, then retry the exact
                        // tool call instead of leaving a dead button behind.
                        if (required.capability == AiCapability.ROOT &&
                            attempt == 0 &&
                            toolMessageId != null
                        ) {
                            attempt++
                            updateToolMessagePermission(
                                id = toolMessageId,
                                content = "Root access is required for this request. " +
                                    "Allow it for this request or enable it in settings.",
                            )
                            if (requestRootForRequest(toolMessageId)) {
                                updateToolMessage(toolMessageId, "Root access granted. Retrying the request…")
                                capability = null
                                navTarget = null
                                navTitle = null
                                imagePath = null
                                continue
                            }
                            capability = null
                            resultText = "Root access was not granted for this request. " +
                                "Do not retry; explain which action needs root and how to enable it."
                            break
                        }
                        if (required.capability == AiCapability.ROOT) capability = null
                        resultText = "${required.message ?: "Permission required for ${required.capability.modelLabel}."} " +
                            "The user has been shown a switch to enable it; do not retry until they confirm."
                    } catch (error: Exception) {
                        resultText = "Error: ${error.message ?: error.javaClass.simpleName}"
                    }
                }
                val result = resultText.orEmpty()
                if (toolMessageId != null) {
                    _uiState.update { state ->
                        state.copy(
                            messages = state.messages.map { message ->
                                if (message.id == toolMessageId) {
                                    message.copy(
                                        content = result,
                                        streaming = false,
                                        navigation = navTarget,
                                        navigationTitle = navTitle,
                                        capability = capability,
                                        imagePath = imagePath,
                                    )
                                } else {
                                    message
                                }
                            }
                        )
                    }
                }
                apiMessages += AiApiMessage(
                    role = "tool",
                    content = result,
                    toolCallId = callId,
                    toolName = call.name,
                )
            }
        }
    }

    private suspend fun buildInitialMessages(
        config: AiConfig,
        userText: String,
    ): MutableList<AiApiMessage> {
        val environment = if (config.includeContext) {
            runCatching { AiEnvironment.snapshot(config) }.getOrNull()
        } else {
            null
        }
        val messages = mutableListOf(
            AiApiMessage("system", AiTools.buildSystemPrompt(config, environment))
        )
        val advanced = config.advancedOptions()
        val history = if (config.keepHistory) {
            val turns = AiSettings.loadHistory().takeLast(advanced.maxHistoryTurns)
            var characters = 0
            val kept = mutableListOf<AiTurn>()
            for (turn in turns.asReversed()) {
                if (characters + turn.content.length > advanced.maxHistoryChars) break
                kept += turn
                characters += turn.content.length
            }
            kept.asReversed()
        } else {
            emptyList()
        }
        history.forEach { turn ->
            if (turn.content.isNotBlank()) {
                messages += AiApiMessage(
                    role = if (turn.role == "assistant") "assistant" else "user",
                    content = turn.content,
                )
            }
        }
        messages += AiApiMessage("user", userText)
        return messages
    }

    /**
     * Complete the currently pending ask_user call. A non-null answer is also
     * appended as a user bubble so the conversation shows what was chosen.
     */
    fun answerQuestion(answer: String?) {
        val deferred = questionDeferred ?: return
        if (deferred.isCompleted) return
        val normalized = answer?.trim()?.takeIf { it.isNotEmpty() }
        if (normalized != null) {
            _uiState.update { state ->
                state.copy(
                    messages = state.messages + AiChatMessage(
                        id = newId(),
                        role = AiMessageRole.USER,
                        content = normalized,
                    )
                )
            }
        }
        deferred.complete(normalized)
    }

    private suspend fun requestQuestion(question: AiUserQuestion): String? {
        val deferred = CompletableDeferred<String?>()
        questionDeferred = deferred
        _uiState.update { state ->
            val last = state.messages.lastOrNull()
            val alreadyShown = last?.role == AiMessageRole.ASSISTANT &&
                last.content.contains(question.question)
            val questionMessage = if (alreadyShown) {
                emptyList()
            } else {
                listOf(
                    AiChatMessage(
                        id = newId(),
                        role = AiMessageRole.ASSISTANT,
                        content = buildString {
                            append(question.question)
                            if (question.options.isNotEmpty()) {
                                append("\n\n")
                                question.options.forEach { append("- ").append(it).append('\n') }
                            }
                        }.trimEnd(),
                    )
                )
            }
            state.copy(
                pendingQuestion = question,
                messages = state.messages + questionMessage,
            )
        }
        return try {
            // Wait until the user answers or explicitly dismisses/stops. The
            // choice panel must not disappear on an arbitrary timer.
            deferred.await()
        } finally {
            questionDeferred = null
            _uiState.update { it.copy(pendingQuestion = null) }
        }
    }

    /**
     * Wait for the user to allow root for the current request. The chat turn
     * stays open (the tool card remains visible) so the exact tool call can be
     * retried after approval instead of ending with a dead button.
     */
    private suspend fun requestRootForRequest(messageId: String?): Boolean {
        val deferred = CompletableDeferred<Boolean>()
        rootRequestDeferred = deferred
        return try {
            withTimeoutOrNull(ROOT_REQUEST_TIMEOUT_MS.milliseconds) { deferred.await() } ?: false
        } finally {
            if (rootRequestDeferred === deferred) rootRequestDeferred = null
            // Never leave a permission card behind once the wait is over or
            // cancelled; a card without a pending request has no action left.
            if (messageId != null) {
                _uiState.update { state ->
                    state.copy(
                        messages = state.messages.map { message ->
                            if (message.id == messageId && message.capability == AiCapability.ROOT) {
                                message.copy(capability = null)
                            } else {
                                message
                            }
                        }
                    )
                }
            }
        }
    }

    private suspend fun requestApproval(request: AiApprovalRequest): Boolean {
        if (autoApproveForRequest) return true
        val deferred = CompletableDeferred<Boolean>()
        approvalDeferred = deferred
        _uiState.update { it.copy(pendingApproval = AiPendingApproval(request)) }
        return try {
            withTimeoutOrNull(APPROVAL_TIMEOUT_MS.milliseconds) { deferred.await() } ?: false
        } finally {
            approvalDeferred = null
            _uiState.update { it.copy(pendingApproval = null) }
        }
    }

    private fun appendAssistantPlaceholder(id: String) {
        _uiState.update { state ->
            state.copy(
                messages = state.messages + AiChatMessage(
                    id = id,
                    role = AiMessageRole.ASSISTANT,
                    content = "",
                    streaming = true,
                )
            )
        }
    }

    private fun removeEmptyAssistant(id: String) {
        _uiState.update { state ->
            state.copy(messages = state.messages.filterNot { it.id == id && it.content.isBlank() })
        }
    }

    private fun updateToolMessage(id: String, content: String) {
        _uiState.update { state ->
            state.copy(messages = state.messages.map { message ->
                if (message.id == id) message.copy(content = content, streaming = true) else message
            })
        }
    }

    /** Show the root permission card while the tool call is waiting for approval. */
    private fun updateToolMessagePermission(id: String, content: String) {
        _uiState.update { state ->
            state.copy(messages = state.messages.map { message ->
                if (message.id == id) {
                    message.copy(
                        content = content,
                        streaming = true,
                        capability = AiCapability.ROOT,
                        navigation = null,
                        navigationTitle = null,
                        imagePath = null,
                    )
                } else {
                    message
                }
            })
        }
    }

    private fun appendAssistantDelta(id: String, chunk: String) {
        _uiState.update { state ->
            val exists = state.messages.any { it.id == id }
            val messages = if (exists) {
                state.messages.map { message ->
                    if (message.id == id) message.copy(content = message.content + chunk) else message
                }
            } else {
                state.messages + AiChatMessage(
                    id = id,
                    role = AiMessageRole.ASSISTANT,
                    content = chunk,
                    streaming = true,
                )
            }
            state.copy(messages = messages)
        }
    }

    private fun finishAssistantMessage(id: String) {
        _uiState.update { state ->
            state.copy(messages = state.messages.map { message ->
                if (message.id == id) message.copy(streaming = false) else message
            })
        }
    }

    private fun appendErrorMessage(message: String) {
        _uiState.update { state ->
            state.copy(
                messages = state.messages.filterNot {
                    it.role == AiMessageRole.ASSISTANT && it.content.isBlank()
                } + AiChatMessage(
                    id = newId(),
                    role = AiMessageRole.ERROR,
                    content = message,
                )
            )
        }
    }

    private fun persistHistory(generation: Int = historyGeneration) {
        if (generation != historyGeneration) return
        val config = _uiState.value.config
        if (!config.keepHistory) {
            AiSettings.clearHistory()
            return
        }
        val turns = _uiState.value.messages
            .filter { it.role == AiMessageRole.USER || it.role == AiMessageRole.ASSISTANT }
            .filter { it.content.isNotBlank() }
            .takeLast(config.advancedOptions().maxHistoryTurns)
            .map { AiTurn(role = if (it.role == AiMessageRole.ASSISTANT) "assistant" else "user", content = it.content) }
        AiSettings.saveHistory(turns)
    }

    private fun newId(): String = UUID.randomUUID().toString()

    private companion object {
        const val SUGGESTION_TIMEOUT_MS = 30_000L
        const val APPROVAL_TIMEOUT_MS = 10 * 60 * 1000L
        const val ROOT_REQUEST_TIMEOUT_MS = 10 * 60 * 1000L
    }
}
