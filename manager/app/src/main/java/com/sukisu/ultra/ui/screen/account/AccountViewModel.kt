package com.sukisu.ultra.ui.screen.account

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.data.model.AccountSession
import com.sukisu.ultra.data.repository.AccountRepository
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.data.repository.ThemeStoreDefaults
import com.sukisu.ultra.data.repository.ThemeStoreRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class AccountSource(
    val id: String,
    val name: String,
    val baseUrl: String,
    val isDefault: Boolean,
)

data class AccountUiState(
    val sessions: Map<String, AccountSession> = emptyMap(),
    val sources: List<AccountSource> = emptyList(),
    val selectedBaseUrl: String = "",
    val defaultUploadBaseUrl: String = "",
    val loading: Boolean = false,
    val submitting: Boolean = false,
    val registerMode: Boolean = false,
    val error: String? = null,
    val message: String? = null,
) {
    val session: AccountSession?
        get() = sessions[selectedBaseUrl]

    val baseUrl: String
        get() = selectedBaseUrl

    val selectedSource: AccountSource?
        get() = sources.firstOrNull { it.baseUrl == selectedBaseUrl }
}

class AccountViewModel(application: Application) : AndroidViewModel(application) {
    private val repository = AccountRepository(application)
    private val settings = SettingsRepositoryImpl()
    private val initialSources = configuredSources()
    private val _uiState = MutableStateFlow(
        AccountUiState(
            sessions = repository.sessions.value,
            sources = initialSources,
            selectedBaseUrl = initialSources.preferred(repository.sessions.value),
            defaultUploadBaseUrl = resolveDefaultUploadBaseUrl(initialSources),
        ),
    )
    val uiState: StateFlow<AccountUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            repository.sessions.collect { sessions ->
                _uiState.update { state ->
                    val selected = state.selectedBaseUrl
                        .takeIf { baseUrl -> state.sources.any { it.baseUrl == baseUrl } }
                        ?: state.sources.preferred(sessions)
                    state.copy(
                        sessions = sessions,
                        selectedBaseUrl = selected,
                        defaultUploadBaseUrl = resolveDefaultUploadBaseUrl(state.sources),
                    )
                }
            }
        }
        refresh()
    }

    fun setRegisterMode(value: Boolean) {
        _uiState.update { it.copy(registerMode = value, error = null, message = null) }
    }

    fun clearNotice() {
        _uiState.update { it.copy(error = null, message = null) }
    }

    /** Switch the account page to another mirror source without touching other source sessions. */
    fun selectSource(baseUrl: String) {
        val source = _uiState.value.sources.firstOrNull { it.baseUrl == baseUrl } ?: return
        _uiState.update {
            it.copy(selectedBaseUrl = source.baseUrl, error = null, message = null)
        }
        refreshSelectedProfile()
    }

    /** Remember the selected source for future uploads; the default source is stored as blank. */
    fun setDefaultUploadSource(baseUrl: String) {
        val sources = _uiState.value.sources
        val normalized = ThemeStoreRepository.normalizeBaseUrl(baseUrl) ?: return
        if (sources.none { it.baseUrl == normalized }) return
        val defaultBase = sources.firstOrNull { it.isDefault }?.baseUrl
        settings.themeStoreUploadSource = if (normalized == defaultBase) "" else normalized
        _uiState.update {
            it.copy(defaultUploadBaseUrl = normalized)
        }
    }

    fun refresh() {
        repository.reload()
        val sources = configuredSources()
        _uiState.update { state ->
            val selected = state.selectedBaseUrl
                .takeIf { baseUrl -> sources.any { it.baseUrl == baseUrl } }
                ?: sources.preferred(repository.sessions.value)
            state.copy(
                sources = sources,
                sessions = repository.sessions.value,
                selectedBaseUrl = selected,
                defaultUploadBaseUrl = resolveDefaultUploadBaseUrl(sources),
            )
        }
        refreshSelectedProfile()
    }

    private fun refreshSelectedProfile() {
        val baseUrl = _uiState.value.selectedBaseUrl
        if (baseUrl.isBlank() || repository.sessionFor(baseUrl) == null) {
            _uiState.update { it.copy(loading = false) }
            return
        }
        _uiState.update { it.copy(loading = true) }
        viewModelScope.launch {
            val result = repository.refreshProfile(baseUrl)
            _uiState.update {
                if (it.selectedBaseUrl != baseUrl) {
                    it
                } else {
                    it.copy(
                        loading = false,
                        sessions = repository.sessions.value,
                        error = result.exceptionOrNull()?.message,
                    )
                }
            }
        }
    }

    fun login(baseUrl: String, login: String, password: String) {
        if (_uiState.value.submitting) return
        _uiState.update {
            it.copy(
                selectedBaseUrl = baseUrl,
                submitting = true,
                error = null,
                message = null,
            )
        }
        viewModelScope.launch {
            val result = repository.login(baseUrl, login, password)
            _uiState.update {
                it.copy(
                    submitting = false,
                    sessions = repository.sessions.value,
                    error = result.exceptionOrNull()?.message,
                    registerMode = false,
                )
            }
            if (result.isSuccess) refreshSelectedProfile()
        }
    }

    fun register(
        baseUrl: String,
        username: String,
        displayName: String,
        email: String,
        password: String,
    ) {
        if (_uiState.value.submitting) return
        _uiState.update {
            it.copy(
                selectedBaseUrl = baseUrl,
                submitting = true,
                error = null,
                message = null,
            )
        }
        viewModelScope.launch {
            repository.register(baseUrl, username, displayName, email, password)
                .onSuccess { response ->
                    _uiState.update {
                        it.copy(
                            submitting = false,
                            registerMode = false,
                            message = response.message ?: "验证邮件已发送",
                        )
                    }
                }
                .onFailure { error ->
                    _uiState.update { it.copy(submitting = false, error = error.message) }
                }
        }
    }

    fun logout() {
        val baseUrl = _uiState.value.selectedBaseUrl
        viewModelScope.launch {
            repository.logout(baseUrl)
            _uiState.update {
                it.copy(
                    sessions = repository.sessions.value,
                    message = null,
                    error = null,
                )
            }
        }
    }

    fun accountUrl(): String? = repository.accountUrl(_uiState.value.selectedBaseUrl)

    fun accountUrl(baseUrl: String): String? = repository.accountUrl(baseUrl)

    private fun configuredSources(): List<AccountSource> {
        val defaultBase = ThemeStoreRepository.normalizeBaseUrl(
            settings.themeStoreBaseUrl.ifBlank { ThemeStoreDefaults.BASE_URL },
        ) ?: return emptyList()
        val sources = mutableListOf(
            AccountSource(
                id = "default",
                name = "",
                baseUrl = defaultBase,
                isDefault = true,
            ),
        )
        settings.themeStoreExtraSources.forEach { config ->
            val base = ThemeStoreRepository.normalizeBaseUrl(config.baseUrl) ?: return@forEach
            sources += AccountSource(
                id = config.id.ifBlank { base },
                name = config.name,
                baseUrl = base,
                isDefault = false,
            )
        }
        return sources.distinctBy { it.baseUrl }
    }

    private fun resolveDefaultUploadBaseUrl(sources: List<AccountSource>): String {
        val configuredDefault = sources.firstOrNull { it.isDefault }?.baseUrl.orEmpty()
        val saved = settings.themeStoreUploadSource
        if (saved.isBlank()) return configuredDefault
        val normalized = ThemeStoreRepository.normalizeBaseUrl(saved) ?: return configuredDefault
        return normalized.takeIf { base -> sources.any { it.baseUrl == base } }
            ?: configuredDefault
    }

    private fun List<AccountSource>.preferred(
        sessions: Map<String, AccountSession>,
    ): String = firstOrNull { sessions.containsKey(it.baseUrl) }?.baseUrl
        ?: firstOrNull { it.isDefault }?.baseUrl
        ?: firstOrNull()?.baseUrl
        .orEmpty()
}
