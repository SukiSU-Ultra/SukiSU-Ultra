package com.sukisu.ultra.ui.screen.account

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.R
import com.sukisu.ultra.data.model.AccountSession
import com.sukisu.ultra.data.repository.AccountRepository
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import com.sukisu.ultra.data.repository.ThemeStoreDefaults
import com.sukisu.ultra.data.repository.ThemeStoreRepository
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

data class AccountSource(
    val id: String,
    val name: String,
    val baseUrl: String,
    val isDefault: Boolean,
)

data class AccountDeviceLogin(
    val deviceCode: String,
    val userCode: String,
    val verifyUrl: String,
    val expiresIn: Long,
    val interval: Long,
    val status: String = "pending",
    val error: String? = null,
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
    val mailConfigured: Boolean? = null,
    val forgotPasswordOpen: Boolean = false,
    val forgotPasswordSending: Boolean = false,
    val forgotPasswordMessage: String? = null,
    val forgotPasswordError: String? = null,
    val deviceLogin: AccountDeviceLogin? = null,
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
            sessions = aliasedSessions(),
            sources = initialSources,
            selectedBaseUrl = initialSources.preferred(aliasedSessions()),
            defaultUploadBaseUrl = resolveDefaultUploadBaseUrl(initialSources),
        ),
    )
    val uiState: StateFlow<AccountUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            repository.sessions.collect {
                val aliased = aliasedSessions()
                _uiState.update { state ->
                    val selected = state.selectedBaseUrl
                        .takeIf { baseUrl -> state.sources.any { it.baseUrl == baseUrl } }
                        ?: state.sources.preferred(aliased)
                    state.copy(
                        sessions = aliased,
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

    fun openForgotPassword() {
        _uiState.update {
            it.copy(
                forgotPasswordOpen = true,
                forgotPasswordMessage = null,
                forgotPasswordError = null,
            )
        }
    }

    fun dismissForgotPassword() {
        _uiState.update {
            it.copy(
                forgotPasswordOpen = false,
                forgotPasswordSending = false,
                forgotPasswordMessage = null,
                forgotPasswordError = null,
            )
        }
    }

    fun sendPasswordReset(login: String) {
        val normalized = login.trim()
        if (normalized.isEmpty() || _uiState.value.forgotPasswordSending) return
        val baseUrl = _uiState.value.selectedBaseUrl
        _uiState.update {
            it.copy(
                forgotPasswordSending = true,
                forgotPasswordMessage = null,
                forgotPasswordError = null,
            )
        }
        viewModelScope.launch {
            repository.forgotPassword(baseUrl, normalized)
                .onSuccess { response ->
                    _uiState.update {
                        it.copy(
                            forgotPasswordSending = false,
                            forgotPasswordMessage = response.message
                                ?: getApplication<Application>().getString(R.string.account_forgot_sent),
                        )
                    }
                }
                .onFailure { error ->
                    _uiState.update {
                        it.copy(
                            forgotPasswordSending = false,
                            forgotPasswordError = error.message,
                        )
                    }
                }
        }
    }

    fun startDeviceLogin() {
        if (_uiState.value.deviceLogin != null) return
        val baseUrl = _uiState.value.selectedBaseUrl
        _uiState.update { it.copy(error = null, message = null) }
        viewModelScope.launch {
            repository.startDeviceLogin(baseUrl)
                .onSuccess { response ->
                    val login = AccountDeviceLogin(
                        deviceCode = response.deviceCode,
                        userCode = response.userCode,
                        verifyUrl = response.verifyUrl,
                        expiresIn = response.expiresIn.coerceAtLeast(60),
                        interval = response.interval.coerceIn(1, 10),
                    )
                    _uiState.update { it.copy(deviceLogin = login) }
                    pollDeviceLogin(baseUrl, login)
                }
                .onFailure { error ->
                    _uiState.update { it.copy(error = error.message) }
                }
        }
    }

    private var devicePollJob: Job? = null

    private fun pollDeviceLogin(baseUrl: String, login: AccountDeviceLogin) {
        devicePollJob?.cancel()
        devicePollJob = viewModelScope.launch {
            val deadline = System.currentTimeMillis() + login.expiresIn * 1000
            while (isActive && System.currentTimeMillis() < deadline) {
                delay(login.interval * 1000)
                val parsed = repository.pollDeviceLogin(baseUrl, login.deviceCode).getOrNull()
                if (parsed == null) {
                    // Keep the code usable; transient network errors are retried until expiry.
                    continue
                }
                when (parsed.status) {
                    "approved" -> {
                        _uiState.update { it.copy(deviceLogin = null) }
                        refreshSelectedProfile()
                        return@launch
                    }
                    "expired", "consumed" -> {
                        _uiState.update { state ->
                            state.copy(deviceLogin = state.deviceLogin?.copy(status = parsed.status))
                        }
                        return@launch
                    }
                    "pending" -> Unit
                }
            }
            _uiState.update { state ->
                state.copy(deviceLogin = state.deviceLogin?.copy(status = "expired"))
            }
        }
    }

    fun cancelDeviceLogin() {
        devicePollJob?.cancel()
        devicePollJob = null
        _uiState.update { it.copy(deviceLogin = null) }
    }

    private fun refreshConfig(baseUrl: String) {
        if (baseUrl.isBlank()) return
        viewModelScope.launch {
            repository.config(baseUrl).getOrNull()?.let { config ->
                if (_uiState.value.selectedBaseUrl == baseUrl) {
                    _uiState.update { it.copy(mailConfigured = config.email) }
                }
            }
        }
    }

    
    fun selectSource(baseUrl: String) {
        val source = _uiState.value.sources.firstOrNull { it.baseUrl == baseUrl } ?: return
        _uiState.update {
            it.copy(selectedBaseUrl = source.baseUrl, error = null, message = null)
        }
        refreshSelectedProfile()
    }

    
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
        val sessions = aliasedSessions()
        val sources = configuredSources()
        _uiState.update { state ->
            val selected = state.selectedBaseUrl
                .takeIf { baseUrl -> sources.any { it.baseUrl == baseUrl } }
                ?: sources.preferred(sessions)
            state.copy(
                sources = sources,
                sessions = sessions,
                selectedBaseUrl = selected,
                defaultUploadBaseUrl = resolveDefaultUploadBaseUrl(sources),
            )
        }
        refreshSelectedProfile()
    }

    /**
     * Built-in mirrors share one account; expose a session for every mirror so
     * auto-selecting a different one does not make the UI look signed out.
     */
    private fun aliasedSessions(): Map<String, AccountSession> {
        val sessions = repository.sessions.value
        if (sessions.isEmpty()) return sessions
        val builtIns = ThemeStoreDefaults.BASE_URLS.mapNotNull {
            ThemeStoreRepository.normalizeBaseUrl(it)
        }
        val fallback = builtIns.firstNotNullOfOrNull { sessions[it] } ?: return sessions
        val result = sessions.toMutableMap()
        builtIns.forEach { base ->
            if (base !in result) {
                result[base] = fallback.copy(baseUrl = base)
            }
        }
        return result
    }

    private fun refreshSelectedProfile() {
        val baseUrl = _uiState.value.selectedBaseUrl
        refreshConfig(baseUrl)
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
                            message = response.message ?: getApplication<Application>()
                                .getString(R.string.account_register_verification_sent),
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
            ThemeStoreDefaults.resolveConfiguredBaseUrl(settings.themeStoreBaseUrl),
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
