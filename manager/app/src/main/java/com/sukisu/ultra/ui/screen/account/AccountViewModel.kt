package com.sukisu.ultra.ui.screen.account

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.data.model.AccountSession
import com.sukisu.ultra.data.repository.AccountRepository
import com.sukisu.ultra.data.repository.ThemeStoreDefaults
import com.sukisu.ultra.data.repository.SettingsRepositoryImpl
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class AccountUiState(
    val session: AccountSession? = null,
    val baseUrl: String = "",
    val loading: Boolean = false,
    val submitting: Boolean = false,
    val registerMode: Boolean = false,
    val error: String? = null,
    val message: String? = null,
)

class AccountViewModel(application: Application) : AndroidViewModel(application) {
    private val repository = AccountRepository(application)
    private val settings = SettingsRepositoryImpl()
    private val _uiState = MutableStateFlow(
        AccountUiState(
            session = repository.session.value,
            baseUrl = settings.themeStoreBaseUrl.ifBlank { ThemeStoreDefaults.BASE_URL },
        ),
    )
    val uiState: StateFlow<AccountUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            repository.session.collect { session ->
                _uiState.update { it.copy(session = session) }
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

    fun refresh() {
        repository.reload()
        val baseUrl = settings.themeStoreBaseUrl.ifBlank { ThemeStoreDefaults.BASE_URL }
        val session = repository.sessionFor(baseUrl)
        if (session == null) {
            _uiState.update { it.copy(baseUrl = baseUrl, session = null) }
            return
        }
        _uiState.update { it.copy(baseUrl = baseUrl, loading = true) }
        viewModelScope.launch {
            val result = repository.refreshProfile()
            val fallback = repository.session.value
            _uiState.update {
                it.copy(
                    loading = false,
                    session = result.getOrNull() ?: fallback,
                    error = result.exceptionOrNull()?.message,
                )
            }
        }
    }

    fun login(login: String, password: String) {
        if (_uiState.value.submitting) return
        val baseUrl = settings.themeStoreBaseUrl.ifBlank { ThemeStoreDefaults.BASE_URL }
        _uiState.update { it.copy(submitting = true, error = null, message = null) }
        viewModelScope.launch {
            val result = repository.login(baseUrl, login, password)
            _uiState.update {
                it.copy(
                    submitting = false,
                    session = result.getOrNull() ?: it.session,
                    error = result.exceptionOrNull()?.message,
                    registerMode = false,
                )
            }
            if (result.isSuccess) refresh()
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
        _uiState.update { it.copy(submitting = true, error = null, message = null) }
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
        viewModelScope.launch {
            repository.logout()
            _uiState.update { it.copy(session = null, message = null, error = null) }
        }
    }

    fun accountUrl(): String? =
        repository.accountUrl(settings.themeStoreBaseUrl.ifBlank { ThemeStoreDefaults.BASE_URL })
}
