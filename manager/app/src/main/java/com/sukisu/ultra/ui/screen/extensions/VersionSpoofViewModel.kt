package com.sukisu.ultra.ui.screen.extensions

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.Natives
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.json.JSONObject

internal data class VersionSpoofState(
    val version: String = "",
    val full: String = "",
    val uapi: String = "",
    val originalVersion: String = "",
    val originalFull: String = "",
    val originalUapi: String = "",
    val busy: Boolean = true,
    val loaded: Boolean = false,
    val acknowledged: Boolean = false,
    val hideWarning: Boolean = false,
    val warningBusy: Boolean = false,
    val error: String? = null,
    val success: Boolean = false,
) {
    val valid: Boolean get() = validVersionNumber(version) && validVersionNumber(uapi) &&
        full.toByteArray(Charsets.UTF_8).size <= 254 && '\u0000' !in full
    val canSave: Boolean get() = loaded && !busy && !warningBusy && valid && acknowledged
}

internal fun validVersionNumber(value: String): Boolean = value.isEmpty() ||
    (value.all { it in '0'..'9' } && value.toULongOrNull()?.let { it <= 4_294_967_295UL } == true)

internal class VersionSpoofViewModel : ViewModel() {
    private val state = MutableStateFlow(VersionSpoofState())
    val uiState = state.asStateFlow()
    val managerVersion = BuildConfig.VERSION_CODE.toString()
    val managerUapi = Natives.managerUAPIVersion.toString()

    init { reload() }

    private suspend fun readCurrent() {
        val data = JSONObject(VersionSpoofRepository.command("get"))
        state.update { it.copy(
            version = data.getLong("version").toString(),
            full = data.getString("full"),
            uapi = data.getLong("uapi").toString(),
            originalVersion = data.getLong("defaultVersion").toString(),
            originalFull = data.getString("defaultFull"),
            originalUapi = data.getLong("defaultUapi").toString(),
            loaded = true,
        ) }
    }

    fun reload() {
        viewModelScope.launch {
            state.update { it.copy(busy = true, error = null) }
            try {
                val hidden = VersionSpoofRepository.isWarningHidden()
                state.update { it.copy(hideWarning = hidden) }
                readCurrent()
            } catch (e: CancellationException) { throw e
            } catch (e: Exception) { state.update { it.copy(error = e.localizedMessage) }
            } finally { state.update { it.copy(busy = false) } }
        }
    }

    fun editVersion(value: String) { state.update { it.copy(version = value, success = false) } }
    fun editFull(value: String) { state.update { it.copy(full = value, success = false) } }
    fun editUapi(value: String) { state.update { it.copy(uapi = value, success = false) } }
    fun acknowledge(value: Boolean) { state.update { it.copy(acknowledged = value) } }

    fun apply(reset: Boolean = false) {
        val snapshot = state.value
        if (snapshot.busy || snapshot.warningBusy || (!reset && !snapshot.canSave)) return
        state.update { it.copy(busy = true, error = null, success = false) }
        viewModelScope.launch {
            try {
                val args = if (reset) "reset" else buildString {
                    append("set --acknowledge-compatibility")
                    if (snapshot.version.isNotEmpty()) append(" --version ${VersionSpoofRepository.quote(snapshot.version)}")
                    if (snapshot.uapi.isNotEmpty()) append(" --uapi ${VersionSpoofRepository.quote(snapshot.uapi)}")
                    if (snapshot.full.isNotEmpty() && snapshot.full != snapshot.originalFull)
                        append(" --full=${VersionSpoofRepository.quote(snapshot.full)}")
                }
                VersionSpoofRepository.command(args)
                readCurrent()
                state.update { it.copy(success = true) }
            } catch (e: CancellationException) { throw e
            } catch (e: Exception) { state.update { it.copy(error = e.localizedMessage) }
            } finally { state.update { it.copy(busy = false) } }
        }
    }

    fun hideWarning(hidden: Boolean) {
        if (state.value.warningBusy || state.value.busy) return
        state.update { it.copy(warningBusy = true, error = null) }
        viewModelScope.launch {
            try {
                VersionSpoofRepository.setWarningHidden(hidden)
                state.update { it.copy(hideWarning = hidden) }
            } catch (e: CancellationException) { throw e
            } catch (e: Exception) { state.update { it.copy(error = e.localizedMessage) }
            } finally { state.update { it.copy(warningBusy = false) } }
        }
    }
}
