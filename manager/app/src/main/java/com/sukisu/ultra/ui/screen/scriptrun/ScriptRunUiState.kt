package com.sukisu.ultra.ui.screen.scriptrun

import android.net.Uri
import android.os.Parcelable
import androidx.compose.runtime.Immutable
import kotlinx.parcelize.Parcelize
import com.sukisu.ultra.data.script.ParamError
import com.sukisu.ultra.data.script.PreparedScript
import com.sukisu.ultra.data.script.ScriptRunRecord


@Parcelize
data class ScriptRunArg(
    val uri: Uri,
    
    val registryId: String? = null,
    
    val offerInstall: Boolean = false,
    
    val displayName: String? = null,
) : Parcelable

enum class ScriptRunPhase {
    PREPARING,
    FAILED,
    READY,
    RUNNING,
    FINISHED,
}

@Immutable
data class ScriptRunUiState(
    val phase: ScriptRunPhase = ScriptRunPhase.PREPARING,
    val displayName: String? = null,
    val offerInstall: Boolean = false,
    val prepared: PreparedScript? = null,
    
    val error: String? = null,
    
    val values: Map<String, String> = emptyMap(),
    val errors: Map<String, ParamError> = emptyMap(),
    val lastRun: ScriptRunRecord? = null,
    val output: String = "",
    val exitCode: Int? = null,
) {
    val canRun: Boolean get() = phase == ScriptRunPhase.READY && errors.isEmpty()
}

@Immutable
data class ScriptRunActions(
    val onBack: () -> Unit,
    val onValueChange: (key: String, value: String) -> Unit,
    val onRun: () -> Unit,
    val onInstallAsModule: () -> Unit,
)
