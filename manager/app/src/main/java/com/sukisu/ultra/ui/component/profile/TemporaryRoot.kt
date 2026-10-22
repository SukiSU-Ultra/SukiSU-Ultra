package com.sukisu.ultra.ui.component.profile

import android.os.Process
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ui.LocalUiMode
import com.sukisu.ultra.ui.UiMode
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.util.getRootShell
import com.sukisu.ultra.ui.util.getKsuDaemonPath
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object TemporaryRoot {
    private const val PREFS = "temporary_root"
    private val profileJson = kotlinx.serialization.json.Json { encodeDefaults = true }
    fun defaultMinutes(context: android.content.Context) =
        context.getSharedPreferences(PREFS, 0).getInt("minutes", 10).coerceIn(1, 10080)

    fun setDefaultMinutes(context: android.content.Context, minutes: Int) {
        context.getSharedPreferences(PREFS, 0).edit().putInt("minutes", minutes).apply()
    }

    suspend fun status(uid: Int): String = withContext(Dispatchers.IO) {
        val result = getRootShell().newJob()
            .add("'${getKsuDaemonPath()}' temporary-root status $uid").exec()
        if (result.isSuccess) result.out.lastOrNull()?.trim() ?: "unknown" else "unknown"
    }

    /** ksud owns the lock across lease validation, persistence and kernel writes. */
    suspend fun saveProfile(
        profile: Natives.Profile,
        expectedRoot: Boolean,
        updateLease: Boolean,
        seconds: Long?,
    ): Boolean = withContext(Dispatchers.IO) {
        fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
        val mode = if (!updateLease) "keep" else seconds?.toString() ?: "permanent"
        val json = profileJson.encodeToString(Natives.Profile.serializer(), profile)
        getRootShell().newJob().add(
            "${quote(getKsuDaemonPath())} temporary-root apply ${Process.myUid()} " +
                "$mode $expectedRoot ${quote(json)}"
        ).exec().isSuccess
    }
}

@Composable
fun TemporaryRootPreferences() {
    val context = LocalContext.current
    var minutes by remember { mutableIntStateOf(TemporaryRoot.defaultMinutes(context)) }
    val durations = (listOf(5, 10, 30, 60) + minutes).distinct().sorted()
    var showCustom by rememberSaveable { mutableStateOf(false) }
    val labels = durations.map { stringResource(R.string.temporary_root_minutes, it) } +
        stringResource(R.string.temporary_root_custom_duration)
    val onSelect: (Int) -> Unit = { index ->
        if (index == durations.size) {
            showCustom = true
        } else {
            minutes = durations[index]
            TemporaryRoot.setDefaultMinutes(context, minutes)
        }
    }
    if (showCustom) {
        var input by rememberSaveable(stateSaver = TextFieldValue.Saver) {
            val text = minutes.toString()
            mutableStateOf(TextFieldValue(text, selection = TextRange(text.length)))
        }
        val valid = input.text.toIntOrNull()?.let { it in 1..10080 } == true
        val onInput: (TextFieldValue) -> Unit = { value ->
            // Keep selection-only and IME composition updates, not just text.
            if (value.text.length <= 5 && value.text.all { it in '0'..'9' }) input = value
        }
        val onConfirm: () -> Unit = {
            if (valid) {
                minutes = input.text.toInt()
                TemporaryRoot.setDefaultMinutes(context, minutes)
                showCustom = false
            }
        }
        when (LocalUiMode.current) {
            UiMode.Miuix -> TemporaryRootCustomDurationMiuix(input, valid, onInput, { showCustom = false }, onConfirm)
            UiMode.Material -> TemporaryRootCustomDurationMaterial(input, valid, onInput, { showCustom = false }, onConfirm)
        }
    }
    when (LocalUiMode.current) {
        UiMode.Miuix -> TemporaryRootPreferencesMiuix(labels, durations.indexOf(minutes), onSelect)
        UiMode.Material -> TemporaryRootPreferencesMaterial(labels, durations.indexOf(minutes), onSelect)
    }
}

internal data class RootGrantOption(val seconds: Long?, val label: String)

@Composable
internal fun temporaryRootOptions(includePermanent: Boolean): List<RootGrantOption> {
    val minutes = TemporaryRoot.defaultMinutes(LocalContext.current)
    return buildList {
        if (includePermanent) add(RootGrantOption(null, stringResource(R.string.temporary_root_permanent)))
        add(RootGrantOption(10L, stringResource(R.string.temporary_root_allow_seconds_test, 10)))
        add(RootGrantOption(600L, stringResource(R.string.temporary_root_allow_minutes, 10)))
        if (minutes != 10) add(RootGrantOption(minutes * 60L, stringResource(R.string.temporary_root_allow_minutes, minutes)))
        add(RootGrantOption(0L, stringResource(R.string.temporary_root_until_reboot)))
    }
}

@Composable
fun TemporaryRootControls(enabled: Boolean, granted: Boolean, onEnabledChange: (Boolean) -> Unit, onChoose: (Long?) -> Unit) {
    val options = temporaryRootOptions(includePermanent = false)
    when (LocalUiMode.current) {
        UiMode.Miuix -> TemporaryRootControlsMiuix(enabled, granted, options, onEnabledChange, onChoose)
        UiMode.Material -> TemporaryRootControlsMaterial(enabled, granted, options, onEnabledChange, onChoose)
    }
}

@Composable
fun TemporaryRootGrantDialog(onDismiss: () -> Unit, onChoose: (Long?) -> Unit) {
    val options = temporaryRootOptions(includePermanent = true)
    when (LocalUiMode.current) {
        UiMode.Miuix -> TemporaryRootGrantDialogMiuix(options, onDismiss, onChoose)
        UiMode.Material -> TemporaryRootGrantDialogMaterial(options, onDismiss, onChoose)
    }
}
