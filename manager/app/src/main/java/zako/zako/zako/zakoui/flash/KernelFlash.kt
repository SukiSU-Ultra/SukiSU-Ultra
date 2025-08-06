package zako.zako.zako.zakoui.flash

import android.app.Activity
import android.content.Context
import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.documentfile.provider.DocumentFile
import com.sukisu.ultra.R
import com.sukisu.ultra.utils.AssetsUtil
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.io.File
import java.io.FileOutputStream
import java.io.IOException


/**
 * @author ShirkNeko
 * @date 2025/5/31.
 */
data class FlashState(
    val isFlashing: Boolean = false,
    val isCompleted: Boolean = false,
    val progress: Float = 0f,
    val currentStep: String = "",
    val logs: List<String> = emptyList(),
    val error: String = ""
)

class HorizonKernelState {
    private val _state = MutableStateFlow(FlashState())
    val state: StateFlow<FlashState> = _state.asStateFlow()

    fun updateProgress(progress: Float) {
        _state.update { it.copy(progress = progress) }
    }

    fun updateStep(step: String) {
        _state.update { it.copy(currentStep = step) }
    }

    fun addLog(log: String) {
        _state.update {
            it.copy(logs = it.logs + log)
        }
    }

    fun setError(error: String) {
        _state.update { it.copy(error = error) }
    }

    fun startFlashing() {
        _state.update {
            it.copy(
                isFlashing = true,
                isCompleted = false,
                progress = 0f,
                currentStep = "under preparation...",
                logs = emptyList(),
                error = ""
            )
        }
    }

    fun completeFlashing() {
        _state.update { it.copy(isCompleted = true, progress = 1f) }
    }

    fun reset() {
        _state.value = FlashState()
    }
}

class HorizonKernelWorker(
    private val context: Context,
    private val state: HorizonKernelState,
    private val slot: String? = null
) : Thread() {
    var uri: Uri? = null
    private lateinit var filePath: String
    private lateinit var binaryPath: String

    private var onFlashComplete: (() -> Unit)? = null
    private var originalSlot: String? = null

    fun setOnFlashCompleteListener(listener: () -> Unit) {
        onFlashComplete = listener
    }

    override fun run() {
        state.startFlashing()
        state.updateStep(context.getString(R.string.horizon_preparing))

        filePath = "${context.filesDir.absolutePath}/${DocumentFile.fromSingleUri(context, uri!!)?.name}"
        binaryPath = "${context.filesDir.absolutePath}/META-INF/com/google/android/update-binary"

        try {
            state.updateStep(context.getString(R.string.horizon_cleaning_files))
            state.updateProgress(0.1f)
            cleanup()

            if (!rootAvailable()) {
                state.setError(context.getString(R.string.root_required))
                return
            }

            state.updateStep(context.getString(R.string.horizon_copying_files))
            state.updateProgress(0.2f)
            copy()

            if (!File(filePath).exists()) {
                state.setError(context.getString(R.string.horizon_copy_failed))
                return
            }

            state.updateStep(context.getString(R.string.horizon_extracting_tool))
            state.updateProgress(0.4f)
            getBinary()

            state.updateStep(context.getString(R.string.horizon_patching_script))
            state.updateProgress(0.6f)
            patch()

            state.updateStep(context.getString(R.string.horizon_flashing))
            state.updateProgress(0.7f)

            val isAbDevice = isAbDevice()

            if (isAbDevice && slot != null) {
                state.updateStep(context.getString(R.string.horizon_getting_original_slot))
                state.updateProgress(0.72f)
                originalSlot = runCommandGetOutput(true, "getprop ro.boot.slot_suffix")

                state.updateStep(context.getString(R.string.horizon_setting_target_slot))
                state.updateProgress(0.74f)
                runCommand(true, "resetprop -n ro.boot.slot_suffix _$slot")
            }

            flash()

            if (isAbDevice && !originalSlot.isNullOrEmpty()) {
                state.updateStep(context.getString(R.string.horizon_restoring_original_slot))
                state.updateProgress(0.8f)
                runCommand(true, "resetprop ro.boot.slot_suffix $originalSlot")
            }

            state.updateStep(context.getString(R.string.horizon_flash_complete_status))
            state.completeFlashing()

            (context as? Activity)?.runOnUiThread {
                onFlashComplete?.invoke()
            }
        } catch (e: Exception) {
            state.setError(e.message ?: context.getString(R.string.horizon_unknown_error))

            if (isAbDevice() && !originalSlot.isNullOrEmpty()) {
                state.updateStep(context.getString(R.string.horizon_restoring_original_slot))
                state.updateProgress(0.8f)
                runCommand(true, "resetprop ro.boot.slot_suffix $originalSlot")
            }
        }
    }

    // 检查设备是否为AB分区设备
    private fun isAbDevice(): Boolean {
        val abUpdate = runCommandGetOutput(true, "getprop ro.build.ab_update")?.trim() ?: ""
        if (abUpdate.equals("false", ignoreCase = true) || abUpdate.isEmpty()) {
            return false
        }

        val slotSuffix = runCommandGetOutput(true, "getprop ro.boot.slot_suffix")
        return !slotSuffix.isNullOrEmpty()
    }

    private fun cleanup() {
        runCommand(false, "find ${context.filesDir.absolutePath} -type f ! -name '*.jpg' ! -name '*.png' -delete")
    }

    private fun copy() {
        uri?.let { safeUri ->
            context.contentResolver.openInputStream(safeUri)?.use { input ->
                FileOutputStream(File(filePath)).use { output ->
                    input.copyTo(output)
                }
            }
        }
    }

    private fun getBinary() {
        runCommand(false, "unzip \"$filePath\" \"*/update-binary\" -d ${context.filesDir.absolutePath}")
        if (!File(binaryPath).exists()) {
            throw IOException("Failed to extract update-binary")
        }
    }

    private fun patch() {
        val kernelVersion = runCommandGetOutput(true, "cat /proc/version")
        val versionRegex = """\d+\.\d+\.\d+""".toRegex()
        val version = kernelVersion?.let { versionRegex.find(it) }?.value ?: ""
        val toolName = if (version.isNotEmpty()) {
            val parts = version.split('.')
            if (parts.size >= 2) {
                val major = parts[0].toIntOrNull() ?: 0
                val minor = parts[1].toIntOrNull() ?: 0
                if (major < 5 || (major == 5 && minor <= 10)) "5_10" else "5_15+"
            } else {
                "5_15+"
            }
        } else {
            "5_15+"
        }
        val toolPath = "${context.filesDir.absolutePath}/mkbootfs"
        AssetsUtil.exportFiles(context, "$toolName-mkbootfs", toolPath)
        state.addLog("${context.getString(R.string.kernel_version_log, version)} ${context.getString(R.string.tool_version_log, toolName)}")
        runCommand(false, "sed -i '/chmod -R 755 tools bin;/i cp -f $toolPath \$AKHOME/tools;' $binaryPath")
    }

    private fun flash() {
        val process = ProcessBuilder("su")
            .redirectErrorStream(true)
            .start()

        try {
            process.outputStream.bufferedWriter().use { writer ->
                writer.write("export POSTINSTALL=${context.filesDir.absolutePath}\n")

                // 写入槽位信息到临时文件
                slot?.let { selectedSlot ->
                    writer.write("echo \"$selectedSlot\" > ${context.filesDir.absolutePath}/bootslot\n")
                }

                // 构建刷写命令
                val flashCommand = buildString {
                    append("sh $binaryPath 3 1 \"$filePath\"")
                    if (slot != null) {
                        append(" \"$(cat ${context.filesDir.absolutePath}/bootslot)\"")
                    }
                    append(" && touch ${context.filesDir.absolutePath}/done\n")
                }

                writer.write(flashCommand)
                writer.write("exit\n")
                writer.flush()
            }

            process.inputStream.bufferedReader().use { reader ->
                reader.lineSequence().forEach { line ->
                    if (line.startsWith("ui_print")) {
                        val logMessage = line.removePrefix("ui_print").trim()
                        state.addLog(logMessage)

                        when {
                            logMessage.contains("extracting", ignoreCase = true) -> {
                                state.updateProgress(0.75f)
                            }
                            logMessage.contains("installing", ignoreCase = true) -> {
                                state.updateProgress(0.85f)
                            }
                            logMessage.contains("complete", ignoreCase = true) -> {
                                state.updateProgress(0.95f)
                            }
                        }
                    }
                }
            }
        } finally {
            process.destroy()
        }

        if (!File("${context.filesDir.absolutePath}/done").exists()) {
            throw IOException(context.getString(R.string.flash_failed_message))
        }
    }

    private fun runCommand(su: Boolean, cmd: String): Int {
        val shell = if (su) "su" else "sh"
        val process = Runtime.getRuntime().exec(arrayOf(shell, "-c", cmd))

        return try {
            process.waitFor()
        } finally {
            process.destroy()
        }
    }

    private fun runCommandGetOutput(su: Boolean, cmd: String): String? {
        val shell = if (su) "su" else "sh"
        val process = Runtime.getRuntime().exec(arrayOf(shell, "-c", cmd))

        return try {
            process.inputStream.bufferedReader().use { reader ->
                reader.readText().trim()
            }
        } catch (_: Exception) {
            ""
        } finally {
            process.destroy()
        }
    }

    private fun rootAvailable(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("su -c true")
            val exitValue = process.waitFor()
            exitValue == 0
        } catch (_: Exception) {
            false
        }
    }
}

@Composable
fun HorizonKernelFlashProgress(state: FlashState) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = stringResource(id = R.string.horizon_flash_title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(bottom = 8.dp)
            )

            LinearProgressIndicator(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 8.dp),
                progress = { state.progress },
            )

            Text(
                text = state.currentStep,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(vertical = 4.dp)
            )

            if (state.logs.isNotEmpty()) {
                Text(
                    text = stringResource(id = R.string.horizon_logs_label),
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier
                        .align(Alignment.Start)
                        .padding(top = 8.dp, bottom = 4.dp)
                )

                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 230.dp)
                        .padding(vertical = 4.dp),
                    color = MaterialTheme.colorScheme.surface,
                    tonalElevation = 1.dp,
                    shape = MaterialTheme.shapes.small
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(8.dp)
                            .verticalScroll(rememberScrollState())
                    ) {
                        state.logs.forEach { log ->
                            Text(
                                text = log,
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.padding(vertical = 2.dp),
                                overflow = TextOverflow.Ellipsis,
                                maxLines = 1
                            )
                        }
                    }
                }
            }

            if (state.error.isNotEmpty()) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.Error,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(end = 8.dp)
                    )
                    Text(
                        text = state.error,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            } else if (state.isCompleted) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Default.CheckCircle,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(end = 8.dp)
                    )
                    Text(
                        text = stringResource(id = R.string.horizon_flash_complete),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }
        }
    }
}