package zako.zako.zako.zakoui.flash

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import com.sukisu.ultra.R
import com.sukisu.ultra.network.RemoteToolsDownloader
import com.sukisu.ultra.ui.util.rootAvailable
import com.sukisu.ultra.utils.AssetsUtil
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream


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
    private val slot: String? = null,
    private val kpmPatchEnabled: Boolean = false,
    private val kpmUndoPatch: Boolean = false
) : Thread() {
    var uri: Uri? = null
    private lateinit var filePath: String
    private lateinit var binaryPath: String
    private lateinit var workDir: String

    private var onFlashComplete: (() -> Unit)? = null
    private var originalSlot: String? = null
    private var downloaderJob: Job? = null

    fun setOnFlashCompleteListener(listener: () -> Unit) {
        onFlashComplete = listener
    }

    override fun run() {
        state.startFlashing()
        state.updateStep(context.getString(R.string.horizon_preparing))

        filePath = "${context.filesDir.absolutePath}/${DocumentFile.fromSingleUri(context, uri!!)?.name}"
        binaryPath = "${context.filesDir.absolutePath}/META-INF/com/google/android/update-binary"
        workDir = "${context.filesDir.absolutePath}/work"

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

            // KPM修补
            if (kpmPatchEnabled || kpmUndoPatch) {
                state.updateStep(context.getString(R.string.kpm_preparing_tools))
                state.updateProgress(0.5f)
                prepareKpmToolsWithDownload()

                state.updateStep(
                    if (kpmUndoPatch) context.getString(R.string.kpm_undoing_patch)
                    else context.getString(R.string.kpm_applying_patch)
                )
                state.updateProgress(0.55f)
                performKpmPatch()
            }

            state.updateStep(context.getString(R.string.horizon_patching_script))
            state.updateProgress(0.6f)
            patch()

            state.updateStep(context.getString(R.string.horizon_flashing))
            state.updateProgress(0.7f)

            val isAbDevice = isAbDevice()

            if (isAbDevice && slot != null) {
                state.updateStep(context.getString(R.string.horizon_getting_original_slot))
                state.updateProgress(0.72f)
                originalSlot = runCommandGetOutput("getprop ro.boot.slot_suffix")

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
        } finally {
            // 取消下载任务并清理
            downloaderJob?.cancel()
            cleanupDownloader()
        }
    }

    private fun prepareKpmToolsWithDownload() {
        try {
            File(workDir).mkdirs()
            val downloader = RemoteToolsDownloader(context, workDir)

            val progressListener = object : RemoteToolsDownloader.DownloadProgressListener {
                override fun onProgress(fileName: String, progress: Int, total: Int) {
                    val percentage = if (total > 0) (progress * 100) / total else 0
                    state.addLog("Downloading $fileName: $percentage% ($progress/$total bytes)")
                }

                override fun onLog(message: String) {
                    state.addLog(message)
                }

                override fun onError(fileName: String, error: String) {
                    state.addLog("Warning: $fileName - $error")
                }

                override fun onSuccess(fileName: String, isRemote: Boolean) {
                    val source = if (isRemote) "remote" else "local"
                    state.addLog("✓ $fileName $source version prepared successfully")
                }
            }

            val downloadJob = CoroutineScope(Dispatchers.IO).launch {
                downloader.downloadToolsAsync(progressListener)
            }

            downloaderJob = downloadJob

            runBlocking {
                downloadJob.join()
            }

            val kptoolsPath = "$workDir/kptools"
            val kpimgPath = "$workDir/kpimg"

            if (!File(kptoolsPath).exists()) {
                throw IOException("kptools file preparation failed")
            }

            if (!File(kpimgPath).exists()) {
                throw IOException("kpimg file preparation failed")
            }

            runCommand(true, "chmod a+rx $kptoolsPath")
            state.addLog("KPM tools preparation completed, starting patch operation")

        } catch (_: CancellationException) {
            state.addLog("KPM tools download cancelled")
            throw IOException("Tool preparation process interrupted")
        } catch (e: Exception) {
            state.addLog("KPM tools preparation failed: ${e.message}")

            state.addLog("Attempting to use legacy local file extraction...")
            try {
                prepareKpmToolsLegacy()
                state.addLog("Successfully used local backup files")
            } catch (legacyException: Exception) {
                state.addLog("Local file extraction also failed: ${legacyException.message}")
                throw IOException("Unable to prepare KPM tool files: ${e.message}")
            }
        }
    }

    private fun prepareKpmToolsLegacy() {
        File(workDir).mkdirs()

        val kptoolsPath = "$workDir/kptools"
        val kpimgPath = "$workDir/kpimg"

        AssetsUtil.exportFiles(context, "kptools", kptoolsPath)
        if (!File(kptoolsPath).exists()) {
            throw IOException("Local kptools file extraction failed")
        }

        AssetsUtil.exportFiles(context, "kpimg", kpimgPath)
        if (!File(kpimgPath).exists()) {
            throw IOException("Local kpimg file extraction failed")
        }

        runCommand(true, "chmod a+rx $kptoolsPath")
    }

    private fun cleanupDownloader() {
        try {
            val downloader = RemoteToolsDownloader(context, workDir)
            downloader.cleanup()
        } catch (_: Exception) {
        }
    }

    /**
     * 执行KPM修补操作
     */
    private fun performKpmPatch() {
        try {
            // 创建临时解压目录
            val extractDir = "$workDir/extracted"
            File(extractDir).mkdirs()

            // 解压压缩包到临时目录
            val unzipResult = runCommand(true, "cd $extractDir && unzip -o \"$filePath\"")
            if (unzipResult != 0) {
                throw IOException(context.getString(R.string.kpm_extract_zip_failed))
            }

            // 查找Image文件
            val findImageResult = runCommandGetOutput("find $extractDir -name '*Image*' -type f")
            if (findImageResult.isBlank()) {
                throw IOException(context.getString(R.string.kpm_image_file_not_found))
            }

            val imageFile = findImageResult.lines().first().trim()
            val imageDir = File(imageFile).parent

            state.addLog(context.getString(R.string.kpm_found_image_file, imageFile))

            // 复制KPM工具到Image文件所在目录
            runCommand(true, "cp $workDir/kptools $imageDir/")
            runCommand(true, "cp $workDir/kpimg $imageDir/")

            // 执行KPM修补命令
            val patchCommand = if (kpmUndoPatch) {
                "cd $imageDir && chmod a+rx kptools && ./kptools -u -s 123 -i Image -k kpimg -o oImage && mv oImage Image"
            } else {
                "cd $imageDir && chmod a+rx kptools && ./kptools -p -s 123 -i Image -k kpimg -o oImage && mv oImage Image"
            }

            val patchResult = runCommand(true, patchCommand)
            if (patchResult != 0) {
                throw IOException(
                    if (kpmUndoPatch) context.getString(R.string.kpm_undo_patch_failed)
                    else context.getString(R.string.kpm_patch_failed)
                )
            }

            state.addLog(
                if (kpmUndoPatch) context.getString(R.string.kpm_undo_patch_success)
                else context.getString(R.string.kpm_patch_success)
            )

            // 清理KPM工具文件
            runCommand(true, "rm -f $imageDir/kptools $imageDir/kpimg $imageDir/oImage")

            // 重新打包ZIP文件
            val originalFileName = File(filePath).name
            val patchedFilePath = "$workDir/patched_$originalFileName"

            repackZipFolder(extractDir, patchedFilePath)

            // 替换原始文件
            runCommand(true, "mv \"$patchedFilePath\" \"$filePath\"")

            state.addLog(context.getString(R.string.kpm_file_repacked))

        } catch (e: Exception) {
            state.addLog(context.getString(R.string.kpm_patch_operation_failed, e.message))
            throw e
        } finally {
            // 清理临时文件
            runCommand(true, "rm -rf $workDir")
        }
    }

    private fun repackZipFolder(sourceDir: String, zipFilePath: String) {
        try {
            val buffer = ByteArray(1024)
            val sourceFolder = File(sourceDir)

            FileOutputStream(zipFilePath).use { fos ->
                ZipOutputStream(fos).use { zos ->
                    sourceFolder.walkTopDown().forEach { file ->
                        if (file.isFile) {
                            val relativePath = file.relativeTo(sourceFolder).path
                            val zipEntry = ZipEntry(relativePath)
                            zos.putNextEntry(zipEntry)

                            file.inputStream().use { fis ->
                                var length: Int
                                while (fis.read(buffer).also { length = it } > 0) {
                                    zos.write(buffer, 0, length)
                                }
                            }

                            zos.closeEntry()
                        }
                    }
                }
            }
        } catch (e: Exception) {
            throw IOException("Failed to create zip file: ${e.message}", e)
        }
    }

    // 检查设备是否为AB分区设备
    private fun isAbDevice(): Boolean {
        val abUpdate = runCommandGetOutput("getprop ro.build.ab_update")
        if (!abUpdate.toBoolean()) return false

        val slotSuffix = runCommandGetOutput("getprop ro.boot.slot_suffix")
        return slotSuffix.isNotEmpty()
    }

    private fun cleanup() {
        runCommand(false, "find ${context.filesDir.absolutePath} -type f ! -name '*.jpg' ! -name '*.png' -delete")
        runCommand(false, "rm -rf $workDir")
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

    @SuppressLint("StringFormatInvalid")
    private fun patch() {
        val kernelVersion = runCommandGetOutput("cat /proc/version")
        val versionRegex = """\d+\.\d+\.\d+""".toRegex()
        val version = kernelVersion.let { versionRegex.find(it) }?.value ?: ""
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

    private fun runCommandGetOutput(cmd: String): String {
        return Shell.cmd(cmd).exec().out.joinToString("\n").trim()
    }
}