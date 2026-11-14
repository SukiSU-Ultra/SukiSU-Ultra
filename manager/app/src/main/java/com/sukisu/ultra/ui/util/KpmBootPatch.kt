package com.sukisu.ultra.ui.util

import android.net.Uri
import android.os.Environment
import com.sukisu.ultra.getKernelVersion
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.kernelFlash.util.KpmTools
import com.topjohnwu.superuser.CallbackList
import java.io.File
import java.nio.file.Files


fun patchKpmBoot(
    uri: Uri?,
    onStdout: (String) -> Unit,
    onStderr: (String) -> Unit,
    outputFile: File? = null,
    undo: Boolean = false,
): FlashResult {
    fun q(value: String) = "'${value.replace("'", "'\\''")}'"
    fun command(cmd: String) {
        val out = object : CallbackList<String?>() {
            override fun onAddElement(s: String?) { s?.let(onStdout) }
        }
        val err = object : CallbackList<String?>() {
            override fun onAddElement(s: String?) { s?.let(onStderr) }
        }
        val result = withNewRootShell { newJob().add(cmd).to(out, err).exec() }
        check(result.isSuccess) { "Command failed (${result.code}): $cmd" }
    }
    fun read(cmd: String): String = withNewRootShell {
        val stdout = ArrayList<String>()
        val stderr = ArrayList<String>()
        val result = newJob().add(cmd).to(stdout, stderr).exec()
        if (!result.isSuccess) {
            val details = stderr.joinToString("\n").ifBlank { stdout.joinToString("\n") }
            error(
                "Cannot read boot partition information " +
                    "(exit ${result.code}, command: $cmd)" +
                    if (details.isNotBlank()) ": $details" else ""
            )
        }
        stdout.joinToString("\n").trim()
    }
    var backup: File? = null
    var writing = false
    var work: File? = null
    try {
        work = Files.createTempDirectory(ksuApp.cacheDir.toPath(), "kpm-boot-").toFile()
        val source = File(work, "boot.img")
        var target: String? = null
        var suffix: String? = null
        if (uri != null) {
            val input = ksuApp.contentResolver.openInputStream(uri) ?: error("Cannot open boot.img")
            input.use { stream -> source.outputStream().use { stream.copyTo(it) } }
        } else {
            check(rootAvailable()) { "Root is required to read and flash boot" }
            suffix = read("getprop ro.boot.slot_suffix")
            check(suffix in listOf("", "_a", "_b")) { "Invalid boot slot" }
            val abProperty = read("getprop ro.build.ab_update")
            val ab = abProperty == "true" || abProperty == "1"
            check(!ab || suffix.isNotEmpty()) { "Cannot determine active slot; refusing to flash" }
            val name = "boot$suffix"
            // Do not use `exit` in a libsu job: it terminates the managed shell
            // before libsu can collect the command's exit status.
            target = read(
                "boot_device=''; for p in /dev/block/by-name/$name /dev/block/bootdevice/by-name/$name; do " +
                    "if [ -b \"\$p\" ]; then boot_device=\$(readlink -f \"\$p\") && break; fi; done; " +
                    "[ -n \"\$boot_device\" ] && [ -b \"\$boot_device\" ] && printf '%s\\n' \"\$boot_device\""
            )
            check(target.startsWith("/dev/block/") && !target.contains('\n')) { "Invalid boot device" }
            onStdout("- Reading $name ($target)")
            // The app owns the file even when root writes its contents.
            source.createNewFile()
            command("cat ${q(target)} > ${q(source.absolutePath)}")
        }
        val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        check(downloads.exists() || downloads.mkdirs()) { "Cannot create Downloads directory" }
        val id = System.currentTimeMillis()
        if (target != null) {
            backup = File(downloads, "SukiSU_boot${suffix}_backup_$id.img")
            source.copyTo(backup)
            check(backup.length() == source.length() && backup.length() > 0) { "Boot backup failed" }
            command("cmp -s ${q(source.absolutePath)} ${q(backup.absolutePath)}")
            java.io.RandomAccessFile(backup, "rw").use { it.fd.sync() }
            onStdout("- Backup: ${backup.absolutePath}")
        }
        // These paths are explicit, not names guessed from an unpack directory.
        val session = checkNotNull(work)
        // Ordinary boot images expose a kernel block, not an AnyKernel3 `Image` entry.
        val kernel = File(session, "kernel")
        val patched = File(session, "kernel.patched")
        val output = File(session, "patched-boot.img")
        val daemon = q(getKsuDaemonPath())
        onStdout("- Preparing bundled KPM tools")
        val tools = KpmTools.prepare(ksuApp, session)
        val toolCommand = tools.command
        val version = getKernelVersion()
        check(version.major >= 0 && version.patchLevel >= 0) { "Cannot determine kernel version" }
        val useKptoolsBoot = version.major > 6 ||
            (version.major == 6 && version.patchLevel >= 12)
        val inSession = "cd ${q(session.absolutePath)} && "
        onStdout("- Running kernel: $version; boot image tool: ${if (useKptoolsBoot) "kptools" else "ksud"}")
        onStdout("- Unpacking boot.img and decompressing kernel")
        if (useKptoolsBoot) {
            // kptools-android uses fixed names relative to cwd: boot.img -> kernel.
            command(inSession + "$toolCommand unpack boot.img")
        } else {
            command("$daemon boot-kernel extract --boot ${q(source.absolutePath)} --output ${q(kernel.absolutePath)}")
        }
        command("[ -s ${q(kernel.absolutePath)} ]")
        onStdout(if (undo) "- Undoing KPM patch" else "- Applying KPM patch")
        tools.patch(kernel, patched, undo, ::command)
        onStdout("- Repacking boot.img")
        if (useKptoolsBoot) {
            // repack reads `kernel`, not `kernel.patched`. Keep the original
            // boot.img intact and replace only the extracted kernel file.
            command("mv ${q(patched.absolutePath)} ${q(kernel.absolutePath)}")
            command(inSession + "$toolCommand repack boot.img")
            val repacked = File(session, "new-boot.img")
            command("[ -s ${q(repacked.absolutePath)} ] && mv ${q(repacked.absolutePath)} ${q(output.absolutePath)}")
        } else {
            command("$daemon boot-kernel repack --boot ${q(source.absolutePath)} " +
                "--kernel ${q(patched.absolutePath)} --output ${q(output.absolutePath)}")
        }
        // ksud uses a private temporary file; allow the app UID to export it
        // even if ksud ran in a root shell.
        command("chmod 644 ${q(output.absolutePath)}")
        if (target == null) {
            val saved = outputFile ?: File(downloads, "SukiSU_KPM_boot_$id.img")
            // Keep the selected-file flow usable without root; do not rely on
            // a shell redirection to a scoped-storage path.
            output.copyTo(saved, overwrite = false)
            onStdout("- Output: ${saved.absolutePath}")
        } else {
            check(read("getprop ro.boot.slot_suffix") == suffix) { "Active slot changed; refusing to flash" }
            onStdout("- Flashing current boot through ksud with source and read-back verification")
            writing = true
            command("$daemon boot-kernel flash-current --boot ${q(source.absolutePath)} " +
                "--patched ${q(output.absolutePath)}")
            onStdout("- Boot flashed and verified. Keep the backup before rebooting.")
        }
        return FlashResult(0, "", target != null, outputFile)
    } catch (e: Exception) {
        val message = buildString {
            append(e.message ?: "KPM patch failed")
            backup?.let { append("\nBackup: ${it.absolutePath}") }
            if (writing) append("\nBoot writing started. Restore the backup before rebooting if flashing failed.")
        }
        onStderr(message)
        return FlashResult(1, message, false)
    } finally {
        runCatching { work?.let { removeAsRoot(it.absolutePath) } }
    }
}
