package com.sukisu.ultra.ui.util

import android.content.ContentResolver
import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.os.Environment
import android.os.Parcelable
import android.os.SystemClock
import android.provider.OpenableColumns
import android.system.Os
import android.util.Log
import com.topjohnwu.superuser.CallbackList
import com.topjohnwu.superuser.Shell
import com.topjohnwu.superuser.ShellUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.parcelize.Parcelize
import com.sukisu.ultra.BuildConfig
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.core.tasks.BootKernelVersion
import com.sukisu.ultra.core.tasks.ExtractImage
import com.sukisu.ultra.core.tasks.ProbeResult
import com.sukisu.ultra.core.utils.DataSourceChannel
import com.sukisu.ultra.data.registry.DownloadVerificationException
import com.sukisu.ultra.data.registry.RegistryDownloadStore
import com.sukisu.ultra.data.registry.copyForInstall
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.screen.susfs.util.SuSFSConfig
import okhttp3.OkHttpClient
import org.json.JSONArray
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit
import java.util.zip.ZipFile

/**
 * @author weishu
 * @date 2023/1/1.
 */
private const val TAG = "KsuCli"

fun getKsuDaemonPath(): String {
    return ksuApp.applicationInfo.nativeLibraryDir + File.separator + "libksud.so"
}

data class FlashResult(val code: Int, val err: String, val showReboot: Boolean, val outputFile: File? = null) {
    constructor(result: Shell.Result, showReboot: Boolean) : this(result.code, result.err.joinToString("\n"), showReboot)
    constructor(result: Shell.Result) : this(result, result.isSuccess)
}

object KsuCli {
    val SHELL: Shell = createRootShell()
    val GLOBAL_MNT_SHELL: Shell = createRootShell(true)
}

fun getRootShell(globalMnt: Boolean = false): Shell {
    return if (globalMnt) KsuCli.GLOBAL_MNT_SHELL else {
        KsuCli.SHELL
    }
}

inline fun <T> withNewRootShell(
    globalMnt: Boolean = false,
    block: Shell.() -> T
): T {
    return createRootShell(globalMnt).use(block)
}

fun Uri.getFileName(context: Context): String? {
    var fileName: String? = null
    val contentResolver: ContentResolver = context.contentResolver
    val cursor: Cursor? = contentResolver.query(this, null, null, null, null)
    cursor?.use {
        if (it.moveToFirst()) {
            fileName = it.getString(it.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME))
        }
    }
    return fileName
}

fun createRootShell(globalMnt: Boolean = false): Shell {
    Shell.enableVerboseLogging = BuildConfig.DEBUG
    val builder = Shell.Builder.create()
    return try {
        if (globalMnt) {
            builder.build(getKsuDaemonPath(), "debug", "su", "-g")
        } else {
            builder.build(getKsuDaemonPath(), "debug", "su")
        }
    } catch (e: Throwable) {
        Log.w(TAG, "ksu failed: ", e)
        try {
            if (globalMnt) {
                builder.build("su", "-mm")
            } else {
                builder.build("su")
            }
        } catch (e: Throwable) {
            Log.e(TAG, "su failed: ", e)
            builder.build("sh")
        }
    }
}

fun execKsud(args: String, newShell: Boolean = false, globalMnt: Boolean = false): Boolean {
    return if (newShell) {
        withNewRootShell(globalMnt = globalMnt) {
            ShellUtils.fastCmdResult(this, "${getKsuDaemonPath()} $args")
        }
    } else {
        ShellUtils.fastCmdResult(getRootShell(globalMnt), "${getKsuDaemonPath()} $args")
    }
}

suspend fun getFeatureStatus(feature: String): String = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val out = shell.newJob()
        .add("${getKsuDaemonPath()} feature check $feature").to(ArrayList<String>(), null).exec().out
    out.firstOrNull()?.trim().orEmpty()
}

suspend fun getFeaturePersistValue(feature: String): Long? = readFeatureValue("--config $feature")

// Current value in kernel
suspend fun getFeatureValue(feature: String): Long? = readFeatureValue(feature)

private suspend fun readFeatureValue(args: String): Long? = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val out = shell.newJob()
        .add("${getKsuDaemonPath()} feature get $args").to(ArrayList<String>(), null).exec().out
    val valueLine = out.firstOrNull { it.trim().startsWith("Value:") } ?: return@withContext null
    valueLine.substringAfter("Value:").trim().toLongOrNull()
}

// Extension helpers (mirror the feature helpers above). The ksud
// subcommand is `extension <get|set|check|list|...>`.
//
// All probe helpers go through withNewRootShell() rather than the
// shared KsuCli.SHELL, so callers can fan out concurrently without
// racing on a single shell's command queue (each shell accepts
// exactly one command at a time, and libsu's job output is a
// per-shell buffer).

suspend fun getExtensionStatus(extension: String): String = withContext(Dispatchers.IO) {
    val out = withNewRootShell {
        newJob()
            .add("${getKsuDaemonPath()} extension check $extension")
            .to(ArrayList<String>(), null)
            .exec()
            .out
    }
    out.firstOrNull()?.trim().orEmpty()
}

suspend fun getExtensionPersistValue(extension: String): Long? = readExtensionValue("--config $extension")

suspend fun getExtensionValue(extension: String): Long? = readExtensionValue(extension)

private suspend fun readExtensionValue(args: String): Long? = withContext(Dispatchers.IO) {
    val out = withNewRootShell {
        newJob()
            .add("${getKsuDaemonPath()} extension get $args")
            .to(ArrayList<String>(), null)
            .exec()
            .out
    }
    out.firstOrNull { it.trim().startsWith("Value:") }
        ?.substringAfter("Value:")
        ?.trim()
        ?.toLongOrNull()
}

/**
 * Pull the state of every extension in a single `ksud extension list`
 * shell call, then parse the trailing `EXTENSION_LIST_V1 ...` machine
 * block that the kernel-side CLI prints after the human-readable part.
 *
 * ABI 2+ kernels additionally emit `EXTENSION_LIST_V3` rows built from the
 * kernel's handler table. When those are present they are the whole answer:
 * they include handlers this build has no [ExtensionId] for, and they carry
 * every field, so no V1/V2 merge is needed. One shell pays the libksud.so
 * startup + root handshake + teardown cost once per refresh, and the parse
 * is linear in the number of extensions.
 */
suspend fun getExtensionOverview(): Map<String, ExtensionOverviewEntry> = withContext(Dispatchers.IO) {
    val out = withNewRootShell {
        newJob()
            .add("${getKsuDaemonPath()} extension list")
            .to(ArrayList<String>(), null)
            .exec()
            .out
    }
    parseExtensionOverview(out)
}

/**
 * Toggle a sticky extension's value through the kernel.
 *
 * The numeric id comes from the kernel's own handler table, so this works
 * for extensions this manager build has no compiled-in id for; ksud
 * resolves it through KSU_EXTENSION_ENUM before falling back to its static
 * table. Passing the id (rather than the wire name) also keeps an
 * unknown extension's name out of the shell command line.
 */
suspend fun setExtensionValue(extensionId: Int, value: Long): Result<Unit> = withContext(Dispatchers.IO) {
    runCatching {
        val result = withNewRootShell {
            newJob()
                .add("${getKsuDaemonPath()} extension set $extensionId $value")
                .to(ArrayList<String>(), null)
                .exec()
        }
        check(result.isSuccess) {
            result.err.joinToString("\n").ifBlank { "extension set failed (${result.code})" }
        }
    }
}

/**
 * One row of the `ksud extension list` machine block. Field names match the
 * on-wire format exactly.
 *
 * The kernel decides what each extension can do and ksud forwards it, so the
 * capability fields ([sticky], [persistent], [perUid], [needsReboot]) are
 * read from the output instead of being derived from [ExtensionId]. They stay
 * at their defaults when the kernel predates extension ABI 1 and only the V1
 * row is available.
 */
data class ExtensionOverviewEntry(
    val name: String,
    val id: Int,
    val supported: Boolean,
    val forced: Boolean,
    val value: Long,
    val managed: Boolean,
    val sticky: Boolean,
    /** Extension ABI the kernel speaks; 0 when it predates the probe. */
    val apiVersion: Int = 0,
    /** Whether the sticky value is replayed from `.extension_config` at boot. */
    val persistent: Boolean = false,
    /** Whether the extension's state is scoped per uid. */
    val perUid: Boolean = false,
    /** Whether changes only land after a reboot. */
    val needsReboot: Boolean = false,
)

private val EXT_V1_LINE = Regex(
    """^EXTENSION_LIST_V1\s+name=(\S+)\s+id=(\d+)\s+supported=(\d+)\s+forced=(\d+)\s+value=(\d+)\s+managed=(\d+)\s+sticky=(\d+)\s*$"""
)

private val EXT_V2_LINE = Regex(
    """^EXTENSION_LIST_V2\s+name=(\S+)\s+id=(\d+)\s+caps=0x([0-9a-fA-F]+)\s+api=(\d+)\s+sticky=(\d+)\s+persist=(\d+)\s+per_uid=(\d+)\s+reboot=(\d+)\s*$"""
)

/**
 * ABI 2+ rows. They enumerate the kernel's handler table, so a V3 row can
 * exist for an extension this manager has never heard of. Every field is
 * present, which is why the parser returns the V3 set as-is instead of
 * merging it with V1/V2.
 */
private val EXT_V3_LINE = Regex(
    """^EXTENSION_LIST_V3\s+name=(\S+)\s+id=(\d+)\s+caps=0x([0-9a-fA-F]+)\s+api=(\d+)\s+supported=(\d+)\s+forced=(\d+)\s+value=(\d+)\s+managed=(\d+)\s+sticky=(\d+)\s+persist=(\d+)\s+per_uid=(\d+)\s+reboot=(\d+)\s*$"""
)

internal fun parseExtensionOverview(lines: List<String>): Map<String, ExtensionOverviewEntry> {
    val parsed = LinkedHashMap<String, ExtensionOverviewEntry>()
    // V2 rows travel separately so V1 keeps its frozen layout for older
    // consumers. They are merged by wire name once the block is read,
    // which also makes the parser order-independent.
    val caps = HashMap<String, ExtensionOverviewEntry>()
    val enumerated = LinkedHashMap<String, ExtensionOverviewEntry>()
    for (line in lines) {
        if (line.startsWith("EXTENSION_LIST_END")) break
        // A `EXTENSION_LIST_V1 ...` line is the first line of an
        // extension row; parse it directly. We don't gate on a
        // separate "entered the block" flag because the very first
        // V1 line is the one that starts the block.
        if (line.startsWith("EXTENSION_LIST_V1")) {
            val m = EXT_V1_LINE.matchEntire(line) ?: continue
            val entry = ExtensionOverviewEntry(
                name = m.groupValues[1],
                id = m.groupValues[2].toIntOrNull() ?: continue,
                supported = m.groupValues[3] == "1",
                forced = m.groupValues[4] == "1",
                value = m.groupValues[5].toLongOrNull() ?: 0L,
                managed = m.groupValues[6] == "1",
                sticky = m.groupValues[7] == "1",
            )
            parsed[entry.name] = entry
            continue
        }
        if (line.startsWith("EXTENSION_LIST_V2")) {
            val m = EXT_V2_LINE.matchEntire(line) ?: continue
            val name = m.groupValues[1]
            caps[name] = ExtensionOverviewEntry(
                name = name,
                id = m.groupValues[2].toIntOrNull() ?: continue,
                supported = false, // V1 owns these; only the caps fields are read
                forced = false,
                value = 0L,
                managed = false,
                sticky = m.groupValues[5] == "1",
                apiVersion = m.groupValues[4].toIntOrNull() ?: 0,
                persistent = m.groupValues[6] == "1",
                perUid = m.groupValues[7] == "1",
                needsReboot = m.groupValues[8] == "1",
            )
            continue
        }
        if (line.startsWith("EXTENSION_LIST_V3")) {
            val m = EXT_V3_LINE.matchEntire(line) ?: continue
            val entry = ExtensionOverviewEntry(
                name = m.groupValues[1],
                id = m.groupValues[2].toIntOrNull() ?: continue,
                supported = m.groupValues[5] == "1",
                forced = m.groupValues[6] == "1",
                value = m.groupValues[7].toLongOrNull() ?: 0L,
                managed = m.groupValues[8] == "1",
                sticky = m.groupValues[9] == "1",
                apiVersion = m.groupValues[4].toIntOrNull() ?: 0,
                persistent = m.groupValues[10] == "1",
                perUid = m.groupValues[11] == "1",
                needsReboot = m.groupValues[12] == "1",
            )
            enumerated[entry.name] = entry
            continue
        }
    }
    // V3 is authoritative when present: it includes handlers the static
    // enum does not know about, and it carries every field itself.
    if (enumerated.isNotEmpty()) return enumerated
    if (caps.isEmpty()) return parsed
    return parsed.mapValues { (name, entry) ->
        val v2 = caps[name] ?: return@mapValues entry
        entry.copy(
            sticky = v2.sticky,
            apiVersion = v2.apiVersion,
            persistent = v2.persistent,
            perUid = v2.perUid,
            needsReboot = v2.needsReboot,
        )
    }
}

fun install() {
    val start = SystemClock.elapsedRealtime()
    val libadbroot = File(ksuApp.applicationInfo.nativeLibraryDir, "libadbroot.so").absolutePath
    val result = execKsud("install --libadbroot $libadbroot --data-path ${ksuApp.applicationInfo.deviceProtectedDataDir}", true)
    Log.w(TAG, "install result: $result, cost: ${SystemClock.elapsedRealtime() - start}ms")
}

fun listModules(): String {
    val shell = getRootShell()

    val out = shell.newJob()
        .add("${getKsuDaemonPath()} module list").to(ArrayList(), null).exec().out
    return out.joinToString("\n").ifBlank { "[]" }
}

fun getModuleCount(): Int {
    val result = listModules()
    runCatching {
        val array = JSONArray(result)
        return array.length()
    }.getOrElse { return 0 }
}

fun getSuperuserCount(): Int {
    return Natives.getSuperuserCount()
}

fun toggleModule(id: String, enable: Boolean): Boolean {
    val cmd = if (enable) {
        "module enable $id"
    } else {
        "module disable $id"
    }
    val result = execKsud(cmd, true)
    Log.i(TAG, "$cmd result: $result")
    return result
}

fun undoUninstallModule(id: String): Boolean {
    val cmd = "module undo-uninstall $id"
    val result = execKsud(cmd, true)
    Log.i(TAG, "undo uninstall module $id result: $result")
    return result
}

fun uninstallModule(id: String): Boolean {
    val cmd = "module uninstall $id"
    val result = execKsud(cmd, true)
    Log.i(TAG, "uninstall module $id result: $result")
    return result
}

private fun flashWithIO(
    cmd: String,
    onStdout: (String) -> Unit,
    onStderr: (String) -> Unit
): Shell.Result {

    val stdoutCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            onStdout(s ?: "")
        }
    }

    val stderrCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            onStderr(s ?: "")
        }
    }

    return withNewRootShell {
        newJob().add(cmd).to(stdoutCallback, stderrCallback).exec()
    }
}

fun flashModule(
    uri: Uri,
    onStdout: (String) -> Unit,
    onStderr: (String) -> Unit,
    deleteSourceOnSuccess: Boolean = false,
): FlashResult {
    // Registry downloads live in app-private storage and carry their expected size + SHA-256;
    // the exact copy handed to ksud is re-hashed right before installing.
    val storeRoot = File(ksuApp.filesDir, RegistryDownloadStore.DIR_NAME)
    val expected = if (uri.scheme == ContentResolver.SCHEME_FILE) {
        uri.path?.let { RegistryDownloadStore.expectedFor(storeRoot, File(it)) }
    } else {
        null
    }
    val file = File.createTempFile("module-", ".zip", ksuApp.cacheDir)
    try {
        try {
            val input = ksuApp.contentResolver.openInputStream(uri) ?: throw IOException("Cannot open $uri")
            input.use { copyForInstall(it, file, expected) }
        } catch (e: IOException) {
            Log.w("KernelSU", "module $uri not installed: ${e.message}")
            if (e is DownloadVerificationException) {
                // Corrupted or tampered after download: never keep it around for a retry.
                uri.path?.let { RegistryDownloadStore.delete(storeRoot, File(it)) }
            }
            val message = "! ${e.message ?: "Failed to read module"}"
            onStderr(message)
            return FlashResult(1, message, false)
        }
        val cmd = "module install ${file.absolutePath}"
        val result = flashWithIO("${getKsuDaemonPath()} $cmd", onStdout, onStderr)
        Log.i("KernelSU", "install module $uri result: $result")
        if (shouldDeleteSourceAfterInstall(deleteSourceOnSuccess, result.isSuccess)) {
            val name = runCatching { uri.getFileName(ksuApp) }.getOrNull()
                ?: uri.lastPathSegment?.substringAfterLast('/').orEmpty()
            val deleted = deleteInstalledModuleZip(uri)
            // The flash screen only renders stdout, so report both outcomes there.
            onStdout(
                ksuApp.getString(
                    if (deleted) R.string.module_zip_deleted else R.string.module_zip_delete_failed,
                    name,
                )
            )
        }
        return FlashResult(result, result.isSuccess && moduleNeedsReboot(file))
    } finally {
        file.delete()
    }
}

private val MODULE_ID_REGEX = Regex("^[a-zA-Z][a-zA-Z0-9._-]+$")

// A hot installed module goes live without leaving the "update" flag behind
private fun moduleNeedsReboot(zip: File): Boolean {
    val id = runCatching {
        ZipFile(zip).use { archive ->
            val entry = archive.getEntry("module.prop") ?: return@use null
            archive.getInputStream(entry).bufferedReader().useLines { lines ->
                lines.map { it.trim() }.firstOrNull { it.startsWith("id=") }?.substringAfter('=')?.trim()
            }
        }
    }.getOrNull()
    if (id == null || !MODULE_ID_REGEX.matches(id)) return true
    val dir = "/data/adb/modules/$id"
    // Any failure to check counts as needing a reboot
    return !ShellUtils.fastCmdResult(getRootShell(), "[ -d $dir ] && [ ! -e $dir/update ]")
}

fun runModuleAction(
    moduleId: String, onStdout: (String) -> Unit, onStderr: (String) -> Unit
): Boolean {
    val stdoutCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            onStdout(s ?: "")
        }
    }

    val stderrCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            onStderr(s ?: "")
        }
    }

    val result = withNewRootShell(true) {
        newJob().add("${getKsuDaemonPath()} module action $moduleId")
            .to(stdoutCallback, stderrCallback).exec()
    }

    Log.i("KernelSU", "Module runAction result: $result")

    return result.isSuccess
}

/**
 * Runs a prepared one-shot script command (see ScriptCommand) in a new root shell in the
 * global mount namespace, like a module action. Returns the exit code.
 */
fun runOneshotScript(
    command: String, onStdout: (String) -> Unit, onStderr: (String) -> Unit
): Int {
    val stdoutCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            onStdout(s ?: "")
        }
    }

    val stderrCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            onStderr(s ?: "")
        }
    }

    val result = withNewRootShell(true) {
        newJob().add(command).to(stdoutCallback, stderrCallback).exec()
    }
    Log.i(TAG, "one-shot script exit code: ${result.code}")
    return result.code
}

/** Removes a script's extraction directory, including files the script created as root. */
fun removeAsRoot(path: String): Boolean {
    val escaped = "'" + path.replace("'", "'\\''") + "'"
    return ShellUtils.fastCmdResult(getRootShell(), "rm -rf $escaped")
}

fun restoreBoot(
    onStdout: (String) -> Unit, onStderr: (String) -> Unit
): FlashResult {
    val result = flashWithIO("${getKsuDaemonPath()} boot-restore -f", onStdout, onStderr)
    return FlashResult(result)
}

fun uninstallPermanently(
    onStdout: (String) -> Unit, onStderr: (String) -> Unit
): FlashResult {
    val result = flashWithIO("${getKsuDaemonPath()} uninstall --package-name ${BuildConfig.APPLICATION_ID}", onStdout, onStderr)
    return FlashResult(result)
}

@Parcelize
sealed class LkmSelection : Parcelable {
    @Parcelize
    data class LkmUri(val uri: Uri) : LkmSelection()

    @Parcelize
    data class KmiString(val value: String) : LkmSelection()

    @Parcelize
    data object KmiNone : LkmSelection()
}

private fun writeLkmFile(lkm: LkmSelection): File? {
    if (lkm !is LkmSelection.LkmUri) return null
    val file = File(ksuApp.cacheDir, "kernelsu-tmp-lkm.ko")
    ksuApp.contentResolver.openInputStream(lkm.uri)?.use { input ->
        file.outputStream().use { output -> input.copyTo(output) }
    }
    return file
}

// A single module name as accepted by ksud's --block-module parser.
private fun isValidBlockModuleName(name: String): Boolean =
    name.isNotEmpty() && name.length <= 64 &&
        name.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '_' }

/** Parse the comma-separated block-modules field into the non-empty names. */
fun parseBlockModules(input: String): List<String> =
    input.split(',').map { it.trim() }.filter { it.isNotEmpty() }

// The kernel copies the block_modules= value into a 256-byte buffer, leaving
// 255 bytes; a longer list would be silently truncated, leaving some modules
// unblocked. Reject it here too.
private const val MAX_BLOCK_MODULES_LEN = 255

/** Whether every name in the block-modules field is valid (empty is valid). */
fun isBlockModulesValid(input: String): Boolean {
    val names = parseBlockModules(input)
    return names.all(::isValidBlockModuleName) &&
        names.joinToString(",").length <= MAX_BLOCK_MODULES_LEN
}

private fun bootPatchFlags(
    allowShell: Boolean,
    enableAdb: Boolean,
    forceBackup: Boolean,
    blockModules: String,
): String = buildString {
    if (allowShell) append(" --allow-shell")
    if (enableAdb) append(" --enable-adbd")
    if (forceBackup) append(" --backup")
    // Names are validated in the UI before install; pass them through without
    // mutating. Drop the flag entirely (never inject) if anything slips through.
    val names = parseBlockModules(blockModules)
    if (names.isNotEmpty() && names.all(::isValidBlockModuleName)) {
        append(" --block-module ${names.joinToString(",")}")
    }
}

fun installBoot(
    bootUri: Uri?,
    lkm: LkmSelection,
    ota: Boolean,
    partition: String?,
    allowShell: Boolean,
    enableAdb: Boolean,
    forceBackup: Boolean,
    blockModules: String,
    spoofRelease: String,
    spoofVersion: String,
    onStdout: (String) -> Unit,
    onStderr: (String) -> Unit,
    kpmEnabled: Boolean = false,
    kpmUndo: Boolean = false,
    kpmBoot: Uri? = null,
    outputDir: File? = null,
): FlashResult {
    if (kpmEnabled) return installBootWithKpm(
        bootUri, lkm, ota, partition, allowShell, enableAdb, forceBackup,
        blockModules, spoofRelease, spoofVersion, kpmBoot, onStdout, onStderr, kpmUndo,
    )
    val resolver = ksuApp.contentResolver

    val bootFile = bootUri?.let { uri ->
        with(resolver.openInputStream(uri)) {
            val bootFile = File(ksuApp.cacheDir, "boot.img")
            bootFile.outputStream().use { output ->
                this?.copyTo(output)
            }

            bootFile
        }
    }

    var cmd = "boot-patch"

    cmd += if (bootFile == null) {
        // no boot.img, use -f to flash
        " -f"
    } else {
        " -b ${bootFile.absolutePath}"
    }
    cmd += bootPatchFlags(allowShell, enableAdb, forceBackup, blockModules)

    cmd += " --spoof-release ${spoofRelease.trim().shellArg()}"
    cmd += " --spoof-version ${spoofVersion.trim().shellArg()}"

    if (ota) {
        cmd += " -u"
    }

    val lkmFile = writeLkmFile(lkm)
    if (lkmFile != null) {
        cmd += " -m ${lkmFile.absolutePath}"
    } else if (lkm is LkmSelection.KmiString) {
        cmd += " --kmi ${lkm.value}"
    }

    if (bootFile != null) {
        val downloadsDir =
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val destination = outputDir ?: downloadsDir
        cmd += " -o ${destination.absolutePath.shellArg()}"
        if (outputDir != null) cmd += " --out-name lkm-patched.img"
    }

    partition?.let { part ->
        cmd += " --partition $part"
    }

    val result = flashWithIO("${getKsuDaemonPath()} $cmd", onStdout, onStderr)
    Log.i("KernelSU", "install boot result: ${result.isSuccess}")

    bootFile?.delete()
    lkmFile?.delete()

    // if boot uri is empty, it is direct install, when success, we should show reboot button
    val showReboot = bootUri == null && result.isSuccess // we create a temporary val here, to avoid calc showReboot double
    if (showReboot) { // because we decide do not update ksud when startActivity
        install() // install ksud here
    }
    return FlashResult(result.code, result.err.joinToString("\n"), showReboot,
        outputDir?.let { File(it, "lkm-patched.img") }?.takeIf { result.isSuccess })
}

private fun installBootWithKpm(
    bootUri: Uri?, lkm: LkmSelection, ota: Boolean, partition: String?,
    allowShell: Boolean, enableAdb: Boolean, forceBackup: Boolean, blockModules: String,
    spoofRelease: String, spoofVersion: String, kpmBoot: Uri?,
    onStdout: (String) -> Unit, onStderr: (String) -> Unit,
    kpmUndo: Boolean,
): FlashResult {
    fun failIfNeeded(result: FlashResult): Boolean {
        if (result.code != 0) onStderr(result.err)
        return result.code != 0
    }
    if (bootUri == null) {
        if (ota) return FlashResult(1, "Combined KPM installation to the inactive slot is not supported yet; no changes made", false)
        // Do not discover an invalid manual boot only after updating LKM.
        if (kpmBoot != null) {
            try {
                val header = ByteArray(64)
                val input = ksuApp.contentResolver.openInputStream(kpmBoot)
                    ?: error("Cannot open the selected boot.img")
                input.use { java.io.DataInputStream(it).readFully(header) }
                check(String(header, 0, 8, Charsets.US_ASCII) == "ANDROID!" &&
                    ByteBuffer.wrap(header).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt(8) > 0) {
                    "Select boot.img containing a kernel, not init_boot.img"
                }
            } catch (e: Exception) {
                return FlashResult(1, e.message ?: "Cannot read manual boot.img", false)
            }
        }
        val lkmResult = installBoot(null, lkm, false, partition, allowShell, enableAdb, forceBackup,
            blockModules, spoofRelease, spoofVersion, onStdout, onStderr, kpmEnabled = false)
        if (failIfNeeded(lkmResult)) return lkmResult
        onStdout("- LKM installation completed. Starting additional KPM operation.")
        if (kpmBoot != null) onStdout("- Manual boot selected: KPM output will be exported, not flashed to the device.")
        val result = patchKpmBoot(kpmBoot, onStdout, onStderr, undo = kpmUndo)
        return result.copy(showReboot = result.code == 0 && lkmResult.showReboot)
    }
    val work = File.createTempFile("lkm-kpm-", ".dir", ksuApp.cacheDir)
    check(work.delete() && work.mkdirs()) { "Cannot create combined patch directory" }
    return try {
        if (kpmBoot == null) {
            val header = ByteArray(64)
            val count = ksuApp.contentResolver.openInputStream(bootUri)?.use { input ->
                java.io.DataInputStream(input).readFully(header)
                header.size
            } ?: 0
            check(count == header.size && String(header, 0, 8, Charsets.US_ASCII) == "ANDROID!" &&
                ByteBuffer.wrap(header).order(java.nio.ByteOrder.LITTLE_ENDIAN).getInt(8) > 0) {
                "Selected image has no boot kernel. Expand manual boot selection and choose the matching boot.img."
            }
        }
        val lkmResult = installBoot(bootUri, lkm, ota, partition, allowShell, enableAdb, forceBackup,
            blockModules, spoofRelease, spoofVersion, onStdout, onStderr,
            kpmEnabled = false, outputDir = work)
        if (failIfNeeded(lkmResult)) return lkmResult
        val lkmOutput = lkmResult.outputFile ?: File(work, "lkm-patched.img")
        check(lkmOutput.isFile) { "LKM patched image was not produced" }
        check(flashWithIO("chmod 644 ${SuSFSConfig.shellQuote(lkmOutput.absolutePath)}", onStdout, onStderr).isSuccess) {
            "Cannot read LKM output"
        }
        val kpmInput = kpmBoot ?: Uri.fromFile(lkmOutput)
        val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        check(downloads.exists() || downloads.mkdirs()) { "Cannot create Downloads directory" }
        val finalOutput = File(downloads, "SukiSU_KPM_boot_${System.currentTimeMillis()}.img")
        val result = patchKpmBoot(kpmInput, onStdout, onStderr, finalOutput, undo = kpmUndo)
        if (kpmBoot != null || result.code != 0) {
            // A separate init_boot/vendor_boot artifact must not disappear
            // when the temporary directory is cleaned up.
            val savedLkm = File(downloads, "SukiSU_LKM_${System.currentTimeMillis()}.img")
            check(flashWithIO("chmod 644 ${SuSFSConfig.shellQuote(lkmOutput.absolutePath)}", onStdout, onStderr).isSuccess) { "Cannot export LKM output" }
            lkmOutput.copyTo(savedLkm)
            onStdout("- LKM output: ${savedLkm.absolutePath}")
        }
        result
    } catch (e: Exception) {
        val message = e.message ?: "Combined LKM/KPM operation failed"
        onStderr(message)
        FlashResult(1, message, false)
    } finally {
        removeAsRoot(work.absolutePath)
    }
}

fun downloadBoot(
    url: String,
    partition: String,
    lkm: LkmSelection,
    allowShell: Boolean,
    enableAdb: Boolean,
    forceBackup: Boolean,
    blockModules: String,
    spoofRelease: String,
    spoofVersion: String,
    onStdout: (String) -> Unit,
    onStderr: (String) -> Unit,
    kpmEnabled: Boolean = false,
    kpmUndo: Boolean = false,
    kpmBoot: Uri? = null,
): FlashResult {
    val bootFile = File(ksuApp.cacheDir, "download-boot.img")
    var probedKmi: String?
    try {
        onStdout("- Downloading and extracting boot image")
        val channel = DataSourceChannel(newDownloadClient(), url)
        val magic = readMagic(channel)
        val image = ExtractImage(bootFile, onStdout)
        // Extract the KMI here while the payload is open. ZipFile closes the
        // channel it is built on, so probe on a separate channel.
        val probeChannel = DataSourceChannel(newDownloadClient(), url)
        probedKmi = probeChannel.use { probeChannel ->
            if (magic == "CrAU") {
                ExtractImage.probePayload(
                    probeChannel,
                    withKmi = lkm is LkmSelection.KmiNone,
                    onProgress = onStdout,
                ).kmi
            } else {
                ExtractImage.probe(
                    probeChannel,
                    withKmi = lkm is LkmSelection.KmiNone,
                    onProgress = onStdout,
                ).kmi
            }
        }
        if (magic == "CrAU") {
            image.consumePayload(channel, partition)
        } else {
            image.consume(channel, partition)
        }
    } catch (e: Exception) {
        bootFile.delete()
        return FlashResult(-1, e.message ?: "Download failed", false)
    }

    // init_boot/vendor_boot carry no kernel, so their KMI comes from the
    // payload's boot probe and must be passed explicitly. A remote download
    // is unrelated to this device, so ksud must not use the local kernel.
    val autoKmi = if (lkm is LkmSelection.KmiNone) {
        (probedKmi ?: BootKernelVersion.parseKmiFromBoot(bootFile))?.also {
            onStdout("- Auto detected KMI: $it")
        }
    } else {
        null
    }
    if (autoKmi == null && lkm is LkmSelection.KmiNone) {
        bootFile.delete()
        return FlashResult(-1, "Failed to determine KMI from the package", false)
    }

    if (kpmEnabled) {
        try {
            var selectedBoot = kpmBoot
            var downloadedKernelBoot: File? = null
            if (selectedBoot == null && partition != "boot") {
                downloadedKernelBoot = File.createTempFile("kpm-remote-boot-", ".img", ksuApp.cacheDir)
                val kernelChannel = DataSourceChannel(newDownloadClient(), url)
                val extractor = ExtractImage(downloadedKernelBoot, onStdout)
                if (readMagic(kernelChannel) == "CrAU") extractor.consumePayload(kernelChannel, "boot")
                else extractor.consume(kernelChannel, "boot")
                selectedBoot = Uri.fromFile(downloadedKernelBoot)
            }
            try {
                val resolvedLkm = autoKmi?.let { LkmSelection.KmiString(it) } ?: lkm
                return installBootWithKpm(Uri.fromFile(bootFile), resolvedLkm, false, partition,
                    allowShell, enableAdb, forceBackup, blockModules, spoofRelease, spoofVersion,
                    selectedBoot, onStdout, onStderr, kpmUndo)
            } finally {
                downloadedKernelBoot?.delete()
            }
        } catch (e: Exception) {
            return FlashResult(1, e.message ?: "Cannot prepare remote boot for KPM", false)
        } finally {
            bootFile.delete()
        }
    }

    var cmd = "${getKsuDaemonPath()} boot-patch -b ${bootFile.absolutePath}"
    cmd += bootPatchFlags(allowShell, enableAdb, forceBackup, blockModules)

    cmd += " --spoof-release ${spoofRelease.trim().shellArg()}"
    cmd += " --spoof-version ${spoofVersion.trim().shellArg()}"

    val lkmFile = writeLkmFile(lkm)
    if (lkmFile != null) {
        cmd += " -m ${lkmFile.absolutePath}"
    } else if (lkm is LkmSelection.KmiString) {
        cmd += " --kmi ${lkm.value}"
    }
    if (autoKmi != null) cmd += " --kmi $autoKmi"
    cmd += " --partition $partition"
    // ksud defaults to cwd, which is read-only in the su session; use Downloads.
    val downloadsDir =
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
    cmd += " -o $downloadsDir"

    val stdoutCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            onStdout(s ?: "")
        }
    }
    val stderrCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            onStderr(s ?: "")
        }
    }

    val result = Shell.getShell().newJob().add(cmd).to(stdoutCallback, stderrCallback).exec()
    lkmFile?.delete()
    bootFile.delete()
    return FlashResult(result, false)
}

suspend fun probeRemoteBootPartitions(url: String): ProbeResult = withContext(Dispatchers.IO) {
    Log.d(TAG, "probe start: $url")
    val channel = DataSourceChannel(newDownloadClient(), url)
    Log.d(TAG, "probe connected, size=${channel.size()}")
    val magic = readMagic(channel)
    Log.d(TAG, "probe magic: $magic")
    // Only list the partitions here; the KMI is extracted later when the
    // payload is downloaded for patching.
    val result = if (magic == "CrAU") {
        ExtractImage.probePayload(channel, withKmi = false)
    } else {
        ExtractImage.probe(channel, withKmi = false)
    }
    Log.d(TAG, "probe partitions: ${result.partitions}")
    result
}

private fun newDownloadClient(): OkHttpClient {
    return OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .writeTimeout(20, TimeUnit.SECONDS)
        .build()
}

private fun readMagic(channel: DataSourceChannel): String {
    val buffer = ByteBuffer.allocate(4)
    channel.read(buffer)
    channel.position(0)
    return String(buffer.array(), StandardCharsets.ISO_8859_1)
}

private fun String.shellArg(): String = "'${replace("'", "'\\''")}'"

fun reboot(reason: String = "") {
    if (reason == "soft_reboot") {
        execKsud("soft-reboot", true, globalMnt = true)
        return
    }
    val shell = getRootShell()
    if (reason == "recovery") {
        // KEYCODE_POWER = 26, hide incorrect "Factory data reset" message
        ShellUtils.fastCmd(shell, "/system/bin/input keyevent 26")
    }
    ShellUtils.fastCmd(shell, "/system/bin/svc power reboot $reason || /system/bin/reboot $reason")
}

fun rootAvailable(): Boolean {
    val shell = getRootShell()
    return shell.isRoot
}

suspend fun getCurrentKmi(): String = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val cmd = "boot-info current-kmi"
    ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} $cmd")
}

suspend fun getSupportedKmis(): List<String> = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val cmd = "boot-info supported-kmis"
    val out = shell.newJob().add("${getKsuDaemonPath()} $cmd").to(ArrayList(), null).exec().out
    out.filter { it.isNotBlank() }.map { it.trim() }
}

suspend fun isAbDevice(): Boolean = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val cmd = "boot-info is-ab-device"
    ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} $cmd").trim().toBoolean()
}

suspend fun getDefaultPartition(): String = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    if (shell.isRoot) {
        val cmd = "boot-info default-partition"
        ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} $cmd").trim()
    } else {
        if (!Os.uname().release.contains("android12-")) "init_boot" else "boot"
    }
}

suspend fun getSlotSuffix(ota: Boolean): String = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val cmd = if (ota) {
        "boot-info slot-suffix --ota"
    } else {
        "boot-info slot-suffix"
    }
    ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} $cmd").trim()
}

suspend fun getAvailablePartitions(): List<String> = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val cmd = "boot-info available-partitions"
    val out = shell.newJob().add("${getKsuDaemonPath()} $cmd").to(ArrayList(), null).exec().out
    out.filter { it.isNotBlank() }.map { it.trim() }
}

// Known vendor anti-root kernel modules that `--block-module` is meant for.
internal val KNOWN_BLOCKABLE_MODULES = listOf(
    "vr", "vklp", "oplus_secure_guard", "oplus_secure_guard_new", "mkp"
)

// Return the known anti-root modules currently loaded on this device (per
// /proc/modules), so the install screen can pre-fill only the relevant ones.
// Modules other modules use are left out: blocking one keeps its users from
// loading as well, so ksuinit refuses to block it in first stage anyway.
suspend fun getLoadedBlockableModules(): List<String> = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val out = shell.newJob().add("cat /proc/modules").to(ArrayList(), null).exec().out
    // <name> <size> <refcount> <used by, or "-"> <state> <address>
    val unused = out.mapNotNull { line ->
        val fields = line.trim().split(Regex("\\s+"))
        fields.getOrNull(0)?.takeIf { fields.getOrNull(3) == "-" }
    }.toHashSet()
    KNOWN_BLOCKABLE_MODULES.filter { it in unused }
}

fun hasMagisk(): Boolean {
    val shell = getRootShell(true)
    val result = shell.newJob().add("which magisk").exec()
    Log.i(TAG, "has magisk: ${result.isSuccess}")
    return result.isSuccess
}

fun isSepolicyValid(rules: String?): Boolean {
    if (rules == null) {
        return true
    }
    val shell = getRootShell()
    val result =
        shell.newJob().add("${getKsuDaemonPath()} sepolicy check '$rules'").to(ArrayList(), null)
            .exec()
    return result.isSuccess
}

fun getSepolicy(pkg: String): String {
    val shell = getRootShell()
    val result =
        shell.newJob().add("${getKsuDaemonPath()} profile get-sepolicy $pkg").to(ArrayList(), null)
            .exec()
    Log.i(TAG, "code: ${result.code}, out: ${result.out}, err: ${result.err}")
    return result.out.joinToString("\n")
}

fun setSepolicy(pkg: String, rules: String): Boolean {
    val shell = getRootShell()
    val result = shell.newJob().add("${getKsuDaemonPath()} profile set-sepolicy $pkg '$rules'")
        .to(ArrayList(), null).exec()
    Log.i(TAG, "set sepolicy result: ${result.code}")
    return result.isSuccess
}

fun listAppProfileTemplates(): List<String> {
    val shell = getRootShell()
    return shell.newJob().add("${getKsuDaemonPath()} profile list-templates").to(ArrayList(), null)
        .exec().out
}

fun getAppProfileTemplate(id: String): String {
    val shell = getRootShell()
    return shell.newJob().add("${getKsuDaemonPath()} profile get-template '${id}'")
        .to(ArrayList(), null).exec().out.joinToString("\n")
}

fun setAppProfileTemplate(id: String, template: String): Boolean {
    val shell = getRootShell()
    val escapedTemplate = template.replace("'", "'\\''")
    val cmd = """${getKsuDaemonPath()} profile set-template "$id" '$escapedTemplate'"""
    return shell.newJob().add(cmd)
        .to(ArrayList(), null).exec().isSuccess
}

fun deleteAppProfileTemplate(id: String): Boolean {
    val shell = getRootShell()
    return shell.newJob().add("${getKsuDaemonPath()} profile delete-template '${id}'")
        .to(ArrayList(), null).exec().isSuccess
}

fun forceStopApp(packageName: String, userId: Int? = null) {
    val shell = getRootShell()
    val userArg = userId?.let { " --user $it" } ?: ""
    val result = shell.newJob().add("am force-stop$userArg $packageName").exec()
    Log.i(TAG, "force stop $packageName result: $result")
}

fun launchApp(packageName: String, userId: Int? = null) {
    val shell = getRootShell()
    val userArg = userId?.let { " --user $it" } ?: ""
    val result =
        shell.newJob()
            .add("cmd package resolve-activity --brief$userArg $packageName | tail -n 1 | xargs cmd activity start-activity$userArg -n")
            .exec()
    Log.i(TAG, "launch $packageName result: $result")
}

fun restartApp(packageName: String, userId: Int? = null) {
    forceStopApp(packageName, userId)
    launchApp(packageName, userId)
}

// KPM鎺у埗
// KPM module names may contain spaces ("ABC EFG"): always pass names, paths and
// args through shellQuote, otherwise the shell splits them into multiple argv and
// ksud (clap) only takes the first token, so info/unload/control hit the wrong
// module or fail.
fun loadKpmModule(path: String, args: String? = null): Boolean {
    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} kpm load ${SuSFSConfig.shellQuote(path)} ${SuSFSConfig.shellQuote(args ?: "")}"
    return ShellUtils.fastCmdResult(shell, cmd)
}

fun unloadKpmModule(name: String): Boolean {
    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} kpm unload ${SuSFSConfig.shellQuote(name)}"
    return ShellUtils.fastCmdResult(shell, cmd)
}

fun getKpmModuleCount(): Int {
    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} kpm num"
    val result = ShellUtils.fastCmd(shell, cmd)
    return result.trim().toIntOrNull() ?: 0
}

fun runCmd(shell: Shell, cmd: String): String {
    return shell.newJob()
        .add(cmd)
        .to(mutableListOf<String>(), null)
        .exec().out
        .joinToString("\n")
}

suspend fun streamFile(path: String): List<String> = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val outLines = mutableListOf<String>()

    val stdoutCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            if (s != null) outLines.add(s)
        }
    }

    val stderrCallback: CallbackList<String?> = object : CallbackList<String?>() {
        override fun onAddElement(s: String?) {
            // ignore stderr for now
        }
    }

    shell.newJob().add("cat $path || true").to(stdoutCallback, stderrCallback).exec()
    outLines
}

fun listKpmModules(): String {
    return listKpmModules(getRootShell().newJob().add("${getKsuDaemonPath()} kpm list"))
}

internal fun listKpmModules(job: Shell.Job): String {
    val result = job.to(ArrayList(), ArrayList()).exec()
    check(result.isSuccess) {
        result.err.joinToString("\n").ifBlank { "KPM list failed (${result.code})" }
    }
    // ksud can report a kernel error on stdout while exiting successfully.
    check(result.out.none { it.trimStart().startsWith("Failed to get kpm list:") }) {
        result.out.joinToString("\n")
    }
    return result.out.joinToString("\n").trim()
}

fun getKpmModuleInfo(name: String): String {
    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} kpm info ${SuSFSConfig.shellQuote(name)}"
    return try {
        runCmd(shell, cmd).trim()
    } catch (e: Exception) {
        Log.e(TAG, "Failed to get KPM module info: $name", e)
        ""
    }
}

fun controlKpmModule(name: String, args: String? = null): Int {
    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} kpm control ${SuSFSConfig.shellQuote(name)} ${SuSFSConfig.shellQuote(args ?: "")}"
    val result = runCmd(shell, cmd)
    return result.trim().toIntOrNull() ?: -1
}

fun getKpmVersion(): String {
    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} kpm version"
    val result = ShellUtils.fastCmd(shell, cmd)
    return result.trim()
}

fun getSuSFSStatus(): String {
    val shell = getRootShell()
    return ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} susfs status").trim()
}

fun getSuSFSVersion(): String {
    val shell = getRootShell()
    val result = ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} susfs version")
    return result
}

fun getSuSFSVariant(): String {
    val shell = getRootShell()
    return ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} susfs variant").trim()
}

fun getSuSFSImplementation(): String {
    val shell = getRootShell()
    return ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} susfs implementation").trim()
}

fun getSuSFSFeatures(): String {
    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} susfs features"
    return runCmd(shell, cmd)
}

fun spoofKernelUname(release: String, version: String): Boolean {
    fun shellQuote(value: String): String = "'${value.replace("'", "'\\''")}'"

    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} kernel spoof-uname --release ${shellQuote(release)} --version ${shellQuote(version)}"
    val result = ShellUtils.fastCmdResult(shell, cmd)
    Log.i(TAG, "kernel spoof-uname result: $result")
    return result
}

fun spoofCpu(
    cpu: Int,
    midr: String,
    bogomips: Int,
    hwcap: String,
    hwcap2: String,
): Boolean {
    val shell = getRootShell()
    fun shellQuote(value: String): String = "'${value.replace("'", "'\\''")}'"
    val cmd = buildString {
        append("${getKsuDaemonPath()} kernel spoof-cpu")
        append(" --cpu $cpu")
        append(" --midr ${shellQuote(midr)}")
        if (bogomips > 0) append(" --bogomips $bogomips")
        if (hwcap.isNotBlank()) append(" --hwcap ${shellQuote(hwcap)}")
        if (hwcap2.isNotBlank()) append(" --hwcap2 ${shellQuote(hwcap2)}")
    }
    val result = ShellUtils.fastCmdResult(shell, cmd)
    Log.i(TAG, "kernel spoof-cpu result: $result")
    return result
}

fun addUmountPath(path: String, flags: Int): Boolean {
    val shell = getRootShell()
    val flagsArg = if (flags >= 0) "--flags $flags" else ""
    val cmd = "${getKsuDaemonPath()} umount add $path $flagsArg"
    val result = ShellUtils.fastCmdResult(shell, cmd)
    Log.i(TAG, "add umount path $path result: $result")
    return result
}

fun removeUmountPath(path: String): Boolean {
    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} umount remove $path"
    val result = ShellUtils.fastCmdResult(shell, cmd)
    Log.i(TAG, "remove umount path $path result: $result")
    return result
}

fun listUmountPaths(): String {
    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} umount list"
    return try {
        runCmd(shell, cmd).trim()
    } catch (e: Exception) {
        Log.e(TAG, "Failed to list umount paths", e)
        ""
    }
}

fun clearCustomUmountPaths(): Boolean {
    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} umount clear-custom"
    val result = ShellUtils.fastCmdResult(shell, cmd)
    Log.i(TAG, "clear custom umount paths result: $result")
    return result
}

fun saveUmountConfig(): Boolean {
    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} umount save"
    val result = ShellUtils.fastCmdResult(shell, cmd)
    Log.i(TAG, "save umount config result: $result")
    return result
}

fun applyUmountConfigToKernel(): Boolean {
    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} umount apply"
    val result = ShellUtils.fastCmdResult(shell, cmd)
    Log.i(TAG, "apply umount config to kernel result: $result")
    return result
}

data class BootConfig(
    val allowShell: Boolean = false,
    val spoofRelease: String = "",
    val spoofVersion: String = "",
)

// 璇诲彇闀滃儚涓殑 ksu_config 鍙傛暟
suspend fun getBootConfig(): BootConfig = withContext(Dispatchers.IO) {
    val shell = getRootShell()
    val cmd = "${getKsuDaemonPath()} boot-info read-config"
    val out = shell.newJob().add(cmd).to(ArrayList(), null).exec().out

    var allowShell = false
    var spoofRelease = ""
    var spoofVersion = ""

    for (line in out) {
        when {
            line.startsWith("allow_shell=") -> allowShell = line.substringAfter("=").trim() == "1"
            line.startsWith("spoof_release=") -> {
                spoofRelease = parseQuotedValue(line.substringAfter("spoof_release="))
            }
            line.startsWith("spoof_version=") -> {
                spoofVersion = parseQuotedValue(line.substringAfter("spoof_version="))
            }
        }
    }

    BootConfig(allowShell, spoofRelease, spoofVersion)
}

private fun parseQuotedValue(value: String): String {
    val trimmed = value.trim()
    val inner = when {
        trimmed.length >= 2 && trimmed.startsWith("\"") && trimmed.endsWith("\"") ->
            trimmed.substring(1, trimmed.length - 1)
        trimmed.length >= 2 && trimmed.startsWith("'") && trimmed.endsWith("'") ->
            trimmed.substring(1, trimmed.length - 1)
        else -> trimmed
    }
    // ksud boot-patch escapes '"' and '\' inside quoted values; undo it here
    if ('\\' !in inner) return inner
    val sb = StringBuilder(inner.length)
    var i = 0
    while (i < inner.length) {
        val c = inner[i]
        if (c == '\\' && i + 1 < inner.length && (inner[i + 1] == '"' || inner[i + 1] == '\\')) {
            sb.append(inner[i + 1])
            i += 2
        } else {
            sb.append(c)
            i += 1
        }
    }
    return sb.toString()
}

data class DynamicManagerEntry(val packageName: String, val certSize: Int, val hash: String, val uid: Int)
data class DynamicManagerState(val enabled: Boolean, val entries: List<DynamicManagerEntry>)
data class DynamicManagerSignature(val certSize: Int, val hash: String)

private suspend fun runDynamicManagerCommand(vararg args: String): String = withContext(Dispatchers.IO) {
    val command = "${getKsuDaemonPath()} " + args.joinToString(" ") { it.ksudShellArg() }
    val output = runCmd(getRootShell(), "$command; printf '\\n__KSUD_EXIT_CODE__:%s' $? ")
    val marker = Regex("\\n__KSUD_EXIT_CODE__:(\\d+)$").find(output)
        ?: error("ksud command did not return an exit status")
    check(marker.groupValues[1] == "0") { output.substringBefore(marker.value).ifBlank { "ksud command failed" } }
    output.substringBefore(marker.value)
}

private fun String.ksudShellArg(): String = "'${replace("'", "'\\''")}'"

suspend fun getDynamicManagers(): DynamicManagerState {
    val lines = runDynamicManagerCommand("manager", "list").lines()
    val enabled = lines.firstOrNull { it.startsWith("enabled:") }
        ?.substringAfter(':')?.trim()?.toBooleanStrictOrNull() ?: false
    val entries = lines.drop(1).filter { it.isNotBlank() }.mapNotNull { line ->
        val fields = line.split('\t')
        if (fields.size < 4) return@mapNotNull null
        DynamicManagerEntry(
            packageName = fields[0],
            certSize = fields[1].toIntOrNull() ?: return@mapNotNull null,
            hash = fields[2],
            uid = fields[3].toIntOrNull() ?: return@mapNotNull null,
        )
    }
    return DynamicManagerState(enabled, entries)
}

suspend fun setDynamicManagersEnabled(enabled: Boolean) {
    runDynamicManagerCommand("manager", "set-enabled", enabled.toString())
}

suspend fun removeDynamicManager(packageName: String) {
    runDynamicManagerCommand("manager", "remove", packageName)
}

suspend fun getDynamicManagerSignature(apkPath: String): DynamicManagerSignature {
    val output = runDynamicManagerCommand("debug", "get-sign", apkPath)
    val size = Regex("size:\\s*(0x[0-9a-fA-F]+|[0-9]+)").find(output)?.groupValues?.get(1)
        ?: error("Could not parse signature size")
    val certSize = if (size.startsWith("0x")) size.substring(2).toLong(16).toInt() else size.toInt()
    val hash = Regex("hash:\\s*([0-9a-fA-F]{64})").find(output)?.groupValues?.get(1)
        ?: error("Could not parse signature hash")
    return DynamicManagerSignature(certSize, hash)
}

suspend fun addDynamicManager(packageName: String, signature: DynamicManagerSignature) {
    runDynamicManagerCommand("manager", "add", packageName, signature.certSize.toString(), signature.hash)
}

data class BuiltinZygiskStatus(
    val enabled: Boolean = false,
    val monitorRunning: Boolean = false,
    val daemonRunning: Boolean = false,
)

fun getBuiltinZygiskStatus(): BuiltinZygiskStatus {
    return runCatching {
        val shell = getRootShell()
        val out = ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} zygisk status").trim()
        val json = org.json.JSONObject(out)
        BuiltinZygiskStatus(
            enabled = json.optBoolean("enabled", false),
            monitorRunning = json.optBoolean("monitor_running", false),
            daemonRunning = json.optBoolean("daemon_running", false)
        )
    }.getOrDefault(BuiltinZygiskStatus())
}

fun setBuiltinZygiskEnabled(enabled: Boolean): Boolean {
    val shell = getRootShell()
    val action = if (enabled) "on" else "off"
    val out = ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} zygisk $action").trim()
    return out == "true"
}

fun rearmBuiltinZygisk(): Boolean {
    return runCatching {
        val shell = getRootShell()
        val out = ShellUtils.fastCmd(shell, "${getKsuDaemonPath()} zygisk rearm").trim()
        out == "true"
    }.getOrDefault(false)
}
