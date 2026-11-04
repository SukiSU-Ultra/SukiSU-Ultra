package com.sukisu.ultra.ui.screen.extensions

import com.sukisu.ultra.ui.util.getKsuDaemonPath
import com.sukisu.ultra.ui.util.withNewRootShell
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject


object VersionSpoofRepository {
    fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    suspend fun command(args: String): String = withContext(Dispatchers.IO) {
        withNewRootShell {
            val output = mutableListOf<String>()
            val errors = mutableListOf<String>()
            val result = newJob()
                .add("${quote(getKsuDaemonPath())} extension version-spoof $args")
                .to(output, errors).exec()
            check(result.isSuccess) {
                errors.joinToString("\n").ifBlank {
                    output.joinToString("\n").ifBlank { "Version command failed" }
                }
            }
            output.joinToString("\n")
        }
    }

    suspend fun isWarningHidden(): Boolean = try {
        command("warning-get").trim() == "true"
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        false
    }

    /**
     * Probe extension support, warning state, and whether the user has actually
     * set a spoofed value — using two root calls.
     *
     * Returns [VersionSpoofProbe]; unsupported kernels report a default instance.
     */
    suspend fun probeWarning(): VersionSpoofProbe = try {
        val warningHidden = command("warning-get").trim() == "true"
        val json = JSONObject(command("get"))
        val spoofed = json.optLong("version", 0) != json.optLong("defaultVersion", 0) ||
            json.optLong("uapi", 0) != json.optLong("defaultUapi", 0) ||
            json.optString("full", "") != json.optString("defaultFull", "")
        VersionSpoofProbe(supported = true, warningHidden = warningHidden, isSpoofed = spoofed)
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        VersionSpoofProbe(supported = false, warningHidden = false, isSpoofed = false)
    }

    suspend fun setWarningHidden(hidden: Boolean) {
        command(if (hidden) "warning-set --hidden" else "warning-set")
    }
}

/**
 * Snapshot of the version-spoof extension state relevant to the home screen.
 *
 * - [supported]: the kernel has a registered handler for the extension.
 * - [warningHidden]: the user dismissed the warning from the version-spoof sub-screen.
 * - [isSpoofed]: the user has actually set a spoofed value (differs from the kernel default).
 *   The home warning is only meaningful when this is true; without a spoof the version
 *   mismatch simply means an update is needed, not that the spoof is broken.
 */
data class VersionSpoofProbe(
    val supported: Boolean,
    val warningHidden: Boolean,
    val isSpoofed: Boolean,
)
