package com.sukisu.ultra.ui.screen.extensions

import com.sukisu.ultra.ui.util.getKsuDaemonPath
import com.sukisu.ultra.ui.util.withNewRootShell
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** All root I/O stays off the main thread. A failed read never hides a warning. */
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

    suspend fun setWarningHidden(hidden: Boolean) {
        command(if (hidden) "warning-set --hidden" else "warning-set")
    }
}
