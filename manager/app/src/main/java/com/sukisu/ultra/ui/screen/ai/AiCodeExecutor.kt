package com.sukisu.ultra.ui.screen.ai

import com.sukisu.ultra.R
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.util.withNewRootShell
import com.topjohnwu.superuser.CallbackList
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration.Companion.milliseconds

/**
 * Runs a shell code block the user explicitly confirmed. This is intentionally
 * manual-only: the model never invokes it through a tool, the setting is off by
 * default, and every tap opens a confirmation dialog first.
 */
object AiCodeExecutor {

    private const val MAX_COMMAND_LENGTH = 8_000
    private const val MAX_OUTPUT_LENGTH = 20_000
    private const val TIMEOUT_MS = 60_000L

    suspend fun run(command: String): String {
        val prepared = prepare(command)
        if (prepared.isBlank()) return ksuApp.getString(R.string.ai_code_empty)
        if (prepared.length > MAX_COMMAND_LENGTH) {
            return ksuApp.getString(R.string.ai_code_too_long)
        }

        return withTimeoutOrNull(TIMEOUT_MS.milliseconds) {
            val output = runInterruptible(Dispatchers.IO) {
                runCatching {
                    withNewRootShell {
                        val stdout = CappedOutput()
                        val stderr = CappedOutput()
                        val result = newJob().add(prepared).to(stdout, stderr).exec()
                        val text = buildString {
                            if (stdout.isNotEmpty()) append(stdout.joinToString("\n"))
                            if (stderr.isNotEmpty()) {
                                if (isNotEmpty()) append("\n")
                                append(stderr.joinToString("\n"))
                            }
                            if (isNotEmpty()) append("\n")
                            append("[exit ${result.code}]")
                        }
                        text
                    }
                }.getOrElse { error ->
                    error.message ?: error.javaClass.simpleName
                }
            }
            if (output.isBlank()) {
                ksuApp.getString(R.string.ai_code_output_empty)
            } else if (output.length > MAX_OUTPUT_LENGTH) {
                output.take(MAX_OUTPUT_LENGTH) + "\n…"
            } else {
                output
            }
        } ?: ksuApp.getString(R.string.ai_code_timeout, (TIMEOUT_MS / 1000).toInt())
    }

    /**
     * Models often render terminal transcripts with a leading `$ `. Strip it only
     * when every command line uses that prompt, so `$HOME` and similar variables
     * are left untouched.
     */
    /** Keep a runaway command from holding an unbounded output buffer. */
    private class CappedOutput : CallbackList<String?>() {
        val lines = ArrayList<String>()
        private var chars = 0

        override fun onAddElement(s: String?) {
            if (s == null || chars >= MAX_OUTPUT_LENGTH) return
            val remaining = MAX_OUTPUT_LENGTH - chars
            val text = if (s.length > remaining) s.take(remaining) else s
            lines += text
            chars += text.length
        }
    }

    internal fun prepare(code: String): String {
        val trimmed = code.trim().trim('\n')
        if (trimmed.isEmpty()) return ""
        if (trimmed.indexOf('\u0000') >= 0) return ""
        val lines = trimmed.lines()
        val commands = lines.filter { line ->
            line.isNotBlank() && !line.trimStart().startsWith("#")
        }
        if (commands.isEmpty() || commands.any { !it.trimStart().startsWith("$ ") }) {
            return trimmed
        }
        return lines.joinToString("\n") { line ->
            val leading = line.takeWhile { it == ' ' || it == '\t' }
            val body = line.removePrefix(leading)
            if (body.startsWith("$ ")) leading + body.removePrefix("$ ") else line
        }
    }
}
