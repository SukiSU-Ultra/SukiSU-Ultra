package com.sukisu.ultra.ai

/**
 * Runs a shell code block the user explicitly confirmed. This is intentionally
 * manual-only: the model never invokes it through a tool, the setting is off by
 * default, and every tap opens a confirmation dialog first.
 *
 * The command executes through [AiHost.executeRootShell]; the library only
 * normalizes model-formatted transcripts and formats the result.
 */
object AiCodeExecutor {

    private const val MAX_COMMAND_LENGTH = 8_000
    private const val MAX_OUTPUT_LENGTH = 20_000
    private const val TIMEOUT_MS = 60_000L

    suspend fun run(command: String): String {
        val prepared = prepare(command)
        if (prepared.isBlank()) return aiContext.getString(R.string.ai_code_empty)
        if (prepared.length > MAX_COMMAND_LENGTH) {
            return aiContext.getString(R.string.ai_code_too_long)
        }

        val result = AiAssistant.requireHost().executeRootShell(prepared)
        if (result.timedOut) {
            return aiContext.getString(R.string.ai_code_timeout, (TIMEOUT_MS / 1000).toInt())
        }
        val text = buildString {
            if (result.output.isNotEmpty()) append(result.output.trimEnd())
            if (isNotEmpty()) append("\n")
            append("[exit ${result.exitCode}]")
        }
        return if (text.length > MAX_OUTPUT_LENGTH) {
            text.take(MAX_OUTPUT_LENGTH) + "\n…"
        } else {
            text
        }
    }

    /**
     * Models often render terminal transcripts with a leading `$ `. Strip it only
     * when every command line uses that prompt, so `$HOME` and similar variables
     * are left untouched.
     */
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
