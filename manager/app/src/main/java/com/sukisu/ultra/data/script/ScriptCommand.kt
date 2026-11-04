package com.sukisu.ultra.data.script


data class ScriptHostInfo(
    val ksuVersion: String,
    val ksuVersionCode: Int,
    val kernelVersionCode: Int,
    val lateLoad: Boolean,
)

/**
 * Builds the shell command that runs a one-shot script's action.sh. Every variable value is
 * single-quoted; only `$PATH` itself is left to the shell to expand.
 */
object ScriptCommand {
    const val BIN_DIR = "/data/adb/ksu/bin"
    const val BUSYBOX = "$BIN_DIR/busybox"
    const val ENTRY = "action.sh"

    private val ENV_NAME = Regex("^[A-Za-z_][A-Za-z0-9_]*$")

    
    fun quote(value: String): String {
        require('\u0000' !in value) { "NUL cannot be passed through a shell" }
        return "'" + value.replace("'", "'\\''") + "'"
    }

    /**
     * Environment of a run, in order. [values] are the user's inputs per param key (missing
     * keys use the default); throws [IllegalArgumentException] if any of them is invalid.
     */
    fun environment(
        host: ScriptHostInfo,
        moduleId: String,
        dir: String,
        params: ScriptParams,
        values: Map<String, String>,
    ): List<Pair<String, String>> {
        val env = mutableListOf(
            "ASH_STANDALONE" to "1",
            "KSU" to "true",
            "KSU_VER" to host.ksuVersion,
            "KSU_VER_CODE" to host.ksuVersionCode.toString(),
            "KSU_KERNEL_VER_CODE" to host.kernelVersionCode.toString(),
        )
        if (host.lateLoad) env += "KSU_LATE_LOAD" to "1"
        env += "KSU_MODULE" to moduleId
        env += "KSU_ONESHOT" to "1"
        env += "MODPATH" to dir
        for (param in params.params) {
            val value = values[param.key] ?: param.defaultValue
            param.validate(value)?.let { throw IllegalArgumentException("${param.key}: $it") }
            env += param.envName to param.canonical(value)
        }
        return env
    }

    
    fun build(dir: String, env: List<Pair<String, String>>): String = buildString {
        append("cd ").append(quote(dir)).append(" && ")
        for ((name, value) in env) {
            require(ENV_NAME.matches(name) && name != "PATH") { "Invalid variable name: $name" }
            append(name).append('=').append(quote(value)).append(' ')
        }
        append("PATH=\"\$PATH\":").append(quote(BIN_DIR)).append(' ')
        append(quote(BUSYBOX)).append(" sh ./").append(ENTRY)
        // libsu feeds commands through the shell's stdin: the script must never read from it.
        append(" </dev/null")
    }
}


enum class ScriptOutcome {
    SUCCESS,

    
    NOT_APPLICABLE,
    FAILURE;

    companion object {
        const val EXIT_NOT_APPLICABLE = 2

        fun of(exitCode: Int): ScriptOutcome = when (exitCode) {
            0 -> SUCCESS
            EXIT_NOT_APPLICABLE -> NOT_APPLICABLE
            else -> FAILURE
        }
    }
}
