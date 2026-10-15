package com.sukisu.ultra.ui.screen.sukisufs

import android.util.Log
import com.sukisu.ultra.ui.util.getKsuDaemonPath
import com.sukisu.ultra.ui.util.getRootShell

private const val TAG = "SukisuFs"

/**
 * Bridge to the kernelsu userspace component (ksud). All calls
 * are forwarded to `ksud sukisu-fs ...` subcommands; failures are
 * surfaced as thrown exceptions so the screen can render an error.
 */

private data class KsudResult(val code: Int, val output: String)

private fun runKsud(vararg args: String): KsudResult {
    val shell = getRootShell()
    val cmd = listOf(getKsuDaemonPath(), "sukisu-fs", *args)
    val joined = cmd.joinToString(" ")
    val out = shell.newJob()
        .add(joined)
        .to(ArrayList<String>(), null)
        .exec()
    val text = out.out.joinToString("\n")
    Log.d(TAG, "ksud $joined -> code=${out.code}\n$text")
    if (!out.isSuccess) {
        throw RuntimeException("ksud $joined failed: ${out.err.joinToString("\n")}")
    }
    return KsudResult(out.code, text)
}

fun sukisuFsGetStatus(): SukisuFsMountState {
    val result = runKsud("mount-status")
    val parts = result.output.trim().split("\n", limit = 2)
    return if (parts.isEmpty() || parts[0].isBlank()) {
        SukisuFsMountState(mounted = false, source = null, target = null)
    } else if (parts[0].startsWith("MOUNTED") && parts.size > 1) {
        val (src, tgt) = parts[1].split("->", limit = 2).let {
            it.getOrNull(0).orEmpty().trim() to it.getOrNull(1).orEmpty().trim()
        }
        SukisuFsMountState(mounted = true, source = src, target = tgt)
    } else {
        SukisuFsMountState(mounted = false, source = null, target = null)
    }
}

fun sukisuFsMount(source: String, target: String) {
    Log.i(TAG, "sukisuFsMount source=$source target=$target")
    runKsud("mount", source, target)
}

fun sukisuFsUnmount(target: String) {
    Log.i(TAG, "sukisuFsUnmount target=$target")
    runKsud("umount", target)
}

fun sukisuFsAddRule(rule: SukisuFsRule) {
    val viewName = rule.view.name.lowercase()
    Log.i(TAG, "sukisuFsAddRule view=$viewName [${rule.uidMin}..${rule.uidMax}] ${rule.path}")
    runKsud(
        "rule-add",
        "--view", viewName,
        "--uid-min", rule.uidMin.toString(),
        "--uid-max", rule.uidMax.toString(),
        rule.path,
    )
}

fun sukisuFsRemoveRule(path: String) {
    Log.i(TAG, "sukisuFsRemoveRule $path")
    runKsud("rule-rm", path)
}

fun sukisuFsClearRules() {
    Log.i(TAG, "sukisuFsClearRules")
    runKsud("rule-clear")
}

fun sukisuFsListRules(): List<SukisuFsRule> {
    val out = runKsud("rule-list").output
    val rules = mutableListOf<SukisuFsRule>()
    out.lineSequence()
        .filter { it.isNotBlank() }
        .forEach { line ->
            val parts = line.split('\t')
            if (parts.size < 4) return@forEach
            val view = runCatching { SukisuFsView.valueOf(parts[0].uppercase()) }
                .getOrDefault(SukisuFsView.HIDE)
            val uidMin = parts[1].toIntOrNull() ?: return@forEach
            val uidMax = parts[2].toIntOrNull() ?: return@forEach
            rules += SukisuFsRule(view, uidMin, uidMax, parts[3])
        }
    return rules
}
