package com.sukisu.ultra.ui.screen.modulerepo

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R

/**
 * Sources that failed with the same message. They share one notice, whose title names them instead
 * of repeating the identical message once per source.
 */
internal data class SourceErrorGroup(
    val names: List<String>,
    val message: String,
)

/**
 * Groups per-source failures by their message. Insertion order is kept, so the notice order follows
 * the order the sources were reported in and does not shuffle between refreshes.
 */
internal fun groupSourceErrors(sourceErrors: Map<String, String>): List<SourceErrorGroup> =
    sourceErrors.entries
        .groupBy({ it.value }, { it.key })
        .map { (message, names) -> SourceErrorGroup(names, message) }

/**
 * Title of a shared failure notice: the sources it covers, followed by what they are — e.g.
 * "KernelSU 模块仓库" or "KernelSU, uonou.github.io 模块仓库". Names are joined with ", " like every
 * other list this app renders (authors, providers), so the separator is not a new translatable.
 */
@Composable
internal fun sourceErrorTitle(names: List<String>): String {
    val repoLabel = stringResource(R.string.module_repos)
    return remember(names, repoLabel) { "${names.joinToString(", ")} $repoLabel" }
}
