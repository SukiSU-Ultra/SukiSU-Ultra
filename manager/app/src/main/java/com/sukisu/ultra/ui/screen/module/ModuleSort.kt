package com.sukisu.ultra.ui.screen.module

import com.sukisu.ultra.data.model.Module
import java.text.Collator
import java.util.Locale

internal data class ModuleSortOptions(
    val enabledFirst: Boolean = false,
    val metamoduleFirst: Boolean = false,
    val zygiskFirst: Boolean = false,
    val webUiFirst: Boolean = false,
    val actionFirst: Boolean = false,
    val nameOrder: ModuleNameSort = ModuleNameSort.DEFAULT,
    val manual: Boolean = false,
    val manualOrder: List<String> = emptyList(),
)

/**
 * Sorts [modules] according to [options]. Active sort keys apply in this order:
 * enabled > metamodule > Zygisk > WebUI > action, with the name order as the tie-break.
 */
internal fun sortModules(
    modules: List<Module>,
    options: ModuleSortOptions,
    locale: Locale = Locale.getDefault(),
): List<Module> {
    if (!options.manual) return modules.sortedWith(moduleComparator(options, locale))

    val byId = modules.associateBy { it.id }
    val ordered = options.manualOrder.mapNotNullTo(mutableListOf()) { byId[it] }
    val orderedIds = ordered.mapTo(HashSet()) { it.id }
    ordered += modules.filter { it.id !in orderedIds }.sortedWith(moduleComparator(options, locale))
    return ordered
}

private fun moduleComparator(options: ModuleSortOptions, locale: Locale): Comparator<Module> {
    val collator = Collator.getInstance(locale)
    val comparator = compareBy<Module>(
        { if (options.enabledFirst) if (it.enabled) 0 else 1 else 0 },
        { if (options.metamoduleFirst) if (it.metamodule) 0 else 1 else 0 },
        { if (options.zygiskFirst) if (it.zygisk) 0 else 1 else 0 },
        { if (options.webUiFirst) if (it.hasWebUi) 0 else 1 else 0 },
        { if (options.actionFirst) if (it.hasWebUi || it.hasActionScript) 0 else 1 else 0 },
    )
    return when (options.nameOrder) {
        ModuleNameSort.DEFAULT -> comparator.thenBy(collator, Module::id)
        ModuleNameSort.ASCENDING -> comparator
            .thenBy(collator) { it.name.ifBlank { it.id } }
            .thenBy(collator, Module::id)

        ModuleNameSort.DESCENDING -> comparator
            .thenByDescending(collator) { it.name.ifBlank { it.id } }
            .thenBy(collator, Module::id)
    }
}
