package com.sukisu.ultra.ui.screen.module

import com.sukisu.ultra.data.model.Module
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Locale

class ModuleSortTest {

    @Test
    fun enabledOutranksMetamodule() {
        val modules = listOf(
            module("disabled-meta", enabled = false, metamodule = true),
            module("enabled-plain"),
            module("enabled-meta", metamodule = true),
        )

        val sorted = sortModules(
            modules,
            ModuleSortOptions(enabledFirst = true, metamoduleFirst = true),
            Locale.ENGLISH,
        )

        assertEquals(listOf("enabled-meta", "enabled-plain", "disabled-meta"), sorted.map { it.id })
    }

    @Test
    fun allSortKeysFollowConfiguredPriority() {
        val modules = listOf(
            module("plain", enabled = false),
            module("action", enabled = false, hasActionScript = true),
            module("webui", enabled = false, hasWebUi = true),
            module("zygisk", enabled = false, zygisk = true),
            module("meta", enabled = false, metamodule = true),
            module("enabled"),
        )

        val sorted = sortModules(
            modules,
            ModuleSortOptions(
                enabledFirst = true,
                metamoduleFirst = true,
                zygiskFirst = true,
                webUiFirst = true,
                actionFirst = true,
            ),
            Locale.ENGLISH,
        )

        assertEquals(
            listOf("enabled", "meta", "zygisk", "webui", "action", "plain"),
            sorted.map { it.id },
        )
    }

    @Test
    fun zygiskOutranksWebUiAndAction() {
        val modules = listOf(
            module("action", hasActionScript = true),
            module("webui", hasWebUi = true),
            module("zygisk", zygisk = true),
        )

        val sorted = sortModules(
            modules,
            ModuleSortOptions(zygiskFirst = true, webUiFirst = true, actionFirst = true),
            Locale.ENGLISH,
        )

        assertEquals(listOf("zygisk", "webui", "action"), sorted.map { it.id })
    }

    @Test
    fun webUiOutranksAction() {
        val modules = listOf(
            module("action", hasActionScript = true),
            module("webui", hasWebUi = true),
        )

        val sorted = sortModules(
            modules,
            ModuleSortOptions(webUiFirst = true, actionFirst = true),
            Locale.ENGLISH,
        )

        assertEquals(listOf("webui", "action"), sorted.map { it.id })
    }

    @Test
    fun defaultSortUsesModuleId() {
        val modules = listOf(
            module("b", name = "Zulu"),
            module("a", name = "Yankee"),
            module("c", name = "Xray"),
        )

        val sorted = sortModules(modules, ModuleSortOptions(), Locale.ENGLISH)

        assertEquals(listOf("a", "b", "c"), sorted.map { it.id })
    }

    @Test
    fun nameSortUsesDisplayName() {
        val modules = listOf(
            module("z", name = "alpha"),
            module("a", name = "bravo"),
            module("m", name = "charlie"),
        )

        assertEquals(
            listOf("z", "a", "m"),
            sortModules(modules, ModuleSortOptions(nameOrder = ModuleNameSort.ASCENDING), Locale.ENGLISH)
                .map { it.id },
        )
        assertEquals(
            listOf("m", "a", "z"),
            sortModules(modules, ModuleSortOptions(nameOrder = ModuleNameSort.DESCENDING), Locale.ENGLISH)
                .map { it.id },
        )
    }

    @Test
    fun blankNameFallsBackToModuleId() {
        val modules = listOf(
            module("z", name = ""),
            module("a", name = "beta"),
            module("m", name = "alpha"),
        )

        val sorted = sortModules(
            modules,
            ModuleSortOptions(nameOrder = ModuleNameSort.ASCENDING),
            Locale.ENGLISH,
        )

        assertEquals(listOf("m", "a", "z"), sorted.map { it.id })
    }

    @Test
    fun manualOrderKeepsSavedOrderAndAppendsNewModules() {
        val modules = listOf(
            module("a"),
            module("b"),
            module("c"),
            module("d"),
        )

        val sorted = sortModules(
            modules,
            ModuleSortOptions(manual = true, manualOrder = listOf("missing", "c", "a")),
            Locale.ENGLISH,
        )

        assertEquals(listOf("c", "a", "b", "d"), sorted.map { it.id })
    }

    @Test
    fun emptyManualOrderFallsBackToAutomaticSort() {
        val modules = listOf(module("b"), module("a"), module("c"))

        val sorted = sortModules(
            modules,
            ModuleSortOptions(manual = true, manualOrder = emptyList()),
            Locale.ENGLISH,
        )

        assertEquals(listOf("a", "b", "c"), sorted.map { it.id })
    }

    @Test
    fun emptyInputReturnsEmptyList() {
        assertEquals(
            emptyList<Module>(),
            sortModules(emptyList(), ModuleSortOptions(enabledFirst = true), Locale.ENGLISH),
        )
        assertEquals(
            emptyList<Module>(),
            sortModules(emptyList(), ModuleSortOptions(manual = true), Locale.ENGLISH),
        )
    }

    @Test
    fun nameSortRestoresKnownNamesAndFallsBackToDefault() {
        assertEquals(ModuleNameSort.ASCENDING, ModuleNameSort.fromStored("ASCENDING"))
        assertEquals(ModuleNameSort.DESCENDING, ModuleNameSort.fromStored("DESCENDING"))
        assertEquals(ModuleNameSort.DEFAULT, ModuleNameSort.fromStored("DEFAULT"))
        assertEquals(ModuleNameSort.DEFAULT, ModuleNameSort.fromStored(null))
        assertEquals(ModuleNameSort.DEFAULT, ModuleNameSort.fromStored("bogus"))
    }

    private fun module(
        id: String,
        name: String = id,
        enabled: Boolean = true,
        metamodule: Boolean = false,
        zygisk: Boolean = false,
        hasWebUi: Boolean = false,
        hasActionScript: Boolean = false,
    ) = Module(
        id = id,
        name = name,
        author = "",
        version = "1.0",
        versionCode = 1,
        description = "",
        enabled = enabled,
        update = false,
        remove = false,
        updateJson = "",
        hasWebUi = hasWebUi,
        hasActionScript = hasActionScript,
        metamodule = metamodule,
        zygisk = zygisk,
        actionIconPath = null,
        webUiIconPath = null,
    )
}
