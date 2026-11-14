package com.sukisu.ultra.ui.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CustomTextTemplateTest {

    private val versionKey = CustomTextKey.HOME_UPDATE_NEW_VERSION
    private val versionTemplate = "New version %s is available, click to upgrade!"

    @Test
    fun `parameterized key splits around its placeholder`() {
        assertEquals(
            listOf("New version ", " is available, click to upgrade!"),
            versionKey.splitTemplate(versionTemplate),
        )
    }

    @Test
    fun `joining split parts restores the placeholder`() {
        assertEquals(versionTemplate, versionKey.joinTemplate(versionKey.splitTemplate(versionTemplate)))
    }

    @Test
    fun `formatting fills the version code`() {
        assertEquals(
            "New version 41131 is available, click to upgrade!",
            formatCustomText(versionTemplate, listOf(41131L)),
        )
    }

    @Test
    fun `positional placeholders are understood`() {
        val key = CustomTextKey.HOME_CI_UPDATE_AVAILABLE
        val template = "New CI build available (#%1\$d)"
        assertEquals(listOf("New CI build available (#", ")"), key.splitTemplate(template))
        assertEquals(
            "New CI build available (#41131)",
            formatCustomText(template, listOf(41131L)),
        )
    }

    @Test
    fun `text without a placeholder still shows the value`() {
        assertEquals("New version 41131", formatCustomText("New version", listOf(41131L)))
    }

    @Test
    fun `keys without arguments are left untouched`() {
        assertTrue(CustomTextKey.HOME_TITLE.formatArgs.isEmpty())
        assertEquals(
            listOf("Home"),
            CustomTextKey.HOME_TITLE.splitTemplate("Home"),
        )
        assertEquals("Home", formatCustomText("Home", emptyList()))
    }

    @Test
    fun `groups are collected from customized entries`() {
        val texts = mapOf(
            CustomTextKey.HOME_TITLE.key to "Home",
            CustomTextKey.PAGE_ABOUT.key to "About",
            CustomTextKey.SETTING_UI_MODE.key to "Mode",
            "unknown.key" to "Ignored",
        )
        assertEquals(
            setOf(CustomTextGroup.HOME, CustomTextGroup.PAGE_FEATURE, CustomTextGroup.SETTINGS),
            customTextGroupsIn(texts),
        )
        assertEquals(
            setOf(CustomTextGroup.HOME),
            customTextGroupsIn(emptyMap(), customHomeTitle = "Home"),
        )
    }

    @Test
    fun `filtering keeps only the selected groups`() {
        val texts = mapOf(
            CustomTextKey.HOME_TITLE.key to "Home",
            CustomTextKey.PAGE_ABOUT.key to "About",
        )
        assertEquals(
            mapOf(CustomTextKey.HOME_TITLE.key to "Home"),
            customTextsInGroups(texts, setOf(CustomTextGroup.HOME)),
        )
    }
}
