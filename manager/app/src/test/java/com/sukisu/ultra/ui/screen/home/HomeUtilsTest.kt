package com.sukisu.ultra.ui.screen.home

import org.junit.Assert.assertEquals
import org.junit.Test

class HomeUtilsTest {
    @Test
    fun shouldPreferRunning_whenAnotherProviderIsEnabled() {
        val json = """[
            {"id":"pending","zygisk_provider":1,"enabled":true},
            {"id":"active","name":"Zygisk Next","version":"1.2","zygisk_provider":true,
             "zygisk_running":true,"enabled":false,"remove":true}
        ]"""

        assertEquals("Zygisk Next 1.2", implementation(json))
        assertEquals(2, getHomeModuleCount(json))
    }

    @Test
    fun shouldUseFirstRunningProvider_whenMultipleProvidersRun() {
        val json = """[
            {"id":"first","zygisk_provider":1,"zygisk_running":1},
            {"id":"second","zygisk_provider":true,"zygisk_running":true}
        ]"""

        assertEquals("first", implementation(json))
    }

    @Test
    fun shouldAcceptFlagRepresentations_whenProviderIsRunning() {
        for (flag in listOf("true", "1", "-1", "2.5", "\"true\"", "\"TRUE\"", "\"1\"", "\"1.0\"")) {
            val json = """[{"id":"provider","zygisk_provider":$flag,"zygisk_running":$flag}]"""
            assertEquals(flag, "provider", implementation(json))
        }
    }

    @Test
    fun shouldIgnoreFalseFlags_whenNoProviderIsInstalled() {
        for (flag in listOf("false", "0", "null", "\"false\"", "\"0\"", "\"invalid\"")) {
            val json = """[{"id":"module","zygisk_provider":$flag,"zygisk_running":true}]"""
            assertEquals(flag, "not installed", implementation(json))
        }
    }

    @Test
    fun shouldListEnabledProviders_whenNoneIsRunning() {
        val json = """[
            {"id":"off","zygisk_provider":1,"enabled":false},
            {"id":"removed","zygisk_provider":1,"enabled":true,"remove":true},
            {"id":"one","name":"First","zygisk_provider":1,"enabled":true},
            {"id":"two","name":" ","zygisk_provider":"true","enabled":"TRUE"}
        ]"""

        assertEquals("First, two (reboot required)", implementation(json))
    }

    @Test
    fun shouldListDisabledProviders_whenAllAreDisabledOrRemoved() {
        val json = """[
            {"id":"one","name":"First","zygisk_provider":1,"enabled":false},
            {"id":"two","zygisk_provider":1,"enabled":true,"remove":true}
        ]"""

        assertEquals("First, two (disabled)", implementation(json))
    }

    @Test
    fun shouldFallBackToId_whenNameAndVersionAreBlank() {
        val json = """[{"id":"fallback","name":" ","version":" ","zygisk_provider":1,"zygisk_running":1}]"""

        assertEquals("fallback", implementation(json))
    }

    @Test
    fun shouldIgnoreOrdinaryZygiskModules_whenProviderFlagsAreMissing() {
        val json = """[{"id":"module","zygisk":true,"enabled":true,"zygisk_running":1}]"""

        assertEquals("not installed", implementation(json))
        assertEquals(1, getHomeModuleCount(json))
    }

    @Test
    fun shouldCountAllModules_whenUsedForPreviewMode() {
        val json = """[
            {"id":"ordinary","enabled":true},
            {"id":"disabled","enabled":false},
            {"id":"removed","remove":true},
            {"id":"provider","zygisk_provider":true,"zygisk_running":true}
        ]"""

        assertEquals(4, getHomeModuleCount(json))
        assertEquals("provider", implementation(json))
    }

    @Test
    fun shouldReturnFallbacks_whenJsonIsEmptyOrMalformed() {
        for (json in listOf("[]", "", "not json", "{}", "null", "[{")) {
            assertEquals(json, "not installed", implementation(json))
            assertEquals(json, 0, getHomeModuleCount(json))
        }
    }

    @Test
    fun shouldPreserveCount_whenProviderEntryCannotBeParsed() {
        val json = """[{"zygisk_provider":true,"zygisk_running":true}]"""

        assertEquals("not installed", implementation(json))
        assertEquals(1, getHomeModuleCount(json))
    }

    private fun implementation(json: String): String = getZygiskImplementation(
        modulesJson = json,
        notInstalledText = "not installed",
        disabledText = "disabled",
        rebootRequiredText = "reboot required",
    )
}
