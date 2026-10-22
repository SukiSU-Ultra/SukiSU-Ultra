package com.sukisu.ultra.ui.screen.susfs

import com.sukisu.ultra.ui.screen.susfs.util.SuSFSConfig
import com.sukisu.ultra.ui.screen.susfs.util.moduleConfigFromValues
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ModuleConfigTest {
    @Test
    fun shouldKeepDefaults_whenConfigurationIsEmpty() {
        val config = moduleConfigFromValues(emptyMap())

        assertEquals("default", config.unameValue)
        assertEquals("default", config.buildTimeValue)
        assertFalse(config.autoStartEnabled)
        assertFalse(config.hideSusMountsForAllProcs)
        assertFalse(config.enableHideBl)
        assertFalse(config.hasAutoStartConfig())
    }

    @Test
    fun shouldKeepDelimitersAndWhitespace_whenReadingPathSets() {
        val config = moduleConfigFromValues(mapOf(
            SuSFSConfig.KEY_SUS_PATHS to "/a=b;/space path;;/a=b;  /quoted'path  ;\n",
            SuSFSConfig.KEY_KSTAT_CONFIGS to "/a|1|2;;/b|3|4;;",
        ))

        assertEquals(setOf("/a=b", "/space path", "  /quoted'path  "), config.susPaths)
        assertEquals(setOf("/a|1|2", "/b|3|4"), config.kstatConfigs)
        assertTrue(config.hasAutoStartConfig())
    }

    @Test
    fun shouldNormalizeScalarValuesOnly_whenReadingSnapshot() {
        val config = moduleConfigFromValues(mapOf(
            SuSFSConfig.KEY_UNAME_VALUE to "  kernel=value\n ",
            SuSFSConfig.KEY_AUTO_START_ENABLED to " true ",
            SuSFSConfig.KEY_EXECUTE_IN_POST_FS_DATA to "TRUE",
            SuSFSConfig.KEY_CMDLINE_OR_BOOTCONFIG_PATH to " /data/quoted\"path ",
        ))

        assertEquals("kernel=value", config.unameValue)
        assertTrue(config.autoStartEnabled)
        assertFalse(config.executeInPostFsData)
        assertEquals("/data/quoted\"path", config.cmdlineOrBootconfigPath)
    }
}
