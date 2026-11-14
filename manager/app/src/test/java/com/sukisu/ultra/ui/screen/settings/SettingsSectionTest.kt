package com.sukisu.ultra.ui.screen.settings

import org.junit.Assert.assertEquals
import org.junit.Test

class SettingsSectionTest {

    @Test
    fun settingsSectionsResolvePreciseAliases() {
        assertEquals(SettingsSection.UI_MODE, SettingsSection.normalize("ui_mode"))
        assertEquals(SettingsSection.GENERAL, SettingsSection.cardFor("ui_mode"))
        assertEquals(SettingsSection.SECURITY, SettingsSection.cardFor("selinux_hide"))
        assertEquals(
            SettingsSection.MODULE_BEHAVIOUR,
            SettingsSection.cardFor("auto_delete_module_zip"),
        )
        assertEquals(SettingsSection.DIAGNOSTICS, SettingsSection.cardFor("diagnostics"))
        assertEquals(SettingsSection.GENERAL, SettingsSection.normalize("not_a_section"))
    }
}
