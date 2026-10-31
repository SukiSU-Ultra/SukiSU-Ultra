package com.sukisu.ultra.ui.screen.settings

/**
 * Stable anchors used by the AI assistant to scroll the Settings page to an
 * exact card or row. Aliases let a precise setting id resolve to the card that
 * contains it when the row is not individually registered.
 */
object SettingsSection {

    const val GENERAL = "general"
    const val PROFILE_TEMPLATES = "profile_templates"
    const val EXTENSIONS = "extensions"
    const val TOOLS = "tools"
    const val TEMPORARY_ROOT = "temporary_root"
    const val SECURITY = "security"
    const val MODULE_BEHAVIOUR = "module_behaviour"
    const val UNINSTALL = "uninstall"
    const val DIAGNOSTICS = "diagnostics"

    // Individual security rows; they resolve to the security card unless the
    // screen registers a finer requester.
    const val SU_COMPAT = "su_compat"
    const val KERNEL_UMOUNT = "kernel_umount"
    const val SELINUX_HIDE = "selinux_hide"
    const val AVC_SPOOF = "avc_spoof"
    const val MOUNT_HIDE = "mount_hide"
    const val SULOG = "sulog"
    const val ADB_ROOT = "adb_root"
    const val SHELL_SU_ADB_ONLY = "shell_su_adb_only"
    const val SOFT_REBOOT = "soft_reboot"

    const val DEFAULT_UMOUNT_MODULES = "default_umount_modules"
    const val AUTO_DELETE_MODULE_ZIP = "auto_delete_module_zip"
    const val WEB_DEBUGGING = "web_debugging"
    const val AUTO_JAILBREAK = "auto_jailbreak"

    const val UI_MODE = "ui_mode"
    const val LANGUAGE = "language"
    const val THEME = "theme"

    /** All valid request ids. */
    val ALL: Set<String> = setOf(
        GENERAL, PROFILE_TEMPLATES, EXTENSIONS, TOOLS, TEMPORARY_ROOT, SECURITY,
        MODULE_BEHAVIOUR, UNINSTALL, DIAGNOSTICS,
        SU_COMPAT, KERNEL_UMOUNT, SELINUX_HIDE, AVC_SPOOF, MOUNT_HIDE, SULOG,
        ADB_ROOT, SHELL_SU_ADB_ONLY, SOFT_REBOOT,
        DEFAULT_UMOUNT_MODULES, AUTO_DELETE_MODULE_ZIP, WEB_DEBUGGING, AUTO_JAILBREAK,
        UI_MODE, LANGUAGE, THEME,
    )

    /** Map a precise setting id to the card that contains it. */
    fun cardFor(anchor: String): String = when (anchor.trim().lowercase().replace('-', '_')) {
        UI_MODE, LANGUAGE, THEME -> GENERAL
        PROFILE_TEMPLATES -> PROFILE_TEMPLATES
        EXTENSIONS -> EXTENSIONS
        TOOLS -> TOOLS
        TEMPORARY_ROOT -> TEMPORARY_ROOT
        SU_COMPAT, KERNEL_UMOUNT, SELINUX_HIDE, AVC_SPOOF, MOUNT_HIDE, SULOG,
        ADB_ROOT, SHELL_SU_ADB_ONLY, SOFT_REBOOT,
        -> SECURITY
        DEFAULT_UMOUNT_MODULES, AUTO_DELETE_MODULE_ZIP, WEB_DEBUGGING, AUTO_JAILBREAK,
        -> MODULE_BEHAVIOUR
        UNINSTALL -> UNINSTALL
        DIAGNOSTICS -> DIAGNOSTICS
        else -> GENERAL
    }

    fun normalize(anchor: String): String {
        val id = anchor.trim().lowercase().replace('-', '_')
        return if (id in ALL) id else GENERAL
    }
}
