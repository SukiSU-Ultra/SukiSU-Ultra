package com.sukisu.ultra.ui.util

import android.content.Context
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.ui.res.stringResource
import com.sukisu.ultra.R

val LocalCustomTexts = compositionLocalOf<Map<String, String>> { emptyMap() }

enum class CustomTextGroup(@StringRes val titleRes: Int) {
    HOME(R.string.custom_text_group_home),
    PAGE_MAIN(R.string.custom_text_group_page_main),
    PAGE_FEATURE(R.string.custom_text_group_page_feature),
    SETTINGS(R.string.custom_text_group_settings),
}

/** A value the app fills into a custom text template at runtime. */
enum class CustomTextArg(@StringRes val labelRes: Int) {
    VERSION_CODE(R.string.custom_text_arg_version_code),
}

enum class CustomTextKey(
    val key: String,
    @StringRes val nameRes: Int,
    @StringRes val defaultRes: Int,
    val group: CustomTextGroup,
    val formatArgs: List<CustomTextArg> = emptyList(),
) {
    // 首頁抬頭
    HOME_TITLE("home.title", R.string.settings_home_title, R.string.app_name, CustomTextGroup.HOME),

    // 首頁狀態英雄卡
    HOME_STATUS_WORKING("home.status_working", R.string.home_working, R.string.home_working, CustomTextGroup.HOME),
    HOME_STATUS_INSTALL_HINT("home.status_install_hint", R.string.home_click_to_install, R.string.home_click_to_install, CustomTextGroup.HOME),
    HOME_BTN_INSTALL("home.btn_install", R.string.install, R.string.install, CustomTextGroup.HOME),
    HOME_TAG_LKM("home.tag_lkm", R.string.home_lkm_custom, R.string.home_lkm_custom, CustomTextGroup.HOME),
    HOME_TAG_SAFEMODE("home.tag_safemode", R.string.safe_mode, R.string.safe_mode, CustomTextGroup.HOME),

    // 首頁統計卡片
    HOME_STATS_SUPERUSER("home.stats_superuser", R.string.superuser, R.string.superuser, CustomTextGroup.HOME),
    HOME_STATS_MODULE("home.stats_module", R.string.module, R.string.module, CustomTextGroup.HOME),

    // 首頁系統資訊
    HOME_INFO_KERNEL("home.info_kernel", R.string.home_kernel, R.string.home_kernel, CustomTextGroup.HOME),
    HOME_INFO_KERNEL_FULL("home.info_kernel_full", R.string.home_kernel_full_version, R.string.home_kernel_full_version, CustomTextGroup.HOME),
    HOME_INFO_MANAGER_VERSION("home.info_manager_version", R.string.home_manager_version, R.string.home_manager_version, CustomTextGroup.HOME),
    HOME_INFO_SELINUX("home.info_selinux", R.string.home_selinux_status, R.string.home_selinux_status, CustomTextGroup.HOME),
    HOME_INFO_SECCOMP("home.info_seccomp", R.string.home_seccomp_status, R.string.home_seccomp_status, CustomTextGroup.HOME),
    HOME_INFO_ZYGISK("home.info_zygisk", R.string.home_zygisk_implementation, R.string.home_zygisk_implementation, CustomTextGroup.HOME),
    HOME_INFO_HOOK_TYPE("home.info_hook_type", R.string.hook_type, R.string.hook_type, CustomTextGroup.HOME),
    HOME_INFO_DEVICE_MODEL("home.info_device_model", R.string.home_device_model, R.string.home_device_model, CustomTextGroup.HOME),
    HOME_INFO_FINGERPRINT("home.info_fingerprint", R.string.home_fingerprint, R.string.home_fingerprint, CustomTextGroup.HOME),

    // 首頁警告與更新
    HOME_WARN_VERSION_SPOOF("home.warn_version_spoof", R.string.version_spoof_home_warning, R.string.version_spoof_home_warning, CustomTextGroup.HOME),
    HOME_UPDATE_NEW_VERSION(
        "home.update_new_version",
        R.string.new_version_available,
        R.string.new_version_available,
        CustomTextGroup.HOME,
        formatArgs = listOf(CustomTextArg.VERSION_CODE),
    ),
    HOME_CI_UPDATE_AVAILABLE(
        "home.ci_update_available",
        R.string.ci_update_available,
        R.string.ci_update_available,
        CustomTextGroup.HOME,
        formatArgs = listOf(CustomTextArg.VERSION_CODE),
    ),
    HOME_CI_UPDATE_BUSY("home.ci_update_busy", R.string.ci_update_busy, R.string.ci_update_busy, CustomTextGroup.HOME),
    HOME_WARN_PR_BUILD("home.warn_pr_build", R.string.home_pr_build_warning, R.string.home_pr_build_warning, CustomTextGroup.HOME),
    HOME_WARN_PR_KERNEL("home.warn_pr_kernel", R.string.home_pr_kernel_warning, R.string.home_pr_kernel_warning, CustomTextGroup.HOME),
    HOME_WARN_REQUIRE_KERNEL("home.warn_require_kernel", R.string.require_kernel_version, R.string.require_kernel_version, CustomTextGroup.HOME),
    HOME_WARN_REQUIRE_KERNEL_GKI("home.warn_require_kernel_gki", R.string.require_kernel_version_gki, R.string.require_kernel_version_gki, CustomTextGroup.HOME),
    HOME_WARN_REQUIRE_MANAGER("home.warn_require_manager", R.string.require_manager_version, R.string.require_manager_version, CustomTextGroup.HOME),
    HOME_WARN_LKM_UPDATE("home.warn_lkm_update", R.string.home_lkm_update_available, R.string.home_lkm_update_available, CustomTextGroup.HOME),
    HOME_WARN_ROOT_FAILED("home.warn_root_failed", R.string.grant_root_failed, R.string.grant_root_failed, CustomTextGroup.HOME),
    HOME_WARN_PREVIEW_MODE("home.warn_preview_mode", R.string.home_preview_mode, R.string.home_preview_mode, CustomTextGroup.HOME),

    // 主要分頁抬頭 (底欄、側欄與對應頁面的頂部抬頭)
    PAGE_HOME("page.home", R.string.home, R.string.home, CustomTextGroup.PAGE_MAIN),
    PAGE_SUPERUSER("page.superuser", R.string.superuser, R.string.superuser, CustomTextGroup.PAGE_MAIN),
    PAGE_MODULES("page.modules", R.string.module, R.string.module, CustomTextGroup.PAGE_MAIN),
    PAGE_SETTINGS("page.settings", R.string.settings, R.string.settings, CustomTextGroup.PAGE_MAIN),

    // 功能與設定頁面抬頭 (排除偽裝與隱藏)
    PAGE_APPEARANCE("page.appearance", R.string.settings_theme, R.string.settings_theme, CustomTextGroup.PAGE_FEATURE),
    PAGE_THEME_STORE("page.theme_store", R.string.theme_store_title, R.string.theme_store_title, CustomTextGroup.PAGE_FEATURE),
    PAGE_CUSTOM_TEXTS("page.custom_texts", R.string.settings_custom_texts, R.string.settings_custom_texts, CustomTextGroup.PAGE_FEATURE),
    PAGE_APP_ICON("page.app_icon", R.string.app_icon_title, R.string.app_icon_title, CustomTextGroup.PAGE_FEATURE),
    PAGE_APP_PROFILE("page.app_profile", R.string.profile, R.string.profile, CustomTextGroup.PAGE_FEATURE),
    PAGE_TEMPLATE("page.template", R.string.settings_profile_template, R.string.settings_profile_template, CustomTextGroup.PAGE_FEATURE),
    PAGE_ABOUT("page.about", R.string.about, R.string.about, CustomTextGroup.PAGE_FEATURE),
    PAGE_UMOUNT("page.umount", R.string.umount_path_manager, R.string.umount_path_manager, CustomTextGroup.PAGE_FEATURE),
    PAGE_EXTENSIONS("page.extensions", R.string.extension_section_title, R.string.extension_section_title, CustomTextGroup.PAGE_FEATURE),
    PAGE_TOOLS("page.tools", R.string.tools, R.string.tools, CustomTextGroup.PAGE_FEATURE),
    PAGE_SULOG("page.sulog", R.string.settings_sulog, R.string.settings_sulog, CustomTextGroup.PAGE_FEATURE),
    PAGE_KERNEL_MODULES("page.kernel_modules", R.string.kernel_modules_title, R.string.kernel_modules_title, CustomTextGroup.PAGE_FEATURE),
    PAGE_DYNAMIC_MANAGERS("page.dynamic_managers", R.string.dynamic_manager_title, R.string.dynamic_manager_title, CustomTextGroup.PAGE_FEATURE),
    PAGE_MODULE_REPO("page.module_repo", R.string.module_repos, R.string.module_repos, CustomTextGroup.PAGE_FEATURE),
    PAGE_INSTALL("page.install", R.string.install, R.string.install, CustomTextGroup.PAGE_FEATURE),
    EXTENSION_KPM("extension.kpm", R.string.extension_kpm_title, R.string.extension_kpm_title, CustomTextGroup.PAGE_FEATURE),
    EXTENSION_CPU_SPOOF("extension.cpu_spoof", R.string.extension_cpu_spoof_title, R.string.extension_cpu_spoof_title, CustomTextGroup.PAGE_FEATURE),
    EXTENSION_SUSFS("extension.susfs", R.string.extension_susfs_title, R.string.extension_susfs_title, CustomTextGroup.PAGE_FEATURE),
    EXTENSION_VERSION_SPOOF("extension.version_spoof", R.string.extension_version_spoof_title, R.string.extension_version_spoof_title, CustomTextGroup.PAGE_FEATURE),

    // 設定頁項目
    SETTING_UI_MODE("settings.ui_mode", R.string.settings_ui_mode, R.string.settings_ui_mode, CustomTextGroup.SETTINGS),
    SETTING_LANGUAGE("settings.language", R.string.settings_language, R.string.settings_language, CustomTextGroup.SETTINGS),
    SETTING_SUCOMPAT("settings.sucompat", R.string.settings_sucompat, R.string.settings_sucompat, CustomTextGroup.SETTINGS),
    SETTING_KERNEL_UMOUNT("settings.kernel_umount", R.string.settings_kernel_umount, R.string.settings_kernel_umount, CustomTextGroup.SETTINGS),
    SETTING_SELINUX_HIDE("settings.selinux_hide", R.string.settings_selinux_hide, R.string.settings_selinux_hide, CustomTextGroup.SETTINGS),
    SETTING_AVC_SPOOF("settings.avc_spoof", R.string.settings_avc_spoof, R.string.settings_avc_spoof, CustomTextGroup.SETTINGS),
    SETTING_MOUNT_HIDE("settings.mount_hide", R.string.settings_mount_hide, R.string.settings_mount_hide, CustomTextGroup.SETTINGS),
    SETTING_SULOG("settings.sulog", R.string.settings_sulog, R.string.settings_sulog, CustomTextGroup.SETTINGS),
    SETTING_ADB_ROOT("settings.adb_root", R.string.settings_adb_root, R.string.settings_adb_root, CustomTextGroup.SETTINGS),
    SETTING_SHELL_SU("settings.shell_su", R.string.settings_shell_su_adb_only, R.string.settings_shell_su_adb_only, CustomTextGroup.SETTINGS),
    SETTING_SOFT_REBOOT("settings.soft_reboot", R.string.settings_soft_reboot, R.string.settings_soft_reboot, CustomTextGroup.SETTINGS),
    SETTING_UMOUNT_MODULES_DEFAULT("settings.umount_modules_default", R.string.settings_umount_modules_default, R.string.settings_umount_modules_default, CustomTextGroup.SETTINGS),
    SETTING_AUTO_DELETE_MODULE_ZIP("settings.auto_delete_module_zip", R.string.settings_auto_delete_module_zip, R.string.settings_auto_delete_module_zip, CustomTextGroup.SETTINGS),
    SETTING_WEB_DEBUGGING("settings.web_debugging", R.string.enable_web_debugging, R.string.enable_web_debugging, CustomTextGroup.SETTINGS),
    SETTING_AUTO_JAILBREAK("settings.auto_jailbreak", R.string.settings_auto_jailbreak, R.string.settings_auto_jailbreak, CustomTextGroup.SETTINGS),
    SETTING_TEMPORARY_ROOT_DURATION("settings.temporary_root_duration", R.string.temporary_root_duration_title, R.string.temporary_root_duration_title, CustomTextGroup.SETTINGS),
    SETTING_UNINSTALL("settings.uninstall", R.string.settings_uninstall, R.string.settings_uninstall, CustomTextGroup.SETTINGS),
    SETTING_SEND_LOG("settings.send_log", R.string.send_log, R.string.send_log, CustomTextGroup.SETTINGS);

    companion object {
        fun fromKey(key: String): CustomTextKey? = entries.find { it.key == key }
    }
}

/** Groups that currently have at least one customized text. */
fun customTextGroupsIn(
    customTexts: Map<String, String>,
    customHomeTitle: String = "",
): Set<CustomTextGroup> = buildSet {
    customTexts.forEach { (key, value) ->
        if (value.isNotBlank()) CustomTextKey.fromKey(key)?.let { add(it.group) }
    }
    if (customHomeTitle.isNotBlank()) add(CustomTextGroup.HOME)
}

/** Keeps only the entries that belong to [groups]. */
fun customTextsInGroups(
    customTexts: Map<String, String>,
    groups: Set<CustomTextGroup>,
): Map<String, String> = customTexts.filter { (key, _) ->
    CustomTextKey.fromKey(key)?.group?.let { it in groups } == true
}

object CustomTextManager {
    fun resolve(key: CustomTextKey, customTexts: Map<String, String>, context: Context): String {
        val custom = customTexts[key.key]
        return if (!custom.isNullOrBlank()) custom else context.getString(key.defaultRes)
    }
}

/**
 * Matches the placeholders the app fills at runtime, e.g. `%s`, `%1$s` or `%d`.
 *
 * The custom text editor never exposes these to the user: it edits the literal pieces around
 * them and [joinTemplate] puts canonical `%s` placeholders back in between.
 */
private val CustomTextFormatSpecifier = Regex("""%(?:\d+\$)?[a-zA-Z]""")

/**
 * Splits [template] into the literal pieces around its placeholders.
 *
 * Keys without arguments return the whole template. A template that has fewer placeholders
 * than the key's arguments is treated as the first piece, with empty trailing pieces, so the
 * editor still shows one input per argument.
 */
fun CustomTextKey.splitTemplate(template: String): List<String> {
    if (formatArgs.isEmpty()) return listOf(template)
    val matches = CustomTextFormatSpecifier.findAll(template).take(formatArgs.size).toList()
    if (matches.size < formatArgs.size) {
        return listOf(template) + List(formatArgs.size) { "" }
    }
    val parts = ArrayList<String>(formatArgs.size + 1)
    var start = 0
    matches.forEach { match ->
        parts += template.substring(start, match.range.first)
        start = match.range.last + 1
    }
    parts += template.substring(start)
    return parts
}

/** Joins the editable pieces back into a template with canonical `%s` placeholders. */
fun CustomTextKey.joinTemplate(parts: List<String>): String {
    if (formatArgs.isEmpty()) return parts.firstOrNull().orEmpty()
    if (parts.size != formatArgs.size + 1) return parts.joinToString("")
    return buildString {
        parts.forEachIndexed { index, part ->
            append(part)
            if (index < formatArgs.size) append("%s")
        }
    }
}

/**
 * Fills [template] with the runtime [args].
 *
 * Custom text written before placeholders were handled by the editor, or supplied by the AI
 * bridge, may have lost its placeholder; the values are then appended instead so they are not
 * silently dropped.
 */
fun formatCustomText(template: String, args: List<Any>): String {
    if (args.isEmpty()) return template
    if (!CustomTextFormatSpecifier.containsMatchIn(template)) {
        val values = args.joinToString(" ")
        return if (template.isBlank()) values else template.trimEnd() + " " + values
    }
    return try {
        String.format(template, *args.toTypedArray())
    } catch (_: IllegalArgumentException) {
        template
    }
}

@Composable
fun customText(key: CustomTextKey, vararg args: Any): String {
    val custom = LocalCustomTexts.current[key.key]
    val template = if (!custom.isNullOrBlank()) custom else stringResource(key.defaultRes)
    return formatCustomText(template, args.toList())
}

/**
 * Text shown in the custom text list: the customized value, or the default when none is set.
 *
 * Placeholders are shown as their human-readable argument labels instead of the raw `%s`
 * tokens the user should never have to write.
 */
@Composable
fun customTextSummary(key: CustomTextKey, custom: String?): String {
    val labels = key.formatArgs.map { stringResource(it.labelRes) }
    val customValue = custom?.takeIf { it.isNotBlank() }
    if (customValue != null) return formatCustomText(customValue, labels)
    val defaultText = formatCustomText(stringResource(key.defaultRes), labels)
    return stringResource(R.string.custom_text_default_value, defaultText)
}
