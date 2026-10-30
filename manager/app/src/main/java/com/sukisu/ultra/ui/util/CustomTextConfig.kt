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
}

enum class CustomTextKey(
    val key: String,
    @StringRes val nameRes: Int,
    @StringRes val defaultRes: Int,
    val group: CustomTextGroup,
) {
    // 首頁抬頭
    HOME_TITLE("home.title", R.string.settings_home_title, R.string.app_name, CustomTextGroup.HOME),

    // 首頁狀態英雄卡
    HOME_STATUS_WORKING("home.status_working", R.string.home_working, R.string.home_working, CustomTextGroup.HOME),
    HOME_BTN_INSTALL("home.btn_install", R.string.home_click_to_install, R.string.home_click_to_install, CustomTextGroup.HOME),
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
    HOME_UPDATE_NEW_VERSION("home.update_new_version", R.string.new_version_available, R.string.new_version_available, CustomTextGroup.HOME),

    // 主要分頁抬頭 (Tab 列對應的頂部抬頭)
    PAGE_SUPERUSER("page.superuser", R.string.superuser, R.string.superuser, CustomTextGroup.PAGE_MAIN),
    PAGE_MODULES("page.modules", R.string.module, R.string.module, CustomTextGroup.PAGE_MAIN),
    PAGE_SETTINGS("page.settings", R.string.settings, R.string.settings, CustomTextGroup.PAGE_MAIN),

    // 功能與設定頁面抬頭 (排除偽裝與隱藏)
    PAGE_APPEARANCE("page.appearance", R.string.settings_theme, R.string.settings_theme, CustomTextGroup.PAGE_FEATURE),
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
    PAGE_INSTALL("page.install", R.string.install, R.string.install, CustomTextGroup.PAGE_FEATURE);

    companion object {
        fun fromKey(key: String): CustomTextKey? = entries.find { it.key == key }
    }
}

object CustomTextManager {
    fun resolve(key: CustomTextKey, customTexts: Map<String, String>, context: Context): String {
        val custom = customTexts[key.key]
        return if (!custom.isNullOrBlank()) custom else context.getString(key.defaultRes)
    }
}

@Composable
fun customText(key: CustomTextKey): String {
    val custom = LocalCustomTexts.current[key.key]
    return if (!custom.isNullOrBlank()) custom else stringResource(key.defaultRes)
}
