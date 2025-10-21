package com.sukisu.ultra.ui.susfs.util

import android.annotation.SuppressLint

/**
 * Magisk模块脚本生成器
 * 用于生成各种启动脚本的内容
 */
object ScriptGenerator {

    // 常量定义
    private const val DEFAULT_UNAME = "default"
    private const val DEFAULT_BUILD_TIME = "default"
    private const val LOG_DIR = "/data/adb/ksu/log"

    /**
     * 生成所有脚本文件
     */
    fun generateAllScripts(config: SuSFSManager.ModuleConfig): Map<String, String> {
        return mapOf(
            "service.sh" to generateServiceScript(config),
            "post-fs-data.sh" to generatePostFsDataScript(config),
            "post-mount.sh" to generatePostMountScript(config),
            "boot-completed.sh" to generateBootCompletedScript(config)
        )
    }

    // 日志相关的通用脚本片段
    private fun generateLogSetup(logFileName: String): String = """
        # 日志目录
        LOG_DIR="$LOG_DIR"
        LOG_FILE="${'$'}LOG_DIR/$logFileName"
        
        # 创建日志目录
        mkdir -p "${'$'}LOG_DIR"
        
        # 获取当前时间
        get_current_time() {
            date '+%Y-%m-%d %H:%M:%S'
        }
    """.trimIndent()

    // 二进制文件检查的通用脚本片段
    private fun generateBinaryCheck(targetPath: String): String = """
        # 检查SuSFS二进制文件
        SUSFS_BIN="$targetPath"
        if [ ! -f "${'$'}SUSFS_BIN" ]; then
            echo "$(get_current_time): SuSFS二进制文件未找到: ${'$'}SUSFS_BIN" >> "${'$'}LOG_FILE"
            exit 1
        fi
    """.trimIndent()

    /**
     * 生成service.sh脚本内容
     */
    @SuppressLint("SdCardPath")
    private fun generateServiceScript(config: SuSFSManager.ModuleConfig): String {
        return buildString {
            appendLine("#!/system/bin/sh")
            appendLine("# SuSFS Service Script")
            appendLine("# 在系统服务启动后执行")
            appendLine()
            appendLine(generateLogSetup("susfs_service.log"))
            appendLine()
            appendLine(generateBinaryCheck(config.targetPath))
            appendLine()

            if (shouldConfigureInService(config)) {
                // 添加SUS路径 (仅在不支持隐藏挂载时)
                if (!config.support158 && config.susPaths.isNotEmpty()) {
                    appendLine()
                    appendLine("until [ -d \"/sdcard/Android\" ]; do sleep 1; done")
                    appendLine("sleep 45")
                    generateSusPathsSection(config.susPaths)
                }

                // 设置uname和构建时间
                generateUnameSection(config)

                // 添加Kstat配置
                generateKstatSection(config.kstatConfigs, config.addKstatPaths)
            }

            // 添加日志设置
            generateLogSettingSection(config.enableLog)

            // 隐藏BL相关配置
            if (config.enableHideBl) {
                generateHideBlSection()
            }

            // 清理工具残留
            if (config.enableCleanupResidue) {
                generateCleanupResidueSection()
            }

            appendLine("echo \"$(get_current_time): Service脚本执行完成\" >> \"${'$'}LOG_FILE\"")
        }
    }

    /**
     * 判断是否需要在service中配置
     */
    private fun shouldConfigureInService(config: SuSFSManager.ModuleConfig): Boolean {
        return config.susPaths.isNotEmpty() ||
                config.susLoopPaths.isNotEmpty() ||
                config.kstatConfigs.isNotEmpty() ||
                config.addKstatPaths.isNotEmpty() ||
                (!config.executeInPostFsData && (config.unameValue != DEFAULT_UNAME || config.buildTimeValue != DEFAULT_BUILD_TIME))
    }

    private fun StringBuilder.generateLogSettingSection(enableLog: Boolean) {
        appendLine("# 设置日志启用状态")
        val logValue = if (enableLog) 1 else 0
        appendLine("\"${'$'}SUSFS_BIN\" enable_log $logValue")
        appendLine("echo \"$(get_current_time): 日志功能设置为: ${if (enableLog) "启用" else "禁用"}\" >> \"${'$'}LOG_FILE\"")
        appendLine()
    }

    private fun StringBuilder.generateAvcLogSpoofingSection(enableAvcLogSpoofing: Boolean) {
        appendLine("# 设置AVC日志欺骗状态")
        val avcLogValue = if (enableAvcLogSpoofing) 1 else 0
        appendLine("\"${'$'}SUSFS_BIN\" enable_avc_log_spoofing $avcLogValue")
        appendLine("echo \"$(get_current_time): AVC日志欺骗功能设置为: ${if (enableAvcLogSpoofing) "启用" else "禁用"}\" >> \"${'$'}LOG_FILE\"")
        appendLine()
    }

    private fun StringBuilder.generateSusPathsSection(susPaths: Set<String>) {
        if (susPaths.isNotEmpty()) {
            appendLine("# 添加SUS路径")
            susPaths.forEach { path ->
                appendLine("\"${'$'}SUSFS_BIN\" add_sus_path '$path'")
                appendLine("echo \"$(get_current_time): 添加SUS路径: $path\" >> \"${'$'}LOG_FILE\"")
            }
            appendLine()
        }
    }

    private fun StringBuilder.generateSusLoopPathsSection(susLoopPaths: Set<String>) {
        if (susLoopPaths.isNotEmpty()) {
            appendLine("# 添加SUS循环路径")
            susLoopPaths.forEach { path ->
                appendLine("\"${'$'}SUSFS_BIN\" add_sus_path_loop '$path'")
                appendLine("echo \"$(get_current_time): 添加SUS循环路径: $path\" >> \"${'$'}LOG_FILE\"")
            }
            appendLine()
        }
    }

    @SuppressLint("SdCardPath")
    private fun StringBuilder.generateKstatSection(
        kstatConfigs: Set<String>,
        addKstatPaths: Set<String>
    ) {
        // 添加Kstat路径
        if (addKstatPaths.isNotEmpty()) {
            appendLine("# 添加Kstat路径")
            addKstatPaths.forEach { path ->
                appendLine("\"${'$'}SUSFS_BIN\" add_sus_kstat '$path'")
                appendLine("echo \"$(get_current_time): 添加Kstat路径: $path\" >> \"${'$'}LOG_FILE\"")
            }
            appendLine()
        }

        // 添加Kstat静态配置
        if (kstatConfigs.isNotEmpty()) {
            appendLine("# 添加Kstat静态配置")
            kstatConfigs.forEach { config ->
                val parts = config.split("|")
                if (parts.size >= 13) {
                    val path = parts[0]
                    val params = parts.drop(1).joinToString("' '", "'", "'")
                    appendLine()
                    appendLine("\"${'$'}SUSFS_BIN\" add_sus_kstat_statically '$path' $params")
                    appendLine("echo \"$(get_current_time): 添加Kstat静态配置: $path\" >> \"${'$'}LOG_FILE\"")
                    appendLine()
                    appendLine("\"${'$'}SUSFS_BIN\" update_sus_kstat '$path'")
                    appendLine("echo \"$(get_current_time): 更新Kstat配置: $path\" >> \"${'$'}LOG_FILE\"")
                }
            }
            appendLine()
        }
    }

    private fun StringBuilder.generateUnameSection(config: SuSFSManager.ModuleConfig) {
        if (!config.executeInPostFsData && (config.unameValue != DEFAULT_UNAME || config.buildTimeValue != DEFAULT_BUILD_TIME)) {
            appendLine("# 设置uname和构建时间")
            appendLine("\"${'$'}SUSFS_BIN\" set_uname '${config.unameValue}' '${config.buildTimeValue}'")
            appendLine("echo \"$(get_current_time): 设置uname为: ${config.unameValue}, 构建时间为: ${config.buildTimeValue}\" >> \"${'$'}LOG_FILE\"")
            appendLine()
        }
    }

    private fun StringBuilder.generateHideBlSection() {
        appendLine("# 隐藏BL 来自 Shamiko 脚本")
        appendLine(
            """
        RESETPROP_BIN="/data/adb/ksu/bin/resetprop"
        
        check_reset_prop() {
            local NAME=$1
            local EXPECTED=$2
            local VALUE=$("${'$'}RESETPROP_BIN" ${'$'}NAME)
            [ -z ${'$'}VALUE ] || [ ${'$'}VALUE = ${'$'}EXPECTED ] || "${'$'}RESETPROP_BIN" ${'$'}NAME ${'$'}EXPECTED
        }
        
        check_missing_prop() {
            local NAME=$1
            local EXPECTED=$2
            local VALUE=$("${'$'}RESETPROP_BIN" ${'$'}NAME)
            [ -z ${'$'}VALUE ] && "${'$'}RESETPROP_BIN" ${'$'}NAME ${'$'}EXPECTED
        }
        
        check_missing_match_prop() {
            local NAME=$1
            local EXPECTED=$2
            local VALUE=$("${'$'}RESETPROP_BIN" ${'$'}NAME)
            [ -z ${'$'}VALUE ] || [ ${'$'}VALUE = ${'$'}EXPECTED ] || "${'$'}RESETPROP_BIN" ${'$'}NAME ${'$'}EXPECTED
            [ -z ${'$'}VALUE ] && "${'$'}RESETPROP_BIN" ${'$'}NAME ${'$'}EXPECTED
        }
        
        contains_reset_prop() {
            local NAME=$1
            local CONTAINS=$2
            local NEWVAL=$3
            case "$("${'$'}RESETPROP_BIN" ${'$'}NAME)" in
                *"${'$'}CONTAINS"*) "${'$'}RESETPROP_BIN" ${'$'}NAME ${'$'}NEWVAL ;;
            esac
        }
    """.trimIndent())
        appendLine()
        appendLine("sleep 30")
        appendLine()
        appendLine("\"${'$'}RESETPROP_BIN\" -w sys.boot_completed 0")

        // 添加所有系统属性重置
        val systemProps = listOf(
            "ro.boot.vbmeta.invalidate_on_error" to "yes",
            "ro.boot.vbmeta.avb_version" to "1.2",
            "ro.boot.vbmeta.hash_alg" to "sha256",
            "ro.boot.vbmeta.size" to "19968",
            "ro.boot.vbmeta.device_state" to "locked",
            "ro.boot.verifiedbootstate" to "green",
            "ro.boot.flash.locked" to "1",
            "ro.boot.veritymode" to "enforcing",
            "ro.boot.warranty_bit" to "0",
            "ro.warranty_bit" to "0",
            "ro.debuggable" to "0",
            "ro.force.debuggable" to "0",
            "ro.secure" to "1",
            "ro.adb.secure" to "1",
            "ro.build.type" to "user",
            "ro.build.tags" to "release-keys",
            "ro.vendor.boot.warranty_bit" to "0",
            "ro.vendor.warranty_bit" to "0",
            "vendor.boot.vbmeta.device_state" to "locked",
            "vendor.boot.verifiedbootstate" to "green",
            "sys.oem_unlock_allowed" to "0",
            "ro.secureboot.lockstate" to "locked",
            "ro.boot.realmebootstate" to "green",
            "ro.boot.realme.lockstate" to "1",
            "ro.crypto.state" to "encrypted"
        )

        systemProps.forEach { (prop, value) ->
            when {
                prop.startsWith("ro.boot.vbmeta") && prop.endsWith("_on_error") ->
                    appendLine("check_missing_prop \"$prop\" \"$value\"")
                prop.contains("device_state") || prop.contains("verifiedbootstate") ->
                    appendLine("check_missing_match_prop \"$prop\" \"$value\"")
                else ->
                    appendLine("check_reset_prop \"$prop\" \"$value\"")
            }
        }

        appendLine()
        appendLine("# Hide adb debugging traces")
        appendLine("resetprop \"sys.usb.adb.disabled\" \" \"")
        appendLine()

        appendLine("# Hide recovery boot mode")
        appendLine("contains_reset_prop \"ro.bootmode\" \"recovery\" \"unknown\"")
        appendLine("contains_reset_prop \"ro.boot.bootmode\" \"recovery\" \"unknown\"")
        appendLine("contains_reset_prop \"vendor.boot.bootmode\" \"recovery\" \"unknown\"")
        appendLine()

        appendLine("# Hide cloudphone detection")
        appendLine("[ -n \"$(resetprop ro.kernel.qemu)\" ] && resetprop ro.kernel.qemu \"\"")
        appendLine()
    }

    // 清理残留脚本生成
    private fun StringBuilder.generateCleanupResidueSection() {
        appendLine("# 清理工具残留文件")
        appendLine("echo \"$(get_current_time): 开始清理工具残留\" >> \"${'$'}LOG_FILE\"")
        appendLine()

        // 定义清理函数
        appendLine("""
        cleanup_path() {
            local path="$1"
            local desc="$2"
            local current="$3"
            local total="$4"
            
            if [ -n "${'$'}desc" ]; then
                echo "$(get_current_time): [${'$'}current/${'$'}total] 清理: ${'$'}path (${'$'}desc)" >> "${'$'}LOG_FILE"
            else
                echo "$(get_current_time): [${'$'}current/${'$'}total] 清理: ${'$'}path" >> "${'$'}LOG_FILE"
            fi
            
            if rm -rf "${'$'}path" 2>/dev/null; then
                echo "$(get_current_time): ✓ 成功清理: ${'$'}path" >> "${'$'}LOG_FILE"
            else
                echo "$(get_current_time): ✗ 清理失败或不存在: ${'$'}path" >> "${'$'}LOG_FILE"
            fi
        }
    """.trimIndent())

        appendLine()
        appendLine("# 开始清理各种工具残留")
        appendLine("TOTAL=33")
        appendLine()

        val cleanupPaths = listOf(
            "/data/local/stryker/" to "Stryker残留",
            "/data/system/AppRetention" to "AppRetention残留",
            "/data/local/tmp/luckys" to "Luck Tool残留",
            "/data/local/tmp/HyperCeiler" to "西米露残留",
            "/data/local/tmp/simpleHook" to "simple Hook残留",
            "/data/local/tmp/DisabledAllGoogleServices" to "谷歌省电模块残留",
            "/data/local/MIO" to "解包软件",
            "/data/DNA" to "解包软件",
            "/data/local/tmp/cleaner_starter" to "质感清理残留",
            "/data/local/tmp/byyang" to "",
            "/data/local/tmp/mount_mask" to "",
            "/data/local/tmp/mount_mark" to "",
            "/data/local/tmp/scriptTMP" to "",
            "/data/local/luckys" to "",
            "/data/local/tmp/horae_control.log" to "",
            "/data/gpu_freq_table.conf" to "",
            "/storage/emulated/0/Download/advanced/" to "",
            "/storage/emulated/0/Documents/advanced/" to "爱玩机",
            "/storage/emulated/0/Android/naki/" to "旧版asoulopt",
            "/data/swap_config.conf" to "scene附加模块2",
            "/data/local/tmp/resetprop" to "",
            "/dev/cpuset/AppOpt/" to "AppOpt模块",
            "/storage/emulated/0/Android/Clash/" to "Clash for Magisk模块",
            "/storage/emulated/0/Android/Yume-Yunyun/" to "网易云后台优化模块",
            "/data/local/tmp/Surfing_update" to "Surfing模块缓存",
            "/data/encore/custom_default_cpu_gov" to "encore模块",
            "/data/encore/default_cpu_gov" to "encore模块",
            "/data/local/tmp/yshell" to "",
            "/data/local/tmp/encore_logo.png" to "",
            "/storage/emulated/legacy/" to "",
            "/storage/emulated/elgg/" to "",
            "/data/system/junge/" to "",
            "/data/local/tmp/mount_namespace" to "挂载命名空间残留"
        )

        cleanupPaths.forEachIndexed { index, (path, desc) ->
            val current = index + 1
            appendLine("cleanup_path '$path' '$desc' $current \$TOTAL")
        }

        appendLine()
        appendLine("echo \"$(get_current_time): 工具残留清理完成\" >> \"${'$'}LOG_FILE\"")
        appendLine()
    }

    /**
     * 生成post-fs-data.sh脚本内容
     */
    private fun generatePostFsDataScript(config: SuSFSManager.ModuleConfig): String {
        return buildString {
            appendLine("#!/system/bin/sh")
            appendLine("# SuSFS Post-FS-Data Script")
            appendLine("# 在文件系统挂载后但在系统完全启动前执行")
            appendLine()
            appendLine(generateLogSetup("susfs_post_fs_data.log"))
            appendLine()
            appendLine(generateBinaryCheck(config.targetPath))
            appendLine()
            appendLine("echo \"$(get_current_time): Post-FS-Data脚本开始执行\" >> \"${'$'}LOG_FILE\"")
            appendLine()

            // 设置uname和构建时间 - 只有在选择在post-fs-data中执行时才执行
            if (config.executeInPostFsData && (config.unameValue != DEFAULT_UNAME || config.buildTimeValue != DEFAULT_BUILD_TIME)) {
                appendLine("# 设置uname和构建时间")
                appendLine("\"${'$'}SUSFS_BIN\" set_uname '${config.unameValue}' '${config.buildTimeValue}'")
                appendLine("echo \"$(get_current_time): 设置uname为: ${config.unameValue}, 构建时间为: ${config.buildTimeValue}\" >> \"${'$'}LOG_FILE\"")
                appendLine()
            }

            generateUmountZygoteIsoServiceSection(config.umountForZygoteIsoService, config.support158)

            // 添加AVC日志欺骗设置
            generateAvcLogSpoofingSection(config.enableAvcLogSpoofing)

            appendLine("echo \"$(get_current_time): Post-FS-Data脚本执行完成\" >> \"${'$'}LOG_FILE\"")
        }
    }

    // 添加新的生成方法
    private fun StringBuilder.generateUmountZygoteIsoServiceSection(umountForZygoteIsoService: Boolean, support158: Boolean) {
        if (support158) {
            appendLine("# 设置Zygote隔离服务卸载状态")
            val umountValue = if (umountForZygoteIsoService) 1 else 0
            appendLine("\"${'$'}SUSFS_BIN\" umount_for_zygote_iso_service $umountValue")
            appendLine("echo \"$(get_current_time): Zygote隔离服务卸载设置为: ${if (umountForZygoteIsoService) "启用" else "禁用"}\" >> \"${'$'}LOG_FILE\"")
            appendLine()
        }
    }

    /**
     * 生成post-mount.sh脚本内容
     */
    private fun generatePostMountScript(config: SuSFSManager.ModuleConfig): String {
        return buildString {
            appendLine("#!/system/bin/sh")
            appendLine("# SuSFS Post-Mount Script")
            appendLine("# 在所有分区挂载完成后执行")
            appendLine()
            appendLine(generateLogSetup("susfs_post_mount.log"))
            appendLine()
            appendLine("echo \"$(get_current_time): Post-Mount脚本开始执行\" >> \"${'$'}LOG_FILE\"")
            appendLine()
            appendLine(generateBinaryCheck(config.targetPath))
            appendLine()

            // 添加SUS挂载
            if (config.susMounts.isNotEmpty()) {
                appendLine("# 添加SUS挂载")
                config.susMounts.forEach { mount ->
                    appendLine("\"${'$'}SUSFS_BIN\" add_sus_mount '$mount'")
                    appendLine("echo \"$(get_current_time): 添加SUS挂载: $mount\" >> \"${'$'}LOG_FILE\"")
                }
                appendLine()
            }

            // 添加尝试卸载
            if (config.tryUmounts.isNotEmpty()) {
                appendLine("# 添加尝试卸载")
                config.tryUmounts.forEach { umount ->
                    val parts = umount.split("|")
                    if (parts.size == 2) {
                        val path = parts[0]
                        val mode = parts[1]
                        appendLine("\"${'$'}SUSFS_BIN\" add_try_umount '$path' $mode")
                        appendLine("echo \"$(get_current_time): 添加尝试卸载: $path (模式: $mode)\" >> \"${'$'}LOG_FILE\"")
                    }
                }
                appendLine()
            }

            appendLine("echo \"$(get_current_time): Post-Mount脚本执行完成\" >> \"${'$'}LOG_FILE\"")
        }
    }

    /**
     * 生成boot-completed.sh脚本内容
     */
    @SuppressLint("SdCardPath")
    private fun generateBootCompletedScript(config: SuSFSManager.ModuleConfig): String {
        return buildString {
            appendLine("#!/system/bin/sh")
            appendLine("# SuSFS Boot-Completed Script")
            appendLine("# 在系统完全启动后执行")
            appendLine()
            appendLine(generateLogSetup("susfs_boot_completed.log"))
            appendLine()
            appendLine("echo \"$(get_current_time): Boot-Completed脚本开始执行\" >> \"${'$'}LOG_FILE\"")
            appendLine()
            appendLine(generateBinaryCheck(config.targetPath))
            appendLine()

            // 仅在支持隐藏挂载功能时执行相关配置
            if (config.support158) {
                // SUS挂载隐藏控制
                val hideValue = if (config.hideSusMountsForAllProcs) 1 else 0
                appendLine("# 设置SUS挂载隐藏控制")
                appendLine("\"${'$'}SUSFS_BIN\" hide_sus_mnts_for_all_procs $hideValue")
                appendLine("echo \"$(get_current_time): SUS挂载隐藏控制设置为: ${if (config.hideSusMountsForAllProcs) "对所有进程隐藏" else "仅对非KSU进程隐藏"}\" >> \"${'$'}LOG_FILE\"")
                appendLine()

                // 路径设置和SUS路径设置
                if (config.susPaths.isNotEmpty() || config.susLoopPaths.isNotEmpty()) {
                    generatePathSettingSection(config.androidDataPath, config.sdcardPath)
                    appendLine()

                    // 添加普通SUS路径
                    if (config.susPaths.isNotEmpty()) {
                        generateSusPathsSection(config.susPaths)
                    }

                    // 添加循环SUS路径
                    if (config.susLoopPaths.isNotEmpty()) {
                        generateSusLoopPathsSection(config.susLoopPaths)
                    }

                    if (config.susMaps.isNotEmpty()) {
                        generateSusMapsSection(config.susMaps)
                    }
                }
            }

            appendLine("echo \"$(get_current_time): Boot-Completed脚本执行完成\" >> \"${'$'}LOG_FILE\"")
        }
    }

    private fun StringBuilder.generateSusMapsSection(susMaps: Set<String>) {
        if (susMaps.isNotEmpty()) {
            appendLine("# 添加SUS映射")
            susMaps.forEach { map ->
                appendLine("\"${'$'}SUSFS_BIN\" add_sus_map '$map'")
                appendLine("echo \"$(get_current_time): 添加SUS映射: $map\" >> \"${'$'}LOG_FILE\"")
            }
            appendLine()
        }
    }

    @SuppressLint("SdCardPath")
    private fun StringBuilder.generatePathSettingSection(androidDataPath: String, sdcardPath: String) {
        appendLine("# 路径配置")
        appendLine("# 设置Android Data路径")
        appendLine("until [ -d \"/sdcard/Android\" ]; do sleep 1; done")
        appendLine("sleep 60")
        appendLine()
        appendLine("\"${'$'}SUSFS_BIN\" set_android_data_root_path '$androidDataPath'")
        appendLine("echo \"$(get_current_time): Android Data路径设置为: $androidDataPath\" >> \"${'$'}LOG_FILE\"")
        appendLine()
        appendLine("# 设置SD卡路径")
        appendLine("\"${'$'}SUSFS_BIN\" set_sdcard_root_path '$sdcardPath'")
        appendLine("echo \"$(get_current_time): SD卡路径设置为: $sdcardPath\" >> \"${'$'}LOG_FILE\"")
        appendLine()
    }

    /**
     * 生成module.prop文件内容
     */
    fun generateModuleProp(moduleId: String): String {
        val moduleVersion = "v1.0.2"
        val moduleVersionCode = "1002"

        return """
            id=$moduleId
            name=SuSFS Manager
            version=$moduleVersion
            versionCode=$moduleVersionCode
            author=ShirkNeko
            description=SuSFS Manager Auto Configuration Module (自动生成请不要手动卸载或删除该模块! / Automatically generated Please do not manually uninstall or delete the module!)
            updateJson=
        """.trimIndent()
    }
}