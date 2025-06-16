package com.sukisu.ultra.ui.util

import android.annotation.SuppressLint

/**
 * Magisk模块脚本生成器
 * 用于生成各种启动脚本的内容
 */
object ScriptGenerator {

    /**
     * 生成service.sh脚本内容
     */
    @SuppressLint("SdCardPath")
    fun generateServiceScript(
        targetPath: String,
        unameValue: String,
        buildTimeValue: String,
        susPaths: Set<String>,
        androidDataPath: String,
        sdcardPath: String,
        enableLog: Boolean
    ): String {
        return buildString {
            appendLine("#!/system/bin/sh")
            appendLine("# SuSFS Service Script")
            appendLine("# 在系统服务启动后执行")
            appendLine()
            appendLine("# 日志目录")
            appendLine("LOG_DIR=\"/data/adb/ksu/log\"")
            appendLine("LOG_FILE=\"\$LOG_DIR/susfs_service.log\"")
            appendLine()
            appendLine("# 创建日志目录")
            appendLine("mkdir -p \"\$LOG_DIR\"")
            appendLine()
            appendLine("# 获取当前时间")
            appendLine("get_current_time() {")
            appendLine("    date '+%Y-%m-%d %H:%M:%S'")
            appendLine("}")
            appendLine()
            appendLine("# 检查SuSFS二进制文件")
            appendLine("SUSFS_BIN=\"$targetPath\"")
            appendLine("if [ ! -f \"\$SUSFS_BIN\" ]; then")
            appendLine("    echo \"\$(get_current_time): SuSFS二进制文件未找到: \$SUSFS_BIN\" >> \"\$LOG_FILE\"")
            appendLine("    exit 1")
            appendLine("fi")
            appendLine()

            // 设置日志启用状态
            appendLine("# 设置日志启用状态")
            val logValue = if (enableLog) 1 else 0
            appendLine("\"\$SUSFS_BIN\" enable_log $logValue")
            appendLine("echo \"\$(get_current_time): 日志功能设置为: ${if (enableLog) "启用" else "禁用"}\" >> \"\$LOG_FILE\"")
            appendLine()

            // 设置Android Data路径
            if (androidDataPath != "/sdcard/Android/data") {
                appendLine("# 设置Android Data路径")
                appendLine("\"\$SUSFS_BIN\" set_android_data_root_path '$androidDataPath'")
                appendLine("echo \"\$(get_current_time): Android Data路径设置为: $androidDataPath\" >> \"\$LOG_FILE\"")
                appendLine()
            }

            // 设置SD卡路径
            if (sdcardPath != "/sdcard") {
                appendLine("# 设置SD卡路径")
                appendLine("\"\$SUSFS_BIN\" set_sdcard_root_path '$sdcardPath'")
                appendLine("echo \"\$(get_current_time): SD卡路径设置为: $sdcardPath\" >> \"\$LOG_FILE\"")
                appendLine()
            }

            // 添加SUS路径
            if (susPaths.isNotEmpty()) {
                appendLine("# 添加SUS路径")
                susPaths.forEach { path ->
                    appendLine("\"\$SUSFS_BIN\" add_sus_path '$path'")
                    appendLine("echo \"\$(get_current_time): 添加SUS路径: $path\" >> \"\$LOG_FILE\"")
                }
                appendLine()
            }

            // 设置uname和构建时间
            if (unameValue != "default" || buildTimeValue != "default") {
                appendLine("# 设置uname和构建时间")
                appendLine("\"\$SUSFS_BIN\" set_uname '$unameValue' '$buildTimeValue'")
                appendLine("echo \"\$(get_current_time): 设置uname为: $unameValue, 构建时间为: $buildTimeValue\" >> \"\$LOG_FILE\"")
                appendLine()
            }

            appendLine("# 隐弱BL 来自 Shamiko 脚本")
            appendLine("check_reset_prop() {")
            appendLine("local NAME=\$1")
            appendLine("local EXPECTED=\$2")
            appendLine("local VALUE=\$(resetprop \$NAME)")
            appendLine("[ -z \$VALUE ] || [ \$VALUE = \$EXPECTED ] || resetprop \$NAME \$EXPECTED")
            appendLine("}")
            appendLine()
            appendLine("check_missing_prop() {")
            appendLine("  local NAME=\$1")
            appendLine("  local EXPECTED=\$2")
            appendLine("  local VALUE=\$(resetprop \$NAME)")
            appendLine("  [ -z \$VALUE ] && resetprop \$NAME \$EXPECTED")
            appendLine("}")
            appendLine()
            appendLine("check_missing_match_prop() {")
            appendLine("  local NAME=\$1")
            appendLine("  local EXPECTED=\$2")
            appendLine("  local VALUE=\$(resetprop \$NAME)")
            appendLine("  [ -z \$VALUE ] || [ \$VALUE = \$EXPECTED ] || resetprop \$NAME \$EXPECTED")
            appendLine("  [ -z \$VALUE ] && resetprop \$NAME \$EXPECTED")
            appendLine("}")
            appendLine()
            appendLine("contains_reset_prop() {")
            appendLine("local NAME=\$1")
            appendLine("local CONTAINS=\$2")
            appendLine("local NEWVAL=\$3")
            appendLine("[[ \"\$(resetprop \$NAME)\" = *\"\$CONTAINS\"* ]] && resetprop \$NAME \$NEWVAL")
            appendLine("}")
            appendLine()
            appendLine("resetprop -w sys.boot_completed 0")
            appendLine()
            appendLine("check_missing_prop \"ro.boot.vbmeta.invalidate_on_error\" \"yes\"")
            appendLine("check_missing_prop \"ro.boot.vbmeta.avb_version\" \"1.2\"")
            appendLine("check_missing_prop \"ro.boot.vbmeta.hash_alg\" \"sha256\"")
            appendLine()
            appendLine("check_missing_match_prop \"ro.boot.vbmeta.device_state\" \"locked\"")
            appendLine("check_missing_match_prop \"ro.boot.verifiedbootstate\" \"green\"")
            appendLine("check_missing_match_prop \"ro.boot.flash.locked\" \"1\"")
            appendLine("check_missing_match_prop \"ro.boot.veritymode\" \"enforcing\"")
            appendLine("check_missing_match_prop \"ro.boot.warranty_bit\" \"0\"")
            appendLine("check_reset_prop \"ro.boot.vbmeta.device_state\" \"locked\"")
            appendLine("check_reset_prop \"ro.boot.verifiedbootstate\" \"green\"")
            appendLine("check_reset_prop \"ro.boot.flash.locked\" \"1\"")
            appendLine("check_reset_prop \"ro.boot.veritymode\" \"enforcing\"")
            appendLine("check_reset_prop \"ro.boot.warranty_bit\" \"0\"")
            appendLine("check_reset_prop \"ro.warranty_bit\" \"0\"")
            appendLine("check_reset_prop \"ro.debuggable\" \"0\"")
            appendLine("check_reset_prop \"ro.force.debuggable\" \"0\"")
            appendLine("check_reset_prop \"ro.secure\" \"1\"")
            appendLine("check_reset_prop \"ro.adb.secure\" \"1\"")
            appendLine("check_reset_prop \"ro.build.type\" \"user\"")
            appendLine("check_reset_prop \"ro.build.tags\" \"release-keys\"")
            appendLine("check_reset_prop \"ro.vendor.boot.warranty_bit\" \"0\"")
            appendLine("check_reset_prop \"ro.vendor.warranty_bit\" \"0\"")
            appendLine("check_reset_prop \"vendor.boot.vbmeta.device_state\" \"locked\"")
            appendLine("check_reset_prop \"vendor.boot.verifiedbootstate\" \"green\"")
            appendLine("check_reset_prop \"sys.oem_unlock_allowed\" \"0\"")
            appendLine()
            appendLine("#Hide adb debugging traces")
            appendLine("resetprop \"sys.usb.adb.disabled\" \" \"")
            appendLine()
            appendLine("# MIUI specific")
            appendLine("check_reset_prop \"ro.secureboot.lockstate\" \"locked\"")
            appendLine()
            appendLine("# Realme specific")
            appendLine("check_reset_prop \"ro.boot.realmebootstate\" \"green\"")
            appendLine("check_reset_prop \"ro.boot.realme.lockstate\" \"1\"")
            appendLine()
            appendLine("# Hide that we booted from recovery when magisk is in recovery mode")
            appendLine("contains_reset_prop \"ro.bootmode\" \"recovery\" \"unknown\"")
            appendLine("contains_reset_prop \"ro.boot.bootmode\" \"recovery\" \"unknown\"")
            appendLine("contains_reset_prop \"vendor.boot.bootmode\" \"recovery\" \"unknown\"")
            appendLine()
            appendLine("# Hide cloudphone detection")
            appendLine("[ -n \"\$(resetprop ro.kernel.qemu)\" ] && resetprop ro.kernel.qemu \"\"")
            appendLine()
            appendLine("# fake encryption status")
            appendLine("check_reset_prop \"ro.crypto.state\" \"encrypted\"")
            appendLine()

            appendLine("echo \"\$(get_current_time): Service脚本执行完成\" >> \"\$LOG_FILE\"")
        }
    }

    /**
     * 生成post-fs-data.sh脚本内容
     */
    fun generatePostFsDataScript(
        targetPath: String,
    ): String {
        return buildString {
            appendLine("#!/system/bin/sh")
            appendLine("# SuSFS Post-FS-Data Script")
            appendLine("# 在文件系统挂载后但在系统完全启动前执行")
            appendLine()
            appendLine("# 日志目录")
            appendLine("LOG_DIR=\"/data/adb/ksu/log\"")
            appendLine("LOG_FILE=\"\$LOG_DIR/susfs_post_fs_data.log\"")
            appendLine()
            appendLine("# 创建日志目录")
            appendLine("mkdir -p \"\$LOG_DIR\"")
            appendLine()
            appendLine("# 获取当前时间")
            appendLine("get_current_time() {")
            appendLine("    date '+%Y-%m-%d %H:%M:%S'")
            appendLine("}")
            appendLine()
            appendLine("# 检查SuSFS二进制文件")
            appendLine("SUSFS_BIN=\"$targetPath\"")
            appendLine("if [ ! -f \"\$SUSFS_BIN\" ]; then")
            appendLine("    echo \"\$(get_current_time): SuSFS二进制文件未找到: \$SUSFS_BIN\" >> \"\$LOG_FILE\"")
            appendLine("    exit 1")
            appendLine("fi")
            appendLine()
            appendLine("echo \"\$(get_current_time): Post-FS-Data脚本开始执行\" >> \"\$LOG_FILE\"")
            appendLine()
            appendLine()
            appendLine()
            appendLine()
            appendLine("echo \"\$(get_current_time): Post-FS-Data脚本执行完成\" >> \"\$LOG_FILE\"")
        }
    }

    /**
     * 生成post-mount.sh脚本内容
     */
    fun generatePostMountScript(
        targetPath: String,
        susMounts: Set<String>,
        tryUmounts: Set<String>
    ): String {
        return buildString {
            appendLine("#!/system/bin/sh")
            appendLine("# SuSFS Post-Mount Script")
            appendLine("# 在所有分区挂载完成后执行")
            appendLine()
            appendLine("# 日志目录")
            appendLine("LOG_DIR=\"/data/adb/ksu/log\"")
            appendLine("LOG_FILE=\"\$LOG_DIR/susfs_post_mount.log\"")
            appendLine()
            appendLine("# 创建日志目录")
            appendLine("mkdir -p \"\$LOG_DIR\"")
            appendLine()
            appendLine("# 获取当前时间")
            appendLine("get_current_time() {")
            appendLine("    date '+%Y-%m-%d %H:%M:%S'")
            appendLine("}")
            appendLine()
            appendLine("echo \"\$(get_current_time): Post-Mount脚本开始执行\" >> \"\$LOG_FILE\"")
            appendLine()
            appendLine("# 检查SuSFS二进制文件")
            appendLine("SUSFS_BIN=\"$targetPath\"")
            appendLine("if [ ! -f \"\$SUSFS_BIN\" ]; then")
            appendLine("    echo \"\$(get_current_time): SuSFS二进制文件未找到: \$SUSFS_BIN\" >> \"\$LOG_FILE\"")
            appendLine("    exit 1")
            appendLine("fi")
            appendLine()

            // 添加SUS挂载
            if (susMounts.isNotEmpty()) {
                appendLine("# 添加SUS挂载")
                susMounts.forEach { mount ->
                    appendLine("\"\$SUSFS_BIN\" add_sus_mount '$mount'")
                    appendLine("echo \"\$(get_current_time): 添加SUS挂载: $mount\" >> \"\$LOG_FILE\"")
                }
                appendLine()
            }

            // 添加尝试卸载
            if (tryUmounts.isNotEmpty()) {
                appendLine("# 添加尝试卸载")
                tryUmounts.forEach { umount ->
                    val parts = umount.split("|")
                    if (parts.size == 2) {
                        val path = parts[0]
                        val mode = parts[1]
                        appendLine("\"\$SUSFS_BIN\" add_try_umount '$path' $mode")
                        appendLine("echo \"\$(get_current_time): 添加尝试卸载: $path (模式: $mode)\" >> \"\$LOG_FILE\"")
                    }
                }
                appendLine()
            }

            appendLine("echo \"\$(get_current_time): Post-Mount脚本执行完成\" >> \"\$LOG_FILE\"")
        }
    }

    /**
     * 生成boot-completed.sh脚本内容
     */
    fun generateBootCompletedScript(targetPath: String): String {
        return buildString {
            appendLine("#!/system/bin/sh")
            appendLine("# SuSFS Boot-Completed Script")
            appendLine("# 在系统完全启动后执行")
            appendLine()
            appendLine("# 日志目录")
            appendLine("LOG_DIR=\"/data/adb/ksu/log\"")
            appendLine("LOG_FILE=\"\$LOG_DIR/susfs_boot_completed.log\"")
            appendLine()
            appendLine("# 创建日志目录")
            appendLine("mkdir -p \"\$LOG_DIR\"")
            appendLine()
            appendLine("# 获取当前时间")
            appendLine("get_current_time() {")
            appendLine("    date '+%Y-%m-%d %H:%M:%S'")
            appendLine("}")
            appendLine()
            appendLine("echo \"\$(get_current_time): Boot-Completed脚本开始执行\" >> \"\$LOG_FILE\"")
            appendLine()
            appendLine("# 检查SuSFS二进制文件")
            appendLine("SUSFS_BIN=\"$targetPath\"")
            appendLine("if [ ! -f \"\$SUSFS_BIN\" ]; then")
            appendLine("    echo \"\$(get_current_time): SuSFS二进制文件未找到: \$SUSFS_BIN\" >> \"\$LOG_FILE\"")
            appendLine("    exit 1")
            appendLine("fi")
            appendLine()
            appendLine()
            appendLine()
            appendLine()
            appendLine("echo \"\$(get_current_time): Boot-Completed脚本执行完成\" >> \"\$LOG_FILE\"")
        }
    }

    /**
     * 生成module.prop文件内容
     */
    fun generateModuleProp(moduleId: String): String {
        val moduleVersion = "v1.0.0"
        val moduleVersionCode = "1000"

        return """
            id=$moduleId
            name=SuSFS Manager
            version=$moduleVersion
            versionCode=$moduleVersionCode
            author=ShirkNeko
            description=SuSFS Manager Auto Configuration Module
            updateJson=
        """.trimIndent()
    }
}