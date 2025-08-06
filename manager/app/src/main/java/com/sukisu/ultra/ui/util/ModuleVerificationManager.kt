package com.sukisu.ultra.ui.util

import android.content.Context
import android.net.Uri
import android.util.Log
import com.sukisu.ultra.Natives
import java.io.File
import java.io.FileOutputStream

/**
 * @author ShirkNeko
 * @date 2025/8/3
 */

// 模块签名验证工具类
object ModuleSignatureUtils {
    private const val TAG = "ModuleSignatureUtils"

    fun verifyModuleSignature(context: Context, moduleUri: Uri): Boolean {
        return try {
            // 创建临时文件
            val tempFile = File(context.cacheDir, "temp_module_${System.currentTimeMillis()}.zip")

            // 复制URI内容到临时文件
            context.contentResolver.openInputStream(moduleUri)?.use { inputStream ->
                FileOutputStream(tempFile).use { outputStream ->
                    inputStream.copyTo(outputStream)
                }
            }

            // 调用native方法验证签名
            val isVerified = Natives.verifyModuleSignature(tempFile.absolutePath)

            // 清理临时文件
            tempFile.delete()

            Log.d(TAG, "Module signature verification result: $isVerified")
            isVerified
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying module signature", e)
            false
        }
    }

}

// 验证模块签名
fun verifyModuleSignature(context: Context, moduleUri: Uri): Boolean {
    return ModuleSignatureUtils.verifyModuleSignature(context, moduleUri)
}

object ModuleOperationUtils {
    private const val TAG = "ModuleOperationUtils"

    fun handleModuleInstallSuccess(context: Context, moduleUri: Uri, isSignatureVerified: Boolean) {
        if (!isSignatureVerified) {
            Log.d(TAG, "模块签名未验证，跳过创建验证标志")
            return
        }

        try {
            // 从ZIP文件提取模块ID
            val moduleId = ModuleUtils.extractModuleId(context, moduleUri)
            if (moduleId == null) {
                Log.e(TAG, "无法提取模块ID，无法创建验证标志")
                return
            }

            // 创建验证标志文件
            val success = ModuleVerificationManager.createVerificationFlag(moduleId)
            if (success) {
                Log.d(TAG, "模块 $moduleId 验证标志创建成功")
            } else {
                Log.e(TAG, "模块 $moduleId 验证标志创建失败")
            }
        } catch (e: Exception) {
            Log.e(TAG, "处理模块安装成功时发生异常", e)
        }
    }

    fun handleModuleUninstall(moduleId: String) {
        try {
            val success = ModuleVerificationManager.removeVerificationFlag(moduleId)
            if (success) {
                Log.d(TAG, "模块 $moduleId 验证标志移除成功")
            } else {
                Log.d(TAG, "模块 $moduleId 验证标志移除失败或不存在")
            }
        } catch (e: Exception) {
            Log.e(TAG, "处理模块卸载时发生异常: $moduleId", e)
        }
    }
    fun handleModuleUpdate(context: Context, moduleUri: Uri, isSignatureVerified: Boolean) {
        try {
            val moduleId = ModuleUtils.extractModuleId(context, moduleUri)
            if (moduleId == null) {
                Log.e(TAG, "无法提取模块ID，无法处理验证标志")
                return
            }

            if (isSignatureVerified) {
                // 签名验证通过，创建或更新验证标志
                val success = ModuleVerificationManager.createVerificationFlag(moduleId)
                if (success) {
                    Log.d(TAG, "模块 $moduleId 更新后验证标志已更新")
                } else {
                    Log.e(TAG, "模块 $moduleId 更新后验证标志更新失败")
                }
            } else {
                // 签名验证失败，移除验证标志
                ModuleVerificationManager.removeVerificationFlag(moduleId)
                Log.d(TAG, "模块 $moduleId 更新后签名未验证，验证标志已移除")
            }
        } catch (e: Exception) {
            Log.e(TAG, "处理模块更新时发生异常", e)
        }
    }
}

object ModuleVerificationManager {
    private const val TAG = "ModuleVerificationManager"
    private const val VERIFICATION_FLAGS_DIR = "/data/adb/ksu/verified_modules"

    // 为指定模块创建验证标志文件
    fun createVerificationFlag(moduleId: String): Boolean {
        return try {
            val shell = getRootShell()
            val flagFilePath = "$VERIFICATION_FLAGS_DIR/$moduleId"

            // 确保目录存在
            val createDirCommand = "mkdir -p '$VERIFICATION_FLAGS_DIR'"
            shell.newJob().add(createDirCommand).exec()

            // 创建验证标志文件，写入验证时间戳
            val timestamp = System.currentTimeMillis()
            val command = "echo '$timestamp' > '$flagFilePath'"

            val result = shell.newJob().add(command).exec()

            if (result.isSuccess) {
                Log.d(TAG, "验证标志文件创建成功: $flagFilePath")
                true
            } else {
                Log.e(TAG, "验证标志文件创建失败: $moduleId")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "创建验证标志文件时发生异常: $moduleId", e)
            false
        }
    }

    fun removeVerificationFlag(moduleId: String): Boolean {
        return try {
            val shell = getRootShell()
            val flagFilePath = "$VERIFICATION_FLAGS_DIR/$moduleId"

            val command = "rm -f '$flagFilePath'"
            val result = shell.newJob().add(command).exec()

            if (result.isSuccess) {
                Log.d(TAG, "验证标志文件移除成功: $flagFilePath")
                true
            } else {
                Log.e(TAG, "验证标志文件移除失败: $moduleId")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "移除验证标志文件时发生异常: $moduleId", e)
            false
        }
    }

    fun getVerificationTimestamp(moduleId: String): Long {
        return try {
            val shell = getRootShell()
            val flagFilePath = "$VERIFICATION_FLAGS_DIR/$moduleId"

            val command = "cat '$flagFilePath' 2>/dev/null || echo '0'"
            val result = shell.newJob().add(command).to(ArrayList(), null).exec()

            if (result.isSuccess && result.out.isNotEmpty()) {
                val timestampStr = result.out.firstOrNull()?.trim() ?: "0"
                timestampStr.toLongOrNull() ?: 0L
            } else {
                0L
            }
        } catch (e: Exception) {
            Log.e(TAG, "获取验证时间戳时发生异常: $moduleId", e)
            0L
        }
    }

    fun batchCheckVerificationStatus(moduleIds: List<String>): Map<String, Boolean> {
        if (moduleIds.isEmpty()) return emptyMap()

        return try {
            val shell = getRootShell()
            val result = mutableMapOf<String, Boolean>()

            // 确保目录存在
            val createDirCommand = "mkdir -p '$VERIFICATION_FLAGS_DIR'"
            shell.newJob().add(createDirCommand).exec()

            // 批量检查所有模块的验证标志文件
            val commands = moduleIds.map { moduleId ->
                "test -f '$VERIFICATION_FLAGS_DIR/$moduleId' && echo '$moduleId:true' || echo '$moduleId:false'"
            }

            val command = commands.joinToString(" && ")
            val shellResult = shell.newJob().add(command).to(ArrayList(), null).exec()

            if (shellResult.isSuccess) {
                shellResult.out.forEach { line ->
                    val parts = line.split(":")
                    if (parts.size == 2) {
                        val moduleId = parts[0]
                        val isVerified = parts[1] == "true"
                        result[moduleId] = isVerified
                    }
                }
            }

            Log.d(TAG, "批量验证检查完成，共检查 ${moduleIds.size} 个模块")
            result
        } catch (e: Exception) {
            Log.e(TAG, "批量检查验证状态时发生异常", e)
            // 返回默认值，所有模块都标记为未验证
            moduleIds.associateWith { false }
        }
    }
}