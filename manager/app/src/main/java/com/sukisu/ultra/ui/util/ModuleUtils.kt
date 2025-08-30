package com.sukisu.ultra.ui.util

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import com.sukisu.ultra.R
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.util.zip.ZipInputStream

object ModuleUtils {
    private const val TAG = "ModuleUtils"

    fun extractModuleName(context: Context, uri: Uri): String {
        if (uri == Uri.EMPTY) {
            Log.e(TAG, "The supplied URI is empty")
            return context.getString(R.string.unknown_module)
        }

        return try {
            Log.d(TAG, "Start extracting module names from URIs: $uri")

            // 从URI路径中提取文件名
            val fileName = uri.lastPathSegment?.let { path ->
                val lastSlash = path.lastIndexOf('/')
                if (lastSlash != -1 && lastSlash < path.length - 1) {
                    path.substring(lastSlash + 1)
                } else {
                    path
                }
            }?.removeSuffix(".zip") ?: context.getString(R.string.unknown_module)

            val formattedFileName = fileName.replace(Regex("[^a-zA-Z0-9\\s\\-_.@()\\u4e00-\\u9fa5]"), "").trim()
            var moduleName = formattedFileName

            try {
                // 打开ZIP文件输入流
                val inputStream = context.contentResolver.openInputStream(uri)
                if (inputStream == null) {
                    Log.e(TAG, "Unable to get input stream from URI: $uri")
                    return formattedFileName
                }

                val zipInputStream = ZipInputStream(inputStream)
                var entry = zipInputStream.nextEntry

                // 遍历ZIP文件中的条目，查找module.prop文件
                while (entry != null) {
                    if (entry.name == "module.prop") {
                        val reader = BufferedReader(InputStreamReader(zipInputStream, StandardCharsets.UTF_8))
                        var line: String?
                        while (reader.readLine().also { line = it } != null) {
                            if (line?.startsWith("name=") == true) {
                                moduleName = line.substringAfter("=")
                                moduleName = moduleName.replace(Regex("[^a-zA-Z0-9\\s\\-_.@()\\u4e00-\\u9fa5]"), "").trim()
                                break
                            }
                        }
                        break
                    }
                    entry = zipInputStream.nextEntry
                }
                zipInputStream.close()
                Log.d(TAG, "Successfully extracted module name: $moduleName")
                moduleName
            } catch (e: IOException) {
                Log.e(TAG, "Error reading ZIP file: ${e.message}")
                formattedFileName
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception when extracting module name: ${e.message}")
            context.getString(R.string.unknown_module)
        }
    }

    // 验证URI是否有效并可访问
    fun isUriAccessible(context: Context, uri: Uri): Boolean {
        if (uri == Uri.EMPTY) return false

        return try {
            val inputStream = context.contentResolver.openInputStream(uri)
            inputStream?.close()
            inputStream != null
        } catch (e: Exception) {
            Log.e(TAG, "The URI is inaccessible: $uri, Error: ${e.message}")
            false
        }
    }

    // 获取URI的持久权限
    fun takePersistableUriPermission(context: Context, uri: Uri) {
        try {
            val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
            context.contentResolver.takePersistableUriPermission(uri, flags)
            Log.d(TAG, "Persistent permissions for URIs have been obtained: $uri")
        } catch (e: Exception) {
            Log.e(TAG, "Unable to get persistent permissions on URIs: $uri, Error: ${e.message}")
        }
    }

    fun extractModuleId(context: Context, uri: Uri): String? {
        if (uri == Uri.EMPTY) {
            return null
        }

        return try {

            val inputStream = context.contentResolver.openInputStream(uri) ?: return null

            val zipInputStream = ZipInputStream(inputStream)
            var entry = zipInputStream.nextEntry
            var moduleId: String? = null

            // 遍历ZIP文件中的条目，查找module.prop文件
            while (entry != null) {
                if (entry.name == "module.prop") {
                    val reader = BufferedReader(InputStreamReader(zipInputStream, StandardCharsets.UTF_8))
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        if (line?.startsWith("id=") == true) {
                            moduleId = line.substringAfter("=").trim()
                            break
                        }
                    }
                    break
                }
                entry = zipInputStream.nextEntry
            }
            zipInputStream.close()
            moduleId
        } catch (e: Exception) {
            Log.e(TAG, "提取模块ID时发生异常: ${e.message}", e)
            null
        }
    }
}