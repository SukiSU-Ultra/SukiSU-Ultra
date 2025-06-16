package com.sukisu.ultra.ui.util.module

import android.util.Log
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * 模块更新JSON数据类
 */
data class UpdateJson(
    val version: String = "",
    val versionCode: Int = 0,
    @SerializedName("zipUrl") val zipUrl: String = "",
    val size: Int = 0,
    val changelog: String = ""
) {
    companion object {
        private const val TAG = "UpdateJson"
        private val client = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()
        
        /**
         * 从URL加载更新JSON
         */
        suspend fun loadFromUrl(url: String): UpdateJson? {
            if (!isValidUrl(url)) return null
            
            return withContext(Dispatchers.IO) {
                try {
                    val request = Request.Builder()
                        .url(url)
                        .build()
                    
                    val response = client.newCall(request).execute()
                    if (!response.isSuccessful) {
                        Log.e(TAG, "Error loading update JSON: ${response.code}")
                        return@withContext null
                    }
                    
                    val body = response.body?.string()
                    if (body.isNullOrBlank()) {
                        Log.e(TAG, "Empty response body")
                        return@withContext null
                    }
                    
                    return@withContext try {
                        Gson().fromJson(body, UpdateJson::class.java)
                    } catch (e: Exception) {
                        Log.e(TAG, "Error parsing JSON: ${e.message}")
                        null
                    }
                } catch (e: IOException) {
                    Log.e(TAG, "Network error: ${e.message}")
                    null
                } catch (e: Exception) {
                    Log.e(TAG, "Unexpected error: ${e.message}")
                    null
                }
            }
        }
        
        /**
         * 检查URL是否有效
         */
        private fun isValidUrl(url: String?): Boolean {
            if (url.isNullOrBlank()) return false
            
            return try {
                val uri = java.net.URI(url)
                uri.scheme == "http" || uri.scheme == "https"
            } catch (e: Exception) {
                false
            }
        }
    }
    
    /**
     * 检查此更新版本是否比当前版本更新
     */
    fun isNewerThan(currentVersionCode: Int): Boolean {
        return versionCode > currentVersionCode
    }
} 