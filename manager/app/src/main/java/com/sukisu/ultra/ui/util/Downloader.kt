package com.sukisu.ultra.ui.util

import android.annotation.SuppressLint
import android.app.DownloadManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import com.sukisu.ultra.ui.util.module.LatestVersionInfo
import java.io.File
import java.util.concurrent.TimeUnit

private const val TAG = "DownloadUtil"
private val CUSTOM_USER_AGENT = "SukiSU-Ultra/2.0 (Linux; Android ${Build.VERSION.RELEASE}; ${Build.MODEL})"
private const val MAX_RETRY_COUNT = 3
private const val RETRY_DELAY_MS = 3000L

/**
 * @author weishu
 * @date 2023/6/22.
 */
@SuppressLint("Range")
fun download(
    context: Context,
    url: String,
    fileName: String,
    description: String,
    onDownloaded: (Uri) -> Unit = {},
    onDownloading: () -> Unit = {},
    onError: (String) -> Unit = {}
) {
    Log.d(TAG, "Start Download: $url")
    val downloadManager = context.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager

    val query = DownloadManager.Query()
    query.setFilterByStatus(DownloadManager.STATUS_RUNNING or DownloadManager.STATUS_PAUSED or DownloadManager.STATUS_PENDING)
    downloadManager.query(query).use { cursor ->
        while (cursor.moveToNext()) {
            val uri = cursor.getString(cursor.getColumnIndex(DownloadManager.COLUMN_URI))
            val localUri = cursor.getString(cursor.getColumnIndex(DownloadManager.COLUMN_LOCAL_URI))
            val status = cursor.getInt(cursor.getColumnIndex(DownloadManager.COLUMN_STATUS))
            val columnTitle = cursor.getString(cursor.getColumnIndex(DownloadManager.COLUMN_TITLE))
            if (url == uri || fileName == columnTitle) {
                if (status == DownloadManager.STATUS_RUNNING || status == DownloadManager.STATUS_PENDING) {
                    onDownloading()
                    return
                } else if (status == DownloadManager.STATUS_SUCCESSFUL) {
                    onDownloaded(localUri.toUri())
                    return
                }
            }
        }
    }
    val downloadFile = File(
        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
        fileName
    )
    if (downloadFile.exists()) {
        downloadFile.delete()
    }

    val request = DownloadManager.Request(url.toUri())
        .setDestinationInExternalPublicDir(
            Environment.DIRECTORY_DOWNLOADS,
            fileName
        )
        .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
        .setMimeType("application/zip")
        .setTitle(fileName)
        .setDescription(description)
        .addRequestHeader("User-Agent", CUSTOM_USER_AGENT)
        .setAllowedOverMetered(true)
        .setAllowedOverRoaming(true)
        .setAllowedNetworkTypes(DownloadManager.Request.NETWORK_WIFI or DownloadManager.Request.NETWORK_MOBILE)

    try {
        val downloadId = downloadManager.enqueue(request)
        Log.d(TAG, "Successful launch of the download，ID: $downloadId")
        monitorDownload(context, downloadManager, downloadId, url, fileName, description, onDownloaded, onDownloading, onError)
    } catch (e: Exception) {
        Log.e(TAG, "Download startup failure", e)
        onError("Download startup failure: ${e.message}")
    }
}

private fun monitorDownload(
    context: Context,
    downloadManager: DownloadManager,
    downloadId: Long,
    url: String,
    fileName: String,
    description: String,
    onDownloaded: (Uri) -> Unit,
    onDownloading: () -> Unit,
    onError: (String) -> Unit,
    retryCount: Int = 0
) {
    val handler = Handler(Looper.getMainLooper())
    val query = DownloadManager.Query().setFilterById(downloadId)

    var lastProgress = -1
    var stuckCounter = 0

    val runnable = object : Runnable {
        override fun run() {
            downloadManager.query(query).use { cursor ->
                if (cursor != null && cursor.moveToFirst()) {
                    @SuppressLint("Range")
                    val status = cursor.getInt(cursor.getColumnIndex(DownloadManager.COLUMN_STATUS))

                    when (status) {
                        DownloadManager.STATUS_SUCCESSFUL -> {
                            @SuppressLint("Range")
                            val localUri = cursor.getString(cursor.getColumnIndex(DownloadManager.COLUMN_LOCAL_URI))
                            Log.d(TAG, "Download Successfully: $localUri")
                            onDownloaded(localUri.toUri())
                            return
                        }
                        DownloadManager.STATUS_FAILED -> {
                            @SuppressLint("Range")
                            val reason = cursor.getInt(cursor.getColumnIndex(DownloadManager.COLUMN_REASON))
                            Log.d(TAG, "Download failed with reason code: $reason")

                            if (retryCount < MAX_RETRY_COUNT) {
                                Log.d(TAG, "Attempts to re download, number of retries: ${retryCount + 1}")
                                handler.postDelayed({
                                    downloadManager.remove(downloadId)
                                    download(context, url, fileName, description, onDownloaded, onDownloading, onError)
                                }, RETRY_DELAY_MS)
                            } else {
                                onError("Download failed, please check network connection or storage space")
                            }
                            return
                        }
                        DownloadManager.STATUS_RUNNING, DownloadManager.STATUS_PENDING, DownloadManager.STATUS_PAUSED -> {
                            @SuppressLint("Range")
                            val totalBytes = cursor.getLong(cursor.getColumnIndex(DownloadManager.COLUMN_TOTAL_SIZE_BYTES))
                            @SuppressLint("Range")
                            val downloadedBytes = cursor.getLong(cursor.getColumnIndex(DownloadManager.COLUMN_BYTES_DOWNLOADED_SO_FAR))

                            if (totalBytes > 0) {
                                val progress = (downloadedBytes * 100 / totalBytes).toInt()
                                if (progress == lastProgress) {
                                    stuckCounter++
                                    if (stuckCounter > 30) {
                                        if (retryCount < MAX_RETRY_COUNT) {
                                            Log.d(TAG, "Download stalled and restarted")
                                            downloadManager.remove(downloadId)
                                            download(context, url, fileName, description, onDownloaded, onDownloading, onError)
                                            return
                                        }
                                    }
                                } else {
                                    lastProgress = progress
                                    stuckCounter = 0
                                    Log.d(TAG, "Download progress: $progress% ($downloadedBytes/$totalBytes)")
                                }
                            }
                        }
                    }
                }
            }
            handler.postDelayed(this, 1000)
        }
    }
    handler.post(runnable)

    val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val id = intent?.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1) ?: -1
            if (id == downloadId) {
                handler.removeCallbacks(runnable)

                val query = DownloadManager.Query().setFilterById(downloadId)
                downloadManager.query(query).use { cursor ->
                    if (cursor != null && cursor.moveToFirst()) {
                        @SuppressLint("Range")
                        val status = cursor.getInt(cursor.getColumnIndex(DownloadManager.COLUMN_STATUS))

                        if (status == DownloadManager.STATUS_SUCCESSFUL) {
                            @SuppressLint("Range")
                            val localUri = cursor.getString(cursor.getColumnIndex(DownloadManager.COLUMN_LOCAL_URI))
                            onDownloaded(localUri.toUri())
                        } else {
                            if (retryCount < MAX_RETRY_COUNT) {
                                download(context!!, url, fileName, description, onDownloaded, onDownloading, onError)
                            } else {
                                onError("Download failed, please try again later")
                            }
                        }
                    }
                }

                context?.unregisterReceiver(this)
            }
        }
    }

    ContextCompat.registerReceiver(
        context,
        receiver,
        IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE),
        ContextCompat.RECEIVER_EXPORTED
    )
}

fun checkNewVersion(): LatestVersionInfo {
    val url = "https://api.github.com/repos/ShirkNeko/SukiSU-Ultra/releases/latest"
    val defaultValue = LatestVersionInfo()
    return runCatching {
        val client = okhttp3.OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .build()

        val request = okhttp3.Request.Builder()
            .url(url)
            .header("User-Agent", CUSTOM_USER_AGENT)
            .build()

        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                Log.d("CheckUpdate", "Network request failed: ${response.message}")
                return defaultValue
            }
            val body = response.body?.string()
            if (body == null) {
                Log.d("CheckUpdate", "Return data is null")
                return defaultValue
            }
            Log.d("CheckUpdate", "Return data: $body")
            val json = org.json.JSONObject(body)

            // 直接从 tag_name 提取版本号（如 v1.1）
            val tagName = json.optString("tag_name", "")
            val versionName = tagName.removePrefix("v") // 移除前缀 "v"

            // 从 body 字段获取更新日志（保留换行符）
            val changelog = json.optString("body")
                .replace("\\r\\n", "\n") // 转换换行符

            val assets = json.getJSONArray("assets")
            for (i in 0 until assets.length()) {
                val asset = assets.getJSONObject(i)
                val name = asset.getString("name")
                if (!name.endsWith(".apk")) continue

                val regex = Regex("SukiSU.*_(\\d+)-release")
                val matchResult = regex.find(name)
                if (matchResult == null) {
                    Log.d("CheckUpdate", "No matches found: $name, skip over")
                    continue
                }
                val versionCode = matchResult.groupValues[1].toInt()

                val downloadUrl = asset.getString("browser_download_url")
                return LatestVersionInfo(
                    versionCode,
                    downloadUrl,
                    changelog,
                    versionName
                )
            }
            Log.d("CheckUpdate", "No valid APK resource found, return default value")
            defaultValue
        }
    }.getOrDefault(defaultValue)
}

@Composable
fun DownloadListener(context: Context, onDownloaded: (Uri) -> Unit) {
    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            @SuppressLint("Range")
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action == DownloadManager.ACTION_DOWNLOAD_COMPLETE) {
                    val id = intent.getLongExtra(
                        DownloadManager.EXTRA_DOWNLOAD_ID, -1
                    )
                    val query = DownloadManager.Query().setFilterById(id)
                    val downloadManager =
                        context?.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
                    val cursor = downloadManager.query(query)
                    if (cursor.moveToFirst()) {
                        val status = cursor.getInt(
                            cursor.getColumnIndex(DownloadManager.COLUMN_STATUS)
                        )
                        if (status == DownloadManager.STATUS_SUCCESSFUL) {
                            val uri = cursor.getString(
                                cursor.getColumnIndex(DownloadManager.COLUMN_LOCAL_URI)
                            )
                            onDownloaded(uri.toUri())
                        }
                    }
                }
            }
        }
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE),
            ContextCompat.RECEIVER_EXPORTED
        )
        onDispose {
            context.unregisterReceiver(receiver)
        }
    }
}