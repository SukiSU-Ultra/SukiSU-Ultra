package com.sukisu.ultra.data.repository

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import com.sukisu.ultra.data.model.Module
import com.sukisu.ultra.data.model.ModuleUpdateInfo
import com.sukisu.ultra.ksuApp
import com.sukisu.ultra.ui.util.isNetworkAvailable
import com.sukisu.ultra.ui.util.listModules
import com.sukisu.ultra.ui.util.module.sanitizeVersionString
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Request
import okhttp3.Response
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import kotlin.coroutines.resumeWithException

class ModuleRepositoryImpl : ModuleRepository {

    companion object {
        private const val TAG = "ModuleRepository"
    }

    override suspend fun getModules(): Result<List<Module>> = withContext(Dispatchers.IO) {
        runCatching {
            val result = listModules()
            val array = JSONArray(result)
            (0 until array.length())
                .asSequence()
                .map { array.getJSONObject(it) }
                .map { obj ->
                    Module(
                        id = obj.getString("id"),
                        name = obj.optString("name"),
                        author = obj.optString("author", "Unknown"),
                        version = obj.optString("version", "Unknown"),
                        versionCode = obj.optLong("versionCode", 0L),
                        description = obj.optString("description"),
                        enabled = obj.getBoolean("enabled"),
                        update = obj.optBoolean("update"),
                        remove = obj.getBoolean("remove"),
                        updateJson = obj.optString("updateJson"),
                        hasWebUi = obj.optBoolean("web"),
                        hasActionScript = obj.optBoolean("action"),
                        metamodule = (obj.optInt("metamodule") != 0) || obj.optBoolean("metamodule"),
                        zygisk = (obj.optInt("zygisk") != 0) || obj.optBoolean("zygisk"),
                        actionIconPath = obj.optString("actionIcon").takeIf { it.isNotBlank() },
                        webUiIconPath = obj.optString("webuiIcon").takeIf { it.isNotBlank() },
                        preinit = obj.optString("preinit"),
                        bannerPath = obj.optString("banner").takeIf { it.isNotBlank() }
                    )
                }.toList()
        }
    }

    override suspend fun checkUpdate(module: Module): Result<ModuleUpdateInfo> = withContext(Dispatchers.IO) {
        runCatching {
            if (!isNetworkAvailable(ksuApp)) {
                return@runCatching ModuleUpdateInfo.Empty
            }
            if (module.updateJson.isEmpty() || module.remove || module.update || !module.enabled) {
                return@runCatching ModuleUpdateInfo.Empty
            }

            val url = module.updateJson
            val result = ksuApp.okhttpClient.newCall(
                Request.Builder().url(url).build()
            ).awaitModuleUpdateBody()

            if (result.isEmpty()) {
                return@runCatching ModuleUpdateInfo.Empty
            }

            val updateJson = JSONObject(result)
            var version = updateJson.optString("version", "")
            version = sanitizeVersionString(version)
            val versionCode = updateJson.optLong("versionCode", 0L)
            val zipUrl = updateJson.optString("zipUrl", "")
            val changelog = updateJson.optString("changelog", "")

            if (versionCode <= module.versionCode || zipUrl.isEmpty()) {
                ModuleUpdateInfo.Empty
            } else {
                ModuleUpdateInfo(zipUrl, version, changelog, versionCode)
            }
        }.onFailure { if (it is CancellationException) throw it }
    }
}

internal suspend fun Call.awaitModuleUpdateBody(): String = suspendCancellableCoroutine { continuation ->
    continuation.invokeOnCancellation { cancel() }
    enqueue(object : Callback {
        override fun onFailure(call: Call, e: IOException) {
            continuation.resumeWithException(e)
        }

        override fun onResponse(call: Call, response: Response) {
            // Read before resuming so cancellation also cancels an in-progress body read.
            val result = runCatching {
                response.use {
                    if (continuation.isActive && it.isSuccessful) it.body.string() else ""
                }
            }
            continuation.resumeWith(result)
        }
    })
}
