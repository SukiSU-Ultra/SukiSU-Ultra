package com.sukisu.ultra.data.repository

import android.content.Context
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

internal interface ThemeAccessStore {
    fun get(key: String): String?
    fun put(key: String, value: String?): Boolean
}

@Serializable
internal data class DeviceAccess(
    val accessToken: String,
    val refreshToken: String,
    val expiresAt: Long,
    val refreshExpiresAt: Long,
    val refreshAfter: Long = expiresAt - 120,
    val owner: String = "",
    val importedHash: String = "",
    val revoked: Boolean = false,
)

/** Serializes rotation across all repositories. Network IO never holds the image lookup lock. */
class ThemeStoreAccessRepository internal constructor(
    private val storage: ThemeAccessStore,
    private val session: () -> Pair<String, String>?,
    private val client: OkHttpClient = transport,
    private val now: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    constructor(context: Context) : this(
        object : ThemeAccessStore {
            private val prefs=context.applicationContext.getSharedPreferences("theme_device_access",Context.MODE_PRIVATE)
            override fun get(key: String)=prefs.getString(key,null)
            override fun put(key: String,value: String?)=prefs.edit().putString(key,value).commit()
        },
        { null },
    ) { accountContext=context.applicationContext }

    private var accountContext: Context? = null
    companion object {
        private val lock=Any()
        private val latest=ConcurrentHashMap<String,String>()
        private val json=Json { ignoreUnknownKeys=true; encodeDefaults=true }
        private val transport: OkHttpClient by lazy {
            OkHttpClient.Builder().followRedirects(false).followSslRedirects(false)
                .connectTimeout(10,TimeUnit.SECONDS).readTimeout(20,TimeUnit.SECONDS)
                .callTimeout(30,TimeUnit.SECONDS).build()
        }
        fun currentForUrl(url: String,fallback: String): String {
            val imported = fallback.trimStart().startsWith("{")
            if (fallback.startsWith("sr_")) return ""
            if (!imported && fallback.isNotBlank() && !fallback.startsWith("sa_")) return fallback
            return latest.entries.filter { url.startsWith(it.key) }.maxByOrNull { it.key.length }?.value ?: if (imported) "" else fallback
        }
        private fun digest(value: String)=MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).joinToString("") { "%02x".format(it) }
        private fun secure(base: String) {
            val url=base.toHttpUrlOrNull() ?: throw IOException("Invalid theme endpoint")
            if (url.scheme!="https" && !(url.scheme=="http" && url.host in setOf("127.0.0.1","localhost","::1"))) throw IOException("Device credentials require HTTPS")
            if(url.username.isNotEmpty() || url.password.isNotEmpty() || url.query!=null || url.fragment!=null) throw IOException("Invalid theme endpoint")
        }
        private fun valid(value: DeviceAccess,at: Long) {
            if(!value.accessToken.matches(Regex("sa_[a-f0-9]{64}")) || !value.refreshToken.matches(Regex("sr_[a-f0-9]{64}")) || value.refreshExpiresAt<=at) throw IOException("Invalid device credential")
        }
    }
    private fun save(id: String,value: DeviceAccess) {
        if(!storage.put(id,json.encodeToString(value))) throw IOException("Cannot persist device credential")
    }
    /** Blocking IO: invoked on Dispatchers.IO, never from a composable. */
    fun resolve(baseUrl: String,configured: String): String = synchronized(lock) {
        val base=ThemeStoreRepository.normalizeBaseUrl(baseUrl) ?: throw IOException("Invalid theme endpoint")
        if (configured.startsWith("sr_")) throw IOException("Import the complete device credential, not a refresh secret")
        if(configured.isNotBlank() && !configured.startsWith("sa_") && !configured.trimStart().startsWith("{")) return@synchronized configured
        secure(base)
        val identity=accountContext?.let { AccountRepository(it).sessionFor(base) }?.let { it.user.id to it.token } ?: session()
        val owner=identity?.first.orEmpty()
        val id=digest(base)
        val at=now()
        var saved=storage.get(id)?.let { json.decodeFromString<DeviceAccess>(it) }
        if(configured.trimStart().startsWith("{") && saved?.importedHash!=digest(configured)) {
            val raw=json.parseToJsonElement(configured).jsonObject
            val importedBase=raw["baseUrl"]?.jsonPrimitive?.content
            if(importedBase!=null && ThemeStoreRepository.normalizeBaseUrl(importedBase)!=base) throw IOException("Credential belongs to another site")
            val imported=DeviceAccess(raw.getValue("token").jsonPrimitive.content,raw.getValue("refreshToken").jsonPrimitive.content,
                raw.getValue("expiresAt").jsonPrimitive.longOrNull ?: 0,raw.getValue("refreshExpiresAt").jsonPrimitive.longOrNull ?: 0,
                owner=owner,importedHash=digest(configured))
            valid(imported,at);save(id,imported);saved=imported
        }
        if(saved?.owner!=owner) saved=null
        if(saved?.revoked==true) throw ThemeStoreUnauthorizedException()
        if(saved!=null && saved.refreshAfter>at+15 && saved.expiresAt>at) {
            latest[base]=saved.accessToken;return@synchronized saved.accessToken
        }
        if(saved==null && configured.startsWith("sa_")) return@synchronized configured
        val rotating=saved!=null
        val payload=if(saved!=null) json.encodeToString(mapOf("refreshToken" to saved.refreshToken)) else json.encodeToString(mapOf("name" to "SukiSU Android"))
        val request=Request.Builder().url(base+if(rotating)"client/refresh" else "client/access")
            .header("X-Requested-With","SukiSUThemeAdmin").header("Cache-Control","no-store")
            .post(payload.toRequestBody("application/json".toMediaType()))
        if(!rotating && identity!=null) request.header("Authorization","Bearer "+identity.second)
        client.newCall(request.build()).execute().use { response ->
            if(response.code==401 || response.code==403) {
                saved?.let { save(id,it.copy(revoked=true)) };latest.remove(base);throw ThemeStoreUnauthorizedException()
            }
            if(!response.isSuccessful) throw IOException("Device access HTTP "+response.code)
            val body=response.body
            if(body.contentLength()>65536 || body.source().request(65537)) throw IOException("Device credential response too large")
            val value=json.decodeFromString<DeviceAccess>(body.string()).copy(owner=owner,importedHash=saved?.importedHash.orEmpty())
            valid(value,at)
            if(value.expiresAt<=at || value.refreshAfter>=value.expiresAt) throw IOException("Expired device credential")
            save(id,value);latest[base]=value.accessToken;value.accessToken
        }
    }
    fun reset(baseUrl: String)=synchronized(lock) {
        val base=ThemeStoreRepository.normalizeBaseUrl(baseUrl) ?: return@synchronized
        if(!storage.put(digest(base),null)) throw IOException("Cannot reset device credential")
        latest.remove(base)
    }
    fun forRequest(url: String,configured: String): String {
        val base=latest.keys.filter { url.startsWith(it) }.maxByOrNull { it.length }
        if (base!=null && (configured.isBlank() || configured.startsWith("sa_") || configured.trimStart().startsWith("{"))) return resolve(base,configured)
        if (configured.trimStart().startsWith("{") || configured.startsWith("sr_")) throw IOException("Device credential must be resolved before requesting assets")
        return configured
    }
}
