package com.sukisu.ultra.data.repository

import android.content.Context
import androidx.core.content.edit
import com.sukisu.ultra.R
import com.sukisu.ultra.data.model.AccountCommentChangeResponse
import com.sukisu.ultra.data.model.AccountConfigResponse
import com.sukisu.ultra.data.model.AccountDevicePollResponse
import com.sukisu.ultra.data.model.AccountDeviceStartResponse
import com.sukisu.ultra.data.model.AccountFollowChangeResponse
import com.sukisu.ultra.data.model.AccountFollowRequest
import com.sukisu.ultra.data.model.AccountFollowsResponse
import com.sukisu.ultra.data.model.AccountForgotPasswordRequest
import com.sukisu.ultra.data.model.AccountHistoryItem
import com.sukisu.ultra.data.model.AccountHistoryRequest
import com.sukisu.ultra.data.model.AccountHistoryResponse
import com.sukisu.ultra.data.model.AccountLoginRequest
import com.sukisu.ultra.data.model.AccountLoginResponse
import com.sukisu.ultra.data.model.AccountMessagesResponse
import com.sukisu.ultra.data.model.AccountPreferencesRequest
import com.sukisu.ultra.data.model.AccountPreferencesResponse
import com.sukisu.ultra.data.model.AccountProfileResponse
import com.sukisu.ultra.data.model.AccountRegisterRequest
import com.sukisu.ultra.data.model.AccountSession
import com.sukisu.ultra.data.model.AccountSimpleResponse
import com.sukisu.ultra.data.model.AccountSubmission
import com.sukisu.ultra.data.model.AccountSubmissionsResponse
import com.sukisu.ultra.data.model.AccountThemeIdResponse
import com.sukisu.ultra.data.model.AccountThemeSummary
import com.sukisu.ultra.data.model.AccountThemesResponse
import com.sukisu.ultra.data.model.AccountUserSearchResponse
import com.sukisu.ultra.data.model.AccountUserSummary
import com.sukisu.ultra.data.model.ThemeComment
import com.sukisu.ultra.data.model.ThemeCommentCreateRequest
import com.sukisu.ultra.data.model.ThemeCommentCreatedResponse
import com.sukisu.ultra.data.model.ThemeCommentsResponse
import com.sukisu.ultra.ksuApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.File
import java.io.IOException

class AccountRepository(
    context: Context,
    private val client: OkHttpClient = ksuApp.okhttpClient,
) {
    private companion object {
        const val PREFS = "theme_account"
        const val KEY_SESSIONS = "sessions"
        const val KEY_SESSION_LEGACY = "session"
        const val CSRF_HEADER = "X-Requested-With"
        const val CSRF_VALUE = "SukiSUThemeAdmin"
        const val CLIENT_HEADER = "X-Client"
        const val HISTORY_KIND_VIEW = "view"
        const val HISTORY_KIND_DOWNLOAD = "download"
        val JSON_MEDIA = "application/json; charset=utf-8".toMediaType()
        val json = Json { ignoreUnknownKeys = true; isLenient = true }
        val SESSIONS_SERIALIZER = MapSerializer(String.serializer(), AccountSession.serializer())
        
        val SESSION_WRITE_LOCK = Any()
    }

    private val appContext = context.applicationContext
    private val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val _sessions = MutableStateFlow(loadSessions())
    val sessions: StateFlow<Map<String, AccountSession>> = _sessions.asStateFlow()

    /**
     * Reads all source sessions. The legacy single-session key is promoted once so existing
     * users keep their login after upgrading.
     */
    private fun loadSessions(): Map<String, AccountSession> {
        prefs.getString(KEY_SESSIONS, null)?.let { raw ->
            val decoded = runCatching { json.decodeFromString(SESSIONS_SERIALIZER, raw) }
                .getOrNull()
            if (decoded != null) return normalizeSessions(decoded)
        }

        val legacyRaw = prefs.getString(KEY_SESSION_LEGACY, null) ?: return emptyMap()
        val legacy = runCatching {
            json.decodeFromString(AccountSession.serializer(), legacyRaw)
        }.getOrNull() ?: return emptyMap()
        if (legacy.token.isBlank()) return emptyMap()
        val base = resolvedBase(legacy.baseUrl) ?: return emptyMap()
        val migrated = mapOf(base to legacy.copy(baseUrl = base))
        prefs.edit {
            putString(KEY_SESSIONS, json.encodeToString(SESSIONS_SERIALIZER, migrated))
            remove(KEY_SESSION_LEGACY)
        }
        return migrated
    }

    private fun normalizeSessions(raw: Map<String, AccountSession>): Map<String, AccountSession> =
        buildMap {
            raw.forEach { (key, session) ->
                if (session.token.isBlank()) return@forEach
                val base = resolvedBase(session.baseUrl.ifBlank { key })
                    ?: resolvedBase(key)
                    ?: return@forEach
                put(base, session.copy(baseUrl = base))
            }
        }

    private fun persistSessions(sessions: Map<String, AccountSession>) {
        prefs.edit {
            putString(KEY_SESSIONS, json.encodeToString(SESSIONS_SERIALIZER, sessions))
        }
        _sessions.value = sessions
    }

    private fun saveSession(session: AccountSession): AccountSession {
        val base = resolvedBase(session.baseUrl) ?: session.baseUrl
        val normalized = session.copy(baseUrl = base)
        // Re-read before writing: the account and theme-store screens own separate repository
        // instances, and each write must not drop sessions created by the other one.
        synchronized(SESSION_WRITE_LOCK) {
            persistSessions(loadSessions() + (base to normalized))
        }
        return normalized
    }

    private fun removeSession(baseUrl: String) {
        val base = resolvedBase(baseUrl) ?: return
        synchronized(SESSION_WRITE_LOCK) {
            val current = loadSessions()
            val targets = if (ThemeStoreDefaults.isBuiltInBaseUrl(base)) {
                // The built-in mirrors are automatically interchangeable; sign out
                // from all of them so a fallback session cannot reappear.
                ThemeStoreDefaults.BASE_URLS
                    .mapNotNull { ThemeStoreRepository.normalizeBaseUrl(it) }
                    .toSet() + base
            } else {
                setOf(base)
            }
            val remaining = current - targets
            if (remaining.size != current.size) {
                persistSessions(remaining)
            }
        }
    }

    fun reload() {
        _sessions.value = loadSessions()
    }

    fun sessionFor(baseUrl: String): AccountSession? {
        val normalized = resolvedBase(baseUrl) ?: return null
        val current = _sessions.value[normalized]
            ?: if (ThemeStoreDefaults.isBuiltInBaseUrl(normalized)) {
                // Auto-selection may point at another mirror than the one used to
                // sign in. Reuse that session and route requests to the current
                // (fastest) mirror.
                ThemeStoreDefaults.BASE_URLS
                    .asSequence()
                    .mapNotNull { ThemeStoreRepository.normalizeBaseUrl(it) }
                    .filter { it != normalized }
                    .mapNotNull { _sessions.value[it] }
                    .firstOrNull()
                    ?.copy(baseUrl = normalized)
            } else {
                null
            }
        return current?.takeIf { it.token.isNotBlank() }
    }

    private fun requireSession(baseUrl: String): AccountSession =
        sessionFor(baseUrl) ?: throw IOException(appContext.getString(R.string.account_login_required))

    fun accountUrl(baseUrl: String): String? =
        resolvedBase(baseUrl)?.let { it + "account/" }

    private fun resolvedBase(baseUrl: String): String? {
        val value = baseUrl.trim().ifBlank { ThemeStoreDefaults.preferredBaseUrl() }
        return ThemeStoreRepository.normalizeBaseUrl(value)
    }

    private fun apiBase(baseUrl: String): String? =
        resolvedBase(baseUrl)?.let { it + "account/api/" }

    private fun parseError(raw: String, code: Int): String {
        val specific = runCatching {
            json.parseToJsonElement(raw).jsonObject["error"]?.toString()?.trim('"')
        }.getOrNull()
        return specific?.takeIf { it.isNotBlank() }
            ?: appContext.getString(R.string.account_http_error, code)
    }

    suspend fun login(baseUrl: String, login: String, password: String): Result<AccountSession> =
        withContext(Dispatchers.IO) {
            runCatching {
                val api = apiBase(baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
                val body = json.encodeToString(AccountLoginRequest.serializer(), AccountLoginRequest(login, password))
                    .toRequestBody(JSON_MEDIA)
                val request = Request.Builder()
                    .url(api + "auth/login")
                    .header(CSRF_HEADER, CSRF_VALUE)
                    .header(CLIENT_HEADER, "android")
                    .post(body)
                    .build()
                client.newCall(request).execute().use { response ->
                    val raw = response.body.string()
                    if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                    val parsed = json.decodeFromString(AccountLoginResponse.serializer(), raw)
                    if (!parsed.ok || parsed.user == null) throw IOException(parsed.error ?: appContext.getString(R.string.account_login_failed))
                    val token = parsed.token?.takeIf { it.isNotBlank() }
                        ?: throw IOException(appContext.getString(R.string.account_token_missing))
                    val session = AccountSession(
                        baseUrl = resolvedBase(baseUrl) ?: "",
                        token = token,
                        user = parsed.user,
                    )
                    saveSession(session)
                }
            }
        }

    suspend fun register(
        baseUrl: String,
        username: String,
        displayName: String,
        email: String,
        password: String,
    ): Result<AccountSimpleResponse> = withContext(Dispatchers.IO) {
        runCatching {
            val api = apiBase(baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val body = json.encodeToString(
                AccountRegisterRequest.serializer(),
                AccountRegisterRequest(username, displayName, email, password),
            ).toRequestBody(JSON_MEDIA)
            val request = Request.Builder()
                .url(api + "register")
                .header(CSRF_HEADER, CSRF_VALUE)
                .header(CLIENT_HEADER, "android")
                .post(body)
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountSimpleResponse.serializer(), raw)
            }
        }
    }

    suspend fun refreshProfile(baseUrl: String): Result<AccountSession?> = withContext(Dispatchers.IO) {
        runCatching {
            val current = sessionFor(baseUrl) ?: return@runCatching null
            val api = apiBase(current.baseUrl) ?: return@runCatching null
            val request = Request.Builder()
                .url(api + "profile")
                .header("Authorization", "Bearer ${current.token}")
                .header(CSRF_HEADER, CSRF_VALUE)
                .get()
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (response.code == 401) {
                    removeSession(current.baseUrl)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                val parsed = json.decodeFromString(AccountProfileResponse.serializer(), raw)
                val user = parsed.user ?: throw IOException(parsed.error ?: appContext.getString(R.string.account_profile_unavailable))
                val updated = current.copy(
                    user = user,
                    authors = parsed.authors,
                    activeAuthor = parsed.activeAuthor ?: current.activeAuthor,
                    followers = parsed.followers,
                    following = parsed.following,
                )
                saveSession(updated)
            }
        }
    }

    suspend fun config(baseUrl: String): Result<AccountConfigResponse> = withContext(Dispatchers.IO) {
        runCatching {
            val api = apiBase(baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val request = Request.Builder()
                .url(api + "config")
                .header(CSRF_HEADER, CSRF_VALUE)
                .get()
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountConfigResponse.serializer(), raw)
            }
        }
    }

    suspend fun forgotPassword(baseUrl: String, login: String): Result<AccountSimpleResponse> =
        withContext(Dispatchers.IO) {
            runCatching {
                val api = apiBase(baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
                val body = json.encodeToString(
                    AccountForgotPasswordRequest.serializer(),
                    AccountForgotPasswordRequest(login = login.trim()),
                ).toRequestBody(JSON_MEDIA)
                val request = Request.Builder()
                    .url(api + "auth/forgot-password")
                    .header(CSRF_HEADER, CSRF_VALUE)
                    .header(CLIENT_HEADER, "android")
                    .post(body)
                    .build()
                client.newCall(request).execute().use { response ->
                    val raw = response.body.string()
                    if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                    json.decodeFromString(AccountSimpleResponse.serializer(), raw)
                }
            }
        }

    suspend fun startDeviceLogin(
        baseUrl: String,
        deviceName: String? = null,
    ): Result<AccountDeviceStartResponse> = withContext(Dispatchers.IO) {
        runCatching {
            val api = apiBase(baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val resolvedName = deviceName ?: appContext.getString(R.string.account_device_name)
            val body = """{"deviceName":${json.encodeToString(String.serializer(), resolvedName)}}"""
                .toRequestBody(JSON_MEDIA)
            val request = Request.Builder()
                .url(api + "auth/device/start")
                .header(CSRF_HEADER, CSRF_VALUE)
                .header(CLIENT_HEADER, "android")
                .post(body)
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                val parsed = json.decodeFromString(AccountDeviceStartResponse.serializer(), raw)
                if (!parsed.ok || parsed.deviceCode.isBlank() || parsed.userCode.isBlank()) {
                    throw IOException(parsed.error ?: appContext.getString(R.string.account_device_unavailable))
                }
                parsed
            }
        }
    }

    suspend fun pollDeviceLogin(baseUrl: String, deviceCode: String): Result<AccountDevicePollResponse> =
        withContext(Dispatchers.IO) {
            runCatching {
                val api = apiBase(baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
                val request = Request.Builder()
                    .url(api + "auth/device/poll?deviceCode=" + deviceCode)
                    .header(CSRF_HEADER, CSRF_VALUE)
                    .get()
                    .build()
                client.newCall(request).execute().use { response ->
                    val raw = response.body.string()
                    if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                    val parsed = json.decodeFromString(AccountDevicePollResponse.serializer(), raw)
                    if (parsed.status == "approved") {
                        val token = parsed.token?.takeIf { it.isNotBlank() }
                            ?: throw IOException(parsed.error ?: appContext.getString(R.string.account_token_missing))
                        val user = parsed.user ?: throw IOException(parsed.error ?: appContext.getString(R.string.account_login_failed))
                        saveSession(
                            AccountSession(
                                baseUrl = resolvedBase(baseUrl) ?: "",
                                token = token,
                                user = user,
                            ),
                        )
                    }
                    parsed
                }
            }
        }

    suspend fun follows(baseUrl: String): Result<AccountFollowsResponse> = withContext(Dispatchers.IO) {
        runCatching {
            val current = sessionFor(baseUrl) ?: throw IOException(appContext.getString(R.string.account_login_required))
            val api = apiBase(current.baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val request = Request.Builder()
                .url(api + "follows")
                .header("Authorization", "Bearer ${current.token}")
                .header(CSRF_HEADER, CSRF_VALUE)
                .get()
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (response.code == 401) {
                    removeSession(current.baseUrl)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountFollowsResponse.serializer(), raw)
            }
        }
    }

    suspend fun setFollow(
        baseUrl: String,
        authorHash: String,
        follow: Boolean,
    ): Result<AccountFollowChangeResponse> = withContext(Dispatchers.IO) {
        runCatching {
            val current = sessionFor(baseUrl) ?: throw IOException(appContext.getString(R.string.account_login_required))
            val api = apiBase(current.baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val body = json.encodeToString(
                AccountFollowRequest.serializer(),
                AccountFollowRequest(authorHash),
            ).toRequestBody(JSON_MEDIA)
            val request = Request.Builder()
                .url(api + if (follow) "follows/follow" else "follows/unfollow")
                .header("Authorization", "Bearer ${current.token}")
                .header(CSRF_HEADER, CSRF_VALUE)
                .post(body)
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (response.code == 401) {
                    removeSession(current.baseUrl)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountFollowChangeResponse.serializer(), raw)
            }
        }
    }

    suspend fun getPreferences(baseUrl: String): Result<AccountPreferencesResponse> =
        withContext(Dispatchers.IO) {
            runCatching {
                val current = sessionFor(baseUrl)
                    ?: throw IOException(appContext.getString(R.string.account_login_required))
                val api = apiBase(current.baseUrl)
                    ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
                val request = Request.Builder()
                    .url(api + "preferences")
                    .header("Authorization", "Bearer ${current.token}")
                    .header(CSRF_HEADER, CSRF_VALUE)
                    .get()
                    .build()
                client.newCall(request).execute().use { response ->
                    val raw = response.body.string()
                    if (response.code == 401) {
                        removeSession(current.baseUrl)
                        throw IOException(appContext.getString(R.string.account_session_expired))
                    }
                    if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                    json.decodeFromString(AccountPreferencesResponse.serializer(), raw)
                }
            }
        }

    suspend fun savePreferences(
        baseUrl: String,
        showR18: Boolean?,
        consentVersion: Long?,
    ): Result<AccountPreferencesResponse> = withContext(Dispatchers.IO) {
        runCatching {
            val current = sessionFor(baseUrl) ?: throw IOException(appContext.getString(R.string.account_login_required))
            val api = apiBase(current.baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val body = json.encodeToString(
                AccountPreferencesRequest.serializer(),
                AccountPreferencesRequest(showR18, consentVersion),
            ).toRequestBody(JSON_MEDIA)
            val request = Request.Builder()
                .url(api + "preferences")
                .header("Authorization", "Bearer ${current.token}")
                .header(CSRF_HEADER, CSRF_VALUE)
                .post(body)
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (response.code == 401) {
                    removeSession(current.baseUrl)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountPreferencesResponse.serializer(), raw)
            }
        }
    }

    suspend fun nextThemeId(baseUrl: String): Result<AccountThemeIdResponse> = withContext(Dispatchers.IO) {
        runCatching {
            val current = requireSession(baseUrl)
            val api = apiBase(current.baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val request = Request.Builder()
                .url(api + "theme-id/next")
                .header("Authorization", "Bearer ${current.token}")
                .header(CSRF_HEADER, CSRF_VALUE)
                .get()
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (response.code == 401) {
                    removeSession(current.baseUrl)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountThemeIdResponse.serializer(), raw)
            }
        }
    }

    suspend fun myThemes(baseUrl: String): Result<List<AccountThemeSummary>> = withContext(Dispatchers.IO) {
        runCatching {
            val current = requireSession(baseUrl)
            val api = apiBase(current.baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val request = Request.Builder()
                .url(api + "my-themes")
                .header("Authorization", "Bearer ${current.token}")
                .header(CSRF_HEADER, CSRF_VALUE)
                .get()
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (response.code == 401) {
                    removeSession(current.baseUrl)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountThemesResponse.serializer(), raw).themes
            }
        }
    }

    suspend fun mySubmissions(baseUrl: String): Result<List<AccountSubmission>> = withContext(Dispatchers.IO) {
        runCatching {
            val current = requireSession(baseUrl)
            val api = apiBase(current.baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val request = Request.Builder()
                .url(api + "submissions")
                .header("Authorization", "Bearer ${current.token}")
                .header(CSRF_HEADER, CSRF_VALUE)
                .get()
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (response.code == 401) {
                    removeSession(current.baseUrl)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountSubmissionsResponse.serializer(), raw).submissions
            }
        }
    }

    suspend fun withdrawTheme(id: String, baseUrl: String): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val current = requireSession(baseUrl)
            val api = apiBase(current.baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val body = json.encodeToString(
                kotlinx.serialization.json.buildJsonObject { put("id", kotlinx.serialization.json.JsonPrimitive(id)) },
            ).toRequestBody(JSON_MEDIA)
            val request = Request.Builder()
                .url(api + "my-themes/withdraw")
                .header("Authorization", "Bearer ${current.token}")
                .header(CSRF_HEADER, CSRF_VALUE)
                .post(body)
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (response.code == 401) {
                    removeSession(current.baseUrl)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountSimpleResponse.serializer(), raw).message.orEmpty()
            }
        }
    }

    suspend fun restoreTheme(id: String, baseUrl: String): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val current = requireSession(baseUrl)
            val api = apiBase(current.baseUrl) ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val body = json.encodeToString(
                kotlinx.serialization.json.buildJsonObject { put("id", kotlinx.serialization.json.JsonPrimitive(id)) },
            ).toRequestBody(JSON_MEDIA)
            val request = Request.Builder()
                .url(api + "my-themes/restore")
                .header("Authorization", "Bearer ${current.token}")
                .header(CSRF_HEADER, CSRF_VALUE)
                .post(body)
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (response.code == 401) {
                    removeSession(current.baseUrl)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountSimpleResponse.serializer(), raw).message.orEmpty()
            }
        }
    }

    suspend fun comments(baseUrl: String, themeId: String): Result<ThemeCommentsResponse> =
        withContext(Dispatchers.IO) {
            runCatching {
                val api = apiBase(baseUrl)
                    ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
                val current = sessionFor(baseUrl)
                val builder = Request.Builder()
                    .url(api + "themes/" + java.net.URLEncoder.encode(themeId, "UTF-8") + "/comments")
                    .header(CSRF_HEADER, CSRF_VALUE)
                    .get()
                if (current != null) {
                    builder.header("Authorization", "Bearer ${current.token}")
                }
                client.newCall(builder.build()).execute().use { response ->
                    val raw = response.body.string()
                    if (response.code == 401) {
                        if (current != null) removeSession(current.baseUrl)
                        throw IOException(appContext.getString(R.string.account_session_expired))
                    }
                    if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                    json.decodeFromString(ThemeCommentsResponse.serializer(), raw)
                }
            }
        }

    suspend fun postComment(
        baseUrl: String,
        themeId: String,
        content: String,
        visibility: String,
        parentId: String?,
    ): Result<ThemeComment> = withContext(Dispatchers.IO) {
        runCatching {
            val current = requireSession(baseUrl)
            val api = apiBase(current.baseUrl)
                ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val body = json.encodeToString(
                ThemeCommentCreateRequest.serializer(),
                ThemeCommentCreateRequest(content = content, visibility = visibility, parentId = parentId),
            ).toRequestBody(JSON_MEDIA)
            val request = Request.Builder()
                .url(api + "themes/" + java.net.URLEncoder.encode(themeId, "UTF-8") + "/comments")
                .header("Authorization", "Bearer ${current.token}")
                .header(CSRF_HEADER, CSRF_VALUE)
                .post(body)
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (response.code == 401) {
                    removeSession(current.baseUrl)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                val parsed = json.decodeFromString(ThemeCommentCreatedResponse.serializer(), raw)
                parsed.comment ?: throw IOException(parsed.error ?: "Comment failed")
            }
        }
    }

    suspend fun deleteComment(baseUrl: String, id: String): Result<Unit> =
        withContext(Dispatchers.IO) {
            runCatching {
                val current = requireSession(baseUrl)
                val api = apiBase(current.baseUrl)
                    ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
                val body = kotlinx.serialization.json.buildJsonObject {
                    put("id", kotlinx.serialization.json.JsonPrimitive(id))
                }.toString().toRequestBody(JSON_MEDIA)
                val request = Request.Builder()
                    .url(api + "comments/delete")
                    .header("Authorization", "Bearer ${current.token}")
                    .header(CSRF_HEADER, CSRF_VALUE)
                    .post(body)
                    .build()
                client.newCall(request).execute().use { response ->
                    val raw = response.body.string()
                    if (response.code == 401) {
                        removeSession(current.baseUrl)
                        throw IOException(appContext.getString(R.string.account_session_expired))
                    }
                    if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                    val parsed = json.decodeFromString(AccountCommentChangeResponse.serializer(), raw)
                    if (!parsed.ok) throw IOException(parsed.error ?: "Delete failed")
                }
            }
        }

    suspend fun messages(baseUrl: String): Result<AccountMessagesResponse> =
        withContext(Dispatchers.IO) {
            runCatching {
                val current = requireSession(baseUrl)
                val api = apiBase(current.baseUrl)
                    ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
                val request = Request.Builder()
                    .url(api + "messages")
                    .header("Authorization", "Bearer ${current.token}")
                    .header(CSRF_HEADER, CSRF_VALUE)
                    .get()
                    .build()
                client.newCall(request).execute().use { response ->
                    val raw = response.body.string()
                    if (response.code == 401) {
                        removeSession(current.baseUrl)
                        throw IOException(appContext.getString(R.string.account_session_expired))
                    }
                    if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                    json.decodeFromString(AccountMessagesResponse.serializer(), raw)
                }
            }
        }

    suspend fun searchUsers(baseUrl: String, query: String): Result<List<AccountUserSummary>> =
        withContext(Dispatchers.IO) {
            runCatching {
                val current = requireSession(baseUrl)
                val api = apiBase(current.baseUrl)
                    ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
                val request = Request.Builder()
                    .url(api + "users/search?q=" + java.net.URLEncoder.encode(query, "UTF-8"))
                    .header("Authorization", "Bearer ${current.token}")
                    .header(CSRF_HEADER, CSRF_VALUE)
                    .get()
                    .build()
                client.newCall(request).execute().use { response ->
                    val raw = response.body.string()
                    if (response.code == 401) {
                        removeSession(current.baseUrl)
                        throw IOException(appContext.getString(R.string.account_session_expired))
                    }
                    if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                    val base = resolvedBase(current.baseUrl) ?: current.baseUrl
                    json.decodeFromString(AccountUserSearchResponse.serializer(), raw)
                        .users
                        .map { user ->
                            user.copy(
                                avatarUrl = user.avatarUrl
                                    .takeIf { it.isNotBlank() }
                                    ?.let { path -> base + path.removePrefix("/") }
                                    .orEmpty(),
                            )
                        }
                }
            }
        }

    suspend fun themeHistory(
        baseUrl: String,
        kind: String,
        limit: Int = 100,
    ): Result<List<AccountHistoryItem>> = withContext(Dispatchers.IO) {
        runCatching {
            val current = requireSession(baseUrl)
            val api = apiBase(current.baseUrl)
                ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val request = Request.Builder()
                .url(api + "history?kind=" + kind + "&limit=" + limit)
                .header("Authorization", "Bearer ${current.token}")
                .header(CSRF_HEADER, CSRF_VALUE)
                .get()
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (response.code == 401) {
                    removeSession(current.baseUrl)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                json.decodeFromString(AccountHistoryResponse.serializer(), raw).items
            }
        }
    }

    suspend fun recordThemeHistory(
        baseUrl: String,
        kind: String,
        themeId: String,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val current = requireSession(baseUrl)
            val api = apiBase(current.baseUrl)
                ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val body = json.encodeToString(
                AccountHistoryRequest.serializer(),
                AccountHistoryRequest(themeId = themeId, kind = kind),
            ).toRequestBody(JSON_MEDIA)
            val path = if (kind == HISTORY_KIND_VIEW) "history/view" else "history/download"
            val request = Request.Builder()
                .url(api + path)
                .header("Authorization", "Bearer ${current.token}")
                .header(CSRF_HEADER, CSRF_VALUE)
                .post(body)
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (response.code == 401) {
                    removeSession(current.baseUrl)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                Unit
            }
        }
    }

    suspend fun deleteThemeHistory(
        baseUrl: String,
        kind: String,
        ids: List<Long> = emptyList(),
        all: Boolean = false,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val current = requireSession(baseUrl)
            val api = apiBase(current.baseUrl)
                ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val payload = kotlinx.serialization.json.buildJsonObject {
                put("kind", kotlinx.serialization.json.JsonPrimitive(kind))
                put("all", kotlinx.serialization.json.JsonPrimitive(all))
                put(
                    "ids",
                    kotlinx.serialization.json.JsonArray(
                        ids.map { kotlinx.serialization.json.JsonPrimitive(it) },
                    ),
                )
            }
            val request = Request.Builder()
                .url(api + "history/delete")
                .header("Authorization", "Bearer ${current.token}")
                .header(CSRF_HEADER, CSRF_VALUE)
                .post(payload.toString().toRequestBody(JSON_MEDIA))
                .build()
            client.newCall(request).execute().use { response ->
                val raw = response.body.string()
                if (response.code == 401) {
                    removeSession(current.baseUrl)
                    throw IOException(appContext.getString(R.string.account_session_expired))
                }
                if (!response.isSuccessful) throw IOException(parseError(raw, response.code))
                Unit
            }
        }
    }

    /** Fetches the current package of an owned theme for the edit form. */
    suspend fun downloadMyThemePackage(baseUrl: String, id: String): Result<File> =
        withContext(Dispatchers.IO) {
            runCatching {
                val current = requireSession(baseUrl)
                val api = apiBase(current.baseUrl)
                    ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
                val url = api + "my-themes/" + id + "/download?history=0"
                downloadToFile(current, url, editDir(id), "package.sukisu")
            }
        }

    /** Fetches a store image (preview, avatar, screenshot) with the account session. */
    suspend fun downloadAccountAsset(
        baseUrl: String,
        path: String,
        filename: String,
        cacheKey: String,
    ): Result<File> = withContext(Dispatchers.IO) {
        runCatching {
            val current = requireSession(baseUrl)
            val api = apiBase(current.baseUrl)
                ?: throw IOException(appContext.getString(R.string.theme_store_invalid_url))
            val url = api + "preview?path=" + java.net.URLEncoder.encode(path, "UTF-8")
            downloadToFile(current, url, editDir(cacheKey), filename)
        }
    }

    private fun editDir(key: String): File {
        val safe = key.replace(Regex("[^A-Za-z0-9._-]"), "_").ifBlank { "theme" }
        return File(appContext.cacheDir, "theme_store/edit/$safe").apply { mkdirs() }
    }

    private fun downloadToFile(
        session: AccountSession,
        url: String,
        directory: File,
        filename: String,
    ): File {
        val request = Request.Builder()
            .url(url)
            .header("Authorization", "Bearer ${session.token}")
            .header(CSRF_HEADER, CSRF_VALUE)
            .get()
            .build()
        client.newCall(request).execute().use { response ->
            if (response.code == 401) {
                removeSession(session.baseUrl)
                throw IOException(appContext.getString(R.string.account_session_expired))
            }
            if (!response.isSuccessful) {
                throw IOException(parseError(response.body.string(), response.code))
            }
            val file = File(directory, filename)
            response.body.byteStream().use { input ->
                file.outputStream().use { output -> input.copyTo(output) }
            }
            return file
        }
    }

    suspend fun logout(baseUrl: String): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val current = sessionFor(baseUrl)
            if (current != null) {
                val api = apiBase(current.baseUrl)
                if (api != null) {
                    val request = Request.Builder()
                        .url(api + "auth/logout")
                        .header("Authorization", "Bearer ${current.token}")
                        .header(CSRF_HEADER, CSRF_VALUE)
                        .post("{}".toRequestBody(JSON_MEDIA))
                        .build()
                    runCatching { client.newCall(request).execute().close() }
                }
                removeSession(current.baseUrl)
            }
        }
    }
}
